//! FDB-based Control JWT authentication
//!
//! This module provides authentication for requests FROM Control TO the Engine
//! using JWKS stored in FDB instead of HTTP-based discovery.
//!
//! Control instances write their JWKS to FDB at startup. Engine reads from FDB
//! to verify Control-signed JWTs. This enables:
//! - Multi-region support via FDB Fearless DR replication
//! - No HTTP connectivity required between Control and Engine
//! - Automatic key aggregation from all Control instances

use std::sync::Arc;

use foundationdb::{Database, RangeOption};
use futures::StreamExt;
use inferadb_engine_fdb_shared::{CONTROL_JWKS_PREFIX, StoredJwk, StoredJwks};
use moka::future::Cache;
use tracing::{debug, info, warn};

use crate::{
    control_auth::{ControlJwtClaims, validate_control_claims},
    error::AuthError,
    jwt::decode_jwt_header,
};

/// FDB-based Control JWKS cache
///
/// Reads Control JWKS from FDB and caches them locally for JWT verification.
/// This replaces HTTP-based JWKS discovery with FDB-based storage.
pub struct FdbControlJwksCache {
    db: Arc<Database>,
    /// Cache of keys by kid
    keys_cache: Cache<String, Arc<CachedControlKey>>,
    /// Cache TTL
    cache_ttl: std::time::Duration,
}

/// Cached Control key with metadata
#[derive(Debug, Clone)]
struct CachedControlKey {
    /// The JWK
    jwk: StoredJwk,
    /// Control instance that owns this key
    #[allow(dead_code)]
    control_id: String,
}

impl FdbControlJwksCache {
    /// Create a new FDB-based Control JWKS cache
    ///
    /// # Arguments
    ///
    /// * `db` - FDB database connection
    /// * `cache_ttl` - How long to cache keys locally (recommended: 5-15 minutes)
    pub fn new(db: Arc<Database>, cache_ttl: std::time::Duration) -> Self {
        let keys_cache = Cache::builder()
            .time_to_live(cache_ttl)
            .max_capacity(100) // Support up to 100 unique keys
            .build();

        Self { db, keys_cache, cache_ttl }
    }

    /// Fetch all JWKS from FDB and aggregate keys
    async fn fetch_all_jwks(&self) -> Result<Vec<(String, StoredJwks)>, AuthError> {
        let db = Arc::clone(&self.db);
        let start_key = CONTROL_JWKS_PREFIX.to_vec();
        let mut end_key = CONTROL_JWKS_PREFIX.to_vec();
        end_key.push(0xff); // Range end

        let result = db
            .run({
                let start_key = start_key.clone();
                let end_key = end_key.clone();
                move |trx, _maybe_committed| {
                    let start_key = start_key.clone();
                    let end_key = end_key.clone();
                    async move {
                        let range_opt = RangeOption::from((start_key.as_slice(), end_key.as_slice()));
                        let mut range_stream = trx.get_ranges(range_opt, false);
                        let mut results = Vec::new();

                        while let Some(batch) = range_stream.next().await {
                            let kvs = batch.map_err(|e| {
                                foundationdb::FdbBindingError::new_custom_error(Box::new(
                                    std::io::Error::other(format!("FDB get_ranges failed: {}", e)),
                                ))
                            })?;

                            for kv in kvs.iter() {
                                results.push((kv.key().to_vec(), kv.value().to_vec()));
                            }
                        }

                        Ok(results)
                    }
                }
            })
            .await
            .map_err(|e| AuthError::JwksError(format!("Failed to read JWKS from FDB: {}", e)))?;

        // Parse each JWKS
        let mut all_jwks = Vec::new();
        for (key, value) in result {
            // Extract control_id from key
            let control_id = if key.len() > CONTROL_JWKS_PREFIX.len() {
                String::from_utf8_lossy(&key[CONTROL_JWKS_PREFIX.len()..]).to_string()
            } else {
                continue;
            };

            match serde_json::from_slice::<StoredJwks>(&value) {
                Ok(jwks) => {
                    debug!(
                        control_id = %control_id,
                        key_count = jwks.keys.len(),
                        "Loaded JWKS from FDB"
                    );
                    all_jwks.push((control_id, jwks));
                },
                Err(e) => {
                    warn!(
                        control_id = %control_id,
                        error = %e,
                        "Failed to parse JWKS from FDB"
                    );
                },
            }
        }

        Ok(all_jwks)
    }

    /// Refresh the local key cache from FDB
    async fn refresh_keys(&self) -> Result<(), AuthError> {
        let all_jwks = self.fetch_all_jwks().await?;

        let mut aggregated_keys = 0;
        for (control_id, jwks) in all_jwks {
            for key in jwks.keys {
                let cached_key = CachedControlKey { jwk: key.clone(), control_id: control_id.clone() };
                self.keys_cache.insert(key.kid.clone(), Arc::new(cached_key)).await;
                aggregated_keys += 1;
            }
        }

        if aggregated_keys == 0 {
            return Err(AuthError::JwksError("No Control JWKS found in FDB".into()));
        }

        info!(
            aggregated_keys = aggregated_keys,
            "Refreshed Control JWKS from FDB"
        );

        Ok(())
    }

    /// Get a specific key by key ID
    async fn get_key(&self, kid: &str) -> Result<StoredJwk, AuthError> {
        // Try cache first
        if let Some(cached) = self.keys_cache.get(kid).await {
            debug!(kid = %kid, "Control key cache hit");
            return Ok(cached.jwk.clone());
        }

        // Cache miss - refresh from FDB
        debug!(kid = %kid, "Control key cache miss, refreshing from FDB");
        self.refresh_keys().await?;

        // Try cache again after refresh
        self.keys_cache
            .get(kid)
            .await
            .map(|c| c.jwk.clone())
            .ok_or_else(|| AuthError::JwksError(format!("Control key '{}' not found in FDB", kid)))
    }

    /// Convert StoredJwk to jsonwebtoken DecodingKey
    fn jwk_to_decoding_key(jwk: &StoredJwk) -> Result<jsonwebtoken::DecodingKey, AuthError> {
        match jwk.kty.as_str() {
            "OKP" => {
                // EdDSA key
                if jwk.crv != "Ed25519" {
                    return Err(AuthError::JwksError(format!(
                        "Unsupported curve: {}",
                        jwk.crv
                    )));
                }

                use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
                let x_bytes = URL_SAFE_NO_PAD
                    .decode(&jwk.x)
                    .map_err(|e| AuthError::JwksError(format!("Invalid base64 in x: {}", e)))?;

                Ok(jsonwebtoken::DecodingKey::from_ed_der(&x_bytes))
            },
            _ => Err(AuthError::JwksError(format!("Unsupported key type: {}", jwk.kty))),
        }
    }

    /// Verify a JWT from the Control
    ///
    /// # Arguments
    ///
    /// * `token` - The JWT token from the Control
    ///
    /// # Returns
    ///
    /// Returns the validated JWT claims if verification succeeds
    pub async fn verify_control_jwt(&self, token: &str) -> Result<ControlJwtClaims, AuthError> {
        // Decode header to get key ID
        let header = decode_jwt_header(token)?;

        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidTokenFormat("Control JWT missing kid".into()))?;

        // Validate algorithm
        let alg_str = format!("{:?}", header.alg);
        crate::validation::validate_algorithm(&alg_str)?;

        // Get key from FDB-based cache
        let jwk = self.get_key(&kid).await?;
        let decoding_key = Self::jwk_to_decoding_key(&jwk)?;

        // Verify signature
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.validate_exp = true;
        validation.validate_nbf = false;
        validation.validate_aud = false;

        let token_data = jsonwebtoken::decode::<ControlJwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| AuthError::InvalidTokenFormat(format!("JWT error: {}", e)))?;

        let claims = token_data.claims;

        // Validate claims
        validate_control_claims(&claims)?;

        Ok(claims)
    }

    /// Get the number of cached keys (for diagnostics)
    pub fn cached_key_count(&self) -> u64 {
        self.keys_cache.entry_count()
    }

    /// Get the cache TTL (for diagnostics)
    pub fn cache_ttl(&self) -> std::time::Duration {
        self.cache_ttl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwk_to_decoding_key_unsupported_type() {
        let jwk = StoredJwk {
            kty: "RSA".to_string(), // Not supported (we only use EdDSA)
            alg: "RS256".to_string(),
            kid: "test".to_string(),
            crv: "".to_string(),
            x: "".to_string(),
            key_use: "sig".to_string(),
        };

        let result = FdbControlJwksCache::jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwk_to_decoding_key_unsupported_curve() {
        let jwk = StoredJwk {
            kty: "OKP".to_string(),
            alg: "EdDSA".to_string(),
            kid: "test".to_string(),
            crv: "X25519".to_string(), // Not Ed25519
            x: "test".to_string(),
            key_use: "sig".to_string(),
        };

        let result = FdbControlJwksCache::jwk_to_decoding_key(&jwk);
        assert!(result.is_err());
    }
}
