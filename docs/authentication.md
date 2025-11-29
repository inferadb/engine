# Server API Authentication Guide

This guide covers how the InferaDB Server API authenticates requests using vault-scoped JWTs issued by the Management API.

## Table of Contents

- [Overview](#overview)
- [Authentication Architecture](#authentication-architecture)
- [JWT Token Validation](#jwt-token-validation)
- [Server-to-Management Authentication](#server-to-management-authentication)
- [Caching Strategy](#caching-strategy)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Configuration Reference](#configuration-reference)

## Overview

The InferaDB Server API is a **policy evaluation engine** that focuses exclusively on authorization decisions. All authentication concerns are delegated to the **Management API**, which acts as the central authentication orchestrator.

### Key Principles

- **Stateless Authentication**: Server validates JWTs without storing session state
- **Management-First**: Management API is the source of truth for all identity and credential data
- **Vault Isolation**: Every request is scoped to a specific vault for multi-tenant isolation
- **Cryptographic Verification**: Ed25519 signatures provide strong authentication guarantees

### Authentication Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Application                        │
│                                                              │
│  1. Obtain vault JWT from Management API                    │
│  2. Include JWT in Authorization header                     │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       │ Authorization: Bearer <vault_jwt>
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    InferaDB Server API                       │
│                                                              │
│  1. Extract kid from JWT header                             │
│  2. Fetch client certificate from Management API (cached)   │
│  3. Verify JWT signature using Ed25519 public key           │
│  4. Validate claims (exp, iss, aud, vault_id, org_id)       │
│  5. Verify vault ownership (cached)                         │
│  6. Verify organization status (cached)                     │
│  7. Execute policy evaluation in vault context              │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       │ Server-to-Management JWTs (bidirectional auth)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   Management API                             │
│                                                              │
│  - Return client certificates (Ed25519 public keys)         │
│  - Return vault metadata (org ownership, status)            │
│  - Return organization status (active/suspended)            │
└─────────────────────────────────────────────────────────────┘
```

## Authentication Architecture

### Vault-Scoped JWTs

The Server API authenticates requests using **vault-scoped JWTs** issued by the Management API. These tokens:

- Are signed with Ed25519 private keys (fast, small signatures)
- Contain claims identifying the vault, organization, and permissions
- Have short lifetimes (5 minutes) to minimize compromise risk
- Are verified using public keys fetched from Management API

### JWT Structure

**Header**:

```json
{
    "alg": "EdDSA",
    "typ": "JWT",
    "kid": "org-{org_id}-client-{client_id}-cert-{cert_id}"
}
```

**Claims (Payload)**:

```json
{
    "iss": "https://api.inferadb.com",
    "sub": "client:1234567890123456789",
    "aud": "https://api.inferadb.com/evaluate",
    "exp": 1234567890,
    "iat": 1234567800,
    "org_id": "9876543210987654321",
    "vault_id": "1111222233334444555",
    "vault_role": "write",
    "scope": "inferadb.check inferadb.read inferadb.write ..."
}
```

**Key Claims**:

| Claim          | Description                                                                       | Validation                            |
| -------------- | --------------------------------------------------------------------------------- | ------------------------------------- |
| `kid` (header) | Certificate identifier in format `org-{org_id}-client-{client_id}-cert-{cert_id}` | Used to fetch public key              |
| `iss`          | Management API URL                                                                | Must match configured `jwks_base_url` |
| `aud`          | Server API evaluation endpoint                                                    | Must match server's expected audience |
| `exp`          | Expiration timestamp (Unix seconds)                                               | Must be in the future                 |
| `org_id`       | Organization ID (Snowflake ID as string)                                          | Verified against vault ownership      |
| `vault_id`     | Vault ID (Snowflake ID as string)                                                 | Determines policy evaluation context  |
| `vault_role`   | Permission level (`read`, `write`, `manage`, `admin`)                             | Enforces access control               |
| `scope`        | Space-separated API permissions                                                   | Determines allowed operations         |

## JWT Token Validation

The Server API validates vault-scoped JWTs through a multi-step process:

### 1. Extract Key ID (kid)

```rust
// Extract kid from JWT header
let header = decode_header(&token)?;
let kid = header.kid.ok_or("Missing kid claim")?;

// Parse kid to extract org_id, client_id, cert_id
// Format: "org-{org_id}-client-{client_id}-cert-{cert_id}"
let parts: Vec<&str> = kid.split('-').collect();
let org_id = parts[1].parse::<i64>()?;
let client_id = parts[3].parse::<i64>()?;
let cert_id = parts[5].parse::<i64>()?;
```

### 2. Fetch Client Certificate

The server fetches the Ed25519 public key from the Management API's **internal server** (port 9091):

```http
GET /v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}
Authorization: Bearer {server_jwt}
Host: localhost:9091
```

This request is made to the Management API's **internal port** (9091), not the public port (3000), as it's a privileged server-to-server operation.

**Caching**: Certificates are cached for 15 minutes (900 seconds) to minimize API calls.

### 3. Verify Signature

```rust
// Decode and verify JWT signature using Ed25519 public key
let validation = Validation::new(Algorithm::EdDSA);
let token_data = decode::<VaultTokenClaims>(
    &token,
    &DecodingKey::from_ed_pem(public_key_pem.as_bytes())?,
    &validation
)?;
```

### 4. Validate Claims

The server validates all required claims:

```rust
// Check expiration
if token_data.claims.exp < current_timestamp {
    return Err("Token expired");
}

// Check issuer matches Management API
if token_data.claims.iss != config.jwks_base_url {
    return Err("Invalid issuer");
}

// Check audience matches Server API
if token_data.claims.aud != expected_audience {
    return Err("Invalid audience");
}

// Validate org_id and vault_id are present
if token_data.claims.org_id.is_none() || token_data.claims.vault_id.is_none() {
    return Err("Missing org_id or vault_id claim");
}
```

### 5. Verify Vault Ownership

The server verifies that the vault belongs to the organization using the Management API's **privileged internal endpoint**:

```http
GET /internal/vaults/{vault_id}
Authorization: Bearer {server_jwt}
Host: localhost:9091
```

This endpoint is served on the Management API's **internal server** (port 9091) and requires a valid server JWT, but performs **no permission checks**. It's designed specifically for server-to-server verification.

```rust
let vault = management_client.get_vault(vault_id).await?;

if vault.organization_id != org_id {
    return Err("Vault does not belong to organization");
}
```

**Caching**: Vault metadata is cached for 5 minutes (300 seconds).

### 6. Verify Organization Status

The server checks that the organization is active using the Management API's **privileged internal endpoint**:

```http
GET /internal/organizations/{org_id}
Authorization: Bearer {server_jwt}
Host: localhost:9091
```

This endpoint is served on the Management API's **internal server** (port 9091) and requires a valid server JWT, but performs **no permission checks**. It's designed specifically for server-to-server verification.

```rust
let org = management_client.get_organization(org_id).await?;

if org.status != "active" {
    return Err("Organization suspended");
}
```

**Caching**: Organization status is cached for 5 minutes (300 seconds).

### 7. Execute Policy Evaluation

Once authenticated and authorized, the request is executed in the vault context:

```rust
// All operations are scoped to the authenticated vault
let result = policy_engine.evaluate(
    vault_id,
    subject,
    resource,
    permission,
    context
).await?;
```

## Server-to-Management Authentication

The Server API makes authenticated requests to the Management API's **internal server** (port 9091) for verification operations. This uses **bidirectional JWT authentication** where the server has its own Ed25519 keypair.

### Dual-Server Architecture

The Management API runs **two separate HTTP servers**:

- **Public Server** (port 3000): User-facing API with session authentication and permission checks
- **Internal Server** (port 9091): Server-to-server API with JWT authentication for privileged operations

The Server API **exclusively communicates with the internal server** on port 9091, which provides privileged endpoints without permission checks specifically for server-to-server verification.

### Server Identity

The server configures its identity on startup:

```yaml
auth:
    enabled: true
    # IMPORTANT: Points to Management API's INTERNAL port (9091), not public port (3000)
    management_api_url: "http://localhost:9091"
    # Server identity for server-to-management requests
    server_identity_private_key: |
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
        -----END PRIVATE KEY-----
    server_identity_kid: "server-primary-2024"
    server_id: "inferadb-server-prod-us-east-1"
```

**Development Mode**: If `server_identity_private_key` is omitted, the server auto-generates a keypair and logs the PEM-encoded private key at startup.

### Server JWT Generation

When making requests to the Management API, the server generates short-lived JWTs:

```rust
// Generate server JWT (5 minute TTL)
let claims = ServerJwtClaims {
    iss: format!("inferadb-server:{}", server_id),
    sub: format!("server:{}", server_id),
    aud: management_api_url.to_string(),
    iat: now.timestamp(),
    exp: (now + Duration::minutes(5)).timestamp(),
    jti: uuid::new_v4().to_string(),
};

// Sign with server's Ed25519 private key
let server_jwt = encode(
    &Header::new(Algorithm::EdDSA),
    &claims,
    &EncodingKey::from_ed_pem(server_identity.to_pem().as_bytes())?
)?;
```

### Server JWKS Endpoint

The server exposes its public key for the Management API to verify server JWTs:

```http
GET /.well-known/jwks.json
```

Response:

```json
{
    "keys": [
        {
            "kty": "OKP",
            "alg": "EdDSA",
            "kid": "server-primary-2024",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "use": "sig"
        }
    ]
}
```

### Management API Privileged Endpoints

The Management API provides **dedicated server-to-server endpoints** on the internal server (port 9091) for the Server API's verification operations:

**Internal Endpoints** (port 9091, server JWT required):

- `GET /internal/organizations/{org_id}` - Organization status lookup (no permission checks)
- `GET /internal/vaults/{vault_id}` - Vault ownership verification (no permission checks)

**Public Endpoints** (port 3000, session authentication required):

- `GET /v1/organizations/{org_id}` - Organization details (requires membership)
- `GET /v1/vaults/{vault_id}` - Vault details (requires vault access)

The Server API **exclusively uses the internal endpoints** for verification, which are isolated from the public API and don't perform permission checks. This separation provides:

1. **Network Isolation**: Internal endpoints only accessible via internal network
2. **No Permission Bypass**: Public endpoints enforce permissions; internal endpoints are isolated
3. **Performance**: Privileged endpoints skip expensive permission checks
4. **Security**: Different attack surface for user vs server requests

## Caching Strategy

The Server API aggressively caches authentication data to minimize latency and Management API load:

### Cache Configuration

| Data Type           | Cache TTL  | Capacity | Purpose                |
| ------------------- | ---------- | -------- | ---------------------- |
| Client Certificates | 15 minutes | 10,000   | Signature verification |
| Vault Metadata      | 5 minutes  | 10,000   | Ownership validation   |
| Organization Status | 5 minutes  | 1,000    | Active/suspended check |

### Cache Performance

**Expected Metrics**:

- **Cache Hit Rate**: >90% after warmup
- **Management API Call Rate**: <10% of total requests
- **Token Validation Latency**:
    - Cache hit: <1ms
    - Cache miss: ~50-100ms (includes network roundtrip)

**Configuration** (`config.yaml`):

```yaml
auth:
    enabled: true
    # IMPORTANT: Points to Management API's INTERNAL port (9091)
    management_api_url: "http://localhost:9091"
    management_api_timeout_ms: 5000

    # Cache TTLs
    cert_cache_ttl_seconds: 900 # 15 minutes
    management_cache_ttl_seconds: 300 # 5 minutes

    # Cache capacities
    cert_cache_max_capacity: 10000
    vault_cache_max_capacity: 10000
    org_cache_max_capacity: 1000
```

### Cache Trade-offs

**Benefits**:

- Continued operation during temporary Management API outages
- Sub-millisecond authentication for cached credentials
- Reduced load on Management API (10x reduction)

**Trade-offs**:

- Certificate revocation propagation: up to 15 minutes
- Vault deletion propagation: up to 5 minutes
- Organization suspension propagation: up to 5 minutes

**Immediate Revocation**: For immediate revocation, restart the server to clear all caches.

## Security Considerations

### Token Lifetimes

**Vault Access Tokens (JWTs)**: 5 minutes (300 seconds)

- Very short lifetime minimizes impact of token compromise
- Automatically refreshed by clients before expiration
- Limits attack window to 5 minutes maximum

**Server JWTs**: 5 minutes (300 seconds)

- Short-lived for server-to-management requests
- Generated on-demand for each verification call
- Reduces impact of server key compromise

### Cryptographic Algorithms

**Ed25519 (EdDSA)**:

- Fast signature verification (~70,000 verifications/second)
- Small signature size (64 bytes)
- Strong security guarantees (128-bit security level)
- No complex parameter configuration

**Why Ed25519?**:

- Simpler than RSA (no key size configuration)
- Faster than ECDSA
- More secure than both RSA-2048 and P-256
- Widely supported in modern cryptographic libraries

### Vault Isolation

The server enforces strict multi-tenant isolation:

1. **Cross-Vault Protection**: Clients can only access vaults owned by their organization
2. **Cross-Organization Protection**: Vaults from different organizations are completely isolated
3. **Vault Ownership Verification**: Every request verifies vault belongs to the token's organization
4. **Relationship Isolation**: Relationships written to vault A are invisible in vault B

### Organization Suspension

When an organization is suspended:

1. **Immediate**: Management API marks organization as suspended
2. **Delayed (5 min)**: Server cache expires, new requests fail
3. **Existing Tokens**: Valid JWTs continue working until expiration (max 5 min)

### Certificate Revocation

When a certificate is revoked:

1. **Immediate**: Management API removes certificate from database
2. **Delayed (15 min)**: Server cache expires
3. **New Tokens**: Cannot be generated (Management API rejects)
4. **Existing Tokens**: Valid JWTs continue working until expiration (max 5 min)

**Total Revocation Time**: Max 15 minutes (cache TTL) + 5 minutes (JWT expiration) = 20 minutes

### Best Practices

**DO**:

- Use HTTPS/TLS for all communication in production
- Monitor authentication failure rates (`infera_auth_failures_total`)
- Monitor cache hit rates (`infera_auth_cache_hit_rate`)
- Set appropriate cache TTLs based on security requirements
- Implement alerting for auth failures >5% over 5 minutes

**DON'T**:

- Expose Management API to public internet
- Disable TLS certificate validation
- Set cache TTLs longer than 15 minutes
- Ignore authentication errors in logs

## Troubleshooting

### Problem: 401 Unauthorized - Invalid signature

**Symptoms**:

```json
{
    "error": "Unauthorized",
    "message": "Invalid token signature"
}
```

**Causes**:

1. JWT signed with wrong private key
2. Certificate not found in Management API
3. Certificate has been revoked
4. Public key mismatch

**Solutions**:

```bash
# Verify certificate exists
curl -X GET http://localhost:8081/v1/organizations/$ORG_ID/clients/$CLIENT_ID/certificates/$CERT_ID \
  -H "Authorization: Bearer $SESSION_ID"

# Check if certificate is revoked
# Response should have "revoked": false

# Verify public key matches your private key
# Use cryptographic tools to derive public key from private and compare
```

### Problem: 403 Forbidden - Vault not found

**Symptoms**:

```json
{
    "error": "Forbidden",
    "message": "Vault not found or access denied"
}
```

**Causes**:

1. Vault ID in JWT doesn't exist
2. Vault belongs to different organization
3. Vault was recently deleted (cache not expired)
4. Management API is unreachable

**Solutions**:

```bash
# Verify vault exists
curl -X GET http://localhost:8081/v1/vaults/$VAULT_ID \
  -H "Authorization: Bearer $SESSION_ID"

# Verify organization ID matches
# vault.organization_id should equal org_id claim in JWT

# Check server logs for Management API errors
grep "management_api" /var/log/inferadb/server.log
```

### Problem: High latency on first request

**Symptoms**:

- First request takes 100-200ms
- Subsequent requests take <10ms

**Cause**: Cold cache - server fetches certificate, vault, and organization data

**Solution**: This is expected behavior. Performance improves after warmup:

```
Request 1: 150ms (fetch cert + vault + org)
Request 2: 5ms (all cached)
Request 3: 5ms (all cached)
...
Request 100: 5ms (all cached)
```

To pre-warm caches in production, send health check requests with valid JWTs on startup.

### Problem: Tokens work, then suddenly fail

**Symptoms**:

- Tokens worked previously
- Now getting 401/403 errors
- No code changes

**Causes**:

1. Certificate was deleted/revoked
2. Vault was deleted
3. Organization was suspended
4. Cache expired after deletion

**Solutions**:

```bash
# Check certificate status
curl http://localhost:8081/v1/organizations/$ORG_ID/clients/$CLIENT_ID/certificates/$CERT_ID \
  -H "Authorization: Bearer $SESSION_ID"

# Check organization status
curl http://localhost:8081/v1/organizations/$ORG_ID \
  -H "Authorization: Bearer $SESSION_ID"

# Check server logs for specific error
tail -f /var/log/inferadb/server.log | grep -i "auth"
```

### Debugging Checklist

When authentication fails, verify in order:

- [ ] Management API is running and healthy (`curl http://localhost:8081/health`)
- [ ] Server configuration points to correct Management API URL
- [ ] JWT has valid structure (header, payload, signature)
- [ ] JWT header includes `kid` field
- [ ] JWT is signed with Ed25519 private key
- [ ] Certificate exists and is not revoked
- [ ] All required claims are present
- [ ] Token is not expired (`exp` > current time)
- [ ] Vault ID exists and belongs to organization
- [ ] Organization ID matches vault owner
- [ ] Organization is active (not suspended)

## Configuration Reference

### Minimal Configuration

```yaml
auth:
    enabled: true
    management_api_url: "http://localhost:8081"
```

### Production Configuration

```yaml
auth:
    enabled: true

    # Management API connection
    management_api_url: "https://management.example.com"
    management_api_timeout_ms: 5000

    # JWKS configuration (for client token verification)
    jwks_base_url: "https://management.example.com"

    # Cache TTLs
    cert_cache_ttl_seconds: 900 # 15 minutes
    management_cache_ttl_seconds: 300 # 5 minutes

    # Cache capacities
    cert_cache_max_capacity: 10000
    vault_cache_max_capacity: 10000
    org_cache_max_capacity: 1000

    # Verification options
    management_verify_vault_ownership: true
    management_verify_org_status: true

    # Server identity (for server-to-management requests)
    server_identity_private_key: |
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
        -----END PRIVATE KEY-----
    server_identity_kid: "server-primary-2024"
    server_id: "inferadb-server-prod-us-east-1"
```

### Environment Variables

Configuration can also be set via environment variables:

```bash
# Core settings
export INFERA__AUTH__ENABLED=true
export INFERA__AUTH__MANAGEMENT_API_URL=http://localhost:8081
export INFERA__AUTH__JWKS_BASE_URL=http://localhost:8081

# Cache configuration
export INFERA__AUTH__CERT_CACHE_TTL_SECONDS=900
export INFERA__AUTH__MANAGEMENT_CACHE_TTL_SECONDS=300

# Server identity
export INFERA__AUTH__SERVER_IDENTITY_KID=server-primary-2024
export INFERA__AUTH__SERVER_ID=inferadb-server-dev
# Note: Set INFERA__AUTH__SERVER_IDENTITY_PRIVATE_KEY for production
```

### Metrics

Monitor these Prometheus metrics for authentication health:

```
# Authentication metrics
infera_auth_validations_total          # Total auth validations
infera_auth_failures_total             # Failed authentications
infera_auth_cache_hits_total          # Cache hits (should be >90%)
infera_auth_cache_misses_total        # Cache misses
infera_auth_management_api_calls_total # Management API calls
infera_auth_validation_duration_seconds # Validation latency

# Cache metrics
infera_auth_cert_cache_size           # Current cert cache size
infera_auth_vault_cache_size          # Current vault cache size
infera_auth_org_cache_size            # Current org cache size
```

### Logging

Authentication events are logged with structured fields:

```json
{
    "level": "info",
    "event_type": "auth.success",
    "vault_id": "1111222233334444555",
    "org_id": "9876543210987654321",
    "client_id": "1234567890123456789",
    "cache_hit": true,
    "duration_ms": 2
}
```

**Log Levels**:

- `INFO`: Successful authentications (when `RUST_LOG=info`)
- `WARN`: Cache misses, Management API errors
- `ERROR`: Authentication failures, configuration errors

## Further Reading

- [Management API Authentication Flow](../../management/docs/Authentication.md) - Complete authentication architecture
- [Server Configuration Guide](../guides/configuration.md) - Detailed configuration options
- [Multi-Tenancy Architecture](../architecture/multi-tenancy.md) - Deep dive on vault isolation
- [Security Hardening Guide](../security/hardening.md) - Production security checklist
