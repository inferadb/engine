# Engine API Authentication Guide

This guide covers how the InferaDB Engine API authenticates requests using vault-scoped JWTs issued by Control.

## Table of Contents

- [Overview](#overview)
- [Authentication Architecture](#authentication-architecture)
- [JWT Token Validation](#jwt-token-validation)
- [Engine-to-Control Authentication](#engine-to-control-authentication)
- [Caching Strategy](#caching-strategy)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Configuration Reference](#configuration-reference)

## Overview

The InferaDB Engine API is a **policy evaluation engine** that focuses exclusively on authorization decisions. All authentication concerns are delegated to the **Control**, which acts as the central authentication orchestrator.

### Key Principles

- **Stateless Authentication**: Engine validates JWTs without storing session state
- **Control-First**: Control is the source of truth for all identity and credential data
- **Vault Isolation**: Every request is scoped to a specific vault for multi-tenant isolation
- **Cryptographic Verification**: Ed25519 signatures provide strong authentication guarantees

### Authentication Flow

```mermaid
sequenceDiagram
    participant Client as Client Application
    participant Engine as InferaDB Engine API
    participant Control as Control

    Note over Client: 1. Obtain vault JWT from Control<br/>2. Include JWT in Authorization header

    Client->>Engine: Authorization: Bearer <vault_jwt>

    Note over Engine: 1. Extract kid from JWT header<br/>2. Fetch client certificate (cached)<br/>3. Verify JWT signature (Ed25519)<br/>4. Validate claims (exp, iss, aud, vault_id, org_id)<br/>5. Verify vault ownership (cached)<br/>6. Verify organization status (cached)<br/>7. Execute policy evaluation in vault context

    Engine->>Control: Engine-to-Control JWTs (bidirectional auth)

    Note over Control: • Return client certificates (Ed25519 public keys)<br/>• Return vault metadata (org ownership, status)<br/>• Return organization status (active/suspended)

    Control-->>Engine: Certificate/Vault/Org data
    Engine-->>Client: Policy evaluation result
```

## Authentication Architecture

### Vault-Scoped JWTs

The Engine API authenticates requests using **vault-scoped JWTs** issued by Control. These tokens:

- Are signed with Ed25519 private keys (fast, small signatures)
- Contain claims identifying the vault, organization, and permissions
- Have short lifetimes (5 minutes) to minimize compromise risk
- Are verified using public keys fetched from Control

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
  "aud": "https://api.inferadb.com",
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
| `iss`          | Control URL                                                                       | Must match configured `jwks_base_url` |
| `aud`          | Engine API URL                                                                    | Must match engine's expected audience |
| `exp`          | Expiration timestamp (Unix seconds)                                               | Must be in the future                 |
| `org_id`       | Organization ID (Snowflake ID as string)                                          | Verified against vault ownership      |
| `vault_id`     | Vault ID (Snowflake ID as string)                                                 | Determines policy evaluation context  |
| `vault_role`   | Permission level (`read`, `write`, `manage`, `admin`)                             | Enforces access control               |
| `scope`        | Space-separated API permissions                                                   | Determines allowed operations         |

## JWT Token Validation

The Engine API validates vault-scoped JWTs through a multi-step process:

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

The engine fetches the Ed25519 public key from Control's **internal API** (port 9091):

```http
GET /v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}
Authorization: Bearer {engine_jwt}
Host: localhost:9091
```

This request is made to Control's **internal port** (9091), not the public port (9090), as it's a privileged engine-to-control operation.

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

The engine validates all required claims:

```rust
// Check expiration
if token_data.claims.exp < current_timestamp {
    return Err("Token expired");
}

// Check issuer matches Control
if token_data.claims.iss != config.jwks_base_url {
    return Err("Invalid issuer");
}

// Check audience matches Engine API
if token_data.claims.aud != expected_audience {
    return Err("Invalid audience");
}

// Validate org_id and vault_id are present
if token_data.claims.org_id.is_none() || token_data.claims.vault_id.is_none() {
    return Err("Missing org_id or vault_id claim");
}
```

### 5. Verify Vault Ownership

The engine verifies that the vault belongs to the organization using Control's **privileged internal endpoint**:

```http
GET /internal/vaults/{vault_id}
Authorization: Bearer {engine_jwt}
Host: localhost:9091
```

This endpoint is served on Control's **internal API** (port 9091) and requires a valid engine JWT, but performs **no permission checks**. It's designed specifically for engine-to-control verification.

```rust
let vault = control_client.get_vault(vault_id).await?;

if vault.organization_id != org_id {
    return Err("Vault does not belong to organization");
}
```

**Caching**: Vault metadata is cached for 5 minutes (300 seconds).

### 6. Verify Organization Status

The engine checks that the organization is active using Control's **privileged internal endpoint**:

```http
GET /internal/organizations/{org_id}
Authorization: Bearer {engine_jwt}
Host: localhost:9091
```

This endpoint is served on Control's **internal API** (port 9091) and requires a valid engine JWT, but performs **no permission checks**. It's designed specifically for engine-to-control verification.

```rust
let org = control_client.get_organization(org_id).await?;

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

## Engine-to-Control Authentication

The Engine API makes authenticated requests to Control's **internal API** (port 9091) for verification operations. This uses **bidirectional JWT authentication** where the engine has its own Ed25519 keypair.

### Dual-Port Architecture

Control runs **two separate HTTP interfaces**:

- **Public API** (port 9090): User-facing API with session authentication and permission checks
- **Internal API** (port 9091): Engine-to-control API with JWT authentication for privileged operations

The Engine API **exclusively communicates with the internal API** on port 9091, which provides privileged endpoints without permission checks specifically for engine-to-control verification.

### Engine Identity

The engine configures its identity on startup:

```yaml
auth:
  enabled: true
  # IMPORTANT: Points to Control's INTERNAL port (9091), not public port (9090)
  control_url: "http://localhost:9091"
  # Engine identity for engine-to-control requests
  engine_identity_private_key: |
    -----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
    -----END PRIVATE KEY-----
  engine_identity_kid: "engine-primary-2024"
  engine_id: "inferadb-engine-prod-us-east-1"
```

**Development Mode**: If `engine_identity_private_key` is omitted, the engine auto-generates a keypair and logs the PEM-encoded private key at startup.

### Engine JWT Generation

When making requests to Control, the engine generates short-lived JWTs:

```rust
// Generate engine JWT (5 minute TTL)
let claims = EngineJwtClaims {
    iss: format!("inferadb-engine:{}", engine_id),
    sub: format!("engine:{}", engine_id),
    aud: control_url.to_string(),
    iat: now.timestamp(),
    exp: (now + Duration::minutes(5)).timestamp(),
    jti: uuid::new_v4().to_string(),
};

// Sign with engine's Ed25519 private key
let engine_jwt = encode(
    &Header::new(Algorithm::EdDSA),
    &claims,
    &EncodingKey::from_ed_pem(engine_identity.to_pem().as_bytes())?
)?;
```

### Engine JWKS Endpoint

The engine exposes its public key for Control to verify engine JWTs:

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
      "kid": "engine-primary-2024",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
      "use": "sig"
    }
  ]
}
```

### Control Privileged Endpoints

Control provides **dedicated engine-to-control endpoints** on the internal API (port 9091) for the Engine API's verification operations:

**Internal Endpoints** (port 9091, engine JWT required):

- `GET /internal/organizations/{org_id}` - Organization status lookup (no permission checks)
- `GET /internal/vaults/{vault_id}` - Vault ownership verification (no permission checks)

**Public Endpoints** (port 9090, session authentication required):

- `GET /v1/organizations/{org_id}` - Organization details (requires membership)
- `GET /v1/vaults/{vault_id}` - Vault details (requires vault access)

The Engine API **exclusively uses the internal endpoints** for verification, which are isolated from the public API and don't perform permission checks. This separation provides:

1. **Network Isolation**: Internal endpoints only accessible via internal network
2. **No Permission Bypass**: Public endpoints enforce permissions; internal endpoints are isolated
3. **Performance**: Privileged endpoints skip expensive permission checks
4. **Security**: Different attack surface for user vs engine requests

## Caching Strategy

The Engine API aggressively caches authentication data to minimize latency and Control load:

### Cache Configuration

| Data Type           | Cache TTL  | Capacity | Purpose                |
| ------------------- | ---------- | -------- | ---------------------- |
| Client Certificates | 15 minutes | 10,000   | Signature verification |
| Vault Metadata      | 5 minutes  | 10,000   | Ownership validation   |
| Organization Status | 5 minutes  | 1,000    | Active/suspended check |

### Cache Performance

**Expected Metrics**:

- **Cache Hit Rate**: >90% after warmup
- **Control Call Rate**: <10% of total requests
- **Token Validation Latency**:
  - Cache hit: <1ms
  - Cache miss: ~50-100ms (includes network roundtrip)

**Configuration** (`config.yaml`):

```yaml
auth:
  enabled: true
  # IMPORTANT: Points to Control's INTERNAL port (9091)
  control_url: "http://localhost:9091"
  control_timeout_ms: 5000

  # Cache TTLs
  cert_cache_ttl_seconds: 900 # 15 minutes
  control_cache_ttl_seconds: 300 # 5 minutes

  # Cache capacities
  cert_cache_max_capacity: 10000
  vault_cache_max_capacity: 10000
  org_cache_max_capacity: 1000
```

### Cache Trade-offs

**Benefits**:

- Continued operation during temporary Control outages
- Sub-millisecond authentication for cached credentials
- Reduced load on Control (10x reduction)

**Trade-offs**:

- Certificate revocation propagation: up to 15 minutes
- Vault deletion propagation: up to 5 minutes
- Organization suspension propagation: up to 5 minutes

**Immediate Revocation**: For immediate revocation, restart the engine to clear all caches.

## Security Considerations

### Token Lifetimes

**Vault Access Tokens (JWTs)**: 5 minutes (300 seconds)

- Very short lifetime minimizes impact of token compromise
- Automatically refreshed by clients before expiration
- Limits attack window to 5 minutes maximum

**Engine JWTs**: 5 minutes (300 seconds)

- Short-lived for engine-to-control requests
- Generated on-demand for each verification call
- Reduces impact of engine key compromise

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

The engine enforces strict multi-tenant isolation:

1. **Cross-Vault Protection**: Clients can only access vaults owned by their organization
2. **Cross-Organization Protection**: Vaults from different organizations are completely isolated
3. **Vault Ownership Verification**: Every request verifies vault belongs to the token's organization
4. **Relationship Isolation**: Relationships written to vault A are invisible in vault B

### Organization Suspension

When an organization is suspended:

1. **Immediate**: Control marks organization as suspended
2. **Delayed (5 min)**: Engine cache expires, new requests fail
3. **Existing Tokens**: Valid JWTs continue working until expiration (max 5 min)

### Certificate Revocation

When a certificate is revoked:

1. **Immediate**: Control removes certificate from database
2. **Delayed (15 min)**: Engine cache expires
3. **New Tokens**: Cannot be generated (Control rejects)
4. **Existing Tokens**: Valid JWTs continue working until expiration (max 5 min)

**Total Revocation Time**: Max 15 minutes (cache TTL) + 5 minutes (JWT expiration) = 20 minutes

### Best Practices

**DO**:

- Use HTTPS/TLS for all communication in production
- Monitor authentication failure rates (`inferadb_engine_auth_failures_total`)
- Monitor cache hit rates (`inferadb_engine_auth_cache_hit_rate`)
- Set appropriate cache TTLs based on security requirements
- Implement alerting for auth failures >5% over 5 minutes

**DON'T**:

- Expose Control to public internet
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
2. Certificate not found in Control
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
4. Control is unreachable

**Solutions**:

```bash
# Verify vault exists
curl -X GET http://localhost:8081/v1/vaults/$VAULT_ID \
  -H "Authorization: Bearer $SESSION_ID"

# Verify organization ID matches
# vault.organization_id should equal org_id claim in JWT

# Check engine logs for Control errors
grep "control" /var/log/inferadb/engine.log
```

### Problem: High latency on first request

**Symptoms**:

- First request takes 100-200ms
- Subsequent requests take <10ms

**Cause**: Cold cache - engine fetches certificate, vault, and organization data

**Solution**: This is expected behavior. Performance improves after warmup:

```text
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

# Check engine logs for specific error
tail -f /var/log/inferadb/engine.log | grep -i "auth"
```

### Debugging Checklist

When authentication fails, verify in order:

- [ ] Control is running and healthy (`curl http://localhost:9090/health`)
- [ ] Engine configuration points to correct Control URL
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
token:
  enabled: true

mesh:
  url: "http://localhost:8081"
```

### Production Configuration

```yaml
# Engine identity (for engine-to-control requests)
pem: |
  -----BEGIN PRIVATE KEY-----
  MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
  -----END PRIVATE KEY-----

token:
  enabled: true
  jwks_url: "https://control.example.com/.well-known/jwks.json"
  clock_skew_seconds: 30

mesh:
  url: "https://control.example.com"
```

### Environment Variables

Configuration can also be set via environment variables:

```bash
# Token validation
export INFERADB__ENGINE__TOKEN__ENABLED=true
export INFERADB__ENGINE__TOKEN__JWKS_URL=https://control.example.com/.well-known/jwks.json
export INFERADB__ENGINE__TOKEN__CLOCK_SKEW_SECONDS=30

# Control mesh connection
export INFERADB__ENGINE__MESH__URL=https://control.example.com

# Engine identity (Ed25519 private key for engine-to-control auth)
export INFERADB__ENGINE__PEM="-----BEGIN PRIVATE KEY-----..."
```

### Metrics

Monitor these Prometheus metrics for authentication health:

```promql
# Authentication metrics
inferadb_engine_auth_validations_total          # Total auth validations
inferadb_engine_auth_failures_total             # Failed authentications
inferadb_engine_auth_cache_hits_total          # Cache hits (should be >90%)
inferadb_engine_auth_cache_misses_total        # Cache misses
inferadb_engine_auth_control_api_calls_total # Control calls
inferadb_engine_auth_validation_duration_seconds # Validation latency

# Cache metrics
inferadb_engine_auth_cert_cache_size           # Current cert cache size
inferadb_engine_auth_vault_cache_size          # Current vault cache size
inferadb_engine_auth_org_cache_size            # Current org cache size
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
- `WARN`: Cache misses, Control errors
- `ERROR`: Authentication failures, configuration errors

## Further Reading

- [Control Authentication Flow](../../control/docs/Authentication.md) - Complete authentication architecture
- [Engine Configuration Guide](../guides/configuration.md) - Detailed configuration options
- [Multi-Tenancy Architecture](../architecture/multi-tenancy.md) - Deep dive on vault isolation
- [Security Hardening Guide](../security/hardening.md) - Production security checklist
