# InferaDB Authentication Guide

This guide explains how authentication works in InferaDB and how developers can authenticate with the server.

## Table of Contents

- [Overview](#overview)
- [Authentication Methods](#authentication-methods)
- [How to Create JWTs](#how-to-create-jwts)
- [Configuration](#configuration)
- [Token Validation](#token-validation)
- [OAuth 2.0 Support](#oauth-20-support)
- [Replay Protection](#replay-protection)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

InferaDB uses **stateless, cryptographically verifiable JWT (JSON Web Token) authentication** for all API requests. The server validates JWTs using public keys fetched from JWKS (JSON Web Key Set) endpoints.

### Supported Authentication Methods

1. **Private-Key JWT (RFC 7523)** - For tenant SDKs and CLIs
2. **OAuth 2.0 Bearer Tokens (RFC 6749)** - For dashboards and enterprise authentication
3. **OpenID Connect (OIDC)** - Automatic JWKS discovery
4. **Internal Service JWT** - For control plane communication

### Key Features

- ✅ **Asymmetric cryptography only** (EdDSA, RS256 only)
- ✅ **Symmetric algorithms rejected** (HS256, etc.)
- ✅ **JWKS caching** for performance
- ✅ **OIDC Discovery** (RFC 8414)
- ✅ **Replay protection** with Redis
- ✅ **Scope validation** for authorization
- ✅ **Audience enforcement** for security
- ✅ **Tenant isolation** via claims

## Authentication Methods

### Method 1: Tenant Private-Key JWT

**Use case**: SDK authentication, CLI tools, service-to-service

Tenants sign their own JWTs using Ed25519 or RSA private keys. InferaDB fetches the corresponding public key from the tenant's JWKS endpoint to verify signatures.

**Required JWT Claims**:

```json
{
  "iss": "tenant:acme",
  "sub": "tenant:acme",
  "aud": "https://api.inferadb.com/evaluate",
  "exp": 1730908800,
  "iat": 1730905200,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "scope": "inferadb.check inferadb.write"
}
```

**Algorithm**: EdDSA (Ed25519) or RS256

### Method 2: OAuth 2.0 Access Tokens

**Use case**: Dashboard authentication, enterprise SSO

OAuth 2.0 access tokens issued by an identity provider (e.g., Auth0, Okta, Keycloak).

**Required JWT Claims**:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user@example.com",
  "aud": "https://api.inferadb.com/evaluate",
  "exp": 1730908800,
  "iat": 1730905200,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "scope": "inferadb.check inferadb.write",
  "tenant_id": "acme"
}
```

**Algorithm**: RS256 or EdDSA (depends on IdP)

### Method 3: Internal Service JWT

**Use case**: Control plane to PDP communication

Internal JWTs signed by the control plane for service-to-service authentication.

**Required JWT Claims**:

```json
{
  "iss": "inferadb-control-plane",
  "sub": "service:control-plane",
  "aud": "inferadb-pdp",
  "exp": 1730908800,
  "iat": 1730905200,
  "scope": "internal:admin"
}
```

## How to Create JWTs

### Using Ed25519 (EdDSA)

Ed25519 is **recommended** for its security and performance.

#### 1. Generate Ed25519 Key Pair

```bash
# Using OpenSSL
openssl genpkey -algorithm Ed25519 -out private_key.pem

# Extract public key
openssl pkey -in private_key.pem -pubout -out public_key.pem
```

#### 2. Create JWKS Endpoint

Convert your public key to JWK format and host it at a JWKS endpoint:

```json
{
  "keys": [
    {
      "kty": "OKP",
      "use": "sig",
      "kid": "acme-key-001",
      "alg": "EdDSA",
      "crv": "Ed25519",
      "x": "<base64url-encoded-public-key>"
    }
  ]
}
```

**Host this at**: `https://your-domain.com/jwks/tenant-name.json`

#### 3. Sign JWT in Your Application

**Python Example**:

```python
from jwcrypto import jwk, jwt
import json
import time
import uuid

# Load private key
with open('private_key.pem', 'rb') as f:
    private_key = jwk.JWK.from_pem(f.read())

# Create claims
claims = {
    "iss": "tenant:acme",
    "sub": "tenant:acme",
    "aud": "https://api.inferadb.com/evaluate",
    "exp": int(time.time()) + 3600,  # 1 hour expiration
    "iat": int(time.time()),
    "jti": str(uuid.uuid4()),
    "scope": "inferadb.check inferadb.write"
}

# Create JWT
token = jwt.JWT(
    header={"alg": "EdDSA", "kid": "acme-key-001"},
    claims=claims
)
token.make_signed_token(private_key)

# Get compact serialization
jwt_string = token.serialize()
print(f"JWT: {jwt_string}")
```

**Node.js Example**:

```javascript
const jose = require("jose");
const fs = require("fs");
const crypto = require("crypto");

async function createJWT() {
  // Load private key
  const privateKey = await jose.importPKCS8(
    fs.readFileSync("private_key.pem", "utf8"),
    "EdDSA"
  );

  // Create claims
  const claims = {
    iss: "tenant:acme",
    sub: "tenant:acme",
    aud: "https://api.inferadb.com/evaluate",
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    scope: "inferadb.check inferadb.write",
  };

  // Sign JWT
  const jwt = await new jose.SignJWT(claims)
    .setProtectedHeader({ alg: "EdDSA", kid: "acme-key-001" })
    .sign(privateKey);

  console.log(`JWT: ${jwt}`);
  return jwt;
}

createJWT();
```

**Rust Example**:

```rust
use ed25519_dalek::SigningKey;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    jti: String,
    scope: String,
}

fn create_jwt(signing_key: &SigningKey) -> Result<String, Box<dyn std::error::Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let claims = Claims {
        iss: "tenant:acme".to_string(),
        sub: "tenant:acme".to_string(),
        aud: "https://api.inferadb.com/evaluate".to_string(),
        exp: now + 3600, // 1 hour
        iat: now,
        jti: uuid::Uuid::new_v4().to_string(),
        scope: "inferadb.check inferadb.write".to_string(),
    };

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("acme-key-001".to_string());

    // Convert Ed25519 key to PEM format
    let key_bytes = signing_key.to_bytes();
    let encoding_key = EncodingKey::from_ed_der(&key_bytes);

    let token = encode(&header, &claims, &encoding_key)?;
    Ok(token)
}
```

### Using RSA (RS256)

#### 1. Generate RSA Key Pair

```bash
# Generate 2048-bit RSA private key
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

#### 2. Create JWKS with RSA

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "acme-key-001",
      "alg": "RS256",
      "n": "<base64url-encoded-modulus>",
      "e": "<base64url-encoded-exponent>"
    }
  ]
}
```

#### 3. Sign JWT with RS256

**Python Example**:

```python
from jwcrypto import jwk, jwt
import json
import time
import uuid

# Load RSA private key
with open('private_key.pem', 'rb') as f:
    private_key = jwk.JWK.from_pem(f.read())

claims = {
    "iss": "tenant:acme",
    "sub": "tenant:acme",
    "aud": "https://api.inferadb.com/evaluate",
    "exp": int(time.time()) + 3600,
    "iat": int(time.time()),
    "jti": str(uuid.uuid4()),
    "scope": "inferadb.check inferadb.write"
}

token = jwt.JWT(
    header={"alg": "RS256", "kid": "acme-key-001"},
    claims=claims
)
token.make_signed_token(private_key)
jwt_string = token.serialize()
```

### Making Authenticated Requests

Once you have a JWT, include it in the `Authorization` header:

```bash
# Using curl
curl -X POST https://api.inferadb.com/v1/evaluate \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [
      {
        "subject": "user:alice",
        "resource": "doc:1",
        "permission": "viewer"
      }
    ]
  }'
```

**Python Requests**:

```python
import requests

jwt_token = "eyJ..."  # Your JWT

response = requests.post(
    "https://api.inferadb.com/v1/evaluate",
    headers={
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json"
    },
    json={
        "evaluations": [
            {
                "subject": "user:alice",
                "resource": "doc:1",
                "permission": "viewer"
            }
        ]
    }
)

print(response.json())
```

**JavaScript Fetch**:

```javascript
const jwt = "eyJ..."; // Your JWT

fetch("https://api.inferadb.com/v1/evaluate", {
  method: "POST",
  headers: {
    Authorization: `Bearer ${jwt}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    evaluations: [
      {
        subject: "user:alice",
        resource: "doc:1",
        permission: "viewer",
      },
    ],
  }),
})
  .then((response) => response.json())
  .then((data) => console.log(data));
```

## Configuration

### Server Configuration

Configure authentication in your `config.yaml` or via environment variables:

```yaml
auth:
  # Enable/disable authentication
  enabled: true

  # JWKS cache TTL (seconds)
  jwks_cache_ttl: 300

  # Scope validation is per-endpoint (inferadb.check, inferadb.write, etc.)
  # Scopes are validated based on the endpoint being accessed

  # Replay protection (requires Redis)
  replay_protection: true
  redis_url: "redis://localhost:6379"

  # JWKS base URL for tenant keys
  jwks_base_url: "https://your-domain.com/jwks"

  # Clock skew tolerance (seconds)
  clock_skew_seconds: 30

  # Maximum token age (seconds from iat)
  max_token_age_seconds: 3600

  # Issuer validation
  issuer_allowlist:
    - "tenant:*"
    - "https://auth.example.com"

  # OAuth configuration (optional)
  oauth_introspection_endpoint: "https://auth.example.com/oauth/introspect"
  oauth_introspection_client_id: "inferadb-server"
  oauth_introspection_client_secret: "<secret>"

  # OIDC discovery cache (seconds)
  oidc_discovery_cache_ttl: 86400 # 24 hours

  # Introspection result cache (seconds)
  introspection_cache_ttl: 300 # 5 minutes
```

### Environment Variables

All configuration can be set via environment variables with the `INFERADB__` prefix:

```bash
# Enable authentication
export INFERADB__AUTH__ENABLED=true

# JWKS configuration
export INFERADB__AUTH__JWKS_BASE_URL=https://your-domain.com/jwks
export INFERADB__AUTH__JWKS_CACHE_TTL=300

# Audience validation (always enforced)
export INFERADB__AUTH__AUDIENCE=https://api.inferadb.com/evaluate

# Replay protection
export INFERADB__AUTH__REPLAY_PROTECTION=true
export INFERADB__AUTH__REDIS_URL=redis://localhost:6379

# Clock skew tolerance
export INFERADB__AUTH__CLOCK_SKEW_SECONDS=30

# OAuth introspection (optional)
export INFERADB__AUTH__OAUTH_INTROSPECTION_ENDPOINT=https://auth.example.com/oauth/introspect
export INFERADB__AUTH__OAUTH_INTROSPECTION_CLIENT_ID=inferadb-server
export INFERADB__AUTH__OAUTH_INTROSPECTION_CLIENT_SECRET=<secret>
```

### Disabling Authentication (Development Only)

For local development and testing, you can disable authentication:

```bash
export INFERADB__AUTH__ENABLED=false
```

**⚠️ WARNING**: Never disable authentication in production!

## Token Validation

### Validation Process

When a request arrives, InferaDB performs the following validation steps:

1. **Extract Bearer Token** from `Authorization` header
2. **Decode JWT Header** to get `kid` and `alg`
3. **Fetch JWKS** from cache or fetch from issuer
4. **Verify Signature** using public key from JWKS
5. **Validate Claims**:
   - `exp` - Token not expired
   - `iat` - Token issued time reasonable
   - `nbf` - Token not used before this time (if present)
   - `iss` - Issuer is allowed
   - `aud` - Audience matches configuration
   - `scope` - Required scopes present
6. **Replay Protection** (if enabled) - Check JTI not seen before
7. **Extract Tenant ID** from claims
8. **Create Auth Context** for request

### JWKS Resolution

InferaDB fetches JWKS (JSON Web Key Sets) to validate JWT signatures:

#### For Tenant JWTs

```text
issuer: "tenant:acme"
JWKS URL: {jwks_base_url}/acme.json
Example: https://your-domain.com/jwks/acme.json
```

#### For OAuth JWTs (with OIDC Discovery)

```text
issuer: "https://auth.example.com"
Discovery: https://auth.example.com/.well-known/openid-configuration
JWKS URL: (from discovery document)
```

#### For Internal JWTs

```text
issuer: "inferadb-control-plane"
JWKS: Loaded from file or environment variable
Path: /etc/inferadb/internal-jwks.json
```

### Caching

- **JWKS Cache**: 5 minutes (default)
- **OIDC Discovery Cache**: 24 hours (default)
- **Introspection Cache**: 5 minutes (default)

Caching reduces latency and load on authentication servers.

## OAuth 2.0 Support

### OIDC Discovery

InferaDB supports OpenID Connect Discovery (RFC 8414) for automatic JWKS endpoint discovery:

```rust
// Automatic discovery from issuer
issuer: "https://auth.example.com"

// InferaDB fetches:
// 1. https://auth.example.com/.well-known/openid-configuration
// 2. Extracts jwks_uri from response
// 3. Fetches public keys from jwks_uri
```

### Token Introspection

For opaque OAuth tokens (non-JWT), InferaDB supports OAuth 2.0 Token Introspection (RFC 7662):

```yaml
auth:
  oauth_introspection_endpoint: "https://auth.example.com/oauth/introspect"
  oauth_introspection_client_id: "inferadb-server"
  oauth_introspection_client_secret: "<secret>"
```

When introspection is configured:

1. InferaDB sends token to introspection endpoint
2. Receives token metadata (active, scopes, tenant_id, etc.)
3. Caches result for 5 minutes
4. Uses metadata for authorization decisions

## Replay Protection

### What is Replay Protection?

Replay protection prevents attackers from reusing captured JWTs. Each JWT must be used only once, even if it hasn't expired.

### How It Works

1. **JTI Requirement**: Every JWT must include a unique `jti` (JWT ID) claim
2. **First Use**: InferaDB marks the JTI as "seen" in Redis
3. **Subsequent Use**: If the same JTI is seen again, request is rejected
4. **Expiration**: JTI entries automatically expire when the token expires

### Implementations

#### Redis (Production)

**Recommended for multi-node deployments**:

```yaml
auth:
  replay_protection: true
  redis_url: "redis://localhost:6379"
```

Features:

- ✅ Atomic SET NX operations
- ✅ Automatic TTL based on token expiration
- ✅ Shared across all InferaDB nodes
- ✅ Survives pod restarts

#### In-Memory (Development)

**Not suitable for production clusters**:

```yaml
auth:
  replay_protection: true
  # No redis_url = falls back to in-memory
```

Limitations:

- ❌ Not shared across nodes
- ❌ Lost on restart
- ❌ Only for single-node development

### Generating Unique JTIs

**Python**:

```python
import uuid
jti = str(uuid.uuid4())
```

**JavaScript**:

```javascript
const crypto = require("crypto");
const jti = crypto.randomUUID();
```

**Rust**:

```rust
use uuid::Uuid;
let jti = Uuid::new_v4().to_string();
```

## Security Best Practices

### 1. Use Asymmetric Algorithms Only

✅ **Allowed**: EdDSA, RS256
❌ **Rejected**: HS256, HS384, HS512 (symmetric), ES256

InferaDB explicitly rejects symmetric algorithms to prevent secret key leakage.

### 2. Keep Private Keys Secure

- **Never** commit private keys to version control
- **Never** share private keys between tenants
- **Never** include private keys in client applications
- Use **key management systems** (AWS KMS, HashiCorp Vault, etc.)
- Rotate keys regularly

### 3. Set Short Expiration Times

```json
{
  "exp": <now + 3600>,  // 1 hour is recommended
  "iat": <now>
}
```

Shorter expiration times reduce the window for token misuse.

### 4. Use Replay Protection

Always enable replay protection in production:

```yaml
auth:
  replay_protection: true
  redis_url: "redis://localhost:6379"
```

### 5. Validate Audience

Audience validation is always enforced and must validate with "<https://api.inferadb.com>".

This prevents tokens intended for other services from being accepted.

### 6. Use Issuer Allowlists

Restrict which issuers are accepted:

```yaml
auth:
  issuer_allowlist:
    - "tenant:*"
    - "https://auth.example.com"
```

### 7. Scope Validation

Scope validation is per-endpoint based on the JWT's `scope` claim. Each endpoint requires specific scopes:

- **`/v1/evaluate`**: Requires `inferadb.check`
- **`/v1/relationships/write`**: Requires `inferadb.write`
- **`/v1/relationships`**: Requires `inferadb.read` or `inferadb.list`
- **`/v1/expand`**: Requires `inferadb.expand`

Ensure your JWTs include the appropriate scopes for the endpoints your application uses.

### 8. Configure Clock Skew Tolerance

Account for clock drift between systems:

```yaml
auth:
  clock_skew_seconds: 30 # 30 seconds tolerance
```

### 9. Monitor Authentication Events

InferaDB logs all authentication events:

```json
{
  "event": "auth_success",
  "tenant_id": "acme",
  "sub": "tenant:acme",
  "method": "tenant_jwt",
  "scopes": ["inferadb.check", "inferadb.write"]
}
```

Set up alerts for:

- Repeated authentication failures
- Token expiration errors
- Replay attack attempts
- Invalid signature errors

## Troubleshooting

### Error: "Invalid signature"

**Cause**: JWT signature doesn't match public key

**Solutions**:

1. Verify you're using the correct private key
2. Ensure JWKS endpoint is accessible
3. Check `kid` in JWT header matches JWKS
4. Verify algorithm matches (EdDSA, RS256, etc.)

```bash
# Test JWKS endpoint
curl https://your-domain.com/jwks/tenant-name.json

# Verify JWT header
echo "<jwt>" | cut -d'.' -f1 | base64 -d
```

### Error: "Token expired"

**Cause**: Current time is past the `exp` claim

**Solutions**:

1. Generate a new token with fresh `exp` time
2. Check system clocks are synchronized
3. Increase `clock_skew_seconds` if needed

```bash
# Check token expiration
echo "<jwt>" | cut -d'.' -f2 | base64 -d | jq '.exp'

# Compare with current time
date +%s
```

### Error: "Missing required scope"

**Cause**: Token doesn't include required scopes

**Solutions**:

1. Add required scopes to JWT claims:

   ```json
   {
     "scope": "inferadb.check inferadb.write"
   }
   ```

2. Update server configuration to accept your scopes
3. Check scope validation is correctly configured

### Error: "Audience mismatch"

**Cause**: Token `aud` claim doesn't match server configuration

**Solutions**:

1. Ensure JWT `aud` matches server `audience`:

   ```json
   {
     "aud": "https://api.inferadb.com/evaluate"
   }
   ```

2. Add audience to `allowed_audiences` list

### Error: "Replay attack detected"

**Cause**: JTI has been seen before

**Solutions**:

1. Generate a new JWT with a unique `jti`
2. Don't reuse tokens across multiple requests
3. Ensure `jti` is truly random (UUID v4)

```python
# Always generate new JTI
import uuid
jti = str(uuid.uuid4())  # Fresh UUID for each token
```

### Error: "Failed to fetch JWKS"

**Cause**: Cannot reach JWKS endpoint

**Solutions**:

1. Verify JWKS URL is correct
2. Check network connectivity
3. Ensure JWKS endpoint is accessible from InferaDB
4. Check firewall rules
5. Verify SSL certificates are valid

```bash
# Test JWKS from InferaDB pod
kubectl exec -it <inferadb-pod> -- curl https://your-domain.com/jwks/tenant.json
```

### Error: "Missing JTI claim"

**Cause**: Replay protection enabled but JWT has no `jti`

**Solutions**:

1. Add `jti` claim to JWT:

   ```json
   {
     "jti": "550e8400-e29b-41d4-a716-446655440000"
   }
   ```

2. Disable replay protection (NOT recommended)

### Debugging Authentication

Enable debug logging:

```yaml
observability:
  log_level: "debug"
```

Or via environment variable:

```bash
export INFERADB__OBSERVABILITY__LOG_LEVEL=debug
```

This will log detailed authentication information:

```json
{
  "level": "DEBUG",
  "message": "JWT validation starting",
  "issuer": "tenant:acme",
  "subject": "tenant:acme",
  "algorithm": "EdDSA",
  "kid": "acme-key-001"
}
```

## API Endpoint Access

Different endpoints require different scopes:

| Endpoint                        | Required Scopes  |
| ------------------------------- | ---------------- |
| `POST /v1/evaluate`             | `inferadb.check` |
| `POST /v1/expand`               | `inferadb.check` |
| `POST /v1/relationships/write`  | `inferadb.write` |
| `POST /v1/relationships/delete` | `inferadb.write` |
| `POST /v1/relationships/list`   | `inferadb.check` |
| `POST /v1/resources/list`       | `inferadb.check` |
| `POST /v1/subjects/list`        | `inferadb.check` |
| `GET /health/live`              | None (public)    |
| `GET /health/ready`             | None (public)    |
| `GET /health/startup`           | None (public)    |

To access all endpoints, include both scopes:

```json
{
  "scope": "inferadb.check inferadb.write"
}
```

## Example: Complete Authentication Flow

### 1. Generate Key Pair

```bash
openssl genpkey -algorithm Ed25519 -out private_key.pem
openssl pkey -in private_key.pem -pubout -out public_key.pem
```

### 2. Create JWKS Endpoint

```json
{
  "keys": [
    {
      "kty": "OKP",
      "use": "sig",
      "kid": "acme-key-001",
      "alg": "EdDSA",
      "crv": "Ed25519",
      "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }
  ]
}
```

Host at: `https://your-domain.com/jwks/acme.json`

### 3. Configure InferaDB

```yaml
auth:
  enabled: true
  jwks_base_url: "https://your-domain.com/jwks"
  audience: "https://api.inferadb.com/evaluate"
  allowed_audiences:
    - "https://api.inferadb.com/evaluate"
  replay_protection: true
  redis_url: "redis://localhost:6379"
```

### 4. Create JWT in Application

```python
from jwcrypto import jwk, jwt
import time
import uuid

# Load private key
with open('private_key.pem', 'rb') as f:
    key = jwk.JWK.from_pem(f.read())

# Create JWT
claims = {
    "iss": "tenant:acme",
    "sub": "tenant:acme",
    "aud": "https://api.inferadb.com/evaluate",
    "exp": int(time.time()) + 3600,
    "iat": int(time.time()),
    "jti": str(uuid.uuid4()),
    "scope": "inferadb.check inferadb.write"
}

token = jwt.JWT(header={"alg": "EdDSA", "kid": "acme-key-001"}, claims=claims)
token.make_signed_token(key)
jwt_string = token.serialize()
```

### 5. Make Authenticated Request

```python
import requests

response = requests.post(
    "https://api.inferadb.com/v1/evaluate",
    headers={"Authorization": f"Bearer {jwt_string}"},
    json={"evaluations": [{"subject": "user:alice", "resource": "doc:1", "permission": "viewer"}]}
)

print(response.json())  # {"results": [{"decision": "allow"}]}
```

## Summary

InferaDB authentication provides:

- ✅ **Stateless verification** - No database lookups for auth
- ✅ **Cryptographic security** - Asymmetric key validation
- ✅ **Tenant isolation** - Each tenant has unique keys
- ✅ **Standard protocols** - JWT, OAuth 2.0, OIDC
- ✅ **Replay protection** - Prevent token reuse attacks
- ✅ **Flexible configuration** - Environment-based config
- ✅ **High performance** - JWKS caching, minimal overhead

For production deployments:

1. Use **EdDSA (Ed25519)** for signing
2. Enable **replay protection** with Redis
3. Set **short token expiration** (1 hour)
4. Configure **allowed audiences**
5. Use **scope-based authorization**
6. Monitor **authentication metrics**
7. Keep **private keys secure**

## See Also

- [Configuration Reference](../guides/configuration.md)
- [Deployment Guide](../guides/deployment.md)
- [Observability Guide](../operations/observability/README.md)
- [Security Best Practices](security.md)
