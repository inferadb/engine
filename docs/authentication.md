# Authentication Guide

This guide covers InferaDB's authentication architecture, token management, and security best practices.

## Table of Contents

- [Overview](#overview)
- [Authentication Architecture](#authentication-architecture)
- [Getting Started](#getting-started)
- [JWT Token Structure](#jwt-token-structure)
- [Client Credentials Management](#client-credentials-management)
- [Vault Isolation](#vault-isolation)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)

## Overview

InferaDB uses **Ed25519-signed JWT tokens** for authentication. The system is designed around:

- **Management API**: Source of truth for users, organizations, vaults, and client credentials
- **Server**: Policy evaluation engine that validates tokens and enforces vault isolation
- **Stateless Authentication**: No session state - all information in JWT claims
- **Multi-Tenant Isolation**: Complete data isolation using Accounts and Vaults

### Key Concepts

- **Organization**: Top-level entity representing a company or team
- **Account**: Billing and resource grouping entity (one per organization)
- **Vault**: Isolated namespace for relationship data and policies
- **Client**: Service identity with cryptographic credentials for API access
- **Certificate**: Ed25519 public key registered for a client

## Authentication Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Client Application                       │
│                                                              │
│  1. Generate JWT with Ed25519 private key                   │
│  2. Include vault UUID in claims                            │
│  3. Sign with certificate's private key                     │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       │ Authorization: Bearer <JWT>
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    InferaDB Server                           │
│                                                              │
│  1. Extract kid from JWT header                             │
│  2. Fetch Ed25519 public key (cached 15min)                 │
│  3. Verify JWT signature                                    │
│  4. Validate claims (exp, iss, aud, vault, etc.)            │
│  5. Verify vault ownership (cached 5min)                    │
│  6. Verify organization status (cached 5min)                │
│  7. Execute request in vault context                        │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       │ GET /v1/vaults/{vault_id}
                       │ GET /v1/organizations/{org_id}/clients/{client_id}/certificates/{cert_id}
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   Management API                             │
│                                                              │
│  - Validate vault exists and belongs to organization        │
│  - Return Ed25519 public key for signature verification     │
│  - Check organization status (active/suspended)             │
└─────────────────────────────────────────────────────────────┘
```

### Caching Strategy

InferaDB aggressively caches authentication data to minimize management API calls:

| Data Type | Cache TTL | Purpose |
|-----------|-----------|---------|
| Ed25519 Public Keys | 15 minutes | Signature verification |
| Vault Metadata | 5 minutes | Ownership validation |
| Organization Status | 5 minutes | Active/suspended check |

**Benefits:**
- >90% cache hit rate after warmup
- <10% management API call rate under steady load
- Continued operation during temporary management API outages

**Trade-offs:**
- Certificate revocation takes up to 15 minutes to propagate
- Vault deletion takes up to 5 minutes to propagate
- For immediate revocation, restart the server to clear caches

## Getting Started

### Prerequisites

1. **Management API Running**: Authentication requires the management API
   ```bash
   cd management
   make run
   # Management API runs on http://localhost:8081
   ```

2. **Ed25519 Key Pair**: You'll need to generate cryptographic keys
   ```python
   from cryptography.hazmat.primitives.asymmetric import ed25519
   import base64

   # Generate key pair
   private_key = ed25519.Ed25519PrivateKey.generate()
   public_key = private_key.public_key()

   # Export public key for certificate registration
   public_key_bytes = public_key.public_bytes_raw()
   public_key_b64 = base64.b64encode(public_key_bytes).decode()

   print(f"Public Key (Base64): {public_key_b64}")
   ```

### Step 1: Register User and Create Organization

```bash
# Register a new user
curl -X POST http://localhost:8081/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Alice Smith",
    "email": "alice@example.com",
    "password": "SecurePassword123!",
    "accept_tos": true
  }'

# Response:
# {
#   "id": "550e8400-e29b-41d4-a716-446655440000",
#   "name": "Alice Smith",
#   "email": "alice@example.com",
#   "organization_id": "660e8400-e29b-41d4-a716-446655440001",
#   "created_at": "2025-01-15T10:00:00Z"
# }
```

### Step 2: Login to Get Session

```bash
# Login
curl -X POST http://localhost:8081/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "SecurePassword123!"
  }'

# Response:
# {
#   "session_id": "sess_770e8400e29b41d4a716446655440002",
#   "user_id": "550e8400-e29b-41d4-a716-446655440000"
# }

export SESSION_ID="sess_770e8400e29b41d4a716446655440002"
export ORG_ID="660e8400-e29b-41d4-a716-446655440001"
```

### Step 3: Create Vault

```bash
# Create a vault
curl -X POST http://localhost:8081/v1/vaults \
  -H "Authorization: Bearer $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Vault",
    "organization_id": "'$ORG_ID'"
  }'

# Response:
# {
#   "id": "880e8400-e29b-41d4-a716-446655440003",
#   "name": "Production Vault",
#   "organization_id": "660e8400-e29b-41d4-a716-446655440001",
#   "account_id": "990e8400-e29b-41d4-a716-446655440004",
#   "created_at": "2025-01-15T10:05:00Z"
# }

export VAULT_ID="880e8400-e29b-41d4-a716-446655440003"
export ACCOUNT_ID="990e8400-e29b-41d4-a716-446655440004"
```

### Step 4: Create Client Credentials

```bash
# Create a client
curl -X POST http://localhost:8081/v1/organizations/$ORG_ID/clients \
  -H "Authorization: Bearer $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Service"
  }'

# Response:
# {
#   "id": "aa0e8400-e29b-41d4-a716-446655440005",
#   "name": "Production Service",
#   "organization_id": "660e8400-e29b-41d4-a716-446655440001",
#   "created_at": "2025-01-15T10:10:00Z"
# }

export CLIENT_ID="aa0e8400-e29b-41d4-a716-446655440005"
```

### Step 5: Register Certificate

```bash
# Register Ed25519 public key
curl -X POST http://localhost:8081/v1/organizations/$ORG_ID/clients/$CLIENT_ID/certificates \
  -H "Authorization: Bearer $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Certificate",
    "public_key": "<base64_encoded_ed25519_public_key>"
  }'

# Response:
# {
#   "id": "bb0e8400-e29b-41d4-a716-446655440006",
#   "name": "Production Certificate",
#   "kid": "org-660e8400-client-aa0e8400-cert-bb0e8400",
#   "public_key": "...",
#   "created_at": "2025-01-15T10:15:00Z"
# }

export CERT_KID="org-660e8400-client-aa0e8400-cert-bb0e8400"
```

### Step 6: Generate and Use JWT

```python
import jwt
import uuid
import datetime
from cryptography.hazmat.primitives.asymmetric import ed25519

# Load your private key (from Step 0)
private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

# Create JWT claims
claims = {
    "iss": "http://localhost:8081/v1",
    "sub": f"client:{CLIENT_ID}",
    "aud": "http://localhost:8080",
    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
    "iat": datetime.datetime.now(datetime.timezone.utc),
    "jti": str(uuid.uuid4()),
    "vault": VAULT_ID,
    "account": ACCOUNT_ID,
    "scope": "read write"
}

# Sign JWT
token = jwt.encode(
    claims,
    private_key,
    algorithm="EdDSA",
    headers={"kid": CERT_KID}
)

print(f"JWT Token: {token}")
```

```bash
# Use the token with InferaDB server
curl -X POST http://localhost:8080/v1/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [{
      "subject": "user:alice",
      "resource": "document:readme",
      "permission": "viewer"
    }]
  }'
```

## JWT Token Structure

### Header

```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "org-{org_id}-client-{client_id}-cert-{cert_id}"
}
```

**Fields:**
- `alg`: Must be `EdDSA` (Ed25519 signature algorithm)
- `typ`: Must be `JWT`
- `kid`: **Required** - Key ID in format `org-{org_id}-client-{client_id}-cert-{cert_id}`

### Claims (Payload)

```json
{
  "iss": "http://localhost:8081/v1",
  "sub": "client:aa0e8400-e29b-41d4-a716-446655440005",
  "aud": "http://localhost:8080",
  "exp": 1736939100,
  "iat": 1736938800,
  "jti": "cc0e8400-e29b-41d4-a716-446655440007",
  "vault": "880e8400-e29b-41d4-a716-446655440003",
  "account": "990e8400-e29b-41d4-a716-446655440004",
  "scope": "read write"
}
```

**Required Claims:**

| Claim | Type | Description | Example |
|-------|------|-------------|---------|
| `iss` | String | Issuer - Management API URL + `/v1` | `http://localhost:8081/v1` |
| `sub` | String | Subject - Format: `client:{client_id}` | `client:aa0e8400-...` |
| `aud` | String | Audience - InferaDB server URL | `http://localhost:8080` |
| `exp` | Integer | Expiration timestamp (Unix seconds) | `1736939100` |
| `iat` | Integer | Issued at timestamp (Unix seconds) | `1736938800` |
| `jti` | String | JWT ID - Unique identifier (UUID v4) | `cc0e8400-...` |
| `vault` | String | Vault UUID | `880e8400-...` |
| `account` | String | Account UUID | `990e8400-...` |
| `scope` | String | Space-separated scopes | `read write` |

### Validation Rules

The server validates tokens according to these rules:

1. **Signature Verification**: Ed25519 signature must be valid using public key from certificate
2. **Expiration**: Current time must be before `exp` claim
3. **Issuer**: `iss` must match configured management API URL
4. **Audience**: `aud` must match server's URL
5. **Vault Ownership**: Vault must belong to the organization that owns the client
6. **Account Ownership**: Account must own the vault
7. **Organization Status**: Organization must be active (not suspended)
8. **Token Reuse**: `jti` must be unique (when replay protection enabled)

### Token Lifetime Recommendations

| Environment | Recommended TTL | Rationale |
|-------------|-----------------|-----------|
| Development | 1-5 minutes | Fast iteration, less risk |
| Staging | 5 minutes | Match production behavior |
| Production | 5 minutes | Balance security and performance |
| CI/CD | 2 minutes | Short-lived automated processes |

**Why Short-Lived Tokens?**
- Minimizes window for token theft/replay attacks
- Reduces impact of leaked tokens
- Simpler than complex revocation infrastructure
- Forces clients to implement proper token refresh

## Client Credentials Management

### Creating Multiple Certificates per Client

A single client can have multiple certificates for key rotation:

```bash
# Create second certificate for rotation
curl -X POST http://localhost:8081/v1/organizations/$ORG_ID/clients/$CLIENT_ID/certificates \
  -H "Authorization: Bearer $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Certificate (New)",
    "public_key": "<new_base64_public_key>"
  }'
```

### Certificate Rotation Process

**Zero-Downtime Rotation:**

1. **Generate new key pair** in your application
2. **Register new certificate** via management API
3. **Deploy new key** to your application instances (gradual rollout)
4. **Wait 15 minutes** for old certificate to expire from cache
5. **Delete old certificate** via management API

```bash
# Delete old certificate
curl -X DELETE http://localhost:8081/v1/organizations/$ORG_ID/clients/$CLIENT_ID/certificates/$OLD_CERT_ID \
  -H "Authorization: Bearer $SESSION_ID"
```

### Client Deactivation

Deactivating a client immediately blocks all its certificates:

```bash
# Deactivate client
curl -X POST http://localhost:8081/v1/organizations/$ORG_ID/clients/$CLIENT_ID/deactivate \
  -H "Authorization: Bearer $SESSION_ID"
```

**Impact:**
- All JWTs signed by this client's certificates become invalid
- Takes up to 15 minutes to propagate (cache TTL)
- For immediate effect, restart the server

### Certificate Revocation

Delete individual certificates without affecting others:

```bash
# Revoke certificate
curl -X DELETE http://localhost:8081/v1/organizations/$ORG_ID/clients/$CLIENT_ID/certificates/$CERT_ID \
  -H "Authorization: Bearer $SESSION_ID"
```

**Propagation Time:**
- Certificate cache TTL: 15 minutes
- For immediate revocation: restart server or reduce `cert_cache_ttl_seconds`

## Vault Isolation

InferaDB enforces strict multi-tenant isolation at the vault level.

### Isolation Guarantees

1. **Cross-Vault Protection**: Clients can only access vaults owned by their organization
2. **Cross-Organization Protection**: Vaults from different organizations are completely isolated
3. **Account Ownership**: Vault must belong to the account specified in JWT
4. **Relationship Isolation**: Relationships written to vault A are invisible in vault B

### Example: Multi-Tenant SaaS Application

```
Organization A (Acme Corp)
├── Account: acct-acme
├── Vault: vault-acme-prod
│   ├── Relationships: document:123#viewer@user:alice
│   └── Policies: IPL schemas for Acme
└── Client: client-acme-backend
    └── Certificate: cert-acme-1

Organization B (Beta Inc)
├── Account: acct-beta
├── Vault: vault-beta-prod
│   ├── Relationships: document:123#viewer@user:bob
│   └── Policies: IPL schemas for Beta
└── Client: client-beta-backend
    └── Certificate: cert-beta-1
```

**Isolation in Action:**

```python
# Acme's JWT (vault: vault-acme-prod)
acme_token = generate_jwt(
    client_id="client-acme-backend",
    vault_id="vault-acme-prod",
    account_id="acct-acme"
)

# Beta's JWT (vault: vault-beta-prod)
beta_token = generate_jwt(
    client_id="client-beta-backend",
    vault_id="vault-beta-prod",
    account_id="acct-beta"
)

# Acme can check their document
response = check_permission(
    token=acme_token,
    subject="user:alice",
    resource="document:123",
    permission="viewer"
)
# Result: ALLOW (relationship exists in vault-acme-prod)

# Beta cannot see Acme's document (different vault)
response = check_permission(
    token=beta_token,
    subject="user:alice",
    resource="document:123",
    permission="viewer"
)
# Result: DENY (no relationship in vault-beta-prod)

# Acme cannot use Beta's vault (cross-org protection)
malicious_token = generate_jwt(
    client_id="client-acme-backend",  # Acme's client
    vault_id="vault-beta-prod",        # Beta's vault
    account_id="acct-beta"
)
# Result: 403 Forbidden (vault not owned by client's organization)
```

### Vault Deletion

When a vault is deleted:

1. **Immediate**: Management API marks vault as deleted
2. **5 minutes**: Server cache expires, new requests fail
3. **Eventually**: Background cleanup removes all vault data

**Best Practice**: Delete vault during maintenance window or after ensuring no active clients

## Security Best Practices

### 1. Private Key Management

**DO:**
- Generate Ed25519 keys using cryptographically secure libraries
- Store private keys in secret management systems (Vault, AWS Secrets Manager, etc.)
- Use environment variables or mounted secrets in containers
- Rotate keys every 90 days minimum

**DON'T:**
- Commit private keys to version control
- Share private keys between environments
- Hardcode keys in application code
- Store keys in log files or databases

### 2. Token Generation

**DO:**
- Generate fresh `jti` (JWT ID) for every token using UUID v4
- Set short expiration times (5 minutes recommended)
- Use UTC timestamps for `iat` and `exp`
- Include only necessary scopes in `scope` claim

**DON'T:**
- Reuse `jti` values (enables replay attacks)
- Set `exp` more than 15 minutes in the future
- Include sensitive data in JWT claims (they're not encrypted)
- Generate tokens client-side in web browsers

### 3. Certificate Management

**DO:**
- Use descriptive names for certificates (e.g., "Production-2025-Q1")
- Maintain certificate inventory in your CMDB
- Automate certificate rotation
- Monitor certificate expiration dates
- Delete unused certificates promptly

**DON'T:**
- Share certificates between environments
- Keep expired certificates registered
- Rely on manual rotation processes

### 4. Scope Management

**Current Scopes:**
- `read`: Permission to evaluate policies, expand relationships, list resources
- `write`: Permission to write/delete relationships

**Best Practice:**
```python
# Service that only checks permissions
readonly_token = generate_jwt(scopes=["read"])

# Service that manages relationships
admin_token = generate_jwt(scopes=["read", "write"])
```

### 5. Network Security

**DO:**
- Use TLS for all communication (HTTPS)
- Validate server certificates in production
- Implement rate limiting at API gateway
- Use VPC/private networks for management API

**DON'T:**
- Expose management API to public internet
- Disable TLS certificate validation
- Send tokens over unencrypted connections

### 6. Monitoring and Alerting

**Metrics to Monitor:**
- `infera_auth_failures_total` - Spike indicates attack or misconfiguration
- `infera_auth_cache_hit_rate` - Should be >90%
- `infera_auth_management_api_calls_total` - Should be <10% of request volume
- `infera_auth_validation_duration_seconds` - Should be <10ms p99

**Alert Conditions:**
- Auth failure rate >5% for 5 minutes
- Cache hit rate <80% for 10 minutes
- Management API call rate >20% for 10 minutes
- Management API errors >1% for 5 minutes

### 7. Incident Response

**Compromised Private Key:**
1. Immediately deactivate the client via management API
2. Restart InferaDB servers to clear caches
3. Generate new key pair
4. Register new certificate
5. Deploy new keys to all instances
6. Review audit logs for unauthorized access
7. Notify security team and affected customers

**Suspicious Activity:**
1. Check `infera_auth_failures_total` metrics
2. Review server logs for 401/403 responses
3. Correlate with management API audit logs
4. Identify affected clients/vaults
5. Rotate credentials if necessary

## Troubleshooting

### Problem: 401 Unauthorized - Invalid signature

**Symptoms:**
```json
{
  "error": "Unauthorized",
  "message": "Invalid token signature"
}
```

**Causes:**
1. JWT signed with wrong private key
2. Public key mismatch in certificate
3. Malformed JWT structure

**Solutions:**
```python
# Verify you're using the correct key pair
public_key_from_private = private_key.public_key()
public_key_bytes = public_key_from_private.public_bytes_raw()
public_key_b64 = base64.b64encode(public_key_bytes).decode()

print(f"Public key derived from private: {public_key_b64}")
print(f"Public key in certificate: {registered_public_key}")
# These must match exactly
```

### Problem: 403 Forbidden - Vault not found

**Symptoms:**
```json
{
  "error": "Forbidden",
  "message": "Vault not found or access denied"
}
```

**Causes:**
1. Vault UUID in JWT doesn't exist
2. Vault belongs to different organization
3. Vault was recently deleted (cache not expired)

**Solutions:**
```bash
# Verify vault exists and belongs to your organization
curl -X GET http://localhost:8081/v1/vaults/$VAULT_ID \
  -H "Authorization: Bearer $SESSION_ID"

# Check organization ID matches
# vault.organization_id should equal client.organization_id
```

### Problem: 403 Forbidden - Account mismatch

**Symptoms:**
```json
{
  "error": "Forbidden",
  "message": "Account does not own vault"
}
```

**Causes:**
1. Account UUID in JWT doesn't match vault's owner
2. Typo in account UUID

**Solutions:**
```bash
# Get vault details to find correct account
curl -X GET http://localhost:8081/v1/vaults/$VAULT_ID \
  -H "Authorization: Bearer $SESSION_ID"

# Use vault.account_id in JWT claims
```

### Problem: 503 Service Unavailable - Management API unreachable

**Symptoms:**
```json
{
  "error": "Service Unavailable",
  "message": "Cannot reach management API"
}
```

**Causes:**
1. Management API is down
2. Network connectivity issues
3. Incorrect `management_api_url` configuration

**Solutions:**
```bash
# Check management API health
curl http://localhost:8081/health

# Check server configuration
grep management_api_url /path/to/config.yaml

# If cached data exists, server will continue operating
# Otherwise, wait for management API to recover
```

### Problem: High latency on first request

**Symptoms:**
- First request takes 100-200ms
- Subsequent requests take <10ms

**Cause:** Cold cache - server fetches certificate and vault data from management API

**Solution:** This is expected behavior. Performance improves after warmup:
```
Request 1: 150ms (cache miss - fetch cert + vault)
Request 2: 5ms (cache hit)
Request 3: 5ms (cache hit)
...
Request 100: 5ms (cache hit)
```

### Problem: Tokens work, then suddenly fail

**Symptoms:**
- Tokens worked previously
- Now getting 401/403 errors
- No code changes

**Causes:**
1. Certificate was deleted
2. Client was deactivated
3. Vault was deleted
4. Organization was suspended
5. Cache expired after deletion

**Solutions:**
```bash
# Check client status
curl http://localhost:8081/v1/organizations/$ORG_ID/clients/$CLIENT_ID \
  -H "Authorization: Bearer $SESSION_ID"

# Check certificate status
curl http://localhost:8081/v1/organizations/$ORG_ID/clients/$CLIENT_ID/certificates/$CERT_ID \
  -H "Authorization: Bearer $SESSION_ID"

# Check organization status
curl http://localhost:8081/v1/organizations/$ORG_ID \
  -H "Authorization: Bearer $SESSION_ID"
```

### Debugging Checklist

When authentication fails, verify in order:

- [ ] Management API is running and healthy
- [ ] Server configuration points to correct management API URL
- [ ] JWT has valid structure (header, payload, signature)
- [ ] JWT header includes `kid` field
- [ ] JWT is signed with Ed25519 private key
- [ ] Public key in certificate matches private key
- [ ] All required claims are present (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `vault`, `account`, `scope`)
- [ ] Token is not expired (`exp` > current time)
- [ ] Vault UUID exists and belongs to client's organization
- [ ] Account UUID owns the vault
- [ ] Client is active (not deactivated)
- [ ] Certificate is registered and active
- [ ] Organization is active (not suspended)

## API Reference

### Management API Endpoints

**Base URL:** `http://localhost:8081/v1`

#### Authentication

```bash
# Register User
POST /auth/register
{
  "name": "Alice Smith",
  "email": "alice@example.com",
  "password": "SecurePass123!",
  "accept_tos": true
}

# Login
POST /auth/login
{
  "email": "alice@example.com",
  "password": "SecurePass123!"
}

# Logout
POST /auth/logout
Authorization: Bearer {session_id}
```

#### Organizations

```bash
# Get Organization
GET /organizations/{org_id}
Authorization: Bearer {session_id}

# Update Organization
PATCH /organizations/{org_id}
Authorization: Bearer {session_id}
{
  "name": "New Name"
}
```

#### Vaults

```bash
# Create Vault
POST /vaults
Authorization: Bearer {session_id}
{
  "name": "Production Vault",
  "organization_id": "{org_id}"
}

# List Vaults
GET /vaults?organization_id={org_id}
Authorization: Bearer {session_id}

# Get Vault
GET /vaults/{vault_id}
Authorization: Bearer {session_id}

# Delete Vault
DELETE /vaults/{vault_id}
Authorization: Bearer {session_id}
```

#### Clients

```bash
# Create Client
POST /organizations/{org_id}/clients
Authorization: Bearer {session_id}
{
  "name": "Production Service"
}

# List Clients
GET /organizations/{org_id}/clients
Authorization: Bearer {session_id}

# Get Client
GET /organizations/{org_id}/clients/{client_id}
Authorization: Bearer {session_id}

# Deactivate Client
POST /organizations/{org_id}/clients/{client_id}/deactivate
Authorization: Bearer {session_id}

# Delete Client
DELETE /organizations/{org_id}/clients/{client_id}
Authorization: Bearer {session_id}
```

#### Certificates

```bash
# Create Certificate
POST /organizations/{org_id}/clients/{client_id}/certificates
Authorization: Bearer {session_id}
{
  "name": "Production Cert",
  "public_key": "{base64_ed25519_public_key}"
}

# List Certificates
GET /organizations/{org_id}/clients/{client_id}/certificates
Authorization: Bearer {session_id}

# Get Certificate
GET /organizations/{org_id}/clients/{client_id}/certificates/{cert_id}
Authorization: Bearer {session_id}

# Delete Certificate
DELETE /organizations/{org_id}/clients/{client_id}/certificates/{cert_id}
Authorization: Bearer {session_id}
```

### InferaDB Server Endpoints

**Base URL:** `http://localhost:8080/v1`

**All endpoints require:** `Authorization: Bearer {jwt_token}`

```bash
# Evaluate Permissions
POST /evaluate
Authorization: Bearer {jwt_token}
{
  "evaluations": [{
    "subject": "user:alice",
    "resource": "document:readme",
    "permission": "viewer"
  }]
}

# Write Relationships
POST /relationships/write
Authorization: Bearer {jwt_token}
{
  "relationships": [{
    "resource": "document:readme",
    "relation": "viewer",
    "subject": "user:alice"
  }]
}

# Delete Relationships
POST /relationships/delete
Authorization: Bearer {jwt_token}
{
  "relationships": [{
    "resource": "document:readme",
    "relation": "viewer",
    "subject": "user:alice"
  }]
}

# Expand Relationships
POST /expand
Authorization: Bearer {jwt_token}
{
  "resource": "document:readme",
  "relation": "viewer"
}

# List Resources
POST /resources/list
Authorization: Bearer {jwt_token}
{
  "subject": "user:alice",
  "relation": "viewer",
  "resource_type": "document"
}

# List Subjects
POST /subjects/list
Authorization: Bearer {jwt_token}
{
  "resource": "document:readme",
  "relation": "viewer",
  "subject_type": "user"
}
```

### Metrics Endpoint

```bash
# Prometheus Metrics
GET /metrics

# Key auth metrics:
# infera_auth_cache_hits_total - Cache hits
# infera_auth_cache_misses_total - Cache misses
# infera_auth_failures_total - Authentication failures
# infera_auth_management_api_calls_total - Management API calls
# infera_auth_validation_duration_seconds - Validation latency
```

## Further Reading

- [Server Configuration Guide](../guides/configuration.md) - Detailed configuration options
- [Multi-Tenancy Architecture](../architecture/multi-tenancy.md) - Deep dive on isolation
- [API Documentation](../../api/README.md) - Complete API reference
- [OpenAPI Specification](../../api/openapi.yaml) - Machine-readable API spec
- [Security Hardening Guide](../security/hardening.md) - Production security checklist
