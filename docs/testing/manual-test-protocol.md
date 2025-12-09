# Manual Test Protocol: Engine-Control Authentication Integration

This document provides a comprehensive manual testing protocol for validating the Engine-Control authentication integration. Use this protocol to verify that all authentication features are working correctly before deployment.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Test Environment Setup](#test-environment-setup)
- [Test Protocol](#test-protocol)
- [Validation Checklist](#validation-checklist)
- [Troubleshooting](#troubleshooting)
- [Test Results Template](#test-results-template)

## Prerequisites

### Required Tools

- [mise](https://mise.jdx.dev/) - Development environment manager
- [jq](https://stedolan.github.io/jq/) - JSON processor for command-line
- [curl](https://curl.se/) - HTTP client
- [Python 3.8+](https://www.python.org/) with pip (for JWT generation examples)
- [Docker](https://www.docker.com/) and Docker Compose (optional, for isolated testing)

### Required Python Packages

```bash
pip install requests PyJWT cryptography
```

### Environment Variables

```bash
export CONTROL_API_URL="http://localhost:8081"
export ENGINE_URL="http://localhost:8080"
export TEST_USER_EMAIL="test-$(date +%s)@example.com"
export TEST_USER_PASSWORD="TestPassword123!"
```

## Test Environment Setup

### Option 1: Local Development Environment

#### Step 1: Start Control

```bash
cd control
make run
# Control starts on http://localhost:8081
# Wait for "Server listening on 0.0.0.0:8081"
```

Verify Control is running:

```bash
curl http://localhost:8081/health
# Expected: {"status":"healthy"}
```

#### Step 2: Start InferaDB Engine

```bash
cd engine
mise run dev
# Engine starts on http://localhost:8080
# Wait for "Engine listening on 127.0.0.1:8080"
```

Verify Engine is running:

```bash
curl http://localhost:8080/health
# Expected: {"status":"ok"}
```

### Option 2: Docker Compose Environment

```bash
# From repository root
docker-compose up -d foundationdb control engine
docker-compose ps
# All services should be "healthy"
```

## Test Protocol

### Test 1: User Registration and Organization Creation

**Objective**: Verify user can register and organization is automatically created.

**Steps**:

1. Register a new user:

```bash
curl -X POST $CONTROL_API_URL/v1/auth/register \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Test User\",
    \"email\": \"$TEST_USER_EMAIL\",
    \"password\": \"$TEST_USER_PASSWORD\",
    \"accept_tos\": true
  }" | jq .
```

1. Save the response:

```bash
# Expected response:
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Test User",
  "email": "test-1234567890@example.com",
  "organization_id": "660e8400-e29b-41d4-a716-446655440001",
  "created_at": "2025-01-19T10:00:00Z"
}
```

1. Record values:

```bash
export USER_ID="<id from response>"
export ORG_ID="<organization_id from response>"
```

**Expected Results**:

- ✅ HTTP 200 OK response
- ✅ User ID returned (UUID format)
- ✅ Organization ID returned (UUID format)
- ✅ Email matches input
- ✅ Name matches input

**Failure Scenarios to Test**:

- Duplicate email returns 409 Conflict
- Invalid email format returns 400 Bad Request
- Password too short returns 400 Bad Request

---

### Test 2: User Login and Session Creation

**Objective**: Verify user can log in and receive a session token.

**Steps**:

1. Login with registered user:

```bash
curl -X POST $CONTROL_API_URL/v1/auth/login \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$TEST_USER_EMAIL\",
    \"password\": \"$TEST_USER_PASSWORD\"
  }" | jq .
```

1. Save session ID:

```bash
# Expected response:
{
  "session_id": "sess_770e8400e29b41d4a716446655440002",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}

export SESSION_ID="<session_id from response>"
```

**Expected Results**:

- ✅ HTTP 200 OK response
- ✅ Session ID returned (starts with "sess\_")
- ✅ User ID matches registration

**Failure Scenarios to Test**:

- Wrong password returns 401 Unauthorized
- Non-existent user returns 401 Unauthorized

---

### Test 3: Vault Creation

**Objective**: Verify vault can be created with proper isolation.

**Steps**:

1. Create a vault:

```bash
curl -X POST $CONTROL_API_URL/v1/vaults \
  -H "Authorization: Bearer $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Test Vault $(date +%s)\",
    \"organization_id\": \"$ORG_ID\"
  }" | jq .
```

1. Save vault and account IDs:

```bash
# Expected response:
{
  "id": "880e8400-e29b-41d4-a716-446655440003",
  "name": "Test Vault 1234567890",
  "organization_id": "660e8400-e29b-41d4-a716-446655440001",
  "account_id": "990e8400-e29b-41d4-a716-446655440004",
  "created_at": "2025-01-19T10:05:00Z"
}

export VAULT_ID="<id from response>"
export ACCOUNT_ID="<account_id from response>"
```

**Expected Results**:

- ✅ HTTP 200 OK response
- ✅ Vault ID returned (UUID format)
- ✅ Account ID returned (UUID format)
- ✅ Organization ID matches

**Failure Scenarios to Test**:

- Invalid session returns 401 Unauthorized
- Missing organization_id returns 400 Bad Request

---

### Test 4: Client Credentials Creation

**Objective**: Verify client can be created for service authentication.

**Steps**:

1. Create a client:

```bash
curl -X POST $CONTROL_API_URL/v1/organizations/$ORG_ID/clients \
  -H "Authorization: Bearer $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Test Client $(date +%s)\"
  }" | jq .
```

1. Save client ID:

```bash
# Expected response:
{
  "id": "aa0e8400-e29b-41d4-a716-446655440005",
  "name": "Test Client 1234567890",
  "organization_id": "660e8400-e29b-41d4-a716-446655440001",
  "created_at": "2025-01-19T10:10:00Z"
}

export CLIENT_ID="<id from response>"
```

**Expected Results**:

- ✅ HTTP 200 OK response
- ✅ Client ID returned (UUID format)
- ✅ Organization ID matches

---

### Test 5: Ed25519 Certificate Registration

**Objective**: Verify Ed25519 public key can be registered for JWT signing.

**Steps**:

1. Generate Ed25519 key pair (Python):

```python
# Save as generate_keys.py
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import base64

# Generate key pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Export keys
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key_bytes = public_key.public_bytes_raw()
public_key_b64 = base64.b64encode(public_key_bytes).decode()

print(f"Private key (save to private_key.pem):")
print(private_bytes.decode())
print(f"\nPublic key (base64): {public_key_b64}")
```

```bash
python3 generate_keys.py
# Save output
```

1. Register certificate:

```bash
export PUBLIC_KEY_B64="<base64_public_key from above>"

curl -X POST $CONTROL_API_URL/v1/organizations/$ORG_ID/clients/$CLIENT_ID/certificates \
  -H "Authorization: Bearer $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Test Certificate $(date +%s)\",
    \"public_key\": \"$PUBLIC_KEY_B64\"
  }" | jq .
```

1. Save certificate KID:

```bash
# Expected response:
{
  "id": "bb0e8400-e29b-41d4-a716-446655440006",
  "name": "Test Certificate 1234567890",
  "kid": "org-660e8400-client-aa0e8400-cert-bb0e8400",
  "public_key": "...",
  "created_at": "2025-01-19T10:15:00Z"
}

export CERT_KID="<kid from response>"
export CERT_ID="<id from response>"
```

**Expected Results**:

- ✅ HTTP 200 OK response
- ✅ Certificate ID returned
- ✅ KID in format: `org-{org_id}-client-{client_id}-cert-{cert_id}`
- ✅ Public key matches input

---

### Test 6: JWT Generation and Signing

**Objective**: Verify JWT can be generated and signed with Ed25519 private key.

**Steps**:

1. Generate JWT (Python):

```python
# Save as generate_jwt.py
import jwt
import uuid
import datetime
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Load private key from PEM file
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# Get values from environment
import os
client_id = os.getenv('CLIENT_ID')
vault_id = os.getenv('VAULT_ID')
account_id = os.getenv('ACCOUNT_ID')
cert_kid = os.getenv('CERT_KID')
control_url = os.getenv('CONTROL_API_URL')
engine_url = os.getenv('ENGINE_URL')

# Create claims
now = datetime.datetime.now(datetime.timezone.utc)
claims = {
    "iss": f"{control_url}/v1",
    "sub": f"client:{client_id}",
    "aud": engine_url,
    "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
    "iat": int(now.timestamp()),
    "jti": str(uuid.uuid4()),
    "vault": vault_id,
    "account": account_id,
    "scope": "read write"
}

# Sign JWT
token = jwt.encode(
    claims,
    private_key,
    algorithm="EdDSA",
    headers={"kid": cert_kid}
)

print(token)
```

```bash
export JWT_TOKEN=$(python3 generate_jwt.py)
echo "JWT Token (first 100 chars): ${JWT_TOKEN:0:100}..."
```

**Expected Results**:

- ✅ JWT token generated successfully
- ✅ Token has three parts separated by dots (header.payload.signature)
- ✅ Token can be decoded (but not yet validated)

---

### Test 7: Authenticated Request to Engine

**Objective**: Verify Engine accepts JWT and validates it against Control.

**Steps**:

1. Make authenticated request to evaluate endpoint:

```bash
curl -X POST $ENGINE_URL/v1/evaluate \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [{
      "subject": "user:alice",
      "resource": "document:readme",
      "permission": "viewer"
    }]
  }' | jq .
```

**Expected Results**:

- ✅ HTTP 200 OK response
- ✅ Result contains `{"results": [{"decision": "deny"}]}` (no relationships exist yet)
- ✅ No authentication errors

**Failure Scenarios to Test**:

- Request without Authorization header returns 401
- Request with malformed JWT returns 401
- Request with expired JWT returns 401

---

### Test 8: Write and Verify Relationships

**Objective**: Verify authenticated write operations work correctly.

**Steps**:

1. Write a relationship:

```bash
curl -X POST $ENGINE_URL/v1/relationships/write \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "relationships": [{
      "resource": "document:readme",
      "relation": "viewer",
      "subject": "user:alice"
    }]
  }' | jq .
```

1. Verify the relationship:

```bash
curl -X POST $ENGINE_URL/v1/evaluate \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [{
      "subject": "user:alice",
      "resource": "document:readme",
      "permission": "viewer"
    }]
  }' | jq .
```

**Expected Results**:

- ✅ Write returns HTTP 200 OK
- ✅ Evaluate now returns `{"decision": "allow"}`
- ✅ Data is isolated to the vault specified in JWT

---

### Test 9: Vault Isolation Validation

**Objective**: Verify vault isolation prevents cross-vault data access.

**Steps**:

1. Create a second vault:

```bash
curl -X POST $CONTROL_API_URL/v1/vaults \
  -H "Authorization: Bearer $SESSION_ID" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Second Vault $(date +%s)\",
    \"organization_id\": \"$ORG_ID\"
  }" | jq .

export VAULT2_ID="<id from response>"
```

1. Generate JWT for second vault:

```python
# Modify generate_jwt.py to use VAULT2_ID
# Generate new token
export JWT_TOKEN2=$(python3 generate_jwt.py)
```

1. Try to read data from vault 1 using vault 2 token:

```bash
curl -X POST $ENGINE_URL/v1/evaluate \
  -H "Authorization: Bearer $JWT_TOKEN2" \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [{
      "subject": "user:alice",
      "resource": "document:readme",
      "permission": "viewer"
    }]
  }' | jq .
```

**Expected Results**:

- ✅ Second vault returns `{"decision": "deny"}` (data not visible)
- ✅ Vaults are completely isolated
- ✅ No cross-vault data leakage

---

### Test 10: Certificate Revocation

**Objective**: Verify certificate deletion prevents JWT validation.

**Steps**:

1. Delete the certificate:

```bash
curl -X DELETE $CONTROL_API_URL/v1/organizations/$ORG_ID/clients/$CLIENT_ID/certificates/$CERT_ID \
  -H "Authorization: Bearer $SESSION_ID" | jq .
```

1. Wait for cache to expire (or skip cache by restarting server):

```bash
# Option 1: Wait 15 minutes (cert_cache_ttl_seconds)
sleep 900

# Option 2: Restart server to clear caches
# Ctrl+C in server terminal, then restart
```

1. Try to use the revoked certificate:

```bash
curl -X POST $ENGINE_URL/v1/evaluate \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [{
      "subject": "user:alice",
      "resource": "document:readme",
      "permission": "viewer"
    }]
  }' | jq .
```

**Expected Results**:

- ✅ HTTP 401 Unauthorized after cache expiration
- ✅ Error message indicates invalid certificate or signature

---

### Test 11: Logs Verification

**Objective**: Verify authentication events are logged correctly.

**Steps**:

1. Check Engine logs for authentication success:

```bash
# In Engine terminal, look for:
grep "authentication_success" logs/engine.log
```

1. Check for structured log fields:

```bash
# Expected log entry structure:
{
  "level": "info",
  "event": "authentication_success",
  "vault_id": "880e8400-...",
  "client_id": "aa0e8400-...",
  "organization_id": "660e8400-...",
  "method": "jwt",
  "timestamp": "2025-01-19T10:20:00Z"
}
```

**Expected Results**:

- ✅ Authentication success events logged
- ✅ Authentication failure events logged (with reasons)
- ✅ All relevant context included (vault_id, client_id, org_id)

---

### Test 12: Metrics Verification

**Objective**: Verify authentication metrics are exposed correctly.

**Steps**:

1. Fetch metrics endpoint:

```bash
curl $ENGINE_URL/metrics | grep inferadb_engine_auth
```

1. Check for key metrics:

```bash
# Expected metrics:
inferadb_engine_auth_validations_total{method="jwt",result="success"} 5
inferadb_engine_auth_cache_hits_total{cache_type="certificate"} 4
inferadb_engine_auth_cache_misses_total{cache_type="certificate"} 1
inferadb_engine_auth_control_api_calls_total{endpoint="/v1/vaults",status="200"} 1
inferadb_engine_auth_validation_duration_seconds_bucket{method="jwt",le="0.01"} 5
```

**Expected Results**:

- ✅ Metrics endpoint returns HTTP 200 OK
- ✅ Authentication validation counters present
- ✅ Cache hit/miss counters present
- ✅ Control API call counters present
- ✅ Validation duration histogram present

---

### Test 13: Cross-Organization Isolation

**Objective**: Verify organizations are completely isolated.

**Steps**:

1. Register a second user (different organization):

```bash
export TEST_USER2_EMAIL="test2-$(date +%s)@example.com"

curl -X POST $CONTROL_API_URL/v1/auth/register \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Test User 2\",
    \"email\": \"$TEST_USER2_EMAIL\",
    \"password\": \"$TEST_USER_PASSWORD\",
    \"accept_tos\": true
  }" | jq .

export ORG2_ID="<organization_id from response>"
```

1. Try to access organization 1's resources:

```bash
# Login as user 2, create vault, client, certificate
# Generate JWT with org2's client but org1's vault ID
# Attempt to evaluate permissions
```

**Expected Results**:

- ✅ HTTP 403 Forbidden
- ✅ Error indicates vault not found or access denied
- ✅ No data leakage between organizations

---

### Test 14: Performance and Cache Effectiveness

**Objective**: Verify caching improves performance.

**Steps**:

1. Make 100 sequential requests:

```bash
for i in {1..100}; do
  curl -X POST $ENGINE_URL/v1/evaluate \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "evaluations": [{
        "subject": "user:alice",
        "resource": "document:readme",
        "permission": "viewer"
      }]
    }' -o /dev/null -s -w "%{time_total}\n"
done | awk '{sum+=$1; count++} END {print "Average: " sum/count " seconds"}'
```

1. Check cache metrics:

```bash
curl $ENGINE_URL/metrics | grep inferadb_engine_auth_cache_hits_total
curl $ENGINE_URL/metrics | grep inferadb_engine_auth_cache_misses_total
```

1. Calculate cache hit rate:

```bash
# Cache hit rate should be > 90% after first request
```

**Expected Results**:

- ✅ Average latency < 50ms per request
- ✅ Cache hit rate > 90% after warmup
- ✅ Control call rate < 10%

---

### Test 15: Graceful Degradation

**Objective**: Verify server continues operating with cached data when Control is unavailable.

**Steps**:

1. Make a successful request to populate cache:

```bash
curl -X POST $ENGINE_URL/v1/evaluate \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [{
      "subject": "user:alice",
      "resource": "document:readme",
      "permission": "viewer"
    }]
  }' | jq .
```

1. Stop Control:

```bash
# Ctrl+C in Control terminal
```

1. Make another request (within cache TTL):

```bash
curl -X POST $ENGINE_URL/v1/evaluate \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "evaluations": [{
      "subject": "user:alice",
      "resource": "document:readme",
      "permission": "viewer"
    }]
  }' | jq .
```

1. Restart Control:

```bash
cd control && make run
```

**Expected Results**:

- ✅ Cached requests succeed (HTTP 200 OK)
- ✅ New certificate requests fail gracefully (HTTP 503)
- ✅ Engine logs warning about Control unavailability
- ✅ Engine resumes normal operation when Control returns

---

## Validation Checklist

Use this checklist to track test completion:

### Basic Functionality

- [ ] User registration works
- [ ] User login works
- [ ] Vault creation works
- [ ] Client creation works
- [ ] Certificate registration works
- [ ] JWT generation works
- [ ] Authenticated requests succeed

### Security & Isolation

- [ ] JWT signature validation works
- [ ] Expired JWTs are rejected
- [ ] Invalid JWTs are rejected
- [ ] Vault isolation prevents cross-vault access
- [ ] Organization isolation prevents cross-org access
- [ ] Certificate revocation prevents access (after cache expiry)

### Performance & Reliability

- [ ] Cache hit rate > 90%
- [ ] Average latency < 50ms
- [ ] Control call rate < 10%
- [ ] Engine handles Control downtime gracefully
- [ ] No memory leaks during extended operation

### Observability

- [ ] Authentication success logged
- [ ] Authentication failure logged with reasons
- [ ] Metrics endpoint accessible
- [ ] All expected metrics present
- [ ] Metrics values are accurate

### Error Handling

- [ ] 401 Unauthorized for invalid auth
- [ ] 403 Forbidden for cross-org/vault access
- [ ] 503 Service Unavailable when Control down
- [ ] Error messages don't leak sensitive information

## Troubleshooting

### Issue: "401 Unauthorized" on valid request

**Possible Causes**:

1. JWT signature invalid
2. Certificate not registered or deleted
3. JWT expired

**Resolution**:

```bash
# Verify JWT is not expired
echo $JWT_TOKEN | cut -d'.' -f2 | base64 -d | jq .exp
date +%s  # Compare with current timestamp

# Verify certificate exists
curl $CONTROL_API_URL/v1/organizations/$ORG_ID/clients/$CLIENT_ID/certificates \
  -H "Authorization: Bearer $SESSION_ID" | jq .

# Generate fresh JWT
python3 generate_jwt.py
```

### Issue: "403 Forbidden - Vault not found"

**Possible Causes**:

1. Vault UUID incorrect in JWT
2. Vault belongs to different organization
3. Vault was deleted

**Resolution**:

```bash
# Verify vault exists
curl $CONTROL_API_URL/v1/vaults/$VAULT_ID \
  -H "Authorization: Bearer $SESSION_ID" | jq .

# Check vault ownership matches JWT claims
# vault.organization_id should match client.organization_id
```

### Issue: "503 Service Unavailable"

**Possible Causes**:

1. Control is down
2. Network connectivity issues

**Resolution**:

```bash
# Check Control health
curl $CONTROL_API_URL/health

# Check Engine logs for connectivity errors
grep "control" logs/engine.log
```

### Issue: Tests pass initially, then fail

**Possible Causes**:

1. JWT expired (5-minute TTL)
2. Session expired
3. Cache expired and Control down

**Resolution**:

```bash
# Generate fresh JWT
python3 generate_jwt.py

# Re-login to get new session
curl -X POST $CONTROL_API_URL/v1/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"$TEST_USER_EMAIL\", \"password\": \"$TEST_USER_PASSWORD\"}"
```

## Test Results Template

Use this template to document test results:

```markdown
# Authentication Integration Test Results

**Test Date**: YYYY-MM-DD
**Tester**: Your Name
**Environment**: Local / Docker / Staging
**Control Version**: vX.Y.Z
**Engine Version**: vX.Y.Z

## Test Summary

| Test                             | Status  | Duration | Notes              |
| -------------------------------- | ------- | -------- | ------------------ |
| Test 1: User Registration        | ✅ Pass | 150ms    | -                  |
| Test 2: User Login               | ✅ Pass | 120ms    | -                  |
| Test 3: Vault Creation           | ✅ Pass | 80ms     | -                  |
| Test 4: Client Creation          | ✅ Pass | 75ms     | -                  |
| Test 5: Certificate Registration | ✅ Pass | 90ms     | -                  |
| Test 6: JWT Generation           | ✅ Pass | 10ms     | -                  |
| Test 7: Authenticated Request    | ✅ Pass | 45ms     | -                  |
| Test 8: Write Relationships      | ✅ Pass | 55ms     | -                  |
| Test 9: Vault Isolation          | ✅ Pass | 40ms     | -                  |
| Test 10: Certificate Revocation  | ✅ Pass | 15s      | Cache wait time    |
| Test 11: Logs Verification       | ✅ Pass | N/A      | -                  |
| Test 12: Metrics Verification    | ✅ Pass | N/A      | -                  |
| Test 13: Cross-Org Isolation     | ✅ Pass | 60ms     | -                  |
| Test 14: Performance             | ✅ Pass | 35ms avg | 95% cache hit rate |
| Test 15: Graceful Degradation    | ✅ Pass | N/A      | -                  |

## Issues Found

None / List any issues discovered

## Recommendations

None / List any recommendations for improvements

## Approval

- [ ] All tests passed
- [ ] All issues resolved or documented
- [ ] Ready for deployment

**Approved by**: **\*\***\_\_\_**\*\***
**Date**: **\*\***\_\_\_**\*\***
```

## Automated Test Script

For convenience, use this automated script to run all tests:

```bash
#!/bin/bash
# Save as: run_manual_tests.sh

set -e

# Load environment
source test_env.sh

echo "=== InferaDB Authentication Integration Tests ==="
echo ""

# Test 1: Registration
echo "Test 1: User Registration..."
# [Add curl commands from above]

# Test 2: Login
echo "Test 2: User Login..."
# [Add curl commands from above]

# ... Continue for all tests

echo ""
echo "=== All Tests Complete ==="
```

## Next Steps

After completing this manual test protocol:

1. Document any issues found in GitHub Issues
2. Update test results in the template
3. Share results with the team
4. Proceed with automated integration tests
5. Schedule performance testing
6. Plan production deployment

## Related Documentation

- [Authentication Guide](../authentication.md) - Comprehensive authentication documentation
- [Configuration Guide](../guides/configuration.md) - Engine configuration options
- [API Documentation](../../api/README.md) - Complete API reference
- [Integration Tests](../../tests/integration/README.md) - Automated integration tests
