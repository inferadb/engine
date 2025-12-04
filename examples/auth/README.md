# Authentication Examples

This directory contains complete authentication examples in multiple programming languages.

## Examples

- [Python Example](python_example.py) - Python 3.8+
- [Node.js Example](nodejs_example.js) - Node.js 16+
- [Rust Example](rust_example.rs) - Rust 1.85+
- [Go Example](go_example.go) - Go 1.20+
- [cURL Example](curl_example.sh) - Bash script using cURL

## Prerequisites

### InferaDB Services Running

Both services must be running:

```bash
# Terminal 1: Management API
cd management
make run
# Runs on http://localhost:8081

# Terminal 2: InferaDB Server
cd server
mise run dev
# Runs on http://localhost:8080
```

### Language-Specific Dependencies

**Python:**

```bash
pip install requests PyJWT cryptography
```

**Node.js:**

```bash
npm install jose node-fetch uuid
```

**Rust:**

```bash
# Dependencies in Cargo.toml
# No additional installation needed
```

**Go:**

```bash
go get github.com/golang-jwt/jwt/v5
go get github.com/google/uuid
```

**cURL:**

```bash
# jq recommended for JSON parsing
brew install jq  # macOS
apt-get install jq  # Ubuntu/Debian
```

## Running the Examples

### Python

```bash
# Option 1: Set environment variables
export USER_EMAIL="test@example.com"
export USER_PASSWORD="TestPassword123!"
python3 python_example.py

# Option 2: Interactive (will prompt for credentials)
python3 python_example.py
```

### Node.js

```bash
# Option 1: Set environment variables
export USER_EMAIL="test@example.com"
export USER_PASSWORD="TestPassword123!"
node nodejs_example.js

# Option 2: Uses default test credentials
node nodejs_example.js
```

### Rust

```bash
cargo run --bin rust_auth_example
```

### Go

```bash
go run go_example.go
```

### cURL

```bash
chmod +x curl_example.sh
./curl_example.sh
```

## What the Examples Demonstrate

Each example shows the complete authentication flow:

1. **User Registration/Login**
   - Register a new user with the management API
   - Login to get a session token

2. **Vault Creation**
   - Create a vault for data isolation
   - Get account ID for JWT claims

3. **Ed25519 Key Generation**
   - Generate Ed25519 public/private key pair
   - Export public key in base64 format

4. **Client Registration**
   - Create client credentials
   - Register Ed25519 public key as a certificate
   - Get certificate KID for JWT signing

5. **JWT Generation**
   - Create JWT with required claims
   - Sign with Ed25519 private key
   - Include KID in JWT header

6. **Server API Calls**
   - Evaluate permissions with authentication
   - Write relationships with authentication
   - Handle authentication errors

## Environment Variables

All examples support these environment variables:

| Variable             | Description          | Default                       |
| -------------------- | -------------------- | ----------------------------- |
| `MANAGEMENT_API_URL` | Management API URL   | `http://localhost:8081`       |
| `SERVER_URL`         | InferaDB server URL  | `http://localhost:8080`       |
| `USER_EMAIL`         | User email for login | Prompts or uses test email    |
| `USER_PASSWORD`      | User password        | Prompts or uses test password |

## Common Issues

### 401 Unauthorized

**Problem:** Invalid JWT signature

**Solution:**

- Ensure you're signing with the correct Ed25519 private key
- Verify the public key was registered correctly
- Check that the KID in JWT header matches the registered certificate

### 403 Forbidden

**Problem:** Vault access denied

**Solution:**

- Verify the vault UUID in JWT claims exists
- Ensure the vault belongs to your organization
- Check that the account UUID is correct

### 503 Service Unavailable

**Problem:** Cannot reach management API

**Solution:**

- Verify management API is running: `curl http://localhost:8081/health`
- Check the `MANAGEMENT_API_URL` environment variable
- Ensure network connectivity

## Next Steps

After running the examples, you can:

1. **Modify the examples** to fit your use case
2. **Integrate into your application** using the patterns shown
3. **Explore additional endpoints** in the [API documentation](../../api/README.md)
4. **Read the authentication guide** for [detailed security best practices](../../docs/authentication.md)

## Example Output

```text
============================================================
InferaDB Authentication Example (Python)
============================================================

✓ Logged in: test@example.com
  Session ID: sess_770e8400e29b41d4a716446655440002
✓ Vault created: Example Vault a3b4c5d6
  Vault ID: 880e8400-e29b-41d4-a716-446655440003
  Account ID: 990e8400-e29b-41d4-a716-446655440004
✓ Ed25519 key pair generated
  Public key (base64): 3q2+7w==...
✓ Client created: Example Client e7f8g9h0
  Client ID: aa0e8400-e29b-41d4-a716-446655440005
✓ Certificate registered: Example Certificate i1j2k3l4
  Certificate ID: bb0e8400-e29b-41d4-a716-446655440006
  KID: org-660e8400-client-aa0e8400-cert-bb0e8400

============================================================
Authentication Setup Complete!
============================================================

✓ JWT generated (expires in 5 minutes)
  Scopes: read, write

JWT Token (first 100 chars):
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6Im9yZy02NjBlODQwMC1jbGllbnQtYWEwZTg0MDAtY2VydC1i...

============================================================
Example: Evaluate Permission
============================================================

✓ Server call: POST /v1/evaluate
  Status: 200
Response: {
  "results": [
    {
      "decision": "deny",
      "context": {}
    }
  ]
}

============================================================
Example: Write Relationship
============================================================

✓ Server call: POST /v1/relationships/write
  Status: 200
Response: {
  "written": 1
}

============================================================
Example Complete!
============================================================
```

## Additional Resources

- [Authentication Guide](../../docs/authentication.md) - Comprehensive authentication documentation
- [API Reference](../../api/README.md) - Complete API documentation
- [Configuration Guide](../../docs/guides/configuration.md) - Server configuration options
- [Quick Start](../../README.md#quick-start) - Get started quickly
