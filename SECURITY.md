# InferaDB Security Model

This document describes the authentication, authorization, and scope model for InferaDB.

## Table of Contents

1. [Authentication](#authentication)
2. [Authorization Scopes](#authorization-scopes)
3. [Multi-Tenancy](#multi-tenancy)
4. [Scope Hierarchy](#scope-hierarchy)
5. [API Endpoint Scope Requirements](#api-endpoint-scope-requirements)
6. [Known Vulnerabilities and Mitigations](#known-vulnerabilities-and-mitigations)
7. [Security Contacts](#security-contacts)

---

## Authentication

InferaDB supports multiple authentication methods:

### 1. Private-Key JWT (RFC 7523)

For tenant SDK/CLI authentication:

- Asymmetric algorithms only (EdDSA, RS256)
- Symmetric algorithms (HS256) are explicitly rejected
- Tokens must include `vault` and `account` claims

### 2. OAuth 2.0 Bearer Tokens (RFC 6749)

For dashboard and enterprise authentication:

- Requires JWKS endpoint for key validation
- Supports OIDC Discovery for configuration
- Tokens validated with asymmetric keys only

### 3. Internal Service JWT

For Control Plane → PDP authentication:

- EdDSA keys only
- Separate JWKS from tenant keys
- Admin-level permissions

**Security Notes:**

- Only asymmetric algorithms (EdDSA, RS256, RS384, RS512) are supported
- Symmetric algorithms are rejected for security reasons
- Replay protection available (in-memory or Redis)

---

## Authorization Scopes

All operations in InferaDB require specific scopes. Scopes follow the pattern `inferadb.<operation>`.

### Core Operation Scopes

#### `inferadb.check`

**Purpose:** Authorization checks and policy evaluation

**Grants access to:**

- `POST /v1/evaluate` - Check if subject has permission on resource
- `POST /v1/expand` - Expand relationship trees (alternative to `inferadb.expand`)
- `POST /v1/simulate` - Simulate policy evaluation
- AuthZEN `/access/v1/evaluation/evaluate` endpoint

**Example:**

```json
{
  "scope": "inferadb.check",
  "aud": "https://api.inferadb.com"
}
```

#### `inferadb.write`

**Purpose:** Create, update, and delete relationships

**Grants access to:**

- `POST /v1/relationships/write` - Batch write relationships
- `DELETE /v1/relationships/:id` - Delete single relationship
- `POST /v1/relationships/delete` - Bulk delete relationships

**Example:**

```json
{
  "scope": "inferadb.write",
  "vault": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### `inferadb.read`

**Purpose:** Read-only access to relationships

**Grants access to:**

- `GET /v1/relationships/:id` - Read single relationship
- `POST /v1/relationships/list` - List relationships

#### `inferadb.expand`

**Purpose:** Expand relationship trees

**Grants access to:**

- `POST /v1/expand` - Expand relationship trees and compute usersets

### Listing Scopes

#### `inferadb.list`

**Purpose:** Generic listing operations (primarily for AuthZEN compliance)

**Grants access to:**

- AuthZEN `/access/v1/search` endpoints
- Generic list operations

#### `inferadb.list-relationships`

**Purpose:** List relationships matching filters

**Grants access to:**

- `POST /v1/relationships/list` - List relationships with filters

#### `inferadb.list-subjects`

**Purpose:** List subjects for permissions

**Grants access to:**

- `POST /v1/subjects/list` - List subjects for a given resource and permission

#### `inferadb.list-resources`

**Purpose:** List accessible resources

**Grants access to:**

- `POST /v1/resources/list` - List resources accessible by a subject

### Real-Time and Simulation Scopes

#### `inferadb.watch`

**Purpose:** Subscribe to real-time relationship changes

**Grants access to:**

- `POST /v1/watch` - Subscribe to relationship change stream (Server-Sent Events)

#### `inferadb.simulate`

**Purpose:** Ephemeral policy evaluation without persisting relationships

**Grants access to:**

- `POST /v1/simulate` - Evaluate policies with temporary relationships

### Administrative Scopes

#### `inferadb.admin`

**Purpose:** Full administrative access (implies all other scopes)

**Grants access to:**

- **Account Management:**
  - `POST /v1/accounts` - Create accounts
  - `GET /v1/accounts` - List all accounts
  - `GET /v1/accounts/:id` - View any account
  - `PATCH /v1/accounts/:id` - Update accounts
  - `DELETE /v1/accounts/:id` - Delete accounts

- **Vault Management:**
  - `POST /v1/accounts/:account_id/vaults` - Create vaults for any account
  - `GET /v1/accounts/:account_id/vaults` - List vaults for any account
  - `GET /v1/vaults/:id` - View any vault
  - `PATCH /v1/vaults/:id` - Update any vault
  - `DELETE /v1/vaults/:id` - Delete any vault

- **Cross-Tenant Operations:**
  - Access to any account's resources
  - Bypass account ownership checks
  - Full system visibility

**Warning:** The admin scope grants unrestricted access. Use with caution.

#### `inferadb.account.manage` _(Reserved for future use)_

**Purpose:** Account-scoped administrative operations

Reserved for Phase 2 implementation:

- Managing accounts the user owns
- Delegated account administration

#### `inferadb.vault.manage` _(Reserved for future use)_

**Purpose:** Vault-scoped administrative operations

Reserved for Phase 2 implementation:

- Managing vaults the user owns
- Delegated vault administration

---

## Multi-Tenancy

InferaDB implements strict multi-tenancy using **vaults** and **accounts**.

### Vault Isolation

Every operation is scoped to a vault (UUID):

- All relationships belong to a single vault
- Vault UUID included in JWT claims
- Cross-vault access is strictly forbidden
- Each vault has its own revision counter

### Account Ownership

Accounts own vaults:

- JWT tokens include both `vault` and `account` claims
- Account ownership verified before vault access
- Users can only access vaults they own (unless admin)

### Authentication Flow

```text
1. Extract JWT from request
2. Validate token signature and claims
3. Extract vault and account UUIDs
4. Verify vault exists in database
5. Verify account owns the vault
6. Validate required scopes
7. Execute operation within vault context
```

---

## Scope Hierarchy

Scopes follow a hierarchical model:

```text
inferadb.admin (grants all permissions)
  ├── inferadb.check
  ├── inferadb.write
  ├── inferadb.read
  ├── inferadb.expand
  ├── inferadb.list
  │   ├── inferadb.list-relationships
  │   ├── inferadb.list-subjects
  │   └── inferadb.list-resources
  ├── inferadb.watch
  ├── inferadb.simulate
  ├── inferadb.account.manage (future)
  └── inferadb.vault.manage (future)
```

**Notes:**

- `inferadb.admin` grants all permissions automatically
- More specific scopes (e.g., `inferadb.list-relationships`) can substitute for generic scopes (e.g., `inferadb.list`)
- `inferadb.check` can often substitute for `inferadb.expand` in read operations

---

## API Endpoint Scope Requirements

### Authorization Endpoints

| Endpoint       | Method | Scope(s)                                | Notes                |
| -------------- | ------ | --------------------------------------- | -------------------- |
| `/v1/evaluate` | POST   | `inferadb.check`                        | Streaming (SSE)      |
| `/v1/expand`   | POST   | `inferadb.expand` OR `inferadb.check`   | Streaming (SSE)      |
| `/v1/simulate` | POST   | `inferadb.check` OR `inferadb.simulate` | Ephemeral evaluation |

### Relationship Endpoints

| Endpoint                   | Method | Scope(s)                                          | Notes                    |
| -------------------------- | ------ | ------------------------------------------------- | ------------------------ |
| `/v1/relationships/write`  | POST   | `inferadb.write`                                  | Batch operation          |
| `/v1/relationships/delete` | POST   | `inferadb.write`                                  | Filter-based bulk delete |
| `/v1/relationships/list`   | POST   | `inferadb.check` OR `inferadb.list-relationships` | Streaming (SSE)          |
| `/v1/relationships/:id`    | GET    | `inferadb.read`                                   | Single relationship      |
| `/v1/relationships/:id`    | DELETE | `inferadb.write`                                  | Single relationship      |

### Listing Endpoints

| Endpoint             | Method | Scope(s)                                      | Notes           |
| -------------------- | ------ | --------------------------------------------- | --------------- |
| `/v1/subjects/list`  | POST   | `inferadb.check` OR `inferadb.list-subjects`  | Streaming (SSE) |
| `/v1/resources/list` | POST   | `inferadb.check` OR `inferadb.list-resources` | Streaming (SSE) |

### Real-Time Endpoints

| Endpoint    | Method | Scope(s)         | Notes           |
| ----------- | ------ | ---------------- | --------------- |
| `/v1/watch` | POST   | `inferadb.watch` | Streaming (SSE) |

### Account Management Endpoints

| Endpoint           | Method | Scope(s)                              | Notes                      |
| ------------------ | ------ | ------------------------------------- | -------------------------- |
| `/v1/accounts`     | POST   | `inferadb.admin`                      | Admin only                 |
| `/v1/accounts`     | GET    | `inferadb.admin`                      | Admin only                 |
| `/v1/accounts/:id` | GET    | `inferadb.admin` OR account ownership | Admin can view any account |
| `/v1/accounts/:id` | PATCH  | `inferadb.admin`                      | Admin only                 |
| `/v1/accounts/:id` | DELETE | `inferadb.admin`                      | Admin only                 |

### Vault Management Endpoints

| Endpoint                          | Method | Scope(s)                                    | Notes                  |
| --------------------------------- | ------ | ------------------------------------------- | ---------------------- |
| `/v1/accounts/:account_id/vaults` | POST   | `inferadb.admin` OR account ownership       | Admin or account owner |
| `/v1/accounts/:account_id/vaults` | GET    | `inferadb.admin` OR account ownership       | Admin or account owner |
| `/v1/vaults/:id`                  | GET    | `inferadb.admin` OR vault account ownership | Admin or vault owner   |
| `/v1/vaults/:id`                  | PATCH  | `inferadb.admin`                            | Admin only             |
| `/v1/vaults/:id`                  | DELETE | `inferadb.admin` OR vault account ownership | Admin or vault owner   |

### AuthZEN Compliance Endpoints

| Endpoint                             | Method | Scope(s)         | Notes              |
| ------------------------------------ | ------ | ---------------- | ------------------ |
| `/access/v1/evaluation/evaluate`     | POST   | `inferadb.check` | AuthZEN spec       |
| `/access/v1/search`                  | POST   | `inferadb.list`  | AuthZEN spec       |
| `/.well-known/authzen-configuration` | GET    | None (public)    | Discovery endpoint |

---

## Best Practices

### Token Issuance

1. **Principle of Least Privilege:** Issue tokens with minimum required scopes
2. **Short-Lived Tokens:** Use short expiration times (e.g., 1 hour)
3. **Scope Combinations:** Combine scopes as needed (e.g., `inferadb.check,inferadb.write`)

### Scope Selection

- **Read-only operations:** Use `inferadb.read` or `inferadb.check`
- **Write operations:** Use `inferadb.write`
- **Administrative tasks:** Use specific admin scopes, not `inferadb.admin`
- **Automated services:** Use `inferadb.admin` sparingly

### Security Considerations

1. **Token Storage:** Store tokens securely (never in code or logs)
2. **Replay Protection:** Enable replay protection for sensitive operations
3. **Audit Logging:** All admin operations are audited
4. **Regular Rotation:** Rotate signing keys regularly
5. **Monitoring:** Monitor for unusual scope usage patterns

---

## Examples

### SDK Authentication Token

```json
{
  "iss": "https://auth.example.com",
  "sub": "app-12345",
  "aud": "https://api.inferadb.com",
  "exp": 1234567890,
  "iat": 1234564290,
  "scope": "inferadb.check inferadb.write",
  "vault": "550e8400-e29b-41d4-a716-446655440000",
  "account": "123e4567-e89b-12d3-a456-426614174000",
  "jti": "unique-token-id"
}
```

### Admin Token

```json
{
  "iss": "https://internal.inferadb.com",
  "sub": "control-plane",
  "aud": "https://api.inferadb.com/internal",
  "exp": 1234567890,
  "iat": 1234564290,
  "scope": "inferadb.admin",
  "vault": "00000000-0000-0000-0000-000000000000",
  "account": "00000000-0000-0000-0000-000000000000",
  "jti": "admin-token-id"
}
```

### Read-Only Token

```json
{
  "iss": "https://auth.example.com",
  "sub": "readonly-service",
  "aud": "https://api.inferadb.com",
  "exp": 1234567890,
  "iat": 1234564290,
  "scope": "inferadb.check inferadb.read",
  "vault": "550e8400-e29b-41d4-a716-446655440000",
  "account": "123e4567-e89b-12d3-a456-426614174000"
}
```

---

## Known Vulnerabilities and Mitigations

### RUSTSEC-2023-0071: RSA Timing Sidechannel (Marvin Attack)

**Status:** ⚠️ **Migration Recommended**
**Severity:** Moderate
**Affected Component:** `rsa` crate v0.9.8 (used for RS256/RS384/RS512 JWT verification)

**Description:**
The `rsa` crate has a non-constant-time implementation that leaks private key information through timing sidechannels observable over the network. While this primarily affects signing operations, it can potentially impact verification in certain scenarios.

**Impact on InferaDB:**

- Affects JWT verification with RSA algorithms (RS256, RS384, RS512)
- Network-observable timing information during token validation
- Low likelihood of exploitation (requires sophisticated attack)

**Recommended Mitigation:**

Migrate to `jsonwebtoken` 10.x with AWS-LC constant-time RSA:

```toml
# Cargo.toml
jsonwebtoken = { version = "10.1", default-features = false, features = ["aws-lc-rs", "use_pem"] }
```

**Alternative:**
Use EdDSA-only tokens (recommended for new deployments):

```yaml
# config.yaml
auth:
  allowed_algorithms: ["EdDSA"]
```

**Detailed Migration Guide:**

- [RSA Vulnerability Mitigation](docs/security/RSA_VULNERABILITY_MITIGATION.md)
- [Security Migration Plan](SECURITY_MIGRATION_PLAN.md)

**References:**

- [RUSTSEC Advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071)
- [Marvin Attack](https://people.redhat.com/~hkario/marvin/)

---

## Security Contacts

For security issues or vulnerabilities, please contact:

- **Email:** <security@inferadb.com>
- **PGP Key:** Available at <https://inferadb.com/.well-known/security.txt>

---

## Version History

- **1.0.0** (2025-11-03): Initial security model documentation
- Scope constants defined in `crates/infera-const/src/scopes.rs`
- All scopes enforced via type-safe constants

---

## CI/CD Security

### Automated Security Checks

Our CI pipeline includes comprehensive security automation:

**Daily Scheduled Checks:**

- `cargo audit` - CVE vulnerability detection against RustSec database
- `cargo deny` - License compliance and supply chain verification

**Every Pull Request:**

- Dependency vulnerability review (blocks moderate+ severity)
- License compliance enforcement (blocks copyleft licenses)
- Security-specific test suites (IPL fuzzing, WASM sandbox)

**Every Release:**

- SBOM (Software Bill of Materials) generation in SPDX format
- SLSA Level 3 provenance with cryptographic signatures
- Binary integrity verification via SHA-256 hashes
- Docker image SBOM and provenance layers

### Reporting CI/CD Security Issues

If you discover a security issue in our workflows or CI/CD pipeline:

1. **Do NOT open a public issue** - This could expose attack vectors
2. **Email <security@inferadb.com>** with:
   - Workflow file name and line number
   - Description of the vulnerability
   - Proof of concept (if safe to share)
   - Suggested remediation
3. **Expected response time:** 48 hours for acknowledgment
4. **Expected resolution time:** 7 days for critical issues

**Scope:**

- Script injection vulnerabilities
- Credential leakage
- Supply chain compromise vectors
- Privilege escalation
- Token permission issues

### Supply Chain Security

InferaDB implements defense-in-depth for supply chain security:

**Action Pinning:**

- All GitHub Actions pinned to **full commit SHA** (40 characters)
- Dependabot automatically creates PRs for action updates
- Tags and versions are NOT used (mutable and vulnerable to hijacking)

**Network Monitoring:**

- Step Security Harden Runner on all workflows
- Egress traffic monitoring and auditing
- Real-time anomaly detection
- Dashboard: <https://app.stepsecurity.io>

**Artifact Integrity:**

- SBOM for all releases (dependencies, licenses, versions)
- SLSA Level 3 provenance (proves build authenticity)
- SHA-256 checksums for all binaries
- Docker images signed with cosign (planned)

**Dependency Management:**

- Dependabot weekly updates for Cargo, GitHub Actions, Docker
- cargo-deny blocks: unlicensed, copyleft, vulnerable dependencies
- License allowlist: MIT, Apache-2.0, BSD-\*, ISC only
- Dependency review on all PRs

### Verifying Releases

All InferaDB releases include verifiable artifacts:

**1. Verify SBOM (Software Bill of Materials):**

```bash
# Download SBOM from release
gh release download v1.0.0 --pattern "sbom-linux-x86_64.spdx.json"

# Validate SBOM format
# (Install: https://github.com/microsoft/sbom-tool)
sbom-tool validate -b sbom-linux-x86_64.spdx.json
```

**2. Verify SLSA Provenance:**

```bash
# Download binary and provenance
gh release download v1.0.0 --pattern "inferadb-linux-x86_64.tar.gz"
gh release download v1.0.0 --pattern "*.intoto.jsonl"

# Verify provenance
# (Install: https://github.com/slsa-framework/slsa-verifier)
slsa-verifier verify-artifact inferadb-linux-x86_64.tar.gz \
  --provenance-path inferadb-linux-x86_64.tar.gz.intoto.jsonl \
  --source-uri github.com/inferadb/inferadb \
  --source-tag v1.0.0
```

**3. Verify Docker Image:**

```bash
# Pull image
docker pull inferadb/inferadb:latest
# or: docker pull ghcr.io/inferadb/inferadb:latest

# Inspect SBOM (embedded in image)
docker buildx imagetools inspect inferadb/inferadb:latest --format "{{json .SBOM}}" | jq

# Inspect provenance
docker buildx imagetools inspect inferadb/inferadb:latest --format "{{json .Provenance}}" | jq
```

**4. Verify Checksums:**

```bash
# Calculate SHA-256 of downloaded binary
sha256sum inferadb-linux-x86_64.tar.gz

# Compare with GitHub release checksums
# (Future: checksums.txt will be attached to releases)
```

### Workflow Security Hardening

Our workflows implement security best practices:

**Permissions:**

- Default: `contents: read` (read-only)
- Explicit job-level permissions only where needed
- No workflow has `write-all` permissions
- Least-privilege principle enforced

**Secret Management:**

- GitHub Container Registry uses OIDC (no secrets)
- Docker Hub uses fine-grained tokens (not passwords)
- Secrets never logged or exposed in outputs
- `add-mask` for sensitive computed values

**Input Validation:**

- All workflow inputs passed via environment variables
- No direct `${{ }}` interpolation in shell scripts
- Prevents command injection attacks
- Validated against expected patterns

**Attack Surface Reduction:**

- No `pull_request_target` trigger (prevents secret leakage)
- Concurrency limits prevent resource exhaustion
- Timeouts on all long-running jobs
- Fail-fast disabled for test matrices (complete picture)

### Vulnerability Response

When a security vulnerability is discovered in our CI/CD:

**Critical (CVSS 9.0-10.0):**

- Hotfix within 24 hours
- Emergency release if needed
- Public disclosure after fix deployed

**High (CVSS 7.0-8.9):**

- Fix within 7 days
- Included in next release
- Security advisory published

**Medium (CVSS 4.0-6.9):**

- Fix within 30 days
- Included in normal release cycle
- Documented in changelog

**Low (CVSS 0.1-3.9):**

- Fix within 90 days
- Batched with other improvements
- Optional disclosure

### Compliance

Our CI/CD pipeline supports:

**Standards:**

- SLSA Build Level 3 (provenance, hermetic builds)
- SPDX 2.3 (SBOM format)
- OpenSSF Scorecard (automated security metrics)
- Sigstore (keyless signing, transparency logs)

**Certifications:**

- SOC 2 Type II (planned)
- ISO 27001 (planned)
- FedRAMP (future consideration)

**Auditing:**

- All workflow runs logged in GitHub
- Step Security insights for 90 days
- Artifact retention: 90 days (releases), 7 days (CI)
- Audit trail includes: actor, commit, environment, outputs

### Security Features Roadmap

**Q1 2025:**

- ✅ SBOM generation for all releases
- ✅ SLSA Level 3 provenance
- ✅ Harden Runner on all workflows
- ✅ Action pinning to commit SHA
- ✅ cargo-deny integration

**Q2 2025:**

- Binary signing with cosign/sigstore
- Keyless signing via OIDC
- Transparency log integration (Rekor)
- OpenSSF Scorecard automation

**Q3 2025:**

- FOSSA integration for license scanning
- Snyk container scanning
- Trivy vulnerability scanning
- SAST with Semgrep

**Q4 2025:**

- SOC 2 Type II compliance
- Artifact attestation framework
- Enhanced supply chain policies
- Continuous compliance monitoring

### Resources

- **Step Security Dashboard:** <https://app.stepsecurity.io>
- **SLSA Framework:** <https://slsa.dev>
- **RustSec Database:** <https://rustsec.org>
- **Sigstore:** <https://sigstore.dev>
- **OpenSSF Scorecard:** <https://github.com/ossf/scorecard>
- **cargo-deny Docs:** <https://embarkstudios.github.io/cargo-deny>

### Contact

- **Security Issues:** <security@inferadb.com>
- **PGP Key:** [TODO: Add PGP key]
- **Bug Bounty:** [TODO: Set up HackerOne/Bugcrowd]
- **Response Time:** 48 hours (acknowledgment), 7 days (critical fixes)
