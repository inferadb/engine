# InferaDB Production Hardening Checklist

This document provides a comprehensive checklist for deploying InferaDB securely in production environments.

## Pre-Deployment Checklist

### Authentication Configuration

- [ ] **Authentication enabled**: Set `auth.enabled = true` in production config
- [ ] **JWKS endpoint configured**: Verify `jwks_base_url` or `jwks_url` points to production JWKS endpoint
- [ ] **HTTPS only**: Ensure all JWKS URLs use `https://` scheme
- [ ] **Accepted algorithms**: Verify only asymmetric algorithms (EdDSA, RS256) are configured

  ```toml
  accepted_algorithms = ["EdDSA", "RS256"]
  ```

- [ ] **Audience validation enabled**: Set `enforce_audience = true`

  ```toml
  enforce_audience = true
  allowed_audiences = ["https://api.inferadb.com/evaluate"]
  ```

- [ ] **Scope validation enabled**: Set `enforce_scopes = true`

  ```toml
  enforce_scopes = true
  ```

### Clock and Time Configuration

- [ ] **Clock skew minimal**: Keep `clock_skew_seconds` ≤ 60 seconds

  ```toml
  clock_skew_seconds = 60
  ```

- [ ] **Maximum token age**: Set appropriate `max_token_age_seconds` (default 24 hours)

  ```toml
  max_token_age_seconds = 86400  # 24 hours
  ```

- [ ] **NTP synchronized**: Ensure all servers use NTP for time synchronization
- [ ] **Timezone configured**: Set servers to UTC to avoid confusion

### Replay Protection (Multi-Node Deployments)

- [ ] **Redis deployed**: Deploy Redis instance for replay protection
- [ ] **Redis URL configured**: Set `redis_url` in configuration

  ```toml
  redis_url = "redis://redis.internal:6379"
  ```

- [ ] **Replay protection enabled**: Set `replay_protection = true`

  ```toml
  replay_protection = true
  ```

- [ ] **JTI required**: Set `require_jti = true` when replay protection is enabled

  ```toml
  require_jti = true
  ```

- [ ] **Redis persistence**: Configure Redis with AOF or RDB persistence
- [ ] **Redis backups**: Set up regular Redis backups
- [ ] **Redis monitoring**: Monitor Redis memory usage and connections

### Secret Management

- [ ] **Internal JWKS secured**: If using file-based internal JWKS, set file permissions to `0600`

  ```bash
  chmod 0600 /etc/inferadb/internal-jwks.json
  ```

- [ ] **Environment variables**: Use environment variables for sensitive config
- [ ] **No secrets in config files**: Don't commit secrets to version control
- [ ] **Secret rotation**: Implement key rotation policy (recommend quarterly)
- [ ] **Vault integration**: Consider using HashiCorp Vault or AWS Secrets Manager

### Network Security

- [ ] **TLS certificates valid**: Ensure all TLS certificates are valid and not expiring soon
- [ ] **Certificate pinning** (optional): Pin JWKS endpoint certificates if static
- [ ] **Firewall rules**: Restrict access to InferaDB API (allow only necessary IPs/ranges)
- [ ] **VPC/subnet isolation**: Deploy InferaDB in private subnet if possible
- [ ] **Load balancer**: Use load balancer with TLS termination in front of InferaDB
- [ ] **DDoS protection**: Enable DDoS protection (CloudFlare, AWS Shield, etc.)

## Runtime Configuration

### Observability

- [ ] **Audit logs enabled**: Ensure authentication audit logging is active

  ```toml
  [observability]
  audit_log_enabled = true
  ```

- [ ] **Logs exported to SIEM**: Configure log shipping to centralized SIEM
  - Splunk
  - Elasticsearch
  - Datadog
  - AWS CloudWatch
- [ ] **Metrics enabled**: Enable Prometheus metrics for authentication

  ```toml
  [observability]
  metrics_enabled = true
  ```

- [ ] **Tracing enabled**: Enable distributed tracing (OpenTelemetry)

  ```toml
  [observability]
  tracing_enabled = true
  ```

### Alerts and Monitoring

- [ ] **Auth failure rate alert**: Alert on >5% authentication failure rate
- [ ] **Token expiration alert**: Alert on high rate of expired token attempts
- [ ] **Replay detection alert**: Alert on replay attacks detected (if enabled)
- [ ] **Algorithm attack alert**: Alert on attempts to use forbidden algorithms
- [ ] **Uptime monitoring**: Monitor InferaDB availability (99.9% target)
- [ ] **Latency monitoring**: Monitor p50, p95, p99 latency for auth operations
- [ ] **Redis health**: Monitor Redis availability if replay protection is enabled

### Rate Limiting

**Note**: Rate limiting should be implemented at the reverse proxy/load balancer level.

- [ ] **Per-IP rate limiting**: Limit authentication attempts per IP address
  - Recommendation: 100 requests/minute per IP
- [ ] **Per-tenant rate limiting**: Limit requests per tenant
  - Recommendation: 1000 requests/minute per tenant
- [ ] **Burst allowance**: Allow short bursts (2x sustained rate for 10 seconds)
- [ ] **429 responses**: Return `429 Too Many Requests` when limits exceeded
- [ ] **Retry-After header**: Include `Retry-After` header in 429 responses

#### Example: Nginx Rate Limiting

```nginx
# /etc/nginx/nginx.conf

http {
    # Define rate limit zones
    limit_req_zone $binary_remote_addr zone=auth_ip:10m rate=100r/m;
    limit_req_zone $http_x_tenant_id zone=auth_tenant:10m rate=1000r/m;

    server {
        location /v1/ {
            # Apply IP-based rate limit
            limit_req zone=auth_ip burst=200 nodelay;

            # Apply tenant-based rate limit
            limit_req zone=auth_tenant burst=2000 nodelay;

            # Return 429 on limit
            limit_req_status 429;

            proxy_pass http://inferadb_backend;
        }
    }
}
```

#### Example: AWS API Gateway Rate Limiting

```yaml
# AWS API Gateway throttling settings
throttle:
  rateLimit: 1000 # requests per second
  burstLimit: 2000 # max concurrent requests
```

### Issuer and Audience Configuration

- [ ] **Issuer allowlist**: If using multiple IdPs, configure issuer allowlist

  ```toml
  issuer_allowlist = ["https://auth.company.com", "tenant:*"]
  ```

- [ ] **Issuer blocklist**: Block known malicious issuers

  ```toml
  issuer_blocklist = ["https://evil.example.com"]
  ```

- [ ] **Audience enforcement**: Never disable `enforce_audience` in production
- [ ] **Multiple audiences**: Configure all valid audience values

  ```toml
  allowed_audiences = [
      "https://api.inferadb.com/evaluate",
      "https://api.inferadb.com/admin"
  ]
  ```

## Post-Deployment Verification

### Security Testing

- [ ] **Vulnerability scan**: Run automated vulnerability scanner
- [ ] **Penetration test**: Conduct penetration test using [pentest.md](pentest.md) guide
- [ ] **Algorithm confusion test**: Verify "none" and HS256 are rejected
- [ ] **Expired token test**: Verify expired tokens are rejected
- [ ] **Replay test**: Verify replay protection works (if enabled)
- [ ] **Cross-tenant test**: Verify tenant isolation is enforced
- [ ] **Malformed JWT test**: Verify server doesn't crash on malformed input

### Configuration Validation

- [ ] **Run config validator**: Execute configuration validation on startup

  ```bash
  cargo run --release -- validate-config
  ```

- [ ] **Check startup logs**: Review logs for security warnings

  ```bash
  grep -i "warn" /var/log/inferadb/startup.log
  grep -i "security" /var/log/inferadb/startup.log
  ```

- [ ] **Verify JWKS fetch**: Ensure JWKS can be fetched from configured endpoint

  ```bash
  curl https://your-jwks-endpoint/.well-known/jwks.json
  ```

### Operational Readiness

- [ ] **Backup procedures**: Document and test backup procedures
- [ ] **Disaster recovery**: Document disaster recovery steps (RTO/RPO targets)
- [ ] **Incident response**: Create incident response playbook
- [ ] **On-call rotation**: Set up on-call rotation for security incidents
- [ ] **Runbooks**: Create operational runbooks for common scenarios
  - Key rotation
  - Redis failover
  - Authentication outage
  - Certificate expiration

## Ongoing Maintenance

### Regular Reviews

- [ ] **Quarterly security review**: Review configuration and logs quarterly
- [ ] **Annual penetration test**: Conduct annual external penetration test
- [ ] **Monthly dependency updates**: Update dependencies and run `cargo audit`

  ```bash
  cargo update
  cargo audit
  ```

- [ ] **Weekly metric reviews**: Review authentication metrics and anomalies

### Key Rotation

- [ ] **Rotation schedule**: Define key rotation schedule (recommend quarterly)
- [ ] **Rotation procedure**: Document step-by-step key rotation process
- [ ] **Overlap period**: Maintain 7-day overlap when rotating keys
- [ ] **Testing**: Test key rotation in staging before production
- [ ] **Rollback plan**: Have rollback plan in case rotation fails

### Dependency Management

- [ ] **Security advisories**: Subscribe to Rust security advisories
  - <https://rustsec.org/>
  - <https://groups.google.com/g/rustlang-security-announcements>
- [ ] **Automated scanning**: Set up automated dependency scanning (Dependabot, Renovate)
- [ ] **Patch management**: Establish SLA for patching critical vulnerabilities
  - Critical: 7 days
  - High: 30 days
  - Medium: 90 days

## Compliance and Auditing

### Audit Trail

- [ ] **Retention policy**: Define log retention policy (recommend 90 days minimum)
- [ ] **Immutable logs**: Store audit logs in immutable storage (S3 with object lock)
- [ ] **Log integrity**: Use cryptographic signatures for log integrity
- [ ] **Access controls**: Restrict access to audit logs (need-to-know basis)

### Compliance Requirements

- [ ] **SOC 2 Type II**: Ensure configuration meets SOC 2 requirements
- [ ] **ISO 27001**: Document controls for ISO 27001 compliance
- [ ] **GDPR**: Ensure PII in logs is handled per GDPR requirements
- [ ] **HIPAA** (if applicable): Meet HIPAA requirements for authentication logs

### Documentation

- [ ] **Architecture diagram**: Create and maintain architecture diagram
- [ ] **Data flow diagram**: Document authentication data flows
- [ ] **Security policies**: Document security policies and procedures
- [ ] **Change log**: Maintain changelog of security-related changes

## Emergency Procedures

### Security Incident Response

1. **Detection**: Monitor alerts and logs for suspicious activity
2. **Containment**: Isolate affected systems if breach detected
3. **Eradication**: Remove threat and patch vulnerabilities
4. **Recovery**: Restore systems to normal operation
5. **Lessons Learned**: Conduct post-mortem and improve defenses

### Emergency Contacts

```yaml
# Store this in your incident response playbook
contacts:
  security_team: security@company.com
  on_call: +1-555-ONCALL
  cloud_provider_support: AWS/GCP/Azure support number
  external_security_consultants: partner@security-firm.com
```

### Breach Response Plan

- [ ] **Communication plan**: Who to notify in case of breach
- [ ] **Legal requirements**: Understand legal breach notification requirements
- [ ] **Public disclosure**: Have pre-approved templates for public disclosure
- [ ] **Customer notification**: Plan for notifying affected customers

## Resources

### Internal Documentation

- [SECURITY.md](../SECURITY.md) - Security audit checklist
- [pentest.md](pentest.md) - Penetration testing guide
- [AUTHENTICATION.md](../AUTHENTICATION.md) - Authentication architecture

### External References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [JWT Best Practices (RFC 8725)](https://tools.ietf.org/html/rfc8725)

## Sign-Off

Before going to production, the following stakeholders must sign off:

- [ ] **Security Team Lead**: **\*\*\*\***\_\_\_**\*\*\*\*** Date: \***\*\_\_\*\***
- [ ] **Engineering Manager**: **\*\*\*\***\_\_\_**\*\*\*\*** Date: \***\*\_\_\*\***
- [ ] **DevOps Lead**: \***\*\*\*\*\*\*\***\_\_\***\*\*\*\*\*\*\*** Date: \***\*\_\_\*\***
- [ ] **Compliance Officer** (if applicable): **\_** Date: \***\*\_\_\*\***

---

**Last Updated**: 2025-10-29
**Next Review Date**: 2026-01-29 (Quarterly)
**Owner**: Security Team
