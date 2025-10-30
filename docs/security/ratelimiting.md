# Rate Limiting Recommendations

## Overview

Rate limiting is a critical security control to prevent abuse of the InferaDB authentication system. While InferaDB does not implement rate limiting at the application layer, this document provides recommendations for implementing rate limiting at the infrastructure level.

## Why Rate Limiting is Important

Rate limiting protects against:

1. **Brute Force Attacks**: Prevent attackers from trying many tokens
2. **Denial of Service (DoS)**: Limit resource consumption per client
3. **Credential Stuffing**: Slow down automated credential testing
4. **Resource Exhaustion**: Prevent single tenants from monopolizing resources
5. **Cost Control**: Limit API usage to prevent unexpected costs

## Recommended Rate Limits

### Authentication Endpoints

| Endpoint Pattern | Rate Limit (per minute) | Burst | Notes                                    |
| ---------------- | ----------------------- | ----- | ---------------------------------------- |
| `/v1/check`      | 1000                    | 2000  | High-volume authorization checks         |
| `/v1/write`      | 100                     | 200   | Write operations should be less frequent |
| `/v1/expand`     | 500                     | 1000  | Moderate-frequency expansion queries     |
| `/v1/lookup`     | 500                     | 1000  | Moderate-frequency lookups               |
| `/health`        | Unlimited               | -     | Health checks should not be rate limited |

### Rate Limiting Dimensions

#### 1. Per IP Address

Limit requests from a single IP address to prevent single-source attacks.

**Recommended Limits**:

- **Normal operations**: 100 requests/minute per IP
- **Burst allowance**: 200 requests/minute for 10 seconds
- **Blocked period**: 60 seconds after limit exceeded

**Configuration Example (Nginx)**:

```nginx
limit_req_zone $binary_remote_addr zone=per_ip:10m rate=100r/m;

location /v1/ {
    limit_req zone=per_ip burst=200 nodelay;
    limit_req_status 429;
}
```

#### 2. Per Tenant ID

Limit requests per tenant to ensure fair resource distribution.

**Recommended Limits**:

- **Standard tier**: 1,000 requests/minute per tenant
- **Premium tier**: 10,000 requests/minute per tenant
- **Enterprise tier**: Unlimited (or very high limit)

**Configuration Example (Nginx)**:

```nginx
# Extract tenant ID from JWT and use for rate limiting
map $http_authorization $tenant_id {
    default "unknown";
    "~*Bearer\s+(?<jwt>[^\s]+)" $jwt;
}

# This requires custom Nginx module to parse JWT
# Alternatively, have the application set X-Tenant-Id header after auth
limit_req_zone $http_x_tenant_id zone=per_tenant:10m rate=1000r/m;

location /v1/ {
    limit_req zone=per_tenant burst=2000 nodelay;
}
```

#### 3. Per User/Subject

Limit requests per authenticated user.

**Recommended Limits**:

- **Per user**: 500 requests/minute
- **Burst**: 1000 requests/minute for 10 seconds

**Rationale**: Prevents compromised credentials from causing excessive load.

#### 4. Global Rate Limit

Limit total requests to the system to prevent resource exhaustion.

**Recommended Limits**:

- **Total requests**: Based on capacity testing
- **Example**: If server can handle 100,000 req/min, set limit to 80,000 req/min (80% capacity)

## Implementation Approaches

### 1. Reverse Proxy (Recommended)

Implement rate limiting at the reverse proxy layer (Nginx, HAProxy, Envoy).

**Advantages**:

- ✅ Low latency (no application involvement)
- ✅ Mature, battle-tested implementations
- ✅ Offloads work from application servers
- ✅ Protects application from reaching rate limited endpoints

**Disadvantages**:

- ❌ Limited context (can't rate limit based on token claims)
- ❌ Configuration can be complex for multi-tier limits

#### Nginx Example

```nginx
http {
    # Define rate limit zones
    limit_req_zone $binary_remote_addr zone=ip:10m rate=100r/m;
    limit_req_zone $http_x_tenant_id zone=tenant:10m rate=1000r/m;

    # Define response for rate limit exceeded
    limit_req_status 429;

    server {
        listen 443 ssl http2;
        server_name api.inferadb.com;

        # SSL configuration
        ssl_certificate /etc/ssl/certs/api.inferadb.com.crt;
        ssl_certificate_key /etc/ssl/private/api.inferadb.com.key;

        # High-volume endpoints
        location /v1/check {
            limit_req zone=ip burst=200 nodelay;
            limit_req zone=tenant burst=2000 nodelay;

            # Add rate limit headers to response
            add_header X-RateLimit-Limit 1000;
            add_header X-RateLimit-Remaining $limit_req_remaining;

            proxy_pass http://inferadb_backend;
        }

        # Lower-volume endpoints
        location /v1/write {
            limit_req zone=ip burst=20 nodelay;
            limit_req zone=tenant burst=200 nodelay;

            proxy_pass http://inferadb_backend;
        }

        # Health check (no rate limit)
        location /health {
            proxy_pass http://inferadb_backend;
        }
    }
}
```

### 2. API Gateway

Use cloud-native API gateways (AWS API Gateway, Google Cloud API Gateway, Kong).

**Advantages**:

- ✅ Managed service (less operational burden)
- ✅ Built-in rate limiting features
- ✅ Integration with other cloud services
- ✅ Analytics and monitoring included

**Disadvantages**:

- ❌ Vendor lock-in
- ❌ Additional cost
- ❌ Less control over implementation details

#### AWS API Gateway Example

```yaml
# AWS API Gateway throttling configuration
Resources:
  InferaDBApi:
    Type: AWS::ApiGatewayV2::Api
    Properties:
      Name: InferaDB API
      ProtocolType: HTTP

  ApiStage:
    Type: AWS::ApiGatewayV2::Stage
    Properties:
      ApiId: !Ref InferaDBApi
      StageName: prod
      ThrottleSettings:
        RateLimit: 1000 # requests per second
        BurstLimit: 2000 # max concurrent requests
```

#### Kong Example

```yaml
# kong.yml
plugins:
  - name: rate-limiting
    config:
      minute: 1000
      hour: 60000
      policy: local
      limit_by: ip
      fault_tolerant: true

  - name: rate-limiting
    config:
      minute: 1000
      limit_by: header
      header_name: X-Tenant-Id
      policy: redis
      redis_host: redis.internal
      redis_port: 6379
```

### 3. Application-Level Middleware

Implement rate limiting in Rust using Tower middleware.

**Advantages**:

- ✅ Full context (can rate limit based on any request property)
- ✅ Fine-grained control
- ✅ Can customize response format

**Disadvantages**:

- ❌ Adds latency to every request
- ❌ Consumes application resources
- ❌ More complex to implement correctly

#### Tower-Governor Example

```rust
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use axum::Router;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Configure rate limiter: 100 requests per minute
    let governor_conf = Box::new(
        GovernorConfigBuilder::default()
            .per_second(100)
            .burst_size(200)
            .finish()
            .unwrap(),
    );

    let governor_limiter = governor_conf.limiter().clone();
    let governor_layer = GovernorLayer {
        config: Box::leak(governor_conf),
    };

    // Build router with rate limiting
    let app = Router::new()
        .route("/v1/check", post(check_handler))
        .route("/v1/write", post(write_handler))
        .layer(governor_layer);

    // Start server
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

## Response Format

When rate limit is exceeded, return HTTP 429 with details:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 60
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1699564800

{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded. Please retry after 60 seconds.",
  "retry_after": 60,
  "limit": 1000,
  "window": "1 minute"
}
```

## Monitoring and Alerting

### Metrics to Track

1. **Rate limit hits per endpoint**: Track how often limits are hit
2. **Rate limit hits per IP**: Identify potentially malicious IPs
3. **Rate limit hits per tenant**: Identify tenants needing tier upgrade
4. **429 response rate**: Overall percentage of rate-limited requests

### Alert Conditions

- **Alert**: Rate limit hit rate > 5% for any endpoint
- **Action**: Investigate if legitimate traffic increase or attack

- **Alert**: Single IP hitting rate limit repeatedly (> 10 times/hour)
- **Action**: Consider blocking IP at firewall level

- **Alert**: Tenant hitting rate limit consistently (> 90% of limit)
- **Action**: Contact tenant about tier upgrade or optimization

## Best Practices

### 1. Return Informative Headers

Always include rate limit information in response headers:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 847
X-RateLimit-Reset: 1699564800
Retry-After: 45
```

### 2. Use Token Bucket or Leaky Bucket Algorithm

- **Token Bucket**: Allows bursts, tokens regenerate at fixed rate
- **Leaky Bucket**: Smooths out bursts, processes at constant rate

Recommendation: **Token Bucket** for InferaDB (allows short bursts)

### 3. Implement Graceful Degradation

When approaching rate limit:

- Return `X-RateLimit-Remaining` header with low value
- Log warning for tenant to review usage

### 4. Whitelist Internal IPs

Exempt internal monitoring and health checks from rate limits:

```nginx
geo $is_internal {
    default 0;
    10.0.0.0/8 1;      # Internal VPC
    172.16.0.0/12 1;   # Internal network
}

map $is_internal $rate_limit_key {
    0 $binary_remote_addr;  # External: rate limit by IP
    1 "";                   # Internal: no rate limit
}

limit_req_zone $rate_limit_key zone=ip:10m rate=100r/m;
```

### 5. Document Limits Publicly

Include rate limits in API documentation:

```markdown
## Rate Limits

| Tier       | Requests per Minute | Burst  |
| ---------- | ------------------- | ------ |
| Free       | 100                 | 200    |
| Standard   | 1,000               | 2,000  |
| Premium    | 10,000              | 20,000 |
| Enterprise | Custom              | Custom |

Rate limit headers are included in all responses.
```

## Testing Rate Limits

### Load Testing Script

```bash
#!/bin/bash
# Test rate limiting with concurrent requests

TOKEN="your-test-token"
ENDPOINT="https://api.inferadb.com/v1/check"

# Send 200 requests as fast as possible
for i in {1..200}; do
    curl -X POST "$ENDPOINT" \
         -H "Authorization: Bearer $TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"namespace": "test", "tuples": []}' \
         -o /dev/null -s -w "%{http_code}\n" &
done

wait
```

Expected: First ~100 requests return `200 OK`, remaining return `429 Too Many Requests`.

## Future Enhancements

### Phase 8 (Future Work)

- [ ] Application-level rate limiting middleware
- [ ] Per-user rate limits based on subscription tier
- [ ] Dynamic rate limits based on system load
- [ ] Rate limit bypass for trusted IPs
- [ ] Machine learning-based anomaly detection
- [ ] Distributed rate limiting with Redis Cluster

## References

- [IETF RFC 6585 - HTTP Status Code 429](https://tools.ietf.org/html/rfc6585)
- [OWASP Rate Limiting Guide](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [Nginx Rate Limiting](https://www.nginx.com/blog/rate-limiting-nginx/)
- [Token Bucket Algorithm](https://en.wikipedia.org/wiki/Token_bucket)
- [Leaky Bucket Algorithm](https://en.wikipedia.org/wiki/Leaky_bucket)

---

**Document Owner**: Security Team
**Last Updated**: 2025-10-29
**Next Review**: 2026-01-29
