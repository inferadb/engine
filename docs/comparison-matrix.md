# InferaDB Competitive Comparison Matrix

This document provides a comprehensive comparison of InferaDB against major authorization platforms: SpiceDB, OpenFGA, Oso, WorkOS FGA, and Amazon Verified Permissions.

**Last Updated**: 2025-10-31

---

## Quick Summary

| Platform                    | Best For                              | License     | Architecture             |
| --------------------------- | ------------------------------------- | ----------- | ------------------------ |
| **InferaDB**                | Production-scale ReBAC with streaming | BSL 1.1     | Distributed microservice |
| SpiceDB                     | Google Zanzibar implementation        | Apache 2.0  | Distributed microservice |
| OpenFGA                     | Cloud-native ReBAC                    | Apache 2.0  | Distributed microservice |
| Oso                         | Embedded authorization library        | Apache 2.0  | In-process library       |
| WorkOS FGA                  | Managed FGA service                   | Proprietary | SaaS only                |
| Amazon Verified Permissions | AWS-native Cedar policies             | Proprietary | AWS SaaS only            |

---

## Feature Comparison Matrix

### Core Authorization Features

| Feature                | InferaDB          | SpiceDB      | OpenFGA      | Oso               | WorkOS FGA   | Amazon VP       |
| ---------------------- | ----------------- | ------------ | ------------ | ----------------- | ------------ | --------------- |
| **ReBAC Model**        | ✅ Yes            | ✅ Yes       | ✅ Yes       | ❌ No (RBAC/ABAC) | ✅ Yes       | ❌ No (ABAC)    |
| **RBAC Support**       | ✅ Via ReBAC      | ✅ Via ReBAC | ✅ Via ReBAC | ✅ Native         | ✅ Via ReBAC | ✅ Via policies |
| **ABAC Support**       | ✅ WASM modules   | ❌ Limited   | ❌ Limited   | ✅ Native         | ❌ No        | ✅ Native       |
| **Graph Traversal**    | ✅ Full           | ✅ Full      | ✅ Full      | ⚠️ DIY            | ✅ Full      | ❌ No           |
| **Computed Relations** | ✅ Yes            | ✅ Yes       | ✅ Yes       | ⚠️ Via rules      | ✅ Yes       | ⚠️ Via policies |
| **Hierarchies**        | ✅ Native         | ✅ Native    | ✅ Native    | ⚠️ DIY            | ✅ Native    | ⚠️ Via policies |
| **Wildcards**          | ✅ Yes (`type:*`) | ✅ Yes       | ✅ Yes       | ❌ No             | ✅ Yes       | ❌ No           |

### API Surface

| Feature                  | InferaDB              | SpiceDB         | OpenFGA         | Oso           | WorkOS FGA | Amazon VP   |
| ------------------------ | --------------------- | --------------- | --------------- | ------------- | ---------- | ----------- |
| **Check Permission**     | ✅ Streaming          | ✅ Unary        | ✅ Unary        | ✅ In-process | ✅ REST    | ✅ REST     |
| **Batch Check**          | ✅ Unlimited          | ⚠️ 30-100 limit | ⚠️ Limited      | ✅ In-process | ⚠️ Limited | ⚠️ 30 limit |
| **Check with Trace**     | ✅ Yes + Batch        | ✅ Yes          | ✅ Yes          | ✅ Yes        | ✅ Yes     | ⚠️ Basic    |
| **Expand Relation**      | ✅ Streaming          | ✅ Unary        | ✅ Unary        | ⚠️ DIY        | ✅ REST    | ❌ No       |
| **ListResources**        | ✅ Streaming          | ✅ Unary        | ✅ Unary        | ⚠️ DIY        | ✅ REST    | ⚠️ Limited  |
| **ListSubjects**         | ✅ Streaming          | ✅ Unary        | ✅ Unary (1.5+) | ⚠️ DIY        | ✅ REST    | ❌ No       |
| **ListRelationships**    | ✅ Streaming          | ✅ Unary        | ✅ Unary        | ⚠️ DIY        | ✅ REST    | ❌ No       |
| **Watch Changes**        | ✅ gRPC + SSE         | ✅ gRPC only    | ✅ gRPC only    | ❌ No         | ❌ No      | ❌ No       |
| **Write Relationships**  | ✅ Streaming          | ✅ Unary        | ✅ Unary        | ⚠️ DIY        | ✅ REST    | ✅ REST     |
| **Delete Relationships** | ✅ Streaming + Filter | ✅ Filter       | ⚠️ Limited      | ⚠️ DIY        | ✅ REST    | ❌ No       |

**Legend**:

-   ✅ Full support
-   ⚠️ Partial/limited support
-   ❌ Not supported
-   DIY: You must implement yourself

### Protocol Support

| Feature              | InferaDB   | SpiceDB | OpenFGA | Oso   | WorkOS FGA | Amazon VP |
| -------------------- | ---------- | ------- | ------- | ----- | ---------- | --------- |
| **gRPC API**         | ✅ Yes     | ✅ Yes  | ✅ Yes  | ❌ No | ❌ No      | ❌ No     |
| **REST API**         | ✅ Yes     | ✅ Yes  | ✅ Yes  | N/A   | ✅ Yes     | ✅ Yes    |
| **Server Streaming** | ✅ Yes     | ❌ No   | ❌ No   | N/A   | ❌ No      | ❌ No     |
| **Client Streaming** | ✅ Yes     | ❌ No   | ❌ No   | N/A   | ❌ No      | ❌ No     |
| **SSE Streaming**    | ✅ Yes     | ❌ No   | ❌ No   | N/A   | ❌ No      | ❌ No     |
| **WebSocket**        | ⏳ Planned | ❌ No   | ❌ No   | N/A   | ❌ No      | ❌ No     |

### Authentication & Security

| Feature            | InferaDB             | SpiceDB           | OpenFGA       | Oso    | WorkOS FGA  | Amazon VP       |
| ------------------ | -------------------- | ----------------- | ------------- | ------ | ----------- | --------------- |
| **Built-in Auth**  | ✅ JWT/OAuth         | ⚠️ Pre-shared key | ❌ No         | ❌ No  | ✅ API keys | ✅ AWS IAM      |
| **JWT Support**    | ✅ EdDSA/RS256/ES256 | ❌ No             | ❌ No         | ❌ No  | ❌ No       | ❌ No           |
| **OAuth 2.0**      | ✅ Yes               | ❌ No             | ❌ No         | ❌ No  | ❌ No       | ❌ No           |
| **OIDC Discovery** | ✅ Yes               | ❌ No             | ❌ No         | ❌ No  | ❌ No       | ❌ No           |
| **Multi-tenancy**  | ✅ Native            | ⚠️ Via namespaces | ⚠️ Via stores | ⚠️ DIY | ✅ Native   | ✅ Via policies |
| **Rate Limiting**  | ✅ Token bucket      | ⚠️ DIY            | ⚠️ DIY        | N/A    | ✅ Yes      | ✅ Yes          |
| **Audit Logging**  | ✅ Structured logs   | ⚠️ DIY            | ⚠️ DIY        | ⚠️ DIY | ✅ Yes      | ✅ CloudTrail   |

### Performance & Scalability

| Feature                | InferaDB         | SpiceDB   | OpenFGA  | Oso          | WorkOS FGA | Amazon VP |
| ---------------------- | ---------------- | --------- | -------- | ------------ | ---------- | --------- |
| **Check Latency**      | <10ms            | <10ms     | <10ms    | <1ms         | <20ms      | <50ms     |
| **Throughput**         | 50K+ RPS         | 50K+ RPS  | 30K+ RPS | N/A          | Unknown    | Unknown   |
| **Caching**            | ✅ Built-in LRU  | ✅ Yes    | ✅ Yes   | ⚠️ DIY       | ✅ Yes     | ✅ Yes    |
| **Horizontal Scaling** | ✅ Yes           | ✅ Yes    | ✅ Yes   | ⚠️ App-level | ✅ Auto    | ✅ Auto   |
| **Multi-region**       | ✅ Active-active | ✅ Yes    | ✅ Yes   | ⚠️ DIY       | ✅ Yes     | ✅ Global |
| **Batch Limits**       | ✅ Unlimited     | ⚠️ 30-100 | ⚠️ ~50   | N/A          | Unknown    | ⚠️ 30     |

### Storage & Consistency

| Feature            | InferaDB      | SpiceDB     | OpenFGA     | Oso    | WorkOS FGA | Amazon VP |
| ------------------ | ------------- | ----------- | ----------- | ------ | ---------- | --------- |
| **Memory Backend** | ✅ Yes        | ❌ No       | ❌ No       | N/A    | N/A        | N/A       |
| **PostgreSQL**     | ⏳ Planned    | ✅ Yes      | ✅ Yes      | N/A    | N/A        | N/A       |
| **MySQL**          | ⏳ Planned    | ✅ Yes      | ✅ Yes      | N/A    | N/A        | N/A       |
| **FoundationDB**   | ✅ Yes        | ❌ No       | ❌ No       | N/A    | Unknown    | N/A       |
| **Spanner**        | ⏳ Planned    | ✅ Yes      | ❌ No       | N/A    | Unknown    | N/A       |
| **CockroachDB**    | ⏳ Planned    | ✅ Yes      | ❌ No       | N/A    | Unknown    | N/A       |
| **Consistency**    | ✅ Sequential | ✅ Snapshot | ✅ Snapshot | N/A    | ✅ Yes     | ✅ Yes    |
| **Versioning**     | ✅ Revisions  | ✅ Zookies  | ✅ Tokens   | ⚠️ DIY | ✅ Yes     | ❌ No     |

### Observability

| Feature                 | InferaDB              | SpiceDB     | OpenFGA     | Oso    | WorkOS FGA | Amazon VP     |
| ----------------------- | --------------------- | ----------- | ----------- | ------ | ---------- | ------------- |
| **Prometheus Metrics**  | ✅ Built-in           | ✅ Built-in | ✅ Built-in | ⚠️ DIY | ❌ No      | ✅ CloudWatch |
| **OpenTelemetry**       | ✅ Yes                | ⚠️ Limited  | ⚠️ Limited  | ⚠️ DIY | ❌ No      | ⚠️ X-Ray      |
| **Structured Logging**  | ✅ JSON               | ✅ Yes      | ✅ Yes      | ⚠️ DIY | ❌ No      | ✅ CloudWatch |
| **Health Checks**       | ✅ Liveness/Readiness | ✅ Yes      | ✅ Yes      | N/A    | ✅ Yes     | ✅ Yes        |
| **Distributed Tracing** | ✅ Yes                | ⚠️ Limited  | ⚠️ Limited  | ⚠️ DIY | ❌ No      | ⚠️ X-Ray      |
| **Custom Dashboards**   | ✅ Grafana            | ✅ Grafana  | ✅ Grafana  | ⚠️ DIY | ⚠️ Limited | ✅ CloudWatch |

### Deployment & Operations

| Feature               | InferaDB   | SpiceDB     | OpenFGA    | Oso         | WorkOS FGA | Amazon VP   |
| --------------------- | ---------- | ----------- | ---------- | ----------- | ---------- | ----------- |
| **Docker Support**    | ✅ Yes     | ✅ Yes      | ✅ Yes     | N/A         | N/A        | N/A         |
| **Kubernetes**        | ✅ + Helm  | ✅ Operator | ✅ Yes     | N/A         | N/A        | N/A         |
| **Terraform**         | ✅ AWS/GCP | ⚠️ Limited  | ⚠️ Limited | N/A         | ⚠️ Limited | ✅ Yes      |
| **Managed Service**   | ⏳ Planned | ❌ No       | ❌ No      | N/A         | ✅ Yes     | ✅ Yes      |
| **Self-hosted**       | ✅ Yes     | ✅ Yes      | ✅ Yes     | ✅ In-app   | ❌ No      | ❌ No       |
| **Graceful Shutdown** | ✅ Yes     | ✅ Yes      | ✅ Yes     | N/A         | N/A        | N/A         |
| **Hot Reload**        | ✅ Config  | ⚠️ Limited  | ⚠️ Limited | ✅ Policies | N/A        | ✅ Policies |

---

## Detailed Feature Breakdown

### 1. Streaming APIs - InferaDB's Key Advantage

**InferaDB** is the only platform with comprehensive streaming support:

| Operation         | InferaDB            | SpiceDB       | OpenFGA       | Others        |
| ----------------- | ------------------- | ------------- | ------------- | ------------- |
| Evaluate (Check)  | ✅ Bidirectional    | ❌ Unary only | ❌ Unary only | ❌ Unary only |
| Expand            | ✅ Server streaming | ❌ Buffer all | ❌ Buffer all | ❌ Buffer all |
| ListResources     | ✅ Server streaming | ❌ Buffer all | ❌ Buffer all | ❌ Buffer all |
| ListSubjects      | ✅ Server streaming | ❌ Buffer all | ❌ Buffer all | ❌ Buffer all |
| ListRelationships | ✅ Server streaming | ❌ Buffer all | ❌ Buffer all | N/A           |
| Watch             | ✅ gRPC + SSE       | ✅ gRPC only  | ✅ gRPC only  | ❌ None       |
| Write             | ✅ Client streaming | ❌ Unary      | ❌ Unary      | ❌ Unary      |
| Delete            | ✅ Client streaming | ❌ Unary      | ❌ Unary      | N/A           |

**Benefits**:

-   ✅ **Memory Efficient**: Handle millions of results without buffering
-   ✅ **Progressive Results**: Start processing before query completes
-   ✅ **Better UX**: Show results as they arrive
-   ✅ **Lower Latency**: TTFB (Time To First Byte) is faster
-   ✅ **Web-friendly**: SSE works in browsers without WebSocket

### 2. Batch Check with Trace

**InferaDB** is the **ONLY** platform supporting detailed trace on batch operations:

```bash
# InferaDB - Stream unlimited checks with trace
grpcurl -d '{
  "subject": "user:alice",
  "resource": "doc:1",
  "permission": "read",
  "trace": true
}{
  "subject": "user:alice",
  "resource": "doc:2",
  "permission": "read",
  "trace": true
}' localhost:8081 infera.v1.InferaService/Evaluate
```

**Comparison**:

-   **SpiceDB**: Batch limited to 30-100, no trace on batch
-   **OpenFGA**: Batch limited, no trace on batch
-   **Oso**: In-process, can trace individual checks
-   **WorkOS FGA**: Unknown batch limits, basic trace
-   **Amazon VP**: Batch limited to 30, basic trace

### 3. Built-in Authentication

**InferaDB** has the most comprehensive built-in auth:

| Feature          | InferaDB             | SpiceDB   | OpenFGA   | Oso    | WorkOS | Amazon |
| ---------------- | -------------------- | --------- | --------- | ------ | ------ | ------ |
| JWT Support      | ✅ EdDSA/RS256/ES256 | ❌        | ❌        | ❌     | ❌     | ❌     |
| OAuth 2.0        | ✅                   | ❌        | ❌        | ❌     | ❌     | ❌     |
| OIDC Discovery   | ✅                   | ❌        | ❌        | ❌     | ❌     | ❌     |
| JWKS Caching     | ✅                   | ❌        | ❌        | ❌     | ❌     | ❌     |
| Multi-tenant     | ✅ From JWT          | ⚠️ Manual | ⚠️ Manual | ⚠️ DIY | ✅     | ✅     |
| Scope Validation | ✅                   | ❌        | ❌        | ❌     | ❌     | ❌     |

**Others require**:

-   API gateway for JWT validation
-   Manual tenant extraction
-   DIY scope/permission checking

### 4. No Artificial Limits

**Batch Check Limits**:

-   **InferaDB**: ✅ Unlimited (streaming)
-   **SpiceDB**: ⚠️ 30-100 items
-   **OpenFGA**: ⚠️ ~50 items
-   **Amazon VP**: ⚠️ 30 items
-   **Oso**: ✅ Unlimited (in-process)
-   **WorkOS FGA**: ⚠️ Unknown

**Why it matters**:

-   Authorization decisions often needed for hundreds of items
-   UI pages showing 100+ documents need batch checks
-   Pagination requires checking all items

### 5. Wildcard Support

All ReBAC platforms support wildcards for public access:

```json
{
    "resource": "document:announcement",
    "relation": "viewer",
    "subject": "user:*"
}
```

**Supported**: InferaDB, SpiceDB, OpenFGA, WorkOS FGA
**Not Supported**: Oso (would need custom logic), Amazon VP

### 6. Watch API - Real-time Changes

**Watch API Comparison**:

| Platform | gRPC Streaming | REST/SSE | Cursor Resumption | Type Filters |
| -------- | -------------- | -------- | ----------------- | ------------ |
| InferaDB | ✅             | ✅       | ✅                | ✅           |
| SpiceDB  | ✅             | ❌       | ✅                | ⚠️ Limited   |
| OpenFGA  | ✅             | ❌       | ⚠️ Limited        | ⚠️ Limited   |
| Others   | ❌             | ❌       | ❌                | ❌           |

**InferaDB Advantages**:

-   ✅ Both gRPC and REST/SSE (web-friendly)
-   ✅ Multiple resource type filters
-   ✅ Base64-encoded cursor for resumption
-   ✅ Proper backpressure handling

---

## Architecture Comparison

### SpiceDB Architecture

```
Client → gRPC → SpiceDB → CockroachDB/Postgres/MySQL/Spanner
                          ↓
                    Zookies (consistency tokens)
```

**Pros**:

-   Mature, battle-tested (Google Zanzibar paper)
-   Multiple storage backends
-   Strong consistency guarantees

**Cons**:

-   No streaming APIs (memory issues with large result sets)
-   Batch limits (30-100 checks)
-   Pre-shared key auth only
-   Complex Zookie management

### OpenFGA Architecture

```
Client → gRPC/REST → OpenFGA → Postgres/MySQL
                               ↓
                    Store models (namespace isolation)
```

**Pros**:

-   Cloud-native design
-   Good REST API
-   Active development

**Cons**:

-   Store model management overhead
-   No built-in authentication
-   Limited streaming
-   Batch limits

### Oso Architecture

```
Application Process
    ↓
Oso Library (in-process)
    ↓
Your Database (you manage schema)
```

**Pros**:

-   Ultra-low latency (no network)
-   Flexible Polar language
-   Native ABAC support

**Cons**:

-   Not a service (embedded only)
-   DIY data layer
-   DIY caching
-   DIY multi-tenancy
-   DIY observability
-   Scales with application (not independently)

### InferaDB Architecture

```
Client → gRPC/REST (streaming) → InferaDB → FoundationDB/Memory
                                    ↓
                            JWT Auth (built-in)
                            Cache (built-in)
                            Metrics (built-in)
                            Multi-region replication
```

**Pros**:

-   ✅ Comprehensive streaming APIs
-   ✅ Built-in JWT/OAuth authentication
-   ✅ No batch limits
-   ✅ Both gRPC and REST
-   ✅ SSE for web clients
-   ✅ Sequential consistency by default

**Cons**:

-   ⏳ Fewer storage backend options (PostgreSQL planned)
-   ⏳ Newer platform (less battle-tested)

---

## Use Case Recommendations

### When to Choose InferaDB

✅ **Best fit**:

-   Need streaming for large result sets (millions of users/resources)
-   Want built-in JWT/OAuth authentication
-   Require batch check with detailed trace
-   Building web applications (REST/SSE support)
-   Need both gRPC and REST APIs
-   Want comprehensive observability out of the box

### When to Choose SpiceDB

✅ **Best fit**:

-   Need battle-tested Google Zanzibar implementation
-   Require CockroachDB or Spanner storage
-   Have existing investment in gRPC
-   Don't need large batch operations
-   Can build your own auth layer

### When to Choose OpenFGA

✅ **Best fit**:

-   Need multi-tenant store isolation
-   Prefer REST over gRPC
-   Want active open-source community
-   Can build your own auth layer
-   Working with CNCF ecosystem

### When to Choose Oso

✅ **Best fit**:

-   Embedded library is acceptable
-   Ultra-low latency required (<1ms)
-   Already have data layer
-   Need flexible policy language
-   Complex ABAC requirements
-   Can manage own infrastructure

### When to Choose WorkOS FGA

✅ **Best fit**:

-   Want fully managed service
-   Don't want to run infrastructure
-   Have budget for SaaS
-   Trust third-party data hosting

### When to Choose Amazon Verified Permissions

✅ **Best fit**:

-   Deep AWS integration required
-   Using Cedar language
-   Want AWS-managed service
-   Primarily ABAC (not ReBAC)

---

## Migration Paths

We provide comprehensive migration guides:

-   **[From SpiceDB](migration/from-spicedb.md)**: API mapping, Zookie → Revision, schema translation
-   **[From OpenFGA](migration/from-openfga.md)**: Store model removal, REST API updates, auth setup
-   **[From Oso](migration/from-oso.md)**: Polar → IPL, embedded → service, data layer migration

---

## Cost Comparison

### Self-Hosted Costs

| Platform | Compute            | Storage             | Bandwidth | Total/month |
| -------- | ------------------ | ------------------- | --------- | ----------- |
| InferaDB | 2x m5.large ($140) | FoundationDB ($100) | Minimal   | ~$240       |
| SpiceDB  | 2x m5.large ($140) | CockroachDB ($200)  | Minimal   | ~$340       |
| OpenFGA  | 2x m5.large ($140) | Postgres ($50)      | Minimal   | ~$190       |
| Oso      | $0 (in-app)        | Your DB             | Minimal   | Variable    |

### Managed Service Costs

| Platform       | Pricing Model         | Est. Cost/month |
| -------------- | --------------------- | --------------- |
| WorkOS FGA     | Per MAU               | $500-5000+      |
| Amazon VP      | Per request + storage | $100-1000+      |
| InferaDB Cloud | ⏳ TBD                | TBD             |

---

## Conclusion

**InferaDB's Unique Value**:

1. ✅ **Only platform with comprehensive streaming** (gRPC + REST/SSE)
2. ✅ **Only platform with batch check + trace** (unlimited size)
3. ✅ **Most complete built-in auth** (JWT/OAuth/OIDC)
4. ✅ **No artificial batch limits** (streaming handles any size)
5. ✅ **Best web support** (SSE streaming for browsers)
6. ✅ **Production-ready observability** (Prometheus + OTel out of box)

**Choose InferaDB if you want**:

-   Modern streaming APIs
-   Built-in production features (auth, metrics, multi-region)
-   No batch size limits
-   Both gRPC and REST support
-   Active development and responsive maintainers

---

## Additional Resources

-   **Full Competitor Analysis**: [COMPARISON.md](../COMPARISON.md)
-   **Individual Comparisons**: [SPICEDB.md](../SPICEDB.md), [OPENFGA.md](../OPENFGA.md), [OSO.md](../OSO.md)
-   **Migration Guides**: [migration/](migration/)
-   **API Documentation**: [api/](../api/README.md)
-   **Architecture**: [docs/architecture.md](architecture.md)

---

**Questions? Feedback?**

-   [GitHub Issues](https://github.com/inferadb/server/issues)
-   [Discussions](https://github.com/inferadb/server/discussions)
-   [Documentation](README.md)
