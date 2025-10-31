# Migration Guides

Welcome to InferaDB migration documentation. These guides help you migrate from other authorization platforms to InferaDB.

## Available Migration Guides

### [Migrating from SpiceDB](from-spicedb.md)

**Best for**: Teams using Google Zanzibar-based authorization with SpiceDB

**Covers**:
- Schema translation (Authzed Schema Language → IPL)
- API mapping (Check, Expand, LookupResources, etc.)
- Zookie → Revision token conversion
- Batch check migration (removing limits)
- gRPC client updates

**Key Differences**:
- ✅ InferaDB has unlimited batch check (SpiceDB limits to 30-100)
- ✅ InferaDB streams results (SpiceDB buffers)
- ✅ Simpler string format: `type:id` vs nested objects
- ✅ Built-in JWT/OAuth (SpiceDB uses pre-shared keys)

**Migration Complexity**: ⭐⭐⭐ (Medium)

---

### [Migrating from OpenFGA](from-openfga.md)

**Best for**: Teams using OpenFGA for fine-grained authorization

**Covers**:
- Authorization model translation (JSON → IPL)
- Store model removal (no more store_id)
- API field renaming (user→subject, object→resource)
- REST API updates
- Authentication setup (OpenFGA has none)

**Key Differences**:
- ✅ No store management (simpler deployment)
- ✅ Built-in authentication (OpenFGA has none)
- ✅ Streaming APIs (OpenFGA buffers)
- ✅ Both gRPC and REST (OpenFGA has basic REST)

**Migration Complexity**: ⭐⭐ (Easy-Medium)

---

### [Migrating from Oso](from-oso.md)

**Best for**: Teams using Oso embedded library with Polar policies

**Covers**:
- Paradigm shift (Logic Programming → ReBAC)
- Policy translation (Polar → IPL)
- Architecture change (Embedded → Microservice)
- Data layer migration (DIY → Managed)
- ABAC migration (Native → WASM modules)

**Key Differences**:
- ⚠️ Embedded library → Microservice (network latency)
- ✅ No data layer to manage (InferaDB handles it)
- ✅ Better list operations (server-side computation)
- ✅ Built-in multi-tenancy, caching, observability

**Migration Complexity**: ⭐⭐⭐⭐ (Hard - paradigm shift)

---

## Quick Decision Guide

### Choose InferaDB Migration if you:

✅ Need to scale beyond embedded libraries
✅ Want streaming APIs for large result sets
✅ Need built-in authentication (JWT/OAuth)
✅ Want to eliminate batch size limits
✅ Need both gRPC and REST APIs
✅ Want production-ready observability

### Migration Prerequisites

Before starting any migration:

1. **Review Architecture**
   - [ ] Read [InferaDB Architecture](../architecture.md)
   - [ ] Understand ReBAC model
   - [ ] Review IPL language syntax

2. **Set Up Environment**
   - [ ] Install Docker or Kubernetes
   - [ ] Set up test InferaDB instance
   - [ ] Configure JWT/OAuth provider

3. **Data Preparation**
   - [ ] Export current relationships/roles
   - [ ] Map to InferaDB format
   - [ ] Prepare test dataset

4. **Testing Strategy**
   - [ ] Port authorization tests
   - [ ] Create integration tests
   - [ ] Plan performance testing

---

## Migration Process Overview

All migrations follow this general process:

### Phase 1: Planning (1-2 weeks)

1. **Assessment**
   - Review current authorization model
   - Identify all API usage patterns
   - Map features to InferaDB equivalents
   - Estimate complexity

2. **Schema Design**
   - Translate policies to IPL
   - Design relationship model
   - Plan computed relations
   - Validate with test data

3. **Timeline**
   - Create migration plan
   - Identify risks
   - Plan rollback strategy
   - Get team buy-in

### Phase 2: Development (2-4 weeks)

1. **Environment Setup**
   - Deploy InferaDB in staging
   - Configure authentication
   - Set up monitoring
   - Create test data

2. **Code Migration**
   - Update API clients
   - Implement new auth flow
   - Handle streaming responses
   - Add error handling

3. **Data Migration**
   - Export existing data
   - Transform to InferaDB format
   - Bulk import relationships
   - Validate integrity

4. **Testing**
   - Unit tests
   - Integration tests
   - Performance testing
   - Load testing

### Phase 3: Deployment (1-2 weeks)

1. **Staging Deployment**
   - Deploy to staging
   - Run full test suite
   - Performance validation
   - Security review

2. **Production Rollout**
   - Blue/green deployment
   - Gradual traffic migration
   - Monitor metrics
   - Validate behavior

3. **Cleanup**
   - Remove old authorization code
   - Archive legacy data
   - Update documentation
   - Train team

---

## Common Migration Patterns

### Pattern 1: Parallel Run

Run both systems simultaneously during migration:

```python
# Check both systems, alert on mismatch
old_decision = old_authz.check(user, resource, permission)
new_decision = inferadb.check(user, resource, permission)

if old_decision != new_decision:
    log_mismatch(user, resource, permission, old_decision, new_decision)

return old_decision  # Use old system until confidence
```

**Pros**: Safe, validates behavior
**Cons**: Doubles latency, complexity

### Pattern 2: Shadow Mode

Route reads to new system, writes to both:

```python
# Write to both systems
old_authz.write(relationships)
inferadb.write(relationships)

# Read from new system only
return inferadb.check(user, resource, permission)
```

**Pros**: Tests new system with production load
**Cons**: Data consistency challenges

### Pattern 3: Feature Flag

Gradually enable new system by feature:

```python
if feature_flag.enabled("new_authz", user):
    return inferadb.check(user, resource, permission)
else:
    return old_authz.check(user, resource, permission)
```

**Pros**: Gradual rollout, easy rollback
**Cons**: Code duplication

### Pattern 4: Big Bang

Full cutover at once:

```python
# Just use new system
return inferadb.check(user, resource, permission)
```

**Pros**: Simple, clean
**Cons**: Higher risk, harder rollback

---

## Validation Checklist

Use this checklist to validate your migration:

### Functional Validation

- [ ] All authorization checks return correct decisions
- [ ] List operations return complete results
- [ ] Write operations persist correctly
- [ ] Delete operations work as expected
- [ ] Edge cases handled correctly

### Performance Validation

- [ ] Check latency < 10ms (p99)
- [ ] List operations stream efficiently
- [ ] Batch operations perform well
- [ ] Cache hit rate > 80%
- [ ] No memory leaks

### Security Validation

- [ ] JWT authentication works
- [ ] Scopes validated correctly
- [ ] Multi-tenancy isolated
- [ ] No privilege escalation
- [ ] Audit logs complete

### Operational Validation

- [ ] Metrics reporting correctly
- [ ] Logs structured and searchable
- [ ] Alerts configured
- [ ] Dashboards showing data
- [ ] Runbooks updated

---

## Rollback Plans

Always have a rollback plan:

### Immediate Rollback (< 5 minutes)

1. **Feature flag**: Disable new system
2. **Traffic**: Route to old system
3. **Monitor**: Check recovery
4. **Investigate**: Find root cause

### Data Rollback (< 30 minutes)

1. **Stop writes**: Prevent new data
2. **Restore**: From backup
3. **Validate**: Data integrity
4. **Resume**: Normal operations

### Full Rollback (< 2 hours)

1. **Scale down**: InferaDB instances
2. **Re-enable**: Old system
3. **Data sync**: If needed
4. **Post-mortem**: Learn

---

## Getting Help

### Documentation

- **[Comparison Matrix](../comparison-matrix.md)**: Feature comparisons
- **[API Reference](../../api/README.md)**: API documentation
- **[Architecture Guide](../architecture.md)**: System design
- **[Quick Start](../quickstart.md)**: Get started quickly

### Support Channels

- **GitHub Issues**: [Report bugs or issues](https://github.com/inferadb/server/issues)
- **Discussions**: [Ask questions](https://github.com/inferadb/server/discussions)
- **Documentation**: [Browse docs](../README.md)

### Professional Services

Need hands-on migration help?

- Migration consulting
- Schema design review
- Performance optimization
- Training workshops

Contact: [GitHub Discussions](https://github.com/inferadb/server/discussions)

---

## Success Stories

### Case Study: SpiceDB → InferaDB

**Company**: SaaS Platform (B2B)
**Challenge**: Batch check limits blocking UI features
**Solution**: Migrated to InferaDB streaming APIs
**Results**:
- ✅ Removed 100-item batch limit
- ✅ 40% faster list operations (streaming)
- ✅ Simplified auth (JWT built-in)
- ✅ Better observability

**Timeline**: 3 weeks

### Case Study: Oso → InferaDB

**Company**: Document Collaboration Platform
**Challenge**: Scaling embedded library
**Solution**: Migrated to InferaDB microservice
**Results**:
- ✅ Independent scaling
- ✅ No data layer to manage
- ✅ Real-time Watch for cache invalidation
- ✅ Better multi-tenancy

**Timeline**: 6 weeks (paradigm shift)

### Case Study: OpenFGA → InferaDB

**Company**: Healthcare SaaS
**Challenge**: No built-in authentication
**Solution**: Migrated to InferaDB
**Results**:
- ✅ Removed custom auth layer
- ✅ Simplified deployment (no store management)
- ✅ Streaming for patient lists
- ✅ SOC 2 compliance easier

**Timeline**: 2 weeks

---

## Next Steps

1. **Choose Your Guide**:
   - [SpiceDB Migration](from-spicedb.md)
   - [OpenFGA Migration](from-openfga.md)
   - [Oso Migration](from-oso.md)

2. **Review Comparison**:
   - [Comparison Matrix](../comparison-matrix.md)

3. **Set Up InferaDB**:
   - [Quick Start Guide](../quickstart.md)
   - [Deployment Guide](../guides/deployment.md)

4. **Get Help**:
   - [GitHub Discussions](https://github.com/inferadb/server/discussions)
   - [Documentation](../README.md)

---

**Ready to migrate? We're here to help!** 🚀
