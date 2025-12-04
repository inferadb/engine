# Migration Guides

Welcome to InferaDB migration documentation. These guides help you migrate from other authorization platforms to InferaDB.

## Available Migration Guides

### [Migrating from SpiceDB](SpiceDB.md)

**Key Differences**:

- ✅ InferaDB has unlimited batch check (SpiceDB limits to 30-100)
- ✅ InferaDB streams results (SpiceDB buffers)
- ✅ Simpler string format: `type:id` vs nested objects
- ✅ Built-in JWT/OAuth (SpiceDB uses pre-shared keys)

---

### [Migrating from OpenFGA](OpenFGA.md)

**Key Differences**:

- ✅ No store management (simpler deployment)
- ✅ Built-in authentication (OpenFGA has none)
- ✅ Streaming APIs (OpenFGA buffers)
- ✅ Both gRPC and REST (OpenFGA has basic REST)

---

### [Migrating from Oso](Oso.md)

**Key Differences**:

- ⚠️ Embedded library → Microservice (network latency)
- ✅ No data layer to manage (InferaDB handles it)
- ✅ Better list operations (server-side computation)
- ✅ Built-in multi-tenancy, caching, observability

---

## Quick Decision Guide

### Choose InferaDB Migration if you

✅ Need to scale beyond embedded libraries
✅ Want streaming APIs for large result sets
✅ Need built-in authentication (JWT/OAuth)
✅ Want to eliminate batch size limits
✅ Need both gRPC and REST APIs
✅ Want production-ready observability

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
