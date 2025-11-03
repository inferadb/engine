# Migrating from Oso to InferaDB

This guide helps you migrate from Oso (Polar-based authorization) to InferaDB's ReBAC model, covering policy translation, API mapping, and architectural paradigm shifts.

## Why Migrate to InferaDB?

**InferaDB Advantages**:

-   ✅ **Production-Ready**: Built for distributed, high-throughput deployments
-   ✅ **Streaming APIs**: All list operations stream for better performance
-   ✅ **Real-time Watch**: Stream relationship changes for cache invalidation
-   ✅ **Built-in Graph Traversal**: ReBAC model handles complex hierarchies natively
-   ✅ **Multi-tenant**: Built-in JWT/OAuth with tenant isolation
-   ✅ **Performance**: Sub-10ms checks with intelligent caching
-   ✅ **Observability**: Prometheus metrics, OpenTelemetry tracing out of the box

## Paradigm Shift: Logic Programming → ReBAC

This is the most important section. Oso uses **logic programming** (Polar), while InferaDB uses **Relationship-Based Access Control** (ReBAC).

### Oso (Polar Logic Programming)

```polar
# Polar policy
actor User {}
resource Document {
  permissions = ["read", "write"];
  roles = ["reader", "writer", "owner"];

  "read" if "reader";
  "write" if "writer";
  "read" if "writer";
  "write" if "owner";
  "read" if "owner";

  "reader" if role("reader");
  "writer" if role("writer");
  "owner" if role("owner");
}

has_permission(user: User, "read", document: Document) if
  role(user, "reader", document);

has_permission(user: User, "write", document: Document) if
  role(user, "writer", document);
```

### InferaDB (ReBAC/IPL)

```ipl
type document {
    # Direct relations (roles)
    relation reader: user
    relation writer: user
    relation owner: user

    # Computed relations (permissions)
    relation read: user | reader | writer | owner
    relation write: user | writer | owner
}
```

### Key Conceptual Differences

| Concept         | Oso                     | InferaDB                          |
| --------------- | ----------------------- | --------------------------------- |
| **Model**       | Logic programming rules | Relationship graph                |
| **Permissions** | Predicates/rules        | Computed relations                |
| **Roles**       | Facts/assertions        | Direct relations                  |
| **Hierarchy**   | Logic rules             | Relation expressions (`\|`, `->`) |
| **Query**       | Prolog-style resolution | Graph traversal                   |

---

## API Migration Guide

### 1. Authorization Check

**Oso (Python)**:

```python
from oso import Oso

oso = Oso()
oso.load_files(["policy.polar"])

# Check permission
user = User("alice")
document = Document("readme")

if oso.is_allowed(user, "read", document):
    print("Allowed")
```

**InferaDB**:

```bash
# REST API
curl -X POST http://localhost:8080/v1/check \
  -H "Authorization: Bearer YOUR_JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "user:alice",
    "resource": "document:readme",
    "permission": "read"
  }'

# Response: {"decision": "allow"}
```

**InferaDB (Python client)**:

```python
import requests

def check_permission(subject, resource, permission):
    response = requests.post(
        "http://localhost:8080/v1/check",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json"
        },
        json={
            "subject": subject,
            "resource": resource,
            "permission": permission
        }
    )
    return response.json()["decision"] == "allow"

# Usage
if check_permission("user:alice", "document:readme", "read"):
    print("Allowed")
```

### 2. List Authorized Resources

**Oso**:

```python
from oso import Oso

oso = Oso()
user = User("alice")

# List all resources user can read
authorized_docs = oso.authorized_resources(user, "read", Document)
for doc in authorized_docs:
    print(doc.id)
```

**InferaDB**:

```bash
# REST with SSE streaming
curl -X POST http://localhost:8080/v1/list-resources/stream \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "subject": "user:alice",
    "resource_type": "document",
    "permission": "read"
  }'
```

**InferaDB (Python client with streaming)**:

```python
import requests

def list_authorized_resources(subject, resource_type, permission):
    response = requests.post(
        "http://localhost:8080/v1/list-resources/stream",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json"
        },
        json={
            "subject": subject,
            "resource_type": resource_type,
            "permission": permission
        },
        stream=True  # Enable streaming
    )

    resources = []
    for line in response.iter_lines():
        if line:
            data = json.loads(line)
            resources.extend(data.get("resources", []))

    return resources

# Usage
docs = list_authorized_resources("user:alice", "document", "read")
for doc in docs:
    print(doc)
```

### 3. List Users with Access

**Oso**:

```python
# Oso doesn't have built-in "list users" functionality
# You'd need to query all users and check each one

all_users = User.all()
users_with_access = []
for user in all_users:
    if oso.is_allowed(user, "read", document):
        users_with_access.append(user)
```

**InferaDB**:

```bash
# Efficient server-side computation with streaming
curl -X POST http://localhost:8080/v1/list-subjects/stream \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "resource": "document:readme",
    "relation": "read",
    "subject_type": "user"
  }'
```

**InferaDB (Python client)**:

```python
def list_users_with_access(resource, permission, subject_type="user"):
    response = requests.post(
        "http://localhost:8080/v1/list-subjects/stream",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json"
        },
        json={
            "resource": resource,
            "relation": permission,
            "subject_type": subject_type
        },
        stream=True
    )

    subjects = []
    for line in response.iter_lines():
        if line:
            data = json.loads(line)
            subjects.extend(data.get("subjects", []))

    return subjects

# Usage - Much more efficient than Oso's approach
users = list_users_with_access("document:readme", "read")
```

### 4. Assign Roles/Permissions

**Oso**:

```python
# Oso requires you to manage data layer
# Typically with database calls
db.execute("""
    INSERT INTO roles (user_id, role, resource_type, resource_id)
    VALUES (?, ?, ?, ?)
""", (user.id, "reader", "document", document.id))

# Then tell Oso about the fact
oso.tell("role", user, "reader", document)
```

**InferaDB**:

```bash
# Single API call, database managed internally
curl -X POST http://localhost:8080/v1/write-relationships \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "relationships": [
      {
        "resource": "document:readme",
        "relation": "reader",
        "subject": "user:alice"
      }
    ]
  }'
```

**InferaDB (Python client)**:

```python
def assign_role(subject, role, resource):
    response = requests.post(
        "http://localhost:8080/v1/write-relationships",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json"
        },
        json={
            "relationships": [{
                "resource": resource,
                "relation": role,
                "subject": subject
            }]
        }
    )
    return response.json()

# Usage
assign_role("user:alice", "reader", "document:readme")
```

### 5. Remove Roles/Permissions

**Oso**:

```python
# Manual database deletion
db.execute("""
    DELETE FROM roles
    WHERE user_id = ? AND role = ? AND resource_id = ?
""", (user.id, "reader", document.id))
```

**InferaDB**:

```bash
curl -X POST http://localhost:8080/v1/delete-relationships \
  -H "Authorization: Bearer YOUR_JWT" \
  -d '{
    "relationships": [
      {
        "resource": "document:readme",
        "relation": "reader",
        "subject": "user:alice"
      }
    ]
  }'
```

**InferaDB (Python client)**:

```python
def remove_role(subject, role, resource):
    response = requests.post(
        "http://localhost:8080/v1/delete-relationships",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json"
        },
        json={
            "relationships": [{
                "resource": resource,
                "relation": role,
                "subject": subject
            }]
        }
    )
    return response.json()

# Usage
remove_role("user:alice", "reader", "document:readme")
```

---

## Policy Translation Guide

### Example 1: Basic RBAC

**Oso (Polar)**:

```polar
resource Document {
  permissions = ["read", "write", "delete"];
  roles = ["reader", "writer", "owner"];

  "read" if "reader";
  "read" if "writer";
  "read" if "owner";

  "write" if "writer";
  "write" if "owner";

  "delete" if "owner";

  "reader" if role("reader");
  "writer" if role("writer");
  "owner" if role("owner");
}
```

**InferaDB (IPL)**:

```ipl
type document {
    # Roles (direct relations)
    relation reader: user
    relation writer: user
    relation owner: user

    # Permissions (computed relations)
    relation read: user | reader | writer | owner
    relation write: user | writer | owner
    relation delete: user | owner
}
```

### Example 2: Hierarchical Organizations

**Oso (Polar)**:

```polar
resource Organization {
  roles = ["member", "admin"];
  relations = {"parent": Organization};

  "member" if role("member");
  "admin" if role("admin");

  # Inherited membership
  "member" if "member" on "parent";
  "admin" if "admin" on "parent";
}

has_role(user: User, role: String, org: Organization) if
  role(user, role, org);

has_role(user: User, role: String, org: Organization) if
  parent_org matches Organization from org.parent and
  has_role(user, role, parent_org);
```

**InferaDB (IPL)**:

```ipl
type organization {
    relation parent: organization
    relation member: user
    relation admin: user

    # Inherited membership through parent
    relation all_members: user | member | parent->all_members
    relation all_admins: user | admin | parent->all_admins
}
```

### Example 3: Folder Hierarchies

**Oso (Polar)**:

```polar
resource Folder {
  permissions = ["view"];
  roles = ["viewer"];
  relations = {"parent": Folder};

  "view" if "viewer";
  "view" if "view" on "parent";

  "viewer" if role("viewer");
}
```

**InferaDB (IPL)**:

```ipl
type folder {
    relation parent: folder
    relation viewer: user

    # View permission includes direct viewers and parent viewers
    relation view: user | viewer | parent->view
}
```

### Example 4: Document with Folder Inheritance

**Oso (Polar)**:

```polar
resource Document {
  permissions = ["view", "edit"];
  roles = ["viewer", "editor"];
  relations = {"parent": Folder};

  "view" if "viewer";
  "view" if "editor";
  "view" if "view" on "parent";

  "edit" if "editor";

  "viewer" if role("viewer");
  "editor" if role("editor");
}
```

**InferaDB (IPL)**:

```ipl
type document {
    relation parent: folder
    relation viewer: user
    relation editor: user

    # View: direct viewers, editors, or inherited from folder
    relation view: user | viewer | editor | parent->view

    # Edit: only direct editors
    relation edit: user | editor
}
```

---

## Attribute-Based Access Control (ABAC)

### Oso (Built-in ABAC)

**Oso**:

```polar
allow(user: User, "read", document: Document) if
  document.public = true;

allow(user: User, "read", document: Document) if
  user.department = document.department;

allow(user: User, "read", document: Document) if
  user.clearance_level >= document.classification_level;
```

### InferaDB (WASM-based ABAC)

**InferaDB** uses WASM modules for attribute-based policies:

```ipl
type document {
    relation reader: user

    # ABAC via WASM module
    relation view: user | reader | wasm("document_access")
}
```

**WASM Module** (Rust):

```rust
use infera_wasm_sdk::*;

#[wasm_policy]
fn document_access(subject: &Subject, resource: &Resource, context: &Context) -> Decision {
    // Check if document is public
    if resource.get_attr("public") == Some("true") {
        return Decision::Allow;
    }

    // Check department match
    if subject.get_attr("department") == resource.get_attr("department") {
        return Decision::Allow;
    }

    // Check clearance level
    let user_clearance: u32 = subject.get_attr("clearance_level")?.parse()?;
    let doc_classification: u32 = resource.get_attr("classification_level")?.parse()?;

    if user_clearance >= doc_classification {
        return Decision::Allow;
    }

    Decision::Deny
}
```

**Trade-offs**:

-   ⚠️ More complex setup (WASM compilation required)
-   ✅ Better performance (compiled code)
-   ✅ Type safety
-   ✅ Separation of logic and data

---

## Data Layer Migration

### Oso Data Storage

**Oso requires you to manage data**:

```python
# You maintain your own database schema
class Role(Model):
    user_id = ForeignKey(User)
    role = CharField()
    resource_type = CharField()
    resource_id = CharField()

# And query it manually
def has_role(user, role, resource):
    return Role.objects.filter(
        user_id=user.id,
        role=role,
        resource_type=resource.type,
        resource_id=resource.id
    ).exists()
```

### InferaDB Data Storage

**InferaDB manages data internally**:

-   ✅ No database schema needed
-   ✅ No SQL queries to write
-   ✅ Optimized indexes automatically created
-   ✅ Built-in replication and consistency

```python
# Just call the API
response = requests.post(
    "http://localhost:8080/v1/write-relationships",
    headers={"Authorization": f"Bearer {jwt}"},
    json={"relationships": [{
        "resource": "document:readme",
        "relation": "reader",
        "subject": "user:alice"
    }]}
)
```

---

## Architecture Comparison

### Oso (Embedded Library)

```
┌─────────────────────────────────────┐
│   Your Application                   │
│                                      │
│   ┌──────────────────────────────┐  │
│   │ Oso Library (in-process)     │  │
│   │ • Policy evaluation          │  │
│   │ • No network calls           │  │
│   │ • Loads .polar files         │  │
│   └──────────────────────────────┘  │
│              ↓                       │
│   ┌──────────────────────────────┐  │
│   │ Your Database                │  │
│   │ • You manage schema          │  │
│   │ • You write queries          │  │
│   │ • You handle replication     │  │
│   └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

### InferaDB (Microservice)

```
┌─────────────────────┐      ┌──────────────────────┐
│ Your Application    │      │   InferaDB Service   │
│                     │      │                      │
│ HTTP/gRPC Client ───┼──────┤ • Policy evaluation  │
│                     │      │ • Manages storage    │
│                     │      │ • Built-in auth      │
│                     │      │ • Replication        │
│                     │      │ • Caching            │
└─────────────────────┘      └──────────────────────┘
                                       ↓
                              ┌──────────────────────┐
                              │ Storage (FDB/Memory) │
                              │ • Automatic indexes  │
                              │ • Distributed        │
                              │ • High availability  │
                              └──────────────────────┘
```

**Trade-offs**:

| Aspect          | Oso (Embedded)     | InferaDB (Service)      |
| --------------- | ------------------ | ----------------------- |
| Deployment      | In-process library | Separate microservice   |
| Latency         | No network (<1ms)  | Network call (~5ms)     |
| Scaling         | Scales with app    | Independent scaling     |
| Data Management | You manage it      | Managed for you         |
| Multi-tenant    | DIY                | Built-in                |
| Observability   | DIY                | Built-in metrics/traces |
| Caching         | DIY                | Built-in                |
| Updates         | Redeploy app       | Deploy service only     |

---

## Migration Checklist

### 1. Policy Translation

-   [ ] Identify all Polar policy files
-   [ ] Map `resource` types to InferaDB `type`
-   [ ] Convert `permissions` to computed `relation`
-   [ ] Convert `roles` to direct `relation`
-   [ ] Map hierarchies to `->` operator
-   [ ] Test schema with sample data

### 2. ABAC Migration

-   [ ] Identify attribute-based rules in Polar
-   [ ] Decide: Convert to ReBAC or use WASM
-   [ ] If WASM: Write WASM modules
-   [ ] If ReBAC: Model attributes as relations
-   [ ] Test attribute checking

### 3. Data Migration

-   [ ] Export role/permission data from your database
-   [ ] Convert to InferaDB relationship format
-   [ ] Bulk import via WriteRelationships API
-   [ ] Verify data integrity

### 4. Application Code Updates

-   [ ] Replace `oso.is_allowed()` with Check API calls
-   [ ] Replace `authorized_resources()` with ListResources
-   [ ] Replace database role queries with ListRelationships
-   [ ] Add JWT tokens to API calls
-   [ ] Handle streaming responses
-   [ ] Update error handling

### 5. Remove Oso Dependencies

-   [ ] Remove Oso library dependency
-   [ ] Remove .polar policy files
-   [ ] Remove role/permission database tables
-   [ ] Remove manual data layer code
-   [ ] Clean up imports

### 6. Deployment

-   [ ] Deploy InferaDB service (Docker/K8s)
-   [ ] Configure storage backend
-   [ ] Deploy IPL schema
-   [ ] Set up JWT/OAuth authentication
-   [ ] Configure monitoring
-   [ ] Set up alerts

### 7. Testing

-   [ ] Port authorization tests
-   [ ] Test with production data sample
-   [ ] Performance testing
-   [ ] Load testing
-   [ ] Verify consistency

---

## Common Gotchas

### 1. Logic Programming vs Graph Traversal

**Oso**: Prolog-style logic resolution
**InferaDB**: Graph traversal

**Solution**: Think in terms of relationships and paths, not predicates and rules.

### 2. Embedded vs Service

**Oso**: In-process, no network overhead
**InferaDB**: Microservice, network calls

**Solution**: Cache frequently-checked permissions, use batch check for multiple items.

### 3. Data Management

**Oso**: You manage data layer
**InferaDB**: Data managed for you

**Solution**: Remove your custom data layer, use InferaDB APIs.

### 4. ABAC Complexity

**Oso**: Built-in attribute checking
**InferaDB**: WASM modules required

**Solution**: Evaluate if you really need ABAC, or if ReBAC can model your use case.

### 5. Schema Changes

**Oso**: Edit .polar file, reload
**InferaDB**: Deploy new schema

**Solution**: Treat schema as code, version control, test in staging first.

---

## Performance Comparison

| Operation      | Oso (In-process) | InferaDB (Network) | Notes                   |
| -------------- | ---------------- | ------------------ | ----------------------- |
| Simple Check   | <1ms             | ~5ms               | Network overhead        |
| Complex Check  | 1-10ms           | 5-20ms             | Graph traversal         |
| List Resources | N \* check_time  | Streaming          | InferaDB more efficient |
| List Users     | N \* check_time  | Streaming          | InferaDB far better     |
| Data Updates   | Database write   | API call           | Similar                 |

**When InferaDB is Faster**:

-   ✅ List operations (server-side computation)
-   ✅ Complex hierarchies (optimized graph traversal)
-   ✅ Multi-tenant scenarios (data isolation)

**When Oso is Faster**:

-   ⚠️ Single, simple checks (no network)
-   ⚠️ Read-heavy, write-rare workloads (in-memory)

---

## Support Resources

-   **InferaDB Documentation**: [docs/](../README.md)
-   **API Reference**: [api/](../../api/README.md)
-   **Oso Comparison**: [OSO.md](../../OSO.md)
-   **WASM Guide**: [docs/advanced/wasm.md](../advanced/wasm.md)
-   **GitHub Issues**: [Issues](https://github.com/inferadb/server/issues)
-   **Community**: [Discussions](https://github.com/inferadb/server/discussions)

---

## Need Help?

Migration from Oso can be complex due to paradigm shift:

1. **Start here**: [Quick Start](../quickstart.md)
2. **Understand ReBAC**: [Architecture](../architecture.md)
3. **Check examples**: [COMPARISON.md](../../COMPARISON.md)
4. **Ask questions**: [Discussions](https://github.com/inferadb/server/discussions)
5. **Report issues**: [GitHub Issues](https://github.com/inferadb/server/issues)

The paradigm shift from logic programming to ReBAC is worth it for production scale! 🚀
