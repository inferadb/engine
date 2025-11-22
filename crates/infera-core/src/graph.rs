//! Graph traversal for policy evaluation

use std::{collections::HashSet, sync::Arc};

use async_recursion::async_recursion;
use infera_store::RelationshipStore;
use infera_types::{RelationshipKey, Revision};

use crate::{
    EvalError, Result,
    ipl::{RelationExpr, Schema},
};

/// Graph traversal context
pub struct GraphContext {
    /// The policy schema
    pub schema: Arc<Schema>,

    /// Storage backend
    pub store: Arc<dyn RelationshipStore>,

    /// Current revision to read at
    pub revision: Revision,

    /// Vault ID for multi-tenant isolation
    pub vault: i64,

    /// Visited nodes for cycle detection
    pub visited: HashSet<String>,

    /// Maximum traversal depth
    max_depth: usize,
}

impl GraphContext {
    pub fn new(
        schema: Arc<Schema>,
        store: Arc<dyn RelationshipStore>,
        revision: Revision,
        vault: i64,
    ) -> Self {
        Self {
            schema,
            store,
            revision,
            vault,
            visited: HashSet::new(),
            max_depth: 100, // Prevent infinite recursion
        }
    }

    /// Check if we're in a cycle
    pub fn is_visited(&self, key: &str) -> bool {
        self.visited.contains(key)
    }

    /// Mark a node as visited
    pub fn visit(&mut self, key: String) {
        self.visited.insert(key);
    }

    /// Unmark a node (for backtracking)
    pub fn unvisit(&mut self, key: &str) {
        self.visited.remove(key);
    }

    /// Check traversal depth
    pub fn check_depth(&self) -> Result<()> {
        if self.visited.len() > self.max_depth {
            return Err(EvalError::Evaluation(
                "Maximum traversal depth exceeded (possible cycle)".to_string(),
            ));
        }
        Ok(())
    }
}

/// Check if a direct relationship exists between subject and resource
///
/// This function checks for both exact subject matches and wildcard patterns
/// (e.g., `user:*` matches any user like `user:alice`). Wildcard matching enables
/// modeling public resources accessible to all users of a given type.
///
/// The function performs two lookups:
/// 1. Exact match: `(resource, relation, subject)` relationship exists
/// 2. Wildcard match: `(resource, relation, type:*)` relationship exists, where `type` is extracted
///    from the subject (e.g., "user" from "user:alice")
///
/// # Arguments
///
/// * `store` - The relationship store to query
/// * `vault` - Vault UUID for multi-tenant isolation
/// * `resource` - The resource identifier (e.g., "doc:readme")
/// * `relation` - The relation name (e.g., "viewer")
/// * `subject` - The subject identifier (e.g., "user:alice")
/// * `revision` - Revision for consistent reads (use `Revision(u64::MAX)` for latest)
///
/// # Returns
///
/// Returns `Ok(true)` if the relationship exists (either exact or wildcard match),
/// `Ok(false)` if no relationship exists, or `Err` if the storage operation fails.
///
/// # Example
///
/// ```ignore
/// use infera_core::graph::has_direct_relationship;
/// use infera_types::Revision;
///
/// # async {
/// let vault_id = 1i64;
/// let revision = Revision(u64::MAX); // Latest revision
///
/// // Check if user:alice is a viewer of doc:readme
/// let exists = has_direct_relationship(
///     &store,
///     vault_id,
///     "doc:readme",
///     "viewer",
///     "user:alice",
///     revision
/// ).await?;
///
/// if exists {
///     println!("Relationship exists");
/// }
/// # Ok::<(), infera_core::EvalError>(())
/// # };
/// ```
pub async fn has_direct_relationship(
    store: &dyn RelationshipStore,
    vault: i64,
    resource: &str,
    relation: &str,
    subject: &str,
    revision: Revision,
) -> Result<bool> {
    // Check for exact subject match
    let key = RelationshipKey {
        resource: resource.to_string(),
        relation: relation.to_string(),
        subject: Some(subject.to_string()),
    };

    let relationships = store.read(vault, &key, revision).await?;
    if !relationships.is_empty() {
        return Ok(true);
    }

    // Also check for wildcard subject match (type:*)
    // Extract the subject type (e.g., "user" from "user:alice")
    if let Some(subject_type) = subject.split(':').next() {
        let wildcard_subject = format!("{}:*", subject_type);
        let wildcard_key = RelationshipKey {
            resource: resource.to_string(),
            relation: relation.to_string(),
            subject: Some(wildcard_subject),
        };

        let wildcard_relationships = store.read(vault, &wildcard_key, revision).await?;
        if !wildcard_relationships.is_empty() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Get all users (subjects) with a specific relation on a resource
///
/// This function retrieves all subjects that have a given relation to a resource.
/// For example, it can answer questions like "Who are all the viewers of doc:readme?"
/// or "Which users can edit folder:shared?".
///
/// The function returns all subjects for the given `(resource, relation)` pair,
/// including both explicitly defined subjects and wildcard subjects (e.g., `user:*`).
///
/// # Arguments
///
/// * `store` - The relationship store to query
/// * `vault` - Vault UUID for multi-tenant isolation
/// * `resource` - The resource identifier (e.g., "doc:readme", "folder:shared")
/// * `relation` - The relation name (e.g., "viewer", "editor", "owner")
/// * `revision` - Revision for consistent reads (use `Revision(u64::MAX)` for latest)
///
/// # Returns
///
/// Returns `Ok(Vec<String>)` containing all subjects with the relation, or `Err`
/// if the storage operation fails. Returns an empty vector if no relationships exist.
///
/// # Example
///
/// ```ignore
/// use infera_core::graph::get_users_with_relation;
/// use infera_types::Revision;
///
/// # async {
/// let vault_id = 1i64;
/// let revision = Revision(u64::MAX); // Latest revision
///
/// // Get all users who can view doc:readme
/// let viewers = get_users_with_relation(
///     &store,
///     vault_id,
///     "doc:readme",
///     "viewer",
///     revision
/// ).await?;
///
/// for viewer in viewers {
///     println!("Viewer: {}", viewer);
/// }
/// # Ok::<(), infera_core::EvalError>(())
/// # };
/// ```
pub async fn get_users_with_relation(
    store: &dyn RelationshipStore,
    vault: i64,
    resource: &str,
    relation: &str,
    revision: Revision,
) -> Result<Vec<String>> {
    let key = RelationshipKey {
        resource: resource.to_string(),
        relation: relation.to_string(),
        subject: None,
    };

    let relationships = store.read(vault, &key, revision).await?;
    Ok(relationships.into_iter().map(|t| t.subject).collect())
}

/// Batch prefetch users with a specific relation for multiple resources
///
/// This function performs concurrent lookups to retrieve subjects for a given
/// relation across multiple resources. It's a performance optimization for graph
/// traversal scenarios where the same relation needs to be queried for many resources,
/// such as when evaluating `ComputedUserset` or `RelatedObjectUserset` expressions.
///
/// Instead of serially querying each resource, this function executes all queries
/// concurrently using `join_all`, significantly reducing total latency when traversing
/// complex permission graphs.
///
/// # Arguments
///
/// * `store` - The relationship store to query
/// * `vault` - Vault UUID for multi-tenant isolation
/// * `objects` - Slice of resource identifiers to query (e.g., `["doc:readme", "doc:guide"]`)
/// * `relation` - The relation name to look up (e.g., "viewer", "owner")
/// * `revision` - Revision for consistent reads (use `Revision(u64::MAX)` for latest)
///
/// # Returns
///
/// Returns `Ok(HashMap<String, Vec<String>>)` mapping each resource to its list of
/// subjects with the given relation. If a resource has no subjects for the relation,
/// it will be present in the map with an empty vector. Returns `Err` if any storage
/// operation fails.
///
/// # Performance
///
/// This function uses parallel execution for all resource queries. For N resources,
/// latency is roughly `O(1)` storage query time rather than `O(N)` sequential queries.
///
/// # Example
///
/// ```ignore
/// use infera_core::graph::prefetch_users_batch;
/// use infera_types::Revision;
///
/// # async {
/// let vault_id = 1i64;
/// let revision = Revision(u64::MAX);
///
/// // Get all editors for multiple documents at once
/// let documents = vec![
///     "doc:readme".to_string(),
///     "doc:guide".to_string(),
///     "doc:tutorial".to_string(),
/// ];
///
/// let editors_map = prefetch_users_batch(
///     &store,
///     vault_id,
///     &documents,
///     "editor",
///     revision
/// ).await?;
///
/// for (doc, editors) in editors_map {
///     println!("{} has {} editors", doc, editors.len());
/// }
/// # Ok::<(), infera_core::EvalError>(())
/// # };
/// ```
pub async fn prefetch_users_batch(
    store: &dyn RelationshipStore,
    vault: i64,
    objects: &[String],
    relation: &str,
    revision: Revision,
) -> Result<std::collections::HashMap<String, Vec<String>>> {
    use futures::future::join_all;

    // Create parallel fetch tasks for each object
    let tasks: Vec<_> = objects
        .iter()
        .map(|object| {
            let obj = object.clone();
            let rel = relation.to_string();
            async move {
                let users = get_users_with_relation(store, vault, &obj, &rel, revision).await?;
                Ok::<_, crate::EvalError>((obj, users))
            }
        })
        .collect();

    // Execute all fetches concurrently
    let results = join_all(tasks).await;

    // Collect into HashMap
    let mut map = std::collections::HashMap::new();
    for result in results {
        let (resource, users) = result?;
        map.insert(resource, users);
    }

    Ok(map)
}

/// Resolve a userset (get all users in a userset)
#[async_recursion]
pub async fn resolve_userset(
    resource: &str,
    relation: &str,
    ctx: &mut GraphContext,
) -> Result<HashSet<String>> {
    ctx.check_depth()?;

    // Check for cycles
    let key = format!("{}#{}", resource, relation);
    if ctx.is_visited(&key) {
        // Cycle detected, return empty set
        return Ok(HashSet::new());
    }

    ctx.visit(key.clone());

    // Get the type and relation definition
    let type_name = resource
        .split(':')
        .next()
        .ok_or_else(|| EvalError::Evaluation("Invalid object format".to_string()))?;

    let type_def = ctx
        .schema
        .find_type(type_name)
        .ok_or_else(|| EvalError::Evaluation(format!("Type not found: {}", type_name)))?;

    let relation_def = type_def
        .find_relation(relation)
        .ok_or_else(|| EvalError::Evaluation(format!("Relation not found: {}", relation)))?;

    let mut users = HashSet::new();

    // If no expression or just "this", return direct relationships
    if let Some(expr) = &relation_def.expr {
        let expr_clone = expr.clone();
        users = evaluate_relation_expr(resource, relation, &expr_clone, ctx).await?;
    } else {
        let direct_users =
            get_users_with_relation(&*ctx.store, ctx.vault, resource, relation, ctx.revision)
                .await?;
        users.extend(direct_users);
    }

    ctx.unvisit(&key);
    Ok(users)
}

/// Evaluate a relation expression to get a userset
#[async_recursion]
async fn evaluate_relation_expr(
    resource: &str,
    relation: &str,
    expr: &RelationExpr,
    ctx: &mut GraphContext,
) -> Result<HashSet<String>> {
    match expr {
        RelationExpr::This => {
            // Direct relationships for the current relation
            let direct_users =
                get_users_with_relation(&*ctx.store, ctx.vault, resource, relation, ctx.revision)
                    .await?;
            Ok(direct_users.into_iter().collect())
        },

        RelationExpr::RelationRef { relation } => {
            // Reference to another relation on the same object
            resolve_userset(resource, relation, ctx).await
        },

        RelationExpr::ComputedUserset { relation, relationship } => {
            // Get objects from relationship, then compute relation on each
            let related_objects = get_users_with_relation(
                &*ctx.store,
                ctx.vault,
                resource,
                relationship,
                ctx.revision,
            )
            .await?;

            let mut users = HashSet::new();
            for obj in related_objects {
                let obj_users = resolve_userset(&obj, relation, ctx).await?;
                users.extend(obj_users);
            }
            Ok(users)
        },

        RelationExpr::RelatedObjectUserset { relationship, computed } => {
            // Get objects from relationship, evaluate computed relation on each
            let related_objects = get_users_with_relation(
                &*ctx.store,
                ctx.vault,
                resource,
                relationship,
                ctx.revision,
            )
            .await?;

            let mut users = HashSet::new();
            for obj in related_objects {
                let obj_users = resolve_userset(&obj, computed, ctx).await?;
                users.extend(obj_users);
            }
            Ok(users)
        },

        RelationExpr::Union(exprs) => {
            let mut users = HashSet::new();
            for expr in exprs {
                let expr_users = evaluate_relation_expr(resource, relation, expr, ctx).await?;
                users.extend(expr_users);
            }
            Ok(users)
        },

        RelationExpr::Intersection(exprs) => {
            if exprs.is_empty() {
                return Ok(HashSet::new());
            }

            // Start with first set
            let mut users = evaluate_relation_expr(resource, relation, &exprs[0], ctx).await?;

            // Intersect with remaining sets
            for expr in &exprs[1..] {
                let expr_users = evaluate_relation_expr(resource, relation, expr, ctx).await?;
                users.retain(|u| expr_users.contains(u));
            }
            Ok(users)
        },

        RelationExpr::Exclusion { base, subtract } => {
            let mut base_users = evaluate_relation_expr(resource, relation, base, ctx).await?;
            let subtract_users = evaluate_relation_expr(resource, relation, subtract, ctx).await?;

            base_users.retain(|u| !subtract_users.contains(u));
            Ok(base_users)
        },

        RelationExpr::WasmModule { module_name } => {
            // WASM modules require specific user context and cannot enumerate users
            // They can only be used in check operations, not in userset resolution
            Err(EvalError::Evaluation(format!(
                "WASM module '{}' cannot be used for user enumeration - use check operations instead",
                module_name
            )))
        },
    }
}

#[cfg(test)]
mod tests {
    use infera_store::MemoryBackend;
    use infera_types::Relationship;

    use super::*;
    use crate::ipl::{RelationDef, Schema, TypeDef};

    #[tokio::test]
    async fn test_has_direct_relationship() {
        let store = MemoryBackend::new();

        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        };

        let rev = store.write(0i64, vec![relationship]).await.unwrap();

        let has_relationship =
            has_direct_relationship(&store, 0i64, "doc:readme", "reader", "user:alice", rev)
                .await
                .unwrap();

        assert!(has_relationship);

        let no_relationship =
            has_direct_relationship(&store, 0i64, "doc:readme", "reader", "user:bob", rev)
                .await
                .unwrap();

        assert!(!no_relationship);
    }

    #[tokio::test]
    async fn test_get_users_with_relation() {
        let store = MemoryBackend::new();

        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: 0i64,
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: 0i64,
            },
        ];

        let rev = store.write(0i64, relationships).await.unwrap();

        let users =
            get_users_with_relation(&store, 0i64, "doc:readme", "reader", rev).await.unwrap();

        assert_eq!(users.len(), 2);
        assert!(users.contains(&"user:alice".to_string()));
        assert!(users.contains(&"user:bob".to_string()));
    }

    #[tokio::test]
    async fn test_cycle_detection() {
        let schema = Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![RelationDef::new("reader".to_string(), None)],
        )]);

        let store = Arc::new(MemoryBackend::new());
        let rev = store.get_revision(0i64).await.unwrap();

        let mut ctx = GraphContext::new(Arc::new(schema), store, rev, 0i64);

        // Manually create a cycle
        ctx.visit("doc:readme#reader".to_string());

        // Try to resolve the same node again
        let key = "doc:readme#reader";
        assert!(ctx.is_visited(key));
    }
}
