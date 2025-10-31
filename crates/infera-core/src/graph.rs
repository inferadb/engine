//! Graph traversal for policy evaluation

use std::collections::HashSet;
use std::sync::Arc;

use async_recursion::async_recursion;

use crate::ipl::{RelationExpr, Schema};
use crate::{EvalError, Result};
#[cfg(test)]
use infera_store::Relationship;
use infera_store::{Revision, RelationshipKey, RelationshipStore};

/// Graph traversal context
pub struct GraphContext {
    /// The policy schema
    pub schema: Arc<Schema>,

    /// Storage backend
    pub store: Arc<dyn RelationshipStore>,

    /// Current revision to read at
    pub revision: Revision,

    /// Visited nodes for cycle detection
    pub visited: HashSet<String>,

    /// Maximum traversal depth
    max_depth: usize,
}

impl GraphContext {
    pub fn new(schema: Arc<Schema>, store: Arc<dyn RelationshipStore>, revision: Revision) -> Self {
        Self {
            schema,
            store,
            revision,
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

/// Check if a direct relationship exists
pub async fn has_direct_relationship(
    store: &dyn RelationshipStore,
    resource: &str,
    relation: &str,
    subject: &str,
    revision: Revision,
) -> Result<bool> {
    // Check for specific user
    let key = RelationshipKey {
        resource: resource.to_string(),
        relation: relation.to_string(),
        subject: Some(subject.to_string()),
    };

    let relationships = store.read(&key, revision).await?;
    if !relationships.is_empty() {
        return Ok(true);
    }

    // Also check for wildcard user (subject:*)
    let wildcard_key = RelationshipKey {
        resource: resource.to_string(),
        relation: relation.to_string(),
        subject: Some("user:*".to_string()),
    };

    let wildcard_relationships = store.read(&wildcard_key, revision).await?;
    Ok(!wildcard_relationships.is_empty())
}

/// Get all users with a specific relation on an object
pub async fn get_users_with_relation(
    store: &dyn RelationshipStore,
    resource: &str,
    relation: &str,
    revision: Revision,
) -> Result<Vec<String>> {
    let key = RelationshipKey {
        resource: resource.to_string(),
        relation: relation.to_string(),
        subject: None,
    };

    let relationships = store.read(&key, revision).await?;
    Ok(relationships.into_iter().map(|t| t.subject).collect())
}

/// Batch prefetch users with a specific relation for multiple objects
/// This is useful for graph traversal optimizations where we know we'll need
/// the same relation for many objects (e.g., ComputedUserset, TupleToUserset)
pub async fn prefetch_users_batch(
    store: &dyn RelationshipStore,
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
                let users = get_users_with_relation(store, &obj, &rel, revision).await?;
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
            get_users_with_relation(&*ctx.store, resource, relation, ctx.revision).await?;
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
                get_users_with_relation(&*ctx.store, resource, relation, ctx.revision).await?;
            Ok(direct_users.into_iter().collect())
        }

        RelationExpr::RelationRef { relation } => {
            // Reference to another relation on the same object
            resolve_userset(resource, relation, ctx).await
        }

        RelationExpr::ComputedUserset { relation, tupleset } => {
            // Get objects from tupleset, then compute relation on each
            let tupleset_objects =
                get_users_with_relation(&*ctx.store, resource, tupleset, ctx.revision).await?;

            let mut users = HashSet::new();
            for obj in tupleset_objects {
                let obj_users = resolve_userset(&obj, relation, ctx).await?;
                users.extend(obj_users);
            }
            Ok(users)
        }

        RelationExpr::TupleToUserset { tupleset, computed } => {
            // Get objects from tupleset, evaluate computed relation on each
            let tupleset_objects =
                get_users_with_relation(&*ctx.store, resource, tupleset, ctx.revision).await?;

            let mut users = HashSet::new();
            for obj in tupleset_objects {
                let obj_users = resolve_userset(&obj, computed, ctx).await?;
                users.extend(obj_users);
            }
            Ok(users)
        }

        RelationExpr::Union(exprs) => {
            let mut users = HashSet::new();
            for expr in exprs {
                let expr_users = evaluate_relation_expr(resource, relation, expr, ctx).await?;
                users.extend(expr_users);
            }
            Ok(users)
        }

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
        }

        RelationExpr::Exclusion { base, subtract } => {
            let mut base_users = evaluate_relation_expr(resource, relation, base, ctx).await?;
            let subtract_users = evaluate_relation_expr(resource, relation, subtract, ctx).await?;

            base_users.retain(|u| !subtract_users.contains(u));
            Ok(base_users)
        }

        RelationExpr::WasmModule { module_name } => {
            // WASM modules require specific user context and cannot enumerate users
            // They can only be used in check operations, not in userset resolution
            Err(EvalError::Evaluation(format!(
                "WASM module '{}' cannot be used for user enumeration - use check operations instead",
                module_name
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipl::{RelationDef, Schema, TypeDef};
    use infera_store::{MemoryBackend, Relationship};

    #[tokio::test]
    async fn test_has_direct_relationship() {
        let store = MemoryBackend::new();

        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        };

        let rev = store.write(vec![relationship]).await.unwrap();

        let has_relationship = has_direct_relationship(&store, "doc:readme", "reader", "user:alice", rev)
            .await
            .unwrap();

        assert!(has_relationship);

        let no_relationship = has_direct_relationship(&store, "doc:readme", "reader", "user:bob", rev)
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
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
            },
        ];

        let rev = store.write(relationships).await.unwrap();

        let users = get_users_with_relation(&store, "doc:readme", "reader", rev)
            .await
            .unwrap();

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
        let rev = store.get_revision().await.unwrap();

        let mut ctx = GraphContext::new(Arc::new(schema), store, rev);

        // Manually create a cycle
        ctx.visit("doc:readme#reader".to_string());

        // Try to resolve the same node again
        let key = "doc:readme#reader";
        assert!(ctx.is_visited(key));
    }
}
