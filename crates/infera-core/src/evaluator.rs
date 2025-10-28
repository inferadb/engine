//! Policy evaluation engine

use std::sync::Arc;
use std::time::Instant;

use tracing::{instrument, debug};

use crate::{CheckRequest, Decision, ExpandRequest, UsersetTree, UsersetNodeType, Result, EvalError};
use crate::graph::{GraphContext, resolve_userset, has_direct_tuple};
use crate::trace::{DecisionTrace, EvaluationNode, NodeType};
use crate::ipl::Schema;
use infera_store::TupleStore;
use infera_wasm::WasmHost;
use infera_cache::{AuthCache, CheckCacheKey};

/// The main policy evaluator
pub struct Evaluator {
    store: Arc<dyn TupleStore>,
    wasm_host: Option<Arc<WasmHost>>,
    schema: Arc<Schema>,
    cache: Option<Arc<AuthCache>>,
}

impl Evaluator {
    pub fn new(store: Arc<dyn TupleStore>, schema: Arc<Schema>, wasm_host: Option<Arc<WasmHost>>) -> Self {
        Self {
            store,
            schema,
            wasm_host,
            cache: Some(Arc::new(AuthCache::default())),
        }
    }

    pub fn new_with_cache(
        store: Arc<dyn TupleStore>,
        schema: Arc<Schema>,
        wasm_host: Option<Arc<WasmHost>>,
        cache: Option<Arc<AuthCache>>,
    ) -> Self {
        Self {
            store,
            schema,
            wasm_host,
            cache,
        }
    }

    /// Check if a subject has permission on a resource
    #[instrument(skip(self))]
    pub async fn check(&self, request: CheckRequest) -> Result<Decision> {
        debug!(
            subject = %request.subject,
            resource = %request.resource,
            permission = %request.permission,
            "Evaluating permission check"
        );

        let start = Instant::now();

        // Get current revision to ensure consistent read
        let revision = self.store.get_revision().await?;

        // Check cache if enabled
        if let Some(cache) = &self.cache {
            let cache_key = CheckCacheKey::new(
                request.subject.clone(),
                request.resource.clone(),
                request.permission.clone(),
                revision,
            );
            if let Some(cached_decision) = cache.get_check(&cache_key).await {
                let decision = match cached_decision {
                    infera_cache::Decision::Allow => Decision::Allow,
                    infera_cache::Decision::Deny => Decision::Deny,
                };
                debug!(
                    decision = ?decision,
                    duration = ?start.elapsed(),
                    "Permission check complete (from cache)"
                );
                return Ok(decision);
            }
        }

        // Create graph context for traversal
        let mut ctx = GraphContext::new(
            Arc::clone(&self.schema),
            Arc::clone(&self.store),
            revision,
        );

        // Resolve the userset for the permission on the resource
        let userset = resolve_userset(&request.resource, &request.permission, &mut ctx).await?;

        // Check if the subject is in the userset
        // Also check for wildcard user (user:*) which grants access to all users
        let decision = if userset.contains(&request.subject) || userset.contains("user:*") {
            Decision::Allow
        } else {
            Decision::Deny
        };

        // Cache the result if enabled
        if let Some(cache) = &self.cache {
            let cache_key = CheckCacheKey::new(
                request.subject.clone(),
                request.resource.clone(),
                request.permission.clone(),
                revision,
            );
            let cache_decision = match decision {
                Decision::Allow => infera_cache::Decision::Allow,
                Decision::Deny => infera_cache::Decision::Deny,
            };
            cache.put_check(cache_key, cache_decision).await;
        }

        debug!(
            decision = ?decision,
            duration = ?start.elapsed(),
            "Permission check complete"
        );

        Ok(decision)
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> Option<infera_cache::CacheStats> {
        self.cache.as_ref().map(|c| c.stats())
    }

    /// Check with tracing for explainability
    #[instrument(skip(self))]
    pub async fn check_with_trace(&self, request: CheckRequest) -> Result<DecisionTrace> {
        let start = Instant::now();

        // Get current revision
        let revision = self.store.get_revision().await?;

        // Create graph context
        let mut ctx = GraphContext::new(
            Arc::clone(&self.schema),
            Arc::clone(&self.store),
            revision,
        );

        // Build evaluation tree
        let root = self.build_evaluation_node(
            &request.resource,
            &request.permission,
            &request.subject,
            &mut ctx,
        ).await?;

        // Get statistics from context
        let tuples_read = ctx.visited.len(); // Approximate
        let relations_evaluated = ctx.visited.len();

        // Determine decision from root node
        let decision = if root.result {
            Decision::Allow
        } else {
            Decision::Deny
        };

        Ok(DecisionTrace {
            decision,
            root,
            duration: start.elapsed(),
            tuples_read,
            relations_evaluated,
        })
    }

    /// Build evaluation tree for a single node
    #[async_recursion::async_recursion]
    async fn build_evaluation_node(
        &self,
        object: &str,
        relation: &str,
        user: &str,
        ctx: &mut GraphContext,
    ) -> Result<EvaluationNode> {
        // Check for direct tuple first
        let has_direct = has_direct_tuple(&*ctx.store, object, relation, user, ctx.revision).await?;

        if has_direct {
            return Ok(EvaluationNode {
                node_type: NodeType::DirectCheck {
                    object: object.to_string(),
                    relation: relation.to_string(),
                    user: user.to_string(),
                },
                result: true,
                children: vec![],
            });
        }

        // Get the relation definition
        let type_name = object.split(':').next()
            .ok_or_else(|| EvalError::Evaluation("Invalid object format".to_string()))?;

        let type_def = ctx.schema.find_type(type_name)
            .ok_or_else(|| EvalError::Evaluation(format!("Type not found: {}", type_name)))?;

        let relation_def = type_def.find_relation(relation)
            .ok_or_else(|| EvalError::Evaluation(format!("Relation not found: {}", relation)))?;

        // Clone the expression to avoid borrow issues
        let expr_opt = relation_def.expr.clone();

        // If no expression, just return the direct check result
        if expr_opt.is_none() {
            return Ok(EvaluationNode {
                node_type: NodeType::DirectCheck {
                    object: object.to_string(),
                    relation: relation.to_string(),
                    user: user.to_string(),
                },
                result: false,
                children: vec![],
            });
        }

        // Evaluate the relation expression
        self.build_expr_node(object, &expr_opt.unwrap(), user, ctx).await
    }

    /// Build evaluation node for a relation expression
    #[async_recursion::async_recursion]
    async fn build_expr_node(
        &self,
        object: &str,
        expr: &crate::ipl::RelationExpr,
        user: &str,
        ctx: &mut GraphContext,
    ) -> Result<EvaluationNode> {
        use crate::ipl::RelationExpr;

        match expr {
            RelationExpr::This => {
                let has_direct = has_direct_tuple(&*ctx.store, object, "this", user, ctx.revision).await?;
                Ok(EvaluationNode {
                    node_type: NodeType::DirectCheck {
                        object: object.to_string(),
                        relation: "this".to_string(),
                        user: user.to_string(),
                    },
                    result: has_direct,
                    children: vec![],
                })
            }

            RelationExpr::RelationRef { relation } => {
                self.build_evaluation_node(object, relation, user, ctx).await
            }

            RelationExpr::ComputedUserset { relation, tupleset } => {
                // Get objects from tupleset and check if any have user in relation
                let tupleset_objects = crate::graph::get_users_with_relation(
                    &*ctx.store,
                    object,
                    tupleset,
                    ctx.revision,
                ).await?;

                let mut children = vec![];
                let mut result = false;

                for obj in tupleset_objects {
                    let child = self.build_evaluation_node(&obj, relation, user, ctx).await?;
                    if child.result {
                        result = true;
                    }
                    children.push(child);
                }

                Ok(EvaluationNode {
                    node_type: NodeType::ComputedUserset {
                        relation: relation.clone(),
                        tupleset: tupleset.clone(),
                    },
                    result,
                    children,
                })
            }

            RelationExpr::TupleToUserset { tupleset, computed } => {
                // Get objects from tupleset and evaluate computed relation on each
                let tupleset_objects = crate::graph::get_users_with_relation(
                    &*ctx.store,
                    object,
                    tupleset,
                    ctx.revision,
                ).await?;

                let mut children = vec![];
                let mut result = false;

                for obj in tupleset_objects {
                    let child = self.build_evaluation_node(&obj, computed, user, ctx).await?;
                    if child.result {
                        result = true;
                    }
                    children.push(child);
                }

                Ok(EvaluationNode {
                    node_type: NodeType::TupleToUserset {
                        tupleset: tupleset.clone(),
                        computed: computed.clone(),
                    },
                    result,
                    children,
                })
            }

            RelationExpr::Union(exprs) => {
                let mut children = vec![];
                let mut result = false;

                for expr in exprs {
                    let child = self.build_expr_node(object, expr, user, ctx).await?;
                    if child.result {
                        result = true;
                    }
                    children.push(child);
                }

                Ok(EvaluationNode {
                    node_type: NodeType::Union,
                    result,
                    children,
                })
            }

            RelationExpr::Intersection(exprs) => {
                let mut children = vec![];
                let mut result = true;

                for expr in exprs {
                    let child = self.build_expr_node(object, expr, user, ctx).await?;
                    if !child.result {
                        result = false;
                    }
                    children.push(child);
                }

                // Empty intersection is false
                if children.is_empty() {
                    result = false;
                }

                Ok(EvaluationNode {
                    node_type: NodeType::Intersection,
                    result,
                    children,
                })
            }

            RelationExpr::Exclusion { base, subtract } => {
                let base_child = self.build_expr_node(object, base, user, ctx).await?;
                let subtract_child = self.build_expr_node(object, subtract, user, ctx).await?;

                let result = base_child.result && !subtract_child.result;

                Ok(EvaluationNode {
                    node_type: NodeType::Exclusion,
                    result,
                    children: vec![base_child, subtract_child],
                })
            }

            RelationExpr::WasmModule { module_name } => {
                // WASM not yet implemented
                Err(EvalError::Evaluation(format!(
                    "WASM module '{}' not yet implemented",
                    module_name
                )))
            }
        }
    }

    /// Expand a relation into its userset tree
    #[instrument(skip(self))]
    pub async fn expand(&self, request: ExpandRequest) -> Result<UsersetTree> {
        debug!(
            resource = %request.resource,
            relation = %request.relation,
            "Expanding userset"
        );

        // Get the relation definition
        let type_name = request.resource.split(':').next()
            .ok_or_else(|| EvalError::Evaluation("Invalid resource format".to_string()))?;

        let type_def = self.schema.find_type(type_name)
            .ok_or_else(|| EvalError::Evaluation(format!("Type not found: {}", type_name)))?;

        let relation_def = type_def.find_relation(&request.relation)
            .ok_or_else(|| EvalError::Evaluation(format!("Relation not found: {}", request.relation)))?;

        // Build userset tree from relation expression
        if relation_def.expr.is_none() {
            // Direct relation - return This node
            return Ok(UsersetTree {
                node_type: UsersetNodeType::This,
                children: vec![],
            });
        }

        self.build_userset_tree(relation_def.expr.as_ref().unwrap()).await
    }

    /// Build userset tree from relation expression
    #[async_recursion::async_recursion]
    #[allow(clippy::only_used_in_recursion)]
    async fn build_userset_tree(&self, expr: &crate::ipl::RelationExpr) -> Result<UsersetTree> {
        use crate::ipl::RelationExpr;

        match expr {
            RelationExpr::This => {
                Ok(UsersetTree {
                    node_type: UsersetNodeType::This,
                    children: vec![],
                })
            }

            RelationExpr::RelationRef { relation } => {
                Ok(UsersetTree {
                    node_type: UsersetNodeType::ComputedUserset {
                        relation: relation.clone(),
                    },
                    children: vec![],
                })
            }

            RelationExpr::ComputedUserset { relation, tupleset } => {
                Ok(UsersetTree {
                    node_type: UsersetNodeType::TupleToUserset {
                        tupleset: tupleset.clone(),
                        computed: relation.clone(),
                    },
                    children: vec![],
                })
            }

            RelationExpr::TupleToUserset { tupleset, computed } => {
                Ok(UsersetTree {
                    node_type: UsersetNodeType::TupleToUserset {
                        tupleset: tupleset.clone(),
                        computed: computed.clone(),
                    },
                    children: vec![],
                })
            }

            RelationExpr::Union(exprs) => {
                let mut children = vec![];
                for expr in exprs {
                    children.push(self.build_userset_tree(expr).await?);
                }
                Ok(UsersetTree {
                    node_type: UsersetNodeType::Union,
                    children,
                })
            }

            RelationExpr::Intersection(exprs) => {
                let mut children = vec![];
                for expr in exprs {
                    children.push(self.build_userset_tree(expr).await?);
                }
                Ok(UsersetTree {
                    node_type: UsersetNodeType::Intersection,
                    children,
                })
            }

            RelationExpr::Exclusion { base, subtract } => {
                Ok(UsersetTree {
                    node_type: UsersetNodeType::Exclusion,
                    children: vec![
                        self.build_userset_tree(base).await?,
                        self.build_userset_tree(subtract).await?,
                    ],
                })
            }

            RelationExpr::WasmModule { module_name } => {
                Err(EvalError::Evaluation(format!(
                    "WASM module '{}' not yet implemented",
                    module_name
                )))
            }
        }
    }

    /// Get the WASM host (if configured)
    pub fn wasm_host(&self) -> Option<&Arc<WasmHost>> {
        self.wasm_host.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use infera_store::{MemoryBackend, Tuple};
    use crate::ipl::{Schema, TypeDef, RelationDef, RelationExpr};

    fn create_simple_schema() -> Schema {
        Schema::new(vec![
            TypeDef::new("doc".to_string(), vec![
                RelationDef::new("reader".to_string(), None),
            ]),
        ])
    }

    fn create_complex_schema() -> Schema {
        Schema::new(vec![
            TypeDef::new("folder".to_string(), vec![
                RelationDef::new("owner".to_string(), None),
                RelationDef::new("viewer".to_string(), Some(RelationExpr::Union(vec![
                    RelationExpr::This,
                    RelationExpr::RelationRef { relation: "owner".to_string() },
                ]))),
            ]),
            TypeDef::new("doc".to_string(), vec![
                RelationDef::new("parent".to_string(), None),
                RelationDef::new("owner".to_string(), None),
                RelationDef::new("editor".to_string(), Some(RelationExpr::Union(vec![
                    RelationExpr::This,
                    RelationExpr::RelationRef { relation: "owner".to_string() },
                ]))),
                RelationDef::new("viewer".to_string(), Some(RelationExpr::Union(vec![
                    RelationExpr::This,
                    RelationExpr::RelationRef { relation: "editor".to_string() },
                    RelationExpr::TupleToUserset {
                        tupleset: "parent".to_string(),
                        computed: "viewer".to_string(),
                    },
                ]))),
            ]),
        ])
    }

    #[tokio::test]
    async fn test_direct_check_allow() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Add a direct tuple
        let tuple = Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:alice".to_string(),
        };
        store.write(vec![tuple]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None);

        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_direct_check_deny() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None);

        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[tokio::test]
    async fn test_wildcard_user_allow() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Add a wildcard user tuple that grants access to all users
        let tuple = Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:*".to_string(),
        };
        store.write(vec![tuple]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None);

        // Check that user:alice has access
        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);

        // Check that user:bob also has access
        let request = CheckRequest {
            subject: "user:bob".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);

        // Check that any user has access
        let request = CheckRequest {
            subject: "user:anyone".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_union_check() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Alice is owner, viewer is owner | this
        let tuple = Tuple {
            object: "folder:docs".to_string(),
            relation: "owner".to_string(),
            user: "user:alice".to_string(),
        };
        store.write(vec![tuple]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None);

        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "folder:docs".to_string(),
            permission: "viewer".to_string(),
            context: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_tuple_to_userset() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Set up: folder:docs has alice as viewer, doc:readme has parent->folder:docs
        let tuples = vec![
            Tuple {
                object: "folder:docs".to_string(),
                relation: "viewer".to_string(),
                user: "user:alice".to_string(),
            },
            Tuple {
                object: "doc:readme".to_string(),
                relation: "parent".to_string(),
                user: "folder:docs".to_string(),
            },
        ];
        store.write(tuples).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None);

        // Alice should be able to view doc:readme through parent->viewer
        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_nested_relations() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Alice is owner, editor = this | owner, viewer = this | editor | parent->viewer
        let tuples = vec![
            Tuple {
                object: "doc:readme".to_string(),
                relation: "owner".to_string(),
                user: "user:alice".to_string(),
            },
        ];
        store.write(tuples).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None);

        // Alice should be viewer through owner->editor->viewer chain
        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_check_with_trace() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let tuple = Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:alice".to_string(),
        };
        store.write(vec![tuple]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None);

        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        };

        let trace = evaluator.check_with_trace(request).await.unwrap();
        assert_eq!(trace.decision, Decision::Allow);
        assert!(trace.root.result);
        assert!(trace.duration.as_micros() > 0);
    }

    #[tokio::test]
    async fn test_expand_direct_relation() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None);

        let request = ExpandRequest {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
        };

        let tree = evaluator.expand(request).await.unwrap();
        assert!(matches!(tree.node_type, UsersetNodeType::This));
        assert_eq!(tree.children.len(), 0);
    }

    #[tokio::test]
    async fn test_expand_union() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        let evaluator = Evaluator::new(store, schema, None);

        let request = ExpandRequest {
            resource: "folder:docs".to_string(),
            relation: "viewer".to_string(),
        };

        let tree = evaluator.expand(request).await.unwrap();
        assert!(matches!(tree.node_type, UsersetNodeType::Union));
        assert_eq!(tree.children.len(), 2);
    }

    #[tokio::test]
    async fn test_expand_intersection() {
        let schema = Schema::new(vec![
            TypeDef::new("doc".to_string(), vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new("employee".to_string(), None),
                RelationDef::new("viewer".to_string(), Some(RelationExpr::Intersection(vec![
                    RelationExpr::RelationRef { relation: "reader".to_string() },
                    RelationExpr::RelationRef { relation: "employee".to_string() },
                ]))),
            ]),
        ]);

        let store = Arc::new(MemoryBackend::new());
        let evaluator = Evaluator::new(store, Arc::new(schema), None);

        let request = ExpandRequest {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
        };

        let tree = evaluator.expand(request).await.unwrap();
        assert!(matches!(tree.node_type, UsersetNodeType::Intersection));
        assert_eq!(tree.children.len(), 2);
    }

    #[tokio::test]
    async fn test_expand_exclusion() {
        let schema = Schema::new(vec![
            TypeDef::new("doc".to_string(), vec![
                RelationDef::new("editor".to_string(), None),
                RelationDef::new("blocked".to_string(), None),
                RelationDef::new("viewer".to_string(), Some(RelationExpr::Exclusion {
                    base: Box::new(RelationExpr::RelationRef { relation: "editor".to_string() }),
                    subtract: Box::new(RelationExpr::RelationRef { relation: "blocked".to_string() }),
                })),
            ]),
        ]);

        let store = Arc::new(MemoryBackend::new());
        let evaluator = Evaluator::new(store, Arc::new(schema), None);

        let request = ExpandRequest {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
        };

        let tree = evaluator.expand(request).await.unwrap();
        assert!(matches!(tree.node_type, UsersetNodeType::Exclusion));
        assert_eq!(tree.children.len(), 2);
    }

    #[tokio::test]
    async fn test_expand_nested() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        let evaluator = Evaluator::new(store, schema, None);

        // Expand doc.viewer which has: this | editor | parent->viewer
        let request = ExpandRequest {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
        };

        let tree = evaluator.expand(request).await.unwrap();
        assert!(matches!(tree.node_type, UsersetNodeType::Union));
        assert_eq!(tree.children.len(), 3); // this, editor, parent->viewer
    }

    #[tokio::test]
    async fn test_expand_tuple_to_userset() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        let evaluator = Evaluator::new(store, schema, None);

        // Get the viewer relation which has a tuple-to-userset component
        let request = ExpandRequest {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
        };

        let tree = evaluator.expand(request).await.unwrap();
        assert!(matches!(tree.node_type, UsersetNodeType::Union));

        // Check that one of the children is a TupleToUserset
        let has_tuple_to_userset = tree.children.iter().any(|child| {
            matches!(child.node_type, UsersetNodeType::TupleToUserset { .. })
        });
        assert!(has_tuple_to_userset);
    }

    #[tokio::test]
    async fn test_expand_invalid_resource() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None);

        let request = ExpandRequest {
            resource: "invalid".to_string(), // Missing colon separator
            relation: "reader".to_string(),
        };

        let result = evaluator.expand(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_expand_unknown_type() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None);

        let request = ExpandRequest {
            resource: "unknown:foo".to_string(),
            relation: "reader".to_string(),
        };

        let result = evaluator.expand(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_expand_unknown_relation() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None);

        let request = ExpandRequest {
            resource: "doc:readme".to_string(),
            relation: "unknown".to_string(),
        };

        let result = evaluator.expand(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_exclusion_check() {
        let schema = Schema::new(vec![
            TypeDef::new("doc".to_string(), vec![
                RelationDef::new("editor".to_string(), None),
                RelationDef::new("blocked".to_string(), None),
                RelationDef::new("viewer".to_string(), Some(RelationExpr::Exclusion {
                    base: Box::new(RelationExpr::RelationRef { relation: "editor".to_string() }),
                    subtract: Box::new(RelationExpr::RelationRef { relation: "blocked".to_string() }),
                })),
            ]),
        ]);

        let store = Arc::new(MemoryBackend::new());

        // Alice is editor but also blocked
        let tuples = vec![
            Tuple {
                object: "doc:readme".to_string(),
                relation: "editor".to_string(),
                user: "user:alice".to_string(),
            },
            Tuple {
                object: "doc:readme".to_string(),
                relation: "blocked".to_string(),
                user: "user:alice".to_string(),
            },
        ];
        store.write(tuples).await.unwrap();

        let evaluator = Evaluator::new(store, Arc::new(schema), None);

        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
        };

        // Alice should be denied (editor - blocked = denied)
        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[tokio::test]
    async fn test_intersection_check() {
        let schema = Schema::new(vec![
            TypeDef::new("doc".to_string(), vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new("employee".to_string(), None),
                RelationDef::new("viewer".to_string(), Some(RelationExpr::Intersection(vec![
                    RelationExpr::RelationRef { relation: "reader".to_string() },
                    RelationExpr::RelationRef { relation: "employee".to_string() },
                ]))),
            ]),
        ]);

        let store = Arc::new(MemoryBackend::new());

        // Alice is reader and employee
        let tuples = vec![
            Tuple {
                object: "doc:readme".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
            Tuple {
                object: "doc:readme".to_string(),
                relation: "employee".to_string(),
                user: "user:alice".to_string(),
            },
        ];
        store.write(tuples).await.unwrap();

        let evaluator = Evaluator::new(store, Arc::new(schema), None);

        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
        };

        // Alice should be allowed (reader & employee)
        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_intersection_check_deny() {
        let schema = Schema::new(vec![
            TypeDef::new("doc".to_string(), vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new("employee".to_string(), None),
                RelationDef::new("viewer".to_string(), Some(RelationExpr::Intersection(vec![
                    RelationExpr::RelationRef { relation: "reader".to_string() },
                    RelationExpr::RelationRef { relation: "employee".to_string() },
                ]))),
            ]),
        ]);

        let store = Arc::new(MemoryBackend::new());

        // Alice is only reader, not employee
        let tuples = vec![
            Tuple {
                object: "doc:readme".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
        ];
        store.write(tuples).await.unwrap();

        let evaluator = Evaluator::new(store, Arc::new(schema), None);

        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
        };

        // Alice should be denied (not an employee)
        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let tuples = vec![Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:alice".to_string(),
        }];
        store.write(tuples).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None);

        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        };

        // First check - cache miss
        let result1 = evaluator.check(request.clone()).await.unwrap();
        assert_eq!(result1, Decision::Allow);

        let stats = evaluator.cache_stats().unwrap();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);

        // Second check - cache hit
        let result2 = evaluator.check(request).await.unwrap();
        assert_eq!(result2, Decision::Allow);

        let stats = evaluator.cache_stats().unwrap();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.hit_rate, 50.0);
    }

    #[tokio::test]
    async fn test_cache_disabled() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let tuples = vec![Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:alice".to_string(),
        }];
        store.write(tuples).await.unwrap();

        // Create evaluator without cache
        let evaluator = Evaluator::new_with_cache(store, schema, None, None);

        let request = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);

        // No cache stats available
        assert!(evaluator.cache_stats().is_none());
    }

    #[tokio::test]
    async fn test_cache_different_requests() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let tuples = vec![
            Tuple {
                object: "doc:readme".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
            Tuple {
                object: "doc:guide".to_string(),
                relation: "reader".to_string(),
                user: "user:bob".to_string(),
            },
        ];
        store.write(tuples).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None);

        // Different subject
        let request1 = CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        };

        // Different resource
        let request2 = CheckRequest {
            subject: "user:bob".to_string(),
            resource: "doc:guide".to_string(),
            permission: "reader".to_string(),
            context: None,
        };

        evaluator.check(request1.clone()).await.unwrap();
        evaluator.check(request2.clone()).await.unwrap();
        evaluator.check(request1).await.unwrap(); // Cache hit
        evaluator.check(request2).await.unwrap(); // Cache hit

        let stats = evaluator.cache_stats().unwrap();
        assert_eq!(stats.misses, 2); // Two different requests
        assert_eq!(stats.hits, 2);   // Two repeated requests
        assert_eq!(stats.hit_rate, 50.0);
    }
}
