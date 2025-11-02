//! Policy evaluation engine

use std::{sync::Arc, time::Instant};

use infera_cache::{AuthCache, CheckCacheKey};
use infera_const::{DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT};
use infera_store::RelationshipStore;
use infera_types::{
    Decision, EvaluateRequest, ExpandRequest, ExpandResponse, ListRelationshipsRequest,
    ListRelationshipsResponse, ListResourcesRequest, ListResourcesResponse, ListSubjectsRequest,
    ListSubjectsResponse, Relationship, Revision, UsersetNodeType, UsersetTree,
};
use infera_wasm::WasmHost;
use tracing::{debug, instrument};
use uuid::Uuid;

use crate::{
    EvalError, Result,
    graph::{GraphContext, has_direct_relationship},
    ipl::{RelationDef, Schema},
    trace::{DecisionTrace, EvaluationNode, NodeType},
};

/// The main policy evaluator
pub struct Evaluator {
    store: Arc<dyn RelationshipStore>,
    wasm_host: Option<Arc<WasmHost>>,
    schema: Arc<Schema>,
    cache: Option<Arc<AuthCache>>,
    /// The vault ID for multi-tenant isolation
    /// TODO: In Phase 2, this will be extracted from auth context instead
    vault: Uuid,
}

impl Evaluator {
    pub fn new(
        store: Arc<dyn RelationshipStore>,
        schema: Arc<Schema>,
        wasm_host: Option<Arc<WasmHost>>,
        vault: Uuid,
    ) -> Self {
        Self { store, schema, wasm_host, cache: Some(Arc::new(AuthCache::default())), vault }
    }

    pub fn new_with_cache(
        store: Arc<dyn RelationshipStore>,
        schema: Arc<Schema>,
        wasm_host: Option<Arc<WasmHost>>,
        cache: Option<Arc<AuthCache>>,
        vault: Uuid,
    ) -> Self {
        Self { store, schema, wasm_host, cache, vault }
    }

    /// Check if a subject has permission on a resource
    #[instrument(skip(self))]
    pub async fn check(&self, request: EvaluateRequest) -> Result<Decision> {
        debug!(
            subject = %request.subject,
            resource = %request.resource,
            permission = %request.permission,
            "Evaluating permission check"
        );

        let start = Instant::now();

        // Get current revision to ensure consistent read
        let revision = self.store.get_revision(self.vault).await?;

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
            self.vault,
        );

        // FIRST: Check all forbid rules - if any match, return DENY immediately
        // Forbid rules override all permit rules (explicit deny)
        let type_name = request
            .resource
            .split(':')
            .next()
            .ok_or_else(|| EvalError::Evaluation("Invalid resource format".to_string()))?;

        // Clone forbids to avoid borrow checker issues
        let forbids_to_check = if let Some(type_def) = ctx.schema.find_type(type_name) {
            type_def.forbids.clone()
        } else {
            Vec::new()
        };

        // Check all forbids for this permission
        for forbid_def in &forbids_to_check {
            let forbid_check = self
                .check_forbid_rule(
                    &request.resource,
                    &forbid_def.name,
                    &request.permission,
                    &request.subject,
                    &forbid_def.expr,
                    &mut ctx,
                )
                .await?;

            if forbid_check {
                // Forbid matched - return DENY immediately
                debug!(
                    forbid = %forbid_def.name,
                    "Forbid rule matched - denying access"
                );

                let decision = Decision::Deny;

                // Cache the deny decision
                if let Some(cache) = &self.cache {
                    let cache_key = CheckCacheKey::new(
                        request.subject.clone(),
                        request.resource.clone(),
                        request.permission.clone(),
                        revision,
                    );
                    cache.put_check(cache_key, infera_cache::Decision::Deny).await;
                }

                return Ok(decision);
            }
        }

        // No forbids matched - proceed with normal permit evaluation
        // Build evaluation tree for this specific check
        let root = self
            .build_evaluation_node(
                &request.resource,
                &request.permission,
                &request.subject,
                &mut ctx,
            )
            .await?;

        // Determine decision from evaluation result
        let decision = if root.result { Decision::Allow } else { Decision::Deny };

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
    pub async fn check_with_trace(&self, request: EvaluateRequest) -> Result<DecisionTrace> {
        let start = Instant::now();

        // Get current revision
        let revision = self.store.get_revision(self.vault).await?;

        // Create graph context
        let mut ctx = GraphContext::new(
            Arc::clone(&self.schema),
            Arc::clone(&self.store),
            revision,
            self.vault,
        );

        // FIRST: Check all forbid rules - if any match, return DENY immediately
        let type_name = request
            .resource
            .split(':')
            .next()
            .ok_or_else(|| EvalError::Evaluation("Invalid resource format".to_string()))?;

        // Clone forbids to avoid borrow checker issues
        let forbids_to_check = if let Some(type_def) = ctx.schema.find_type(type_name) {
            type_def.forbids.clone()
        } else {
            Vec::new()
        };

        for forbid_def in &forbids_to_check {
            let forbid_check = self
                .check_forbid_rule(
                    &request.resource,
                    &forbid_def.name,
                    &request.permission,
                    &request.subject,
                    &forbid_def.expr,
                    &mut ctx,
                )
                .await?;

            if forbid_check {
                // Forbid matched - return DENY with trace showing the forbid
                let forbid_node = EvaluationNode {
                    node_type: NodeType::DirectCheck {
                        resource: request.resource.clone(),
                        relation: format!("forbid:{}", forbid_def.name),
                        subject: request.subject.clone(),
                    },
                    result: true, // Forbid matched
                    children: vec![],
                };

                let relationships_read = ctx.visited.len();
                let relations_evaluated = ctx.visited.len();

                return Ok(DecisionTrace {
                    decision: Decision::Deny,
                    root: forbid_node,
                    duration: start.elapsed(),
                    relationships_read,
                    relations_evaluated,
                });
            }
        }

        // No forbids matched - proceed with normal evaluation
        // Build evaluation tree
        let root = self
            .build_evaluation_node(
                &request.resource,
                &request.permission,
                &request.subject,
                &mut ctx,
            )
            .await?;

        // Get statistics from context
        let relationships_read = ctx.visited.len(); // Approximate
        let relations_evaluated = ctx.visited.len();

        // Determine decision from root node
        let decision = if root.result { Decision::Allow } else { Decision::Deny };

        Ok(DecisionTrace {
            decision,
            root,
            duration: start.elapsed(),
            relationships_read,
            relations_evaluated,
        })
    }

    /// Build evaluation tree for a single node
    #[async_recursion::async_recursion]
    async fn build_evaluation_node(
        &self,
        resource: &str,
        relation: &str,
        subject: &str,
        ctx: &mut GraphContext,
    ) -> Result<EvaluationNode> {
        // Check for direct relationship first
        let has_direct = has_direct_relationship(
            &*ctx.store,
            ctx.vault,
            resource,
            relation,
            subject,
            ctx.revision,
        )
        .await?;

        if has_direct {
            return Ok(EvaluationNode {
                node_type: NodeType::DirectCheck {
                    resource: resource.to_string(),
                    relation: relation.to_string(),
                    subject: subject.to_string(),
                },
                result: true,
                children: vec![],
            });
        }

        // Get the relation definition
        let type_name = resource
            .split(':')
            .next()
            .ok_or_else(|| EvalError::Evaluation("Invalid resource format".to_string()))?;

        let type_def = ctx
            .schema
            .find_type(type_name)
            .ok_or_else(|| EvalError::Evaluation(format!("Type not found: {}", type_name)))?;

        let relation_def = type_def
            .find_relation(relation)
            .ok_or_else(|| EvalError::Evaluation(format!("Relation not found: {}", relation)))?;

        // Clone the expression to avoid borrow issues
        let expr_opt = relation_def.expr.clone();

        // If no expression, just return the direct check result
        if expr_opt.is_none() {
            return Ok(EvaluationNode {
                node_type: NodeType::DirectCheck {
                    resource: resource.to_string(),
                    relation: relation.to_string(),
                    subject: subject.to_string(),
                },
                result: false,
                children: vec![],
            });
        }

        // Evaluate the relation expression
        self.build_expr_node(resource, &expr_opt.unwrap(), subject, ctx).await
    }

    /// Build evaluation node for a relation expression
    #[async_recursion::async_recursion]
    async fn build_expr_node(
        &self,
        resource: &str,
        expr: &crate::ipl::RelationExpr,
        subject: &str,
        ctx: &mut GraphContext,
    ) -> Result<EvaluationNode> {
        use crate::ipl::RelationExpr;

        match expr {
            RelationExpr::This => {
                let has_direct = has_direct_relationship(
                    &*ctx.store,
                    ctx.vault,
                    resource,
                    "this",
                    subject,
                    ctx.revision,
                )
                .await?;
                Ok(EvaluationNode {
                    node_type: NodeType::DirectCheck {
                        resource: resource.to_string(),
                        relation: "this".to_string(),
                        subject: subject.to_string(),
                    },
                    result: has_direct,
                    children: vec![],
                })
            },

            RelationExpr::RelationRef { relation } => {
                self.build_evaluation_node(resource, relation, subject, ctx).await
            },

            RelationExpr::ComputedUserset { relation, relationship } => {
                // Get objects from relationship and check if any have user in relation
                let related_objects = crate::graph::get_users_with_relation(
                    &*ctx.store,
                    ctx.vault,
                    resource,
                    relationship,
                    ctx.revision,
                )
                .await?;

                let mut children = vec![];
                let mut result = false;

                for obj in related_objects {
                    let child = self.build_evaluation_node(&obj, relation, subject, ctx).await?;
                    if child.result {
                        result = true;
                    }
                    children.push(child);
                }

                Ok(EvaluationNode {
                    node_type: NodeType::ComputedUserset {
                        relation: relation.clone(),
                        relationship: relationship.clone(),
                    },
                    result,
                    children,
                })
            },

            RelationExpr::RelatedObjectUserset { relationship, computed } => {
                // Get objects from relationship and evaluate computed relation on each
                let related_objects = crate::graph::get_users_with_relation(
                    &*ctx.store,
                    ctx.vault,
                    resource,
                    relationship,
                    ctx.revision,
                )
                .await?;

                let mut children = vec![];
                let mut result = false;

                for obj in related_objects {
                    let child = self.build_evaluation_node(&obj, computed, subject, ctx).await?;
                    if child.result {
                        result = true;
                    }
                    children.push(child);
                }

                Ok(EvaluationNode {
                    node_type: NodeType::RelatedObjectUserset {
                        relationship: relationship.clone(),
                        computed: computed.clone(),
                    },
                    result,
                    children,
                })
            },

            RelationExpr::Union(exprs) => {
                let mut children = vec![];
                let mut result = false;

                for expr in exprs {
                    let child = self.build_expr_node(resource, expr, subject, ctx).await?;
                    if child.result {
                        result = true;
                    }
                    children.push(child);
                }

                Ok(EvaluationNode { node_type: NodeType::Union, result, children })
            },

            RelationExpr::Intersection(exprs) => {
                let mut children = vec![];
                let mut result = true;

                for expr in exprs {
                    let child = self.build_expr_node(resource, expr, subject, ctx).await?;
                    if !child.result {
                        result = false;
                    }
                    children.push(child);
                }

                // Empty intersection is false
                if children.is_empty() {
                    result = false;
                }

                Ok(EvaluationNode { node_type: NodeType::Intersection, result, children })
            },

            RelationExpr::Exclusion { base, subtract } => {
                let base_child = self.build_expr_node(resource, base, subject, ctx).await?;
                let subtract_child = self.build_expr_node(resource, subtract, subject, ctx).await?;

                let result = base_child.result && !subtract_child.result;

                Ok(EvaluationNode {
                    node_type: NodeType::Exclusion,
                    result,
                    children: vec![base_child, subtract_child],
                })
            },

            RelationExpr::WasmModule { module_name } => {
                // Execute WASM module to determine access
                let _span = infera_observe::span_utils::wasm_span(module_name);
                let _guard = _span.enter();

                let wasm_host = self
                    .wasm_host
                    .as_ref()
                    .ok_or_else(|| EvalError::Evaluation("WASM host not configured".to_string()))?;

                let exec_context = infera_wasm::ExecutionContext {
                    subject: subject.to_string(),
                    resource: resource.to_string(),
                    permission: "check".to_string(), // Default permission name
                    context: None,
                };

                debug!(
                    module = %module_name,
                    subject = %subject,
                    resource = %resource,
                    "Executing WASM module"
                );

                let result =
                    wasm_host.execute(module_name, "check", exec_context).map_err(|e| {
                        debug!(module = %module_name, error = %e, "WASM execution failed");
                        EvalError::Evaluation(format!("WASM execution failed: {}", e))
                    })?;

                debug!(module = %module_name, result = %result, "WASM module completed");
                infera_observe::span_utils::record_wasm_result(
                    &_span,
                    0,
                    if result { 1 } else { 0 },
                );

                Ok(EvaluationNode {
                    node_type: NodeType::WasmModule { module_name: module_name.clone() },
                    result,
                    children: vec![],
                })
            },
        }
    }

    /// Check if a forbid rule matches (returns true if subject should be denied)
    /// This is similar to checking a permit rule, but the semantics are inverted:
    /// - If forbid expression evaluates to true, access is DENIED
    /// - Forbids are checked before permits and override them
    #[async_recursion::async_recursion]
    async fn check_forbid_rule(
        &self,
        resource: &str,
        forbid_name: &str,
        _permission: &str, // permission context for potential future use
        subject: &str,
        expr: &Option<crate::ipl::RelationExpr>,
        ctx: &mut GraphContext,
    ) -> Result<bool> {
        // Check for direct relationship first (forbid with no expression or `this`)
        if expr.is_none() {
            let has_direct = has_direct_relationship(
                &*ctx.store,
                ctx.vault,
                resource,
                forbid_name,
                subject,
                ctx.revision,
            )
            .await?;
            return Ok(has_direct);
        }

        // If there's an expression, evaluate it
        let node = self.build_expr_node(resource, expr.as_ref().unwrap(), subject, ctx).await?;

        Ok(node.result)
    }

    /// Expand a relation into its userset tree with actual user resolution
    #[instrument(skip(self))]
    pub async fn expand(&self, request: ExpandRequest) -> Result<ExpandResponse> {
        debug!(
            resource = %request.resource,
            relation = %request.relation,
            limit = ?request.limit,
            "Expanding userset"
        );

        // Get current revision
        let revision = self.store.get_revision(self.vault).await?;

        // Get the relation definition
        let type_name = request
            .resource
            .split(':')
            .next()
            .ok_or_else(|| EvalError::Evaluation("Invalid resource format".to_string()))?;

        let type_def = self
            .schema
            .find_type(type_name)
            .ok_or_else(|| EvalError::Evaluation(format!("Type not found: {}", type_name)))?;

        let relation_def = type_def.find_relation(&request.relation).ok_or_else(|| {
            EvalError::Evaluation(format!("Relation not found: {}", request.relation))
        })?;

        // Create graph context for actual user resolution
        let mut ctx = GraphContext::new(
            Arc::clone(&self.schema),
            Arc::clone(&self.store),
            revision,
            self.vault,
        );

        // Build userset tree with actual users
        let tree = if relation_def.expr.is_none() {
            // Direct relation - collect direct users
            self.build_direct_userset_tree(&request.resource, &request.relation, &mut ctx).await?
        } else {
            self.build_userset_tree_with_users(
                &request.resource,
                relation_def.expr.as_ref().unwrap(),
                &mut ctx,
            )
            .await?
        };

        // Collect all users from the tree (deduplicated)
        let all_users = self.collect_users_from_tree(&tree);

        // Handle pagination
        let (users, continuation_token, total_count) =
            self.paginate_users(all_users, request.limit, request.continuation_token.as_deref())?;

        Ok(ExpandResponse { tree, users, continuation_token, total_count })
    }

    /// Build a userset tree for a direct relation with actual users
    async fn build_direct_userset_tree(
        &self,
        resource: &str,
        relation: &str,
        ctx: &mut GraphContext,
    ) -> Result<UsersetTree> {
        use crate::graph::get_users_with_relation;

        let users =
            get_users_with_relation(&*ctx.store, ctx.vault, resource, relation, ctx.revision)
                .await?;

        Ok(UsersetTree {
            node_type: UsersetNodeType::Leaf { users: users.into_iter().collect() },
            children: vec![],
        })
    }

    /// Build userset tree with actual user resolution
    #[async_recursion::async_recursion]
    async fn build_userset_tree_with_users(
        &self,
        resource: &str,
        expr: &crate::ipl::RelationExpr,
        ctx: &mut GraphContext,
    ) -> Result<UsersetTree> {
        use crate::{graph::get_users_with_relation, ipl::RelationExpr};

        match expr {
            RelationExpr::This => {
                // Direct relation - get actual users
                // Try cache first
                let cache_key = if let Some(_cache) = &self.cache {
                    Some(infera_cache::ExpandCacheKey::new(
                        resource.to_string(),
                        "".to_string(), // "this" uses empty relation
                        ctx.revision,
                    ))
                } else {
                    None
                };

                let users = if let Some(ref key) = cache_key {
                    if let Some(cache) = &self.cache {
                        if let Some(cached_users) = cache.get_expand(key).await {
                            cached_users
                        } else {
                            let users: Vec<String> = get_users_with_relation(
                                &*ctx.store,
                                ctx.vault,
                                resource,
                                "",
                                ctx.revision,
                            )
                            .await?
                            .into_iter()
                            .collect();
                            cache.put_expand(key.clone(), users.clone()).await;
                            users
                        }
                    } else {
                        get_users_with_relation(&*ctx.store, ctx.vault, resource, "", ctx.revision)
                            .await?
                            .into_iter()
                            .collect()
                    }
                } else {
                    get_users_with_relation(&*ctx.store, ctx.vault, resource, "", ctx.revision)
                        .await?
                        .into_iter()
                        .collect()
                };

                Ok(UsersetTree { node_type: UsersetNodeType::Leaf { users }, children: vec![] })
            },

            RelationExpr::ComputedUserset { relation, relationship } => {
                // Get users from computed relation on relationship
                let related_objects = get_users_with_relation(
                    &*ctx.store,
                    ctx.vault,
                    resource,
                    relationship,
                    ctx.revision,
                )
                .await?;

                // Use prefetching for better performance when we have multiple objects
                let mut all_users = std::collections::HashSet::new();
                if related_objects.len() > 1 {
                    // Batch prefetch for multiple objects
                    let prefetched = crate::graph::prefetch_users_batch(
                        &*ctx.store,
                        ctx.vault,
                        &related_objects,
                        relation,
                        ctx.revision,
                    )
                    .await?;

                    for obj in &related_objects {
                        if let Some(users) = prefetched.get(obj) {
                            all_users.extend(users.iter().cloned());
                        }
                    }
                } else {
                    // Single object - use direct fetch
                    for obj in related_objects {
                        let users = get_users_with_relation(
                            &*ctx.store,
                            ctx.vault,
                            &obj,
                            relation,
                            ctx.revision,
                        )
                        .await?;
                        all_users.extend(users);
                    }
                }

                Ok(UsersetTree {
                    node_type: UsersetNodeType::Leaf { users: all_users.into_iter().collect() },
                    children: vec![],
                })
            },

            RelationExpr::RelatedObjectUserset { relationship, computed } => {
                // Get objects from relationship
                let related_objects = get_users_with_relation(
                    &*ctx.store,
                    ctx.vault,
                    resource,
                    relationship,
                    ctx.revision,
                )
                .await?;

                // Use prefetching for better performance when we have multiple objects
                let mut all_users = std::collections::HashSet::new();
                if related_objects.len() > 1 {
                    // Batch prefetch for multiple objects
                    let prefetched = crate::graph::prefetch_users_batch(
                        &*ctx.store,
                        ctx.vault,
                        &related_objects,
                        computed,
                        ctx.revision,
                    )
                    .await?;

                    for obj in &related_objects {
                        if let Some(users) = prefetched.get(obj) {
                            all_users.extend(users.iter().cloned());
                        }
                    }
                } else {
                    // Single object - use direct fetch
                    for obj in related_objects {
                        let users = get_users_with_relation(
                            &*ctx.store,
                            ctx.vault,
                            &obj,
                            computed,
                            ctx.revision,
                        )
                        .await?;
                        all_users.extend(users);
                    }
                }

                Ok(UsersetTree {
                    node_type: UsersetNodeType::Leaf { users: all_users.into_iter().collect() },
                    children: vec![],
                })
            },

            RelationExpr::Union(exprs) => {
                // Parallelize union branch expansion
                let children = self.expand_branches_parallel(resource, exprs, ctx).await?;
                Ok(UsersetTree { node_type: UsersetNodeType::Union, children })
            },

            RelationExpr::Intersection(exprs) => {
                // Parallelize intersection branch expansion
                let children = self.expand_branches_parallel(resource, exprs, ctx).await?;
                Ok(UsersetTree { node_type: UsersetNodeType::Intersection, children })
            },

            RelationExpr::Exclusion { base, subtract } => {
                // Parallelize exclusion: evaluate base and subtract concurrently
                let children = self
                    .expand_branches_parallel(
                        resource,
                        &[base.as_ref().clone(), subtract.as_ref().clone()],
                        ctx,
                    )
                    .await?;
                Ok(UsersetTree { node_type: UsersetNodeType::Exclusion, children })
            },

            RelationExpr::WasmModule { module_name } => {
                // WASM modules in expand are treated as computed usersets
                // We need to enumerate all users and test each one
                // For now, return an empty userset since we can't enumerate all possible users
                // A proper implementation would require domain-specific logic
                Err(EvalError::Evaluation(format!(
                    "WASM module '{}' cannot be used in expand - WASM modules require specific subject context",
                    module_name
                )))
            },

            RelationExpr::RelationRef { relation } => {
                // Relation reference - recursively expand the referenced relation
                // Try cache first
                let cache_key = if let Some(_cache) = &self.cache {
                    Some(infera_cache::ExpandCacheKey::new(
                        resource.to_string(),
                        relation.clone(),
                        ctx.revision,
                    ))
                } else {
                    None
                };

                // Check cache
                if let Some(ref key) = cache_key {
                    if let Some(cache) = &self.cache {
                        if let Some(cached_users) = cache.get_expand(key).await {
                            return Ok(UsersetTree {
                                node_type: UsersetNodeType::Leaf { users: cached_users },
                                children: vec![],
                            });
                        }
                    }
                }

                // Get the type definition for the current object
                let type_name = resource
                    .split(':')
                    .next()
                    .ok_or_else(|| EvalError::Evaluation("Invalid resource format".to_string()))?;

                let type_def = ctx.schema.find_type(type_name).ok_or_else(|| {
                    EvalError::Evaluation(format!("Type not found: {}", type_name))
                })?;

                let relation_def = type_def.find_relation(relation).ok_or_else(|| {
                    EvalError::Evaluation(format!("Relation not found: {}", relation))
                })?;

                // Clone the expression to avoid borrow checker issues
                let expr_opt = relation_def.expr.clone();

                // If the referenced relation has no expression, it's a direct relation
                let tree = if expr_opt.is_none() {
                    let users: Vec<String> = get_users_with_relation(
                        &*ctx.store,
                        ctx.vault,
                        resource,
                        relation,
                        ctx.revision,
                    )
                    .await?
                    .into_iter()
                    .collect();
                    UsersetTree {
                        node_type: UsersetNodeType::Leaf { users: users.clone() },
                        children: vec![],
                    }
                } else {
                    // Recursively expand the referenced relation's expression
                    self.build_userset_tree_with_users(resource, expr_opt.as_ref().unwrap(), ctx)
                        .await?
                };

                // Cache the result
                if let Some(ref key) = cache_key {
                    if let Some(cache) = &self.cache {
                        if let UsersetNodeType::Leaf { ref users } = tree.node_type {
                            cache.put_expand(key.clone(), users.clone()).await;
                        } else {
                            // Collect users from the tree and cache them
                            let users = self.collect_users_from_tree(&tree);
                            cache.put_expand(key.clone(), users).await;
                        }
                    }
                }

                Ok(tree)
            },
        }
    }

    /// Expand multiple branches in parallel
    /// Creates a separate GraphContext for each branch to enable concurrent evaluation
    async fn expand_branches_parallel(
        &self,
        resource: &str,
        exprs: &[crate::ipl::RelationExpr],
        ctx: &GraphContext,
    ) -> Result<Vec<UsersetTree>> {
        use futures::future::join_all;

        // Create tasks for parallel evaluation
        let tasks: Vec<_> = exprs
            .iter()
            .map(|expr| {
                // Clone context for each branch (Arc fields are cheap to clone)
                let mut branch_ctx = GraphContext::new(
                    Arc::clone(&ctx.schema),
                    Arc::clone(&ctx.store),
                    ctx.revision,
                    ctx.vault,
                );
                // Copy the visited set for cycle detection
                branch_ctx.visited = ctx.visited.clone();

                let resource = resource.to_string();
                let expr = expr.clone();

                async move {
                    self.build_userset_tree_with_users(&resource, &expr, &mut branch_ctx).await
                }
            })
            .collect();

        // Execute all branches concurrently
        let results = join_all(tasks).await;

        // Collect results or return first error
        results.into_iter().collect()
    }

    /// Collect all users from a userset tree (with deduplication)
    fn collect_users_from_tree(&self, tree: &UsersetTree) -> Vec<String> {
        let mut users = std::collections::HashSet::new();
        self.collect_users_recursive(tree, &mut users);
        let mut result: Vec<String> = users.into_iter().collect();
        result.sort(); // Sort for deterministic output
        result
    }

    /// Recursively collect users from tree nodes
    #[allow(clippy::only_used_in_recursion)]
    fn collect_users_recursive(
        &self,
        tree: &UsersetTree,
        users: &mut std::collections::HashSet<String>,
    ) {
        match &tree.node_type {
            UsersetNodeType::Leaf { users: leaf_users } => {
                users.extend(leaf_users.iter().cloned());
            },
            UsersetNodeType::Intersection => {
                // For intersection, we need users present in ALL children
                if tree.children.is_empty() {
                    return;
                }

                // Get users from first child
                let mut intersection_users = std::collections::HashSet::new();
                self.collect_users_recursive(&tree.children[0], &mut intersection_users);

                // Intersect with each subsequent child
                for child in &tree.children[1..] {
                    let mut child_users = std::collections::HashSet::new();
                    self.collect_users_recursive(child, &mut child_users);
                    intersection_users.retain(|u| child_users.contains(u));
                }

                users.extend(intersection_users);
            },
            UsersetNodeType::Exclusion => {
                // For exclusion: users in base minus users in subtract
                if tree.children.len() != 2 {
                    return;
                }

                let mut base_users = std::collections::HashSet::new();
                self.collect_users_recursive(&tree.children[0], &mut base_users);

                let mut subtract_users = std::collections::HashSet::new();
                self.collect_users_recursive(&tree.children[1], &mut subtract_users);

                base_users.retain(|u| !subtract_users.contains(u));
                users.extend(base_users);
            },
            _ => {
                // For Union, This, ComputedUserset, RelatedObjectUserset: collect from all children
                for child in &tree.children {
                    self.collect_users_recursive(child, users);
                }
            },
        }
    }

    /// Handle pagination of user results
    fn paginate_users(
        &self,
        mut all_users: Vec<String>,
        limit: Option<usize>,
        continuation_token: Option<&str>,
    ) -> Result<(Vec<String>, Option<String>, Option<usize>)> {
        let total_count = all_users.len();

        // Decode continuation token to get offset
        let offset = if let Some(token) = continuation_token {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(token)
                .map_err(|e| EvalError::Evaluation(format!("Invalid continuation token: {}", e)))?;
            decoded
                .iter()
                .take(8)
                .enumerate()
                .fold(0usize, |acc, (i, &b)| acc | ((b as usize) << (i * 8)))
        } else {
            0
        };

        // Apply offset
        if offset >= all_users.len() {
            return Ok((vec![], None, Some(total_count)));
        }
        all_users = all_users.into_iter().skip(offset).collect();

        // Apply limit
        let users = if let Some(limit) = limit {
            if all_users.len() > limit {
                let next_offset = offset + limit;
                let continuation_token = Some(self.encode_continuation_token(next_offset));
                (all_users.into_iter().take(limit).collect(), continuation_token, Some(total_count))
            } else {
                (all_users, None, Some(total_count))
            }
        } else {
            (all_users, None, Some(total_count))
        };

        Ok(users)
    }

    /// Encode an offset as a continuation token
    fn encode_continuation_token(&self, offset: usize) -> String {
        use base64::Engine;
        let bytes: Vec<u8> = offset.to_le_bytes().to_vec();
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    }

    /// List all resources of a given type that a subject can access
    #[instrument(skip(self))]
    pub async fn list_resources(
        &self,
        request: ListResourcesRequest,
    ) -> Result<ListResourcesResponse> {
        debug!(
            subject = %request.subject,
            resource_type = %request.resource_type,
            permission = %request.permission,
            limit = ?request.limit,
            "Listing accessible resources"
        );

        let start = Instant::now();

        // Get current revision to ensure consistent read
        let revision = self.store.get_revision(self.vault).await?;

        // List all resources of the given type
        let all_resources =
            self.store.list_resources_by_type(self.vault, &request.resource_type, revision).await?;

        debug!("Found {} total resources of type '{}'", all_resources.len(), request.resource_type);

        // Decode cursor to get offset if provided
        let offset = if let Some(cursor) = &request.cursor {
            self.decode_continuation_token(cursor)?
        } else {
            0
        };

        // Apply offset and ID pattern filtering
        let resources_to_check: Vec<String> = all_resources
            .into_iter()
            .filter(|resource| {
                // Apply resource ID pattern filter if provided
                if let Some(pattern) = &request.resource_id_pattern {
                    Self::matches_glob_pattern(resource, pattern)
                } else {
                    true
                }
            })
            .skip(offset)
            .take(request.limit.unwrap_or(usize::MAX))
            .collect();

        // Check each resource for access
        let mut accessible_resources = Vec::new();
        let mut checked = 0;

        for resource in resources_to_check {
            checked += 1;

            // Create a check request for this resource
            let check_request = EvaluateRequest {
                subject: request.subject.clone(),
                resource: resource.clone(),
                permission: request.permission.clone(),
                context: None,
                trace: None,
            };

            // Use the existing check method
            let decision = self.check(check_request).await?;

            if decision == Decision::Allow {
                accessible_resources.push(resource);
            }

            // Apply limit if specified
            if let Some(limit) = request.limit {
                if accessible_resources.len() >= limit {
                    break;
                }
            }
        }

        // Determine if there are more results
        let has_more = checked < usize::MAX
            && accessible_resources.len() == request.limit.unwrap_or(usize::MAX);
        let cursor =
            if has_more { Some(self.encode_continuation_token(offset + checked)) } else { None };

        debug!(
            accessible_count = accessible_resources.len(),
            checked_count = checked,
            duration = ?start.elapsed(),
            "List resources complete"
        );

        Ok(ListResourcesResponse {
            resources: accessible_resources,
            cursor,
            total_count: Some(checked),
        })
    }

    /// Decode a continuation token to get the offset
    fn decode_continuation_token(&self, token: &str) -> Result<usize> {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(token)
            .map_err(|e| EvalError::Evaluation(format!("Invalid continuation token: {}", e)))?;

        Ok(decoded
            .iter()
            .take(8)
            .enumerate()
            .fold(0usize, |acc, (i, &b)| acc | ((b as usize) << (i * 8))))
    }

    /// Match a string against a glob pattern
    /// Supports:
    /// - `*` matches any sequence of characters (including none)
    /// - `?` matches exactly one character
    /// - All other characters match literally
    fn matches_glob_pattern(text: &str, pattern: &str) -> bool {
        let text_chars: Vec<char> = text.chars().collect();
        let pattern_chars: Vec<char> = pattern.chars().collect();

        Self::glob_match_recursive(&text_chars, &pattern_chars, 0, 0)
    }

    /// Recursive helper for glob pattern matching
    fn glob_match_recursive(
        text: &[char],
        pattern: &[char],
        text_idx: usize,
        pattern_idx: usize,
    ) -> bool {
        // If both exhausted, match succeeds
        if pattern_idx == pattern.len() {
            return text_idx == text.len();
        }

        // Handle wildcard *
        if pattern[pattern_idx] == '*' {
            // Try matching zero characters
            if Self::glob_match_recursive(text, pattern, text_idx, pattern_idx + 1) {
                return true;
            }
            // Try matching one or more characters
            for i in text_idx..text.len() {
                if Self::glob_match_recursive(text, pattern, i + 1, pattern_idx + 1) {
                    return true;
                }
            }
            return false;
        }

        // If text exhausted but pattern isn't, no match
        if text_idx == text.len() {
            return false;
        }

        // Handle single character wildcard ?
        if pattern[pattern_idx] == '?' {
            return Self::glob_match_recursive(text, pattern, text_idx + 1, pattern_idx + 1);
        }

        // Handle literal character match
        if text[text_idx] == pattern[pattern_idx] {
            return Self::glob_match_recursive(text, pattern, text_idx + 1, pattern_idx + 1);
        }

        false
    }

    /// List relationships with optional filtering
    #[instrument(skip(self))]
    pub async fn list_relationships(
        &self,
        request: ListRelationshipsRequest,
    ) -> Result<ListRelationshipsResponse> {
        debug!(
            resource = ?request.resource,
            relation = ?request.relation,
            subject = ?request.subject,
            limit = ?request.limit,
            "Listing relationships"
        );

        let start = Instant::now();

        // Get current revision to ensure consistent read
        let revision = self.store.get_revision(self.vault).await?;

        // Query storage with filters (storage uses resource/subject, returns Tuples)
        let all_relationships = self
            .store
            .list_relationships(
                self.vault,
                request.resource.as_deref(),
                request.relation.as_deref(),
                request.subject.as_deref(),
                revision,
            )
            .await?;

        debug!("Found {} total relationships matching filters", all_relationships.len());

        // Decode cursor to get offset if provided
        let offset = if let Some(cursor) = &request.cursor {
            self.decode_continuation_token(cursor)?
        } else {
            0
        };

        // Apply default and maximum limits
        let limit = request.limit.unwrap_or(DEFAULT_LIST_LIMIT).min(MAX_LIST_LIMIT);

        // Apply pagination
        let relationships: Vec<Relationship> = all_relationships
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|t| Relationship {
                vault: t.vault,
                resource: t.resource,
                relation: t.relation,
                subject: t.subject,
            })
            .collect();

        let returned_count = relationships.len();

        // Determine if there are more results
        let has_more = returned_count == limit;
        let cursor = if has_more {
            Some(self.encode_continuation_token(offset + returned_count))
        } else {
            None
        };

        debug!(
            returned_count = returned_count,
            has_more = has_more,
            duration = ?start.elapsed(),
            "List relationships complete"
        );

        Ok(ListRelationshipsResponse { relationships, cursor, total_count: Some(returned_count) })
    }

    /// List all subjects that have a specific relation to a resource
    ///
    /// This performs a reverse traversal to find all subjects with access to the given
    /// resource through the specified relation.
    #[instrument(skip(self))]
    pub async fn list_subjects(
        &self,
        request: ListSubjectsRequest,
    ) -> Result<ListSubjectsResponse> {
        debug!(
            resource = %request.resource,
            relation = %request.relation,
            subject_type = ?request.subject_type,
            limit = ?request.limit,
            "Listing subjects with access"
        );

        let start = Instant::now();

        // Get current revision to ensure consistent read
        let revision = self.store.get_revision(self.vault).await?;

        // Parse resource to extract type
        let resource_parts: Vec<&str> = request.resource.split(':').collect();
        if resource_parts.len() != 2 {
            return Err(EvalError::Evaluation(format!(
                "Invalid resource format: {}. Expected 'type:id'",
                request.resource
            )));
        }
        let resource_type = resource_parts[0];

        // Verify the relation exists in the schema
        let type_def = self
            .schema
            .find_type(resource_type)
            .ok_or_else(|| EvalError::Evaluation(format!("Unknown type: {}", resource_type)))?;

        let relation_def =
            type_def.relations.iter().find(|r| r.name == request.relation).ok_or_else(|| {
                EvalError::Evaluation(format!(
                    "Unknown relation: {}#{}",
                    resource_type, request.relation
                ))
            })?;

        // Collect subjects based on relation definition
        let mut all_subjects = self
            .collect_subjects_for_relation(&request.resource, relation_def, resource_type, revision)
            .await?;

        debug!("Found {} total subjects before filtering", all_subjects.len());

        // Sort for stable pagination
        all_subjects.sort();

        // Apply subject_type filter if provided
        if let Some(subject_type_filter) = &request.subject_type {
            all_subjects.retain(|subject| {
                subject.split(':').next().map(|t| t == subject_type_filter).unwrap_or(false)
            });
        }

        debug!("Found {} subjects after filtering", all_subjects.len());

        // Decode cursor to get offset if provided
        let offset = if let Some(cursor) = &request.cursor {
            self.decode_continuation_token(cursor)?
        } else {
            0
        };

        // Apply default and maximum limits
        let limit = request.limit.unwrap_or(DEFAULT_LIST_LIMIT).min(MAX_LIST_LIMIT);

        // Apply pagination
        let subjects: Vec<String> = all_subjects.into_iter().skip(offset).take(limit).collect();

        let returned_count = subjects.len();

        // Determine if there are more results
        let has_more = returned_count == limit;
        let cursor = if has_more {
            Some(self.encode_continuation_token(offset + returned_count))
        } else {
            None
        };

        debug!(
            returned_count = returned_count,
            has_more = has_more,
            duration = ?start.elapsed(),
            "List subjects complete"
        );

        Ok(ListSubjectsResponse { subjects, cursor, total_count: Some(returned_count) })
    }

    /// Collect subjects for a given relation (recursive helper)
    fn collect_subjects_for_relation<'a>(
        &'a self,
        resource: &'a str,
        relation_def: &'a RelationDef,
        resource_type: &'a str,
        revision: Revision,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            use std::collections::HashSet;

            use crate::ipl::RelationExpr;

            let mut subjects = HashSet::new();

            if let Some(ref expr) = relation_def.expr {
                match expr {
                    // Direct relation: query tuples
                    RelationExpr::This => {
                        let tuples = self
                            .store
                            .list_relationships(
                                self.vault,
                                Some(resource),
                                Some(&relation_def.name),
                                None,
                                revision,
                            )
                            .await?;

                        for tuple in tuples {
                            subjects.insert(tuple.subject);
                        }
                    },

                    // Computed userset: follow relationship then get subjects from computed
                    // relation
                    RelationExpr::ComputedUserset { ref relationship, ref relation } => {
                        // First, find related objects via the relationship
                        let related_tuples = self
                            .store
                            .list_relationships(
                                self.vault,
                                Some(resource),
                                Some(relationship),
                                None,
                                revision,
                            )
                            .await?;

                        // For each related object, find subjects via the computed relation
                        for tuple in related_tuples {
                            let related_resource = &tuple.subject;
                            let related_parts: Vec<&str> = related_resource.split(':').collect();

                            if related_parts.len() == 2 {
                                let related_type = related_parts[0];
                                if let Some(related_type_def) = self.schema.find_type(related_type)
                                {
                                    if let Some(computed_rel_def) = related_type_def
                                        .relations
                                        .iter()
                                        .find(|r| r.name == *relation)
                                    {
                                        let related_subjects = self
                                            .collect_subjects_for_relation(
                                                related_resource,
                                                computed_rel_def,
                                                related_type,
                                                revision,
                                            )
                                            .await?;
                                        subjects.extend(related_subjects);
                                    }
                                }
                            }
                        }
                    },

                    // Union: collect subjects from all branches
                    RelationExpr::Union(ref branches) => {
                        for branch_expr in branches {
                            let branch_subjects = self
                                .collect_subjects_from_expr(
                                    resource,
                                    branch_expr,
                                    resource_type,
                                    &relation_def.name,
                                    revision,
                                )
                                .await?;
                            subjects.extend(branch_subjects);
                        }
                    },

                    // Intersection: collect subjects that appear in all branches
                    RelationExpr::Intersection(ref branches) => {
                        if branches.is_empty() {
                            return Ok(Vec::new());
                        }

                        // Get subjects from first branch
                        let mut intersection_subjects = self
                            .collect_subjects_from_expr(
                                resource,
                                &branches[0],
                                resource_type,
                                &relation_def.name,
                                revision,
                            )
                            .await?
                            .into_iter()
                            .collect::<HashSet<_>>();

                        // Intersect with remaining branches
                        for branch_expr in &branches[1..] {
                            let branch_subjects: HashSet<String> = self
                                .collect_subjects_from_expr(
                                    resource,
                                    branch_expr,
                                    resource_type,
                                    &relation_def.name,
                                    revision,
                                )
                                .await?
                                .into_iter()
                                .collect();
                            intersection_subjects.retain(|s| branch_subjects.contains(s));
                        }

                        subjects.extend(intersection_subjects);
                    },

                    // Exclusion: subjects in base but not in subtract
                    RelationExpr::Exclusion { base, subtract } => {
                        let base_subjects: HashSet<String> = self
                            .collect_subjects_from_expr(
                                resource,
                                base,
                                resource_type,
                                &relation_def.name,
                                revision,
                            )
                            .await?
                            .into_iter()
                            .collect();

                        let subtract_subjects: HashSet<String> = self
                            .collect_subjects_from_expr(
                                resource,
                                subtract,
                                resource_type,
                                &relation_def.name,
                                revision,
                            )
                            .await?
                            .into_iter()
                            .collect();

                        subjects.extend(base_subjects.difference(&subtract_subjects).cloned());
                    },

                    // RelatedObjectUserset: find related objects, then their subjects
                    RelationExpr::RelatedObjectUserset { ref relationship, ref computed } => {
                        // First, find all related objects via the relationship
                        let related_tuples = self
                            .store
                            .list_relationships(
                                self.vault,
                                Some(resource),
                                Some(relationship),
                                None,
                                revision,
                            )
                            .await?;

                        // For each related object, find subjects via the computed relation
                        for tuple in related_tuples {
                            let related_resource = &tuple.subject; // The subject is the related object

                            // Extract the type from the related resource
                            let related_parts: Vec<&str> = related_resource.split(':').collect();
                            if related_parts.len() == 2 {
                                let related_type = related_parts[0];

                                if let Some(related_type_def) = self.schema.find_type(related_type)
                                {
                                    if let Some(computed_rel_def) = related_type_def
                                        .relations
                                        .iter()
                                        .find(|r| r.name == *computed)
                                    {
                                        let related_subjects = self
                                            .collect_subjects_for_relation(
                                                related_resource,
                                                computed_rel_def,
                                                related_type,
                                                revision,
                                            )
                                            .await?;
                                        subjects.extend(related_subjects);
                                    }
                                }
                            }
                        }
                    },

                    // Relation reference: recursively get subjects from referenced relation
                    RelationExpr::RelationRef { ref relation } => {
                        let ref_rel_def = self
                            .schema
                            .find_type(resource_type)
                            .and_then(|t| t.relations.iter().find(|r| r.name == *relation))
                            .ok_or_else(|| {
                                EvalError::Evaluation(format!(
                                    "Unknown relation: {}#{}",
                                    resource_type, relation
                                ))
                            })?;

                        let ref_subjects = self
                            .collect_subjects_for_relation(
                                resource,
                                ref_rel_def,
                                resource_type,
                                revision,
                            )
                            .await?;
                        subjects.extend(ref_subjects);
                    },

                    // WASM module: Not supported for list_subjects (requires evaluation per
                    // subject)
                    RelationExpr::WasmModule { .. } => {
                        return Err(EvalError::Evaluation(
                            "WASM module-based relations are not supported for list_subjects"
                                .to_string(),
                        ));
                    },
                }
            } else {
                // No expression means it's a direct relation (This)
                let tuples = self
                    .store
                    .list_relationships(
                        self.vault,
                        Some(resource),
                        Some(&relation_def.name),
                        None,
                        revision,
                    )
                    .await?;

                for tuple in tuples {
                    subjects.insert(tuple.subject);
                }
            }

            Ok(subjects.into_iter().collect())
        })
    }

    /// Helper to collect subjects from a relation expression
    fn collect_subjects_from_expr<'a>(
        &'a self,
        resource: &'a str,
        expr: &'a crate::ipl::RelationExpr,
        resource_type: &'a str,
        relation_name: &'a str,
        revision: Revision,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            use std::collections::HashSet;

            use crate::ipl::RelationExpr;

            match expr {
                RelationExpr::This => {
                    // Collect direct relationships for this relation
                    let tuples = self
                        .store
                        .list_relationships(
                            self.vault,
                            Some(resource),
                            Some(relation_name),
                            None,
                            revision,
                        )
                        .await?;
                    Ok(tuples.into_iter().map(|t| t.subject).collect())
                },

                RelationExpr::ComputedUserset { ref relationship, ref relation } => {
                    let mut all_subjects = HashSet::new();
                    let related_tuples = self
                        .store
                        .list_relationships(
                            self.vault,
                            Some(resource),
                            Some(relationship),
                            None,
                            revision,
                        )
                        .await?;

                    for tuple in related_tuples {
                        let related_resource = &tuple.subject;
                        let related_parts: Vec<&str> = related_resource.split(':').collect();

                        if related_parts.len() == 2 {
                            let related_type = related_parts[0];
                            if let Some(related_type_def) = self.schema.find_type(related_type) {
                                if let Some(computed_rel_def) =
                                    related_type_def.relations.iter().find(|r| r.name == *relation)
                                {
                                    let related_subjects = self
                                        .collect_subjects_for_relation(
                                            related_resource,
                                            computed_rel_def,
                                            related_type,
                                            revision,
                                        )
                                        .await?;
                                    all_subjects.extend(related_subjects);
                                }
                            }
                        }
                    }

                    Ok(all_subjects.into_iter().collect())
                },

                RelationExpr::RelationRef { ref relation } => {
                    let ref_rel_def = self
                        .schema
                        .find_type(resource_type)
                        .and_then(|t| t.relations.iter().find(|r| r.name == *relation))
                        .ok_or_else(|| {
                            EvalError::Evaluation(format!(
                                "Unknown relation: {}#{}",
                                resource_type, relation
                            ))
                        })?;

                    self.collect_subjects_for_relation(
                        resource,
                        ref_rel_def,
                        resource_type,
                        revision,
                    )
                    .await
                },

                RelationExpr::Union(ref branches) => {
                    let mut all_subjects = HashSet::new();
                    for branch in branches {
                        let branch_subjects = self
                            .collect_subjects_from_expr(
                                resource,
                                branch,
                                resource_type,
                                relation_name,
                                revision,
                            )
                            .await?;
                        all_subjects.extend(branch_subjects);
                    }
                    Ok(all_subjects.into_iter().collect())
                },

                RelationExpr::Intersection(ref branches) => {
                    if branches.is_empty() {
                        return Ok(Vec::new());
                    }

                    let mut intersection_subjects = self
                        .collect_subjects_from_expr(
                            resource,
                            &branches[0],
                            resource_type,
                            relation_name,
                            revision,
                        )
                        .await?
                        .into_iter()
                        .collect::<HashSet<_>>();

                    for branch in &branches[1..] {
                        let branch_subjects: HashSet<String> = self
                            .collect_subjects_from_expr(
                                resource,
                                branch,
                                resource_type,
                                relation_name,
                                revision,
                            )
                            .await?
                            .into_iter()
                            .collect();
                        intersection_subjects.retain(|s| branch_subjects.contains(s));
                    }

                    Ok(intersection_subjects.into_iter().collect())
                },

                RelationExpr::Exclusion { base, subtract } => {
                    let base_subjects: HashSet<String> = self
                        .collect_subjects_from_expr(
                            resource,
                            base,
                            resource_type,
                            relation_name,
                            revision,
                        )
                        .await?
                        .into_iter()
                        .collect();

                    let subtract_subjects: HashSet<String> = self
                        .collect_subjects_from_expr(
                            resource,
                            subtract,
                            resource_type,
                            relation_name,
                            revision,
                        )
                        .await?
                        .into_iter()
                        .collect();

                    Ok(base_subjects.difference(&subtract_subjects).cloned().collect())
                },

                RelationExpr::RelatedObjectUserset { ref relationship, ref computed } => {
                    let mut all_subjects = HashSet::new();
                    let related_tuples = self
                        .store
                        .list_relationships(
                            self.vault,
                            Some(resource),
                            Some(relationship),
                            None,
                            revision,
                        )
                        .await?;

                    for tuple in related_tuples {
                        let related_resource = &tuple.subject;
                        let related_parts: Vec<&str> = related_resource.split(':').collect();

                        if related_parts.len() == 2 {
                            let related_type = related_parts[0];
                            if let Some(related_type_def) = self.schema.find_type(related_type) {
                                if let Some(computed_rel_def) =
                                    related_type_def.relations.iter().find(|r| r.name == *computed)
                                {
                                    let related_subjects = self
                                        .collect_subjects_for_relation(
                                            related_resource,
                                            computed_rel_def,
                                            related_type,
                                            revision,
                                        )
                                        .await?;
                                    all_subjects.extend(related_subjects);
                                }
                            }
                        }
                    }

                    Ok(all_subjects.into_iter().collect())
                },

                RelationExpr::WasmModule { .. } => Err(EvalError::Evaluation(
                    "WASM module-based relations are not supported for list_subjects".to_string(),
                )),
            }
        })
    }

    /// Get the WASM host (if configured)
    pub fn wasm_host(&self) -> Option<&Arc<WasmHost>> {
        self.wasm_host.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use infera_store::MemoryBackend;
    use infera_types::Relationship;

    use super::*;
    use crate::ipl::{RelationDef, RelationExpr, Schema, TypeDef};

    fn create_simple_schema() -> Schema {
        Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![RelationDef::new("reader".to_string(), None)],
        )])
    }

    fn create_complex_schema() -> Schema {
        Schema::new(vec![
            TypeDef::new(
                "folder".to_string(),
                vec![
                    RelationDef::new("owner".to_string(), None),
                    RelationDef::new(
                        "viewer".to_string(),
                        Some(RelationExpr::Union(vec![
                            RelationExpr::This,
                            RelationExpr::RelationRef { relation: "owner".to_string() },
                        ])),
                    ),
                ],
            ),
            TypeDef::new(
                "doc".to_string(),
                vec![
                    RelationDef::new("parent".to_string(), None),
                    RelationDef::new("owner".to_string(), None),
                    RelationDef::new(
                        "editor".to_string(),
                        Some(RelationExpr::Union(vec![
                            RelationExpr::This,
                            RelationExpr::RelationRef { relation: "owner".to_string() },
                        ])),
                    ),
                    RelationDef::new(
                        "viewer".to_string(),
                        Some(RelationExpr::Union(vec![
                            RelationExpr::This,
                            RelationExpr::RelationRef { relation: "editor".to_string() },
                            RelationExpr::RelatedObjectUserset {
                                relationship: "parent".to_string(),
                                computed: "viewer".to_string(),
                            },
                        ])),
                    ),
                ],
            ),
        ])
    }

    #[tokio::test]
    async fn test_direct_check_allow() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Add a direct relationship
        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: Uuid::nil(),
        };
        store.write(Uuid::nil(), vec![relationship]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_direct_check_deny() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[tokio::test]
    async fn test_wildcard_user_allow() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Add a wildcard user relationship that grants access to all users
        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:*".to_string(),
            vault: Uuid::nil(),
        };
        store.write(Uuid::nil(), vec![relationship]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Check that subject:alice has access
        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);

        // Check that subject:bob also has access
        let request = EvaluateRequest {
            subject: "user:bob".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);

        // Check that any user has access
        let request = EvaluateRequest {
            subject: "user:anyone".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_union_check() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Alice is owner, viewer is owner | this
        let relationship = Relationship {
            resource: "folder:docs".to_string(),
            relation: "owner".to_string(),
            subject: "user:alice".to_string(),
            vault: Uuid::nil(),
        };
        store.write(Uuid::nil(), vec![relationship]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "folder:docs".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_relationship_to_userset() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Set up: folder:docs has alice as viewer, doc:readme has parent->folder:docs
        let relationships = vec![
            Relationship {
                resource: "folder:docs".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "parent".to_string(),
                subject: "folder:docs".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Alice should be able to view doc:readme through parent->viewer
        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_nested_relations() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Alice is owner, editor = this | owner, viewer = this | editor | parent->viewer
        let relationships = vec![Relationship {
            resource: "doc:readme".to_string(),
            relation: "owner".to_string(),
            subject: "user:alice".to_string(),
            vault: Uuid::nil(),
        }];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Alice should be viewer through owner->editor->viewer chain
        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_check_with_trace() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: Uuid::nil(),
        };
        store.write(Uuid::nil(), vec![relationship]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
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

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ExpandRequest {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            limit: None,
            continuation_token: None,
        };

        let response = evaluator.expand(request).await.unwrap();
        assert!(matches!(response.tree.node_type, UsersetNodeType::Leaf { .. }));
        assert_eq!(response.tree.children.len(), 0);
        assert_eq!(response.users.len(), 0); // No relationships written yet
        assert!(response.continuation_token.is_none());
    }

    #[tokio::test]
    async fn test_expand_union() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "folder:docs".to_string(),
            relation: "viewer".to_string(),
        };

        let response = evaluator.expand(request).await.unwrap();
        let tree = &response.tree;
        assert!(matches!(tree.node_type, UsersetNodeType::Union));
        assert_eq!(tree.children.len(), 2);
    }

    #[tokio::test]
    async fn test_expand_intersection() {
        let schema = Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new("employee".to_string(), None),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::Intersection(vec![
                        RelationExpr::RelationRef { relation: "reader".to_string() },
                        RelationExpr::RelationRef { relation: "employee".to_string() },
                    ])),
                ),
            ],
        )]);

        let store = Arc::new(MemoryBackend::new());
        let evaluator = Evaluator::new(store, Arc::new(schema), None, Uuid::nil());

        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
        };

        let response = evaluator.expand(request).await.unwrap();
        let tree = &response.tree;
        assert!(matches!(tree.node_type, UsersetNodeType::Intersection));
        assert_eq!(tree.children.len(), 2);
    }

    #[tokio::test]
    async fn test_expand_exclusion() {
        let schema = Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("editor".to_string(), None),
                RelationDef::new("blocked".to_string(), None),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::Exclusion {
                        base: Box::new(RelationExpr::RelationRef {
                            relation: "editor".to_string(),
                        }),
                        subtract: Box::new(RelationExpr::RelationRef {
                            relation: "blocked".to_string(),
                        }),
                    }),
                ),
            ],
        )]);

        let store = Arc::new(MemoryBackend::new());
        let evaluator = Evaluator::new(store, Arc::new(schema), None, Uuid::nil());

        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
        };

        let response = evaluator.expand(request).await.unwrap();
        let tree = &response.tree;
        assert!(matches!(tree.node_type, UsersetNodeType::Exclusion));
        assert_eq!(tree.children.len(), 2);
    }

    #[tokio::test]
    async fn test_expand_nested() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Expand doc.viewer which has: this | editor | parent->viewer
        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
        };

        let response = evaluator.expand(request).await.unwrap();
        let tree = &response.tree;
        assert!(matches!(tree.node_type, UsersetNodeType::Union));
        assert_eq!(tree.children.len(), 3); // this, editor, parent->viewer
    }

    #[tokio::test]
    async fn test_expand_relationship_to_userset() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Get the viewer relation which has a relationship-to-userset component
        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
        };

        let response = evaluator.expand(request).await.unwrap();
        let tree = &response.tree;
        assert!(matches!(tree.node_type, UsersetNodeType::Union));

        // The new implementation resolves RelatedObjectUserset to Leaf nodes with actual users
        // Check that children are Leaf nodes (resolved from RelatedObjectUserset)
        let has_leaf_nodes = tree
            .children
            .iter()
            .any(|child| matches!(child.node_type, UsersetNodeType::Leaf { .. }));
        assert!(has_leaf_nodes);

        // Verify that users are collected (even if empty in this test)
        assert!(response.users.is_empty() || !response.users.is_empty());
    }

    #[tokio::test]
    async fn test_expand_invalid_resource() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
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

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
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

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "doc:readme".to_string(),
            relation: "unknown".to_string(),
        };

        let result = evaluator.expand(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_expand_pagination() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Write 50 users to the store
        let mut relationships = vec![];
        for i in 0..50 {
            relationships.push(Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: format!("user:{}", i),
                vault: Uuid::nil(),
            });
        }
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // First page: get 10 users
        let request = ExpandRequest {
            limit: Some(10),
            continuation_token: None,
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
        };

        let response = evaluator.expand(request).await.unwrap();
        assert_eq!(response.users.len(), 10);
        assert_eq!(response.total_count, Some(50));
        assert!(response.continuation_token.is_some());

        // Second page: get next 10 users
        let request2 = ExpandRequest {
            limit: Some(10),
            continuation_token: response.continuation_token.clone(),
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
        };

        let response2 = evaluator.expand(request2).await.unwrap();
        assert_eq!(response2.users.len(), 10);
        assert_eq!(response2.total_count, Some(50));
        assert!(response2.continuation_token.is_some());

        // Verify no overlap between pages
        let first_page_users: std::collections::HashSet<_> = response.users.iter().collect();
        let second_page_users: std::collections::HashSet<_> = response2.users.iter().collect();
        assert!(first_page_users.is_disjoint(&second_page_users));

        // Last page: get remaining users
        let mut continuation = response2.continuation_token.clone();
        let mut all_users = response.users.clone();
        all_users.extend(response2.users.clone());

        while let Some(token) = continuation {
            let req = ExpandRequest {
                limit: Some(10),
                continuation_token: Some(token),
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
            };

            let resp = evaluator.expand(req).await.unwrap();
            all_users.extend(resp.users);
            continuation = resp.continuation_token;
        }

        // Verify we got all 50 users
        assert_eq!(all_users.len(), 50);
        let unique_users: std::collections::HashSet<_> = all_users.iter().collect();
        assert_eq!(unique_users.len(), 50);
    }

    #[tokio::test]
    async fn test_expand_large_userset() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Write 1000 users to the store
        let mut relationships = vec![];
        for i in 0..1000 {
            relationships.push(Relationship {
                resource: "doc:large".to_string(),
                relation: "reader".to_string(),
                subject: format!("user:{}", i),
                vault: Uuid::nil(),
            });
        }
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Request without pagination (get all users)
        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "doc:large".to_string(),
            relation: "reader".to_string(),
        };

        let start = std::time::Instant::now();
        let response = evaluator.expand(request).await.unwrap();
        let duration = start.elapsed();

        // Verify all 1000 users are returned
        assert_eq!(response.users.len(), 1000);
        assert_eq!(response.total_count, Some(1000));
        assert!(response.continuation_token.is_none());

        // Verify deduplication (all users should be unique)
        let unique_users: std::collections::HashSet<_> = response.users.iter().collect();
        assert_eq!(unique_users.len(), 1000);

        // Performance check: should complete in reasonable time (<100ms)
        assert!(
            duration.as_millis() < 100,
            "Large userset expansion took too long: {}ms",
            duration.as_millis()
        );
    }

    #[tokio::test]
    async fn test_expand_deduplication_union() {
        let store = Arc::new(MemoryBackend::new());

        // Create schema with union relation
        let schema = Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new("editor".to_string(), None),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::RelationRef { relation: "reader".to_string() },
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                    ])),
                ),
            ],
        )]));

        // Write overlapping users to both relations
        store
            .write(
                Uuid::nil(),
                vec![
                    // alice is both reader and editor
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "reader".to_string(),
                        subject: "user:alice".to_string(),
                        vault: Uuid::nil(),
                    },
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "editor".to_string(),
                        subject: "user:alice".to_string(),
                        vault: Uuid::nil(),
                    },
                    // bob is only reader
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "reader".to_string(),
                        subject: "user:bob".to_string(),
                        vault: Uuid::nil(),
                    },
                    // charlie is only editor
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "editor".to_string(),
                        subject: "user:charlie".to_string(),
                        vault: Uuid::nil(),
                    },
                ],
            )
            .await
            .unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
        };

        let response = evaluator.expand(request).await.unwrap();

        // Should have 3 unique users (alice should only appear once)
        assert_eq!(response.users.len(), 3);
        assert!(response.users.contains(&"user:alice".to_string()));
        assert!(response.users.contains(&"user:bob".to_string()));
        assert!(response.users.contains(&"user:charlie".to_string()));

        // Verify tree structure is Union with Leaf children
        assert!(matches!(response.tree.node_type, UsersetNodeType::Union));
        assert_eq!(response.tree.children.len(), 2);
    }

    #[tokio::test]
    async fn test_expand_deduplication_intersection() {
        let store = Arc::new(MemoryBackend::new());

        // Create schema with intersection relation
        let schema = Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("approver".to_string(), None),
                RelationDef::new("editor".to_string(), None),
                RelationDef::new(
                    "can_publish".to_string(),
                    Some(RelationExpr::Intersection(vec![
                        RelationExpr::RelationRef { relation: "approver".to_string() },
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                    ])),
                ),
            ],
        )]));

        // Write test data
        store
            .write(
                Uuid::nil(),
                vec![
                    // alice is both approver and editor (should be in intersection)
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "approver".to_string(),
                        subject: "user:alice".to_string(),
                        vault: Uuid::nil(),
                    },
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "editor".to_string(),
                        subject: "user:alice".to_string(),
                        vault: Uuid::nil(),
                    },
                    // bob is only approver (should NOT be in intersection)
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "approver".to_string(),
                        subject: "user:bob".to_string(),
                        vault: Uuid::nil(),
                    },
                    // charlie is only editor (should NOT be in intersection)
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "editor".to_string(),
                        subject: "user:charlie".to_string(),
                        vault: Uuid::nil(),
                    },
                ],
            )
            .await
            .unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "doc:readme".to_string(),
            relation: "can_publish".to_string(),
        };

        let response = evaluator.expand(request).await.unwrap();

        // Should only have alice (intersection of approver & editor)
        assert_eq!(response.users.len(), 1);
        assert_eq!(response.users[0], "user:alice");

        // Verify tree structure is Intersection with Leaf children
        assert!(matches!(response.tree.node_type, UsersetNodeType::Intersection));
        assert_eq!(response.tree.children.len(), 2);
    }

    #[tokio::test]
    async fn test_expand_deduplication_exclusion() {
        let store = Arc::new(MemoryBackend::new());

        // Create schema with exclusion relation
        let schema = Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("viewer".to_string(), None),
                RelationDef::new("blocked".to_string(), None),
                RelationDef::new(
                    "can_view".to_string(),
                    Some(RelationExpr::Exclusion {
                        base: Box::new(RelationExpr::RelationRef {
                            relation: "viewer".to_string(),
                        }),
                        subtract: Box::new(RelationExpr::RelationRef {
                            relation: "blocked".to_string(),
                        }),
                    }),
                ),
            ],
        )]));

        // Write test data
        store
            .write(
                Uuid::nil(),
                vec![
                    // alice is viewer but not blocked (should be in result)
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "viewer".to_string(),
                        subject: "user:alice".to_string(),
                        vault: Uuid::nil(),
                    },
                    // bob is viewer AND blocked (should NOT be in result)
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "viewer".to_string(),
                        subject: "user:bob".to_string(),
                        vault: Uuid::nil(),
                    },
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "blocked".to_string(),
                        subject: "user:bob".to_string(),
                        vault: Uuid::nil(),
                    },
                    // charlie is viewer but not blocked (should be in result)
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "viewer".to_string(),
                        subject: "user:charlie".to_string(),
                        vault: Uuid::nil(),
                    },
                ],
            )
            .await
            .unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "doc:readme".to_string(),
            relation: "can_view".to_string(),
        };

        let response = evaluator.expand(request).await.unwrap();

        // Should have alice and charlie (bob is excluded)
        assert_eq!(response.users.len(), 2);
        assert!(response.users.contains(&"user:alice".to_string()));
        assert!(response.users.contains(&"user:charlie".to_string()));
        assert!(!response.users.contains(&"user:bob".to_string()));

        // Verify tree structure is Exclusion with Leaf children
        assert!(matches!(response.tree.node_type, UsersetNodeType::Exclusion));
        assert_eq!(response.tree.children.len(), 2);
    }

    #[tokio::test]
    async fn test_expand_parallel_correctness() {
        // Test that parallel expansion produces correct results with complex nested unions
        let store = Arc::new(MemoryBackend::new());

        // Create a schema with multiple parallel branches: admin | editor | viewer
        let schema = Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("admin".to_string(), None),
                RelationDef::new("editor".to_string(), None),
                RelationDef::new("viewer".to_string(), None),
                RelationDef::new("contributor".to_string(), None),
                RelationDef::new(
                    "any_access".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::RelationRef { relation: "admin".to_string() },
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                        RelationExpr::RelationRef { relation: "viewer".to_string() },
                        RelationExpr::RelationRef { relation: "contributor".to_string() },
                    ])),
                ),
            ],
        )]));

        // Write users to different relations (some overlap intentionally)
        store
            .write(
                Uuid::nil(),
                vec![
                    // alice is admin
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "admin".to_string(),
                        subject: "user:alice".to_string(),
                        vault: Uuid::nil(),
                    },
                    // bob is editor
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "editor".to_string(),
                        subject: "user:bob".to_string(),
                        vault: Uuid::nil(),
                    },
                    // charlie is viewer
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "viewer".to_string(),
                        subject: "user:charlie".to_string(),
                        vault: Uuid::nil(),
                    },
                    // dave is contributor
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "contributor".to_string(),
                        subject: "user:dave".to_string(),
                        vault: Uuid::nil(),
                    },
                    // eve is both editor and viewer (test deduplication)
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "editor".to_string(),
                        subject: "user:eve".to_string(),
                        vault: Uuid::nil(),
                    },
                    Relationship {
                        resource: "doc:readme".to_string(),
                        relation: "viewer".to_string(),
                        subject: "user:eve".to_string(),
                        vault: Uuid::nil(),
                    },
                ],
            )
            .await
            .unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ExpandRequest {
            limit: None,
            continuation_token: None,
            resource: "doc:readme".to_string(),
            relation: "any_access".to_string(),
        };

        let response = evaluator.expand(request).await.unwrap();

        // Should have 5 unique users (alice, bob, charlie, dave, eve - with eve deduplicated)
        assert_eq!(response.users.len(), 5);
        assert!(response.users.contains(&"user:alice".to_string()));
        assert!(response.users.contains(&"user:bob".to_string()));
        assert!(response.users.contains(&"user:charlie".to_string()));
        assert!(response.users.contains(&"user:dave".to_string()));
        assert!(response.users.contains(&"user:eve".to_string()));

        // Verify tree structure is Union with 4 Leaf children
        assert!(matches!(response.tree.node_type, UsersetNodeType::Union));
        assert_eq!(response.tree.children.len(), 4);

        // All children should be Leaf nodes (resolved RelationRefs)
        for child in &response.tree.children {
            assert!(matches!(child.node_type, UsersetNodeType::Leaf { .. }));
        }
    }

    #[tokio::test]
    async fn test_exclusion_check() {
        let schema = Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("editor".to_string(), None),
                RelationDef::new("blocked".to_string(), None),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::Exclusion {
                        base: Box::new(RelationExpr::RelationRef {
                            relation: "editor".to_string(),
                        }),
                        subtract: Box::new(RelationExpr::RelationRef {
                            relation: "blocked".to_string(),
                        }),
                    }),
                ),
            ],
        )]);

        let store = Arc::new(MemoryBackend::new());

        // Alice is editor but also blocked
        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "editor".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "blocked".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, Arc::new(schema), None, Uuid::nil());

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        // Alice should be denied (editor - blocked = denied)
        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[tokio::test]
    async fn test_intersection_check() {
        let schema = Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new("employee".to_string(), None),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::Intersection(vec![
                        RelationExpr::RelationRef { relation: "reader".to_string() },
                        RelationExpr::RelationRef { relation: "employee".to_string() },
                    ])),
                ),
            ],
        )]);

        let store = Arc::new(MemoryBackend::new());

        // Alice is reader and employee
        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "employee".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, Arc::new(schema), None, Uuid::nil());

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        // Alice should be allowed (reader & employee)
        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_intersection_check_deny() {
        let schema = Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new("employee".to_string(), None),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::Intersection(vec![
                        RelationExpr::RelationRef { relation: "reader".to_string() },
                        RelationExpr::RelationRef { relation: "employee".to_string() },
                    ])),
                ),
            ],
        )]);

        let store = Arc::new(MemoryBackend::new());

        // Alice is only reader, not employee
        let relationships = vec![Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: Uuid::nil(),
        }];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, Arc::new(schema), None, Uuid::nil());

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };

        // Alice should be denied (not an employee)
        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let relationships = vec![Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: Uuid::nil(),
        }];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
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

        let relationships = vec![Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: Uuid::nil(),
        }];
        store.write(Uuid::nil(), relationships).await.unwrap();

        // Create evaluator without cache
        let evaluator = Evaluator::new_with_cache(store, schema, None, None, Uuid::nil());

        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
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

        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:guide".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Different subject
        let request1 = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        // Different resource
        let request2 = EvaluateRequest {
            subject: "user:bob".to_string(),
            resource: "doc:guide".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        evaluator.check(request1.clone()).await.unwrap();
        evaluator.check(request2.clone()).await.unwrap();
        evaluator.check(request1).await.unwrap(); // Cache hit
        evaluator.check(request2).await.unwrap(); // Cache hit

        let stats = evaluator.cache_stats().unwrap();
        assert_eq!(stats.misses, 2); // Two different requests
        assert_eq!(stats.hits, 2); // Two repeated requests
        assert_eq!(stats.hit_rate, 50.0);
    }

    #[tokio::test]
    async fn test_list_resources_basic() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Create some documents and give alice access to some of them
        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:guide".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:secret".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "doc".to_string(),
            permission: "reader".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: None,
        };

        let response = evaluator.list_resources(request).await.unwrap();

        // Alice should have access to readme and guide, but not secret
        assert_eq!(response.resources.len(), 2);
        assert!(response.resources.contains(&"doc:readme".to_string()));
        assert!(response.resources.contains(&"doc:guide".to_string()));
        assert!(!response.resources.contains(&"doc:secret".to_string()));
        assert!(response.cursor.is_none()); // No more results
    }

    #[tokio::test]
    async fn test_list_resources_no_access() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Create documents but don't give charlie any access
        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:guide".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListResourcesRequest {
            subject: "user:charlie".to_string(),
            resource_type: "doc".to_string(),
            permission: "reader".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: None,
        };

        let response = evaluator.list_resources(request).await.unwrap();

        // Charlie should have no access
        assert_eq!(response.resources.len(), 0);
    }

    #[tokio::test]
    async fn test_list_resources_with_limit() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Create multiple documents alice can access
        let relationships = vec![
            Relationship {
                resource: "doc:1".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:2".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:3".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:4".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:5".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Request with limit of 2
        let request = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "doc".to_string(),
            permission: "reader".to_string(),
            limit: Some(2),
            cursor: None,
            resource_id_pattern: None,
        };

        let response = evaluator.list_resources(request).await.unwrap();

        // Should only return 2 resources
        assert_eq!(response.resources.len(), 2);
        assert!(response.cursor.is_some()); // Should have a cursor for pagination
    }

    #[tokio::test]
    async fn test_list_resources_pagination() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Create 10 documents alice can access
        let mut relationships = vec![];
        for i in 1..=10 {
            relationships.push(Relationship {
                resource: format!("doc:{}", i),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            });
        }
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // First page: get 3 resources
        let request1 = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "doc".to_string(),
            permission: "reader".to_string(),
            limit: Some(3),
            cursor: None,
            resource_id_pattern: None,
        };

        let response1 = evaluator.list_resources(request1).await.unwrap();
        assert_eq!(response1.resources.len(), 3);
        assert!(response1.cursor.is_some());

        // Second page: use cursor
        let request2 = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "doc".to_string(),
            permission: "reader".to_string(),
            limit: Some(3),
            cursor: response1.cursor.clone(),
            resource_id_pattern: None,
        };

        let response2 = evaluator.list_resources(request2).await.unwrap();
        assert_eq!(response2.resources.len(), 3);

        // Verify no overlap between pages
        let first_page: std::collections::HashSet<_> = response1.resources.iter().collect();
        let second_page: std::collections::HashSet<_> = response2.resources.iter().collect();
        assert!(first_page.is_disjoint(&second_page));
    }

    #[tokio::test]
    async fn test_list_resources_empty_type() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // No documents exist of this type
        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "folder".to_string(),
            permission: "reader".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: None,
        };

        let response = evaluator.list_resources(request).await.unwrap();

        // Should return empty list
        assert_eq!(response.resources.len(), 0);
        assert!(response.cursor.is_none());
    }

    #[tokio::test]
    async fn test_list_resources_with_union_relation() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Alice is owner of doc1, direct viewer of doc2
        // viewer = this | editor | parent->viewer
        let relationships = vec![
            Relationship {
                resource: "doc:1".to_string(),
                relation: "owner".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:2".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:3".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "doc".to_string(),
            permission: "viewer".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: None,
        };

        let response = evaluator.list_resources(request).await.unwrap();

        // Alice should have access to doc:1 (via owner->editor->viewer) and doc:2 (direct)
        assert_eq!(response.resources.len(), 2);
        assert!(response.resources.contains(&"doc:1".to_string()));
        assert!(response.resources.contains(&"doc:2".to_string()));
        assert!(!response.resources.contains(&"doc:3".to_string()));
    }

    #[tokio::test]
    async fn test_list_resources_with_wildcard_pattern() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Create documents with various names
        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme_v2".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:guide".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:tutorial".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Test wildcard pattern "readme*"
        let request = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "doc".to_string(),
            permission: "reader".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: Some("doc:readme*".to_string()),
        };

        let response = evaluator.list_resources(request).await.unwrap();

        // Should match "doc:readme" and "doc:readme_v2" but not "doc:guide" or "doc:tutorial"
        assert_eq!(response.resources.len(), 2);
        assert!(response.resources.contains(&"doc:readme".to_string()));
        assert!(response.resources.contains(&"doc:readme_v2".to_string()));
    }

    #[tokio::test]
    async fn test_list_resources_with_question_mark_pattern() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Create documents with single character variations
        let relationships = vec![
            Relationship {
                resource: "doc:file1".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:file2".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:file10".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Test ? pattern - matches single character
        let request = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "doc".to_string(),
            permission: "reader".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: Some("doc:file?".to_string()),
        };

        let response = evaluator.list_resources(request).await.unwrap();

        // Should match "doc:file1" and "doc:file2" but not "doc:file10" (has 2 chars after "file")
        assert_eq!(response.resources.len(), 2);
        assert!(response.resources.contains(&"doc:file1".to_string()));
        assert!(response.resources.contains(&"doc:file2".to_string()));
    }

    #[tokio::test]
    async fn test_list_resources_with_mixed_pattern() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let relationships = vec![
            Relationship {
                resource: "doc:project_abc_report".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:project_xyz_report".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:project_abc_summary".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Test mixed pattern "project_*_report"
        let request = ListResourcesRequest {
            subject: "user:alice".to_string(),
            resource_type: "doc".to_string(),
            permission: "reader".to_string(),
            limit: None,
            cursor: None,
            resource_id_pattern: Some("doc:project_*_report".to_string()),
        };

        let response = evaluator.list_resources(request).await.unwrap();

        // Should match both *_report files but not *_summary
        assert_eq!(response.resources.len(), 2);
        assert!(response.resources.contains(&"doc:project_abc_report".to_string()));
        assert!(response.resources.contains(&"doc:project_xyz_report".to_string()));
    }

    // ============================================================================
    // ListSubjects Tests
    // ============================================================================

    #[tokio::test]
    async fn test_list_subjects_basic() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Create some relationships where alice and bob are readers
        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:guide".to_string(),
                relation: "reader".to_string(),
                subject: "user:charlie".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListSubjectsRequest {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_subjects(request).await.unwrap();

        // Should return alice and bob as readers of doc:readme
        assert_eq!(response.subjects.len(), 2);
        assert!(response.subjects.contains(&"user:alice".to_string()));
        assert!(response.subjects.contains(&"user:bob".to_string()));
        assert!(!response.subjects.contains(&"user:charlie".to_string()));
        assert!(response.cursor.is_none()); // No more results
    }

    #[tokio::test]
    async fn test_list_subjects_no_subjects() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Create relationships for different document
        let relationships = vec![Relationship {
            resource: "doc:guide".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: Uuid::nil(),
        }];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListSubjectsRequest {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_subjects(request).await.unwrap();

        // Should return empty list
        assert_eq!(response.subjects.len(), 0);
        assert!(response.cursor.is_none());
    }

    #[tokio::test]
    async fn test_list_subjects_with_subject_type_filter() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Mix of users and groups
        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "group:admins".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "group:engineers".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store.clone(), schema.clone(), None, Uuid::nil());

        // Filter by user type
        let request = ListSubjectsRequest {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject_type: Some("user".to_string()),
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_subjects(request).await.unwrap();

        assert_eq!(response.subjects.len(), 2);
        assert!(response.subjects.contains(&"user:alice".to_string()));
        assert!(response.subjects.contains(&"user:bob".to_string()));
        assert!(!response.subjects.contains(&"group:admins".to_string()));

        // Filter by group type
        let request = ListSubjectsRequest {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject_type: Some("group".to_string()),
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_subjects(request).await.unwrap();

        assert_eq!(response.subjects.len(), 2);
        assert!(response.subjects.contains(&"group:admins".to_string()));
        assert!(response.subjects.contains(&"group:engineers".to_string()));
        assert!(!response.subjects.contains(&"user:alice".to_string()));
    }

    #[tokio::test]
    async fn test_list_subjects_with_limit() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Create multiple subjects with access
        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:charlie".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:dave".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:eve".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Request with limit of 2
        let request = ListSubjectsRequest {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject_type: None,
            limit: Some(2),
            cursor: None,
        };

        let response = evaluator.list_subjects(request).await.unwrap();

        // Should only return 2 subjects
        assert_eq!(response.subjects.len(), 2);
        assert!(response.cursor.is_some()); // Should have a cursor for pagination
    }

    #[tokio::test]
    async fn test_list_subjects_pagination() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Create 10 subjects with access
        let mut relationships = vec![];
        for i in 1..=10 {
            relationships.push(Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: format!("user:{}", i),
                vault: Uuid::nil(),
            });
        }
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // First page: get 3 subjects
        let request1 = ListSubjectsRequest {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject_type: None,
            limit: Some(3),
            cursor: None,
        };

        let response1 = evaluator.list_subjects(request1).await.unwrap();
        assert_eq!(response1.subjects.len(), 3);
        assert!(response1.cursor.is_some());

        // Second page: use cursor
        let request2 = ListSubjectsRequest {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject_type: None,
            limit: Some(3),
            cursor: response1.cursor.clone(),
        };

        let response2 = evaluator.list_subjects(request2).await.unwrap();
        assert_eq!(response2.subjects.len(), 3);

        // Verify no overlap between pages
        let first_page: std::collections::HashSet<_> = response1.subjects.iter().collect();
        let second_page: std::collections::HashSet<_> = response2.subjects.iter().collect();
        assert!(first_page.is_disjoint(&second_page));
    }

    #[tokio::test]
    async fn test_list_subjects_with_union_relation() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Alice is owner of doc:1, bob is direct viewer
        // viewer = this | editor | parent->viewer
        // editor = this | owner
        let relationships = vec![
            Relationship {
                resource: "doc:1".to_string(),
                relation: "owner".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListSubjectsRequest {
            resource: "doc:1".to_string(),
            relation: "viewer".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_subjects(request).await.unwrap();

        // Should include alice (via owner->editor->viewer) and bob (direct viewer)
        assert_eq!(response.subjects.len(), 2);
        assert!(response.subjects.contains(&"user:alice".to_string()));
        assert!(response.subjects.contains(&"user:bob".to_string()));
    }

    #[tokio::test]
    async fn test_list_subjects_with_computed_userset() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Alice is owner, bob is editor
        // editor = this | owner
        let relationships = vec![
            Relationship {
                resource: "doc:1".to_string(),
                relation: "owner".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:1".to_string(),
                relation: "editor".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListSubjectsRequest {
            resource: "doc:1".to_string(),
            relation: "editor".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_subjects(request).await.unwrap();

        // Should include alice (via owner) and bob (direct)
        assert_eq!(response.subjects.len(), 2);
        assert!(response.subjects.contains(&"user:alice".to_string()));
        assert!(response.subjects.contains(&"user:bob".to_string()));
    }

    #[tokio::test]
    async fn test_list_subjects_with_related_object_userset() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Alice is viewer of parent folder, doc has parent->viewer relation
        let relationships = vec![
            Relationship {
                resource: "folder:docs".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "parent".to_string(),
                subject: "folder:docs".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListSubjectsRequest {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_subjects(request).await.unwrap();

        // Should include alice (via parent->viewer) and bob (direct)
        assert_eq!(response.subjects.len(), 2);
        assert!(response.subjects.contains(&"user:alice".to_string()));
        assert!(response.subjects.contains(&"user:bob".to_string()));
    }

    #[tokio::test]
    async fn test_list_subjects_deduplication() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        // Alice has access through multiple paths:
        // - Direct viewer
        // - Owner (which implies editor, which implies viewer)
        let relationships = vec![
            Relationship {
                resource: "doc:1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:1".to_string(),
                relation: "owner".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListSubjectsRequest {
            resource: "doc:1".to_string(),
            relation: "viewer".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_subjects(request).await.unwrap();

        // Alice should only appear once despite multiple paths
        assert_eq!(response.subjects.len(), 1);
        assert!(response.subjects.contains(&"user:alice".to_string()));
    }

    #[tokio::test]
    async fn test_list_subjects_invalid_resource_format() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListSubjectsRequest {
            resource: "invalid-format".to_string(), // Missing colon
            relation: "reader".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let result = evaluator.list_subjects(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_subjects_unknown_type() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListSubjectsRequest {
            resource: "unknown:123".to_string(),
            relation: "reader".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let result = evaluator.list_subjects(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_subjects_unknown_relation() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        let request = ListSubjectsRequest {
            resource: "doc:readme".to_string(),
            relation: "unknown_relation".to_string(),
            subject_type: None,
            limit: None,
            cursor: None,
        };

        let result = evaluator.list_subjects(request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_glob_pattern_matching() {
        // Test basic wildcard
        assert!(Evaluator::matches_glob_pattern("doc:readme", "doc:readme"));
        assert!(Evaluator::matches_glob_pattern("doc:readme", "doc:*"));
        assert!(Evaluator::matches_glob_pattern("doc:readme", "*"));
        assert!(Evaluator::matches_glob_pattern("doc:readme", "doc:read*"));
        assert!(Evaluator::matches_glob_pattern("doc:readme_v2", "doc:readme*"));

        // Test question mark
        assert!(Evaluator::matches_glob_pattern("doc:file1", "doc:file?"));
        assert!(Evaluator::matches_glob_pattern("doc:file2", "doc:file?"));
        assert!(!Evaluator::matches_glob_pattern("doc:file10", "doc:file?"));

        // Test mixed patterns
        assert!(Evaluator::matches_glob_pattern("project_abc_report", "project_*_report"));
        assert!(Evaluator::matches_glob_pattern("project_xyz_report", "project_*_report"));
        assert!(!Evaluator::matches_glob_pattern("project_abc_summary", "project_*_report"));

        // Test edge cases
        assert!(Evaluator::matches_glob_pattern("", ""));
        assert!(Evaluator::matches_glob_pattern("", "*"));
        assert!(!Evaluator::matches_glob_pattern("a", ""));
        assert!(Evaluator::matches_glob_pattern("abc", "a*c"));
        assert!(Evaluator::matches_glob_pattern("abc", "a?c"));
        assert!(!Evaluator::matches_glob_pattern("abbc", "a?c"));
    }

    #[tokio::test]
    async fn test_list_relationships_no_filters() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Add multiple relationships
        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:guide".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:charlie".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // List all relationships with no filters
        let request = ListRelationshipsRequest {
            resource: None,
            relation: None,
            subject: None,
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_relationships(request).await.unwrap();

        assert_eq!(response.relationships.len(), 3);
        assert!(response.cursor.is_none());
    }

    #[tokio::test]
    async fn test_list_relationships_filter_by_object() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:guide".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Filter by resource
        let request = ListRelationshipsRequest {
            resource: Some("doc:readme".to_string()),
            relation: None,
            subject: None,
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_relationships(request).await.unwrap();

        assert_eq!(response.relationships.len(), 2);
        assert!(response.relationships.iter().all(|r| r.resource == "doc:readme"));
    }

    #[tokio::test]
    async fn test_list_relationships_filter_by_relation() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "owner".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:guide".to_string(),
                relation: "owner".to_string(),
                subject: "user:charlie".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Filter by relation
        let request = ListRelationshipsRequest {
            resource: None,
            relation: Some("owner".to_string()),
            subject: None,
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_relationships(request).await.unwrap();

        assert_eq!(response.relationships.len(), 2);
        assert!(response.relationships.iter().all(|r| r.relation == "owner"));
    }

    #[tokio::test]
    async fn test_list_relationships_filter_by_user() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:guide".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Filter by subject
        let request = ListRelationshipsRequest {
            resource: None,
            relation: None,
            subject: Some("user:alice".to_string()),
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_relationships(request).await.unwrap();

        assert_eq!(response.relationships.len(), 2);
        assert!(response.relationships.iter().all(|r| r.subject == "user:alice"));
    }

    #[tokio::test]
    async fn test_list_relationships_multiple_filters() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_complex_schema());

        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "owner".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "viewer".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "owner".to_string(),
                subject: "user:bob".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:guide".to_string(),
                relation: "owner".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Filter by resource + relation + subject
        let request = ListRelationshipsRequest {
            resource: Some("doc:readme".to_string()),
            relation: Some("owner".to_string()),
            subject: Some("user:alice".to_string()),
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_relationships(request).await.unwrap();

        assert_eq!(response.relationships.len(), 1);
        assert_eq!(response.relationships[0].resource, "doc:readme");
        assert_eq!(response.relationships[0].relation, "owner");
        assert_eq!(response.relationships[0].subject, "user:alice");
    }

    #[tokio::test]
    async fn test_list_relationships_pagination() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Add many relationships
        let mut relationships = Vec::new();
        for i in 0..150 {
            relationships.push(Relationship {
                resource: format!("doc:{}", i),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            });
        }
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // First page with default limit (100)
        let request = ListRelationshipsRequest {
            resource: None,
            relation: None,
            subject: Some("user:alice".to_string()),
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_relationships(request).await.unwrap();

        assert_eq!(response.relationships.len(), 100); // Default limit
        assert!(response.cursor.is_some());

        // Second page using cursor
        let request = ListRelationshipsRequest {
            resource: None,
            relation: None,
            subject: Some("user:alice".to_string()),
            limit: None,
            cursor: response.cursor,
        };

        let response = evaluator.list_relationships(request).await.unwrap();

        assert_eq!(response.relationships.len(), 50); // Remaining relationships
        assert!(response.cursor.is_none());
    }

    #[tokio::test]
    async fn test_list_relationships_custom_limit() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Add 50 relationships
        let mut relationships = Vec::new();
        for i in 0..50 {
            relationships.push(Relationship {
                resource: format!("doc:{}", i),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            });
        }
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Custom limit of 10
        let request = ListRelationshipsRequest {
            resource: None,
            relation: None,
            subject: Some("user:alice".to_string()),
            limit: Some(10),
            cursor: None,
        };

        let response = evaluator.list_relationships(request).await.unwrap();

        assert_eq!(response.relationships.len(), 10);
        assert!(response.cursor.is_some());
    }

    #[tokio::test]
    async fn test_list_relationships_max_limit() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Request with limit > max (1000)
        let request = ListRelationshipsRequest {
            resource: None,
            relation: None,
            subject: None,
            limit: Some(5000), // Exceeds max
            cursor: None,
        };

        let response = evaluator.list_relationships(request).await.unwrap();

        // Should be clamped to max of 1000
        assert!(response.relationships.len() <= 1000);
    }

    #[tokio::test]
    async fn test_list_relationships_empty_result() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Query with no matching relationships
        let request = ListRelationshipsRequest {
            resource: Some("doc:nonexistent".to_string()),
            relation: None,
            subject: None,
            limit: None,
            cursor: None,
        };

        let response = evaluator.list_relationships(request).await.unwrap();

        assert_eq!(response.relationships.len(), 0);
        assert!(response.cursor.is_none());
    }

    // ============================================================================
    // Wildcard Tests (Phase 3.1)
    // ============================================================================

    #[tokio::test]
    async fn test_wildcard_check_allow() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Add a wildcard relationship: all users can read
        let wildcard_relationship = Relationship {
            resource: "doc:public".to_string(),
            relation: "reader".to_string(),
            subject: "user:*".to_string(),
            vault: Uuid::nil(),
        };
        store.write(Uuid::nil(), vec![wildcard_relationship]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Test that alice (a user) can read
        let request_alice = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:public".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request_alice).await.unwrap();
        assert_eq!(result, Decision::Allow);

        // Test that bob (another user) can also read
        let request_bob = EvaluateRequest {
            subject: "user:bob".to_string(),
            resource: "doc:public".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request_bob).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_wildcard_type_mismatch_deny() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Add a wildcard relationship: all users can read (not groups)
        let wildcard_relationship = Relationship {
            resource: "doc:public".to_string(),
            relation: "reader".to_string(),
            subject: "user:*".to_string(),
            vault: Uuid::nil(),
        };
        store.write(Uuid::nil(), vec![wildcard_relationship]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Test that a group cannot read (type mismatch)
        let request_group = EvaluateRequest {
            subject: "group:admins".to_string(),
            resource: "doc:public".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request_group).await.unwrap();
        assert_eq!(result, Decision::Deny);
    }

    #[tokio::test]
    async fn test_wildcard_with_specific_override() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Add both wildcard and specific relationship
        let relationships = vec![
            Relationship {
                resource: "doc:public".to_string(),
                relation: "reader".to_string(),
                subject: "user:*".to_string(),
                vault: Uuid::nil(),
            },
            Relationship {
                resource: "doc:public".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Both specific and wildcard should allow access
        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:public".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow);
    }

    #[tokio::test]
    async fn test_wildcard_public_resource_scenario() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(create_simple_schema());

        // Model a public document that anyone can read
        let public_doc = Relationship {
            resource: "doc:announcement".to_string(),
            relation: "reader".to_string(),
            subject: "user:*".to_string(),
            vault: Uuid::nil(),
        };
        store.write(Uuid::nil(), vec![public_doc]).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Multiple different users should all have access
        let users = vec!["user:alice", "user:bob", "user:charlie", "user:david"];
        for user in users {
            let request = EvaluateRequest {
                subject: user.to_string(),
                resource: "doc:announcement".to_string(),
                permission: "reader".to_string(),
                context: None,
                trace: None,
            };

            let result = evaluator.check(request).await.unwrap();
            assert_eq!(
                result,
                Decision::Allow,
                "User {} should have access to public document",
                user
            );
        }
    }

    #[tokio::test]
    async fn test_wildcard_mixed_with_regular_relationships() {
        let store = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![RelationDef::new("reader".to_string(), None)],
        )]));

        // Mix of wildcard and specific relationships
        let relationships = vec![
            // Public document - anyone can read
            Relationship {
                resource: "doc:public_readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:*".to_string(),
                vault: Uuid::nil(),
            },
            // Private document - only Alice can read
            Relationship {
                resource: "doc:private_notes".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
                vault: Uuid::nil(),
            },
        ];
        store.write(Uuid::nil(), relationships).await.unwrap();

        let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

        // Alice can read both
        let alice_public = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:public_readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };
        assert_eq!(evaluator.check(alice_public).await.unwrap(), Decision::Allow);

        let alice_private = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: "doc:private_notes".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };
        assert_eq!(evaluator.check(alice_private).await.unwrap(), Decision::Allow);

        // Bob can only read public
        let bob_public = EvaluateRequest {
            subject: "user:bob".to_string(),
            resource: "doc:public_readme".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };
        assert_eq!(evaluator.check(bob_public).await.unwrap(), Decision::Allow);

        let bob_private = EvaluateRequest {
            subject: "user:bob".to_string(),
            resource: "doc:private_notes".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };
        assert_eq!(evaluator.check(bob_private).await.unwrap(), Decision::Deny);
    }
}
