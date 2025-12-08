//! Permission checking logic

use super::*;

impl Evaluator {
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
                self.vault,
                request.subject.clone(),
                request.resource.clone(),
                request.permission.clone(),
                revision,
            );
            if let Some(decision) = cache.get_check(&cache_key).await {
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
                        self.vault,
                        request.subject.clone(),
                        request.resource.clone(),
                        request.permission.clone(),
                        revision,
                    );
                    cache.put_check(cache_key, Decision::Deny).await;
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
                self.vault,
                request.subject.clone(),
                request.resource.clone(),
                request.permission.clone(),
                revision,
            );
            cache.put_check(cache_key, decision.clone()).await;
        }

        debug!(
            decision = ?decision,
            duration = ?start.elapsed(),
            "Permission check complete"
        );

        Ok(decision)
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> Option<inferadb_engine_cache::CacheStats> {
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
                let _span = inferadb_engine_observe::span_utils::wasm_span(module_name);
                let _guard = _span.enter();

                let wasm_host = self
                    .wasm_host
                    .as_ref()
                    .ok_or_else(|| EvalError::Evaluation("WASM host not configured".to_string()))?;

                let exec_context = inferadb_engine_wasm::ExecutionContext {
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
                inferadb_engine_observe::span_utils::record_wasm_result(
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
}
