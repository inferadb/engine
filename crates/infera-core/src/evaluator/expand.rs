//! Userset expansion logic

use super::*;

impl Evaluator {
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
                        self.vault,
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
                        self.vault,
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
                let tree = if let Some(expr) = expr_opt.as_ref() {
                    // Recursively expand the referenced relation's expression
                    self.build_userset_tree_with_users(resource, expr, ctx).await?
                } else {
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
}
