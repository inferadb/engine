//! Resource, relationship, and subject listing logic

use super::*;

impl Evaluator {
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
            if let Some(limit) = request.limit
                && accessible_resources.len() >= limit
            {
                break;
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
    pub(super) fn decode_continuation_token(&self, token: &str) -> Result<usize> {
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

    /// Encode an offset as a continuation token
    pub(super) fn encode_continuation_token(&self, offset: usize) -> String {
        use base64::Engine;
        let bytes: Vec<u8> = offset.to_le_bytes().to_vec();
        base64::engine::general_purpose::STANDARD.encode(&bytes)
    }

    /// Match a string against a glob pattern
    /// Supports:
    /// - `*` matches any sequence of characters (including none)
    /// - `?` matches exactly one character
    /// - All other characters match literally
    ///
    /// Note: Made pub(crate) for testing
    pub(crate) fn matches_glob_pattern(text: &str, pattern: &str) -> bool {
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
                    RelationExpr::ComputedUserset { relationship, relation } => {
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
                                    && let Some(computed_rel_def) = related_type_def
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
                    },

                    // Union: collect subjects from all branches
                    RelationExpr::Union(branches) => {
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
                    RelationExpr::Intersection(branches) => {
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
                    RelationExpr::RelatedObjectUserset { relationship, computed } => {
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
                                    && let Some(computed_rel_def) = related_type_def
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
                    },

                    // Relation reference: recursively get subjects from referenced relation
                    RelationExpr::RelationRef { relation } => {
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

                RelationExpr::ComputedUserset { relationship, relation } => {
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
                            if let Some(related_type_def) = self.schema.find_type(related_type)
                                && let Some(computed_rel_def) =
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

                    Ok(all_subjects.into_iter().collect())
                },

                RelationExpr::RelationRef { relation } => {
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

                RelationExpr::Union(branches) => {
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

                RelationExpr::Intersection(branches) => {
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

                RelationExpr::RelatedObjectUserset { relationship, computed } => {
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
                            if let Some(related_type_def) = self.schema.find_type(related_type)
                                && let Some(computed_rel_def) =
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

                    Ok(all_subjects.into_iter().collect())
                },

                RelationExpr::WasmModule { .. } => Err(EvalError::Evaluation(
                    "WASM module-based relations are not supported for list_subjects".to_string(),
                )),
            }
        })
    }
}
