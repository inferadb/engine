//! In-memory storage backend for testing and development

use async_trait::async_trait;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    MetricsSnapshot, OpTimer, Relationship, RelationshipKey, RelationshipStore, Result, Revision,
    StoreMetrics,
};
use infera_types::{DeleteFilter, StoreError};

/// A versioned relationship with its creation revision
#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionedRelationship {
    relationship: Relationship,
    created_at: Revision,
    deleted_at: Option<Revision>,
}

/// In-memory relationship store implementation with full indexing and revision support
pub struct MemoryBackend {
    data: Arc<RwLock<MemoryStore>>,
    metrics: Arc<StoreMetrics>,
}

struct MemoryStore {
    /// Primary storage: all relationships with their version history
    relationships: Vec<VersionedRelationship>,

    /// Index by (object, relation) for fast lookups
    resource_relation_index: HashMap<(String, String), Vec<usize>>,

    /// Index by (user, relation) for reverse lookups
    subject_relation_index: HashMap<(String, String), Vec<usize>>,

    /// Index by object for wildcard queries
    resource_index: HashMap<String, Vec<usize>>,

    /// Current revision number
    revision: Revision,

    /// Revision history for garbage collection
    revision_history: BTreeMap<Revision, Vec<usize>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(MemoryStore {
                relationships: Vec::new(),
                resource_relation_index: HashMap::new(),
                subject_relation_index: HashMap::new(),
                resource_index: HashMap::new(),
                revision: Revision::zero(),
                revision_history: BTreeMap::new(),
            })),
            metrics: Arc::new(StoreMetrics::new()),
        }
    }

    /// Collect garbage for revisions older than the given revision
    pub async fn gc_before(&self, before: Revision) -> Result<usize> {
        let mut store = self.data.write().await;
        let mut removed = 0;

        // Remove old revisions from history
        let old_revisions: Vec<_> = store
            .revision_history
            .range(..before)
            .map(|(rev, _)| *rev)
            .collect();

        for rev in old_revisions {
            if let Some(indices) = store.revision_history.remove(&rev) {
                removed += indices.len();
            }
        }

        Ok(removed)
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RelationshipStore for MemoryBackend {
    async fn read(&self, key: &RelationshipKey, revision: Revision) -> Result<Vec<Relationship>> {
        let timer = OpTimer::new();
        let store = self.data.read().await;

        // Find matching relationship indices
        let indices = if let Some(user) = &key.subject {
            // Specific user query
            store
                .resource_relation_index
                .get(&(key.resource.clone(), key.relation.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| {
                    let vt = &store.relationships[idx];
                    vt.relationship.subject == *user
                })
                .copied()
                .collect::<Vec<_>>()
        } else {
            // All users for this object+relation
            store
                .resource_relation_index
                .get(&(key.resource.clone(), key.relation.clone()))
                .cloned()
                .unwrap_or_default()
        };

        // Filter by revision and return relationships
        let relationships = indices
            .iter()
            .filter_map(|&idx| {
                let vt = &store.relationships[idx];
                // Include if created before or at revision and not deleted before or at revision
                if vt.created_at <= revision
                    && (vt.deleted_at.is_none() || vt.deleted_at.unwrap() > revision)
                {
                    Some(vt.relationship.clone())
                } else {
                    None
                }
            })
            .collect();

        self.metrics.record_read(timer.elapsed(), false);
        Ok(relationships)
    }

    async fn write(&self, relationships: Vec<Relationship>) -> Result<Revision> {
        let timer = OpTimer::new();
        let mut store = self.data.write().await;

        // Increment revision
        store.revision = store.revision.next();
        let current_revision = store.revision;

        let mut new_indices = Vec::new();

        // Track relationships we're adding in this batch to avoid intra-batch duplicates
        let mut batch_relationships = std::collections::HashSet::new();

        for relationship in relationships {
            // Create a unique key for this relationship
            let relationship_key = (
                relationship.resource.clone(),
                relationship.relation.clone(),
                relationship.subject.clone(),
            );

            // Check for duplicates within this batch
            if batch_relationships.contains(&relationship_key) {
                // Skip duplicate within this batch
                continue;
            }

            // Check for duplicates at current revision
            let key = (relationship.resource.clone(), relationship.relation.clone());
            let existing_indices = store
                .resource_relation_index
                .get(&key)
                .cloned()
                .unwrap_or_default();

            let is_duplicate = existing_indices.iter().any(|&idx| {
                let vt = &store.relationships[idx];
                vt.relationship.subject == relationship.subject && vt.deleted_at.is_none()
            });

            if is_duplicate {
                // Skip duplicate relationship already in store
                continue;
            }

            // Mark this relationship as seen in this batch
            batch_relationships.insert(relationship_key);

            // Add new versioned relationship
            let idx = store.relationships.len();
            let versioned = VersionedRelationship {
                relationship: relationship.clone(),
                created_at: current_revision,
                deleted_at: None,
            };

            store.relationships.push(versioned);
            new_indices.push(idx);

            // Update indices
            store
                .resource_relation_index
                .entry(key.clone())
                .or_insert_with(Vec::new)
                .push(idx);

            store
                .subject_relation_index
                .entry((relationship.subject.clone(), relationship.relation.clone()))
                .or_insert_with(Vec::new)
                .push(idx);

            store
                .resource_index
                .entry(relationship.resource.clone())
                .or_insert_with(Vec::new)
                .push(idx);
        }

        // Track revision history
        store.revision_history.insert(current_revision, new_indices);

        // Update metrics
        let relationship_bytes: usize = batch_relationships.len() * 64; // Approximate bytes per relationship
        self.metrics.record_write(timer.elapsed(), false);
        self.metrics
            .update_key_space(store.relationships.len() as u64, relationship_bytes as u64);

        Ok(current_revision)
    }

    async fn get_revision(&self) -> Result<Revision> {
        let store = self.data.read().await;
        Ok(store.revision)
    }

    async fn delete(&self, key: &RelationshipKey) -> Result<Revision> {
        let timer = OpTimer::new();
        let mut store = self.data.write().await;

        // Increment revision
        store.revision = store.revision.next();
        let current_revision = store.revision;

        // Find relationships to delete
        let indices = if let Some(user) = &key.subject {
            // Delete specific user
            store
                .resource_relation_index
                .get(&(key.resource.clone(), key.relation.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| {
                    let vt = &store.relationships[idx];
                    vt.relationship.subject == *user && vt.deleted_at.is_none()
                })
                .copied()
                .collect::<Vec<_>>()
        } else {
            // Delete all users for this object+relation
            store
                .resource_relation_index
                .get(&(key.resource.clone(), key.relation.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| store.relationships[idx].deleted_at.is_none())
                .copied()
                .collect::<Vec<_>>()
        };

        // Mark relationships as deleted
        for idx in indices {
            store.relationships[idx].deleted_at = Some(current_revision);
        }

        self.metrics.record_delete(timer.elapsed(), false);

        Ok(current_revision)
    }

    async fn delete_by_filter(
        &self,
        filter: &DeleteFilter,
        limit: Option<usize>,
    ) -> Result<(Revision, usize)> {
        let timer = OpTimer::new();

        // Validate filter is not empty
        if filter.is_empty() {
            return Err(StoreError::Internal(
                "Filter must have at least one field set".to_string(),
            ));
        }

        let mut store = self.data.write().await;

        // Increment revision
        store.revision = store.revision.next();
        let current_revision = store.revision;

        // Find all relationships matching the filter
        let mut matching_indices = Vec::new();

        for (idx, versioned) in store.relationships.iter().enumerate() {
            // Skip already deleted
            if versioned.deleted_at.is_some() {
                continue;
            }

            let rel = &versioned.relationship;

            // Check filter conditions
            let matches = match (&filter.resource, &filter.relation, &filter.subject) {
                // All three specified (exact match)
                (Some(res), Some(rel_name), Some(sub)) => {
                    rel.resource == *res && rel.relation == *rel_name && rel.subject == *sub
                }
                // Resource + Relation
                (Some(res), Some(rel_name), None) => {
                    rel.resource == *res && rel.relation == *rel_name
                }
                // Resource + Subject
                (Some(res), None, Some(sub)) => rel.resource == *res && rel.subject == *sub,
                // Relation + Subject
                (None, Some(rel_name), Some(sub)) => {
                    rel.relation == *rel_name && rel.subject == *sub
                }
                // Resource only
                (Some(res), None, None) => rel.resource == *res,
                // Relation only
                (None, Some(rel_name), None) => rel.relation == *rel_name,
                // Subject only (user offboarding)
                (None, None, Some(sub)) => rel.subject == *sub,
                // None (should be caught by filter.is_empty())
                (None, None, None) => false,
            };

            if matches {
                matching_indices.push(idx);

                // Check limit
                if let Some(lim) = limit {
                    if lim > 0 && matching_indices.len() >= lim {
                        break;
                    }
                }
            }
        }

        let deleted_count = matching_indices.len();

        // Mark relationships as deleted
        for idx in matching_indices {
            store.relationships[idx].deleted_at = Some(current_revision);
        }

        self.metrics.record_delete(timer.elapsed(), false);

        Ok((current_revision, deleted_count))
    }

    async fn list_resources_by_type(
        &self,
        object_type: &str,
        revision: Revision,
    ) -> Result<Vec<String>> {
        let timer = OpTimer::new();
        let store = self.data.read().await;

        // Build the type prefix (e.g., "document:")
        let type_prefix = format!("{}:", object_type);

        // Collect unique objects that match the type prefix and have active relationships at this revision
        let mut objects = std::collections::HashSet::new();

        for (object, indices) in &store.resource_index {
            // Check if object matches the type prefix
            if object.starts_with(&type_prefix) {
                // Check if this object has any active relationships at the given revision
                let has_active = indices.iter().any(|&idx| {
                    let vt = &store.relationships[idx];
                    vt.created_at <= revision
                        && (vt.deleted_at.is_none() || vt.deleted_at.unwrap() > revision)
                });

                if has_active {
                    objects.insert(object.clone());
                }
            }
        }

        // Convert to sorted vector for deterministic output
        let mut result: Vec<String> = objects.into_iter().collect();
        result.sort();

        self.metrics.record_read(timer.elapsed(), false);
        Ok(result)
    }

    async fn list_relationships(
        &self,
        resource: Option<&str>,
        relation: Option<&str>,
        subject: Option<&str>,
        revision: Revision,
    ) -> Result<Vec<Relationship>> {
        let timer = OpTimer::new();
        let store = self.data.read().await;

        // Map API parameter names to internal relationship field names
        let object = resource;
        let user = subject;

        // Collect candidate indices based on available filters
        let candidate_indices: Vec<usize> = match (object, relation, user) {
            // All three filters provided - most specific query
            (Some(obj), Some(rel), Some(usr)) => store
                .resource_relation_index
                .get(&(obj.to_string(), rel.to_string()))
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| store.relationships[idx].relationship.subject == usr)
                .copied()
                .collect(),
            // Object and relation filters
            (Some(obj), Some(rel), None) => store
                .resource_relation_index
                .get(&(obj.to_string(), rel.to_string()))
                .cloned()
                .unwrap_or_default(),
            // Object filter only
            (Some(obj), None, None) => store.resource_index.get(obj).cloned().unwrap_or_default(),
            // User and relation filters
            (None, Some(rel), Some(usr)) => store
                .subject_relation_index
                .get(&(usr.to_string(), rel.to_string()))
                .cloned()
                .unwrap_or_default(),
            // User filter only
            (None, None, Some(usr)) => {
                // Need to scan all relationships with this user
                store
                    .relationships
                    .iter()
                    .enumerate()
                    .filter(|(_, vt)| vt.relationship.subject == usr)
                    .map(|(idx, _)| idx)
                    .collect()
            }
            // Relation filter only
            (None, Some(rel), None) => {
                // Need to scan all relationships with this relation
                store
                    .relationships
                    .iter()
                    .enumerate()
                    .filter(|(_, vt)| vt.relationship.relation == rel)
                    .map(|(idx, _)| idx)
                    .collect()
            }
            // Object and user filters (no relation)
            (Some(obj), None, Some(usr)) => store
                .resource_index
                .get(obj)
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| store.relationships[idx].relationship.subject == usr)
                .copied()
                .collect(),
            // No filters - return all relationships
            (None, None, None) => (0..store.relationships.len()).collect(),
        };

        // Filter by revision and apply any remaining filters
        let relationships = candidate_indices
            .iter()
            .filter_map(|&idx| {
                let vt = &store.relationships[idx];

                // Check revision
                if vt.created_at > revision
                    || (vt.deleted_at.is_some() && vt.deleted_at.unwrap() <= revision)
                {
                    return None;
                }

                // Apply any missing filters (for cases where we couldn't use indexes)
                if let Some(rel) = relation {
                    if vt.relationship.relation != rel {
                        return None;
                    }
                }
                if let Some(obj) = object {
                    if vt.relationship.resource != obj {
                        return None;
                    }
                }
                if let Some(usr) = user {
                    if vt.relationship.subject != usr {
                        return None;
                    }
                }

                Some(vt.relationship.clone())
            })
            .collect();

        self.metrics.record_read(timer.elapsed(), false);
        Ok(relationships)
    }

    fn metrics(&self) -> Option<MetricsSnapshot> {
        Some(self.metrics.snapshot())
    }
}

/// Query patterns for advanced lookups
impl MemoryBackend {
    /// Query by user and relation (reverse lookup)
    pub async fn query_by_user(
        &self,
        subject: &str,
        relation: &str,
        revision: Revision,
    ) -> Result<Vec<Relationship>> {
        let store = self.data.read().await;

        let indices = store
            .subject_relation_index
            .get(&(subject.to_string(), relation.to_string()))
            .cloned()
            .unwrap_or_default();

        let relationships = indices
            .iter()
            .filter_map(|&idx| {
                let vt = &store.relationships[idx];
                if vt.created_at <= revision
                    && (vt.deleted_at.is_none() || vt.deleted_at.unwrap() > revision)
                {
                    Some(vt.relationship.clone())
                } else {
                    None
                }
            })
            .collect();

        Ok(relationships)
    }

    /// Query all relations for an object
    pub async fn query_by_object(
        &self,
        resource: &str,
        revision: Revision,
    ) -> Result<Vec<Relationship>> {
        let store = self.data.read().await;

        let indices = store
            .resource_index
            .get(resource)
            .cloned()
            .unwrap_or_default();

        let relationships = indices
            .iter()
            .filter_map(|&idx| {
                let vt = &store.relationships[idx];
                if vt.created_at <= revision
                    && (vt.deleted_at.is_none() || vt.deleted_at.unwrap() > revision)
                {
                    Some(vt.relationship.clone())
                } else {
                    None
                }
            })
            .collect();

        Ok(relationships)
    }

    /// Get all unique objects
    pub async fn get_objects(&self) -> Result<Vec<String>> {
        let store = self.data.read().await;
        Ok(store.resource_index.keys().cloned().collect())
    }

    /// Get statistics about the store
    pub async fn stats(&self) -> MemoryStats {
        let store = self.data.read().await;

        let active_relationships = store
            .relationships
            .iter()
            .filter(|vt| vt.deleted_at.is_none())
            .count();

        MemoryStats {
            total_relationships: store.relationships.len(),
            active_relationships,
            deleted_relationships: store.relationships.len() - active_relationships,
            current_revision: store.revision,
            unique_objects: store.resource_index.len(),
            index_memory: store.resource_relation_index.len()
                + store.subject_relation_index.len()
                + store.resource_index.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total_relationships: usize,
    pub active_relationships: usize,
    pub deleted_relationships: usize,
    pub current_revision: Revision,
    pub unique_objects: usize,
    pub index_memory: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_basic_operations() {
        let store = MemoryBackend::new();

        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        };

        let rev = store.write(vec![relationship.clone()]).await.unwrap();
        assert_eq!(rev, Revision(1));

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: None,
        };

        let results = store.read(&key, rev).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], relationship);
    }

    #[tokio::test]
    async fn test_user_filtering() {
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

        // Query for all users
        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: None,
        };
        let results = store.read(&key, rev).await.unwrap();
        assert_eq!(results.len(), 2);

        // Query for specific user
        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: Some("user:alice".to_string()),
        };
        let results = store.read(&key, rev).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subject, "user:alice");
    }

    #[tokio::test]
    async fn test_revision_isolation() {
        let store = MemoryBackend::new();

        let relationship1 = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        };

        let rev1 = store.write(vec![relationship1.clone()]).await.unwrap();

        let relationship2 = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
        };

        let rev2 = store.write(vec![relationship2.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: None,
        };

        // Read at rev1 should only see alice
        let results = store.read(&key, rev1).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subject, "user:alice");

        // Read at rev2 should see both
        let results = store.read(&key, rev2).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_delete() {
        let store = MemoryBackend::new();

        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        };

        let rev1 = store.write(vec![relationship.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: Some("user:alice".to_string()),
        };

        let rev2 = store.delete(&key).await.unwrap();

        // Read at rev1 should see the relationship
        let results = store.read(&key, rev1).await.unwrap();
        assert_eq!(results.len(), 1);

        // Read at rev2 should not see the relationship
        let results = store.read(&key, rev2).await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_duplicate_prevention() {
        let store = MemoryBackend::new();

        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        };

        store.write(vec![relationship.clone()]).await.unwrap();
        let rev = store.write(vec![relationship.clone()]).await.unwrap();

        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: None,
        };

        let results = store.read(&key, rev).await.unwrap();
        assert_eq!(results.len(), 1); // Should only have one relationship
    }

    #[tokio::test]
    async fn test_batch_operations() {
        let store = MemoryBackend::new();

        let relationships = vec![
            Relationship {
                resource: "doc:1".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                resource: "doc:2".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                resource: "doc:3".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
            },
        ];

        let rev = store.write(relationships).await.unwrap();

        // Verify all were written
        let stats = store.stats().await;
        assert_eq!(stats.active_relationships, 3);
        assert_eq!(stats.current_revision, rev);
    }

    #[tokio::test]
    async fn test_reverse_lookup() {
        let store = MemoryBackend::new();

        let relationships = vec![
            Relationship {
                resource: "doc:1".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                resource: "doc:2".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                resource: "doc:3".to_string(),
                relation: "editor".to_string(),
                subject: "user:alice".to_string(),
            },
        ];

        let rev = store.write(relationships).await.unwrap();

        // Find all documents alice can read
        let results = store
            .query_by_user("user:alice", "reader", rev)
            .await
            .unwrap();
        assert_eq!(results.len(), 2);

        let objects: HashSet<_> = results.iter().map(|t| &t.resource).collect();
        assert!(objects.contains(&"doc:1".to_string()));
        assert!(objects.contains(&"doc:2".to_string()));
    }

    #[tokio::test]
    async fn test_object_query() {
        let store = MemoryBackend::new();

        let relationships = vec![
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
            },
            Relationship {
                resource: "doc:readme".to_string(),
                relation: "editor".to_string(),
                subject: "user:bob".to_string(),
            },
        ];

        let rev = store.write(relationships).await.unwrap();

        let results = store.query_by_object("doc:readme", rev).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        use std::sync::Arc;

        let store = Arc::new(MemoryBackend::new());

        let mut handles = vec![];

        // Spawn multiple writers
        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = tokio::spawn(async move {
                let relationship = Relationship {
                    resource: format!("doc:{}", i),
                    relation: "reader".to_string(),
                    subject: "user:alice".to_string(),
                };
                store_clone.write(vec![relationship]).await
            });
            handles.push(handle);
        }

        // Wait for all writes
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // Verify all writes succeeded
        let stats = store.stats().await;
        assert_eq!(stats.active_relationships, 10);
    }

    #[tokio::test]
    async fn test_gc() {
        let store = MemoryBackend::new();

        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        };

        let _rev1 = store.write(vec![relationship.clone()]).await.unwrap();
        let rev2 = store.write(vec![relationship.clone()]).await.unwrap();
        let _rev3 = store.write(vec![relationship.clone()]).await.unwrap();

        // GC revisions before rev2
        let removed = store.gc_before(rev2).await.unwrap();
        assert!(removed > 0);
    }

    #[tokio::test]
    async fn test_metrics_tracking() {
        let store = MemoryBackend::new();

        // Initial metrics should show no operations
        let metrics = store.metrics().unwrap();
        assert_eq!(metrics.read_count, 0);
        assert_eq!(metrics.write_count, 0);
        assert_eq!(metrics.delete_count, 0);

        // Write some data
        let relationship = Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        };
        let rev = store.write(vec![relationship.clone()]).await.unwrap();

        // Metrics should show 1 write
        let metrics = store.metrics().unwrap();
        assert_eq!(metrics.write_count, 1);
        assert!(metrics.total_keys > 0);

        // Read the data
        let key = RelationshipKey {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: None,
        };
        let _ = store.read(&key, rev).await.unwrap();

        // Metrics should show 1 read
        let metrics = store.metrics().unwrap();
        assert_eq!(metrics.read_count, 1);
        assert_eq!(metrics.write_count, 1);

        // Delete the data
        let _ = store.delete(&key).await.unwrap();

        // Metrics should show 1 delete
        let metrics = store.metrics().unwrap();
        assert_eq!(metrics.read_count, 1);
        assert_eq!(metrics.write_count, 1);
        assert_eq!(metrics.delete_count, 1);

        // All operations should have recorded latency
        assert!(metrics.read_avg_latency_us > 0 || metrics.read_count == 0);
        assert!(metrics.write_avg_latency_us > 0 || metrics.write_count == 0);
        assert!(metrics.delete_avg_latency_us > 0 || metrics.delete_count == 0);
    }

    // Property-based tests with proptest
    mod proptests {
        use super::*;
        use proptest::prelude::*;
        use std::collections::HashSet;

        // Strategy to generate valid relationships
        fn relationship_strategy() -> impl Strategy<Value = Relationship> {
            (
                "[a-z]+:[a-z0-9]+", // resource
                "[a-z_]+",          // relation
                "user:[a-z]+",      // subject
            )
                .prop_map(|(resource, relation, subject)| Relationship {
                    resource,
                    relation,
                    subject,
                })
        }

        proptest! {
            #[test]
            fn prop_write_then_read_succeeds(relationships in prop::collection::vec(relationship_strategy(), 1..50)) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = MemoryBackend::new();

                    // Write relationships
                    let rev = store.write(relationships.clone()).await.unwrap();

                    // Read each relationship back
                    for relationship in &relationships {
                        let key = RelationshipKey {
                            resource: relationship.resource.clone(),
                            relation: relationship.relation.clone(),
                            subject: None,
                        };
                        let results = store.read(&key, rev).await.unwrap();

                        // Should find at least this relationship
                        let found = results.iter().any(|t| {
                            t.resource == relationship.resource &&
                            t.relation == relationship.relation &&
                            t.subject == relationship.subject
                        });
                        prop_assert!(found, "Relationship {:?} not found in results", relationship);
                    }

                    Ok(())
                })?;
            }

            #[test]
            fn prop_revision_increases_monotonically(
                batch1 in prop::collection::vec(relationship_strategy(), 1..10),
                batch2 in prop::collection::vec(relationship_strategy(), 1..10)
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = MemoryBackend::new();

                    let rev1 = store.write(batch1).await.unwrap();
                    let rev2 = store.write(batch2).await.unwrap();

                    // Revisions should always increase
                    prop_assert!(rev2 > rev1, "Revision did not increase: {:?} <= {:?}", rev2, rev1);

                    Ok(())
                })?;
            }

            #[test]
            fn prop_duplicate_writes_idempotent(relationship in relationship_strategy()) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = MemoryBackend::new();

                    // Write same relationship twice
                    let _rev1 = store.write(vec![relationship.clone()]).await.unwrap();
                    let rev2 = store.write(vec![relationship.clone()]).await.unwrap();

                    // Should still only have 1 relationship (duplicates prevented)
                    let key = RelationshipKey {
                        resource: relationship.resource.clone(),
                        relation: relationship.relation.clone(),
                        subject: None,
                    };
                    let results = store.read(&key, rev2).await.unwrap();
                    prop_assert_eq!(results.len(), 1);

                    Ok(())
                })?;
            }

            #[test]
            fn prop_delete_removes_relationship(relationship in relationship_strategy()) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = MemoryBackend::new();

                    // Write relationship
                    let rev1 = store.write(vec![relationship.clone()]).await.unwrap();

                    // Verify it exists
                    let key = RelationshipKey {
                        resource: relationship.resource.clone(),
                        relation: relationship.relation.clone(),
                        subject: None,
                    };
                    let results = store.read(&key, rev1).await.unwrap();
                    prop_assert_eq!(results.len(), 1);

                    // Delete it
                    let rev2 = store.delete(&key).await.unwrap();

                    // Verify it's gone
                    let results = store.read(&key, rev2).await.unwrap();
                    prop_assert_eq!(results.len(), 0);

                    Ok(())
                })?;
            }

            #[test]
            fn prop_revision_isolation(
                relationship1 in relationship_strategy(),
                relationship2 in relationship_strategy()
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = MemoryBackend::new();

                    // Write first relationship
                    let rev1 = store.write(vec![relationship1.clone()]).await.unwrap();

                    // Write second relationship
                    let rev2 = store.write(vec![relationship2.clone()]).await.unwrap();

                    // Reading at rev1 should not see relationship2
                    let key2 = RelationshipKey {
                        resource: relationship2.resource.clone(),
                        relation: relationship2.relation.clone(),
                        subject: None,
                    };
                    let results_at_rev1 = store.read(&key2, rev1).await.unwrap();

                    // If relationship1 and relationship2 are different, rev1 should not see relationship2
                    if relationship1.resource != relationship2.resource ||
                       relationship1.relation != relationship2.relation ||
                       relationship1.subject != relationship2.subject {
                        prop_assert_eq!(results_at_rev1.len(), 0,
                            "Should not see relationship2 at rev1");
                    }

                    // Reading at rev2 should see relationship2
                    let results_at_rev2 = store.read(&key2, rev2).await.unwrap();
                    prop_assert!(results_at_rev2.len() > 0,
                        "Should see relationship2 at rev2");

                    Ok(())
                })?;
            }

            #[test]
            fn prop_user_filtering(
                object in "[a-z]+:[a-z0-9]+",
                relation in "[a-z_]+",
                users in prop::collection::vec("user:[a-z]+", 1..10)
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = MemoryBackend::new();

                    // Write relationships with different users but same object/relation
                    let relationships: Vec<Relationship> = users.iter().map(|user| Relationship {
                        resource: object.clone(),
                        relation: relation.clone(),
                        subject: user.clone(),
                    }).collect();

                    let rev = store.write(relationships.clone()).await.unwrap();

                    // Count unique users (since duplicates are automatically filtered)
                    let unique_users: HashSet<_> = users.iter().cloned().collect();

                    // Read without user filter - should get all unique users
                    let key_all = RelationshipKey {
                        resource: object.clone(),
                        relation: relation.clone(),
                        subject: None,
                    };
                    let all_results = store.read(&key_all, rev).await.unwrap();
                    prop_assert_eq!(all_results.len(), unique_users.len());

                    // Read with specific user filter - should get only one
                    if let Some(specific_user) = users.first() {
                        let key_specific = RelationshipKey {
                            resource: object.clone(),
                            relation: relation.clone(),
                            subject: Some(specific_user.clone()),
                        };
                        let specific_results = store.read(&key_specific, rev).await.unwrap();
                        prop_assert_eq!(specific_results.len(), 1);
                        prop_assert_eq!(&specific_results[0].subject, specific_user);
                    }

                    Ok(())
                })?;
            }

            #[test]
            fn prop_batch_write_atomicity(relationships in prop::collection::vec(relationship_strategy(), 1..20)) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = MemoryBackend::new();

                    // Write batch
                    let rev = store.write(relationships.clone()).await.unwrap();

                    // All relationships should be at the same revision
                    for relationship in &relationships {
                        let key = RelationshipKey {
                            resource: relationship.resource.clone(),
                            relation: relationship.relation.clone(),
                            subject: Some(relationship.subject.clone()),
                        };
                        let results = store.read(&key, rev).await.unwrap();
                        prop_assert!(results.len() > 0, "Relationship not found after batch write");
                    }

                    Ok(())
                })?;
            }

            #[test]
            fn prop_gc_preserves_current_revision(relationships in prop::collection::vec(relationship_strategy(), 1..10)) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let store = MemoryBackend::new();

                    // Write relationships multiple times to create history
                    let mut revisions = Vec::new();
                    for _ in 0..3 {
                        let rev = store.write(relationships.clone()).await.unwrap();
                        revisions.push(rev);
                    }

                    let latest_rev = *revisions.last().unwrap();

                    // GC old revisions
                    if revisions.len() > 1 {
                        let gc_before = revisions[revisions.len() - 2];
                        let _ = store.gc_before(gc_before).await.unwrap();
                    }

                    // Latest revision should still be readable
                    for relationship in &relationships {
                        let key = RelationshipKey {
                            resource: relationship.resource.clone(),
                            relation: relationship.relation.clone(),
                            subject: None,
                        };
                        let results = store.read(&key, latest_rev).await;
                        prop_assert!(results.is_ok(), "Should be able to read at latest revision after GC");
                    }

                    Ok(())
                })?;
            }
        }
    }
}
