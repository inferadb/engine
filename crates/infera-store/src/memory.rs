//! In-memory storage backend for testing and development

use std::collections::{HashMap, HashSet, BTreeMap};
use std::sync::Arc;
use tokio::sync::RwLock;
use async_trait::async_trait;

use crate::{TupleStore, TupleKey, Tuple, Revision, Result, StoreError};

/// A versioned tuple with its creation revision
#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionedTuple {
    tuple: Tuple,
    created_at: Revision,
    deleted_at: Option<Revision>,
}

/// In-memory tuple store implementation with full indexing and revision support
pub struct MemoryBackend {
    data: Arc<RwLock<MemoryStore>>,
}

struct MemoryStore {
    /// Primary storage: all tuples with their version history
    tuples: Vec<VersionedTuple>,

    /// Index by (object, relation) for fast lookups
    object_relation_index: HashMap<(String, String), Vec<usize>>,

    /// Index by (user, relation) for reverse lookups
    user_relation_index: HashMap<(String, String), Vec<usize>>,

    /// Index by object for wildcard queries
    object_index: HashMap<String, Vec<usize>>,

    /// Current revision number
    revision: Revision,

    /// Revision history for garbage collection
    revision_history: BTreeMap<Revision, Vec<usize>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(MemoryStore {
                tuples: Vec::new(),
                object_relation_index: HashMap::new(),
                user_relation_index: HashMap::new(),
                object_index: HashMap::new(),
                revision: Revision::zero(),
                revision_history: BTreeMap::new(),
            })),
        }
    }

    /// Collect garbage for revisions older than the given revision
    pub async fn gc_before(&self, before: Revision) -> Result<usize> {
        let mut store = self.data.write().await;
        let mut removed = 0;

        // Remove old revisions from history
        let old_revisions: Vec<_> = store.revision_history
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
impl TupleStore for MemoryBackend {
    async fn read(&self, key: &TupleKey, revision: Revision) -> Result<Vec<Tuple>> {
        let store = self.data.read().await;

        // Find matching tuple indices
        let indices = if let Some(user) = &key.user {
            // Specific user query
            store.object_relation_index
                .get(&(key.object.clone(), key.relation.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| {
                    let vt = &store.tuples[idx];
                    vt.tuple.user == *user
                })
                .copied()
                .collect::<Vec<_>>()
        } else {
            // All users for this object+relation
            store.object_relation_index
                .get(&(key.object.clone(), key.relation.clone()))
                .cloned()
                .unwrap_or_default()
        };

        // Filter by revision and return tuples
        let tuples = indices
            .iter()
            .filter_map(|&idx| {
                let vt = &store.tuples[idx];
                // Include if created before or at revision and not deleted before or at revision
                if vt.created_at <= revision &&
                   (vt.deleted_at.is_none() || vt.deleted_at.unwrap() > revision) {
                    Some(vt.tuple.clone())
                } else {
                    None
                }
            })
            .collect();

        Ok(tuples)
    }

    async fn write(&self, tuples: Vec<Tuple>) -> Result<Revision> {
        let mut store = self.data.write().await;

        // Increment revision
        store.revision = store.revision.next();
        let current_revision = store.revision;

        let mut new_indices = Vec::new();

        for tuple in tuples {
            // Check for duplicates at current revision
            let key = (tuple.object.clone(), tuple.relation.clone());
            let existing_indices = store.object_relation_index
                .get(&key)
                .cloned()
                .unwrap_or_default();

            let is_duplicate = existing_indices.iter().any(|&idx| {
                let vt = &store.tuples[idx];
                vt.tuple.user == tuple.user &&
                vt.deleted_at.is_none()
            });

            if is_duplicate {
                // Skip duplicate tuple
                continue;
            }

            // Add new versioned tuple
            let idx = store.tuples.len();
            let versioned = VersionedTuple {
                tuple: tuple.clone(),
                created_at: current_revision,
                deleted_at: None,
            };

            store.tuples.push(versioned);
            new_indices.push(idx);

            // Update indices
            store.object_relation_index
                .entry(key.clone())
                .or_insert_with(Vec::new)
                .push(idx);

            store.user_relation_index
                .entry((tuple.user.clone(), tuple.relation.clone()))
                .or_insert_with(Vec::new)
                .push(idx);

            store.object_index
                .entry(tuple.object.clone())
                .or_insert_with(Vec::new)
                .push(idx);
        }

        // Track revision history
        store.revision_history.insert(current_revision, new_indices);

        Ok(current_revision)
    }

    async fn get_revision(&self) -> Result<Revision> {
        let store = self.data.read().await;
        Ok(store.revision)
    }

    async fn delete(&self, key: &TupleKey) -> Result<Revision> {
        let mut store = self.data.write().await;

        // Increment revision
        store.revision = store.revision.next();
        let current_revision = store.revision;

        // Find tuples to delete
        let indices = if let Some(user) = &key.user {
            // Delete specific user
            store.object_relation_index
                .get(&(key.object.clone(), key.relation.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| {
                    let vt = &store.tuples[idx];
                    vt.tuple.user == *user && vt.deleted_at.is_none()
                })
                .copied()
                .collect::<Vec<_>>()
        } else {
            // Delete all users for this object+relation
            store.object_relation_index
                .get(&(key.object.clone(), key.relation.clone()))
                .map(|v| v.as_slice())
                .unwrap_or(&[])
                .iter()
                .filter(|&&idx| store.tuples[idx].deleted_at.is_none())
                .copied()
                .collect::<Vec<_>>()
        };

        // Mark tuples as deleted
        for idx in indices {
            store.tuples[idx].deleted_at = Some(current_revision);
        }

        Ok(current_revision)
    }
}

/// Query patterns for advanced lookups
impl MemoryBackend {
    /// Query by user and relation (reverse lookup)
    pub async fn query_by_user(&self, user: &str, relation: &str, revision: Revision) -> Result<Vec<Tuple>> {
        let store = self.data.read().await;

        let indices = store.user_relation_index
            .get(&(user.to_string(), relation.to_string()))
            .cloned()
            .unwrap_or_default();

        let tuples = indices
            .iter()
            .filter_map(|&idx| {
                let vt = &store.tuples[idx];
                if vt.created_at <= revision &&
                   (vt.deleted_at.is_none() || vt.deleted_at.unwrap() > revision) {
                    Some(vt.tuple.clone())
                } else {
                    None
                }
            })
            .collect();

        Ok(tuples)
    }

    /// Query all relations for an object
    pub async fn query_by_object(&self, object: &str, revision: Revision) -> Result<Vec<Tuple>> {
        let store = self.data.read().await;

        let indices = store.object_index
            .get(object)
            .cloned()
            .unwrap_or_default();

        let tuples = indices
            .iter()
            .filter_map(|&idx| {
                let vt = &store.tuples[idx];
                if vt.created_at <= revision &&
                   (vt.deleted_at.is_none() || vt.deleted_at.unwrap() > revision) {
                    Some(vt.tuple.clone())
                } else {
                    None
                }
            })
            .collect();

        Ok(tuples)
    }

    /// Get all unique objects
    pub async fn get_objects(&self) -> Result<Vec<String>> {
        let store = self.data.read().await;
        Ok(store.object_index.keys().cloned().collect())
    }

    /// Get statistics about the store
    pub async fn stats(&self) -> MemoryStats {
        let store = self.data.read().await;

        let active_tuples = store.tuples
            .iter()
            .filter(|vt| vt.deleted_at.is_none())
            .count();

        MemoryStats {
            total_tuples: store.tuples.len(),
            active_tuples,
            deleted_tuples: store.tuples.len() - active_tuples,
            current_revision: store.revision,
            unique_objects: store.object_index.len(),
            index_memory: store.object_relation_index.len() +
                         store.user_relation_index.len() +
                         store.object_index.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total_tuples: usize,
    pub active_tuples: usize,
    pub deleted_tuples: usize,
    pub current_revision: Revision,
    pub unique_objects: usize,
    pub index_memory: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_operations() {
        let store = MemoryBackend::new();

        let tuple = Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:alice".to_string(),
        };

        let rev = store.write(vec![tuple.clone()]).await.unwrap();
        assert_eq!(rev, Revision(1));

        let key = TupleKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: None,
        };

        let results = store.read(&key, rev).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], tuple);
    }

    #[tokio::test]
    async fn test_user_filtering() {
        let store = MemoryBackend::new();

        let tuples = vec![
            Tuple {
                object: "doc:readme".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
            Tuple {
                object: "doc:readme".to_string(),
                relation: "reader".to_string(),
                user: "user:bob".to_string(),
            },
        ];

        let rev = store.write(tuples).await.unwrap();

        // Query for all users
        let key = TupleKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: None,
        };
        let results = store.read(&key, rev).await.unwrap();
        assert_eq!(results.len(), 2);

        // Query for specific user
        let key = TupleKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: Some("user:alice".to_string()),
        };
        let results = store.read(&key, rev).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].user, "user:alice");
    }

    #[tokio::test]
    async fn test_revision_isolation() {
        let store = MemoryBackend::new();

        let tuple1 = Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:alice".to_string(),
        };

        let rev1 = store.write(vec![tuple1.clone()]).await.unwrap();

        let tuple2 = Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:bob".to_string(),
        };

        let rev2 = store.write(vec![tuple2.clone()]).await.unwrap();

        let key = TupleKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: None,
        };

        // Read at rev1 should only see alice
        let results = store.read(&key, rev1).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].user, "user:alice");

        // Read at rev2 should see both
        let results = store.read(&key, rev2).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_delete() {
        let store = MemoryBackend::new();

        let tuple = Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:alice".to_string(),
        };

        let rev1 = store.write(vec![tuple.clone()]).await.unwrap();

        let key = TupleKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: Some("user:alice".to_string()),
        };

        let rev2 = store.delete(&key).await.unwrap();

        // Read at rev1 should see the tuple
        let results = store.read(&key, rev1).await.unwrap();
        assert_eq!(results.len(), 1);

        // Read at rev2 should not see the tuple
        let results = store.read(&key, rev2).await.unwrap();
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_duplicate_prevention() {
        let store = MemoryBackend::new();

        let tuple = Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:alice".to_string(),
        };

        store.write(vec![tuple.clone()]).await.unwrap();
        let rev = store.write(vec![tuple.clone()]).await.unwrap();

        let key = TupleKey {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: None,
        };

        let results = store.read(&key, rev).await.unwrap();
        assert_eq!(results.len(), 1); // Should only have one tuple
    }

    #[tokio::test]
    async fn test_batch_operations() {
        let store = MemoryBackend::new();

        let tuples = vec![
            Tuple {
                object: "doc:1".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
            Tuple {
                object: "doc:2".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
            Tuple {
                object: "doc:3".to_string(),
                relation: "reader".to_string(),
                user: "user:bob".to_string(),
            },
        ];

        let rev = store.write(tuples).await.unwrap();

        // Verify all were written
        let stats = store.stats().await;
        assert_eq!(stats.active_tuples, 3);
        assert_eq!(stats.current_revision, rev);
    }

    #[tokio::test]
    async fn test_reverse_lookup() {
        let store = MemoryBackend::new();

        let tuples = vec![
            Tuple {
                object: "doc:1".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
            Tuple {
                object: "doc:2".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
            Tuple {
                object: "doc:3".to_string(),
                relation: "editor".to_string(),
                user: "user:alice".to_string(),
            },
        ];

        let rev = store.write(tuples).await.unwrap();

        // Find all documents alice can read
        let results = store.query_by_user("user:alice", "reader", rev).await.unwrap();
        assert_eq!(results.len(), 2);

        let objects: HashSet<_> = results.iter().map(|t| &t.object).collect();
        assert!(objects.contains(&"doc:1".to_string()));
        assert!(objects.contains(&"doc:2".to_string()));
    }

    #[tokio::test]
    async fn test_object_query() {
        let store = MemoryBackend::new();

        let tuples = vec![
            Tuple {
                object: "doc:readme".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
            Tuple {
                object: "doc:readme".to_string(),
                relation: "editor".to_string(),
                user: "user:bob".to_string(),
            },
        ];

        let rev = store.write(tuples).await.unwrap();

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
                let tuple = Tuple {
                    object: format!("doc:{}", i),
                    relation: "reader".to_string(),
                    user: "user:alice".to_string(),
                };
                store_clone.write(vec![tuple]).await
            });
            handles.push(handle);
        }

        // Wait for all writes
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // Verify all writes succeeded
        let stats = store.stats().await;
        assert_eq!(stats.active_tuples, 10);
    }

    #[tokio::test]
    async fn test_gc() {
        let store = MemoryBackend::new();

        let tuple = Tuple {
            object: "doc:readme".to_string(),
            relation: "reader".to_string(),
            user: "user:alice".to_string(),
        };

        let rev1 = store.write(vec![tuple.clone()]).await.unwrap();
        let rev2 = store.write(vec![tuple.clone()]).await.unwrap();
        let _rev3 = store.write(vec![tuple.clone()]).await.unwrap();

        // GC revisions before rev2
        let removed = store.gc_before(rev2).await.unwrap();
        assert!(removed > 0);
    }
}
