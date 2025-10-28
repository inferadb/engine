//! In-memory storage backend for testing

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use async_trait::async_trait;

use crate::{TupleStore, TupleKey, Tuple, Revision, Result, StoreError};

/// In-memory tuple store implementation
pub struct MemoryBackend {
    data: Arc<RwLock<MemoryStore>>,
}

struct MemoryStore {
    tuples: HashMap<TupleKey, Vec<Tuple>>,
    revision: Revision,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(MemoryStore {
                tuples: HashMap::new(),
                revision: Revision::zero(),
            })),
        }
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TupleStore for MemoryBackend {
    async fn read(&self, key: &TupleKey, _revision: Revision) -> Result<Vec<Tuple>> {
        let store = self.data.read().await;

        // For simplicity, ignore user filter in key for now
        let search_key = TupleKey {
            object: key.object.clone(),
            relation: key.relation.clone(),
            user: None,
        };

        Ok(store.tuples.get(&search_key).cloned().unwrap_or_default())
    }

    async fn write(&self, tuples: Vec<Tuple>) -> Result<Revision> {
        let mut store = self.data.write().await;

        for tuple in tuples {
            let key = TupleKey {
                object: tuple.object.clone(),
                relation: tuple.relation.clone(),
                user: None,
            };

            store.tuples.entry(key).or_insert_with(Vec::new).push(tuple);
        }

        store.revision = store.revision.next();
        Ok(store.revision)
    }

    async fn get_revision(&self) -> Result<Revision> {
        let store = self.data.read().await;
        Ok(store.revision)
    }

    async fn delete(&self, key: &TupleKey) -> Result<Revision> {
        let mut store = self.data.write().await;

        let search_key = TupleKey {
            object: key.object.clone(),
            relation: key.relation.clone(),
            user: None,
        };

        store.tuples.remove(&search_key);
        store.revision = store.revision.next();
        Ok(store.revision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_backend() {
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
}
