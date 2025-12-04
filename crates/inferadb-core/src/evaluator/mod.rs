//! Policy evaluation engine

use std::{sync::Arc, time::Instant};

use inferadb_cache::{AuthCache, CheckCacheKey};
use inferadb_const::{DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT};
use inferadb_store::RelationshipStore;
use inferadb_types::{
    Decision, EvaluateRequest, ExpandRequest, ExpandResponse, ListRelationshipsRequest,
    ListRelationshipsResponse, ListResourcesRequest, ListResourcesResponse, ListSubjectsRequest,
    ListSubjectsResponse, Relationship, Revision, UsersetNodeType, UsersetTree,
};
use inferadb_wasm::WasmHost;
use tracing::{debug, instrument};

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
    /// (Extracted from auth context at the API handler level)
    vault: i64,
}

impl Evaluator {
    pub fn new(
        store: Arc<dyn RelationshipStore>,
        schema: Arc<Schema>,
        wasm_host: Option<Arc<WasmHost>>,
        vault: i64,
    ) -> Self {
        Self { store, schema, wasm_host, cache: Some(Arc::new(AuthCache::default())), vault }
    }

    pub fn new_with_cache(
        store: Arc<dyn RelationshipStore>,
        schema: Arc<Schema>,
        wasm_host: Option<Arc<WasmHost>>,
        cache: Option<Arc<AuthCache>>,
        vault: i64,
    ) -> Self {
        Self { store, schema, wasm_host, cache, vault }
    }

    /// Get a reference to the cache for manual invalidation
    ///
    /// Returns Some(&Arc<AuthCache>) if caching is enabled, None otherwise.
    /// This is used by API handlers to invalidate cache entries after writes.
    pub fn cache(&self) -> Option<&Arc<AuthCache>> {
        self.cache.as_ref()
    }
}

// Method implementations organized by functionality
mod check;
mod expand;
mod list;

impl Evaluator {
    /// Get the WASM host (if configured)
    pub fn wasm_host(&self) -> Option<&Arc<WasmHost>> {
        self.wasm_host.as_ref()
    }

    /// Get the schema
    pub fn schema(&self) -> &Arc<Schema> {
        &self.schema
    }
}

#[cfg(test)]
#[path = "../evaluator_tests.rs"]
mod tests;
