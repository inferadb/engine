//! Service layer for InferaDB API
//!
//! This module contains the business logic layer that sits between protocol handlers
//! (gRPC, REST, AuthZEN) and the core evaluation engine. Services handle:
//!
//! - Vault-scoped evaluator creation for multi-tenant isolation
//! - Request validation
//! - Business logic execution
//! - Protocol-agnostic error handling
//!
//! Protocol handlers are thin adapters that convert between protocol-specific formats
//! and call the appropriate service methods.

use std::sync::Arc;

use inferadb_engine_cache::AuthCache;
use inferadb_engine_core::{Evaluator, ipl::Schema};
use inferadb_engine_store::RelationshipStore;
use inferadb_engine_wasm::WasmHost;

pub mod evaluation;
pub mod expansion;
pub mod relationships;
pub mod resources;
pub mod subjects;
pub mod validation;
pub mod watch;

pub use evaluation::EvaluationService;
pub use expansion::ExpansionService;
pub use relationships::RelationshipService;
pub use resources::ResourceService;
pub use subjects::SubjectService;
pub use watch::WatchService;

/// Shared context for all authorization services
///
/// This struct holds the dependencies shared across all service types
/// (evaluation, expansion, resources, subjects, relationships). Using a shared
/// context reduces duplication and ensures consistent configuration across services.
///
/// # Example
///
/// ```no_run
/// use std::sync::Arc;
/// use inferadb_engine_api::services::{ServiceContext, EvaluationService};
///
/// let context = Arc::new(ServiceContext::builder()
///     .store(store)
///     .schema(schema)
///     .build());
///
/// let evaluation_service = EvaluationService::new(Arc::clone(&context));
/// let expansion_service = ExpansionService::new(Arc::clone(&context));
/// ```
#[derive(bon::Builder)]
pub struct ServiceContext {
    /// Storage backend for relationships
    pub store: Arc<dyn RelationshipStore>,
    /// IPL schema defining types and relations
    pub schema: Arc<Schema>,
    /// Optional WASM host for custom policy functions
    pub wasm_host: Option<Arc<WasmHost>>,
    /// Optional cache for authorization decisions
    pub cache: Option<Arc<AuthCache>>,
}

impl ServiceContext {
    /// Creates a vault-scoped evaluator for multi-tenant isolation
    ///
    /// Each vault gets its own evaluator instance to ensure complete isolation
    /// of authorization data and decisions between tenants.
    pub fn create_evaluator(&self, vault: i64) -> Arc<Evaluator> {
        Arc::new(Evaluator::new_with_cache(
            Arc::clone(&self.store),
            Arc::clone(&self.schema),
            self.wasm_host.clone(),
            self.cache.clone(),
            vault,
        ))
    }
}
