//! gRPC service implementation
//!
//! This module provides both server and client implementations for the InferaDB gRPC API.
//!
//! # Client Usage
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use infera_api::grpc::InferaServiceClient;
//! use infera_api::grpc::proto::{EvaluateRequest};
//! use futures::StreamExt;
//!
//! // Connect to server
//! let mut client = InferaServiceClient::connect("http://localhost:8080").await?;
//!
//! // Make an evaluate request (evaluate is a bidirectional streaming RPC)
//! let request = EvaluateRequest {
//!     subject: "user:alice".to_string(),
//!     resource: "doc:readme".to_string(),
//!     permission: "reader".to_string(),
//!     context: None,
//!     trace: None,
//! };
//!
//! // Create a stream with the request
//! let stream = futures::stream::once(async { request });
//! let request = tonic::Request::new(stream);
//!
//! // Send the request and get the response stream
//! let mut response_stream = client.evaluate(request).await?.into_inner();
//!
//! // Read the first response from the stream
//! if let Some(response) = response_stream.next().await {
//!     let response = response?;
//!     println!("Decision: {:?}", response.decision);
//! }
//! # Ok(())
//! # }
//! ```

use tonic::{Request, Response, Status};

use crate::AppState;

// Include generated proto code
pub mod proto {
    tonic::include_proto!("infera.v1");
}

// Re-export client for external use
pub use proto::infera_service_client::InferaServiceClient;
use proto::{
    DeleteRequest, DeleteResponse, EvaluateRequest, EvaluateResponse, ExpandRequest, HealthRequest,
    HealthResponse, ListRelationshipsRequest, ListRelationshipsResponse, ListResourcesRequest,
    ListResourcesResponse, ListSubjectsRequest, ListSubjectsResponse, SimulateRequest,
    SimulateResponse, WatchRequest, WatchResponse, WriteRequest, WriteResponse,
    infera_service_server::InferaService,
};

/// Get the vault ID for the current request
/// TODO(Phase 2): Extract this from authentication context (JWT token)
/// For Phase 1, we use 0 as a placeholder for the default vault
pub(crate) fn get_vault() -> i64 {
    0
}

pub struct InferaServiceImpl {
    state: AppState,
}

impl InferaServiceImpl {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

// Submodules
mod evaluate;
mod expand;
mod health;
mod list;
mod relationships;
mod simulate;
mod watch;

#[tonic::async_trait]
impl InferaService for InferaServiceImpl {
    type EvaluateStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<EvaluateResponse, Status>> + Send + 'static>,
    >;

    async fn evaluate(
        &self,
        request: Request<tonic::Streaming<EvaluateRequest>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        evaluate::evaluate(self, request).await
    }

    type ExpandStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<proto::ExpandResponse, Status>> + Send + 'static>,
    >;

    async fn expand(
        &self,
        request: Request<ExpandRequest>,
    ) -> Result<Response<Self::ExpandStream>, Status> {
        expand::expand(self, request).await
    }

    async fn delete_relationships(
        &self,
        request: Request<tonic::Streaming<DeleteRequest>>,
    ) -> Result<Response<DeleteResponse>, Status> {
        relationships::delete_relationships(self, request).await
    }

    async fn write_relationships(
        &self,
        request: Request<tonic::Streaming<WriteRequest>>,
    ) -> Result<Response<WriteResponse>, Status> {
        relationships::write_relationships(self, request).await
    }

    type ListResourcesStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<ListResourcesResponse, Status>> + Send + 'static>,
    >;

    async fn list_resources(
        &self,
        request: Request<ListResourcesRequest>,
    ) -> Result<Response<Self::ListResourcesStream>, Status> {
        list::list_resources(self, request).await
    }

    type ListRelationshipsStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<ListRelationshipsResponse, Status>> + Send + 'static>,
    >;

    async fn list_relationships(
        &self,
        request: Request<ListRelationshipsRequest>,
    ) -> Result<Response<Self::ListRelationshipsStream>, Status> {
        list::list_relationships(self, request).await
    }

    type ListSubjectsStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<ListSubjectsResponse, Status>> + Send + 'static>,
    >;

    async fn list_subjects(
        &self,
        request: Request<ListSubjectsRequest>,
    ) -> Result<Response<Self::ListSubjectsStream>, Status> {
        list::list_subjects(self, request).await
    }

    type WatchStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<WatchResponse, Status>> + Send + 'static>,
    >;

    async fn watch(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        watch::watch(self, request).await
    }

    async fn health(
        &self,
        request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        health::health(self, request).await
    }

    async fn simulate(
        &self,
        request: Request<SimulateRequest>,
    ) -> Result<Response<SimulateResponse>, Status> {
        simulate::simulate(self, request).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use infera_config::Config;
    use infera_core::ipl::{RelationDef, RelationExpr, Schema, TypeDef};
    use infera_store::MemoryBackend;

    use super::*;

    fn create_test_state() -> AppState {
        let store: Arc<dyn infera_store::InferaStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new(
                    "editor".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "reader".to_string() },
                    ])),
                ),
            ],
        )]));
        // Use a test vault ID
        let test_vault = 1i64;
        let config = Arc::new(Config::default());

        let state = AppState::new(
            store, schema, None, // No WASM host for tests
            config, None, // No JWKS cache for tests
            test_vault, 0i64,
        );

        // Set health tracker state for tests
        state.health_tracker.set_ready(true);
        state.health_tracker.set_startup_complete(true);

        state
    }

    #[tokio::test]
    async fn test_grpc_health() {
        let service = InferaServiceImpl::new(create_test_state());
        let request = Request::new(HealthRequest {});

        let response = service.health(request).await.unwrap();
        let health = response.into_inner();

        assert_eq!(health.status, "healthy");
        assert_eq!(health.service, "inferadb");
    }

    // NOTE: gRPC streaming Evaluate tests are complex to mock and are instead
    // tested via integration tests and REST API tests (which provide equivalent coverage).
    // The REST API tests in lib.rs thoroughly test both single and batch evaluate functionality.

    // NOTE: gRPC streaming Expand tests are complex to mock and are instead
    // tested via integration tests and REST API tests (which provide equivalent coverage).
    // The REST API test in lib.rs tests the streaming expand functionality.

    // NOTE: Evaluate with trace functionality is now integrated into the unified Evaluate API
    // via the trace flag. Trace testing is covered by REST API tests which
    // provide equivalent coverage.
}
