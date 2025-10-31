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

use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::AppState;
use infera_core::{DecisionTrace, EvaluationNode, NodeType as CoreNodeType};
use infera_types::{
    Decision, DeleteFilter as CoreDeleteFilter, EvaluateRequest as CoreEvaluateRequest,
    ExpandRequest as CoreExpandRequest, ListRelationshipsRequest as CoreListRelationshipsRequest,
    ListResourcesRequest as CoreListResourcesRequest,
    ListSubjectsRequest as CoreListSubjectsRequest, Relationship, RelationshipKey, Revision,
    UsersetNodeType as CoreUsersetNodeType, UsersetTree,
};

// Include generated proto code
pub mod proto {
    tonic::include_proto!("infera.v1");
}

// Re-export client for external use
pub use proto::infera_service_client::InferaServiceClient;

use proto::{
    infera_service_server::InferaService, ChangeOperation, Decision as ProtoDecision,
    DeleteRequest, DeleteResponse, EvaluateRequest, EvaluateResponse, ExpandRequest, HealthRequest,
    HealthResponse, ListRelationshipsRequest, ListRelationshipsResponse, ListResourcesRequest,
    ListResourcesResponse, ListSubjectsRequest, ListSubjectsResponse, WatchRequest, WatchResponse,
    WriteRequest, WriteResponse,
};

pub struct InferaServiceImpl {
    state: AppState,
}

impl InferaServiceImpl {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl InferaService for InferaServiceImpl {
    type EvaluateStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<EvaluateResponse, Status>> + Send + 'static>,
    >;

    async fn evaluate(
        &self,
        request: Request<tonic::Streaming<EvaluateRequest>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        use futures::StreamExt;

        let mut stream = request.into_inner();
        let evaluator = self.state.evaluator.clone();

        // Process each check request in the stream
        let output_stream = async_stream::stream! {
            let mut index = 0u32;
            while let Some(check_req) = stream.next().await {
                match check_req {
                    Ok(req) => {
                        // Validate request
                        if req.subject.is_empty() {
                            yield Err(Status::invalid_argument("Subject cannot be empty"));
                            continue;
                        }
                        if req.resource.is_empty() {
                            yield Err(Status::invalid_argument("Resource cannot be empty"));
                            continue;
                        }
                        if req.permission.is_empty() {
                            yield Err(Status::invalid_argument("Permission cannot be empty"));
                            continue;
                        }

                        let evaluate_request = CoreEvaluateRequest {
                            subject: req.subject.clone(),
                            resource: req.resource.clone(),
                            permission: req.permission.clone(),
                            context: req.context.and_then(|s| serde_json::from_str(&s).ok()),
                            trace: None,
                        };

                        // Check if trace is requested
                        let trace = req.trace.unwrap_or(false);

                        if trace {
                            // Use check_with_trace for detailed evaluation trace
                            match evaluator.check_with_trace(evaluate_request).await {
                                Ok(trace_result) => {
                                    let proto_decision = match trace_result.decision {
                                        Decision::Allow => ProtoDecision::Allow,
                                        Decision::Deny => ProtoDecision::Deny,
                                    };

                                    let proto_trace = convert_trace_to_proto(trace_result);

                                    yield Ok(EvaluateResponse {
                                        decision: proto_decision as i32,
                                        index,
                                        error: None,
                                        trace: Some(proto_trace),
                                    });
                                }
                                Err(e) => {
                                    yield Ok(EvaluateResponse {
                                        decision: ProtoDecision::Deny as i32,
                                        index,
                                        error: Some(format!("Evaluation error: {}", e)),
                                        trace: None,
                                    });
                                }
                            }
                        } else {
                            // Regular evaluation without trace
                            match evaluator.check(evaluate_request).await {
                                Ok(decision) => {
                                    let proto_decision = match decision {
                                        Decision::Allow => ProtoDecision::Allow,
                                        Decision::Deny => ProtoDecision::Deny,
                                    };

                                    yield Ok(EvaluateResponse {
                                        decision: proto_decision as i32,
                                        index,
                                        error: None,
                                        trace: None,
                                    });
                                }
                                Err(e) => {
                                    // Return error in response rather than failing the stream
                                    yield Ok(EvaluateResponse {
                                        decision: ProtoDecision::Deny as i32,
                                        index,
                                        error: Some(format!("Evaluation error: {}", e)),
                                        trace: None,
                                    });
                                }
                            }
                        }

                        index += 1;
                    }
                    Err(status) => {
                        yield Err(status);
                        break;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(output_stream)))
    }

    type ExpandStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<proto::ExpandResponse, Status>> + Send + 'static>,
    >;

    async fn expand(
        &self,
        request: Request<ExpandRequest>,
    ) -> Result<Response<Self::ExpandStream>, Status> {
        let req = request.into_inner();

        let expand_request = CoreExpandRequest {
            resource: req.resource,
            relation: req.relation,
            limit: None,
            continuation_token: None,
        };

        // Execute expansion
        let response = self
            .state
            .evaluator
            .expand(expand_request)
            .await
            .map_err(|e| Status::internal(format!("Expansion failed: {}", e)))?;

        // Convert tree to proto
        let tree = convert_userset_tree_to_proto(response.tree);
        let users = response.users;
        let total_users = users.len() as u64;

        // Create stream of users followed by summary
        let stream = futures::stream::iter(
            users
                .into_iter()
                .map(|user| {
                    Ok(proto::ExpandResponse {
                        payload: Some(proto::expand_response::Payload::User(user)),
                    })
                })
                .chain(std::iter::once(Ok(proto::ExpandResponse {
                    payload: Some(proto::expand_response::Payload::Summary(
                        proto::ExpandStreamSummary {
                            tree: Some(tree),
                            total_users,
                        },
                    )),
                }))),
        );

        Ok(Response::new(Box::pin(stream)))
    }

    async fn delete_relationships(
        &self,
        request: Request<tonic::Streaming<DeleteRequest>>,
    ) -> Result<Response<DeleteResponse>, Status> {
        use futures::StreamExt;

        let mut stream = request.into_inner();
        let mut all_filters = Vec::new();
        let mut all_relationships = Vec::new();
        let mut limit_override: Option<Option<u32>> = None;

        // Collect all deletion requests from the stream
        while let Some(delete_req) = stream.next().await {
            let delete_req = delete_req?;

            // Collect filter if provided
            if let Some(filter) = delete_req.filter {
                all_filters.push(filter);
            }

            // Collect relationships if provided
            for relationship in delete_req.relationships {
                all_relationships.push(relationship);
            }

            // Take the last limit value if specified
            if delete_req.limit.is_some() {
                limit_override = Some(delete_req.limit);
            }
        }

        // Validate that at least one deletion method is specified
        if all_filters.is_empty() && all_relationships.is_empty() {
            return Err(Status::invalid_argument(
                "Must provide either filter or relationships to delete",
            ));
        }

        let mut total_deleted = 0;
        let mut last_revision = Revision::zero();

        // Handle filter-based deletion for each filter
        for proto_filter in all_filters {
            // Convert proto filter to core filter
            let filter = CoreDeleteFilter {
                resource: proto_filter.resource,
                relation: proto_filter.relation,
                subject: proto_filter.subject,
            };

            // Validate filter is not empty
            if filter.is_empty() {
                return Err(Status::invalid_argument(
                    "Filter must have at least one field set to avoid deleting all relationships",
                ));
            }

            // Apply default limit of 1000 if not specified, 0 means unlimited
            let limit = match limit_override.flatten() {
                Some(0) => None,             // 0 means unlimited
                Some(n) => Some(n as usize), // Explicit limit
                None => Some(1000),          // Default limit
            };

            // Perform batch deletion
            let (revision, count) = self
                .state
                .store
                .delete_by_filter(&filter, limit)
                .await
                .map_err(|e| Status::internal(format!("Failed to delete by filter: {}", e)))?;

            last_revision = revision;
            total_deleted += count;
        }

        // Handle exact relationship deletion
        for relationship in all_relationships {
            // Validate relationship format
            if relationship.resource.is_empty() {
                return Err(Status::invalid_argument("Resource cannot be empty"));
            }
            if relationship.relation.is_empty() {
                return Err(Status::invalid_argument("Relation cannot be empty"));
            }
            if relationship.subject.is_empty() {
                return Err(Status::invalid_argument("Subject cannot be empty"));
            }

            let key = RelationshipKey {
                resource: relationship.resource,
                relation: relationship.relation,
                subject: Some(relationship.subject),
            };

            last_revision =
                self.state.store.delete(&key).await.map_err(|e| {
                    Status::internal(format!("Failed to delete relationship: {}", e))
                })?;

            total_deleted += 1;
        }

        Ok(Response::new(DeleteResponse {
            revision: last_revision.0.to_string(),
            relationships_deleted: total_deleted as u64,
        }))
    }

    async fn write_relationships(
        &self,
        request: Request<tonic::Streaming<WriteRequest>>,
    ) -> Result<Response<WriteResponse>, Status> {
        use futures::StreamExt;

        let mut stream = request.into_inner();
        let mut all_relationships = Vec::new();

        // Collect all relationships from the stream
        while let Some(write_req) = stream.next().await {
            let write_req = write_req?;
            for relationship in write_req.relationships {
                all_relationships.push(Relationship {
                    resource: relationship.resource,
                    relation: relationship.relation,
                    subject: relationship.subject,
                });
            }
        }

        if all_relationships.is_empty() {
            return Err(Status::invalid_argument("No relationships provided"));
        }

        // Validate relationship format
        for relationship in &all_relationships {
            if relationship.resource.is_empty() {
                return Err(Status::invalid_argument(
                    "Relationship resource cannot be empty",
                ));
            }
            if relationship.relation.is_empty() {
                return Err(Status::invalid_argument(
                    "Relationship relation cannot be empty",
                ));
            }
            if relationship.subject.is_empty() {
                return Err(Status::invalid_argument(
                    "Relationship subject cannot be empty",
                ));
            }
            if !relationship.resource.contains(':') {
                return Err(Status::invalid_argument(format!(
                    "Invalid object format '{}': must be 'type:id'",
                    relationship.resource
                )));
            }
            if !relationship.subject.contains(':') {
                return Err(Status::invalid_argument(format!(
                    "Invalid user format '{}': must be 'type:id'",
                    relationship.subject
                )));
            }
            // Validate wildcard placement (wildcards only allowed in subject position as "type:*")
            if let Err(err) = relationship.validate_wildcard_placement() {
                return Err(Status::invalid_argument(err));
            }
        }

        // Write all relationships in a batch
        let revision = self
            .state
            .store
            .write(all_relationships.clone())
            .await
            .map_err(|e| Status::internal(format!("Write failed: {}", e)))?;

        Ok(Response::new(WriteResponse {
            revision: revision.0.to_string(),
            relationships_written: all_relationships.len() as u64,
        }))
    }

    type ListResourcesStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<ListResourcesResponse, Status>> + Send + 'static>,
    >;

    async fn list_resources(
        &self,
        request: Request<ListResourcesRequest>,
    ) -> Result<Response<Self::ListResourcesStream>, Status> {
        let req = request.into_inner();

        // Validate request
        if req.subject.is_empty() {
            return Err(Status::invalid_argument("Subject cannot be empty"));
        }
        if req.resource_type.is_empty() {
            return Err(Status::invalid_argument("Resource type cannot be empty"));
        }
        if req.permission.is_empty() {
            return Err(Status::invalid_argument("Permission cannot be empty"));
        }

        let list_request = CoreListResourcesRequest {
            subject: req.subject,
            resource_type: req.resource_type,
            permission: req.permission,
            limit: req.limit.map(|l| l as usize),
            cursor: req.cursor,
            resource_id_pattern: req.resource_id_pattern,
        };

        // Execute list
        let response = self
            .state
            .evaluator
            .list_resources(list_request)
            .await
            .map_err(|e| Status::internal(format!("List failed: {}", e)))?;

        // Create stream of resources
        let resources = response.resources;
        let cursor = response.cursor;
        let total_count = response.total_count.map(|c| c as u64);

        // Stream each resource followed by a final message with metadata
        let stream = futures::stream::iter(
            resources
                .into_iter()
                .map(|resource| {
                    Ok(ListResourcesResponse {
                        resource,
                        cursor: None,
                        total_count: None,
                    })
                })
                .chain(std::iter::once(Ok(ListResourcesResponse {
                    resource: String::new(), // Empty resource in final message
                    cursor,
                    total_count,
                }))),
        );

        Ok(Response::new(Box::pin(stream)))
    }

    type ListRelationshipsStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<ListRelationshipsResponse, Status>> + Send + 'static>,
    >;

    async fn list_relationships(
        &self,
        request: Request<ListRelationshipsRequest>,
    ) -> Result<Response<Self::ListRelationshipsStream>, Status> {
        let req = request.into_inner();

        // Build core request (all filters are optional)
        let list_request = CoreListRelationshipsRequest {
            resource: req.resource,
            relation: req.relation,
            subject: req.subject,
            limit: req.limit.map(|l| l as usize),
            cursor: req.cursor,
        };

        // Execute list
        let response = self
            .state
            .evaluator
            .list_relationships(list_request)
            .await
            .map_err(|e| Status::internal(format!("List relationships failed: {}", e)))?;

        // Create stream of relationships
        let relationships = response.relationships;
        let cursor = response.cursor;
        let total_count = response.total_count.map(|c| c as u64);

        // Stream each relationship followed by a final message with metadata
        let stream = futures::stream::iter(
            relationships
                .into_iter()
                .map(|rel| {
                    Ok(ListRelationshipsResponse {
                        relationship: Some(proto::Relationship {
                            resource: rel.resource,
                            relation: rel.relation,
                            subject: rel.subject,
                        }),
                        cursor: None,
                        total_count: None,
                    })
                })
                .chain(std::iter::once(Ok(ListRelationshipsResponse {
                    relationship: None, // No relationship in final message
                    cursor,
                    total_count,
                }))),
        );

        Ok(Response::new(Box::pin(stream)))
    }

    type ListSubjectsStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<ListSubjectsResponse, Status>> + Send + 'static>,
    >;

    type WatchStream = std::pin::Pin<
        Box<dyn futures::Stream<Item = Result<WatchResponse, Status>> + Send + 'static>,
    >;

    async fn list_subjects(
        &self,
        request: Request<ListSubjectsRequest>,
    ) -> Result<Response<Self::ListSubjectsStream>, Status> {
        let req = request.into_inner();

        // Build core request
        let list_request = CoreListSubjectsRequest {
            resource: req.resource,
            relation: req.relation,
            subject_type: req.subject_type,
            limit: req.limit.map(|l| l as usize),
            cursor: req.cursor,
        };

        // Execute list
        let response = self
            .state
            .evaluator
            .list_subjects(list_request)
            .await
            .map_err(|e| Status::internal(format!("List subjects failed: {}", e)))?;

        // Create stream of subjects
        let subjects = response.subjects;
        let cursor = response.cursor;
        let total_count = response.total_count.map(|c| c as u64);

        // Stream each subject followed by a final message with metadata
        let stream = futures::stream::iter(
            subjects
                .into_iter()
                .map(|subject| {
                    Ok(ListSubjectsResponse {
                        subject,
                        cursor: None,
                        total_count: None,
                    })
                })
                .chain(std::iter::once(Ok(ListSubjectsResponse {
                    subject: String::new(), // Empty subject in final message
                    cursor,
                    total_count,
                }))),
        );

        Ok(Response::new(Box::pin(stream)))
    }

    async fn watch(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let req = request.into_inner();
        let store = Arc::clone(&self.state.store);

        // Parse cursor to get start revision
        let start_revision = if let Some(cursor) = &req.cursor {
            if cursor.is_empty() || cursor == "0" {
                Revision::zero()
            } else {
                // Decode base64 cursor
                use base64::{engine::general_purpose, Engine as _};
                let decoded = general_purpose::STANDARD
                    .decode(cursor)
                    .map_err(|e| Status::invalid_argument(format!("Invalid cursor: {}", e)))?;
                let rev_str = String::from_utf8(decoded)
                    .map_err(|e| Status::invalid_argument(format!("Invalid cursor: {}", e)))?;
                let rev_num: u64 = rev_str
                    .parse()
                    .map_err(|e| Status::invalid_argument(format!("Invalid cursor: {}", e)))?;
                Revision(rev_num)
            }
        } else {
            // Start from current revision (won't get historical events)
            store
                .get_change_log_revision()
                .await
                .map_err(|e| Status::internal(format!("Failed to get current revision: {}", e)))?
        };

        let resource_types = req.resource_types;

        // Create a stream that continuously polls for new changes
        let stream = async_stream::stream! {
            let mut last_revision = start_revision;

            loop {
                // Read changes from the change log
                match store.read_changes(last_revision, &resource_types, Some(100)).await {
                    Ok(events) => {
                        for event in &events {
                            // Convert ChangeEvent to WatchResponse
                            let operation = match event.operation {
                                infera_types::ChangeOperation::Create => ChangeOperation::Create,
                                infera_types::ChangeOperation::Delete => ChangeOperation::Delete,
                            };

                            // Format timestamp as ISO 8601
                            let timestamp = {
                                let secs = event.timestamp_nanos / 1_000_000_000;
                                let nanos = (event.timestamp_nanos % 1_000_000_000) as u32;
                                chrono::DateTime::from_timestamp(secs, nanos)
                                    .map(|dt| dt.to_rfc3339())
                                    .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
                            };

                            let response = WatchResponse {
                                operation: operation as i32,
                                relationship: Some(proto::Relationship {
                                    resource: event.relationship.resource.clone(),
                                    relation: event.relationship.relation.clone(),
                                    subject: event.relationship.subject.clone(),
                                }),
                                revision: event.revision.0.to_string(),
                                timestamp,
                            };

                            last_revision = event.revision.next();
                            yield Ok(response);
                        }

                        // If no events, wait a bit before polling again
                        if events.is_empty() {
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        }
                    }
                    Err(e) => {
                        yield Err(Status::internal(format!("Failed to read changes: {}", e)));
                        break;
                    }
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "healthy".to_string(),
            service: "inferadb".to_string(),
        }))
    }
}

// Helper function to convert DecisionTrace to proto
fn convert_trace_to_proto(trace: DecisionTrace) -> proto::DecisionTrace {
    fn convert_node(node: EvaluationNode) -> proto::EvaluationNode {
        let node_type = match node.node_type {
            CoreNodeType::DirectCheck {
                resource,
                relation,
                subject,
            } => Some(proto::node_type::Type::DirectCheck(proto::DirectCheck {
                resource,
                relation,
                subject,
            })),
            CoreNodeType::ComputedUserset {
                relation,
                relationship,
            } => Some(proto::node_type::Type::ComputedUserset(
                proto::ComputedUserset {
                    relation,
                    relationship,
                },
            )),
            CoreNodeType::RelatedObjectUserset {
                relationship,
                computed,
            } => Some(proto::node_type::Type::RelatedObjectUserset(
                proto::RelatedObjectUserset {
                    relationship,
                    computed,
                },
            )),
            CoreNodeType::Union => Some(proto::node_type::Type::Union(proto::Union {})),
            CoreNodeType::Intersection => {
                Some(proto::node_type::Type::Intersection(proto::Intersection {}))
            }
            CoreNodeType::Exclusion => Some(proto::node_type::Type::Exclusion(proto::Exclusion {})),
            CoreNodeType::WasmModule { module_name } => {
                Some(proto::node_type::Type::WasmModule(proto::WasmModule {
                    module_name,
                }))
            }
        };

        proto::EvaluationNode {
            node_type: Some(proto::NodeType { r#type: node_type }),
            result: node.result,
            children: node.children.into_iter().map(convert_node).collect(),
        }
    }

    let proto_decision = match trace.decision {
        Decision::Allow => ProtoDecision::Allow,
        Decision::Deny => ProtoDecision::Deny,
    };

    proto::DecisionTrace {
        decision: proto_decision as i32,
        root: Some(convert_node(trace.root)),
        duration_micros: trace.duration.as_micros() as u64,
        relationships_read: trace.relationships_read as u64,
        relations_evaluated: trace.relations_evaluated as u64,
    }
}

// Helper function to convert UsersetTree to proto
fn convert_userset_tree_to_proto(tree: UsersetTree) -> proto::UsersetTree {
    use proto::{userset_node_type::Type, UsersetNodeType};

    let node_type = match tree.node_type {
        CoreUsersetNodeType::This => Some(Type::This(proto::This {})),
        CoreUsersetNodeType::ComputedUserset { relation } => {
            Some(Type::ComputedUserset(proto::ComputedUsersetRef {
                relation,
            }))
        }
        CoreUsersetNodeType::RelatedObjectUserset {
            relationship,
            computed,
        } => Some(Type::RelatedObjectUserset(proto::RelatedObjectUsersetRef {
            relationship,
            computed,
        })),
        CoreUsersetNodeType::Union => Some(Type::Union(proto::UnionNode {})),
        CoreUsersetNodeType::Intersection => Some(Type::Intersection(proto::IntersectionNode {})),
        CoreUsersetNodeType::Exclusion => Some(Type::Exclusion(proto::ExclusionNode {})),
        CoreUsersetNodeType::Leaf { users } => Some(Type::Leaf(proto::Leaf { users })),
    };

    proto::UsersetTree {
        node_type: Some(UsersetNodeType { r#type: node_type }),
        children: tree
            .children
            .into_iter()
            .map(convert_userset_tree_to_proto)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use infera_config::Config;
    use infera_core::{
        ipl::{RelationDef, RelationExpr, Schema, TypeDef},
        Evaluator,
    };
    use infera_store::{MemoryBackend, RelationshipStore};
    use std::sync::Arc;

    fn create_test_state() -> AppState {
        let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());
        let schema = Arc::new(Schema::new(vec![TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("reader".to_string(), None),
                RelationDef::new(
                    "editor".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef {
                            relation: "reader".to_string(),
                        },
                    ])),
                ),
            ],
        )]));
        let evaluator = Arc::new(Evaluator::new(Arc::clone(&store), schema, None));
        let config = Arc::new(Config::default());

        let health_tracker = Arc::new(crate::health::HealthTracker::new());
        health_tracker.set_ready(true);
        health_tracker.set_startup_complete(true);

        AppState {
            evaluator,
            store,
            config,
            jwks_cache: None,
            health_tracker,
        }
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
