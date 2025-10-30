//! gRPC service implementation
//!
//! This module provides both server and client implementations for the InferaDB gRPC API.
//!
//! # Client Usage
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use infera_api::grpc::InferaServiceClient;
//! use infera_api::grpc::proto::{CheckRequest};
//!
//! // Connect to server
//! let mut client = InferaServiceClient::connect("http://localhost:8080").await?;
//!
//! // Make a check request
//! let request = tonic::Request::new(CheckRequest {
//!     subject: "user:alice".to_string(),
//!     resource: "doc:readme".to_string(),
//!     permission: "reader".to_string(),
//!     context: None,
//! });
//!
//! let response = client.check(request).await?;
//! println!("Decision: {:?}", response.into_inner().decision);
//! # Ok(())
//! # }
//! ```

use tonic::{Request, Response, Status};

use crate::AppState;
use infera_core::{
    CheckRequest as CoreCheckRequest, Decision, DecisionTrace, EvaluationNode,
    ExpandRequest as CoreExpandRequest, NodeType as CoreNodeType,
    UsersetNodeType as CoreUsersetNodeType, UsersetTree,
};

// Include generated proto code
pub mod proto {
    tonic::include_proto!("infera.v1");
}

// Re-export client for external use
pub use proto::infera_service_client::InferaServiceClient;

use proto::{
    infera_service_server::InferaService, CheckRequest, CheckResponse, CheckWithTraceResponse,
    Decision as ProtoDecision, DeleteRequest, DeleteResponse, ExpandRequest, ExpandResponse,
    HealthRequest, HealthResponse, WriteRequest, WriteResponse,
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
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let req = request.into_inner();

        let check_request = CoreCheckRequest {
            subject: req.subject,
            resource: req.resource,
            permission: req.permission,
            context: req.context.and_then(|s| serde_json::from_str(&s).ok()),
        };

        let decision = self
            .state
            .evaluator
            .check(check_request)
            .await
            .map_err(|e| Status::internal(format!("Evaluation error: {}", e)))?;

        let proto_decision = match decision {
            Decision::Allow => ProtoDecision::Allow,
            Decision::Deny => ProtoDecision::Deny,
        };

        Ok(Response::new(CheckResponse {
            decision: proto_decision as i32,
        }))
    }

    async fn check_with_trace(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckWithTraceResponse>, Status> {
        let req = request.into_inner();

        let check_request = CoreCheckRequest {
            subject: req.subject,
            resource: req.resource,
            permission: req.permission,
            context: req.context.and_then(|s| serde_json::from_str(&s).ok()),
        };

        let trace = self
            .state
            .evaluator
            .check_with_trace(check_request)
            .await
            .map_err(|e| Status::internal(format!("Evaluation error: {}", e)))?;

        let proto_decision = match trace.decision {
            Decision::Allow => ProtoDecision::Allow,
            Decision::Deny => ProtoDecision::Deny,
        };

        let proto_trace = convert_trace_to_proto(trace);

        Ok(Response::new(CheckWithTraceResponse {
            decision: proto_decision as i32,
            trace: Some(proto_trace),
        }))
    }

    async fn expand(
        &self,
        request: Request<ExpandRequest>,
    ) -> Result<Response<ExpandResponse>, Status> {
        let req = request.into_inner();

        let expand_request = CoreExpandRequest {
            resource: req.resource,
            relation: req.relation,
            limit: None,
            continuation_token: None,
        };

        let expand_response = self
            .state
            .evaluator
            .expand(expand_request)
            .await
            .map_err(|e| Status::internal(format!("Evaluation error: {}", e)))?;

        let proto_tree = convert_userset_tree_to_proto(expand_response.tree);

        Ok(Response::new(ExpandResponse {
            tree: Some(proto_tree),
        }))
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
    ) -> Result<Response<WriteResponse>, Status> {
        let req = request.into_inner();

        if req.tuples.is_empty() {
            return Err(Status::invalid_argument("No tuples provided"));
        }

        let tuples: Vec<infera_store::Tuple> = req
            .tuples
            .into_iter()
            .map(|t| infera_store::Tuple {
                object: t.object,
                relation: t.relation,
                user: t.user,
            })
            .collect();

        // Validate tuple format
        for tuple in &tuples {
            if tuple.object.is_empty() {
                return Err(Status::invalid_argument("Tuple object cannot be empty"));
            }
            if tuple.relation.is_empty() {
                return Err(Status::invalid_argument("Tuple relation cannot be empty"));
            }
            if tuple.user.is_empty() {
                return Err(Status::invalid_argument("Tuple user cannot be empty"));
            }
            if !tuple.object.contains(':') {
                return Err(Status::invalid_argument(format!(
                    "Invalid object format '{}': must be 'type:id'",
                    tuple.object
                )));
            }
            if !tuple.user.contains(':') {
                return Err(Status::invalid_argument(format!(
                    "Invalid user format '{}': must be 'type:id'",
                    tuple.user
                )));
            }
        }

        let tuples_count = tuples.len();

        let revision = self
            .state
            .store
            .write(tuples)
            .await
            .map_err(|e| Status::internal(format!("Failed to write tuples: {}", e)))?;

        Ok(Response::new(WriteResponse {
            revision: revision.0.to_string(),
            tuples_written: tuples_count as u64,
        }))
    }

    async fn delete(
        &self,
        request: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let req = request.into_inner();

        if req.tuples.is_empty() {
            return Err(Status::invalid_argument("No tuples provided"));
        }

        let tuples_count = req.tuples.len();

        // Delete each tuple individually
        let mut last_revision = infera_store::Revision::zero();
        for tuple in req.tuples {
            let key = infera_store::TupleKey {
                object: tuple.object,
                relation: tuple.relation,
                user: Some(tuple.user),
            };
            last_revision = self
                .state
                .store
                .delete(&key)
                .await
                .map_err(|e| Status::internal(format!("Failed to delete tuple: {}", e)))?;
        }

        Ok(Response::new(DeleteResponse {
            revision: last_revision.0.to_string(),
            tuples_deleted: tuples_count as u64,
        }))
    }

    type ExpandStreamStream = std::pin::Pin<
        Box<
            dyn futures::Stream<Item = Result<proto::ExpandStreamResponse, Status>>
                + Send
                + 'static,
        >,
    >;

    async fn expand_stream(
        &self,
        request: Request<ExpandRequest>,
    ) -> Result<Response<Self::ExpandStreamStream>, Status> {
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
                    Ok(proto::ExpandStreamResponse {
                        payload: Some(proto::expand_stream_response::Payload::User(user)),
                    })
                })
                .chain(std::iter::once(Ok(proto::ExpandStreamResponse {
                    payload: Some(proto::expand_stream_response::Payload::Summary(
                        proto::ExpandStreamSummary {
                            tree: Some(tree),
                            total_users,
                        },
                    )),
                }))),
        );

        Ok(Response::new(Box::pin(stream)))
    }

    async fn write_stream(
        &self,
        request: Request<tonic::Streaming<WriteRequest>>,
    ) -> Result<Response<WriteResponse>, Status> {
        use futures::StreamExt;

        let mut stream = request.into_inner();
        let mut all_tuples = Vec::new();

        // Collect all tuples from the stream
        while let Some(write_req) = stream.next().await {
            let write_req = write_req?;
            for tuple in write_req.tuples {
                all_tuples.push(infera_store::Tuple {
                    object: tuple.object,
                    relation: tuple.relation,
                    user: tuple.user,
                });
            }
        }

        if all_tuples.is_empty() {
            return Err(Status::invalid_argument("No tuples provided"));
        }

        // Write all tuples in a batch
        let revision = self
            .state
            .store
            .write(all_tuples.clone())
            .await
            .map_err(|e| Status::internal(format!("Write failed: {}", e)))?;

        Ok(Response::new(WriteResponse {
            revision: revision.0.to_string(),
            tuples_written: all_tuples.len() as u64,
        }))
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
                object,
                relation,
                user,
            } => Some(proto::node_type::Type::DirectCheck(proto::DirectCheck {
                object,
                relation,
                user,
            })),
            CoreNodeType::ComputedUserset { relation, tupleset } => {
                Some(proto::node_type::Type::ComputedUserset(
                    proto::ComputedUserset { relation, tupleset },
                ))
            }
            CoreNodeType::TupleToUserset { tupleset, computed } => {
                Some(proto::node_type::Type::TupleToUserset(
                    proto::TupleToUserset { tupleset, computed },
                ))
            }
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
        tuples_read: trace.tuples_read as u64,
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
        CoreUsersetNodeType::TupleToUserset { tupleset, computed } => {
            Some(Type::TupleToUserset(proto::TupleToUsersetRef {
                tupleset,
                computed,
            }))
        }
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
    use infera_store::{MemoryBackend, TupleStore};
    use std::sync::Arc;

    fn create_test_state() -> AppState {
        let store: Arc<dyn TupleStore> = Arc::new(MemoryBackend::new());
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

        AppState {
            evaluator,
            store,
            config,
            jwks_cache: None,
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

    #[tokio::test]
    async fn test_grpc_check_deny() {
        let service = InferaServiceImpl::new(create_test_state());
        let request = Request::new(CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        });

        let response = service.check(request).await.unwrap();
        let check_response = response.into_inner();

        assert_eq!(check_response.decision, ProtoDecision::Deny as i32);
    }

    #[tokio::test]
    async fn test_grpc_write_and_check() {
        let state = create_test_state();
        let service = InferaServiceImpl::new(state);

        // Write a tuple
        let write_request = Request::new(WriteRequest {
            tuples: vec![proto::Tuple {
                object: "doc:readme".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            }],
        });

        let write_response = service.write(write_request).await.unwrap();
        let write_result = write_response.into_inner();
        assert_eq!(write_result.tuples_written, 1);

        // Check permission
        let check_request = Request::new(CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        });

        let check_response = service.check(check_request).await.unwrap();
        let check_result = check_response.into_inner();
        assert_eq!(check_result.decision, ProtoDecision::Allow as i32);
    }

    #[tokio::test]
    async fn test_grpc_expand() {
        let service = InferaServiceImpl::new(create_test_state());
        let request = Request::new(ExpandRequest {
            resource: "doc:readme".to_string(),
            relation: "editor".to_string(),
        });

        let response = service.expand(request).await.unwrap();
        let expand_response = response.into_inner();

        assert!(expand_response.tree.is_some());
    }

    #[tokio::test]
    async fn test_grpc_write_validation_empty_tuples() {
        let service = InferaServiceImpl::new(create_test_state());
        let request = Request::new(WriteRequest { tuples: vec![] });

        let result = service.write(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_grpc_write_validation_invalid_object_format() {
        let service = InferaServiceImpl::new(create_test_state());
        let request = Request::new(WriteRequest {
            tuples: vec![proto::Tuple {
                object: "invalid".to_string(), // Missing colon
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            }],
        });

        let result = service.write(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn test_grpc_check_with_trace() {
        let state = create_test_state();
        let service = InferaServiceImpl::new(state);

        let request = Request::new(CheckRequest {
            subject: "user:alice".to_string(),
            resource: "doc:readme".to_string(),
            permission: "reader".to_string(),
            context: None,
        });

        let response = service.check_with_trace(request).await.unwrap();
        let result = response.into_inner();

        assert_eq!(result.decision, ProtoDecision::Deny as i32);
        assert!(result.trace.is_some());

        let trace = result.trace.unwrap();
        assert!(trace.root.is_some());
        assert!(trace.duration_micros > 0);
    }
}
