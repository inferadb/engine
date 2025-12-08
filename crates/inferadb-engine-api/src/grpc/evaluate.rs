//! gRPC evaluate handler - thin protocol adapter over EvaluationService

use std::sync::Arc;

use inferadb_engine_core::DecisionTrace;
use inferadb_engine_types::{AuthContext, Decision, EvaluateRequest as CoreEvaluateRequest};
use tonic::{Request, Response, Status};

use super::{
    InferadbServiceImpl,
    proto::{Decision as ProtoDecision, EvaluateRequest, EvaluateResponse},
};

/// Handles bidirectional streaming evaluation requests
///
/// This is a thin protocol adapter that converts between gRPC proto format
/// and calls the EvaluationService for business logic.
pub async fn evaluate(
    service: &InferadbServiceImpl,
    request: Request<tonic::Streaming<EvaluateRequest>>,
) -> Result<
    Response<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<EvaluateResponse, Status>> + Send + 'static>,
        >,
    >,
    Status,
> {
    use futures::StreamExt;

    // Extract vault from request extensions (set by auth middleware)
    // Authentication is always required
    let vault = request
        .extensions()
        .get::<Arc<AuthContext>>()
        .map(|ctx| ctx.vault)
        .ok_or_else(|| Status::unauthenticated("Authentication required"))?;

    let mut stream = request.into_inner();
    let evaluation_service = service.state.evaluation_service.clone();

    // Process each check request in the stream
    let output_stream = async_stream::stream! {
        let mut index = 0u32;
        while let Some(check_req) = stream.next().await {
            match check_req {
                Ok(req) => {
                    // Convert proto to core type
                    let evaluate_request = CoreEvaluateRequest {
                        subject: req.subject.clone(),
                        resource: req.resource.clone(),
                        permission: req.permission.clone(),
                        context: req.context.and_then(|s| serde_json::from_str(&s).ok()),
                        trace: None,
                    };

                    // Check if trace is requested
                    let trace_requested = req.trace.unwrap_or(false);

                    if trace_requested {
                        // Use evaluation service with trace
                        match evaluation_service.evaluate_with_trace(vault, evaluate_request).await {
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
                                // Return validation/evaluation errors in response
                                yield Ok(EvaluateResponse {
                                    decision: ProtoDecision::Deny as i32,
                                    index,
                                    error: Some(e.to_string()),
                                    trace: None,
                                });
                            }
                        }
                    } else {
                        // Regular evaluation without trace
                        match evaluation_service.evaluate(vault, evaluate_request).await {
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
                                // Return validation/evaluation errors in response
                                yield Ok(EvaluateResponse {
                                    decision: ProtoDecision::Deny as i32,
                                    index,
                                    error: Some(e.to_string()),
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

/// Helper function to convert DecisionTrace to proto format
fn convert_trace_to_proto(trace: DecisionTrace) -> super::proto::DecisionTrace {
    use inferadb_engine_core::{EvaluationNode, NodeType as CoreNodeType};

    fn convert_node(node: EvaluationNode) -> super::proto::EvaluationNode {
        let node_type = match node.node_type {
            CoreNodeType::DirectCheck { resource, relation, subject } => {
                Some(super::proto::node_type::Type::DirectCheck(super::proto::DirectCheck {
                    resource,
                    relation,
                    subject,
                }))
            },
            CoreNodeType::ComputedUserset { relation, relationship } => {
                Some(super::proto::node_type::Type::ComputedUserset(
                    super::proto::ComputedUserset { relation, relationship },
                ))
            },
            CoreNodeType::RelatedObjectUserset { relationship, computed } => {
                Some(super::proto::node_type::Type::RelatedObjectUserset(
                    super::proto::RelatedObjectUserset { relationship, computed },
                ))
            },
            CoreNodeType::Union => {
                Some(super::proto::node_type::Type::Union(super::proto::Union {}))
            },
            CoreNodeType::Intersection => {
                Some(super::proto::node_type::Type::Intersection(super::proto::Intersection {}))
            },
            CoreNodeType::Exclusion => {
                Some(super::proto::node_type::Type::Exclusion(super::proto::Exclusion {}))
            },
            CoreNodeType::WasmModule { module_name } => {
                Some(super::proto::node_type::Type::WasmModule(super::proto::WasmModule {
                    module_name,
                }))
            },
        };

        super::proto::EvaluationNode {
            node_type: Some(super::proto::NodeType { r#type: node_type }),
            result: node.result,
            children: node.children.into_iter().map(convert_node).collect(),
        }
    }

    let proto_decision = match trace.decision {
        Decision::Allow => ProtoDecision::Allow,
        Decision::Deny => ProtoDecision::Deny,
    };

    super::proto::DecisionTrace {
        decision: proto_decision as i32,
        root: Some(convert_node(trace.root)),
        duration_micros: trace.duration.as_micros() as u64,
        relationships_read: trace.relationships_read as u64,
        relations_evaluated: trace.relations_evaluated as u64,
    }
}
