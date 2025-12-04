//! gRPC expand handler - thin protocol adapter over ExpansionService

use std::sync::Arc;

use inferadb_types::{
    AuthContext, ExpandRequest as CoreExpandRequest, UsersetNodeType as CoreUsersetNodeType,
    UsersetTree,
};
use tonic::{Request, Response, Status};

use super::{InferadbServiceImpl, proto::ExpandRequest};

pub async fn expand(
    service: &InferadbServiceImpl,
    request: Request<ExpandRequest>,
) -> Result<
    Response<
        std::pin::Pin<
            Box<
                dyn futures::Stream<Item = Result<super::proto::ExpandResponse, Status>>
                    + Send
                    + 'static,
            >,
        >,
    >,
    Status,
> {
    // Extract vault from request extensions (set by auth middleware)
    let vault = request
        .extensions()
        .get::<Arc<AuthContext>>()
        .map(|ctx| ctx.vault)
        .unwrap_or(service.state.default_vault);

    let req = request.into_inner();

    let expand_request = CoreExpandRequest {
        resource: req.resource,
        relation: req.relation,
        limit: None,
        continuation_token: None,
    };

    // Execute expansion using expansion service
    let response = service
        .state
        .expansion_service
        .expand(vault, expand_request)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // Convert tree to proto
    let tree = convert_userset_tree_to_proto(response.tree);
    let users = response.users;
    let total_users = users.len() as u64;

    // Create stream of users followed by summary
    let stream = futures::stream::iter(
        users
            .into_iter()
            .map(|user| {
                Ok(super::proto::ExpandResponse {
                    payload: Some(super::proto::expand_response::Payload::User(user)),
                })
            })
            .chain(std::iter::once(Ok(super::proto::ExpandResponse {
                payload: Some(super::proto::expand_response::Payload::Summary(
                    super::proto::ExpandStreamSummary { tree: Some(tree), total_users },
                )),
            }))),
    );

    Ok(Response::new(Box::pin(stream)))
}

// Helper function to convert UsersetTree to proto
fn convert_userset_tree_to_proto(tree: UsersetTree) -> super::proto::UsersetTree {
    use super::proto::{UsersetNodeType, userset_node_type::Type};

    let node_type = match tree.node_type {
        CoreUsersetNodeType::This => Some(Type::This(super::proto::This {})),
        CoreUsersetNodeType::ComputedUserset { relation } => {
            Some(Type::ComputedUserset(super::proto::ComputedUsersetRef { relation }))
        },
        CoreUsersetNodeType::RelatedObjectUserset { relationship, computed } => {
            Some(Type::RelatedObjectUserset(super::proto::RelatedObjectUsersetRef {
                relationship,
                computed,
            }))
        },
        CoreUsersetNodeType::Union => Some(Type::Union(super::proto::UnionNode {})),
        CoreUsersetNodeType::Intersection => {
            Some(Type::Intersection(super::proto::IntersectionNode {}))
        },
        CoreUsersetNodeType::Exclusion => Some(Type::Exclusion(super::proto::ExclusionNode {})),
        CoreUsersetNodeType::Leaf { users } => Some(Type::Leaf(super::proto::Leaf { users })),
    };

    super::proto::UsersetTree {
        node_type: Some(UsersetNodeType { r#type: node_type }),
        children: tree.children.into_iter().map(convert_userset_tree_to_proto).collect(),
    }
}
