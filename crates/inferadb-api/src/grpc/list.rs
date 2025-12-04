//! gRPC list handlers - thin protocol adapters over service layer

use std::sync::Arc;

use inferadb_types::{
    AuthContext, ListRelationshipsRequest as CoreListRelationshipsRequest,
    ListResourcesRequest as CoreListResourcesRequest,
    ListSubjectsRequest as CoreListSubjectsRequest,
};
use tonic::{Request, Response, Status};

use super::{
    InferadbServiceImpl,
    proto::{
        ListRelationshipsRequest, ListRelationshipsResponse, ListResourcesRequest,
        ListResourcesResponse, ListSubjectsRequest, ListSubjectsResponse,
    },
};

/// Handles list resources requests
///
/// This is a thin protocol adapter that converts between gRPC proto format
/// and calls the ResourceService for business logic.
pub async fn list_resources(
    service: &InferadbServiceImpl,
    request: Request<ListResourcesRequest>,
) -> Result<
    Response<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<ListResourcesResponse, Status>> + Send + 'static>,
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

    // Convert proto to core type
    let list_request = CoreListResourcesRequest {
        subject: req.subject,
        resource_type: req.resource_type,
        permission: req.permission,
        limit: req.limit.map(|l| l as usize),
        cursor: req.cursor,
        resource_id_pattern: req.resource_id_pattern,
    };

    // Execute list using resource service
    let response = service
        .state
        .resource_service
        .list_resources(vault, list_request)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // Create stream of resources
    let resources = response.resources;
    let cursor = response.cursor;
    let total_count = response.total_count.map(|c| c as u64);

    // Stream each resource followed by a final message with metadata
    let stream = futures::stream::iter(
        resources
            .into_iter()
            .map(|resource| Ok(ListResourcesResponse { resource, cursor: None, total_count: None }))
            .chain(std::iter::once(Ok(ListResourcesResponse {
                resource: String::new(), // Empty resource in final message
                cursor,
                total_count,
            }))),
    );

    Ok(Response::new(Box::pin(stream)))
}

/// Handles list relationships requests
///
/// This is a thin protocol adapter that converts between gRPC proto format
/// and calls the RelationshipService for business logic.
pub async fn list_relationships(
    service: &InferadbServiceImpl,
    request: Request<ListRelationshipsRequest>,
) -> Result<
    Response<
        std::pin::Pin<
            Box<
                dyn futures::Stream<Item = Result<ListRelationshipsResponse, Status>>
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

    // Convert proto to core type (all filters are optional)
    let list_request = CoreListRelationshipsRequest {
        resource: req.resource,
        relation: req.relation,
        subject: req.subject,
        limit: req.limit.map(|l| l as usize),
        cursor: req.cursor,
    };

    // Execute list using relationship service
    let response = service
        .state
        .relationship_service
        .list_relationships(vault, list_request)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

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
                    relationship: Some(super::proto::Relationship {
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

/// Handles list subjects requests
///
/// This is a thin protocol adapter that converts between gRPC proto format
/// and calls the SubjectService for business logic.
pub async fn list_subjects(
    service: &InferadbServiceImpl,
    request: Request<ListSubjectsRequest>,
) -> Result<
    Response<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<ListSubjectsResponse, Status>> + Send + 'static>,
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

    // Convert proto to core type
    let list_request = CoreListSubjectsRequest {
        resource: req.resource,
        relation: req.relation,
        subject_type: req.subject_type,
        limit: req.limit.map(|l| l as usize),
        cursor: req.cursor,
    };

    // Execute list using subject service
    let response = service
        .state
        .subject_service
        .list_subjects(vault, list_request)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    // Create stream of subjects
    let subjects = response.subjects;
    let cursor = response.cursor;
    let total_count = response.total_count.map(|c| c as u64);

    // Stream each subject followed by a final message with metadata
    let stream = futures::stream::iter(
        subjects
            .into_iter()
            .map(|subject| Ok(ListSubjectsResponse { subject, cursor: None, total_count: None }))
            .chain(std::iter::once(Ok(ListSubjectsResponse {
                subject: String::new(), // Empty subject in final message
                cursor,
                total_count,
            }))),
    );

    Ok(Response::new(Box::pin(stream)))
}
