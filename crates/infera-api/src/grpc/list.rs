use infera_types::{
    ListRelationshipsRequest as CoreListRelationshipsRequest,
    ListResourcesRequest as CoreListResourcesRequest,
    ListSubjectsRequest as CoreListSubjectsRequest,
};
use tonic::{Request, Response, Status};

use super::{
    InferaServiceImpl,
    proto::{
        ListRelationshipsRequest, ListRelationshipsResponse, ListResourcesRequest,
        ListResourcesResponse, ListSubjectsRequest, ListSubjectsResponse,
    },
};

pub async fn list_resources(
    service: &InferaServiceImpl,
    request: Request<ListResourcesRequest>,
) -> Result<
    Response<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<ListResourcesResponse, Status>> + Send + 'static>,
        >,
    >,
    Status,
> {
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
    let response = service
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
            .map(|resource| Ok(ListResourcesResponse { resource, cursor: None, total_count: None }))
            .chain(std::iter::once(Ok(ListResourcesResponse {
                resource: String::new(), // Empty resource in final message
                cursor,
                total_count,
            }))),
    );

    Ok(Response::new(Box::pin(stream)))
}

pub async fn list_relationships(
    service: &InferaServiceImpl,
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
    let response = service
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

pub async fn list_subjects(
    service: &InferaServiceImpl,
    request: Request<ListSubjectsRequest>,
) -> Result<
    Response<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<ListSubjectsResponse, Status>> + Send + 'static>,
        >,
    >,
    Status,
> {
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
    let response = service
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
            .map(|subject| Ok(ListSubjectsResponse { subject, cursor: None, total_count: None }))
            .chain(std::iter::once(Ok(ListSubjectsResponse {
                subject: String::new(), // Empty subject in final message
                cursor,
                total_count,
            }))),
    );

    Ok(Response::new(Box::pin(stream)))
}
