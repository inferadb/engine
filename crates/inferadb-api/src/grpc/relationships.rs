//! gRPC relationship handlers - thin protocol adapters over RelationshipService

use std::sync::Arc;

use inferadb_types::{AuthContext, DeleteFilter as CoreDeleteFilter, Relationship, Revision};
use tonic::{Request, Response, Status};

use super::{
    InferadbServiceImpl,
    proto::{DeleteRequest, DeleteResponse, WriteRequest, WriteResponse},
};

/// Handles client streaming write requests for relationships
///
/// This is a thin protocol adapter that converts between gRPC proto format
/// and calls the RelationshipService for business logic.
pub async fn write_relationships(
    service: &InferadbServiceImpl,
    request: Request<tonic::Streaming<WriteRequest>>,
) -> Result<Response<WriteResponse>, Status> {
    use futures::StreamExt;

    // Extract vault from request extensions (set by auth middleware)
    // Authentication is always required
    let vault = request
        .extensions()
        .get::<Arc<AuthContext>>()
        .map(|ctx| ctx.vault)
        .ok_or_else(|| Status::unauthenticated("Authentication required"))?;

    let mut stream = request.into_inner();
    let mut all_relationships = Vec::new();

    // Collect all relationships from the stream
    while let Some(write_req) = stream.next().await {
        let write_req = write_req?;
        for relationship in write_req.relationships {
            all_relationships.push(Relationship {
                vault,
                resource: relationship.resource,
                relation: relationship.relation,
                subject: relationship.subject,
            });
        }
    }

    // Write using relationship service (handles validation)
    let revision = service
        .state
        .relationship_service
        .write_relationships(vault, all_relationships.clone())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Response::new(WriteResponse {
        revision: revision.0.to_string(),
        relationships_written: all_relationships.len() as u64,
    }))
}

/// Handles client streaming delete requests for relationships
///
/// This is a thin protocol adapter that converts between gRPC proto format
/// and calls the RelationshipService for business logic.
pub async fn delete_relationships(
    service: &InferadbServiceImpl,
    request: Request<tonic::Streaming<DeleteRequest>>,
) -> Result<Response<DeleteResponse>, Status> {
    use futures::StreamExt;

    // Extract vault from request extensions (set by auth middleware)
    // Authentication is always required
    let vault = request
        .extensions()
        .get::<Arc<AuthContext>>()
        .map(|ctx| ctx.vault)
        .ok_or_else(|| Status::unauthenticated("Authentication required"))?;

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

        // Apply default limit of 1000 if not specified, 0 means unlimited
        let limit = match limit_override.flatten() {
            Some(0) => None,             // 0 means unlimited
            Some(n) => Some(n as usize), // Explicit limit
            None => Some(1000),          // Default limit
        };

        // Delete using relationship service (handles validation)
        let response = service
            .state
            .relationship_service
            .delete_relationships(vault, filter, limit)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        last_revision = response.revision;
        total_deleted += response.relationships_deleted;
    }

    // Handle exact relationship deletion by converting to exact filters
    for relationship in all_relationships {
        // Create exact filter for this relationship (all three fields specified)
        let filter = CoreDeleteFilter {
            resource: Some(relationship.resource),
            relation: Some(relationship.relation),
            subject: Some(relationship.subject),
        };

        // Delete using relationship service (limit 1 for exact match)
        let response = service
            .state
            .relationship_service
            .delete_relationships(vault, filter, Some(1))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        last_revision = response.revision;
        total_deleted += response.relationships_deleted;
    }

    Ok(Response::new(DeleteResponse {
        revision: last_revision.0.to_string(),
        relationships_deleted: total_deleted as u64,
    }))
}
