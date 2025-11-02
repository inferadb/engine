use infera_types::{DeleteFilter as CoreDeleteFilter, Relationship, RelationshipKey, Revision};
use tonic::{Request, Response, Status};

use super::{
    InferaServiceImpl, get_vault,
    proto::{DeleteRequest, DeleteResponse, WriteRequest, WriteResponse},
};

pub async fn write_relationships(
    service: &InferaServiceImpl,
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
                vault: get_vault(),
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
            return Err(Status::invalid_argument("Relationship resource cannot be empty"));
        }
        if relationship.relation.is_empty() {
            return Err(Status::invalid_argument("Relationship relation cannot be empty"));
        }
        if relationship.subject.is_empty() {
            return Err(Status::invalid_argument("Relationship subject cannot be empty"));
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
    let revision = service
        .state
        .store
        .write(get_vault(), all_relationships.clone())
        .await
        .map_err(|e| Status::internal(format!("Write failed: {}", e)))?;

    Ok(Response::new(WriteResponse {
        revision: revision.0.to_string(),
        relationships_written: all_relationships.len() as u64,
    }))
}

pub async fn delete_relationships(
    service: &InferaServiceImpl,
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
        let (revision, count) = service
            .state
            .store
            .delete_by_filter(get_vault(), &filter, limit)
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

        last_revision = service
            .state
            .store
            .delete(get_vault(), &key)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete relationship: {}", e)))?;

        total_deleted += 1;
    }

    Ok(Response::new(DeleteResponse {
        revision: last_revision.0.to_string(),
        relationships_deleted: total_deleted as u64,
    }))
}
