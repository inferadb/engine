//! gRPC watch handler - protocol adapter for watch functionality

use std::sync::Arc;

use futures::StreamExt;
use inferadb_engine_types::{AuthContext, Revision};
use tonic::{Request, Response, Status};

use super::{
    AuthorizationServiceImpl,
    proto::{ChangeOperation, WatchRequest, WatchResponse},
};

pub async fn watch(
    service: &AuthorizationServiceImpl,
    request: Request<WatchRequest>,
) -> Result<
    Response<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<WatchResponse, Status>> + Send + 'static>,
        >,
    >,
    Status,
> {
    // Extract vault from request extensions (set by auth middleware)
    let vault = request
        .extensions()
        .get::<Arc<AuthContext>>()
        .map(|ctx| ctx.vault)
        .ok_or_else(|| Status::unauthenticated("Authentication required"))?;

    let req = request.into_inner();

    // Parse cursor to get start revision
    let start_revision = if let Some(cursor) = &req.cursor {
        if cursor.is_empty() || cursor == "0" {
            Revision::zero()
        } else {
            use base64::{Engine as _, engine::general_purpose};
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
        service
            .state
            .store
            .get_change_log_revision(vault)
            .await
            .map_err(|e| Status::internal(format!("Failed to get current revision: {}", e)))?
    };

    // Use WatchService for the polling logic
    let change_stream =
        service.state.watch_service.watch_changes(vault, start_revision, req.resource_types);

    // Transform ChangeEvent stream to WatchResponse stream
    let stream = change_stream.map(|result| {
        result
            .map(|event| {
                let operation = match event.operation {
                    inferadb_engine_types::ChangeOperation::Create => ChangeOperation::Create,
                    inferadb_engine_types::ChangeOperation::Delete => ChangeOperation::Delete,
                };

                let timestamp = {
                    let secs = event.timestamp_nanos / 1_000_000_000;
                    let nanos = (event.timestamp_nanos % 1_000_000_000) as u32;
                    chrono::DateTime::from_timestamp(secs, nanos)
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
                };

                WatchResponse {
                    operation: operation as i32,
                    relationship: Some(super::proto::Relationship {
                        resource: event.relationship.resource.clone(),
                        relation: event.relationship.relation.clone(),
                        subject: event.relationship.subject.clone(),
                    }),
                    revision: event.revision.0.to_string(),
                    timestamp,
                }
            })
            .map_err(|e| Status::internal(e.to_string()))
    });

    Ok(Response::new(Box::pin(stream)))
}
