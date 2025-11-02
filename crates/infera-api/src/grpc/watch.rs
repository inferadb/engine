use std::sync::Arc;

use infera_types::Revision;
use tonic::{Request, Response, Status};

use super::{
    InferaServiceImpl, get_vault,
    proto::{ChangeOperation, WatchRequest, WatchResponse},
};

pub async fn watch(
    service: &InferaServiceImpl,
    request: Request<WatchRequest>,
) -> Result<
    Response<
        std::pin::Pin<
            Box<dyn futures::Stream<Item = Result<WatchResponse, Status>> + Send + 'static>,
        >,
    >,
    Status,
> {
    let req = request.into_inner();
    let store = Arc::clone(&service.state.store) as Arc<dyn infera_store::RelationshipStore>;

    // Parse cursor to get start revision
    let start_revision = if let Some(cursor) = &req.cursor {
        if cursor.is_empty() || cursor == "0" {
            Revision::zero()
        } else {
            // Decode base64 cursor
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
        // Start from current revision (won't get historical events)
        store
            .get_change_log_revision(get_vault())
            .await
            .map_err(|e| Status::internal(format!("Failed to get current revision: {}", e)))?
    };

    let resource_types = req.resource_types;

    // Create a stream that continuously polls for new changes
    let stream = async_stream::stream! {
        let mut last_revision = start_revision;

        loop {
            // Read changes from the change log
            match store.read_changes(get_vault(), last_revision, &resource_types, Some(100)).await {
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
                            relationship: Some(super::proto::Relationship {
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
