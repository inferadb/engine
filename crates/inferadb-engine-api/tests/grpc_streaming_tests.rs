//! Integration tests for gRPC streaming operations
//!
//! These tests verify streaming functionality:
//! - ExpandStream: streaming expand results
//! - WriteStream: streaming write operations
//! - Watch: streaming change events

use std::sync::Arc;

use base64::Engine;
use futures::StreamExt;
use inferadb_engine_api::{
    AppState,
    grpc::{
        AuthorizationServiceImpl,
        proto::{
            DeleteRelationshipsRequest, ExpandRequest, Relationship as ProtoRelationship,
            WriteRelationshipsRequest, authorization_service_client::AuthorizationServiceClient,
            authorization_service_server::AuthorizationServiceServer, expand_response,
        },
    },
};
use inferadb_engine_config::Config;
use inferadb_engine_core::ipl::{RelationDef, Schema, TypeDef};
use inferadb_engine_repository::EngineStorage;
use inferadb_engine_types::{AuthContext, AuthMethod};
use inferadb_storage::MemoryBackend;
use tonic::{Request, Status, transport::Server};

/// Test interceptor that injects a mock AuthContext for all requests
#[derive(Clone)]
struct TestAuthInterceptor {
    auth_ctx: Arc<AuthContext>,
}

impl TestAuthInterceptor {
    fn new() -> Self {
        let auth_ctx = AuthContext {
            client_id: "test_client".to_string(),
            key_id: "test_key".to_string(),
            auth_method: AuthMethod::PrivateKeyJwt,
            scopes: vec![
                "inferadb.admin".to_string(),
                "inferadb.check".to_string(),
                "inferadb.write".to_string(),
                "inferadb.expand".to_string(),
                "inferadb.list".to_string(),
                "inferadb.watch".to_string(),
            ],
            issued_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            jti: Some("test_jti".to_string()),
            vault: 12345678901234,        // Test vault ID
            organization: 98765432109876, // Test organization ID
        };
        Self { auth_ctx: Arc::new(auth_ctx) }
    }
}

impl tonic::service::Interceptor for TestAuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request.extensions_mut().insert(self.auth_ctx.clone());
        Ok(request)
    }
}

async fn setup_test_server() -> (AuthorizationServiceClient<tonic::transport::Channel>, String) {
    let store: Arc<dyn inferadb_engine_store::InferaStore> =
        Arc::new(EngineStorage::builder().backend(MemoryBackend::new()).build());
    let schema = Arc::new(Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![RelationDef::new("reader".to_string(), None)],
    )]));
    let config = Config::default();

    let state = AppState::builder().store(store).schema(schema).config(Arc::new(config)).build();

    let health_tracker = state.health_tracker.clone();
    health_tracker.set_ready(true);
    health_tracker.set_startup_complete(true);

    let service = AuthorizationServiceImpl::new(state);
    let interceptor = TestAuthInterceptor::new();

    // Find available port
    let port = portpicker::pick_unused_port().expect("No free ports");
    let addr = format!("127.0.0.1:{}", port);
    let addr_clone = addr.clone();

    // Start gRPC server in background with auth interceptor
    tokio::spawn(async move {
        Server::builder()
            .add_service(AuthorizationServiceServer::with_interceptor(service, interceptor))
            .serve(addr_clone.parse().unwrap())
            .await
            .unwrap();
    });

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = AuthorizationServiceClient::connect(format!("http://{}", addr)).await.unwrap();

    (client, addr)
}

#[tokio::test]
async fn test_expand_stream() {
    let (mut client, _addr) = setup_test_server().await;

    // First write some tuples
    let write_req = WriteRelationshipsRequest {
        relationships: vec![
            ProtoRelationship {
                resource: "doc:test".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
            },
            ProtoRelationship {
                resource: "doc:test".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
            },
            ProtoRelationship {
                resource: "doc:test".to_string(),
                relation: "reader".to_string(),
                subject: "user:charlie".to_string(),
            },
        ],
    };

    let stream = futures::stream::once(async { write_req });
    client.write_relationships(stream).await.unwrap();

    // Now stream expand results
    let expand_req = Request::new(ExpandRequest {
        resource: "doc:test".to_string(),
        relation: "reader".to_string(),
    });

    let mut stream = client.expand(expand_req).await.unwrap().into_inner();

    let mut users = Vec::new();
    let mut got_summary = false;

    while let Some(response) = stream.next().await {
        let response = response.unwrap();
        match response.payload {
            Some(expand_response::Payload::User(user)) => {
                users.push(user);
            },
            Some(expand_response::Payload::Summary(summary)) => {
                got_summary = true;
                assert_eq!(summary.total_users, 3);
                assert!(summary.tree.is_some());
            },
            None => {},
        }
    }

    assert_eq!(users.len(), 3);
    assert!(got_summary);
    assert!(users.contains(&"user:alice".to_string()));
    assert!(users.contains(&"user:bob".to_string()));
    assert!(users.contains(&"user:charlie".to_string()));
}

#[tokio::test]
async fn test_write_stream() {
    let (mut client, _addr) = setup_test_server().await;

    // Create a stream of write requests
    let requests = vec![
        WriteRelationshipsRequest {
            relationships: vec![ProtoRelationship {
                resource: "doc:stream1".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
            }],
        },
        WriteRelationshipsRequest {
            relationships: vec![ProtoRelationship {
                resource: "doc:stream2".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
            }],
        },
        WriteRelationshipsRequest {
            relationships: vec![
                ProtoRelationship {
                    resource: "doc:stream3".to_string(),
                    relation: "reader".to_string(),
                    subject: "user:charlie".to_string(),
                },
                ProtoRelationship {
                    resource: "doc:stream3".to_string(),
                    relation: "reader".to_string(),
                    subject: "user:david".to_string(),
                },
            ],
        },
    ];

    let stream = futures::stream::iter(requests);
    let response = client.write_relationships(stream).await.unwrap();

    let inner = response.into_inner();
    assert_eq!(inner.relationships_written, 4);
    assert!(!inner.revision.is_empty());
}

#[tokio::test]
async fn test_expand_stream_empty() {
    let (mut client, _addr) = setup_test_server().await;

    // Expand a non-existent resource
    let expand_req = Request::new(ExpandRequest {
        resource: "doc:nonexistent".to_string(),
        relation: "reader".to_string(),
    });

    let mut stream = client.expand(expand_req).await.unwrap().into_inner();

    let mut users = Vec::new();
    let mut got_summary = false;

    while let Some(response) = stream.next().await {
        let response = response.unwrap();
        match response.payload {
            Some(expand_response::Payload::User(user)) => {
                users.push(user);
            },
            Some(expand_response::Payload::Summary(summary)) => {
                got_summary = true;
                assert_eq!(summary.total_users, 0);
            },
            None => {},
        }
    }

    assert_eq!(users.len(), 0);
    assert!(got_summary);
}

#[tokio::test]
async fn test_watch_captures_write_events() {
    let (mut client, _addr) = setup_test_server().await;

    // Start watching from beginning
    let watch_req = Request::new(inferadb_engine_api::grpc::proto::WatchRequest {
        resource_types: vec![],
        cursor: None,
    });

    let mut watch_stream = client.watch(watch_req).await.unwrap().into_inner();

    // Write some relationships
    let write_req = WriteRelationshipsRequest {
        relationships: vec![
            ProtoRelationship {
                resource: "doc:test1".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
            },
            ProtoRelationship {
                resource: "doc:test2".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
            },
        ],
    };

    let stream = futures::stream::once(async { write_req });
    client.write_relationships(stream).await.unwrap();

    // Collect events with timeout
    let mut events = Vec::new();
    let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(2));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(result) = watch_stream.next() => {
                let event = result.unwrap();
                events.push(event);
                if events.len() >= 2 {
                    break;
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }

    // Should have captured 2 create events
    assert_eq!(events.len(), 2);
    assert_eq!(
        events[0].operation,
        inferadb_engine_api::grpc::proto::ChangeOperation::Create as i32
    );
    assert_eq!(
        events[1].operation,
        inferadb_engine_api::grpc::proto::ChangeOperation::Create as i32
    );
}

#[tokio::test]
async fn test_watch_with_resource_type_filter() {
    let (mut client, _addr) = setup_test_server().await;

    // Start watching only "doc" resource types
    let watch_req = Request::new(inferadb_engine_api::grpc::proto::WatchRequest {
        resource_types: vec!["doc".to_string()],
        cursor: None,
    });

    let mut watch_stream = client.watch(watch_req).await.unwrap().into_inner();

    // Write relationships for different resource types
    let write_req = WriteRelationshipsRequest {
        relationships: vec![
            ProtoRelationship {
                resource: "doc:test1".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
            },
            ProtoRelationship {
                resource: "folder:test1".to_string(),
                relation: "viewer".to_string(),
                subject: "user:bob".to_string(),
            },
        ],
    };

    let stream = futures::stream::once(async { write_req });
    client.write_relationships(stream).await.unwrap();

    // Collect events with timeout
    let mut events = Vec::new();
    let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(2));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(result) = watch_stream.next() => {
                let event = result.unwrap();
                events.push(event);
                // Should only get 1 event (doc type only)
                if !events.is_empty() {
                    // Wait a bit more to make sure no other events come through
                    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                    break;
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }

    // Should only have captured 1 event (doc type, not folder)
    assert_eq!(events.len(), 1);
    let rel = events[0].relationship.as_ref().unwrap();
    assert!(rel.resource.starts_with("doc:"));
}

#[tokio::test]
async fn test_watch_captures_delete_events() {
    let (mut client, _addr) = setup_test_server().await;

    // Write a relationship first
    let write_req = WriteRelationshipsRequest {
        relationships: vec![ProtoRelationship {
            resource: "doc:test".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        }],
    };

    let stream = futures::stream::once(async { write_req });
    let write_response = client.write_relationships(stream).await.unwrap().into_inner();

    // Start watching from after the write
    let cursor = format!("{}", write_response.revision.parse::<u64>().unwrap() + 1);
    let watch_req = Request::new(inferadb_engine_api::grpc::proto::WatchRequest {
        resource_types: vec![],
        cursor: Some(base64::engine::general_purpose::STANDARD.encode(cursor.as_bytes())),
    });

    let mut watch_stream = client.watch(watch_req).await.unwrap().into_inner();

    // Delete the relationship
    let delete_req = DeleteRelationshipsRequest {
        filter: Some(inferadb_engine_api::grpc::proto::DeleteFilter {
            resource: Some("doc:test".to_string()),
            relation: None,
            subject: None,
        }),
        relationships: vec![],
        limit: None,
    };

    let stream = futures::stream::once(async { delete_req });
    client.delete_relationships(stream).await.unwrap();

    // Collect events with timeout
    let mut events = Vec::new();
    let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(2));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            Some(result) = watch_stream.next() => {
                let event = result.unwrap();
                events.push(event);
                if !events.is_empty() {
                    break;
                }
            }
            _ = &mut timeout => {
                break;
            }
        }
    }

    // Should have captured 1 delete event
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].operation,
        inferadb_engine_api::grpc::proto::ChangeOperation::Delete as i32
    );
}
