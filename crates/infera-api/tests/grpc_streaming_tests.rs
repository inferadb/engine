//! Integration tests for gRPC streaming operations
//!
//! These tests verify streaming functionality:
//! - ExpandStream: streaming expand results
//! - WriteStream: streaming write operations

use std::sync::Arc;

use futures::StreamExt;
use infera_api::grpc::proto::{
    expand_stream_response, infera_service_client::InferaServiceClient, ExpandRequest,
    Relationship as ProtoRelationship, WriteRequest,
};
use infera_api::{grpc::InferaServiceImpl, AppState};
use infera_config::Config;
use infera_core::{
    ipl::{RelationDef, Schema, TypeDef},
    Evaluator,
};
use infera_store::{MemoryBackend, RelationshipStore};
use tonic::transport::{Channel, Server};
use tonic::Request;

async fn setup_test_server() -> (InferaServiceClient<Channel>, String) {
    let store: Arc<dyn RelationshipStore> = Arc::new(MemoryBackend::new());
    let schema = Arc::new(Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![RelationDef::new("reader".to_string(), None)],
    )]));
    let evaluator = Arc::new(Evaluator::new(Arc::clone(&store), schema, None));
    let mut config = Config::default();
    config.auth.enabled = false; // Disable auth for tests

    let health_tracker = Arc::new(infera_api::health::HealthTracker::new());
    health_tracker.set_ready(true);
    health_tracker.set_startup_complete(true);

    let state = AppState {
        evaluator,
        store,
        config: Arc::new(config),
        jwks_cache: None,
        health_tracker,
    };

    let service = InferaServiceImpl::new(state);

    // Find available port
    let port = portpicker::pick_unused_port().expect("No free ports");
    let addr = format!("127.0.0.1:{}", port);
    let addr_clone = addr.clone();

    // Start gRPC server in background
    tokio::spawn(async move {
        Server::builder()
            .add_service(
                infera_api::grpc::proto::infera_service_server::InferaServiceServer::new(service),
            )
            .serve(addr_clone.parse().unwrap())
            .await
            .unwrap();
    });

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let client = InferaServiceClient::connect(format!("http://{}", addr))
        .await
        .unwrap();

    (client, addr)
}

#[tokio::test]
async fn test_expand_stream() {
    let (mut client, _addr) = setup_test_server().await;

    // First write some tuples
    let write_req = Request::new(WriteRequest {
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
    });

    client.write(write_req).await.unwrap();

    // Now stream expand results
    let expand_req = Request::new(ExpandRequest {
        resource: "doc:test".to_string(),
        relation: "reader".to_string(),
    });

    let mut stream = client.expand_stream(expand_req).await.unwrap().into_inner();

    let mut users = Vec::new();
    let mut got_summary = false;

    while let Some(response) = stream.next().await {
        let response = response.unwrap();
        match response.payload {
            Some(expand_stream_response::Payload::User(user)) => {
                users.push(user);
            }
            Some(expand_stream_response::Payload::Summary(summary)) => {
                got_summary = true;
                assert_eq!(summary.total_users, 3);
                assert!(summary.tree.is_some());
            }
            None => {}
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
        WriteRequest {
            relationships: vec![ProtoRelationship {
                resource: "doc:stream1".to_string(),
                relation: "reader".to_string(),
                subject: "user:alice".to_string(),
            }],
        },
        WriteRequest {
            relationships: vec![ProtoRelationship {
                resource: "doc:stream2".to_string(),
                relation: "reader".to_string(),
                subject: "user:bob".to_string(),
            }],
        },
        WriteRequest {
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
    let response = client.write_stream(stream).await.unwrap();

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

    let mut stream = client.expand_stream(expand_req).await.unwrap().into_inner();

    let mut users = Vec::new();
    let mut got_summary = false;

    while let Some(response) = stream.next().await {
        let response = response.unwrap();
        match response.payload {
            Some(expand_stream_response::Payload::User(user)) => {
                users.push(user);
            }
            Some(expand_stream_response::Payload::Summary(summary)) => {
                got_summary = true;
                assert_eq!(summary.total_users, 0);
            }
            None => {}
        }
    }

    assert_eq!(users.len(), 0);
    assert!(got_summary);
}
