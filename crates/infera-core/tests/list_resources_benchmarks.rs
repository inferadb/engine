// Performance benchmarks for ListResources API

use std::{sync::Arc, time::Instant};

use infera_core::Evaluator;
use infera_store::{MemoryBackend, RelationshipStore};
use infera_types::{Decision, EvaluateRequest, ListResourcesRequest, Relationship};
use uuid::Uuid;

fn create_simple_schema() -> infera_core::ipl::Schema {
    let schema_str = r#"
    type doc {
        relation reader
    }
    type user {}
    "#;
    infera_core::ipl::parse_schema(schema_str).unwrap()
}

// Create test data with N resources
async fn create_test_data(store: &Arc<MemoryBackend>, num_resources: usize) {
    let mut relationships = Vec::new();
    for i in 0..num_resources {
        relationships.push(Relationship {
            resource: format!("doc:{}", i),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: Uuid::nil(),
        });

        // Batch writes every 1000 relationships to avoid memory issues
        if relationships.len() >= 1000 {
            store.write(Uuid::nil(), relationships.clone()).await.unwrap();
            relationships.clear();
        }
    }
    if !relationships.is_empty() {
        store.write(Uuid::nil(), relationships).await.unwrap();
    }
}

#[tokio::test]
async fn bench_list_resources_1k() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create 1K resources
    create_test_data(&store, 1_000).await;

    let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: None,
    };

    // Warmup
    evaluator.list_resources(request.clone()).await.unwrap();

    // Benchmark
    let start = Instant::now();
    let response = evaluator.list_resources(request).await.unwrap();
    let duration = start.elapsed();

    assert_eq!(response.resources.len(), 1_000);
    println!("✅ 1K resources: {:?} (target: <10ms)", duration);

    // This is an aggressive target - log warning if exceeded but don't fail
    if duration.as_millis() > 10 {
        println!("⚠️  WARNING: Exceeded 10ms target ({:?})", duration);
    }
}

#[tokio::test]
async fn bench_list_resources_10k() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create 10K resources
    create_test_data(&store, 10_000).await;

    let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: None,
    };

    // Warmup
    evaluator.list_resources(request.clone()).await.unwrap();

    // Benchmark
    let start = Instant::now();
    let response = evaluator.list_resources(request).await.unwrap();
    let duration = start.elapsed();

    assert_eq!(response.resources.len(), 10_000);
    println!("✅ 10K resources: {:?} (target: <100ms)", duration);

    if duration.as_millis() > 100 {
        println!("⚠️  WARNING: Exceeded 100ms target ({:?})", duration);
    }
}

#[tokio::test]
#[ignore] // Expensive test - run with --ignored
async fn bench_list_resources_100k() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create 100K resources
    println!("Creating 100K test resources...");
    create_test_data(&store, 100_000).await;

    let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: None,
    };

    // Warmup
    evaluator.list_resources(request.clone()).await.unwrap();

    // Benchmark
    let start = Instant::now();
    let response = evaluator.list_resources(request).await.unwrap();
    let duration = start.elapsed();

    assert_eq!(response.resources.len(), 100_000);
    println!("✅ 100K resources: {:?} (target: <1s)", duration);

    assert!(duration.as_secs() < 1, "Failed to meet <1s target: {:?}", duration);
}

#[tokio::test]
async fn bench_list_resources_deep_hierarchy() {
    let schema_str = r#"
    type folder {
        relation parent
        relation viewer: this | parent->viewer
    }
    type user {}
    "#;
    let schema = Arc::new(infera_core::ipl::parse_schema(schema_str).unwrap());
    let store = Arc::new(MemoryBackend::new());

    // Create a hierarchy 15 levels deep
    let depth = 15;
    let mut relationships = Vec::new();

    // Create parent relationships
    for i in 1..depth {
        relationships.push(Relationship {
            resource: format!("folder:level{}", i),
            relation: "parent".to_string(),
            subject: format!("folder:level{}", i - 1),
            vault: Uuid::nil(),
        });
    }

    // Alice is viewer of root folder
    relationships.push(Relationship {
        resource: "folder:level0".to_string(),
        relation: "viewer".to_string(),
        subject: "user:alice".to_string(),
        vault: Uuid::nil(),
    });

    store.write(Uuid::nil(), relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

    // Check that Alice can access the deepest folder
    let check_request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: format!("folder:level{}", depth - 1),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let start = Instant::now();
    let decision = evaluator.check(check_request).await.unwrap();
    let duration = start.elapsed();

    assert_eq!(decision, Decision::Allow);
    println!("✅ Deep hierarchy ({} levels): {:?}", depth, duration);

    // Should complete in reasonable time even with deep hierarchy
    assert!(duration.as_millis() < 100, "Deep hierarchy check took too long: {:?}", duration);
}

#[tokio::test]
async fn bench_list_resources_with_pattern() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create 10K resources with predictable names
    let mut relationships = Vec::new();
    for i in 0..10_000 {
        relationships.push(Relationship {
            vault: Uuid::nil(),
            resource: if i % 3 == 0 {
                format!("doc:project_a_{}", i)
            } else if i % 3 == 1 {
                format!("doc:project_b_{}", i)
            } else {
                format!("doc:other_{}", i)
            },
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
        });
    }
    store.write(Uuid::nil(), relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, Uuid::nil());

    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: Some("doc:project_a_*".to_string()),
    };

    // Warmup
    evaluator.list_resources(request.clone()).await.unwrap();

    // Benchmark
    let start = Instant::now();
    let response = evaluator.list_resources(request).await.unwrap();
    let duration = start.elapsed();

    // Should filter to ~3333 resources (every 3rd one)
    assert!(response.resources.len() > 3000 && response.resources.len() < 3500);
    println!(
        "✅ Pattern filtering (10K total, {} matched): {:?}",
        response.resources.len(),
        duration
    );
}

#[tokio::test]
async fn bench_concurrent_requests_100qps() {
    use tokio::time::{Duration, sleep};

    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create 1K resources for testing
    create_test_data(&store, 1_000).await;

    let evaluator = Arc::new(Evaluator::new(store, schema, None, Uuid::nil()));

    // Run for 1 second at 100 QPS = 100 requests
    let num_requests: usize = 100;
    let test_duration = Duration::from_secs(1);
    let request_interval = test_duration / (num_requests as u32);

    let start = Instant::now();
    let mut handles = vec![];

    for i in 0..num_requests {
        let evaluator = Arc::clone(&evaluator);
        let handle = tokio::spawn(async move {
            let request = ListResourcesRequest {
                subject: "user:alice".to_string(),
                resource_type: "doc".to_string(),
                permission: "reader".to_string(),
                limit: Some(100),
                cursor: None,
                resource_id_pattern: None,
            };

            let req_start = Instant::now();
            let result = evaluator.list_resources(request).await;
            let req_duration = req_start.elapsed();

            (result.is_ok(), req_duration)
        });
        handles.push(handle);

        // Space out requests to achieve target QPS
        if i < num_requests - 1 {
            sleep(request_interval).await;
        }
    }

    let results: Vec<_> = futures::future::join_all(handles).await;
    let total_duration = start.elapsed();

    let successful = results.iter().filter(|r| r.as_ref().unwrap().0).count();
    let avg_latency: Duration =
        results.iter().map(|r| r.as_ref().unwrap().1).sum::<Duration>() / (num_requests as u32);

    println!(
        "✅ 100 QPS load test: {}/{} successful, avg latency: {:?}, total time: {:?}",
        successful, num_requests, avg_latency, total_duration
    );

    assert_eq!(successful, num_requests);
    assert!(avg_latency.as_millis() < 50, "Average latency too high");
}

#[tokio::test]
#[ignore] // Expensive test - run with --ignored
async fn bench_concurrent_requests_1000qps() {
    use tokio::time::{Duration, sleep};

    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create 1K resources for testing
    create_test_data(&store, 1_000).await;

    let evaluator = Arc::new(Evaluator::new(store, schema, None, Uuid::nil()));

    // Run for 1 second at 1000 QPS = 1000 requests
    let num_requests: usize = 1000;
    let test_duration = Duration::from_secs(1);
    let request_interval = test_duration / (num_requests as u32);

    let start = Instant::now();
    let mut handles = vec![];

    for i in 0..num_requests {
        let evaluator = Arc::clone(&evaluator);
        let handle = tokio::spawn(async move {
            let request = ListResourcesRequest {
                subject: "user:alice".to_string(),
                resource_type: "doc".to_string(),
                permission: "reader".to_string(),
                limit: Some(100),
                cursor: None,
                resource_id_pattern: None,
            };

            let req_start = Instant::now();
            let result = evaluator.list_resources(request).await;
            let req_duration = req_start.elapsed();

            (result.is_ok(), req_duration)
        });
        handles.push(handle);

        // Space out requests to achieve target QPS
        if i < num_requests - 1 {
            sleep(request_interval).await;
        }
    }

    let results: Vec<_> = futures::future::join_all(handles).await;
    let total_duration = start.elapsed();

    let successful = results.iter().filter(|r| r.as_ref().unwrap().0).count();
    let avg_latency: Duration =
        results.iter().map(|r| r.as_ref().unwrap().1).sum::<Duration>() / (num_requests as u32);
    let max_latency = results.iter().map(|r| r.as_ref().unwrap().1).max().unwrap();

    println!(
        "✅ 1000 QPS load test: {}/{} successful, avg latency: {:?}, max latency: {:?}, total time: {:?}",
        successful, num_requests, avg_latency, max_latency, total_duration
    );

    assert_eq!(successful, num_requests);
    println!("Success rate: 100%");
}
