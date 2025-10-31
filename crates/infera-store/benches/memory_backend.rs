use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use infera_store::{MemoryBackend, Revision, Tuple, TupleKey, TupleStore};
use tokio::runtime::Runtime;

fn bench_single_write(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let store = MemoryBackend::new();

    c.bench_function("single write", |b| {
        b.iter(|| {
            rt.block_on(async {
                let tuple = Tuple {
                    object: "doc:readme".to_string(),
                    relation: "reader".to_string(),
                    user: "user:alice".to_string(),
                };
                store.write(vec![tuple]).await.unwrap()
            })
        })
    });
}

fn bench_single_read(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let store = MemoryBackend::new();

    // Setup: write some tuples
    let rev = rt.block_on(async {
        let tuples: Vec<_> = (0..100)
            .map(|i| Tuple {
                object: format!("doc:{}", i),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            })
            .collect();
        store.write(tuples).await.unwrap()
    });

    c.bench_function("single read", |b| {
        b.iter(|| {
            rt.block_on(async {
                let key = TupleKey {
                    object: "doc:50".to_string(),
                    relation: "reader".to_string(),
                    user: None,
                };
                store.read(black_box(&key), black_box(rev)).await.unwrap()
            })
        })
    });
}

fn bench_batch_write(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    for size in [10, 100, 1000].iter() {
        c.bench_with_input(BenchmarkId::new("batch write", size), size, |b, &size| {
            let store = MemoryBackend::new();
            b.iter(|| {
                rt.block_on(async {
                    let tuples: Vec<_> = (0..size)
                        .map(|i| Tuple {
                            object: format!("doc:{}", i),
                            relation: "reader".to_string(),
                            user: "user:alice".to_string(),
                        })
                        .collect();
                    store.write(tuples).await.unwrap()
                })
            });
        });
    }
}

fn bench_concurrent_writes(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("concurrent writes (10 tasks)", |b| {
        b.iter(|| {
            rt.block_on(async {
                let store = std::sync::Arc::new(MemoryBackend::new());
                let mut handles = vec![];

                for i in 0..10 {
                    let store_clone = std::sync::Arc::clone(&store);
                    let handle = tokio::spawn(async move {
                        let tuple = Tuple {
                            object: format!("doc:{}", i),
                            relation: "reader".to_string(),
                            user: "user:alice".to_string(),
                        };
                        store_clone.write(vec![tuple]).await
                    });
                    handles.push(handle);
                }

                for handle in handles {
                    handle.await.unwrap().unwrap();
                }
            })
        })
    });
}

fn bench_read_with_filter(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let store = MemoryBackend::new();

    // Setup: write tuples with multiple users
    let rev = rt.block_on(async {
        let tuples: Vec<_> = (0..100)
            .flat_map(|i| {
                vec![
                    Tuple {
                        object: format!("doc:{}", i),
                        relation: "reader".to_string(),
                        user: "user:alice".to_string(),
                    },
                    Tuple {
                        object: format!("doc:{}", i),
                        relation: "reader".to_string(),
                        user: "user:bob".to_string(),
                    },
                ]
            })
            .collect();
        store.write(tuples).await.unwrap()
    });

    c.bench_function("read with user filter", |b| {
        b.iter(|| {
            rt.block_on(async {
                let key = TupleKey {
                    object: "doc:50".to_string(),
                    relation: "reader".to_string(),
                    user: Some("user:alice".to_string()),
                };
                store.read(black_box(&key), black_box(rev)).await.unwrap()
            })
        })
    });
}

fn bench_reverse_lookup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let store = MemoryBackend::new();

    // Setup: write tuples
    let rev = rt.block_on(async {
        let tuples: Vec<_> = (0..100)
            .map(|i| Tuple {
                object: format!("doc:{}", i),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            })
            .collect();
        store.write(tuples).await.unwrap()
    });

    c.bench_function("reverse lookup by user", |b| {
        b.iter(|| {
            rt.block_on(async {
                store
                    .query_by_user(black_box("user:alice"), black_box("reader"), black_box(rev))
                    .await
                    .unwrap()
            })
        })
    });
}

fn bench_large_dataset_query(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let store = MemoryBackend::new();

    // Setup: write 10k tuples
    let rev = rt.block_on(async {
        let tuples: Vec<_> = (0..10000)
            .map(|i| Tuple {
                object: format!("doc:{}", i),
                relation: "reader".to_string(),
                user: format!("user:{}", i % 100),
            })
            .collect();
        store.write(tuples).await.unwrap()
    });

    c.bench_function("query on 10k relationships", |b| {
        b.iter(|| {
            rt.block_on(async {
                let key = TupleKey {
                    object: "doc:5000".to_string(),
                    relation: "reader".to_string(),
                    user: None,
                };
                store.read(black_box(&key), black_box(rev)).await.unwrap()
            })
        })
    });
}

criterion_group!(
    benches,
    bench_single_write,
    bench_single_read,
    bench_batch_write,
    bench_concurrent_writes,
    bench_read_with_filter,
    bench_reverse_lookup,
    bench_large_dataset_query
);
criterion_main!(benches);
