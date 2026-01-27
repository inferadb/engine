#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{hint::black_box, sync::Arc, time::Duration};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use inferadb_engine_cache::{AuthCache, CheckCacheKey};
use inferadb_engine_types::{Decision, Revision};

async fn setup_cache(max_capacity: u64) -> AuthCache {
    AuthCache::new(max_capacity, Duration::from_secs(300))
}

fn bench_cache_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_insert");

    for size in [100, 1_000, 10_000].iter() {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.to_async(tokio::runtime::Runtime::new().unwrap()).iter(|| async {
                let cache = setup_cache(size).await;
                let revision = Revision::zero();

                let key = CheckCacheKey::new(
                    black_box(0i64),
                    black_box("user:alice".to_string()),
                    black_box("doc:readme".to_string()),
                    black_box("can_view".to_string()),
                    black_box(revision),
                );

                cache.put_check(key, black_box(Decision::Allow)).await;
            });
        });
    }

    group.finish();
}

fn bench_cache_get_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_get_hit");
    group.throughput(Throughput::Elements(1));

    for size in [100, 1_000, 10_000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.to_async(tokio::runtime::Runtime::new().unwrap()).iter_custom(|iters| async move {
                let cache = setup_cache(size).await;
                let revision = Revision::zero();

                // Pre-populate cache
                for i in 0..100 {
                    let key = CheckCacheKey::new(
                        0i64,
                        format!("user:{}", i),
                        "doc:readme".to_string(),
                        "can_view".to_string(),
                        revision,
                    );
                    cache.put_check(key, Decision::Allow).await;
                }

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let key = CheckCacheKey::new(
                        black_box(0i64),
                        black_box("user:50".to_string()),
                        black_box("doc:readme".to_string()),
                        black_box("can_view".to_string()),
                        black_box(revision),
                    );
                    let _ = cache.get_check(&key).await;
                }
                start.elapsed()
            });
        });
    }

    group.finish();
}

fn bench_cache_get_miss(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_get_miss");
    group.throughput(Throughput::Elements(1));

    for size in [100, 1_000, 10_000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.to_async(tokio::runtime::Runtime::new().unwrap()).iter_custom(|iters| async move {
                let cache = setup_cache(size).await;
                let revision = Revision::zero();

                // Pre-populate cache with different keys
                for i in 0..100 {
                    let key = CheckCacheKey::new(
                        0i64,
                        format!("user:{}", i),
                        "doc:readme".to_string(),
                        "can_view".to_string(),
                        revision,
                    );
                    cache.put_check(key, Decision::Allow).await;
                }

                let start = std::time::Instant::now();
                for i in 0..iters {
                    let key = CheckCacheKey::new(
                        black_box(0i64),
                        black_box(format!("user:miss_{}", i)),
                        black_box("doc:readme".to_string()),
                        black_box("can_view".to_string()),
                        black_box(revision),
                    );
                    let _ = cache.get_check(&key).await;
                }
                start.elapsed()
            });
        });
    }

    group.finish();
}

fn bench_cache_concurrent_access(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_concurrent");
    group.throughput(Throughput::Elements(10));

    for size in [1_000, 10_000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.to_async(tokio::runtime::Runtime::new().unwrap()).iter_custom(|iters| async move {
                let cache = Arc::new(setup_cache(size).await);
                let revision = Revision::zero();

                // Pre-populate
                for i in 0..100 {
                    let key = CheckCacheKey::new(
                        0i64,
                        format!("user:{}", i),
                        "doc:readme".to_string(),
                        "can_view".to_string(),
                        revision,
                    );
                    cache.put_check(key, Decision::Allow).await;
                }

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let mut handles = Vec::new();

                    // Spawn 10 concurrent tasks
                    for i in 0..10 {
                        let cache = Arc::clone(&cache);
                        let handle = tokio::spawn(async move {
                            let key = CheckCacheKey::new(
                                0i64,
                                format!("user:{}", i % 100),
                                "doc:readme".to_string(),
                                "can_view".to_string(),
                                revision,
                            );
                            cache.get_check(&key).await
                        });
                        handles.push(handle);
                    }

                    // Wait for all tasks
                    for handle in handles {
                        let _ = handle.await;
                    }
                }
                start.elapsed()
            });
        });
    }

    group.finish();
}

fn bench_cache_invalidation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_invalidation");
    group.throughput(Throughput::Elements(1));

    for size in [100, 1_000, 10_000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.to_async(tokio::runtime::Runtime::new().unwrap()).iter_custom(|iters| async move {
                let cache = setup_cache(size).await;
                let revision = Revision::zero();

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    // Populate cache
                    for i in 0..100 {
                        let key = CheckCacheKey::new(
                            0i64,
                            format!("user:{}", i),
                            "doc:readme".to_string(),
                            "can_view".to_string(),
                            revision,
                        );
                        cache.put_check(key, Decision::Allow).await;
                    }

                    // Invalidate all
                    let _: () = cache.invalidate_all().await;
                    black_box(());
                }
                start.elapsed()
            });
        });
    }

    group.finish();
}

fn bench_cache_selective_invalidation(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_selective_invalidation");
    group.throughput(Throughput::Elements(1));

    for size in [100, 1_000, 10_000].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.to_async(tokio::runtime::Runtime::new().unwrap()).iter_custom(|iters| async move {
                let cache = setup_cache(size).await;
                let revision = Revision::zero();

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    // Populate cache with entries for 10 different resources
                    for i in 0..10 {
                        for j in 0..10 {
                            let key = CheckCacheKey::new(
                                0i64,
                                format!("user:{}", j),
                                format!("doc:{}", i),
                                "can_view".to_string(),
                                revision,
                            );
                            cache.put_check(key, Decision::Allow).await;
                        }
                    }

                    // Selectively invalidate only one resource (10% of entries)
                    let _: () = cache.invalidate_resources(&["doc:0".to_string()]).await;
                    black_box(());
                }
                start.elapsed()
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_cache_insert,
    bench_cache_get_hit,
    bench_cache_get_miss,
    bench_cache_concurrent_access,
    bench_cache_invalidation,
    bench_cache_selective_invalidation
);
criterion_main!(benches);
