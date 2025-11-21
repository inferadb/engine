//! Cache Invalidation Integration Tests
//!
//! These tests verify that cache invalidation works correctly when relationships
//! are written, deleted, or modified. The tests ensure that:
//! - Authorization decisions are cached properly
//! - Cache is invalidated on relationship changes
//! - Selective invalidation only affects relevant resources
//! - Vault isolation is maintained in cache operations

use infera_types::{Decision, EvaluateRequest};

use crate::{
    create_multi_vault_test_state, create_test_relationship, create_test_state,
    write_test_relationships,
};

/// Test: Cache population - authorization decisions are cached
#[tokio::test]
async fn test_cache_population_on_evaluation() {
    let state = create_test_state();
    let vault = 11111111111111i64;

    // Write a relationship
    let relationships =
        vec![create_test_relationship(vault, "document:readme", "viewer", "user:alice")];
    write_test_relationships(&state, vault, relationships).await.unwrap();

    // Reset cache stats to have clean baseline
    state.auth_cache.reset_stats();

    // First evaluation - cache miss, then cached
    let request1 = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };
    let decision1 = state.evaluation_service.evaluate(vault, request1.clone()).await.unwrap();
    assert_eq!(decision1, Decision::Allow);

    // Check stats after first evaluation
    let stats_after_first = state.auth_cache.stats();
    assert_eq!(stats_after_first.misses, 1, "First evaluation should be a cache miss");

    // Second evaluation - should be cache hit
    let decision2 = state.evaluation_service.evaluate(vault, request1).await.unwrap();
    assert_eq!(decision2, Decision::Allow);

    // Check stats after second evaluation
    let stats_after_second = state.auth_cache.stats();
    assert_eq!(stats_after_second.hits, 1, "Second evaluation should be a cache hit");
    assert_eq!(stats_after_second.misses, 1, "Should still only have one miss from first eval");
    assert_eq!(stats_after_second.hit_rate, 50.0, "Hit rate should be 50% (1 hit / 2 total)");
}

/// Test: Cache invalidation on relationship write
#[tokio::test]
async fn test_cache_invalidation_on_write() {
    let state = create_test_state();
    let vault = 22222222222222i64;

    // Write initial relationship
    let relationships =
        vec![create_test_relationship(vault, "document:readme", "viewer", "user:alice")];
    write_test_relationships(&state, vault, relationships.clone()).await.unwrap();

    // Evaluate and cache the result
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    state.auth_cache.reset_stats();
    let _ = state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
    let _ = state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();

    // After two evaluations, should have 1 hit
    let stats_before_write = state.auth_cache.stats();
    assert_eq!(stats_before_write.hits, 1, "Should have 1 cache hit before write");

    // Write another relationship for the same resource (should invalidate cache)
    let new_relationships =
        vec![create_test_relationship(vault, "document:readme", "editor", "user:bob")];

    // Simulate handler behavior: write then invalidate
    write_test_relationships(&state, vault, new_relationships.clone()).await.unwrap();
    let affected_resources: Vec<String> =
        new_relationships.iter().map(|r| r.resource.clone()).collect();
    state.relationship_service.invalidate_cache_for_resources(&affected_resources).await;

    // Verify invalidation happened
    let stats_after_invalidate = state.auth_cache.stats();
    assert_eq!(stats_after_invalidate.invalidations, 1, "Should have 1 invalidation");

    // Next evaluation should be a cache miss (since we invalidated)
    let _ = state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
    let stats_after_eval = state.auth_cache.stats();
    assert_eq!(stats_after_eval.misses, 2, "Should have 2 misses (initial + after invalidation)");
}

/// Test: Cache invalidation on relationship delete
#[tokio::test]
async fn test_cache_invalidation_on_delete() {
    let state = create_test_state();
    let vault = 33333333333333i64;

    // Write relationship
    let relationships =
        vec![create_test_relationship(vault, "document:readme", "viewer", "user:alice")];
    write_test_relationships(&state, vault, relationships).await.unwrap();

    // Evaluate and cache
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    state.auth_cache.reset_stats();
    let decision_before = state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
    assert_eq!(decision_before, Decision::Allow);

    // Second evaluation - should hit cache
    let _ = state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
    let stats_before_delete = state.auth_cache.stats();
    assert_eq!(stats_before_delete.hits, 1, "Should have cached result");

    // Delete the relationship (simulate handler behavior: delete then invalidate)
    let delete_filter = infera_types::DeleteFilter {
        resource: Some("document:readme".to_string()),
        relation: Some("viewer".to_string()),
        subject: Some("user:alice".to_string()),
    };
    state.store.delete_by_filter(vault, &delete_filter, None).await.unwrap();
    state
        .relationship_service
        .invalidate_cache_for_resources(&["document:readme".to_string()])
        .await;

    // Verify invalidation
    let stats_after_delete = state.auth_cache.stats();
    assert_eq!(stats_after_delete.invalidations, 1, "Should have invalidated cache");

    // Next evaluation should miss cache and return Deny (relationship deleted)
    let decision_after = state.evaluation_service.evaluate(vault, request).await.unwrap();
    assert_eq!(decision_after, Decision::Deny, "Should deny after relationship deleted");

    let stats_final = state.auth_cache.stats();
    assert_eq!(stats_final.misses, 2, "Should have 2 misses (initial + after delete)");
}

/// Test: Selective cache invalidation - only affected resources invalidated
#[tokio::test]
async fn test_selective_cache_invalidation() {
    let state = create_test_state();
    let vault = 44444444444444i64;

    // Write relationships for multiple resources
    let relationships = vec![
        create_test_relationship(vault, "document:readme", "viewer", "user:alice"),
        create_test_relationship(vault, "document:guide", "viewer", "user:alice"),
        create_test_relationship(vault, "document:manual", "viewer", "user:alice"),
    ];
    write_test_relationships(&state, vault, relationships).await.unwrap();

    // Evaluate all three and cache them
    state.auth_cache.reset_stats();

    let request_readme = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let request_guide = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:guide".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let request_manual = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:manual".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    // First evaluations - all cache misses
    state.evaluation_service.evaluate(vault, request_readme.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request_guide.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request_manual.clone()).await.unwrap();

    // Second evaluations - all cache hits
    state.evaluation_service.evaluate(vault, request_readme.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request_guide.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request_manual.clone()).await.unwrap();

    let stats_before_invalidate = state.auth_cache.stats();
    assert_eq!(stats_before_invalidate.hits, 3, "Should have 3 cache hits before invalidation");
    assert_eq!(stats_before_invalidate.misses, 3, "Should have 3 misses from first evaluations");

    // Invalidate only doc:guide
    state
        .relationship_service
        .invalidate_cache_for_resources(&["document:guide".to_string()])
        .await;

    // Evaluate all three again
    state.evaluation_service.evaluate(vault, request_readme.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request_guide.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request_manual.clone()).await.unwrap();

    let stats_after_selective = state.auth_cache.stats();

    // Should have 2 more hits (readme + manual still cached) and 1 more miss (guide invalidated)
    assert_eq!(
        stats_after_selective.hits, 5,
        "Should have 5 total hits (3 before + 2 still cached)"
    );
    assert_eq!(
        stats_after_selective.misses, 4,
        "Should have 4 total misses (3 initial + 1 after invalidation)"
    );
    assert_eq!(stats_after_selective.invalidations, 1, "Should have 1 selective invalidation");
}

/// Test: Bulk invalidation - writing multiple resources invalidates all
#[tokio::test]
async fn test_bulk_cache_invalidation() {
    let state = create_test_state();
    let vault = 55555555555555i64;

    // Write relationships
    let relationships = vec![
        create_test_relationship(vault, "document:1", "viewer", "user:alice"),
        create_test_relationship(vault, "document:2", "viewer", "user:alice"),
        create_test_relationship(vault, "document:3", "viewer", "user:alice"),
    ];
    write_test_relationships(&state, vault, relationships).await.unwrap();

    // Cache all evaluations
    state.auth_cache.reset_stats();

    for i in 1..=3 {
        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: format!("document:{}", i),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };
        // Evaluate twice to cache
        state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
        state.evaluation_service.evaluate(vault, request).await.unwrap();
    }

    let stats_before = state.auth_cache.stats();
    assert_eq!(stats_before.hits, 3, "Should have 3 cached results");

    // Write new relationships affecting multiple resources
    let new_relationships = vec![
        create_test_relationship(vault, "document:1", "editor", "user:bob"),
        create_test_relationship(vault, "document:2", "editor", "user:bob"),
    ];

    write_test_relationships(&state, vault, new_relationships.clone()).await.unwrap();

    // Simulate handler invalidation
    let affected_resources: Vec<String> =
        new_relationships.iter().map(|r| r.resource.clone()).collect();
    state.relationship_service.invalidate_cache_for_resources(&affected_resources).await;

    // Re-evaluate all three
    for i in 1..=3 {
        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: format!("document:{}", i),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };
        state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
    }

    let stats_after = state.auth_cache.stats();

    // All three should be cache misses because the revision changed after writing
    // (Cache keys include revision, so old cached entries won't match new revision)
    assert_eq!(stats_after.hits, 3, "Should have 3 hits (only from before the write)");
    assert_eq!(stats_after.misses, 6, "Should have 6 misses (3 initial + 3 after revision change)");
    assert_eq!(stats_after.invalidations, 1, "Should have 1 selective invalidation call");
}

/// Test: Vault isolation in cache operations
#[tokio::test]
async fn test_vault_cache_isolation() {
    let (state, vault_a, _account_a, vault_b, _account_b) = create_multi_vault_test_state();

    // Write same resource/relation/subject to both vaults
    let rel_a = create_test_relationship(vault_a, "document:readme", "viewer", "user:alice");
    let rel_b = create_test_relationship(vault_b, "document:readme", "viewer", "user:alice");

    write_test_relationships(&state, vault_a, vec![rel_a]).await.unwrap();
    write_test_relationships(&state, vault_b, vec![rel_b]).await.unwrap();

    // Evaluate on both vaults and cache results
    state.auth_cache.reset_stats();

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    // Evaluate twice on each vault to cache
    state.evaluation_service.evaluate(vault_a, request.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault_a, request.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault_b, request.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault_b, request.clone()).await.unwrap();

    let stats_before_invalidate = state.auth_cache.stats();
    assert_eq!(stats_before_invalidate.hits, 2, "Should have 2 cache hits (one per vault)");

    // Invalidate vault A only (using vault-wide invalidation)
    state.relationship_service.invalidate_cache_for_vault(vault_a).await;

    // Evaluate again on both vaults
    state.evaluation_service.evaluate(vault_a, request.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault_b, request.clone()).await.unwrap();

    let stats_after_invalidate = state.auth_cache.stats();

    // Vault A should be cache miss (invalidated)
    // Vault B should be cache hit (not invalidated)
    assert_eq!(stats_after_invalidate.hits, 3, "Should have 3 hits (2 before + 1 for vault B)");
    assert_eq!(
        stats_after_invalidate.misses, 3,
        "Should have 3 misses (2 initial + 1 for vault A after invalidation)"
    );
    assert_eq!(stats_after_invalidate.invalidations, 1, "Should have 1 vault invalidation");
}

/// Test: Resource-specific invalidation doesn't affect other resources in same vault
#[tokio::test]
async fn test_resource_specific_invalidation_within_vault() {
    let state = create_test_state();
    let vault = 66666666666666i64;

    // Write relationships for two resources
    let relationships = vec![
        create_test_relationship(vault, "document:public", "viewer", "user:alice"),
        create_test_relationship(vault, "document:private", "viewer", "user:alice"),
    ];
    write_test_relationships(&state, vault, relationships).await.unwrap();

    // Cache both
    state.auth_cache.reset_stats();

    let request_public = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:public".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let request_private = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:private".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    // Evaluate twice each to cache
    state.evaluation_service.evaluate(vault, request_public.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request_public.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request_private.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request_private.clone()).await.unwrap();

    assert_eq!(state.auth_cache.stats().hits, 2, "Should have 2 cached");

    // Invalidate only doc:public
    state
        .relationship_service
        .invalidate_cache_for_resources(&["document:public".to_string()])
        .await;

    // Evaluate both again
    state.evaluation_service.evaluate(vault, request_public.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request_private.clone()).await.unwrap();

    let stats = state.auth_cache.stats();

    // doc:public should miss (invalidated), doc:private should hit (still cached)
    assert_eq!(stats.hits, 3, "Should have 3 hits (2 before + 1 for private)");
    assert_eq!(
        stats.misses, 3,
        "Should have 3 misses (2 initial + 1 for public after invalidation)"
    );
}

/// Test: Multiple writes to same resource invalidate correctly
#[tokio::test]
async fn test_multiple_writes_same_resource() {
    let state = create_test_state();
    let vault = 77777777777777i64;

    // Initial write
    let relationships =
        vec![create_test_relationship(vault, "document:readme", "viewer", "user:alice")];
    write_test_relationships(&state, vault, relationships.clone()).await.unwrap();

    // Cache evaluation
    state.auth_cache.reset_stats();
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "document:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
    state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
    assert_eq!(state.auth_cache.stats().hits, 1, "Initial cache hit");

    // First write - invalidate
    let new_rel_1 = vec![create_test_relationship(vault, "document:readme", "editor", "user:bob")];
    write_test_relationships(&state, vault, new_rel_1.clone()).await.unwrap();
    state
        .relationship_service
        .invalidate_cache_for_resources(&["document:readme".to_string()])
        .await;

    // Evaluate - should miss
    state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
    assert_eq!(state.auth_cache.stats().misses, 2, "Cache miss after first write");

    // Evaluate again - should hit (re-cached)
    state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
    assert_eq!(state.auth_cache.stats().hits, 2, "Cache hit after re-cache");

    // Second write - invalidate again
    let new_rel_2 =
        vec![create_test_relationship(vault, "document:readme", "owner", "user:charlie")];
    write_test_relationships(&state, vault, new_rel_2.clone()).await.unwrap();
    state
        .relationship_service
        .invalidate_cache_for_resources(&["document:readme".to_string()])
        .await;

    // Evaluate - should miss again
    state.evaluation_service.evaluate(vault, request).await.unwrap();
    let final_stats = state.auth_cache.stats();
    assert_eq!(
        final_stats.misses, 3,
        "Should have 3 misses total (initial + 2 after invalidations)"
    );
    assert_eq!(final_stats.invalidations, 2, "Should have 2 invalidations");
}

/// Test: Vault-wide invalidation clears all cache entries for that vault
#[tokio::test]
async fn test_vault_wide_invalidation() {
    let state = create_test_state();
    let vault = 88888888888888i64;

    // Write multiple relationships for different resources
    let relationships = vec![
        create_test_relationship(vault, "document:1", "viewer", "user:alice"),
        create_test_relationship(vault, "document:2", "viewer", "user:alice"),
        create_test_relationship(vault, "document:3", "viewer", "user:alice"),
    ];
    write_test_relationships(&state, vault, relationships).await.unwrap();

    // Cache all evaluations
    state.auth_cache.reset_stats();
    for i in 1..=3 {
        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: format!("document:{}", i),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };
        state.evaluation_service.evaluate(vault, request.clone()).await.unwrap();
        state.evaluation_service.evaluate(vault, request).await.unwrap();
    }

    assert_eq!(state.auth_cache.stats().hits, 3, "All 3 should be cached");

    // Vault-wide invalidation
    state.relationship_service.invalidate_cache_for_vault(vault).await;

    // All evaluations should now miss
    for i in 1..=3 {
        let request = EvaluateRequest {
            subject: "user:alice".to_string(),
            resource: format!("document:{}", i),
            permission: "viewer".to_string(),
            context: None,
            trace: None,
        };
        state.evaluation_service.evaluate(vault, request).await.unwrap();
    }

    let stats = state.auth_cache.stats();
    assert_eq!(stats.misses, 6, "Should have 6 misses (3 initial + 3 after vault invalidation)");
    assert_eq!(stats.invalidations, 1, "Should have 1 vault-wide invalidation");
}
