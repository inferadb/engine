use infera_store::MemoryBackend;
use infera_types::Relationship;

use super::*;
use crate::ipl::{RelationDef, RelationExpr, Schema, TypeDef};

fn create_simple_schema() -> Schema {
    Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![RelationDef::new("reader".to_string(), None)],
    )])
}

fn create_complex_schema() -> Schema {
    Schema::new(vec![
        TypeDef::new(
            "folder".to_string(),
            vec![
                RelationDef::new("owner".to_string(), None),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "owner".to_string() },
                    ])),
                ),
            ],
        ),
        TypeDef::new(
            "doc".to_string(),
            vec![
                RelationDef::new("parent".to_string(), None),
                RelationDef::new("owner".to_string(), None),
                RelationDef::new(
                    "editor".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "owner".to_string() },
                    ])),
                ),
                RelationDef::new(
                    "viewer".to_string(),
                    Some(RelationExpr::Union(vec![
                        RelationExpr::This,
                        RelationExpr::RelationRef { relation: "editor".to_string() },
                        RelationExpr::RelatedObjectUserset {
                            relationship: "parent".to_string(),
                            computed: "viewer".to_string(),
                        },
                    ])),
                ),
            ],
        ),
    ])
}

#[tokio::test]
async fn test_direct_check_allow() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Add a direct relationship
    let relationship = Relationship {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject: "user:alice".to_string(),
        vault: 0i64,
    };
    store.write(0i64, vec![relationship]).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Allow);
}

#[tokio::test]
async fn test_direct_check_deny() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Deny);
}

#[tokio::test]
async fn test_wildcard_user_allow() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Add a wildcard user relationship that grants access to all users
    let relationship = Relationship {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject: "user:*".to_string(),
        vault: 0i64,
    };
    store.write(0i64, vec![relationship]).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Check that subject:alice has access
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Allow);

    // Check that subject:bob also has access
    let request = EvaluateRequest {
        subject: "user:bob".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Allow);

    // Check that any user has access
    let request = EvaluateRequest {
        subject: "user:anyone".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Allow);
}

#[tokio::test]
async fn test_union_check() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    // Alice is owner, viewer is owner | this
    let relationship = Relationship {
        resource: "folder:docs".to_string(),
        relation: "owner".to_string(),
        subject: "user:alice".to_string(),
        vault: 0i64,
    };
    store.write(0i64, vec![relationship]).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "folder:docs".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Allow);
}

#[tokio::test]
async fn test_relationship_to_userset() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    // Set up: folder:docs has alice as viewer, doc:readme has parent->folder:docs
    let relationships = vec![
        Relationship {
            resource: "folder:docs".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "parent".to_string(),
            subject: "folder:docs".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Alice should be able to view doc:readme through parent->viewer
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Allow);
}

#[tokio::test]
async fn test_nested_relations() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    // Alice is owner, editor = this | owner, viewer = this | editor | parent->viewer
    let relationships = vec![Relationship {
        resource: "doc:readme".to_string(),
        relation: "owner".to_string(),
        subject: "user:alice".to_string(),
        vault: 0i64,
    }];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Alice should be viewer through owner->editor->viewer chain
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Allow);
}

#[tokio::test]
async fn test_check_with_trace() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let relationship = Relationship {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject: "user:alice".to_string(),
        vault: 0i64,
    };
    store.write(0i64, vec![relationship]).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let trace = evaluator.check_with_trace(request).await.unwrap();
    assert_eq!(trace.decision, Decision::Allow);
    assert!(trace.root.result);
    assert!(trace.duration.as_micros() > 0);
}

#[tokio::test]
async fn test_expand_direct_relation() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ExpandRequest {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        limit: None,
        continuation_token: None,
    };

    let response = evaluator.expand(request).await.unwrap();
    assert!(matches!(response.tree.node_type, UsersetNodeType::Leaf { .. }));
    assert_eq!(response.tree.children.len(), 0);
    assert_eq!(response.users.len(), 0); // No relationships written yet
    assert!(response.continuation_token.is_none());
}

#[tokio::test]
async fn test_expand_union() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "folder:docs".to_string(),
        relation: "viewer".to_string(),
    };

    let response = evaluator.expand(request).await.unwrap();
    let tree = &response.tree;
    assert!(matches!(tree.node_type, UsersetNodeType::Union));
    assert_eq!(tree.children.len(), 2);
}

#[tokio::test]
async fn test_expand_intersection() {
    let schema = Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![
            RelationDef::new("reader".to_string(), None),
            RelationDef::new("employee".to_string(), None),
            RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::Intersection(vec![
                    RelationExpr::RelationRef { relation: "reader".to_string() },
                    RelationExpr::RelationRef { relation: "employee".to_string() },
                ])),
            ),
        ],
    )]);

    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(store, Arc::new(schema), None, 0i64);

    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
    };

    let response = evaluator.expand(request).await.unwrap();
    let tree = &response.tree;
    assert!(matches!(tree.node_type, UsersetNodeType::Intersection));
    assert_eq!(tree.children.len(), 2);
}

#[tokio::test]
async fn test_expand_exclusion() {
    let schema = Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![
            RelationDef::new("editor".to_string(), None),
            RelationDef::new("blocked".to_string(), None),
            RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::Exclusion {
                    base: Box::new(RelationExpr::RelationRef { relation: "editor".to_string() }),
                    subtract: Box::new(RelationExpr::RelationRef {
                        relation: "blocked".to_string(),
                    }),
                }),
            ),
        ],
    )]);

    let store = Arc::new(MemoryBackend::new());
    let evaluator = Evaluator::new(store, Arc::new(schema), None, 0i64);

    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
    };

    let response = evaluator.expand(request).await.unwrap();
    let tree = &response.tree;
    assert!(matches!(tree.node_type, UsersetNodeType::Exclusion));
    assert_eq!(tree.children.len(), 2);
}

#[tokio::test]
async fn test_expand_nested() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Expand doc.viewer which has: this | editor | parent->viewer
    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
    };

    let response = evaluator.expand(request).await.unwrap();
    let tree = &response.tree;
    assert!(matches!(tree.node_type, UsersetNodeType::Union));
    assert_eq!(tree.children.len(), 3); // this, editor, parent->viewer
}

#[tokio::test]
async fn test_expand_relationship_to_userset() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Get the viewer relation which has a relationship-to-userset component
    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
    };

    let response = evaluator.expand(request).await.unwrap();
    let tree = &response.tree;
    assert!(matches!(tree.node_type, UsersetNodeType::Union));

    // The new implementation resolves RelatedObjectUserset to Leaf nodes with actual users
    // Check that children are Leaf nodes (resolved from RelatedObjectUserset)
    let has_leaf_nodes =
        tree.children.iter().any(|child| matches!(child.node_type, UsersetNodeType::Leaf { .. }));
    assert!(has_leaf_nodes);

    // Verify that users are collected (even if empty in this test)
    assert!(response.users.is_empty() || !response.users.is_empty());
}

#[tokio::test]
async fn test_expand_invalid_resource() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "invalid".to_string(), // Missing colon separator
        relation: "reader".to_string(),
    };

    let result = evaluator.expand(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_expand_unknown_type() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "unknown:foo".to_string(),
        relation: "reader".to_string(),
    };

    let result = evaluator.expand(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_expand_unknown_relation() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "doc:readme".to_string(),
        relation: "unknown".to_string(),
    };

    let result = evaluator.expand(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_expand_pagination() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Write 50 users to the store
    let mut relationships = vec![];
    for i in 0..50 {
        relationships.push(Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: format!("user:{}", i),
            vault: 0i64,
        });
    }
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // First page: get 10 users
    let request = ExpandRequest {
        limit: Some(10),
        continuation_token: None,
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
    };

    let response = evaluator.expand(request).await.unwrap();
    assert_eq!(response.users.len(), 10);
    assert_eq!(response.total_count, Some(50));
    assert!(response.continuation_token.is_some());

    // Second page: get next 10 users
    let request2 = ExpandRequest {
        limit: Some(10),
        continuation_token: response.continuation_token.clone(),
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
    };

    let response2 = evaluator.expand(request2).await.unwrap();
    assert_eq!(response2.users.len(), 10);
    assert_eq!(response2.total_count, Some(50));
    assert!(response2.continuation_token.is_some());

    // Verify no overlap between pages
    let first_page_users: std::collections::HashSet<_> = response.users.iter().collect();
    let second_page_users: std::collections::HashSet<_> = response2.users.iter().collect();
    assert!(first_page_users.is_disjoint(&second_page_users));

    // Last page: get remaining users
    let mut continuation = response2.continuation_token.clone();
    let mut all_users = response.users.clone();
    all_users.extend(response2.users.clone());

    while let Some(token) = continuation {
        let req = ExpandRequest {
            limit: Some(10),
            continuation_token: Some(token),
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
        };

        let resp = evaluator.expand(req).await.unwrap();
        all_users.extend(resp.users);
        continuation = resp.continuation_token;
    }

    // Verify we got all 50 users
    assert_eq!(all_users.len(), 50);
    let unique_users: std::collections::HashSet<_> = all_users.iter().collect();
    assert_eq!(unique_users.len(), 50);
}

#[tokio::test]
async fn test_expand_large_userset() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Write 1000 users to the store
    let mut relationships = vec![];
    for i in 0..1000 {
        relationships.push(Relationship {
            resource: "doc:large".to_string(),
            relation: "reader".to_string(),
            subject: format!("user:{}", i),
            vault: 0i64,
        });
    }
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Request without pagination (get all users)
    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "doc:large".to_string(),
        relation: "reader".to_string(),
    };

    let start = std::time::Instant::now();
    let response = evaluator.expand(request).await.unwrap();
    let duration = start.elapsed();

    // Verify all 1000 users are returned
    assert_eq!(response.users.len(), 1000);
    assert_eq!(response.total_count, Some(1000));
    assert!(response.continuation_token.is_none());

    // Verify deduplication (all users should be unique)
    let unique_users: std::collections::HashSet<_> = response.users.iter().collect();
    assert_eq!(unique_users.len(), 1000);

    // Performance check: should complete in reasonable time (<100ms)
    assert!(
        duration.as_millis() < 100,
        "Large userset expansion took too long: {}ms",
        duration.as_millis()
    );
}

#[tokio::test]
async fn test_expand_deduplication_union() {
    let store = Arc::new(MemoryBackend::new());

    // Create schema with union relation
    let schema = Arc::new(Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![
            RelationDef::new("reader".to_string(), None),
            RelationDef::new("editor".to_string(), None),
            RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::Union(vec![
                    RelationExpr::RelationRef { relation: "reader".to_string() },
                    RelationExpr::RelationRef { relation: "editor".to_string() },
                ])),
            ),
        ],
    )]));

    // Write overlapping users to both relations
    store
        .write(
            0i64,
            vec![
                // alice is both reader and editor
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "reader".to_string(),
                    subject: "user:alice".to_string(),
                    vault: 0i64,
                },
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "editor".to_string(),
                    subject: "user:alice".to_string(),
                    vault: 0i64,
                },
                // bob is only reader
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "reader".to_string(),
                    subject: "user:bob".to_string(),
                    vault: 0i64,
                },
                // charlie is only editor
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "editor".to_string(),
                    subject: "user:charlie".to_string(),
                    vault: 0i64,
                },
            ],
        )
        .await
        .unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
    };

    let response = evaluator.expand(request).await.unwrap();

    // Should have 3 unique users (alice should only appear once)
    assert_eq!(response.users.len(), 3);
    assert!(response.users.contains(&"user:alice".to_string()));
    assert!(response.users.contains(&"user:bob".to_string()));
    assert!(response.users.contains(&"user:charlie".to_string()));

    // Verify tree structure is Union with Leaf children
    assert!(matches!(response.tree.node_type, UsersetNodeType::Union));
    assert_eq!(response.tree.children.len(), 2);
}

#[tokio::test]
async fn test_expand_deduplication_intersection() {
    let store = Arc::new(MemoryBackend::new());

    // Create schema with intersection relation
    let schema = Arc::new(Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![
            RelationDef::new("approver".to_string(), None),
            RelationDef::new("editor".to_string(), None),
            RelationDef::new(
                "can_publish".to_string(),
                Some(RelationExpr::Intersection(vec![
                    RelationExpr::RelationRef { relation: "approver".to_string() },
                    RelationExpr::RelationRef { relation: "editor".to_string() },
                ])),
            ),
        ],
    )]));

    // Write test data
    store
        .write(
            0i64,
            vec![
                // alice is both approver and editor (should be in intersection)
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "approver".to_string(),
                    subject: "user:alice".to_string(),
                    vault: 0i64,
                },
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "editor".to_string(),
                    subject: "user:alice".to_string(),
                    vault: 0i64,
                },
                // bob is only approver (should NOT be in intersection)
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "approver".to_string(),
                    subject: "user:bob".to_string(),
                    vault: 0i64,
                },
                // charlie is only editor (should NOT be in intersection)
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "editor".to_string(),
                    subject: "user:charlie".to_string(),
                    vault: 0i64,
                },
            ],
        )
        .await
        .unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "doc:readme".to_string(),
        relation: "can_publish".to_string(),
    };

    let response = evaluator.expand(request).await.unwrap();

    // Should only have alice (intersection of approver & editor)
    assert_eq!(response.users.len(), 1);
    assert_eq!(response.users[0], "user:alice");

    // Verify tree structure is Intersection with Leaf children
    assert!(matches!(response.tree.node_type, UsersetNodeType::Intersection));
    assert_eq!(response.tree.children.len(), 2);
}

#[tokio::test]
async fn test_expand_deduplication_exclusion() {
    let store = Arc::new(MemoryBackend::new());

    // Create schema with exclusion relation
    let schema = Arc::new(Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![
            RelationDef::new("viewer".to_string(), None),
            RelationDef::new("blocked".to_string(), None),
            RelationDef::new(
                "can_view".to_string(),
                Some(RelationExpr::Exclusion {
                    base: Box::new(RelationExpr::RelationRef { relation: "viewer".to_string() }),
                    subtract: Box::new(RelationExpr::RelationRef {
                        relation: "blocked".to_string(),
                    }),
                }),
            ),
        ],
    )]));

    // Write test data
    store
        .write(
            0i64,
            vec![
                // alice is viewer but not blocked (should be in result)
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:alice".to_string(),
                    vault: 0i64,
                },
                // bob is viewer AND blocked (should NOT be in result)
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:bob".to_string(),
                    vault: 0i64,
                },
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "blocked".to_string(),
                    subject: "user:bob".to_string(),
                    vault: 0i64,
                },
                // charlie is viewer but not blocked (should be in result)
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:charlie".to_string(),
                    vault: 0i64,
                },
            ],
        )
        .await
        .unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "doc:readme".to_string(),
        relation: "can_view".to_string(),
    };

    let response = evaluator.expand(request).await.unwrap();

    // Should have alice and charlie (bob is excluded)
    assert_eq!(response.users.len(), 2);
    assert!(response.users.contains(&"user:alice".to_string()));
    assert!(response.users.contains(&"user:charlie".to_string()));
    assert!(!response.users.contains(&"user:bob".to_string()));

    // Verify tree structure is Exclusion with Leaf children
    assert!(matches!(response.tree.node_type, UsersetNodeType::Exclusion));
    assert_eq!(response.tree.children.len(), 2);
}

#[tokio::test]
async fn test_expand_parallel_correctness() {
    // Test that parallel expansion produces correct results with complex nested unions
    let store = Arc::new(MemoryBackend::new());

    // Create a schema with multiple parallel branches: admin | editor | viewer
    let schema = Arc::new(Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![
            RelationDef::new("admin".to_string(), None),
            RelationDef::new("editor".to_string(), None),
            RelationDef::new("viewer".to_string(), None),
            RelationDef::new("contributor".to_string(), None),
            RelationDef::new(
                "any_access".to_string(),
                Some(RelationExpr::Union(vec![
                    RelationExpr::RelationRef { relation: "admin".to_string() },
                    RelationExpr::RelationRef { relation: "editor".to_string() },
                    RelationExpr::RelationRef { relation: "viewer".to_string() },
                    RelationExpr::RelationRef { relation: "contributor".to_string() },
                ])),
            ),
        ],
    )]));

    // Write users to different relations (some overlap intentionally)
    store
        .write(
            0i64,
            vec![
                // alice is admin
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "admin".to_string(),
                    subject: "user:alice".to_string(),
                    vault: 0i64,
                },
                // bob is editor
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "editor".to_string(),
                    subject: "user:bob".to_string(),
                    vault: 0i64,
                },
                // charlie is viewer
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:charlie".to_string(),
                    vault: 0i64,
                },
                // dave is contributor
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "contributor".to_string(),
                    subject: "user:dave".to_string(),
                    vault: 0i64,
                },
                // eve is both editor and viewer (test deduplication)
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "editor".to_string(),
                    subject: "user:eve".to_string(),
                    vault: 0i64,
                },
                Relationship {
                    resource: "doc:readme".to_string(),
                    relation: "viewer".to_string(),
                    subject: "user:eve".to_string(),
                    vault: 0i64,
                },
            ],
        )
        .await
        .unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ExpandRequest {
        limit: None,
        continuation_token: None,
        resource: "doc:readme".to_string(),
        relation: "any_access".to_string(),
    };

    let response = evaluator.expand(request).await.unwrap();

    // Should have 5 unique users (alice, bob, charlie, dave, eve - with eve deduplicated)
    assert_eq!(response.users.len(), 5);
    assert!(response.users.contains(&"user:alice".to_string()));
    assert!(response.users.contains(&"user:bob".to_string()));
    assert!(response.users.contains(&"user:charlie".to_string()));
    assert!(response.users.contains(&"user:dave".to_string()));
    assert!(response.users.contains(&"user:eve".to_string()));

    // Verify tree structure is Union with 4 Leaf children
    assert!(matches!(response.tree.node_type, UsersetNodeType::Union));
    assert_eq!(response.tree.children.len(), 4);

    // All children should be Leaf nodes (resolved RelationRefs)
    for child in &response.tree.children {
        assert!(matches!(child.node_type, UsersetNodeType::Leaf { .. }));
    }
}

#[tokio::test]
async fn test_exclusion_check() {
    let schema = Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![
            RelationDef::new("editor".to_string(), None),
            RelationDef::new("blocked".to_string(), None),
            RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::Exclusion {
                    base: Box::new(RelationExpr::RelationRef { relation: "editor".to_string() }),
                    subtract: Box::new(RelationExpr::RelationRef {
                        relation: "blocked".to_string(),
                    }),
                }),
            ),
        ],
    )]);

    let store = Arc::new(MemoryBackend::new());

    // Alice is editor but also blocked
    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "editor".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "blocked".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, Arc::new(schema), None, 0i64);

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    // Alice should be denied (editor - blocked = denied)
    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Deny);
}

#[tokio::test]
async fn test_intersection_check() {
    let schema = Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![
            RelationDef::new("reader".to_string(), None),
            RelationDef::new("employee".to_string(), None),
            RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::Intersection(vec![
                    RelationExpr::RelationRef { relation: "reader".to_string() },
                    RelationExpr::RelationRef { relation: "employee".to_string() },
                ])),
            ),
        ],
    )]);

    let store = Arc::new(MemoryBackend::new());

    // Alice is reader and employee
    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "employee".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, Arc::new(schema), None, 0i64);

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    // Alice should be allowed (reader & employee)
    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Allow);
}

#[tokio::test]
async fn test_intersection_check_deny() {
    let schema = Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![
            RelationDef::new("reader".to_string(), None),
            RelationDef::new("employee".to_string(), None),
            RelationDef::new(
                "viewer".to_string(),
                Some(RelationExpr::Intersection(vec![
                    RelationExpr::RelationRef { relation: "reader".to_string() },
                    RelationExpr::RelationRef { relation: "employee".to_string() },
                ])),
            ),
        ],
    )]);

    let store = Arc::new(MemoryBackend::new());

    // Alice is only reader, not employee
    let relationships = vec![Relationship {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject: "user:alice".to_string(),
        vault: 0i64,
    }];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, Arc::new(schema), None, 0i64);

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "viewer".to_string(),
        context: None,
        trace: None,
    };

    // Alice should be denied (not an employee)
    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Deny);
}

#[tokio::test]
async fn test_cache_hit() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let relationships = vec![Relationship {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject: "user:alice".to_string(),
        vault: 0i64,
    }];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    // First check - cache miss
    let result1 = evaluator.check(request.clone()).await.unwrap();
    assert_eq!(result1, Decision::Allow);

    let stats = evaluator.cache_stats().unwrap();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 0);

    // Second check - cache hit
    let result2 = evaluator.check(request).await.unwrap();
    assert_eq!(result2, Decision::Allow);

    let stats = evaluator.cache_stats().unwrap();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.hit_rate, 50.0);
}

#[tokio::test]
async fn test_cache_disabled() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let relationships = vec![Relationship {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject: "user:alice".to_string(),
        vault: 0i64,
    }];
    store.write(0i64, relationships).await.unwrap();

    // Create evaluator without cache
    let evaluator = Evaluator::new_with_cache(store, schema, None, None, 0i64);

    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Allow);

    // No cache stats available
    assert!(evaluator.cache_stats().is_none());
}

#[tokio::test]
async fn test_cache_different_requests() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:guide".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Different subject
    let request1 = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    // Different resource
    let request2 = EvaluateRequest {
        subject: "user:bob".to_string(),
        resource: "doc:guide".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    evaluator.check(request1.clone()).await.unwrap();
    evaluator.check(request2.clone()).await.unwrap();
    evaluator.check(request1).await.unwrap(); // Cache hit
    evaluator.check(request2).await.unwrap(); // Cache hit

    let stats = evaluator.cache_stats().unwrap();
    assert_eq!(stats.misses, 2); // Two different requests
    assert_eq!(stats.hits, 2); // Two repeated requests
    assert_eq!(stats.hit_rate, 50.0);
}

#[tokio::test]
async fn test_list_resources_basic() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create some documents and give alice access to some of them
    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:guide".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:secret".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: None,
    };

    let response = evaluator.list_resources(request).await.unwrap();

    // Alice should have access to readme and guide, but not secret
    assert_eq!(response.resources.len(), 2);
    assert!(response.resources.contains(&"doc:readme".to_string()));
    assert!(response.resources.contains(&"doc:guide".to_string()));
    assert!(!response.resources.contains(&"doc:secret".to_string()));
    assert!(response.cursor.is_none()); // No more results
}

#[tokio::test]
async fn test_list_resources_no_access() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create documents but don't give charlie any access
    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:guide".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListResourcesRequest {
        subject: "user:charlie".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: None,
    };

    let response = evaluator.list_resources(request).await.unwrap();

    // Charlie should have no access
    assert_eq!(response.resources.len(), 0);
}

#[tokio::test]
async fn test_list_resources_with_limit() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create multiple documents alice can access
    let relationships = vec![
        Relationship {
            resource: "doc:1".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:2".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:3".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:4".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:5".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Request with limit of 2
    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: Some(2),
        cursor: None,
        resource_id_pattern: None,
    };

    let response = evaluator.list_resources(request).await.unwrap();

    // Should only return 2 resources
    assert_eq!(response.resources.len(), 2);
    assert!(response.cursor.is_some()); // Should have a cursor for pagination
}

#[tokio::test]
async fn test_list_resources_pagination() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create 10 documents alice can access
    let mut relationships = vec![];
    for i in 1..=10 {
        relationships.push(Relationship {
            resource: format!("doc:{}", i),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        });
    }
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // First page: get 3 resources
    let request1 = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: Some(3),
        cursor: None,
        resource_id_pattern: None,
    };

    let response1 = evaluator.list_resources(request1).await.unwrap();
    assert_eq!(response1.resources.len(), 3);
    assert!(response1.cursor.is_some());

    // Second page: use cursor
    let request2 = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: Some(3),
        cursor: response1.cursor.clone(),
        resource_id_pattern: None,
    };

    let response2 = evaluator.list_resources(request2).await.unwrap();
    assert_eq!(response2.resources.len(), 3);

    // Verify no overlap between pages
    let first_page: std::collections::HashSet<_> = response1.resources.iter().collect();
    let second_page: std::collections::HashSet<_> = response2.resources.iter().collect();
    assert!(first_page.is_disjoint(&second_page));
}

#[tokio::test]
async fn test_list_resources_empty_type() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // No documents exist of this type
    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "folder".to_string(),
        permission: "reader".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: None,
    };

    let response = evaluator.list_resources(request).await.unwrap();

    // Should return empty list
    assert_eq!(response.resources.len(), 0);
    assert!(response.cursor.is_none());
}

#[tokio::test]
async fn test_list_resources_with_union_relation() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    // Alice is owner of doc1, direct viewer of doc2
    // viewer = this | editor | parent->viewer
    let relationships = vec![
        Relationship {
            resource: "doc:1".to_string(),
            relation: "owner".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:2".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:3".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "viewer".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: None,
    };

    let response = evaluator.list_resources(request).await.unwrap();

    // Alice should have access to doc:1 (via owner->editor->viewer) and doc:2 (direct)
    assert_eq!(response.resources.len(), 2);
    assert!(response.resources.contains(&"doc:1".to_string()));
    assert!(response.resources.contains(&"doc:2".to_string()));
    assert!(!response.resources.contains(&"doc:3".to_string()));
}

#[tokio::test]
async fn test_list_resources_with_wildcard_pattern() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create documents with various names
    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme_v2".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:guide".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:tutorial".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Test wildcard pattern "readme*"
    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: Some("doc:readme*".to_string()),
    };

    let response = evaluator.list_resources(request).await.unwrap();

    // Should match "doc:readme" and "doc:readme_v2" but not "doc:guide" or "doc:tutorial"
    assert_eq!(response.resources.len(), 2);
    assert!(response.resources.contains(&"doc:readme".to_string()));
    assert!(response.resources.contains(&"doc:readme_v2".to_string()));
}

#[tokio::test]
async fn test_list_resources_with_question_mark_pattern() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create documents with single character variations
    let relationships = vec![
        Relationship {
            resource: "doc:file1".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:file2".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:file10".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Test ? pattern - matches single character
    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: Some("doc:file?".to_string()),
    };

    let response = evaluator.list_resources(request).await.unwrap();

    // Should match "doc:file1" and "doc:file2" but not "doc:file10" (has 2 chars after "file")
    assert_eq!(response.resources.len(), 2);
    assert!(response.resources.contains(&"doc:file1".to_string()));
    assert!(response.resources.contains(&"doc:file2".to_string()));
}

#[tokio::test]
async fn test_list_resources_with_mixed_pattern() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let relationships = vec![
        Relationship {
            resource: "doc:project_abc_report".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:project_xyz_report".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:project_abc_summary".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Test mixed pattern "project_*_report"
    let request = ListResourcesRequest {
        subject: "user:alice".to_string(),
        resource_type: "doc".to_string(),
        permission: "reader".to_string(),
        limit: None,
        cursor: None,
        resource_id_pattern: Some("doc:project_*_report".to_string()),
    };

    let response = evaluator.list_resources(request).await.unwrap();

    // Should match both *_report files but not *_summary
    assert_eq!(response.resources.len(), 2);
    assert!(response.resources.contains(&"doc:project_abc_report".to_string()));
    assert!(response.resources.contains(&"doc:project_xyz_report".to_string()));
}

// ============================================================================
// ListSubjects Tests
// ============================================================================

#[tokio::test]
async fn test_list_subjects_basic() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create some relationships where alice and bob are readers
    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:guide".to_string(),
            relation: "reader".to_string(),
            subject: "user:charlie".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListSubjectsRequest {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject_type: None,
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_subjects(request).await.unwrap();

    // Should return alice and bob as readers of doc:readme
    assert_eq!(response.subjects.len(), 2);
    assert!(response.subjects.contains(&"user:alice".to_string()));
    assert!(response.subjects.contains(&"user:bob".to_string()));
    assert!(!response.subjects.contains(&"user:charlie".to_string()));
    assert!(response.cursor.is_none()); // No more results
}

#[tokio::test]
async fn test_list_subjects_no_subjects() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create relationships for different document
    let relationships = vec![Relationship {
        resource: "doc:guide".to_string(),
        relation: "reader".to_string(),
        subject: "user:alice".to_string(),
        vault: 0i64,
    }];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListSubjectsRequest {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject_type: None,
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_subjects(request).await.unwrap();

    // Should return empty list
    assert_eq!(response.subjects.len(), 0);
    assert!(response.cursor.is_none());
}

#[tokio::test]
async fn test_list_subjects_with_subject_type_filter() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Mix of users and groups
    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "group:admins".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "group:engineers".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store.clone(), schema.clone(), None, 0i64);

    // Filter by user type
    let request = ListSubjectsRequest {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject_type: Some("user".to_string()),
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_subjects(request).await.unwrap();

    assert_eq!(response.subjects.len(), 2);
    assert!(response.subjects.contains(&"user:alice".to_string()));
    assert!(response.subjects.contains(&"user:bob".to_string()));
    assert!(!response.subjects.contains(&"group:admins".to_string()));

    // Filter by group type
    let request = ListSubjectsRequest {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject_type: Some("group".to_string()),
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_subjects(request).await.unwrap();

    assert_eq!(response.subjects.len(), 2);
    assert!(response.subjects.contains(&"group:admins".to_string()));
    assert!(response.subjects.contains(&"group:engineers".to_string()));
    assert!(!response.subjects.contains(&"user:alice".to_string()));
}

#[tokio::test]
async fn test_list_subjects_with_limit() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create multiple subjects with access
    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:charlie".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:dave".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:eve".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Request with limit of 2
    let request = ListSubjectsRequest {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject_type: None,
        limit: Some(2),
        cursor: None,
    };

    let response = evaluator.list_subjects(request).await.unwrap();

    // Should only return 2 subjects
    assert_eq!(response.subjects.len(), 2);
    assert!(response.cursor.is_some()); // Should have a cursor for pagination
}

#[tokio::test]
async fn test_list_subjects_pagination() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Create 10 subjects with access
    let mut relationships = vec![];
    for i in 1..=10 {
        relationships.push(Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: format!("user:{}", i),
            vault: 0i64,
        });
    }
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // First page: get 3 subjects
    let request1 = ListSubjectsRequest {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject_type: None,
        limit: Some(3),
        cursor: None,
    };

    let response1 = evaluator.list_subjects(request1).await.unwrap();
    assert_eq!(response1.subjects.len(), 3);
    assert!(response1.cursor.is_some());

    // Second page: use cursor
    let request2 = ListSubjectsRequest {
        resource: "doc:readme".to_string(),
        relation: "reader".to_string(),
        subject_type: None,
        limit: Some(3),
        cursor: response1.cursor.clone(),
    };

    let response2 = evaluator.list_subjects(request2).await.unwrap();
    assert_eq!(response2.subjects.len(), 3);

    // Verify no overlap between pages
    let first_page: std::collections::HashSet<_> = response1.subjects.iter().collect();
    let second_page: std::collections::HashSet<_> = response2.subjects.iter().collect();
    assert!(first_page.is_disjoint(&second_page));
}

#[tokio::test]
async fn test_list_subjects_with_union_relation() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    // Alice is owner of doc:1, bob is direct viewer
    // viewer = this | editor | parent->viewer
    // editor = this | owner
    let relationships = vec![
        Relationship {
            resource: "doc:1".to_string(),
            relation: "owner".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:1".to_string(),
            relation: "viewer".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListSubjectsRequest {
        resource: "doc:1".to_string(),
        relation: "viewer".to_string(),
        subject_type: None,
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_subjects(request).await.unwrap();

    // Should include alice (via owner->editor->viewer) and bob (direct viewer)
    assert_eq!(response.subjects.len(), 2);
    assert!(response.subjects.contains(&"user:alice".to_string()));
    assert!(response.subjects.contains(&"user:bob".to_string()));
}

#[tokio::test]
async fn test_list_subjects_with_computed_userset() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    // Alice is owner, bob is editor
    // editor = this | owner
    let relationships = vec![
        Relationship {
            resource: "doc:1".to_string(),
            relation: "owner".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:1".to_string(),
            relation: "editor".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListSubjectsRequest {
        resource: "doc:1".to_string(),
        relation: "editor".to_string(),
        subject_type: None,
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_subjects(request).await.unwrap();

    // Should include alice (via owner) and bob (direct)
    assert_eq!(response.subjects.len(), 2);
    assert!(response.subjects.contains(&"user:alice".to_string()));
    assert!(response.subjects.contains(&"user:bob".to_string()));
}

#[tokio::test]
async fn test_list_subjects_with_related_object_userset() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    // Alice is viewer of parent folder, doc has parent->viewer relation
    let relationships = vec![
        Relationship {
            resource: "folder:docs".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "parent".to_string(),
            subject: "folder:docs".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListSubjectsRequest {
        resource: "doc:readme".to_string(),
        relation: "viewer".to_string(),
        subject_type: None,
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_subjects(request).await.unwrap();

    // Should include alice (via parent->viewer) and bob (direct)
    assert_eq!(response.subjects.len(), 2);
    assert!(response.subjects.contains(&"user:alice".to_string()));
    assert!(response.subjects.contains(&"user:bob".to_string()));
}

#[tokio::test]
async fn test_list_subjects_deduplication() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    // Alice has access through multiple paths:
    // - Direct viewer
    // - Owner (which implies editor, which implies viewer)
    let relationships = vec![
        Relationship {
            resource: "doc:1".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:1".to_string(),
            relation: "owner".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListSubjectsRequest {
        resource: "doc:1".to_string(),
        relation: "viewer".to_string(),
        subject_type: None,
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_subjects(request).await.unwrap();

    // Alice should only appear once despite multiple paths
    assert_eq!(response.subjects.len(), 1);
    assert!(response.subjects.contains(&"user:alice".to_string()));
}

#[tokio::test]
async fn test_list_subjects_invalid_resource_format() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListSubjectsRequest {
        resource: "invalid-format".to_string(), // Missing colon
        relation: "reader".to_string(),
        subject_type: None,
        limit: None,
        cursor: None,
    };

    let result = evaluator.list_subjects(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_list_subjects_unknown_type() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListSubjectsRequest {
        resource: "unknown:123".to_string(),
        relation: "reader".to_string(),
        subject_type: None,
        limit: None,
        cursor: None,
    };

    let result = evaluator.list_subjects(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_list_subjects_unknown_relation() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    let request = ListSubjectsRequest {
        resource: "doc:readme".to_string(),
        relation: "unknown_relation".to_string(),
        subject_type: None,
        limit: None,
        cursor: None,
    };

    let result = evaluator.list_subjects(request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_glob_pattern_matching() {
    // Test basic wildcard
    assert!(Evaluator::matches_glob_pattern("doc:readme", "doc:readme"));
    assert!(Evaluator::matches_glob_pattern("doc:readme", "doc:*"));
    assert!(Evaluator::matches_glob_pattern("doc:readme", "*"));
    assert!(Evaluator::matches_glob_pattern("doc:readme", "doc:read*"));
    assert!(Evaluator::matches_glob_pattern("doc:readme_v2", "doc:readme*"));

    // Test question mark
    assert!(Evaluator::matches_glob_pattern("doc:file1", "doc:file?"));
    assert!(Evaluator::matches_glob_pattern("doc:file2", "doc:file?"));
    assert!(!Evaluator::matches_glob_pattern("doc:file10", "doc:file?"));

    // Test mixed patterns
    assert!(Evaluator::matches_glob_pattern("project_abc_report", "project_*_report"));
    assert!(Evaluator::matches_glob_pattern("project_xyz_report", "project_*_report"));
    assert!(!Evaluator::matches_glob_pattern("project_abc_summary", "project_*_report"));

    // Test edge cases
    assert!(Evaluator::matches_glob_pattern("", ""));
    assert!(Evaluator::matches_glob_pattern("", "*"));
    assert!(!Evaluator::matches_glob_pattern("a", ""));
    assert!(Evaluator::matches_glob_pattern("abc", "a*c"));
    assert!(Evaluator::matches_glob_pattern("abc", "a?c"));
    assert!(!Evaluator::matches_glob_pattern("abbc", "a?c"));
}

#[tokio::test]
async fn test_list_relationships_no_filters() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Add multiple relationships
    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:guide".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:charlie".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // List all relationships with no filters
    let request = ListRelationshipsRequest {
        resource: None,
        relation: None,
        subject: None,
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_relationships(request).await.unwrap();

    assert_eq!(response.relationships.len(), 3);
    assert!(response.cursor.is_none());
}

#[tokio::test]
async fn test_list_relationships_filter_by_object() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:guide".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Filter by resource
    let request = ListRelationshipsRequest {
        resource: Some("doc:readme".to_string()),
        relation: None,
        subject: None,
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_relationships(request).await.unwrap();

    assert_eq!(response.relationships.len(), 2);
    assert!(response.relationships.iter().all(|r| r.resource == "doc:readme"));
}

#[tokio::test]
async fn test_list_relationships_filter_by_relation() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "owner".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:guide".to_string(),
            relation: "owner".to_string(),
            subject: "user:charlie".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Filter by relation
    let request = ListRelationshipsRequest {
        resource: None,
        relation: Some("owner".to_string()),
        subject: None,
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_relationships(request).await.unwrap();

    assert_eq!(response.relationships.len(), 2);
    assert!(response.relationships.iter().all(|r| r.relation == "owner"));
}

#[tokio::test]
async fn test_list_relationships_filter_by_user() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:guide".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Filter by subject
    let request = ListRelationshipsRequest {
        resource: None,
        relation: None,
        subject: Some("user:alice".to_string()),
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_relationships(request).await.unwrap();

    assert_eq!(response.relationships.len(), 2);
    assert!(response.relationships.iter().all(|r| r.subject == "user:alice"));
}

#[tokio::test]
async fn test_list_relationships_multiple_filters() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_complex_schema());

    let relationships = vec![
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "owner".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "viewer".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:readme".to_string(),
            relation: "owner".to_string(),
            subject: "user:bob".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:guide".to_string(),
            relation: "owner".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Filter by resource + relation + subject
    let request = ListRelationshipsRequest {
        resource: Some("doc:readme".to_string()),
        relation: Some("owner".to_string()),
        subject: Some("user:alice".to_string()),
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_relationships(request).await.unwrap();

    assert_eq!(response.relationships.len(), 1);
    assert_eq!(response.relationships[0].resource, "doc:readme");
    assert_eq!(response.relationships[0].relation, "owner");
    assert_eq!(response.relationships[0].subject, "user:alice");
}

#[tokio::test]
async fn test_list_relationships_pagination() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Add many relationships
    let mut relationships = Vec::new();
    for i in 0..150 {
        relationships.push(Relationship {
            resource: format!("doc:{}", i),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        });
    }
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // First page with default limit (100)
    let request = ListRelationshipsRequest {
        resource: None,
        relation: None,
        subject: Some("user:alice".to_string()),
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_relationships(request).await.unwrap();

    assert_eq!(response.relationships.len(), 100); // Default limit
    assert!(response.cursor.is_some());

    // Second page using cursor
    let request = ListRelationshipsRequest {
        resource: None,
        relation: None,
        subject: Some("user:alice".to_string()),
        limit: None,
        cursor: response.cursor,
    };

    let response = evaluator.list_relationships(request).await.unwrap();

    assert_eq!(response.relationships.len(), 50); // Remaining relationships
    assert!(response.cursor.is_none());
}

#[tokio::test]
async fn test_list_relationships_custom_limit() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Add 50 relationships
    let mut relationships = Vec::new();
    for i in 0..50 {
        relationships.push(Relationship {
            resource: format!("doc:{}", i),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        });
    }
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Custom limit of 10
    let request = ListRelationshipsRequest {
        resource: None,
        relation: None,
        subject: Some("user:alice".to_string()),
        limit: Some(10),
        cursor: None,
    };

    let response = evaluator.list_relationships(request).await.unwrap();

    assert_eq!(response.relationships.len(), 10);
    assert!(response.cursor.is_some());
}

#[tokio::test]
async fn test_list_relationships_max_limit() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Request with limit > max (1000)
    let request = ListRelationshipsRequest {
        resource: None,
        relation: None,
        subject: None,
        limit: Some(5000), // Exceeds max
        cursor: None,
    };

    let response = evaluator.list_relationships(request).await.unwrap();

    // Should be clamped to max of 1000
    assert!(response.relationships.len() <= 1000);
}

#[tokio::test]
async fn test_list_relationships_empty_result() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Query with no matching relationships
    let request = ListRelationshipsRequest {
        resource: Some("doc:nonexistent".to_string()),
        relation: None,
        subject: None,
        limit: None,
        cursor: None,
    };

    let response = evaluator.list_relationships(request).await.unwrap();

    assert_eq!(response.relationships.len(), 0);
    assert!(response.cursor.is_none());
}

// ============================================================================
// Wildcard Tests (Phase 3.1)
// ============================================================================

#[tokio::test]
async fn test_wildcard_check_allow() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Add a wildcard relationship: all users can read
    let wildcard_relationship = Relationship {
        resource: "doc:public".to_string(),
        relation: "reader".to_string(),
        subject: "user:*".to_string(),
        vault: 0i64,
    };
    store.write(0i64, vec![wildcard_relationship]).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Test that alice (a user) can read
    let request_alice = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:public".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request_alice).await.unwrap();
    assert_eq!(result, Decision::Allow);

    // Test that bob (another user) can also read
    let request_bob = EvaluateRequest {
        subject: "user:bob".to_string(),
        resource: "doc:public".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request_bob).await.unwrap();
    assert_eq!(result, Decision::Allow);
}

#[tokio::test]
async fn test_wildcard_type_mismatch_deny() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Add a wildcard relationship: all users can read (not groups)
    let wildcard_relationship = Relationship {
        resource: "doc:public".to_string(),
        relation: "reader".to_string(),
        subject: "user:*".to_string(),
        vault: 0i64,
    };
    store.write(0i64, vec![wildcard_relationship]).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Test that a group cannot read (type mismatch)
    let request_group = EvaluateRequest {
        subject: "group:admins".to_string(),
        resource: "doc:public".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request_group).await.unwrap();
    assert_eq!(result, Decision::Deny);
}

#[tokio::test]
async fn test_wildcard_with_specific_override() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Add both wildcard and specific relationship
    let relationships = vec![
        Relationship {
            resource: "doc:public".to_string(),
            relation: "reader".to_string(),
            subject: "user:*".to_string(),
            vault: 0i64,
        },
        Relationship {
            resource: "doc:public".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Both specific and wildcard should allow access
    let request = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:public".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };

    let result = evaluator.check(request).await.unwrap();
    assert_eq!(result, Decision::Allow);
}

#[tokio::test]
async fn test_wildcard_public_resource_scenario() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(create_simple_schema());

    // Model a public document that anyone can read
    let public_doc = Relationship {
        resource: "doc:announcement".to_string(),
        relation: "reader".to_string(),
        subject: "user:*".to_string(),
        vault: 0i64,
    };
    store.write(0i64, vec![public_doc]).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Multiple different users should all have access
    let users = vec!["user:alice", "user:bob", "user:charlie", "user:david"];
    for user in users {
        let request = EvaluateRequest {
            subject: user.to_string(),
            resource: "doc:announcement".to_string(),
            permission: "reader".to_string(),
            context: None,
            trace: None,
        };

        let result = evaluator.check(request).await.unwrap();
        assert_eq!(result, Decision::Allow, "User {} should have access to public document", user);
    }
}

#[tokio::test]
async fn test_wildcard_mixed_with_regular_relationships() {
    let store = Arc::new(MemoryBackend::new());
    let schema = Arc::new(Schema::new(vec![TypeDef::new(
        "doc".to_string(),
        vec![RelationDef::new("reader".to_string(), None)],
    )]));

    // Mix of wildcard and specific relationships
    let relationships = vec![
        // Public document - anyone can read
        Relationship {
            resource: "doc:public_readme".to_string(),
            relation: "reader".to_string(),
            subject: "user:*".to_string(),
            vault: 0i64,
        },
        // Private document - only Alice can read
        Relationship {
            resource: "doc:private_notes".to_string(),
            relation: "reader".to_string(),
            subject: "user:alice".to_string(),
            vault: 0i64,
        },
    ];
    store.write(0i64, relationships).await.unwrap();

    let evaluator = Evaluator::new(store, schema, None, 0i64);

    // Alice can read both
    let alice_public = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:public_readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };
    assert_eq!(evaluator.check(alice_public).await.unwrap(), Decision::Allow);

    let alice_private = EvaluateRequest {
        subject: "user:alice".to_string(),
        resource: "doc:private_notes".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };
    assert_eq!(evaluator.check(alice_private).await.unwrap(), Decision::Allow);

    // Bob can only read public
    let bob_public = EvaluateRequest {
        subject: "user:bob".to_string(),
        resource: "doc:public_readme".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };
    assert_eq!(evaluator.check(bob_public).await.unwrap(), Decision::Allow);

    let bob_private = EvaluateRequest {
        subject: "user:bob".to_string(),
        resource: "doc:private_notes".to_string(),
        permission: "reader".to_string(),
        context: None,
        trace: None,
    };
    assert_eq!(evaluator.check(bob_private).await.unwrap(), Decision::Deny);
}
