//! Decision tracing for explainability

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::Decision;

/// A complete decision trace showing how a decision was reached
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTrace {
    /// The final decision
    pub decision: Decision,

    /// Root evaluation node
    pub root: EvaluationNode,

    /// Total evaluation time
    pub duration: Duration,

    /// Number of tuples read
    pub tuples_read: usize,

    /// Number of relation evaluations
    pub relations_evaluated: usize,
}

/// A node in the evaluation tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationNode {
    /// Type of evaluation
    pub node_type: NodeType,

    /// Result at this node (true = allow, false = deny)
    pub result: bool,

    /// Child nodes
    pub children: Vec<EvaluationNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    /// Direct tuple check
    DirectCheck {
        object: String,
        relation: String,
        user: String,
    },

    /// Computed userset evaluation
    ComputedUserset {
        relation: String,
        tupleset: String,
    },

    /// Tuple to userset
    TupleToUserset {
        tupleset: String,
        computed: String,
    },

    /// Union operation
    Union,

    /// Intersection operation
    Intersection,

    /// Exclusion operation
    Exclusion,

    /// WASM module execution
    WasmModule {
        module_name: String,
    },
}

impl DecisionTrace {
    pub fn new(decision: Decision, root: EvaluationNode, duration: Duration) -> Self {
        let (tuples_read, relations_evaluated) = Self::count_operations(&root);

        Self {
            decision,
            root,
            duration,
            tuples_read,
            relations_evaluated,
        }
    }

    fn count_operations(node: &EvaluationNode) -> (usize, usize) {
        let mut tuples = match &node.node_type {
            NodeType::DirectCheck { .. } => 1,
            _ => 0,
        };

        let mut relations = match &node.node_type {
            NodeType::ComputedUserset { .. } | NodeType::TupleToUserset { .. } => 1,
            _ => 0,
        };

        for child in &node.children {
            let (t, r) = Self::count_operations(child);
            tuples += t;
            relations += r;
        }

        (tuples, relations)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_creation() {
        let node = EvaluationNode {
            node_type: NodeType::DirectCheck {
                object: "doc:readme".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
            result: true,
            children: Vec::new(),
        };

        let trace = DecisionTrace::new(
            Decision::Allow,
            node,
            Duration::from_micros(100),
        );

        assert_eq!(trace.decision, Decision::Allow);
        assert_eq!(trace.tuples_read, 1);
        assert_eq!(trace.relations_evaluated, 0);
    }

    #[test]
    fn test_trace_counting() {
        let child1 = EvaluationNode {
            node_type: NodeType::DirectCheck {
                object: "doc:readme".to_string(),
                relation: "reader".to_string(),
                user: "user:alice".to_string(),
            },
            result: true,
            children: Vec::new(),
        };

        let child2 = EvaluationNode {
            node_type: NodeType::ComputedUserset {
                relation: "reader".to_string(),
                tupleset: "parent".to_string(),
            },
            result: false,
            children: Vec::new(),
        };

        let root = EvaluationNode {
            node_type: NodeType::Union,
            result: true,
            children: vec![child1, child2],
        };

        let trace = DecisionTrace::new(
            Decision::Allow,
            root,
            Duration::from_micros(100),
        );

        assert_eq!(trace.tuples_read, 1);
        assert_eq!(trace.relations_evaluated, 1);
    }
}
