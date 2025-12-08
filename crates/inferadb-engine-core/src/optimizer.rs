//! Query optimizer for efficient relation evaluation

use crate::ipl::{RelationDef, RelationExpr};

/// Query plan for evaluating a relation
#[derive(Debug, Clone)]
pub struct QueryPlan {
    /// The steps to execute, in order
    pub steps: Vec<QueryStep>,
    /// Whether steps can be parallelized
    pub parallelizable: bool,
    /// Estimated cost (lower is better)
    pub estimated_cost: u64,
}

/// A single step in a query plan
#[derive(Debug, Clone)]
pub enum QueryStep {
    /// Direct tuple lookup
    DirectLookup { relation: String },
    /// Compute a userset
    ComputeUserset { relation: String, computed_userset: String },
    /// Evaluate a union (can be parallelized)
    Union { branches: Vec<QueryPlan> },
    /// Evaluate an intersection (must check all)
    Intersection { branches: Vec<QueryPlan> },
    /// Evaluate an exclusion (base minus subtract)
    Exclusion { base: Box<QueryPlan>, subtract: Box<QueryPlan> },
    /// Related object userset lookup
    RelatedObjectUserset { relationship_relation: String, computed_userset: String },
}

/// Query planner that analyzes relations and creates optimal execution plans
pub struct QueryPlanner;

impl QueryPlanner {
    /// Create a query plan for evaluating a relation
    pub fn plan_relation(relation: &RelationDef, relation_name: &str) -> QueryPlan {
        let expr = match &relation.expr {
            None => {
                // No expression means direct tuple lookup
                return QueryPlan {
                    steps: vec![QueryStep::DirectLookup { relation: relation_name.to_string() }],
                    parallelizable: false,
                    estimated_cost: 1,
                };
            },
            Some(e) => e,
        };

        match expr {
            RelationExpr::This => {
                // Direct tuple lookup
                QueryPlan {
                    steps: vec![QueryStep::DirectLookup { relation: relation_name.to_string() }],
                    parallelizable: false,
                    estimated_cost: 1, // Direct lookup is cheapest
                }
            },
            RelationExpr::RelationRef { relation: computed_userset } => {
                // Reference to another relation (computed userset)
                QueryPlan {
                    steps: vec![QueryStep::ComputeUserset {
                        relation: relation_name.to_string(),
                        computed_userset: computed_userset.clone(),
                    }],
                    parallelizable: false,
                    estimated_cost: 5, // Requires recursion
                }
            },
            RelationExpr::ComputedUserset { relation: computed_userset, .. } => {
                // Computed userset: `<relation> from <relationship>`
                QueryPlan {
                    steps: vec![QueryStep::ComputeUserset {
                        relation: relation_name.to_string(),
                        computed_userset: computed_userset.clone(),
                    }],
                    parallelizable: false,
                    estimated_cost: 5, // Requires recursion
                }
            },
            RelationExpr::RelatedObjectUserset {
                relationship: relationship_relation,
                computed: computed_userset,
            } => {
                // Related object userset requires two lookups
                QueryPlan {
                    steps: vec![QueryStep::RelatedObjectUserset {
                        relationship_relation: relationship_relation.clone(),
                        computed_userset: computed_userset.clone(),
                    }],
                    parallelizable: false,
                    estimated_cost: 10, // Most expensive operation
                }
            },
            RelationExpr::WasmModule { .. } => {
                // WASM module invocation
                QueryPlan {
                    steps: vec![QueryStep::DirectLookup { relation: relation_name.to_string() }],
                    parallelizable: false,
                    estimated_cost: 8, // WASM is moderately expensive
                }
            },
            RelationExpr::Union(exprs) => {
                // Plan each branch independently
                let mut branches = Vec::new();
                let mut total_cost = 0;

                for expr in exprs {
                    // Create temporary relation for planning
                    let temp_relation =
                        RelationDef { name: relation_name.to_string(), expr: Some(expr.clone()) };
                    let plan = Self::plan_relation(&temp_relation, relation_name);
                    total_cost += plan.estimated_cost;
                    branches.push(plan);
                }

                let avg_cost = if !branches.is_empty() { total_cost / 2 } else { 0 };

                QueryPlan {
                    steps: vec![QueryStep::Union { branches }],
                    parallelizable: true, // Union branches can run in parallel
                    estimated_cost: avg_cost, // Parallelization reduces effective cost
                }
            },
            RelationExpr::Intersection(exprs) => {
                // Plan each branch independently
                let mut branches = Vec::new();
                let mut max_cost = 0;

                for expr in exprs {
                    let temp_relation =
                        RelationDef { name: relation_name.to_string(), expr: Some(expr.clone()) };
                    let plan = Self::plan_relation(&temp_relation, relation_name);
                    max_cost = max_cost.max(plan.estimated_cost);
                    branches.push(plan);
                }

                QueryPlan {
                    steps: vec![QueryStep::Intersection { branches }],
                    parallelizable: true, // Intersection branches can run in parallel
                    estimated_cost: max_cost + 1, // Cost is dominated by slowest branch
                }
            },
            RelationExpr::Exclusion { base, subtract } => {
                // Plan both base and subtract
                let base_relation =
                    RelationDef { name: relation_name.to_string(), expr: Some((**base).clone()) };
                let base_plan = Self::plan_relation(&base_relation, relation_name);

                let subtract_relation = RelationDef {
                    name: relation_name.to_string(),
                    expr: Some((**subtract).clone()),
                };
                let subtract_plan = Self::plan_relation(&subtract_relation, relation_name);

                let total_cost = base_plan.estimated_cost + subtract_plan.estimated_cost;

                QueryPlan {
                    steps: vec![QueryStep::Exclusion {
                        base: Box::new(base_plan),
                        subtract: Box::new(subtract_plan),
                    }],
                    parallelizable: true, // Base and subtract can run in parallel
                    estimated_cost: total_cost / 2,
                }
            },
        }
    }

    /// Analyze a query plan and suggest optimizations
    pub fn analyze_plan(plan: &QueryPlan) -> Vec<OptimizationHint> {
        let mut hints = Vec::new();

        // Check if plan is expensive
        if plan.estimated_cost > 20 {
            hints.push(OptimizationHint::ExpensiveQuery {
                estimated_cost: plan.estimated_cost,
                suggestion: "Consider caching this query result".to_string(),
            });
        }

        // Check for parallelization opportunities
        if plan.parallelizable {
            hints.push(OptimizationHint::ParallelizationOpportunity {
                description: "This query can benefit from parallel evaluation".to_string(),
            });
        }

        // Recursively analyze nested plans
        for step in &plan.steps {
            match step {
                QueryStep::Union { branches } | QueryStep::Intersection { branches } => {
                    for branch in branches {
                        hints.extend(Self::analyze_plan(branch));
                    }
                },
                QueryStep::Exclusion { base, subtract } => {
                    hints.extend(Self::analyze_plan(base));
                    hints.extend(Self::analyze_plan(subtract));
                },
                _ => {},
            }
        }

        hints
    }

    /// Identify tuples that should be prefetched for a query
    pub fn identify_prefetch_candidates(
        resource: &str,
        plan: &QueryPlan,
    ) -> Vec<PrefetchCandidate> {
        let mut candidates = Vec::new();

        for step in &plan.steps {
            match step {
                QueryStep::DirectLookup { relation } => {
                    candidates.push(PrefetchCandidate {
                        resource: resource.to_string(),
                        relation: relation.clone(),
                        priority: PrefetchPriority::High,
                    });
                },
                QueryStep::RelatedObjectUserset { relationship_relation, .. } => {
                    candidates.push(PrefetchCandidate {
                        resource: resource.to_string(),
                        relation: relationship_relation.clone(),
                        priority: PrefetchPriority::High,
                    });
                },
                QueryStep::Union { branches } | QueryStep::Intersection { branches } => {
                    for branch in branches {
                        candidates.extend(Self::identify_prefetch_candidates(resource, branch));
                    }
                },
                QueryStep::Exclusion { base, subtract } => {
                    candidates.extend(Self::identify_prefetch_candidates(resource, base));
                    candidates.extend(Self::identify_prefetch_candidates(resource, subtract));
                },
                _ => {},
            }
        }

        candidates
    }
}

/// Optimization hint for query improvement
#[derive(Debug, Clone, PartialEq)]
pub enum OptimizationHint {
    /// Query is expensive and should be cached
    ExpensiveQuery { estimated_cost: u64, suggestion: String },
    /// Query can benefit from parallel evaluation
    ParallelizationOpportunity { description: String },
}

/// Priority for prefetching
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrefetchPriority {
    Low = 1,
    Medium = 2,
    High = 3,
}

/// A candidate for prefetching
#[derive(Debug, Clone, PartialEq)]
pub struct PrefetchCandidate {
    pub resource: String,
    pub relation: String,
    pub priority: PrefetchPriority,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_direct_lookup() {
        let relation = RelationDef { name: "viewer".to_string(), expr: Some(RelationExpr::This) };

        let plan = QueryPlanner::plan_relation(&relation, "viewer");

        assert_eq!(plan.steps.len(), 1);
        assert!(!plan.parallelizable);
        assert_eq!(plan.estimated_cost, 1);

        match &plan.steps[0] {
            QueryStep::DirectLookup { relation } => {
                assert_eq!(relation, "viewer");
            },
            _ => panic!("Expected DirectLookup step"),
        }
    }

    #[test]
    fn test_plan_computed_userset() {
        let relation = RelationDef {
            name: "viewer".to_string(),
            expr: Some(RelationExpr::RelationRef { relation: "owner".to_string() }),
        };

        let plan = QueryPlanner::plan_relation(&relation, "viewer");

        assert_eq!(plan.steps.len(), 1);
        assert!(!plan.parallelizable);
        assert_eq!(plan.estimated_cost, 5);

        match &plan.steps[0] {
            QueryStep::ComputeUserset { relation, computed_userset } => {
                assert_eq!(relation, "viewer");
                assert_eq!(computed_userset, "owner");
            },
            _ => panic!("Expected ComputeUserset step"),
        }
    }

    #[test]
    fn test_plan_union() {
        let relation = RelationDef {
            name: "viewer".to_string(),
            expr: Some(RelationExpr::Union(vec![
                RelationExpr::This,
                RelationExpr::RelationRef { relation: "owner".to_string() },
            ])),
        };

        let plan = QueryPlanner::plan_relation(&relation, "viewer");

        assert_eq!(plan.steps.len(), 1);
        assert!(plan.parallelizable); // Union can be parallelized

        match &plan.steps[0] {
            QueryStep::Union { branches } => {
                assert_eq!(branches.len(), 2);
            },
            _ => panic!("Expected Union step"),
        }
    }

    #[test]
    fn test_plan_intersection() {
        let relation = RelationDef {
            name: "viewer".to_string(),
            expr: Some(RelationExpr::Intersection(vec![
                RelationExpr::This,
                RelationExpr::RelationRef { relation: "owner".to_string() },
            ])),
        };

        let plan = QueryPlanner::plan_relation(&relation, "viewer");

        assert_eq!(plan.steps.len(), 1);
        assert!(plan.parallelizable); // Intersection can be parallelized

        match &plan.steps[0] {
            QueryStep::Intersection { branches } => {
                assert_eq!(branches.len(), 2);
            },
            _ => panic!("Expected Intersection step"),
        }
    }

    #[test]
    fn test_plan_exclusion() {
        let relation = RelationDef {
            name: "viewer".to_string(),
            expr: Some(RelationExpr::Exclusion {
                base: Box::new(RelationExpr::RelationRef { relation: "owner".to_string() }),
                subtract: Box::new(RelationExpr::This),
            }),
        };

        let plan = QueryPlanner::plan_relation(&relation, "viewer");

        assert_eq!(plan.steps.len(), 1);
        assert!(plan.parallelizable); // Exclusion can be parallelized

        match &plan.steps[0] {
            QueryStep::Exclusion { base, subtract } => {
                assert_eq!(base.estimated_cost, 5);
                assert_eq!(subtract.estimated_cost, 1);
            },
            _ => panic!("Expected Exclusion step"),
        }
    }

    #[test]
    fn test_plan_related_object_userset() {
        let relation = RelationDef {
            name: "viewer".to_string(),
            expr: Some(RelationExpr::RelatedObjectUserset {
                relationship: "parent".to_string(),
                computed: "viewer".to_string(),
            }),
        };

        let plan = QueryPlanner::plan_relation(&relation, "viewer");

        assert_eq!(plan.steps.len(), 1);
        assert!(!plan.parallelizable);
        assert_eq!(plan.estimated_cost, 10); // Most expensive

        match &plan.steps[0] {
            QueryStep::RelatedObjectUserset { relationship_relation, computed_userset } => {
                assert_eq!(relationship_relation, "parent");
                assert_eq!(computed_userset, "viewer");
            },
            _ => panic!("Expected RelatedObjectUserset step"),
        }
    }

    #[test]
    fn test_analyze_cheap_query() {
        let relation = RelationDef { name: "viewer".to_string(), expr: Some(RelationExpr::This) };

        let plan = QueryPlanner::plan_relation(&relation, "viewer");
        let hints = QueryPlanner::analyze_plan(&plan);

        // Cheap query should not generate expensive query hint
        assert!(!hints.iter().any(|h| matches!(h, OptimizationHint::ExpensiveQuery { .. })));
    }

    #[test]
    fn test_analyze_expensive_query() {
        // Create an expensive query (union of related object usersets)
        // With 5 branches @ cost 10 each = 50 / 2 = 25 > 20 threshold
        let relation = RelationDef {
            name: "viewer".to_string(),
            expr: Some(RelationExpr::Union(vec![
                RelationExpr::RelatedObjectUserset {
                    relationship: "parent".to_string(),
                    computed: "viewer".to_string(),
                },
                RelationExpr::RelatedObjectUserset {
                    relationship: "parent".to_string(),
                    computed: "editor".to_string(),
                },
                RelationExpr::RelatedObjectUserset {
                    relationship: "parent".to_string(),
                    computed: "owner".to_string(),
                },
                RelationExpr::RelatedObjectUserset {
                    relationship: "parent".to_string(),
                    computed: "admin".to_string(),
                },
                RelationExpr::RelatedObjectUserset {
                    relationship: "parent".to_string(),
                    computed: "manager".to_string(),
                },
            ])),
        };

        let plan = QueryPlanner::plan_relation(&relation, "viewer");
        let hints = QueryPlanner::analyze_plan(&plan);

        // Should suggest caching
        assert!(hints.iter().any(|h| matches!(h, OptimizationHint::ExpensiveQuery { .. })));

        // Should identify parallelization opportunity
        assert!(
            hints.iter().any(|h| matches!(h, OptimizationHint::ParallelizationOpportunity { .. }))
        );
    }

    #[test]
    fn test_identify_prefetch_candidates() {
        let relation = RelationDef {
            name: "viewer".to_string(),
            expr: Some(RelationExpr::Union(vec![
                RelationExpr::This,
                RelationExpr::RelatedObjectUserset {
                    relationship: "parent".to_string(),
                    computed: "viewer".to_string(),
                },
            ])),
        };

        let plan = QueryPlanner::plan_relation(&relation, "viewer");
        let candidates = QueryPlanner::identify_prefetch_candidates("document:readme", &plan);

        // Should identify both the direct lookup and tuple-to-userset
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .any(|c| c.relation == "viewer" && c.priority == PrefetchPriority::High)
        );
        assert!(
            candidates
                .iter()
                .any(|c| c.relation == "parent" && c.priority == PrefetchPriority::High)
        );
    }

    #[test]
    fn test_cost_estimation() {
        // Direct lookup should be cheapest
        let direct = RelationDef { name: "viewer".to_string(), expr: Some(RelationExpr::This) };
        let direct_plan = QueryPlanner::plan_relation(&direct, "viewer");

        // Computed userset should be more expensive
        let computed = RelationDef {
            name: "viewer".to_string(),
            expr: Some(RelationExpr::RelationRef { relation: "owner".to_string() }),
        };
        let computed_plan = QueryPlanner::plan_relation(&computed, "viewer");

        // Related object userset should be most expensive
        let rou = RelationDef {
            name: "viewer".to_string(),
            expr: Some(RelationExpr::RelatedObjectUserset {
                relationship: "parent".to_string(),
                computed: "viewer".to_string(),
            }),
        };
        let rou_plan = QueryPlanner::plan_relation(&rou, "viewer");

        assert!(direct_plan.estimated_cost < computed_plan.estimated_cost);
        assert!(computed_plan.estimated_cost < rou_plan.estimated_cost);
    }
}
