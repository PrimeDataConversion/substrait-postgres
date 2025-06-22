// Module declarations for the plan translator components
pub mod constants;
pub mod expressions;
pub mod plan_nodes;
pub mod relations;
pub mod translator;
pub mod types;

// Re-export the main public interface
pub use translator::translate_substrait_plan;
pub use types::{ColumnInfo, ExecutionResult};

// Re-export key functions that might be needed externally
pub use expressions::{
    convert_expression_to_postgres_with_context, convert_expressions_to_target_list_with_context,
    create_scalar_function_expr_with_context,
};
pub use plan_nodes::{
    create_aggregate_node, create_cross_join_node, create_filter_node,
    create_limit_node_with_expressions, create_seqscan_node, create_sort_node,
    create_values_scan_node, create_values_scan_with_target_list,
};
pub use relations::{
    build_function_extension_map, convert_plan_relation_to_plan_tree_with_context,
    convert_rel_to_plan_tree_with_context,
};
