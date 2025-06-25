// Module declarations for the plan translator components
mod aggregate;
pub mod constants;
pub mod expressions;
pub mod plan_nodes;
pub mod relations;
pub mod translator;
pub mod types;

// Re-export the main public interface
pub use translator::{translate_substrait_plan, translate_substrait_plan_with_function_map};
pub use types::{ColumnInfo, ExecutionResult};

// Re-export key functions that might be needed externally
pub use relations::build_function_extension_map;
