// Module declarations for the plan translator components.
//
// This module is being replaced by query_builder and is slated for removal;
// suppress lints rather than polishing code that is about to be deleted.
#![allow(
    dead_code,
    deprecated,
    non_snake_case,
    unused_doc_comments,
    unexpected_cfgs,
    clippy::all
)]

mod aggregate;
pub mod constants;
pub mod expressions;
pub mod plan_nodes;
pub mod relations;
pub mod schema;
#[cfg(test)]
mod schema_tests;
pub mod translator;
pub mod types;

// Re-export the main public interface
pub use translator::translate_substrait_plan_with_function_map;
pub use types::{ColumnInfo, ExecutionResult};

// Re-export key functions that might be needed externally
pub use relations::build_function_extension_map;
