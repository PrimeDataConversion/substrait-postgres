use anyhow::Result;
use pgrx::pg_sys;
use substrait::proto::Plan;

use super::relations::{
    build_function_extension_map, convert_plan_relation_to_plan_tree_with_context,
};

/// Translates a Substrait plan to a PostgreSQL plan tree without executing it
pub fn translate_substrait_plan(
    plan: Plan,
) -> Result<(&'static pg_sys::Plan, Vec<String>), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "DEBUG: translate_substrait_plan called with {} relations",
        plan.relations.len()
    );

    // Build function extension map for reference lookup
    let function_map = build_function_extension_map(&plan);
    eprintln!(
        "DEBUG: Built function map with {} functions",
        function_map.len()
    );
    for (ref_id, func_name) in &function_map {
        eprintln!("  Function ref {}: {}", ref_id, func_name);
    }

    // Validate the plan has exactly one relation
    if plan.relations.len() != 1 {
        return Err(format!(
            "Expected exactly 1 relation, found {}",
            plan.relations.len()
        )
        .into());
    }

    let relation = &plan.relations[0];

    // Extract column names from the root relation
    let column_names =
        if let Some(substrait::proto::plan_rel::RelType::Root(root)) = &relation.rel_type {
            root.names.clone()
        } else {
            vec![]
        };

    // Convert Substrait relation to PostgreSQL plan tree
    unsafe {
        let plan_tree = convert_plan_relation_to_plan_tree_with_context(relation, &function_map)?;

        // Debug: Print the PostgreSQL plan tree structure
        let plan_str = pg_sys::nodeToString(plan_tree as *const std::ffi::c_void);
        if !plan_str.is_null() {
            let plan_cstr = std::ffi::CStr::from_ptr(plan_str);
            if let Ok(plan_string) = plan_cstr.to_str() {
                eprintln!("DEBUG: PostgreSQL Plan Tree: {}", plan_string);
                pgrx::info!("PostgreSQL Plan Tree: {}", plan_string);
            }
            pg_sys::pfree(plan_str as *mut std::ffi::c_void);
        }

        Ok((&*plan_tree, column_names))
    }
}
