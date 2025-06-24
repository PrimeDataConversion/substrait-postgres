use anyhow::Result;
use pgrx::pg_sys;
use substrait::proto::Plan;

use super::relations::{
    build_function_extension_map, convert_plan_relation_to_plan_tree_with_context,
};

/// Translates a Substrait plan to a PostgreSQL plan tree without executing it
pub fn translate_substrait_plan(
    plan: &Plan,
) -> Result<(&'static pg_sys::Plan, Vec<String>), Box<dyn std::error::Error + Send + Sync>> {
    pgrx::info!(
        "DEBUG: translate_substrait_plan called with {} relations",
        plan.relations.len()
    );
    eprintln!(
        "DEBUG: translate_substrait_plan called with {} relations",
        plan.relations.len()
    );

    eprintln!("DEBUG: About to build function extension map");
    pgrx::info!("DEBUG: About to build function extension map");

    let function_map = build_function_extension_map(plan.clone());
    eprintln!(
        "DEBUG: Built function map with {} functions",
        function_map.len()
    );
    for (ref_id, func_name) in &function_map {
        eprintln!("  Function ref {}: {}", ref_id, func_name);
    }

    translate_substrait_plan_with_function_map(plan, function_map)
}

/// Translates a Substrait plan to a PostgreSQL plan tree using a pre-built function map
/// This avoids memory context issues when accessing protobuf data
pub fn translate_substrait_plan_with_function_map(
    plan: &Plan,
    function_map: std::collections::HashMap<u32, String>,
) -> Result<(&'static pg_sys::Plan, Vec<String>), Box<dyn std::error::Error + Send + Sync>> {
    pgrx::info!(
        "DEBUG: translate_substrait_plan_with_function_map called with {} plan relations and {} functions",
        plan.relations.len(),
        function_map.len()
    );

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
        eprintln!("DEBUG: About to call convert_plan_relation_to_plan_tree_with_context");
        pgrx::info!("DEBUG: About to call convert_plan_relation_to_plan_tree_with_context");

        let plan_tree = convert_plan_relation_to_plan_tree_with_context(relation, &function_map)?;

        eprintln!("DEBUG: convert_plan_relation_to_plan_tree_with_context returned successfully, plan_tree: {:p}", plan_tree);
        pgrx::info!("DEBUG: convert_plan_relation_to_plan_tree_with_context returned successfully, plan_tree: {:p}", plan_tree);

        // DIAGNOSTIC: Check plan tree structure before nodeToString
        eprintln!("DEBUG: Performing plan tree diagnostics before nodeToString");
        pgrx::info!("DEBUG: Performing plan tree diagnostics before nodeToString");

        // Verify the plan tree pointer is valid
        if plan_tree.is_null() {
            eprintln!("DEBUG: ERROR - plan_tree is null!");
            pgrx::info!("DEBUG: ERROR - plan_tree is null!");
            return Err("Plan tree is null".into());
        }

        eprintln!("DEBUG: plan_tree pointer is valid: {:p}", plan_tree);
        pgrx::info!("DEBUG: plan_tree pointer is valid: {:p}", plan_tree);

        // Check the NodeTag of the root plan
        let node_tag = (*plan_tree).type_;
        eprintln!("DEBUG: Root plan node type: {:?}", node_tag);
        pgrx::info!("DEBUG: Root plan node type: {:?}", node_tag);

        // Check if targetlist is valid
        let targetlist = (*plan_tree).targetlist;
        eprintln!("DEBUG: Target list pointer: {:p}", targetlist);
        pgrx::info!("DEBUG: Target list pointer: {:p}", targetlist);

        if !targetlist.is_null() {
            let list_length = (*targetlist).length;
            eprintln!("DEBUG: Target list length: {}", list_length);
            pgrx::info!("DEBUG: Target list length: {}", list_length);
        }

        eprintln!("DEBUG: About to call nodeToString to verify plan tree structure");
        pgrx::info!("DEBUG: About to call nodeToString to verify plan tree structure");

        // Debug: Print the PostgreSQL plan tree structure
        let plan_str = pg_sys::nodeToString(plan_tree as *const std::ffi::c_void);

        eprintln!("DEBUG: nodeToString returned, plan_str: {:p}", plan_str);
        pgrx::info!("DEBUG: nodeToString returned, plan_str: {:p}", plan_str);

        if !plan_str.is_null() {
            eprintln!("DEBUG: plan_str is not null, creating CStr");
            pgrx::info!("DEBUG: plan_str is not null, creating CStr");

            let plan_cstr = std::ffi::CStr::from_ptr(plan_str);

            eprintln!("DEBUG: CStr created, converting to str");
            pgrx::info!("DEBUG: CStr created, converting to str");

            if let Ok(plan_string) = plan_cstr.to_str() {
                eprintln!("DEBUG: PostgreSQL Plan Tree: {}", plan_string);
                pgrx::info!("PostgreSQL Plan Tree: {}", plan_string);
            }

            eprintln!("DEBUG: About to pfree plan_str");
            pgrx::info!("DEBUG: About to pfree plan_str");

            pg_sys::pfree(plan_str as *mut std::ffi::c_void);

            eprintln!("DEBUG: pfree completed");
            pgrx::info!("DEBUG: pfree completed");
        } else {
            eprintln!("DEBUG: plan_str is null");
            pgrx::info!("DEBUG: plan_str is null");
        }

        eprintln!("DEBUG: About to create return value");
        pgrx::info!("DEBUG: About to create return value");

        let result = (&*plan_tree, column_names);

        eprintln!("DEBUG: Return value created, about to return");
        pgrx::info!("DEBUG: Return value created, about to return");

        Ok(result)
    }
}
