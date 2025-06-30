use anyhow::Result;
use pgrx::pg_sys;
use substrait::proto::Plan;

use super::relations::{
    build_function_extension_map, convert_plan_relation_to_plan_tree_with_context,
};

/// Translates a Substrait plan to a PostgreSQL plan tree without executing it
pub fn translate_substrait_plan(
    plan: &Plan,
) -> Result<
    (*mut pg_sys::Plan, Vec<String>, *mut pg_sys::List),
    Box<dyn std::error::Error + Send + Sync>,
> {
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
) -> Result<
    (*mut pg_sys::Plan, Vec<String>, *mut pg_sys::List),
    Box<dyn std::error::Error + Send + Sync>,
> {
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

        let plan_tree =
            convert_plan_relation_to_plan_tree_with_context(relation, &function_map, None)?;

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

        // Build range table by collecting RTEs from the plan tree with error handling
        eprintln!("DEBUG: About to call collect_range_table_from_plan_tree");
        pgrx::info!("DEBUG: About to call collect_range_table_from_plan_tree");

        let range_table = match collect_range_table_from_plan_tree(plan_tree) {
            Ok(rt) => {
                eprintln!("DEBUG: collect_range_table_from_plan_tree succeeded");
                pgrx::info!("DEBUG: collect_range_table_from_plan_tree succeeded");
                rt
            }
            Err(e) => {
                eprintln!("DEBUG: collect_range_table_from_plan_tree failed: {}", e);
                pgrx::info!("DEBUG: collect_range_table_from_plan_tree failed: {}", e);
                return Err(format!("Range table collection failed: {}", e).into());
            }
        };

        eprintln!("DEBUG: Built range table during translation");
        pgrx::info!("DEBUG: Built range table during translation");

        let result = (plan_tree, column_names, range_table);

        eprintln!("DEBUG: Return value created, about to return");
        pgrx::info!("DEBUG: Return value created, about to return");

        Ok(result)
    }
}

/// Collect range table entries from a plan tree
/// This function traverses the plan tree and builds a range table with proper scanrelid assignments
unsafe fn collect_range_table_from_plan_tree(
    plan_tree: *mut pg_sys::Plan,
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    let mut range_table = std::ptr::null_mut::<pg_sys::List>();
    let mut current_scanrelid = 1u32;

    // Traverse the plan tree and collect all SeqScan nodes with error handling
    collect_seqscan_nodes_recursive(plan_tree, &mut range_table, &mut current_scanrelid)?;

    Ok(range_table)
}

/// Recursively traverse plan tree to collect SeqScan nodes and build range table
unsafe fn collect_seqscan_nodes_recursive(
    plan: *mut pg_sys::Plan,
    range_table: &mut *mut pg_sys::List,
    current_scanrelid: &mut u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if plan.is_null() {
        return Ok(());
    }

    match (*plan).type_ {
        pg_sys::NodeTag::T_SeqScan => {
            // Get table OID from plan_node_id (stored during SeqScan creation)
            let table_oid = pg_sys::Oid::from((*plan).plan_node_id as u32);

            eprintln!("DEBUG: Processing SeqScan with table OID: {}", table_oid);
            pgrx::info!("DEBUG: Processing SeqScan with table OID: {}", table_oid);

            // Create range table entry for this table with proper error handling
            let rte =
                super::plan_nodes::create_range_table_entry_from_oid(table_oid).map_err(|e| {
                    eprintln!(
                        "DEBUG: Failed to create RTE for table OID {}: {}",
                        table_oid, e
                    );
                    format!(
                        "Failed to create range table entry for table OID {}: {}",
                        table_oid, e
                    )
                })?;
            *range_table = pg_sys::lappend(*range_table, rte as *mut std::ffi::c_void);

            // Update the SeqScan node to use the correct scanrelid
            let seqscan = plan as *mut pg_sys::SeqScan;

            #[cfg(any(feature = "pg13", feature = "pg14"))]
            {
                (*seqscan).scanrelid = *current_scanrelid;
            }
            #[cfg(any(feature = "pg15", feature = "pg16", feature = "pg17"))]
            {
                (*seqscan).scan.scanrelid = *current_scanrelid;
            }

            eprintln!(
                "DEBUG: Updated SeqScan scanrelid to {} for table OID {}",
                *current_scanrelid, table_oid
            );
            pgrx::info!(
                "DEBUG: Updated SeqScan scanrelid to {} for table OID {}",
                *current_scanrelid,
                table_oid
            );

            *current_scanrelid += 1;
        }
        _ => {
            // For other node types, recurse into child nodes
            if !(*plan).lefttree.is_null() {
                collect_seqscan_nodes_recursive((*plan).lefttree, range_table, current_scanrelid)?;
            }
            if !(*plan).righttree.is_null() {
                collect_seqscan_nodes_recursive((*plan).righttree, range_table, current_scanrelid)?;
            }
        }
    }

    Ok(())
}
