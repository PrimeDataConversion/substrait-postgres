use anyhow::Result;
use pgrx::pg_sys;
use std::collections::HashMap;

use super::expressions::{create_cstring, create_int4_const, create_int8_const, create_text_const};

/// Create a simple values scan node for constant projections
pub unsafe fn create_values_scan_node(
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // For now, just return a simple Result node with no input (constant projection)
    let result_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Result>()) as *mut pg_sys::Result;
    (*result_node).plan.type_ = pg_sys::NodeTag::T_Result;
    (*result_node).plan.lefttree = std::ptr::null_mut();
    (*result_node).plan.righttree = std::ptr::null_mut();
    (*result_node).plan.initPlan = std::ptr::null_mut();
    (*result_node).plan.extParam = std::ptr::null_mut();
    (*result_node).plan.allParam = std::ptr::null_mut();
    (*result_node).plan.startup_cost = 0.0;
    (*result_node).plan.total_cost = 1.0;
    (*result_node).plan.plan_rows = 1.0;
    (*result_node).plan.plan_width = 32;
    (*result_node).plan.parallel_aware = false;
    (*result_node).plan.parallel_safe = true;
    (*result_node).plan.async_capable = false;
    (*result_node).plan.plan_node_id = 0;
    (*result_node).plan.qual = std::ptr::null_mut();
    (*result_node).plan.targetlist = std::ptr::null_mut();

    Ok(result_node as *mut pg_sys::Plan)
}

/// Create a Values scan node with specific target list for literal projections
pub unsafe fn create_values_scan_with_target_list(
    target_list: *mut pg_sys::List,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Create a ValuesScan plan node specifically for literal values
    let values_scan =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::ValuesScan>()) as *mut pg_sys::ValuesScan;

    // Set up the scan portion (for PostgreSQL 15+)
    #[cfg(any(feature = "pg15", feature = "pg16", feature = "pg17"))]
    {
        (*values_scan).scan.plan.type_ = pg_sys::NodeTag::T_ValuesScan;
        (*values_scan).scan.plan.lefttree = std::ptr::null_mut();
        (*values_scan).scan.plan.righttree = std::ptr::null_mut();
        (*values_scan).scan.plan.initPlan = std::ptr::null_mut();
        (*values_scan).scan.plan.extParam = std::ptr::null_mut();
        (*values_scan).scan.plan.allParam = std::ptr::null_mut();
        (*values_scan).scan.plan.startup_cost = 0.0;
        (*values_scan).scan.plan.total_cost = 1.0;
        (*values_scan).scan.plan.plan_rows = 1.0;
        (*values_scan).scan.plan.plan_width = 32;
        (*values_scan).scan.plan.parallel_aware = false;
        (*values_scan).scan.plan.parallel_safe = true;
        (*values_scan).scan.plan.async_capable = false;
        (*values_scan).scan.plan.plan_node_id = 0;
        (*values_scan).scan.plan.qual = std::ptr::null_mut();
        (*values_scan).scan.plan.targetlist = target_list;
        (*values_scan).scan.scanrelid = 0; // No base relation
    }

    // For PostgreSQL 13/14 (different structure)
    #[cfg(any(feature = "pg13", feature = "pg14"))]
    {
        (*values_scan).plan.type_ = pg_sys::NodeTag::T_ValuesScan;
        (*values_scan).plan.lefttree = std::ptr::null_mut();
        (*values_scan).plan.righttree = std::ptr::null_mut();
        (*values_scan).plan.initPlan = std::ptr::null_mut();
        (*values_scan).plan.extParam = std::ptr::null_mut();
        (*values_scan).plan.allParam = std::ptr::null_mut();
        (*values_scan).plan.startup_cost = 0.0;
        (*values_scan).plan.total_cost = 1.0;
        (*values_scan).plan.plan_rows = 1.0;
        (*values_scan).plan.plan_width = 32;
        (*values_scan).plan.parallel_aware = false;
        (*values_scan).plan.parallel_safe = true;
        (*values_scan).plan.async_capable = false;
        (*values_scan).plan.plan_node_id = 0;
        (*values_scan).plan.qual = std::ptr::null_mut();
        (*values_scan).plan.targetlist = target_list;
        (*values_scan).scanrelid = 0; // No base relation
    }

    // Create a values list from the target entries
    let mut values_lists: *mut pg_sys::List = std::ptr::null_mut();
    let mut row_values: *mut pg_sys::List = std::ptr::null_mut();

    // Extract literal values from target entries
    if !target_list.is_null() {
        let list_len = (*target_list).length;
        for i in 0..list_len {
            let target_entry = pg_sys::list_nth(target_list, i) as *mut pg_sys::TargetEntry;
            if !target_entry.is_null() && !(*target_entry).expr.is_null() {
                // Add the expression to the row values
                row_values =
                    pg_sys::lappend(row_values, (*target_entry).expr as *mut std::ffi::c_void);
            }
        }
    }

    // Add this single row to the values lists
    values_lists = pg_sys::lappend(values_lists, row_values as *mut std::ffi::c_void);
    (*values_scan).values_lists = values_lists;

    Ok(values_scan as *mut pg_sys::Plan)
}

/// Create a PostgreSQL SeqScan node for table scans
pub unsafe fn create_seqscan_node(
    table_name: &str,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Look up the table OID by name
    let table_oid = lookup_table_oid(table_name)?;

    // Create a SeqScan node
    let seqscan_node =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::SeqScan>()) as *mut pg_sys::SeqScan;
    // Handle different PostgreSQL versions
    #[cfg(any(feature = "pg13", feature = "pg14"))]
    {
        (*seqscan_node).plan.type_ = pg_sys::NodeTag::T_SeqScan;
        (*seqscan_node).plan.lefttree = std::ptr::null_mut();
        (*seqscan_node).plan.righttree = std::ptr::null_mut();
        (*seqscan_node).plan.initPlan = std::ptr::null_mut();
        (*seqscan_node).plan.extParam = std::ptr::null_mut();
        (*seqscan_node).plan.allParam = std::ptr::null_mut();
        (*seqscan_node).plan.startup_cost = 0.0;
        (*seqscan_node).plan.total_cost = 1000.0;
        (*seqscan_node).plan.plan_rows = 1000.0;
        (*seqscan_node).plan.plan_width = 32;
        (*seqscan_node).plan.parallel_aware = false;
        (*seqscan_node).plan.parallel_safe = true;
        (*seqscan_node).plan.async_capable = false;
        (*seqscan_node).plan.plan_node_id = 0;
        (*seqscan_node).plan.qual = std::ptr::null_mut();
        (*seqscan_node).scanrelid = table_oid.into();

        // Create target list for the table's columns
        let target_list = create_target_list_for_table(table_oid)?;
        (*seqscan_node).plan.targetlist = target_list;
    }
    #[cfg(any(feature = "pg15", feature = "pg16", feature = "pg17"))]
    {
        (*seqscan_node).scan.plan.type_ = pg_sys::NodeTag::T_SeqScan;
        (*seqscan_node).scan.plan.lefttree = std::ptr::null_mut();
        (*seqscan_node).scan.plan.righttree = std::ptr::null_mut();
        (*seqscan_node).scan.plan.initPlan = std::ptr::null_mut();
        (*seqscan_node).scan.plan.extParam = std::ptr::null_mut();
        (*seqscan_node).scan.plan.allParam = std::ptr::null_mut();
        (*seqscan_node).scan.plan.startup_cost = 0.0;
        (*seqscan_node).scan.plan.total_cost = 1000.0;
        (*seqscan_node).scan.plan.plan_rows = 1000.0;
        (*seqscan_node).scan.plan.plan_width = 32;
        (*seqscan_node).scan.plan.parallel_aware = false;
        (*seqscan_node).scan.plan.parallel_safe = true;
        (*seqscan_node).scan.plan.async_capable = false;
        (*seqscan_node).scan.plan.plan_node_id = 0;
        (*seqscan_node).scan.plan.qual = std::ptr::null_mut();
        (*seqscan_node).scan.scanrelid = table_oid.into();

        // Create target list for the table's columns
        let target_list = create_target_list_for_table(table_oid)?;
        (*seqscan_node).scan.plan.targetlist = target_list;
    }

    Ok(seqscan_node as *mut pg_sys::Plan)
}

/// Look up a table OID by name
unsafe fn lookup_table_oid(
    table_name: &str,
) -> Result<pg_sys::Oid, Box<dyn std::error::Error + Send + Sync>> {
    // Try to look up the table in the current search path
    let table_cstring = create_cstring(table_name);

    // Use PostgreSQL's RangeVarGetRelid to look up the table
    let range_var =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::RangeVar>()) as *mut pg_sys::RangeVar;
    (*range_var).relname = table_cstring;
    (*range_var).inh = true;
    (*range_var).relpersistence = pg_sys::RELPERSISTENCE_PERMANENT as i8;

    // Look up the relation OID
    let relation_oid = pg_sys::RangeVarGetRelidExtended(
        range_var,
        pg_sys::NoLock as i32,
        0,
        None,
        std::ptr::null_mut(),
    );

    if relation_oid == pg_sys::InvalidOid {
        return Err(format!("Table '{}' not found", table_name).into());
    }

    Ok(relation_oid)
}

/// Create a target list for a table's columns
unsafe fn create_target_list_for_table(
    table_oid: pg_sys::Oid,
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    // Open the relation to get its tuple descriptor
    let relation = pg_sys::relation_open(table_oid, pg_sys::AccessShareLock as i32);
    if relation.is_null() {
        return Err(format!("Could not open relation with OID {}", table_oid).into());
    }

    let tuple_desc = (*relation).rd_att;
    let num_attrs = (*tuple_desc).natts;

    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();

    // Create target entries for each column
    for i in 0..num_attrs {
        let attr = (*tuple_desc).attrs.as_ptr().offset(i as isize);
        if (*attr).attisdropped {
            continue; // Skip dropped columns
        }

        // Create a Var node for this column
        let var_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Var>()) as *mut pg_sys::Var;
        (*var_node).xpr.type_ = pg_sys::NodeTag::T_Var;
        (*var_node).varno = 1; // Single table scan
        (*var_node).varattno = (*attr).attnum;
        (*var_node).vartype = (*attr).atttypid;
        (*var_node).vartypmod = (*attr).atttypmod;
        (*var_node).varcollid = (*attr).attcollation;
        (*var_node).varlevelsup = 0;

        // Create target entry
        let target_entry =
            pg_sys::palloc0(std::mem::size_of::<pg_sys::TargetEntry>()) as *mut pg_sys::TargetEntry;
        (*target_entry).xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
        (*target_entry).expr = var_node as *mut pg_sys::Expr;
        (*target_entry).resno = (*attr).attnum;

        // Copy the column name
        let attr_name = std::ffi::CStr::from_ptr((*attr).attname.data.as_ptr());
        let attr_name_str = attr_name.to_string_lossy();
        (*target_entry).resname = create_cstring(&attr_name_str);
        (*target_entry).resjunk = false;

        target_list = pg_sys::lappend(target_list, target_entry as *mut std::ffi::c_void);
    }

    // Close the relation
    pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);

    Ok(target_list)
}

/// Create a PostgreSQL Sort plan node from Substrait sort specification
pub unsafe fn create_sort_node(
    input_plan: *mut pg_sys::Plan,
    sorts: &[substrait::proto::SortField],
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Create a Sort plan node
    let sort_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Sort>()) as *mut pg_sys::Sort;
    (*sort_node).plan.type_ = pg_sys::NodeTag::T_Sort;
    (*sort_node).plan.lefttree = input_plan;
    (*sort_node).plan.righttree = std::ptr::null_mut();
    (*sort_node).plan.initPlan = std::ptr::null_mut();
    (*sort_node).plan.extParam = std::ptr::null_mut();
    (*sort_node).plan.allParam = std::ptr::null_mut();
    (*sort_node).plan.startup_cost = 0.0;
    (*sort_node).plan.total_cost = 1000.0;
    (*sort_node).plan.plan_rows = 100.0;
    (*sort_node).plan.plan_width = 32;
    (*sort_node).plan.parallel_aware = false;
    (*sort_node).plan.parallel_safe = true;
    (*sort_node).plan.async_capable = false;
    (*sort_node).plan.plan_node_id = 0;
    (*sort_node).plan.qual = std::ptr::null_mut();

    // For now, pass through the target list from the input plan
    (*sort_node).plan.targetlist = (*input_plan).targetlist;

    // Convert Substrait sort fields to PostgreSQL sort keys
    let mut sort_keys: *mut pg_sys::List = std::ptr::null_mut();
    let mut sort_operators: *mut pg_sys::List = std::ptr::null_mut();
    let mut sort_collations: *mut pg_sys::List = std::ptr::null_mut();
    let mut sort_nulls_first: *mut pg_sys::List = std::ptr::null_mut();

    for (i, sort_field) in sorts.iter().enumerate() {
        // For now, assume we're sorting by column position (simplified)
        // In a full implementation, we'd need to evaluate the sort expression
        let col_index = i + 1; // 1-based indexing for PostgreSQL

        // Add to sort keys list
        sort_keys = pg_sys::lappend_int(sort_keys, col_index as i32);

        // Determine sort operator based on direction
        // For now, use a simple integer comparison operator
        // In a real implementation, we'd need to determine the correct operator based on data type
        let sort_op = match &sort_field.sort_kind {
            Some(substrait::proto::sort_field::SortKind::Direction(dir)) => {
                match *dir {
                    // TODO: Replace 97 with its Postgres enum equivalent.
                    x if x == substrait::proto::sort_field::SortDirection::AscNullsFirst as i32 => {
                        97
                    }
                    x if x == substrait::proto::sort_field::SortDirection::AscNullsLast as i32 => {
                        97
                    } // INT4_LT_OP
                    x if x
                        == substrait::proto::sort_field::SortDirection::DescNullsFirst as i32 =>
                    {
                        521
                    }
                    x if x == substrait::proto::sort_field::SortDirection::DescNullsLast as i32 => {
                        521
                    } // INT4_GT_OP
                    _ => 97, // Default to ascending (INT4_LT_OP)
                }
            }
            _ => 97, // Default to ascending (INT4_LT_OP)
        };
        sort_operators = pg_sys::lappend_oid(sort_operators, pg_sys::Oid::from(sort_op));

        // Add collation (use default for now)
        sort_collations = pg_sys::lappend_oid(sort_collations, pg_sys::DEFAULT_COLLATION_OID);

        // Handle nulls first/last
        let nulls_first = match &sort_field.sort_kind {
            Some(substrait::proto::sort_field::SortKind::Direction(dir)) => {
                match *dir {
                    x if x
                        == substrait::proto::sort_field::SortDirection::DescNullsFirst as i32
                        || x == substrait::proto::sort_field::SortDirection::AscNullsFirst
                            as i32 =>
                    {
                        true
                    }
                    _ => false, // Default to nulls last
                }
            }
            _ => false, // Default to nulls last
        };
        sort_nulls_first = pg_sys::lappend_int(sort_nulls_first, if nulls_first { 1 } else { 0 });
    }

    (*sort_node).numCols = sorts.len() as i32;
    (*sort_node).sortColIdx = if sorts.is_empty() {
        std::ptr::null_mut()
    } else {
        // Allocate and populate the sort column indices array
        let sort_col_array = pg_sys::palloc(sorts.len() * std::mem::size_of::<pg_sys::AttrNumber>())
            as *mut pg_sys::AttrNumber;
        for (i, _sort_field) in sorts.iter().enumerate() {
            // For now, sort by column position (1-based indexing)
            // In a full implementation, we'd evaluate the sort expression to get the actual column
            *sort_col_array.offset(i as isize) = (i + 1) as pg_sys::AttrNumber;
        }
        sort_col_array
    };

    // Set other required sort node fields by converting lists to arrays
    (*sort_node).sortOperators = if sorts.is_empty() {
        std::ptr::null_mut()
    } else {
        // Convert List to array for sortOperators
        let ops_array =
            pg_sys::palloc(sorts.len() * std::mem::size_of::<pg_sys::Oid>()) as *mut pg_sys::Oid;
        for (i, _sort_field) in sorts.iter().enumerate() {
            let op_oid = pg_sys::list_nth_oid(sort_operators, i as i32);
            *ops_array.offset(i as isize) = op_oid;
        }
        ops_array
    };

    (*sort_node).collations = if sorts.is_empty() {
        std::ptr::null_mut()
    } else {
        // Convert List to array for collations
        let collations_array =
            pg_sys::palloc(sorts.len() * std::mem::size_of::<pg_sys::Oid>()) as *mut pg_sys::Oid;
        for (i, _sort_field) in sorts.iter().enumerate() {
            let collation_oid = pg_sys::list_nth_oid(sort_collations, i as i32);
            *collations_array.offset(i as isize) = collation_oid;
        }
        collations_array
    };

    (*sort_node).nullsFirst = if sorts.is_empty() {
        std::ptr::null_mut()
    } else {
        // Convert List to array for nullsFirst
        let nulls_array = pg_sys::palloc(sorts.len() * std::mem::size_of::<bool>()) as *mut bool;
        for (i, _sort_field) in sorts.iter().enumerate() {
            let nulls_first = pg_sys::list_nth_int(sort_nulls_first, i as i32) != 0;
            *nulls_array.offset(i as isize) = nulls_first;
        }
        nulls_array
    };

    Ok(sort_node as *mut pg_sys::Plan)
}

/// Create a PostgreSQL Limit plan node with expression-based offset and count
pub unsafe fn create_limit_node_with_expressions(
    input_plan: *mut pg_sys::Plan,
    offset_expr: Option<*mut pg_sys::Expr>,
    count_expr: Option<*mut pg_sys::Expr>,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Create a Limit plan node
    let limit_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Limit>()) as *mut pg_sys::Limit;
    (*limit_node).plan.type_ = pg_sys::NodeTag::T_Limit;
    (*limit_node).plan.lefttree = input_plan;
    (*limit_node).plan.righttree = std::ptr::null_mut();
    (*limit_node).plan.initPlan = std::ptr::null_mut();
    (*limit_node).plan.extParam = std::ptr::null_mut();
    (*limit_node).plan.allParam = std::ptr::null_mut();
    (*limit_node).plan.startup_cost = 0.0;
    (*limit_node).plan.total_cost = 1000.0;
    (*limit_node).plan.plan_rows = 100.0;
    (*limit_node).plan.plan_width = 32;
    (*limit_node).plan.parallel_aware = false;
    (*limit_node).plan.parallel_safe = true;
    (*limit_node).plan.async_capable = false;
    (*limit_node).plan.plan_node_id = 0;
    (*limit_node).plan.qual = std::ptr::null_mut();

    // Pass through the target list from input
    (*limit_node).plan.targetlist = (*input_plan).targetlist;

    // Set limit count from expression
    (*limit_node).limitCount = if let Some(count_expr) = count_expr {
        count_expr as *mut pg_sys::Node
    } else {
        std::ptr::null_mut()
    };

    // Set limit offset from expression
    (*limit_node).limitOffset = if let Some(offset_expr) = offset_expr {
        offset_expr as *mut pg_sys::Node
    } else {
        std::ptr::null_mut()
    };

    Ok(limit_node as *mut pg_sys::Plan)
}

/// Create a PostgreSQL Filter plan node from Substrait filter specification
pub unsafe fn create_filter_node(
    input_plan: *mut pg_sys::Plan,
    condition_expr: *mut pg_sys::Expr,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // In PostgreSQL, filters are typically implemented as Result nodes with a qual condition
    // For more complex filtering, we might need a custom scan node

    let result_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Result>()) as *mut pg_sys::Result;
    (*result_node).plan.type_ = pg_sys::NodeTag::T_Result;
    (*result_node).plan.lefttree = input_plan;
    (*result_node).plan.righttree = std::ptr::null_mut();
    (*result_node).plan.initPlan = std::ptr::null_mut();
    (*result_node).plan.extParam = std::ptr::null_mut();
    (*result_node).plan.allParam = std::ptr::null_mut();
    (*result_node).plan.startup_cost = 0.0;
    (*result_node).plan.total_cost = 1000.0;
    (*result_node).plan.plan_rows = 100.0;
    (*result_node).plan.plan_width = 32;
    (*result_node).plan.parallel_aware = false;
    (*result_node).plan.parallel_safe = true;
    (*result_node).plan.async_capable = false;
    (*result_node).plan.plan_node_id = 0;

    // Pass through the target list from input
    (*result_node).plan.targetlist = (*input_plan).targetlist;

    // Set the filter condition as a qualification
    let mut qual_list: *mut pg_sys::List = std::ptr::null_mut();
    qual_list = pg_sys::lappend(qual_list, condition_expr as *mut std::ffi::c_void);
    (*result_node).plan.qual = qual_list;

    Ok(result_node as *mut pg_sys::Plan)
}

/// Create a PostgreSQL NestLoop plan node for Cross (Cartesian product) join
pub unsafe fn create_cross_join_node(
    left_plan: *mut pg_sys::Plan,
    right_plan: *mut pg_sys::Plan,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Create a NestLoop plan node for Cartesian product (cross join)
    let nestloop_node =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::NestLoop>()) as *mut pg_sys::NestLoop;
    (*nestloop_node).join.plan.type_ = pg_sys::NodeTag::T_NestLoop;
    (*nestloop_node).join.plan.lefttree = left_plan;
    (*nestloop_node).join.plan.righttree = right_plan;
    (*nestloop_node).join.plan.initPlan = std::ptr::null_mut();
    (*nestloop_node).join.plan.extParam = std::ptr::null_mut();
    (*nestloop_node).join.plan.allParam = std::ptr::null_mut();
    (*nestloop_node).join.plan.startup_cost = 0.0;
    (*nestloop_node).join.plan.total_cost = 1000.0;
    (*nestloop_node).join.plan.plan_rows = 1000.0;
    (*nestloop_node).join.plan.plan_width = 64;
    (*nestloop_node).join.plan.parallel_aware = false;
    (*nestloop_node).join.plan.parallel_safe = true;
    (*nestloop_node).join.plan.async_capable = false;
    (*nestloop_node).join.plan.plan_node_id = 0;
    (*nestloop_node).join.plan.qual = std::ptr::null_mut();

    // Set join type to INNER for cross join
    (*nestloop_node).join.jointype = pg_sys::JoinType::JOIN_INNER;

    // No join conditions for cross join (Cartesian product)
    (*nestloop_node).join.joinqual = std::ptr::null_mut();
    (*nestloop_node).join.plan.qual = std::ptr::null_mut();

    // Create target list combining both input relations
    let combined_target_list = create_combined_target_list(left_plan, right_plan)?;
    (*nestloop_node).join.plan.targetlist = combined_target_list;

    Ok(nestloop_node as *mut pg_sys::Plan)
}

/// Create a combined target list for join operations
unsafe fn create_combined_target_list(
    left_plan: *mut pg_sys::Plan,
    right_plan: *mut pg_sys::Plan,
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    let mut combined_list: *mut pg_sys::List = std::ptr::null_mut();
    let mut resno = 1;

    // Add target entries from left plan
    if !(*left_plan).targetlist.is_null() {
        let left_list = (*left_plan).targetlist;
        let length = (*left_list).length as usize;

        for i in 0..length {
            let target_entry = pg_sys::list_nth(left_list, i as i32) as *mut pg_sys::TargetEntry;

            // Create a copy of the target entry with updated resno and varno
            let new_target_entry = pg_sys::palloc0(std::mem::size_of::<pg_sys::TargetEntry>())
                as *mut pg_sys::TargetEntry;
            *new_target_entry = *target_entry; // Copy the structure
            (*new_target_entry).resno = resno;

            // Update varno in the expression if it's a Var node
            if !(*new_target_entry).expr.is_null() {
                let expr = (*new_target_entry).expr;
                if (*expr).type_ == pg_sys::NodeTag::T_Var {
                    let var_node = expr as *mut pg_sys::Var;
                    (*var_node).varno = 1; // Left relation
                }
            }

            combined_list =
                pg_sys::lappend(combined_list, new_target_entry as *mut std::ffi::c_void);
            resno += 1;
        }
    }

    // Add target entries from right plan
    if !(*right_plan).targetlist.is_null() {
        let right_list = (*right_plan).targetlist;
        let length = (*right_list).length as usize;

        for i in 0..length {
            let target_entry = pg_sys::list_nth(right_list, i as i32) as *mut pg_sys::TargetEntry;

            // Create a copy of the target entry with updated resno and varno
            let new_target_entry = pg_sys::palloc0(std::mem::size_of::<pg_sys::TargetEntry>())
                as *mut pg_sys::TargetEntry;
            *new_target_entry = *target_entry; // Copy the structure
            (*new_target_entry).resno = resno;

            // Update varno in the expression if it's a Var node
            if !(*new_target_entry).expr.is_null() {
                let expr = (*new_target_entry).expr;
                if (*expr).type_ == pg_sys::NodeTag::T_Var {
                    let var_node = expr as *mut pg_sys::Var;
                    (*var_node).varno = 2; // Right relation
                }
            }

            combined_list =
                pg_sys::lappend(combined_list, new_target_entry as *mut std::ffi::c_void);
            resno += 1;
        }
    }

    Ok(combined_list)
}

/// Create a PostgreSQL Agg plan node for aggregate operations with GROUP BY
pub unsafe fn create_aggregate_node(
    input_plan: *mut pg_sys::Plan,
    aggregate: &substrait::proto::AggregateRel,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Create an Agg plan node
    let agg_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Agg>()) as *mut pg_sys::Agg;
    (*agg_node).plan.type_ = pg_sys::NodeTag::T_Agg;
    (*agg_node).plan.lefttree = input_plan;
    (*agg_node).plan.righttree = std::ptr::null_mut();
    (*agg_node).plan.initPlan = std::ptr::null_mut();
    (*agg_node).plan.extParam = std::ptr::null_mut();
    (*agg_node).plan.allParam = std::ptr::null_mut();
    (*agg_node).plan.startup_cost = 0.0;
    (*agg_node).plan.total_cost = 1000.0;
    (*agg_node).plan.plan_rows = 100.0;
    (*agg_node).plan.plan_width = 32;
    (*agg_node).plan.parallel_aware = false;
    (*agg_node).plan.parallel_safe = true;
    (*agg_node).plan.async_capable = false;
    (*agg_node).plan.plan_node_id = 0;
    (*agg_node).plan.qual = std::ptr::null_mut();

    // Determine aggregation strategy (for now, use plain aggregation)
    (*agg_node).aggstrategy = pg_sys::AggStrategy::AGG_PLAIN;

    // Process GROUP BY columns
    let mut num_group_cols = 0;
    let mut group_col_indices: Vec<pg_sys::AttrNumber> = Vec::new();

    if !aggregate.groupings.is_empty() {
        let grouping = &aggregate.groupings[0]; // Take the first grouping set
        for group_expr in &grouping.grouping_expressions {
            if let Some(substrait::proto::expression::RexType::Selection(selection)) =
                &group_expr.rex_type
            {
                if let Some(
                    substrait::proto::expression::field_reference::ReferenceType::DirectReference(
                        direct_ref,
                    ),
                ) = &selection.reference_type
                {
                    if let Some(
                        substrait::proto::expression::reference_segment::ReferenceType::StructField(
                            field,
                        ),
                    ) = &direct_ref.reference_type
                    {
                        group_col_indices.push((field.field + 1) as pg_sys::AttrNumber); // 1-based indexing
                        num_group_cols += 1;
                    }
                }
            }
        }
    }

    (*agg_node).numCols = num_group_cols;
    if num_group_cols > 0 {
        // Allocate memory for group column indices
        let group_cols_ptr =
            pg_sys::palloc(num_group_cols as usize * std::mem::size_of::<pg_sys::AttrNumber>())
                as *mut pg_sys::AttrNumber;
        for (i, &col_idx) in group_col_indices.iter().enumerate() {
            *group_cols_ptr.offset(i as isize) = col_idx;
        }
        (*agg_node).grpColIdx = group_cols_ptr;
    } else {
        (*agg_node).grpColIdx = std::ptr::null_mut();
    }

    // Build target list including GROUP BY columns and aggregate functions
    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();
    let mut resno = 1;

    // Add GROUP BY columns to target list
    for &group_col in &group_col_indices {
        let var_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Var>()) as *mut pg_sys::Var;
        (*var_node).xpr.type_ = pg_sys::NodeTag::T_Var;
        (*var_node).varno = 1; // Input relation number
        (*var_node).varattno = group_col;
        (*var_node).vartype = pg_sys::UNKNOWNOID; // Will be resolved during planning
        (*var_node).vartypmod = -1;
        (*var_node).varcollid = pg_sys::InvalidOid;
        (*var_node).varlevelsup = 0;

        let target_entry =
            pg_sys::palloc0(std::mem::size_of::<pg_sys::TargetEntry>()) as *mut pg_sys::TargetEntry;
        (*target_entry).xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
        (*target_entry).expr = var_node as *mut pg_sys::Expr;
        (*target_entry).resno = resno;
        (*target_entry).resname = create_cstring(&format!("group_col_{}", resno));
        (*target_entry).resjunk = false;

        target_list = pg_sys::lappend(target_list, target_entry as *mut std::ffi::c_void);
        resno += 1;
    }

    // Add aggregate functions to target list
    for measure in &aggregate.measures {
        if let Some(agg_func) = &measure.measure {
            // Create an Aggref node for the aggregate function
            let aggref_node =
                pg_sys::palloc0(std::mem::size_of::<pg_sys::Aggref>()) as *mut pg_sys::Aggref;
            (*aggref_node).xpr.type_ = pg_sys::NodeTag::T_Aggref;

            // Map function reference to PostgreSQL aggregate function OID using function_map
            let function_name = function_map
                .get(&agg_func.function_reference)
                .map(|s| s.as_str())
                .unwrap_or("unknown");

            let agg_func_oid = match function_name {
                "sum:fp64" => pg_sys::Oid::from(2108), // SUM function for float8
                "avg:fp64" => pg_sys::Oid::from(2100), // AVG function for float8
                "count:" => pg_sys::Oid::from(2803),   // COUNT(*) function
                _ => {
                    eprintln!(
                        "DEBUG: Unknown aggregate function: {} (ref={})",
                        function_name, agg_func.function_reference
                    );
                    pg_sys::Oid::from(2803) // Default to COUNT(*)
                }
            };

            (*aggref_node).aggfnoid = agg_func_oid;
            (*aggref_node).aggtype = pg_sys::UNKNOWNOID; // Will be resolved
            (*aggref_node).aggcollid = pg_sys::InvalidOid;
            (*aggref_node).inputcollid = pg_sys::InvalidOid;
            (*aggref_node).aggdirectargs = std::ptr::null_mut();
            (*aggref_node).aggdistinct = std::ptr::null_mut();
            (*aggref_node).aggfilter = std::ptr::null_mut();
            (*aggref_node).aggstar = agg_func.arguments.is_empty(); // COUNT(*) if no arguments
            (*aggref_node).aggvariadic = false;
            (*aggref_node).aggkind = 'n' as i8; // Normal aggregate
            (*aggref_node).agglevelsup = 0;
            (*aggref_node).aggsplit = pg_sys::AggSplit::AGGSPLIT_SIMPLE;

            // Process aggregate function arguments
            let mut agg_args: *mut pg_sys::List = std::ptr::null_mut();
            for arg in &agg_func.arguments {
                if let Some(substrait::proto::function_argument::ArgType::Value(expr)) =
                    &arg.arg_type
                {
                    if let Some(substrait::proto::expression::RexType::Selection(selection)) =
                        &expr.rex_type
                    {
                        if let Some(substrait::proto::expression::field_reference::ReferenceType::DirectReference(direct_ref)) = &selection.reference_type {
                            if let Some(substrait::proto::expression::reference_segment::ReferenceType::StructField(field)) = &direct_ref.reference_type {
                                let var_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Var>()) as *mut pg_sys::Var;
                                (*var_node).xpr.type_ = pg_sys::NodeTag::T_Var;
                                (*var_node).varno = 1;
                                (*var_node).varattno = (field.field + 1) as pg_sys::AttrNumber;
                                (*var_node).vartype = pg_sys::UNKNOWNOID;
                                (*var_node).vartypmod = -1;
                                (*var_node).varcollid = pg_sys::InvalidOid;
                                (*var_node).varlevelsup = 0;

                                agg_args = pg_sys::lappend(agg_args, var_node as *mut std::ffi::c_void);
                            }
                        }
                    }
                }
            }
            (*aggref_node).args = agg_args;

            // Create target entry for the aggregate function
            let target_entry = pg_sys::palloc0(std::mem::size_of::<pg_sys::TargetEntry>())
                as *mut pg_sys::TargetEntry;
            (*target_entry).xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            (*target_entry).expr = aggref_node as *mut pg_sys::Expr;
            (*target_entry).resno = resno;
            (*target_entry).resname = create_cstring(&format!("agg_func_{}", resno));
            (*target_entry).resjunk = false;

            target_list = pg_sys::lappend(target_list, target_entry as *mut std::ffi::c_void);
            resno += 1;
        }
    }

    (*agg_node).plan.targetlist = target_list;

    Ok(agg_node as *mut pg_sys::Plan)
}
