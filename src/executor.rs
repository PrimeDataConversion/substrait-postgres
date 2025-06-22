use anyhow::Result;
use pgrx::pg_sys;

use crate::plan_translator::{ColumnInfo, ExecutionResult};

/// Executes a PostgreSQL plan tree using PostgreSQL's native executor
/// and returns the tuple descriptor and tuplestore directly.
/// This is the simplified approach that minimizes unpacking/packing operations.
pub unsafe fn execute_plan_directly(
    plan_tree: &pg_sys::Plan,
    column_names: Vec<String>,
) -> Result<
    (*mut pg_sys::TupleDescData, *mut pg_sys::Tuplestorestate),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // Get the tuple descriptor from the plan's target list
    let tupdesc = pg_sys::ExecTypeFromTL((*plan_tree).targetlist);
    if tupdesc.is_null() {
        return Err("Failed to create tuple descriptor from plan".into());
    }

    // Update column names in the tuple descriptor
    let natts = (*tupdesc).natts;
    for i in 0..natts as usize {
        if i < column_names.len() {
            let attr = (*tupdesc).attrs.as_mut_ptr().offset(i as isize);
            // Update the attribute name (carefully to avoid buffer overflow)
            let name_data = (*attr).attname.data.as_mut_ptr();
            let src_len = std::cmp::min(column_names[i].len(), (pg_sys::NAMEDATALEN - 1) as usize);
            std::ptr::copy_nonoverlapping(column_names[i].as_ptr(), name_data as *mut u8, src_len);
            *name_data.offset(src_len as isize) = 0; // null terminate
        }
    }

    // Create a tuplestore to collect results
    let tuplestore = pg_sys::tuplestore_begin_heap(true, false, pg_sys::work_mem);
    if tuplestore.is_null() {
        return Err("Failed to create tuplestore".into());
    }

    // Create executor state and start execution with proper error handling
    let estate = pg_sys::CreateExecutorState();
    if estate.is_null() {
        return Err("Failed to create executor state".into());
    }

    let plan_state = pg_sys::ExecInitNode(
        plan_tree as *const pg_sys::Plan as *mut pg_sys::Plan,
        estate,
        0,
    );
    if plan_state.is_null() {
        pg_sys::FreeExecutorState(estate);
        return Err("Failed to initialize plan node for execution".into());
    }

    // Execute the plan and collect tuples into tuplestore with error handling
    let mut tuple_count = 0;
    loop {
        // Use PostgreSQL's PG_TRY/PG_CATCH mechanism for error handling
        let slot = pg_sys::ExecProcNode(plan_state);
        if slot.is_null() {
            break; // No more tuples
        }

        // Store tuple directly in tuplestore
        pg_sys::tuplestore_puttupleslot(tuplestore, slot);
        tuple_count += 1;

        // Prevent infinite loops and excessive memory usage
        if tuple_count > 1000000 {
            pg_sys::ExecEndNode(plan_state);
            pg_sys::FreeExecutorState(estate);
            return Err("Query returned too many rows (> 1M), execution aborted".into());
        }
    }

    // Clean up executor
    pg_sys::ExecEndNode(plan_state);
    pg_sys::FreeExecutorState(estate);

    Ok((tupdesc, tuplestore))
}

/// Executes a PostgreSQL plan tree and returns the results
pub unsafe fn execute_postgres_plan(
    plan_tree: &pg_sys::Plan,
    column_names: Vec<String>,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
    // Use PostgreSQL's native executor instead of our custom implementation
    execute_plan_with_postgres_executor(plan_tree, column_names)
}

/// Compatibility wrapper that converts PostgreSQL's native execution results
/// back to ExecutionResult format for backward compatibility.
pub unsafe fn execute_plan_with_postgres_executor(
    plan_tree: &pg_sys::Plan,
    column_names: Vec<String>,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
    // Check if this is a ValuesScan node - if so, use the legacy approach
    // because the new direct executor can hang on ValuesScan nodes
    if plan_tree.type_ == pg_sys::NodeTag::T_ValuesScan {
        return execute_plan_tree_structured(plan_tree);
    }

    // For complex plan types (joins, aggregates, etc.), execution is not yet fully supported
    match plan_tree.type_ {
        pg_sys::NodeTag::T_NestLoop
        | pg_sys::NodeTag::T_Sort
        | pg_sys::NodeTag::T_Limit
        | pg_sys::NodeTag::T_Agg => {
            return Err(format!(
                "Execution of complex plan node type {:?} is not yet fully implemented. \
                Translation succeeded but execution is limited to simple projections and table scans.",
                plan_tree.type_
            ).into());
        }
        _ => {}
    }

    // Use the direct execution approach for other node types
    let (tupdesc, tuplestore) = execute_plan_directly(plan_tree, column_names)?;

    // Convert tuple descriptor to ColumnInfo
    let mut columns = Vec::new();
    let natts = (*tupdesc).natts;
    for i in 0..natts {
        let attr = (*tupdesc).attrs.as_ptr().offset(i as isize);
        let name_cstr = std::ffi::CStr::from_ptr((*attr).attname.data.as_ptr());
        let name = name_cstr.to_string_lossy().to_string();

        columns.push(ColumnInfo {
            name,
            type_oid: (*attr).atttypid,
            type_mod: (*attr).atttypmod,
            attr_number: (*attr).attnum,
        });
    }

    // Extract rows from tuplestore
    let mut rows = Vec::new();
    let mut nulls = Vec::new();

    // Set up tuplestore for reading
    let slot = pg_sys::MakeTupleTableSlot(tupdesc, &pg_sys::TTSOpsHeapTuple);
    pg_sys::tuplestore_rescan(tuplestore);

    while pg_sys::tuplestore_gettupleslot(tuplestore, true, false, slot) {
        let mut row_values = Vec::new();
        let mut row_nulls = Vec::new();

        // Extract values from slot
        for i in 1..=natts {
            let mut is_null = false;
            let datum = pg_sys::slot_getattr(slot, i, &mut is_null);
            row_values.push(datum);
            row_nulls.push(is_null);
        }

        rows.push(row_values);
        nulls.push(row_nulls);
    }

    // Clean up slot
    pg_sys::ExecDropSingleTupleTableSlot(slot);

    // Clean up tuplestore
    pg_sys::tuplestore_end(tuplestore);

    Ok(ExecutionResult {
        columns,
        rows,
        nulls,
    })
}

/// Legacy function for backward compatibility - executes a PostgreSQL plan tree
/// and returns structured results using the old approach.
/// This function is deprecated in favor of execute_plan_with_postgres_executor.
pub unsafe fn execute_plan_tree_structured(
    plan: &pg_sys::Plan,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
    // For now, handle simple Result nodes directly by extracting their target list
    match plan.type_ {
        pg_sys::NodeTag::T_Result => {
            let result_node = plan as *const pg_sys::Plan as *const pg_sys::Result;
            let target_list = (*result_node).plan.targetlist;

            if target_list.is_null() {
                return Ok(ExecutionResult {
                    columns: vec![],
                    rows: vec![],
                    nulls: vec![],
                });
            }

            // Extract column information
            let mut columns = Vec::new();
            let list_length = (*target_list).length;

            for i in 0..list_length {
                let target_entry = pg_sys::list_nth(target_list, i) as *mut pg_sys::TargetEntry;
                if !target_entry.is_null() {
                    let col_name = extract_column_name(target_entry);

                    // Get column type from the expression
                    let expr = (*target_entry).expr;
                    let (type_oid, type_mod) =
                        if !expr.is_null() && (*expr).type_ == pg_sys::NodeTag::T_Const {
                            let const_node = expr as *mut pg_sys::Const;
                            let const_type = (*const_node).consttype;

                            // Debug: print the OID we got from the const node
                            eprintln!("DEBUG: Const node type_oid: {}", const_type);

                            // Fail if we have an invalid OID
                            if const_type == pg_sys::InvalidOid || const_type == 0.into() {
                                return Err(format!(
                                    "Invalid type OID {} for const expression",
                                    const_type
                                )
                                .into());
                            }
                            (const_type, (*const_node).consttypmod)
                        } else {
                            return Err(
                                "Expected const expression but found different node type".into()
                            );
                        };

                    // Debug: Verify type OID before creating ColumnInfo
                    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
                        return Err(format!(
                            "About to create ColumnInfo with invalid type OID {} for column '{}' at index {}",
                            type_oid, col_name, i
                        ).into());
                    }

                    // Add explicit logging to track the OID values
                    let column_info = ColumnInfo {
                        name: col_name.clone(),
                        type_oid,
                        type_mod,
                        attr_number: i as pg_sys::AttrNumber + 1, // 1-based attribute numbers
                    };

                    // Log the actual values being stored
                    eprintln!(
                        "DEBUG: Created ColumnInfo - name: '{}', type_oid: {}, type_mod: {}",
                        column_info.name, column_info.type_oid, column_info.type_mod
                    );

                    columns.push(column_info);
                }
            }

            // Extract the single row of data
            let mut row_values = Vec::new();
            let mut row_nulls = Vec::new();

            for i in 0..list_length {
                let target_entry = pg_sys::list_nth(target_list, i) as *mut pg_sys::TargetEntry;
                if !target_entry.is_null() {
                    let expr = (*target_entry).expr;
                    if !expr.is_null() && (*expr).type_ == pg_sys::NodeTag::T_Const {
                        let const_node = expr as *mut pg_sys::Const;
                        let is_null = (*const_node).constisnull;

                        // Don't reprocess datums - just pass them through directly
                        // The SRF handler will do the final extraction in the correct memory context
                        row_values.push((*const_node).constvalue);
                        row_nulls.push(is_null);
                    } else {
                        row_values.push(pg_sys::Datum::null());
                        row_nulls.push(true);
                    }
                }
            }

            Ok(ExecutionResult {
                columns,
                rows: vec![row_values],
                nulls: vec![row_nulls],
            })
        }
        pg_sys::NodeTag::T_ValuesScan => {
            let values_node = plan as *const pg_sys::Plan as *const pg_sys::ValuesScan;

            // Handle different PostgreSQL versions for accessing target list
            #[cfg(any(feature = "pg13", feature = "pg14"))]
            let target_list = (*values_node).plan.targetlist;
            #[cfg(any(feature = "pg15", feature = "pg16", feature = "pg17"))]
            let target_list = (*values_node).scan.plan.targetlist;

            if target_list.is_null() {
                return Ok(ExecutionResult {
                    columns: vec![],
                    rows: vec![],
                    nulls: vec![],
                });
            }

            // Extract column information from target list
            let mut columns = Vec::new();
            let list_length = (*target_list).length;

            for i in 0..list_length {
                let target_entry = pg_sys::list_nth(target_list, i) as *mut pg_sys::TargetEntry;
                if !target_entry.is_null() {
                    let col_name = extract_column_name(target_entry);

                    // For ValuesScan, we need to determine column type from the values_lists
                    // For now, we'll extract the type from the first value in the first row
                    let values_lists = (*values_node).values_lists;
                    if !values_lists.is_null() && (*values_lists).length > 0 {
                        let first_row = pg_sys::list_nth(values_lists, 0) as *mut pg_sys::List;
                        if !first_row.is_null() && i < (*first_row).length {
                            let value_expr = pg_sys::list_nth(first_row, i) as *mut pg_sys::Node;
                            let (type_oid, type_mod) = if !value_expr.is_null()
                                && (*value_expr).type_ == pg_sys::NodeTag::T_Const
                            {
                                let const_node = value_expr as *mut pg_sys::Const;
                                let const_type = (*const_node).consttype;

                                eprintln!("DEBUG: ValuesScan const node type_oid: {}", const_type);

                                if const_type == pg_sys::InvalidOid || const_type == 0.into() {
                                    return Err(format!(
                                        "Invalid type OID {} for const expression in ValuesScan",
                                        const_type
                                    )
                                    .into());
                                }
                                (const_type, (*const_node).consttypmod)
                            } else {
                                return Err("Expected const expression in ValuesScan but found different node type".into());
                            };

                            if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
                                return Err(format!(
                                    "About to create ColumnInfo with invalid type OID {} for ValuesScan column '{}' at index {}",
                                    type_oid, col_name, i
                                ).into());
                            }

                            let column_info = ColumnInfo {
                                name: col_name.clone(),
                                type_oid,
                                type_mod,
                                attr_number: i as pg_sys::AttrNumber + 1,
                            };

                            eprintln!(
                                "DEBUG: Created ValuesScan ColumnInfo - name: '{}', type_oid: {}, type_mod: {}",
                                column_info.name, column_info.type_oid, column_info.type_mod
                            );

                            columns.push(column_info);
                        } else {
                            return Err(
                                format!("No value found for column {} in ValuesScan", i).into()
                            );
                        }
                    } else {
                        return Err("ValuesScan has no values_lists".into());
                    }
                }
            }

            // Extract all rows of data from values_lists
            let mut all_rows = Vec::new();
            let mut all_nulls = Vec::new();

            let values_lists = (*values_node).values_lists;
            if !values_lists.is_null() {
                let num_rows = (*values_lists).length;

                for row_idx in 0..num_rows {
                    let row_list = pg_sys::list_nth(values_lists, row_idx) as *mut pg_sys::List;
                    if !row_list.is_null() {
                        let mut row_values = Vec::new();
                        let mut row_nulls = Vec::new();

                        let num_cols = (*row_list).length;
                        for col_idx in 0..num_cols {
                            let value_expr =
                                pg_sys::list_nth(row_list, col_idx) as *mut pg_sys::Node;
                            if !value_expr.is_null()
                                && (*value_expr).type_ == pg_sys::NodeTag::T_Const
                            {
                                let const_node = value_expr as *mut pg_sys::Const;
                                let is_null = (*const_node).constisnull;

                                row_values.push((*const_node).constvalue);
                                row_nulls.push(is_null);
                            } else {
                                row_values.push(pg_sys::Datum::null());
                                row_nulls.push(true);
                            }
                        }

                        all_rows.push(row_values);
                        all_nulls.push(row_nulls);
                    }
                }
            }

            Ok(ExecutionResult {
                columns,
                rows: all_rows,
                nulls: all_nulls,
            })
        }
        pg_sys::NodeTag::T_SeqScan => {
            let seqscan_node = plan as *const pg_sys::Plan as *const pg_sys::SeqScan;
            // Handle different PostgreSQL versions
            #[cfg(any(feature = "pg13", feature = "pg14"))]
            let (target_list, _relation_oid) = {
                let target_list = (*seqscan_node).plan.targetlist;
                let relation_oid = (*seqscan_node).scanrelid;
                (target_list, relation_oid)
            };
            #[cfg(any(feature = "pg15", feature = "pg16", feature = "pg17"))]
            let (target_list, _relation_oid) = {
                let target_list = (*seqscan_node).scan.plan.targetlist;
                let relation_oid = (*seqscan_node).scan.scanrelid;
                (target_list, relation_oid)
            };

            if target_list.is_null() {
                return Ok(ExecutionResult {
                    columns: vec![],
                    rows: vec![],
                    nulls: vec![],
                });
            }

            // This would normally scan the table, but for now we just return empty results
            // with correct column information
            let mut columns = Vec::new();
            let list_length = (*target_list).length;

            for i in 0..list_length {
                let target_entry = pg_sys::list_nth(target_list, i) as *mut pg_sys::TargetEntry;
                if !target_entry.is_null() {
                    let col_name = extract_column_name(target_entry);

                    // Get column type from the Var node
                    let expr = (*target_entry).expr;
                    let (type_oid, type_mod) = if !expr.is_null()
                        && (*expr).type_ == pg_sys::NodeTag::T_Var
                    {
                        let var_node = expr as *mut pg_sys::Var;
                        let var_type = (*var_node).vartype;
                        // Fail if we have an invalid OID
                        if var_type == pg_sys::InvalidOid || var_type == 0.into() {
                            return Err(format!(
                                "Invalid type OID {} for var expression",
                                var_type
                            )
                            .into());
                        }
                        (var_type, (*var_node).vartypmod)
                    } else {
                        return Err("Expected var expression but found different node type".into());
                    };

                    // Debug: Verify type OID before creating ColumnInfo
                    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
                        return Err(format!(
                            "About to create ColumnInfo with invalid type OID {} for column '{}' at index {}",
                            type_oid, col_name, i
                        ).into());
                    }

                    columns.push(ColumnInfo {
                        name: col_name,
                        type_oid,
                        type_mod,
                        attr_number: i as pg_sys::AttrNumber + 1, // 1-based attribute numbers
                    });
                }
            }

            // Execute table scan
            let rows_and_nulls = execute_table_scan(_relation_oid.into(), &columns)?;

            Ok(ExecutionResult {
                columns,
                rows: rows_and_nulls.0,
                nulls: rows_and_nulls.1,
            })
        }
        _ => Err(format!("Unsupported plan node type: {:?}", plan.type_).into()),
    }
}

/// Helper function to extract column name from a target entry
unsafe fn extract_column_name(target_entry: *mut pg_sys::TargetEntry) -> String {
    if !(*target_entry).resname.is_null() {
        let c_str = std::ffi::CStr::from_ptr((*target_entry).resname);
        c_str.to_string_lossy().to_string()
    } else {
        "result".to_string()
    }
}

type ScanResult =
    Result<(Vec<Vec<pg_sys::Datum>>, Vec<Vec<bool>>), Box<dyn std::error::Error + Send + Sync>>;

unsafe fn execute_table_scan(relation_oid: pg_sys::Oid, columns: &[ColumnInfo]) -> ScanResult {
    // Open the relation
    let relation = pg_sys::relation_open(relation_oid, pg_sys::AccessShareLock as i32);
    if relation.is_null() {
        return Err(format!("Could not open relation with OID {}", relation_oid).into());
    }

    // Start a table scan
    let scan = pg_sys::table_beginscan(
        relation,
        pg_sys::GetActiveSnapshot(),
        0,
        std::ptr::null_mut(),
    );
    if scan.is_null() {
        pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);
        return Err("Could not start table scan".into());
    }

    let mut rows = Vec::new();
    let mut nulls = Vec::new();

    // Scan all tuples
    loop {
        let tuple = pg_sys::heap_getnext(scan, pg_sys::ScanDirection::ForwardScanDirection);
        if tuple.is_null() {
            break; // No more tuples
        }

        let mut row_values = Vec::new();
        let mut row_nulls = Vec::new();

        // Extract values for each column
        for col in columns {
            let mut is_null = false;
            let datum = pg_sys::heap_getattr(
                tuple,
                col.attr_number.into(),
                (*relation).rd_att,
                &mut is_null,
            );

            row_values.push(datum);
            row_nulls.push(is_null);
        }

        rows.push(row_values);
        nulls.push(row_nulls);
    }

    // Clean up
    pg_sys::table_endscan(scan);
    pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);

    Ok((rows, nulls))
}
