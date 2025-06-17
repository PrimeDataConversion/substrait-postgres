use anyhow::Result;
use pgrx::pg_sys;

use crate::plan_translator::{ColumnInfo, ExecutionResult};

/// Helper function to extract column name from a target entry
unsafe fn extract_column_name(target_entry: *mut pg_sys::TargetEntry) -> String {
    if !(*target_entry).resname.is_null() {
        let c_str = std::ffi::CStr::from_ptr((*target_entry).resname);
        c_str.to_string_lossy().to_string()
    } else {
        "result".to_string()
    }
}

/// Executes a PostgreSQL plan tree and returns structured results
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
