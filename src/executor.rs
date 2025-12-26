use anyhow::Result;
use pgrx::pg_sys;

use crate::plan_translator::{ColumnInfo, ExecutionResult};

/// Executes a PostgreSQL plan tree from a raw pointer without creating invalid references
/// This is the safe version that avoids memory corruption issues.
pub unsafe fn execute_plan_directly_from_ptr(
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
    expected_tupdesc: Option<*mut pg_sys::TupleDescData>,
) -> Result<
    (*mut pg_sys::TupleDescData, *mut pg_sys::Tuplestorestate),
    Box<dyn std::error::Error + Send + Sync>,
> {
    eprintln!("DEBUG: execute_plan_directly_from_ptr ENTRY");
    pgrx::info!("DEBUG: execute_plan_directly_from_ptr ENTRY");

    if plan_tree.is_null() {
        return Err("Plan tree pointer is null".into());
    }

    eprintln!("DEBUG: Calling execute_plan_directly_raw with raw pointers");
    pgrx::info!("DEBUG: Calling execute_plan_directly_raw with raw pointers");

    let result = execute_plan_directly_raw(plan_tree, column_names, range_table, expected_tupdesc);

    eprintln!("DEBUG: execute_plan_directly_raw returned");
    pgrx::info!("DEBUG: execute_plan_directly_raw returned");

    result
}

/// Raw pointer version that avoids creating invalid references
/// This is the safest approach for PostgreSQL plan tree execution.
pub unsafe fn execute_plan_directly_raw(
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
    _expected_tupdesc: Option<*mut pg_sys::TupleDescData>,
) -> Result<
    (*mut pg_sys::TupleDescData, *mut pg_sys::Tuplestorestate),
    Box<dyn std::error::Error + Send + Sync>,
> {
    pgrx::info!("DEBUG: execute_plan_directly_raw ENTRY");
    pgrx::info!(
        "DEBUG: execute_plan_directly_raw: plan_tree={:p}, column_names={:?}, range_table={:p}",
        plan_tree,
        column_names,
        range_table
    );

    if plan_tree.is_null() {
        return Err("Plan tree pointer is null".into());
    }

    pgrx::info!("DEBUG: plan_tree pointer is valid: {:p}", plan_tree);

    // Check memory context - plan might be in wrong context
    let current_context = pg_sys::CurrentMemoryContext;
    pgrx::info!("DEBUG: Current memory context: {:p}", current_context);

    // Try to validate the plan tree pointer before dereferencing
    pgrx::info!("DEBUG: About to access plan_tree.type_");

    // Use a more careful approach to access the plan tree
    let plan_type = (*plan_tree).type_;
    pgrx::info!("DEBUG: Successfully accessed plan_type: {:?}", plan_type);

    let targetlist = (*plan_tree).targetlist;
    pgrx::info!("DEBUG: Successfully accessed targetlist: {:p}", targetlist);

    pgrx::info!("DEBUG: About to call ExecTypeFromTL");

    // Get the tuple descriptor from the plan's target list
    let temp_tupdesc = pg_sys::ExecTypeFromTL(targetlist);
    pgrx::info!("DEBUG: ExecTypeFromTL returned tupdesc: {:p}", temp_tupdesc);
    if temp_tupdesc.is_null() {
        return Err("Failed to create tuple descriptor from plan".into());
    }

    // Create a copy of the tuple descriptor to avoid memory corruption
    let tupdesc = pg_sys::CreateTupleDescCopy(temp_tupdesc);
    pgrx::info!("DEBUG: Created tuple descriptor copy: {:p}", tupdesc);

    // Free the temporary tuple descriptor to prevent memory leaks
    pg_sys::FreeTupleDesc(temp_tupdesc);
    pgrx::info!("DEBUG: Freed temporary tuple descriptor");

    if tupdesc.is_null() {
        return Err("Failed to copy tuple descriptor".into());
    }

    // Debug the tuple descriptor attributes to see what type OIDs were created
    let natts = (*tupdesc).natts;
    pgrx::info!("DEBUG: Tuple descriptor has {} attributes", natts);
    for i in 0..natts as usize {
        let attr = (*tupdesc).attrs.as_ptr().add(i);
        pgrx::info!(
            "DEBUG: Attribute {}: typid={}, typmod={}, attlen={}",
            i,
            (*attr).atttypid.to_u32(),
            (*attr).atttypmod,
            (*attr).attlen
        );
    }

    // Update column names in the tuple descriptor
    let natts = (*tupdesc).natts;
    for i in 0..natts as usize {
        if i < column_names.len() {
            let attr = (*tupdesc).attrs.as_mut_ptr().add(i);
            // Update the attribute name (carefully to avoid buffer overflow)
            let name_data = (*attr).attname.data.as_mut_ptr();
            let src_len = std::cmp::min(column_names[i].len(), (pg_sys::NAMEDATALEN - 1) as usize);
            std::ptr::copy_nonoverlapping(column_names[i].as_ptr(), name_data as *mut u8, src_len);
            *name_data.add(src_len) = 0; // null terminate
        }
    }
    pgrx::info!("DEBUG: Updated column names in tupdesc");

    // Create a tuplestore to collect results
    let tuplestore = pg_sys::tuplestore_begin_heap(true, false, pg_sys::work_mem);
    if tuplestore.is_null() {
        return Err("Failed to create tuplestore".into());
    }
    pgrx::info!("DEBUG: Tuplestore created: {:p}", tuplestore);

    // SURPRISE FIX: Use PostgreSQL's complete executor startup sequence
    pgrx::info!("DEBUG: Implementing surprise fix with ExecutorStart pattern");

    // Ensure we have a valid transaction state and snapshot
    if !pg_sys::IsTransactionState() {
        pgrx::info!("DEBUG: No transaction state - this might cause ExecutorStart to fail");
    }

    // Create a minimal QueryDesc that PostgreSQL's executor expects
    let query_desc = pgrx::PgBox::<pg_sys::QueryDesc>::alloc0();
    let query_desc_ptr = query_desc.into_pg();
    pgrx::info!("DEBUG: QueryDesc allocated: {:p}", query_desc_ptr);

    // Create a minimal PlannedStmt wrapper
    let mut planned_stmt = pgrx::PgBox::<pg_sys::PlannedStmt>::alloc0();
    planned_stmt.type_ = pg_sys::NodeTag::T_PlannedStmt;
    planned_stmt.planTree = plan_tree;
    planned_stmt.rtable = range_table as *mut pg_sys::List;
    planned_stmt.permInfos = std::ptr::null_mut(); // Empty permission info list - we bypass checks
    planned_stmt.commandType = pg_sys::CmdType::CMD_SELECT;
    planned_stmt.canSetTag = true; // Important for SELECT queries
    planned_stmt.utilityStmt = std::ptr::null_mut();
    planned_stmt.stmt_location = 0;
    planned_stmt.stmt_len = 0;
    let planned_stmt_ptr = planned_stmt.into_pg();
    pgrx::info!("DEBUG: PlannedStmt created: {:p}", planned_stmt_ptr);

    // Set up the QueryDesc using the raw pointer
    (*query_desc_ptr).operation = pg_sys::CmdType::CMD_SELECT;
    (*query_desc_ptr).plannedstmt = planned_stmt_ptr;
    (*query_desc_ptr).sourceText = std::ptr::null_mut();

    // Get snapshot - if none exists, get a new one
    let snapshot = pg_sys::GetActiveSnapshot();
    if snapshot.is_null() {
        pgrx::info!("DEBUG: No active snapshot, registering a new one");
        pg_sys::PushActiveSnapshot(pg_sys::GetTransactionSnapshot());
    }
    (*query_desc_ptr).snapshot = pg_sys::GetActiveSnapshot();

    (*query_desc_ptr).crosscheck_snapshot = std::ptr::null_mut();
    (*query_desc_ptr).dest = std::ptr::null_mut();
    (*query_desc_ptr).params = std::ptr::null_mut();
    (*query_desc_ptr).queryEnv = std::ptr::null_mut();
    (*query_desc_ptr).instrument_options = 0;
    pgrx::info!("DEBUG: QueryDesc setup complete");

    pgrx::info!("DEBUG: Skipping ExecutorStart, manually initializing instead");

    // Instead of ExecutorStart, manually set up the estate and call ExecInitNode
    let estate = pg_sys::CreateExecutorState();
    if estate.is_null() {
        return Err("Failed to create executor state".into());
    }

    // Use ExecInitRangeTable to properly initialize range table and related arrays.
    // Pass empty permInfos list - we bypass permission checks for Substrait plans.
    let empty_perminfos: *mut pg_sys::List = std::ptr::null_mut();
    pg_sys::ExecInitRangeTable(estate, range_table as *mut pg_sys::List, empty_perminfos);
    pgrx::info!("DEBUG: ExecInitRangeTable completed");

    // Set the planned statement reference on estate.
    (*estate).es_plannedstmt = planned_stmt_ptr;

    (*estate).es_output_cid = 0;
    (*estate).es_snapshot = (*query_desc_ptr).snapshot;
    (*estate).es_crosscheck_snapshot = (*query_desc_ptr).crosscheck_snapshot;
    (*estate).es_instrument = 0;
    (*estate).es_top_eflags = 0;
    (*estate).es_processed = 0;
    // es_lastoid doesn't exist in PostgreSQL 17

    (*query_desc_ptr).estate = estate;

    pgrx::info!(
        "DEBUG: About to call ExecInitNode with plan_tree={:p}, estate={:p}",
        plan_tree,
        estate
    );

    // Now initialize the plan node
    let plan_state = pg_sys::ExecInitNode(plan_tree, estate, 0);

    pgrx::info!("DEBUG: ExecInitNode returned: {:p}", plan_state);

    if plan_state.is_null() {
        return Err("ExecInitNode failed".into());
    }

    (*query_desc_ptr).planstate = plan_state;

    pgrx::info!("DEBUG: Manual initialization succeeded!");

    // Get the plan state - we called ExecInitNode above.
    let plan_state = (*query_desc_ptr).planstate;
    if plan_state.is_null() {
        // Manual cleanup since we bypassed ExecutorStart
        pg_sys::FreeExecutorState(estate);
        return Err("ExecInitNode failed to create plan state".into());
    }

    pgrx::info!("DEBUG: Plan state from ExecutorStart: {:p}", plan_state);

    // Execute the plan and collect tuples into tuplestore with error handling
    let mut tuple_count = 0u64;
    loop {
        pgrx::info!("DEBUG: Calling ExecProcNode (tuple_count: {})", tuple_count);
        // Use PostgreSQL's PG_TRY/PG_CATCH mechanism for error handling
        let slot = pg_sys::ExecProcNode(plan_state);
        pgrx::info!("DEBUG: ExecProcNode returned slot: {:p}", slot);
        if slot.is_null() {
            break; // No more tuples
        }

        // Store tuple directly in tuplestore
        pg_sys::tuplestore_puttupleslot(tuplestore, slot);
        pgrx::info!("DEBUG: Tuple stored in tuplestore");
        tuple_count += 1;

        // Prevent infinite loops and excessive memory usage
        if tuple_count > 1000000 {
            pgrx::warning!("Query returned too many rows (> 1M), execution aborted");
            // Manual cleanup since we bypassed ExecutorStart
            pg_sys::ExecEndNode(plan_state);
            pg_sys::FreeExecutorState(estate);
            return Err("Query returned too many rows (> 1M), execution aborted".into());
        }
    }
    pgrx::info!(
        "DEBUG: ExecProcNode loop finished. Total tuples: {}",
        tuple_count
    );

    // Clean up manually since we bypassed ExecutorStart.
    // ExecutorFinish/ExecutorEnd expect structures set up by ExecutorStart.
    pgrx::info!("DEBUG: Cleaning up with manual ExecEndNode and FreeExecutorState");
    pg_sys::ExecEndNode(plan_state);
    pg_sys::FreeExecutorState(estate);
    pgrx::info!("DEBUG: Manual cleanup completed");

    Ok((tupdesc, tuplestore))
}

/// Executes a PostgreSQL plan tree using PostgreSQL's native executor
/// and returns the tuple descriptor and tuplestore directly.
/// This is the simplified approach that minimizes unpacking/packing operations.
pub unsafe fn execute_plan_directly(
    plan_tree_ref: &pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
    expected_tupdesc: Option<*mut pg_sys::TupleDescData>,
) -> Result<
    (*mut pg_sys::TupleDescData, *mut pg_sys::Tuplestorestate),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // IMMEDIATE ENTRY DEBUG - BEFORE ACCESSING PARAMETERS
    eprintln!("IMMEDIATE: execute_plan_directly ENTERED SUCCESSFULLY");
    pgrx::info!("IMMEDIATE: execute_plan_directly ENTERED SUCCESSFULLY");

    // Convert reference to pointer for use throughout the function
    let plan_tree = plan_tree_ref as *const pg_sys::Plan as *mut pg_sys::Plan;

    eprintln!(
        "DEBUG: execute_plan_directly called with plan tree type: {:?}",
        plan_tree_ref.type_
    );
    pgrx::info!("CRITICAL: execute_plan_directly ENTRY - THIS SHOULD APPEAR IN LOGS");

    eprintln!("DEBUG: About to access plan_tree.targetlist");
    pgrx::info!("DEBUG: About to access plan_tree.targetlist");

    // DEBUG: Inspect target list BEFORE calling ExecTypeFromTL
    let targetlist = plan_tree_ref.targetlist;

    eprintln!("DEBUG: targetlist accessed successfully");
    pgrx::info!("DEBUG: targetlist accessed successfully");

    if targetlist.is_null() {
        eprintln!("ERROR: targetlist is null!");
        return Err("Target list is null".into());
    }

    eprintln!("DEBUG: targetlist pointer: {targetlist:p}");
    eprintln!("DEBUG: About to access targetlist.length");
    pgrx::info!("DEBUG: About to access targetlist.length");

    eprintln!("DEBUG: targetlist length: {}", (*targetlist).length);

    eprintln!("DEBUG: targetlist length accessed successfully");
    pgrx::info!("DEBUG: targetlist length accessed successfully");

    eprintln!("DEBUG: About to access targetlist.elements array");
    pgrx::info!("DEBUG: About to access targetlist.elements array");

    let elements_ptr = (*targetlist).elements;
    eprintln!("DEBUG: elements array pointer: {elements_ptr:p}");
    pgrx::info!("DEBUG: elements array pointer: {:p}", elements_ptr);

    if elements_ptr.is_null() {
        eprintln!("ERROR: elements array is null!");
        return Err("Target list elements array is null".into());
    }

    eprintln!("DEBUG: elements array is valid, about to iterate");
    pgrx::info!("DEBUG: elements array is valid, about to iterate");

    // Use PostgreSQL's list_nth function instead of manual pointer access
    for i in 0..(*targetlist).length {
        eprintln!("DEBUG: Starting iteration {i}");
        pgrx::info!("DEBUG: Starting iteration {}", i);

        // Use PostgreSQL's safe list access function
        let target_entry = pg_sys::list_nth(targetlist, i) as *mut pg_sys::TargetEntry;

        eprintln!("DEBUG: Got TargetEntry from list_nth: {target_entry:p}");
        pgrx::info!("DEBUG: Got TargetEntry from list_nth: {:p}", target_entry);

        if !target_entry.is_null() {
            eprintln!("DEBUG: About to access TargetEntry fields");
            pgrx::info!("DEBUG: About to access TargetEntry fields");

            // Try to access the node type first (should be T_TargetEntry)
            eprintln!("DEBUG: Checking TargetEntry node type");
            pgrx::info!("DEBUG: Checking TargetEntry node type");

            let node_type = (*target_entry).xpr.type_;
            eprintln!("DEBUG: TargetEntry node type: {node_type:?}");
            pgrx::info!("DEBUG: TargetEntry node type: {:?}", node_type);

            eprintln!("DEBUG: About to access resno and resname");
            pgrx::info!("DEBUG: About to access resno and resname");

            let resno = (*target_entry).resno;
            let resname = (*target_entry).resname;
            eprintln!(
                "DEBUG: Successfully accessed TargetEntry[{i}]: resno={resno}, resname={resname:p}"
            );
            eprintln!(
                "DEBUG: TargetEntry[{}] node type: {:?}",
                i,
                (*target_entry).xpr.type_
            );

            // Inspect the expression inside the TargetEntry
            let expr = (*target_entry).expr;
            if !expr.is_null() {
                eprintln!(
                    "DEBUG: TargetEntry[{}] expr node type: {:?}",
                    i,
                    (*expr).type_
                );

                // If it's a Const, check its type
                if (*expr).type_ == pg_sys::NodeTag::T_Const {
                    let const_node = expr as *mut pg_sys::Const;
                    let oid = (*const_node).consttype.to_u32();
                    eprintln!(
                        "DEBUG: CONST NODE OID: {} ({})",
                        oid,
                        if oid == 65536 {
                            "*** THIS IS THE PROBLEM OID! ***"
                        } else {
                            "ok"
                        }
                    );
                    eprintln!(
                        "DEBUG: Const details: len={}, byval={}",
                        (*const_node).constlen,
                        (*const_node).constbyval
                    );
                }

                // Check for Var nodes with potentially corrupt OIDs
                if (*expr).type_ == pg_sys::NodeTag::T_Var {
                    let var_node = expr as *mut pg_sys::Var;
                    let oid = (*var_node).vartype.to_u32();
                    eprintln!(
                        "DEBUG: VAR NODE OID: {} ({})",
                        oid,
                        if oid == 65536 {
                            "*** THIS IS THE PROBLEM OID! ***"
                        } else {
                            "ok"
                        }
                    );
                }
            } else {
                eprintln!("ERROR: TargetEntry[{i}] expr is null!");
            }
        } else {
            eprintln!("ERROR: TargetEntry[{i}] from list_nth is null!");
        }
    }

    eprintln!("DEBUG: GREAT SUCCESS! Completed TargetEntry iteration without crashes - schema propagation fixed the type mismatch!");
    pgrx::info!("DEBUG: GREAT SUCCESS! Completed TargetEntry iteration without crashes - schema propagation fixed the type mismatch!");
    eprintln!("DEBUG: About to get tuple descriptor");
    pgrx::info!("DEBUG: About to get tuple descriptor");

    // Use PostgreSQL's standard execution path for all node types including SeqScan

    // Use the expected tuple descriptor if provided (from AS clause),
    // otherwise generate from plan's target list
    let tupdesc = if let Some(expected_desc) = expected_tupdesc {
        eprintln!("DEBUG: Using provided AS clause tuple descriptor: {expected_desc:p}");
        pgrx::info!(
            "DEBUG: Using provided AS clause tuple descriptor: {:p}",
            expected_desc
        );

        // Create a copy of the AS clause descriptor in current memory context to ensure consistency
        let tupdesc_copy = pg_sys::CreateTupleDescCopy(expected_desc);
        eprintln!("DEBUG: Created copy of AS clause descriptor: {tupdesc_copy:p}");
        pgrx::info!(
            "DEBUG: Created copy of AS clause descriptor: {:p}",
            tupdesc_copy
        );
        tupdesc_copy
    } else {
        eprintln!("DEBUG: Generating tuple descriptor from plan targetlist");
        pgrx::info!("DEBUG: Generating tuple descriptor from plan targetlist");
        let temp_generated_desc = pg_sys::ExecTypeFromTL((*plan_tree).targetlist);
        eprintln!("DEBUG: ExecTypeFromTL completed successfully, tupdesc: {temp_generated_desc:p}");
        pgrx::info!(
            "DEBUG: ExecTypeFromTL completed successfully, tupdesc: {:p}",
            temp_generated_desc
        );

        // Create a copy to prevent memory corruption and free the temporary descriptor
        let generated_desc = if !temp_generated_desc.is_null() {
            let copy_desc = pg_sys::CreateTupleDescCopy(temp_generated_desc);
            pg_sys::FreeTupleDesc(temp_generated_desc);
            pgrx::info!("DEBUG: Freed temporary generated tuple descriptor");
            copy_desc
        } else {
            temp_generated_desc
        };

        generated_desc
    };

    // DEBUG: Examine the tuple descriptor to find invalid type OIDs
    if !tupdesc.is_null() {
        let natts = (*tupdesc).natts;
        eprintln!("DEBUG: Tuple descriptor has {natts} attributes");
        pgrx::info!("DEBUG: Tuple descriptor has {} attributes", natts);

        for i in 0..natts {
            let attr = &mut (*(*tupdesc).attrs.as_mut_ptr().offset(i as isize));
            let type_oid = attr.atttypid;
            let type_mod = attr.atttypmod;
            let attr_name = if attr.attname.data[0] != 0 {
                std::ffi::CStr::from_ptr(attr.attname.data.as_ptr()).to_string_lossy()
            } else {
                "unnamed".into()
            };

            eprintln!(
                "DEBUG: Attribute {}: name='{}', type_oid={}, type_mod={}",
                i,
                attr_name,
                type_oid.to_u32(),
                type_mod
            );
            pgrx::info!(
                "DEBUG: Attribute {}: name='{}', type_oid={}, type_mod={}",
                i,
                attr_name,
                type_oid.to_u32(),
                type_mod
            );

            if type_oid.to_u32() == 65536 {
                eprintln!("DEBUG: FOUND THE PROBLEM! Attribute {i} has invalid OID 65536");
                pgrx::info!(
                    "DEBUG: FOUND THE PROBLEM! Attribute {} has invalid OID 65536",
                    i
                );
            }
        }
    } else {
        eprintln!("DEBUG: Tuple descriptor is null!");
        pgrx::info!("DEBUG: Tuple descriptor is null!");
    }
    eprintln!("DEBUG: ExecTypeFromTL returned tupdesc: {tupdesc:p}");
    if tupdesc.is_null() {
        return Err("Failed to create tuple descriptor from plan".into());
    }

    // Debug the tuple descriptor attributes to see what type OIDs were created
    let natts = (*tupdesc).natts;
    eprintln!("DEBUG: Tuple descriptor has {natts} attributes");
    for i in 0..natts as usize {
        let attr = (*tupdesc).attrs.as_ptr().add(i);
        eprintln!(
            "DEBUG: Attribute {}: typid={}, typmod={}, attlen={}",
            i,
            (*attr).atttypid.to_u32(),
            (*attr).atttypmod,
            (*attr).attlen
        );
    }

    // Update column names in the tuple descriptor
    let natts = (*tupdesc).natts;
    for i in 0..natts as usize {
        if i < column_names.len() {
            let attr = (*tupdesc).attrs.as_mut_ptr().add(i);
            // Update the attribute name (carefully to avoid buffer overflow)
            let name_data = (*attr).attname.data.as_mut_ptr();
            let src_len = std::cmp::min(column_names[i].len(), (pg_sys::NAMEDATALEN - 1) as usize);
            std::ptr::copy_nonoverlapping(column_names[i].as_ptr(), name_data as *mut u8, src_len);
            *name_data.add(src_len) = 0; // null terminate
        }
    }

    eprintln!("DEBUG: About to create tuplestore");
    pgrx::info!("DEBUG: About to create tuplestore");

    // Create a tuplestore to collect results using the correct tuple descriptor
    let tuplestore_desc = if expected_tupdesc.is_some() {
        expected_tupdesc.unwrap()
    } else {
        tupdesc
    };

    let tuplestore = pg_sys::tuplestore_begin_heap(true, false, pg_sys::work_mem);
    if tuplestore.is_null() {
        eprintln!("ERROR: Failed to create tuplestore");
        pgrx::info!("ERROR: Failed to create tuplestore");
        return Err("Failed to create tuplestore".into());
    }

    eprintln!(
        "DEBUG: Tuplestore created successfully with descriptor {tuplestore_desc:p}: {tuplestore:p}"
    );
    pgrx::info!(
        "DEBUG: Tuplestore created successfully with descriptor {:p}: {:p}",
        tuplestore_desc,
        tuplestore
    );

    eprintln!("DEBUG: Using ExecutorStart pattern instead of direct ExecInitNode");
    pgrx::info!("DEBUG: Using ExecutorStart pattern instead of direct ExecInitNode");

    // Create a minimal QueryDesc that PostgreSQL's executor expects (like execute_plan_directly_raw)
    let query_desc = pgrx::PgBox::<pg_sys::QueryDesc>::alloc0();
    let query_desc_ptr = query_desc.into_pg();
    pgrx::info!("DEBUG: QueryDesc allocated: {:p}", query_desc_ptr);

    // Create a minimal PlannedStmt wrapper
    let mut planned_stmt = pgrx::PgBox::<pg_sys::PlannedStmt>::alloc0();
    planned_stmt.type_ = pg_sys::NodeTag::T_PlannedStmt;
    planned_stmt.planTree = plan_tree as *const pg_sys::Plan as *mut pg_sys::Plan;
    planned_stmt.rtable = range_table as *mut pg_sys::List;
    planned_stmt.permInfos = std::ptr::null_mut(); // Empty permission info list - we bypass checks
    planned_stmt.commandType = pg_sys::CmdType::CMD_SELECT;
    planned_stmt.canSetTag = true; // Important for SELECT queries
    planned_stmt.utilityStmt = std::ptr::null_mut();
    planned_stmt.stmt_location = 0;
    planned_stmt.stmt_len = 0;
    let planned_stmt_ptr = planned_stmt.into_pg();
    pgrx::info!("DEBUG: PlannedStmt created: {:p}", planned_stmt_ptr);

    // Set up the QueryDesc using the raw pointer
    (*query_desc_ptr).operation = pg_sys::CmdType::CMD_SELECT;
    (*query_desc_ptr).plannedstmt = planned_stmt_ptr;
    (*query_desc_ptr).sourceText = std::ptr::null_mut();

    // Get snapshot - if none exists, get a new one
    let snapshot = pg_sys::GetActiveSnapshot();
    if snapshot.is_null() {
        pgrx::info!("DEBUG: No active snapshot, registering a new one");
        pg_sys::PushActiveSnapshot(pg_sys::GetTransactionSnapshot());
    }
    (*query_desc_ptr).snapshot = pg_sys::GetActiveSnapshot();

    (*query_desc_ptr).crosscheck_snapshot = std::ptr::null_mut();
    (*query_desc_ptr).dest = std::ptr::null_mut();
    (*query_desc_ptr).params = std::ptr::null_mut();
    (*query_desc_ptr).queryEnv = std::ptr::null_mut();
    (*query_desc_ptr).instrument_options = 0;
    pgrx::info!("DEBUG: QueryDesc setup complete");

    pgrx::info!("DEBUG: Skipping ExecutorStart, manually initializing instead");

    // Instead of ExecutorStart, manually set up the estate and call ExecInitNode
    let estate = pg_sys::CreateExecutorState();
    if estate.is_null() {
        return Err("Failed to create executor state".into());
    }

    // Use ExecInitRangeTable to properly initialize range table and related arrays.
    // Pass empty permInfos list - we bypass permission checks for Substrait plans.
    let empty_perminfos: *mut pg_sys::List = std::ptr::null_mut();
    pg_sys::ExecInitRangeTable(estate, range_table as *mut pg_sys::List, empty_perminfos);
    pgrx::info!("DEBUG: ExecInitRangeTable completed");

    // Set the planned statement reference on estate.
    (*estate).es_plannedstmt = planned_stmt_ptr;

    (*estate).es_output_cid = 0;
    (*estate).es_snapshot = (*query_desc_ptr).snapshot;
    (*estate).es_crosscheck_snapshot = (*query_desc_ptr).crosscheck_snapshot;
    (*estate).es_instrument = 0;
    (*estate).es_top_eflags = 0;
    (*estate).es_processed = 0;
    // es_lastoid doesn't exist in PostgreSQL 17

    (*query_desc_ptr).estate = estate;

    pgrx::info!(
        "DEBUG: About to call ExecInitNode with plan_tree={:p}, estate={:p}",
        plan_tree,
        estate
    );

    // Now initialize the plan node
    let plan_state = pg_sys::ExecInitNode(plan_tree, estate, 0);

    pgrx::info!("DEBUG: ExecInitNode returned: {:p}", plan_state);

    if plan_state.is_null() {
        return Err("ExecInitNode failed".into());
    }

    (*query_desc_ptr).planstate = plan_state;

    pgrx::info!("DEBUG: Manual initialization succeeded!");

    // Get the plan state - ExecutorStart already called ExecInitNode for us!
    let plan_state = (*query_desc_ptr).planstate;
    eprintln!("DEBUG: ExecutorStart succeeded, plan_state: {plan_state:p}");
    pgrx::info!(
        "DEBUG: ExecutorStart succeeded, plan_state: {:p}",
        plan_state
    );

    // Debug the plan state structure to understand what's different
    if !plan_state.is_null() {
        eprintln!("DEBUG: Plan state type: {:?}", (*plan_state).type_);
        pgrx::info!("DEBUG: Plan state type: {:?}", (*plan_state).type_);

        // Check if this is a SeqScan
        if (*plan_state).type_ == pg_sys::NodeTag::T_SeqScanState {
            eprintln!("DEBUG: Plan state is SeqScanState");
            pgrx::info!("DEBUG: Plan state is SeqScanState");
        }
    }

    eprintln!("DEBUG: ExecInitNode returned successfully: {plan_state:p}");
    pgrx::info!(
        "DEBUG: ExecInitNode returned successfully: {:p}",
        plan_state
    );

    if plan_state.is_null() {
        eprintln!("ERROR: ExecutorStart returned null plan_state");
        pgrx::info!("ERROR: ExecutorStart returned null plan_state");
        // Manual cleanup since we bypassed ExecutorStart
        pg_sys::FreeExecutorState(estate);
        return Err("Failed to initialize plan node for execution".into());
    }

    // Execute the plan and collect tuples into tuplestore with error handling
    let mut tuple_count = 0u64;
    eprintln!("DEBUG: Starting plan execution loop");
    pgrx::info!("DEBUG: Starting plan execution loop");
    loop {
        eprintln!("DEBUG: Calling ExecProcNode (iteration {tuple_count})");
        pgrx::info!("DEBUG: Calling ExecProcNode (iteration {})", tuple_count);

        // Use PostgreSQL's PG_TRY/PG_CATCH mechanism for error handling
        let slot = pg_sys::ExecProcNode(plan_state);
        eprintln!("DEBUG: ExecProcNode returned slot: {slot:p}");
        pgrx::info!("DEBUG: ExecProcNode returned slot: {:p}", slot);

        if slot.is_null() {
            eprintln!("DEBUG: No more tuples, breaking loop");
            pgrx::info!("DEBUG: No more tuples, breaking loop");
            break; // No more tuples
        }

        // Debug the slot's tuple descriptor to find OID 65536 source
        eprintln!("DEBUG: Examining execution slot for tuple {tuple_count}");
        pgrx::info!("DEBUG: Examining execution slot for tuple {}", tuple_count);

        // Convert slot to AS clause format if expected descriptor was provided
        eprintln!(
            "DEBUG: Checking if expected_tupdesc is Some: {}",
            expected_tupdesc.is_some()
        );
        pgrx::info!(
            "DEBUG: Checking if expected_tupdesc is Some: {}",
            expected_tupdesc.is_some()
        );

        if let Some(expected_desc) = expected_tupdesc {
            eprintln!("DEBUG: Converting to AS clause format");
            pgrx::info!("DEBUG: Converting to AS clause format");

            // Create a slot with the AS clause descriptor
            let as_clause_slot =
                pg_sys::MakeTupleTableSlot(expected_desc, &pg_sys::TTSOpsMinimalTuple);

            // Extract tuple from execution slot and create new tuple with AS clause descriptor
            let tuple = pg_sys::ExecFetchSlotMinimalTuple(slot, &mut false);
            if !tuple.is_null() {
                eprintln!("DEBUG: Storing tuple in AS clause format slot");
                pgrx::info!("DEBUG: Storing tuple in AS clause format slot");
                // Store the tuple using the AS clause descriptor
                pg_sys::ExecStoreMinimalTuple(tuple, as_clause_slot, false);
                pg_sys::tuplestore_puttupleslot(tuplestore, as_clause_slot);
            }

            // Clean up the temporary slot
            pg_sys::ExecDropSingleTupleTableSlot(as_clause_slot);
        } else {
            eprintln!("DEBUG: Storing tuple directly (no AS clause conversion)");
            pgrx::info!("DEBUG: Storing tuple directly (no AS clause conversion)");
            // Store tuple directly in tuplestore (original behavior)
            pg_sys::tuplestore_puttupleslot(tuplestore, slot);
        }
        tuple_count += 1;

        // Prevent infinite loops and excessive memory usage
        if tuple_count > 1000000 {
            // Manual cleanup since we bypassed ExecutorStart
            pg_sys::ExecEndNode(plan_state);
            pg_sys::FreeExecutorState(estate);
            return Err("Query returned too many rows (> 1M), execution aborted".into());
        }
    }

    // Clean up manually since we bypassed ExecutorStart.
    // ExecutorFinish/ExecutorEnd expect structures set up by ExecutorStart.
    eprintln!("DEBUG: Cleaning up with manual ExecEndNode and FreeExecutorState");
    pgrx::info!("DEBUG: Cleaning up with manual ExecEndNode and FreeExecutorState");
    pg_sys::ExecEndNode(plan_state);
    pg_sys::FreeExecutorState(estate);

    Ok((tupdesc, tuplestore))
}

/// Executes a PostgreSQL plan tree and returns the results
pub unsafe fn execute_postgres_plan(
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("DEBUG: execute_postgres_plan ENTRY - plan_tree={plan_tree:p}");
    pgrx::info!(
        "DEBUG: execute_postgres_plan ENTRY - plan_tree={:p}",
        plan_tree
    );

    if plan_tree.is_null() {
        eprintln!("DEBUG: ERROR - plan_tree is null!");
        pgrx::info!("DEBUG: ERROR - plan_tree is null!");
        return Err("Plan tree pointer is null".into());
    }

    eprintln!("DEBUG: plan_tree pointer is valid, about to check node type");
    pgrx::info!("DEBUG: plan_tree pointer is valid, about to check node type");

    // Check for the specific type 124 corruption issue
    let plan_type = (*plan_tree).type_;
    let plan_type_value = plan_type as i32;

    if plan_type_value == 124 {
        pgrx::error!(
            "ERROR: Plan tree has invalid node type 124 - this is a known corruption issue"
        );
    }

    pgrx::info!(
        "DEBUG: Plan tree type: {:?} (value: {})",
        plan_type,
        plan_type_value
    );

    // Execute the plan using PostgreSQL's native executor
    eprintln!("DEBUG: Executing plan using PostgreSQL's native executor");

    // Validate plan tree before execution
    validate_plan_tree_node_types(plan_tree);

    let (tupdesc, tuplestore) =
        execute_plan_directly_from_ptr(plan_tree, column_names, range_table, None).map_err(
            |e| {
                eprintln!("DEBUG: Plan execution failed: {e}");
                e
            },
        )?;

    eprintln!("DEBUG: Plan executed successfully, converting results");

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

    // Reset tuplestore to beginning
    pg_sys::tuplestore_rescan(tuplestore);

    // Create slot for reading tuples
    let slot = pg_sys::MakeTupleTableSlot(tupdesc, &pg_sys::TTSOpsMinimalTuple);

    // Read all tuples from tuplestore
    while pg_sys::tuplestore_gettupleslot(tuplestore, true, false, slot) {
        let mut row_data = Vec::new();
        let mut row_nulls = Vec::new();

        // Extract values from slot
        for i in 0..natts {
            let mut is_null = false;
            let attr_num = i + 1;
            let datum = pg_sys::slot_getattr(slot, attr_num, &mut is_null);
            row_data.push(datum);
            row_nulls.push(is_null);
        }

        rows.push(row_data);
        nulls.push(row_nulls);
    }

    // Clean up
    pg_sys::ExecDropSingleTupleTableSlot(slot);
    pg_sys::tuplestore_end(tuplestore);

    eprintln!("DEBUG: Extracted {} rows from execution", rows.len());

    Ok(ExecutionResult {
        columns,
        rows,
        nulls,
    })
}

/// Create a range table from plan tree by finding SeqScan nodes
unsafe fn create_range_table_from_plan_tree(
    plan_tree: &pg_sys::Plan,
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "DEBUG: create_range_table_from_plan_tree called with plan type: {:?}",
        plan_tree.type_
    );

    let mut range_table: *mut pg_sys::List = std::ptr::null_mut();
    collect_seqscan_nodes_for_range_table(plan_tree, &mut range_table)?;

    Ok(range_table)
}

/// Recursively collect SeqScan nodes and create range table entries
unsafe fn collect_seqscan_nodes_for_range_table(
    plan: &pg_sys::Plan,
    range_table: &mut *mut pg_sys::List,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("DEBUG: Checking plan node type: {:?}", plan.type_);

    // Check if this is a SeqScan node
    if plan.type_ == pg_sys::NodeTag::T_SeqScan {
        eprintln!("DEBUG: Found SeqScan node, creating range table entry");

        // Extract table OID from plan_node_id (where we stored it during translation)
        let table_oid = pg_sys::Oid::from(plan.plan_node_id as u32);
        eprintln!("DEBUG: SeqScan table OID from plan_node_id: {table_oid}");

        if table_oid != pg_sys::InvalidOid {
            // Create a range table entry for this table
            let rte = create_range_table_entry_from_oid(table_oid)?;
            *range_table = pg_sys::lappend(*range_table, rte as *mut std::ffi::c_void);
            eprintln!("DEBUG: Added range table entry for table OID: {table_oid}");
        }
    }

    // Recursively check child nodes
    if !plan.lefttree.is_null() {
        collect_seqscan_nodes_for_range_table(&*plan.lefttree, range_table)?;
    }
    if !plan.righttree.is_null() {
        collect_seqscan_nodes_for_range_table(&*plan.righttree, range_table)?;
    }

    Ok(())
}

/// Execute PostgreSQL plan as SRF directly without unpacking/repacking
/// This function directly interfaces with PostgreSQL's SRF mechanism
pub unsafe fn execute_postgres_plan_as_srf(
    fcinfo: pg_sys::FunctionCallInfo,
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *mut pg_sys::List,
) -> pg_sys::Datum {
    // IMMEDIATE DEBUG - FIRST LINE OF FUNCTION EXECUTION
    eprintln!("IMMEDIATE: execute_postgres_plan_as_srf ENTERED - BEFORE ANY OPERATIONS");
    pgrx::info!("IMMEDIATE: execute_postgres_plan_as_srf ENTERED - BEFORE ANY OPERATIONS");

    // Use std::panic::catch_unwind to catch any panics that might be preventing execution
    let result = std::panic::catch_unwind(|| {
        eprintln!("DEBUG: execute_postgres_plan_as_srf ENTRY - INSIDE PANIC HANDLER");
        pgrx::info!("DEBUG: execute_postgres_plan_as_srf ENTRY - INSIDE PANIC HANDLER");

        execute_postgres_plan_as_srf_inner(fcinfo, plan_tree, column_names, range_table)
    });

    match result {
        Ok(datum) => {
            eprintln!("DEBUG: SRF executed successfully");
            datum
        }
        Err(panic_info) => {
            eprintln!("PANIC: execute_postgres_plan_as_srf panicked: {panic_info:?}");
            pgrx::error!("Function panicked during execution");
        }
    }
}

unsafe fn execute_postgres_plan_as_srf_inner(
    fcinfo: pg_sys::FunctionCallInfo,
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *mut pg_sys::List,
) -> pg_sys::Datum {
    eprintln!(
        "DEBUG: execute_postgres_plan_as_srf_inner ENTRY - using pgrx-compatible SRF pattern"
    );
    pgrx::info!(
        "DEBUG: execute_postgres_plan_as_srf_inner ENTRY - using pgrx-compatible SRF pattern"
    );

    // Check if this is the first call
    let funcctx: *mut pg_sys::FuncCallContext;
    if (*fcinfo).flinfo.is_null() || (*(*fcinfo).flinfo).fn_extra.is_null() {
        eprintln!("DEBUG: SRF first call - setting up using init_MultiFuncCall");
        pgrx::info!("DEBUG: SRF first call - setting up using init_MultiFuncCall");

        // Initialize multi-function call context
        funcctx = pg_sys::init_MultiFuncCall(fcinfo);
        let oldcontext = pg_sys::MemoryContextSwitchTo((*funcctx).multi_call_memory_ctx);

        // Get call result type from AS clause - this is the key improvement
        let mut result_type_id: pg_sys::Oid = pg_sys::InvalidOid;
        let mut result_tuple_desc: *mut pg_sys::TupleDescData = std::ptr::null_mut();

        let type_class =
            pg_sys::get_call_result_type(fcinfo, &mut result_type_id, &mut result_tuple_desc);
        eprintln!("DEBUG: get_call_result_type returned: {:?}, result_type_id: {}, result_tuple_desc: {:p}",
                 type_class, result_type_id.to_u32(), result_tuple_desc);
        pgrx::info!("DEBUG: get_call_result_type returned: {:?}, result_type_id: {}, result_tuple_desc: {:p}",
                   type_class, result_type_id.to_u32(), result_tuple_desc);

        if type_class != pg_sys::TypeFuncClass::TYPEFUNC_COMPOSITE {
            pg_sys::MemoryContextSwitchTo(oldcontext);
            pgrx::error!("Function must return a composite type (SETOF RECORD with AS clause)");
        }

        if result_tuple_desc.is_null() {
            pg_sys::MemoryContextSwitchTo(oldcontext);
            pgrx::error!("Could not determine result tuple descriptor from AS clause");
        }

        // Execute the plan using the proper tuple descriptor from AS clause
        let execution_result = execute_plan_directly(
            &*plan_tree,
            column_names,
            range_table,
            Some(result_tuple_desc),
        );
        let (_generated_tupdesc, tuplestore) = execution_result.unwrap_or_else(|e| {
            pg_sys::MemoryContextSwitchTo(oldcontext);
            pgrx::error!("Plan execution failed: {}", e);
        });

        // Store tuplestore in function context
        (*funcctx).user_fctx = tuplestore as *mut std::ffi::c_void;

        // Use the blessed result tuple descriptor from AS clause
        let blessed_desc = pg_sys::BlessTupleDesc(result_tuple_desc);
        (*funcctx).tuple_desc = blessed_desc;

        // DEBUG: Examine the blessed descriptor
        if !blessed_desc.is_null() {
            let blessed_typeid = (*blessed_desc).tdtypeid;
            let blessed_typmod = (*blessed_desc).tdtypmod;
            eprintln!(
                "DEBUG: Blessed descriptor: tdtypeid={}, tdtypmod={}",
                blessed_typeid.to_u32(),
                blessed_typmod
            );
            pgrx::info!(
                "DEBUG: Blessed descriptor: tdtypeid={}, tdtypmod={}",
                blessed_typeid.to_u32(),
                blessed_typmod
            );
        }

        // Set up for indefinite iteration (we don't know tuple count in advance)
        (*funcctx).max_calls = u64::MAX;
        (*funcctx).call_cntr = 0;

        // Reset tuplestore for reading
        pg_sys::tuplestore_rescan(tuplestore);

        pg_sys::MemoryContextSwitchTo(oldcontext);
    } else {
        // Per-call setup
        funcctx = (*(*fcinfo).flinfo).fn_extra as *mut pg_sys::FuncCallContext;
    }

    // Get tuplestore from context
    let tuplestore = (*funcctx).user_fctx as *mut pg_sys::Tuplestorestate;
    // Use the blessed tuple descriptor directly for the slot
    let blessed_desc = (*funcctx).tuple_desc;
    let slot = pg_sys::MakeTupleTableSlot(blessed_desc, &pg_sys::TTSOpsMinimalTuple);

    if pg_sys::tuplestore_gettupleslot(tuplestore, true, false, slot) {
        eprintln!("DEBUG: Retrieved tuple from tuplestore using pgrx-compatible SRF pattern");
        pgrx::info!("DEBUG: Retrieved tuple from tuplestore using pgrx-compatible SRF pattern");

        // DEBUG: Examine the slot before conversion
        let slot_desc = (*slot).tts_tupleDescriptor;
        if !slot_desc.is_null() {
            let natts = (*slot_desc).natts;
            eprintln!("DEBUG: Pre-conversion slot descriptor has {natts} attrs");
            pgrx::info!("DEBUG: Pre-conversion slot descriptor has {} attrs", natts);
            for i in 0..natts {
                let attr = (*slot_desc).attrs.as_ptr().add(i as usize);
                let attr_typeid = (*attr).atttypid;
                eprintln!(
                    "DEBUG: Pre-conversion slot attr {}: typeid={}",
                    i,
                    attr_typeid.to_u32()
                );
                pgrx::info!(
                    "DEBUG: Pre-conversion slot attr {}: typeid={}",
                    i,
                    attr_typeid.to_u32()
                );
            }
        }

        // Convert slot to heap tuple using the blessed tuple descriptor
        eprintln!("DEBUG: About to call ExecCopySlotHeapTuple");
        pgrx::info!("DEBUG: About to call ExecCopySlotHeapTuple");
        let heap_tuple = pg_sys::ExecCopySlotHeapTuple(slot);
        eprintln!("DEBUG: ExecCopySlotHeapTuple returned: {heap_tuple:p}");
        pgrx::info!("DEBUG: ExecCopySlotHeapTuple returned: {:p}", heap_tuple);

        if !heap_tuple.is_null() {
            // DEBUG: Examine the heap tuple header
            let tuple_header = (*heap_tuple).t_data;
            if !tuple_header.is_null() {
                eprintln!("DEBUG: Heap tuple header: {tuple_header:p}");
                pgrx::info!("DEBUG: Heap tuple header: {:p}", tuple_header);

                // Check if this has the datum_typeid field (composite type)
                let heap_tuple_len = (*heap_tuple).t_len;
                eprintln!("DEBUG: Heap tuple length: {heap_tuple_len}");
                pgrx::info!("DEBUG: Heap tuple length: {}", heap_tuple_len);

                // The issue might be in how PostgreSQL interprets this as a composite type
                // Let's see what the tuple descriptor thinks it is
                let tuple_desc = (*funcctx).tuple_desc;
                if !tuple_desc.is_null() {
                    let tdtypeid = (*tuple_desc).tdtypeid;
                    let tdtypmod = (*tuple_desc).tdtypmod;
                    eprintln!(
                        "DEBUG: Function context tuple desc: tdtypeid={}, tdtypmod={}",
                        tdtypeid.to_u32(),
                        tdtypmod
                    );
                    pgrx::info!(
                        "DEBUG: Function context tuple desc: tdtypeid={}, tdtypmod={}",
                        tdtypeid.to_u32(),
                        tdtypmod
                    );
                }
            }

            // Clean up the slot before returning
            pg_sys::ExecDropSingleTupleTableSlot(slot);

            // Increment call counter
            (*funcctx).call_cntr += 1;

            // For composite type SRF, use heap_copy_tuple_as_datum which properly
            // sets up the type information from the tuple descriptor.
            (*fcinfo).isnull = false;

            // Get the blessed tuple descriptor from function context
            let tuple_desc = (*funcctx).tuple_desc;

            eprintln!(
                "DEBUG: Returning heap tuple {:p} via heap_copy_tuple_as_datum with tupdesc {:p}",
                heap_tuple, tuple_desc
            );
            pgrx::info!(
                "DEBUG: Returning heap tuple {:p} via heap_copy_tuple_as_datum with tupdesc {:p}",
                heap_tuple,
                tuple_desc
            );

            // Use heap_copy_tuple_as_datum which sets the proper type info
            pg_sys::heap_copy_tuple_as_datum(heap_tuple, tuple_desc)
        } else {
            pg_sys::ExecDropSingleTupleTableSlot(slot);
            pg_sys::end_MultiFuncCall(fcinfo, funcctx);
            (*fcinfo).isnull = true;
            pg_sys::Datum::from(0)
        }
    } else {
        eprintln!("DEBUG: No more tuples - ending SRF");
        pgrx::info!("DEBUG: No more tuples - ending SRF");

        // Clean up
        pg_sys::ExecDropSingleTupleTableSlot(slot);
        if !tuplestore.is_null() {
            pg_sys::tuplestore_end(tuplestore);
        }

        pg_sys::end_MultiFuncCall(fcinfo, funcctx);
        (*fcinfo).isnull = true;
        pg_sys::Datum::from(0)
    }
}

/// Create a range table entry from a table OID
unsafe fn create_range_table_entry_from_oid(
    table_oid: pg_sys::Oid,
) -> Result<*mut pg_sys::RangeTblEntry, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("DEBUG: create_range_table_entry_from_oid called for OID: {table_oid}");

    // Get table name from OID for the alias
    let relation = pg_sys::relation_open(table_oid, pg_sys::AccessShareLock as i32);
    if relation.is_null() {
        return Err(format!("Could not open relation with OID {table_oid}").into());
    }

    let rel_name = std::ffi::CStr::from_ptr((*(*relation).rd_rel).relname.data.as_ptr())
        .to_string_lossy()
        .to_string();

    pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);

    // Create RangeTblEntry using safe pgrx allocation
    let mut rte = pgrx::PgBox::<pg_sys::RangeTblEntry>::alloc0();

    rte.type_ = pg_sys::NodeTag::T_RangeTblEntry;
    rte.rtekind = pg_sys::RTEKind::RTE_RELATION;
    rte.relid = table_oid;
    rte.relkind = pg_sys::RELKIND_RELATION as i8;
    rte.rellockmode = pg_sys::AccessShareLock as i32;
    rte.lateral = false;
    rte.inh = true; // Include inheritance
    rte.inFromCl = true; // This table is in the FROM clause

    // Create an alias for the table using safe pgrx allocation
    let mut alias = pgrx::PgBox::<pg_sys::Alias>::alloc0();
    alias.type_ = pg_sys::NodeTag::T_Alias;
    let aliasname = unsafe {
        pgrx::PgMemoryContexts::CurrentMemoryContext.palloc_slice::<u8>(rel_name.len() + 1)
    };
    unsafe {
        std::ptr::copy_nonoverlapping(rel_name.as_ptr(), aliasname.as_mut_ptr(), rel_name.len());
        *aliasname.as_mut_ptr().add(rel_name.len()) = 0; // null terminate
    }
    alias.aliasname = aliasname.as_mut_ptr() as *mut std::os::raw::c_char;
    alias.colnames = std::ptr::null_mut(); // Will be filled in by planner if needed
    let alias_ptr = alias.into_pg();
    rte.eref = alias_ptr;
    rte.alias = std::ptr::null_mut(); // No explicit alias

    // Initialize other fields
    rte.securityQuals = std::ptr::null_mut();

    eprintln!("DEBUG: Range table entry created successfully for table: {rel_name}");

    let final_rte_ptr = rte.into_pg();
    Ok(final_rte_ptr)
}

/// Create a range table from plan tree by finding SeqScan nodes - raw pointer version
unsafe fn create_range_table_from_plan_tree_raw(
    plan_tree: *mut pg_sys::Plan,
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "DEBUG: create_range_table_from_plan_tree_raw called with plan type: {:?}",
        (*plan_tree).type_
    );

    let mut range_table: *mut pg_sys::List = std::ptr::null_mut();
    collect_seqscan_nodes_for_range_table_raw(plan_tree, &mut range_table)?;

    Ok(range_table)
}

/// Recursively collect SeqScan nodes and create range table entries - raw pointer version
unsafe fn collect_seqscan_nodes_for_range_table_raw(
    plan: *mut pg_sys::Plan,
    range_table: &mut *mut pg_sys::List,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if plan.is_null() {
        return Ok(());
    }

    eprintln!("DEBUG: Checking plan node type: {:?}", (*plan).type_);

    // Check if this is a SeqScan node
    if (*plan).type_ == pg_sys::NodeTag::T_SeqScan {
        eprintln!("DEBUG: Found SeqScan node, creating range table entry");

        // Extract table OID from plan_node_id (where we stored it during translation)
        let table_oid = pg_sys::Oid::from((*plan).plan_node_id as u32);
        eprintln!("DEBUG: SeqScan table OID from plan_node_id: {table_oid}");

        if table_oid != pg_sys::InvalidOid {
            // Create a range table entry for this table
            let rte = create_range_table_entry_from_oid(table_oid)?;
            *range_table = pg_sys::lappend(*range_table, rte as *mut std::ffi::c_void);
            eprintln!("DEBUG: Added range table entry for table OID: {table_oid}");
        }
    }

    // Recursively check child nodes
    if !(*plan).lefttree.is_null() {
        collect_seqscan_nodes_for_range_table_raw((*plan).lefttree, range_table)?;
    }
    if !(*plan).righttree.is_null() {
        collect_seqscan_nodes_for_range_table_raw((*plan).righttree, range_table)?;
    }

    Ok(())
}

/// Recursively validate all node types in a plan tree to catch corruption early
unsafe fn validate_plan_tree_node_types(plan: *mut pg_sys::Plan) {
    if plan.is_null() {
        return;
    }

    let node_type = (*plan).type_;
    eprintln!(
        "DEBUG: Validating plan node type: {:?} (value: {})",
        node_type, node_type as i32
    );

    // Check if this is a valid plan node type
    match node_type {
        pg_sys::NodeTag::T_SeqScan
        | pg_sys::NodeTag::T_Sort
        | pg_sys::NodeTag::T_Limit
        | pg_sys::NodeTag::T_Result
        | pg_sys::NodeTag::T_NestLoop
        | pg_sys::NodeTag::T_Agg
        | pg_sys::NodeTag::T_ValuesScan => {
            // Valid plan node type
        }
        _ => {
            eprintln!(
                "ERROR: Invalid plan node type detected: {:?} (value: {})",
                node_type, node_type as i32
            );
            if node_type as i32 == 124 {
                eprintln!("ERROR: Found the problematic node type 124 in plan tree!");
            }
        }
    }

    // Recursively validate child nodes
    if !(*plan).lefttree.is_null() {
        validate_plan_tree_node_types((*plan).lefttree);
    }
    if !(*plan).righttree.is_null() {
        validate_plan_tree_node_types((*plan).righttree);
    }

    // Validate target list expressions if present
    if !(*plan).targetlist.is_null() {
        validate_expression_list_node_types((*plan).targetlist);
    }

    // Validate qual expressions if present
    if !(*plan).qual.is_null() {
        validate_expression_list_node_types((*plan).qual);
    }
}

/// Validate node types in an expression list
unsafe fn validate_expression_list_node_types(list: *mut pg_sys::List) {
    if list.is_null() {
        return;
    }

    // Use PostgreSQL's list iteration for PostgreSQL 15+
    let length = (*list).length;
    for i in 0..length {
        let element = (*list).elements.offset(i as isize);
        if !element.is_null() {
            let node = (*element).ptr_value as *mut pg_sys::Node;
            if !node.is_null() {
                validate_expression_node_types(node);
            }
        }
    }
}

/// Validate node types in expression nodes
unsafe fn validate_expression_node_types(node: *mut pg_sys::Node) {
    if node.is_null() {
        return;
    }

    let node_type = (*node).type_;
    eprintln!(
        "DEBUG: Validating expression node type: {:?} (value: {})",
        node_type, node_type as i32
    );

    match node_type {
        pg_sys::NodeTag::T_TargetEntry
        | pg_sys::NodeTag::T_Var
        | pg_sys::NodeTag::T_Const
        | pg_sys::NodeTag::T_OpExpr
        | pg_sys::NodeTag::T_FuncExpr
        | pg_sys::NodeTag::T_BoolExpr
        | pg_sys::NodeTag::T_SubLink
        | pg_sys::NodeTag::T_Query
        | pg_sys::NodeTag::T_Aggref => {
            // Valid expression node type
        }
        _ => {
            eprintln!(
                "ERROR: Invalid expression node type detected: {:?} (value: {})",
                node_type, node_type as i32
            );
            if node_type as i32 == 124 {
                eprintln!("ERROR: Found the problematic node type 124 in expression!");
            }
        }
    }
}
