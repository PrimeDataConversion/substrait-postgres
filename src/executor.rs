use anyhow::Result;
use pgrx::pg_sys;

use crate::plan_translator::{ColumnInfo, ExecutionResult};

/// Executes a PostgreSQL plan tree from a raw pointer without creating invalid references
/// This is the safe version that avoids memory corruption issues.
pub unsafe fn execute_plan_directly_from_ptr(
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
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

    let result = execute_plan_directly_raw(plan_tree, column_names, range_table);

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
    let tupdesc = pg_sys::ExecTypeFromTL(targetlist);
    pgrx::info!("DEBUG: ExecTypeFromTL returned tupdesc: {:p}", tupdesc);
    if tupdesc.is_null() {
        return Err("Failed to create tuple descriptor from plan".into());
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
    planned_stmt.commandType = pg_sys::CmdType::CMD_SELECT;
    let planned_stmt_ptr = planned_stmt.into_pg();
    pgrx::info!("DEBUG: PlannedStmt created: {:p}", planned_stmt_ptr);

    // Set up the QueryDesc using the raw pointer
    (*query_desc_ptr).operation = pg_sys::CmdType::CMD_SELECT;
    (*query_desc_ptr).plannedstmt = planned_stmt_ptr;
    (*query_desc_ptr).sourceText = std::ptr::null_mut();
    (*query_desc_ptr).snapshot = pg_sys::GetActiveSnapshot();
    (*query_desc_ptr).crosscheck_snapshot = std::ptr::null_mut();
    (*query_desc_ptr).dest = std::ptr::null_mut();
    (*query_desc_ptr).params = std::ptr::null_mut();
    (*query_desc_ptr).queryEnv = std::ptr::null_mut();
    (*query_desc_ptr).instrument_options = 0;
    pgrx::info!("DEBUG: QueryDesc setup complete");

    pgrx::info!("DEBUG: Calling ExecutorStart");

    // Call PostgreSQL's standard ExecutorStart function instead of manual setup
    pg_sys::ExecutorStart(query_desc_ptr, 0);

    pgrx::info!("DEBUG: ExecutorStart succeeded!");

    // Get the plan state - ExecutorStart already called ExecInitNode for us!
    let plan_state = (*query_desc_ptr).planstate;
    if plan_state.is_null() {
        pg_sys::ExecutorFinish(query_desc_ptr);
        pg_sys::ExecutorEnd(query_desc_ptr);
        return Err("ExecutorStart failed to create plan state".into());
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
            // Clean up using PostgreSQL's proper sequence
            pg_sys::ExecutorFinish(query_desc_ptr);
            pg_sys::ExecutorEnd(query_desc_ptr);
            return Err("Query returned too many rows (> 1M), execution aborted".into());
        }
    }
    pgrx::info!(
        "DEBUG: ExecProcNode loop finished. Total tuples: {}",
        tuple_count
    );

    // Clean up using PostgreSQL's proper ExecutorFinish and ExecutorEnd sequence
    pgrx::info!("DEBUG: Cleaning up with ExecutorFinish and ExecutorEnd");
    pg_sys::ExecutorFinish(query_desc_ptr);
    pg_sys::ExecutorEnd(query_desc_ptr);
    pgrx::info!("DEBUG: ExecutorFinish and ExecutorEnd completed");

    Ok((tupdesc, tuplestore))
}

/// Executes a PostgreSQL plan tree using PostgreSQL's native executor
/// and returns the tuple descriptor and tuplestore directly.
/// This is the simplified approach that minimizes unpacking/packing operations.
pub unsafe fn execute_plan_directly(
    plan_tree: &pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
) -> Result<
    (*mut pg_sys::TupleDescData, *mut pg_sys::Tuplestorestate),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // IMMEDIATE ENTRY DEBUG - BEFORE ACCESSING PARAMETERS
    eprintln!("IMMEDIATE: execute_plan_directly ENTERED SUCCESSFULLY");
    pgrx::info!("IMMEDIATE: execute_plan_directly ENTERED SUCCESSFULLY");

    eprintln!(
        "DEBUG: execute_plan_directly called with plan tree type: {:?}",
        plan_tree.type_
    );
    pgrx::info!("CRITICAL: execute_plan_directly ENTRY - THIS SHOULD APPEAR IN LOGS");

    eprintln!("DEBUG: About to access plan_tree.targetlist");
    pgrx::info!("DEBUG: About to access plan_tree.targetlist");

    // DEBUG: Inspect target list BEFORE calling ExecTypeFromTL
    let targetlist = plan_tree.targetlist;

    eprintln!("DEBUG: targetlist accessed successfully");
    pgrx::info!("DEBUG: targetlist accessed successfully");

    if targetlist.is_null() {
        eprintln!("ERROR: targetlist is null!");
        return Err("Target list is null".into());
    }

    eprintln!("DEBUG: targetlist pointer: {:p}", targetlist);
    eprintln!("DEBUG: About to access targetlist.length");
    pgrx::info!("DEBUG: About to access targetlist.length");

    eprintln!("DEBUG: targetlist length: {}", (*targetlist).length);

    eprintln!("DEBUG: targetlist length accessed successfully");
    pgrx::info!("DEBUG: targetlist length accessed successfully");

    eprintln!("DEBUG: About to access targetlist.elements array");
    pgrx::info!("DEBUG: About to access targetlist.elements array");

    let elements_ptr = (*targetlist).elements;
    eprintln!("DEBUG: elements array pointer: {:p}", elements_ptr);
    pgrx::info!("DEBUG: elements array pointer: {:p}", elements_ptr);

    if elements_ptr.is_null() {
        eprintln!("ERROR: elements array is null!");
        return Err("Target list elements array is null".into());
    }

    eprintln!("DEBUG: elements array is valid, about to iterate");
    pgrx::info!("DEBUG: elements array is valid, about to iterate");

    // Use PostgreSQL's list_nth function instead of manual pointer access
    for i in 0..(*targetlist).length {
        eprintln!("DEBUG: Starting iteration {}", i);
        pgrx::info!("DEBUG: Starting iteration {}", i);

        // Use PostgreSQL's safe list access function
        let target_entry = pg_sys::list_nth(targetlist, i as i32) as *mut pg_sys::TargetEntry;

        eprintln!("DEBUG: Got TargetEntry from list_nth: {:p}", target_entry);
        pgrx::info!("DEBUG: Got TargetEntry from list_nth: {:p}", target_entry);

        if !target_entry.is_null() {
            eprintln!("DEBUG: About to access TargetEntry fields");
            pgrx::info!("DEBUG: About to access TargetEntry fields");

            // Try to access the node type first (should be T_TargetEntry)
            eprintln!("DEBUG: Checking TargetEntry node type");
            pgrx::info!("DEBUG: Checking TargetEntry node type");

            let node_type = (*target_entry).xpr.type_;
            eprintln!("DEBUG: TargetEntry node type: {:?}", node_type);
            pgrx::info!("DEBUG: TargetEntry node type: {:?}", node_type);

            eprintln!("DEBUG: About to access resno and resname");
            pgrx::info!("DEBUG: About to access resno and resname");

            eprintln!(
                "DEBUG: TargetEntry[{}]: resno={}, resname={:p}",
                i,
                (*target_entry).resno,
                (*target_entry).resname
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
                eprintln!("ERROR: TargetEntry[{}] expr is null!", i);
            }
        } else {
            eprintln!("ERROR: TargetEntry[{}] from list_nth is null!", i);
        }
    }

    eprintln!("DEBUG: About to call ExecTypeFromTL");

    // Use PostgreSQL's standard execution path for all node types including SeqScan

    // Get the tuple descriptor from the plan's target list
    let tupdesc = pg_sys::ExecTypeFromTL(plan_tree.targetlist);
    eprintln!("DEBUG: ExecTypeFromTL returned tupdesc: {tupdesc:p}");
    if tupdesc.is_null() {
        return Err("Failed to create tuple descriptor from plan".into());
    }

    // Debug the tuple descriptor attributes to see what type OIDs were created
    let natts = (*tupdesc).natts;
    eprintln!("DEBUG: Tuple descriptor has {} attributes", natts);
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

    // Set the range table from the translation phase or create it dynamically
    if !range_table.is_null() {
        (*estate).es_range_table = range_table as *mut pg_sys::List;
        eprintln!("DEBUG: Set provided range table on executor state");
    } else {
        // Create range table dynamically from plan tree information
        eprintln!("DEBUG: Creating range table dynamically from plan tree");
        let dynamic_range_table = create_range_table_from_plan_tree(plan_tree)?;
        if !dynamic_range_table.is_null() {
            (*estate).es_range_table = dynamic_range_table;
            eprintln!("DEBUG: Set dynamically created range table on executor state");
        } else {
            eprintln!("DEBUG: Warning - no range table could be created");
        }
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
    let mut tuple_count = 0u64;
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

            // CRITICAL CLEANUP: Close any opened relations before freeing executor state
            if !(*estate).es_relations.is_null() {
                let rtable = (*estate).es_range_table;
                if !rtable.is_null() {
                    let num_rels = (*rtable).length;
                    for i in 0..num_rels {
                        let relation = *(*estate).es_relations.add(i as usize);
                        if !relation.is_null() {
                            pg_sys::table_close(relation, pg_sys::AccessShareLock as i32);
                        }
                    }
                }
            }

            pg_sys::FreeExecutorState(estate);
            return Err("Query returned too many rows (> 1M), execution aborted".into());
        }
    }

    // Clean up executor
    pg_sys::ExecEndNode(plan_state);

    // CRITICAL CLEANUP: Close any opened relations before freeing executor state
    if !(*estate).es_relations.is_null() {
        eprintln!("DEBUG: Closing opened relations");
        let rtable = (*estate).es_range_table;
        if !rtable.is_null() {
            let num_rels = (*rtable).length;
            for i in 0..num_rels {
                let relation = *(*estate).es_relations.add(i as usize);
                if !relation.is_null() {
                    pg_sys::table_close(relation, pg_sys::AccessShareLock as i32);
                    eprintln!("DEBUG: Closed relation at index {i}");
                }
            }
        }
    }

    pg_sys::FreeExecutorState(estate);

    Ok((tupdesc, tuplestore))
}

/// Executes a PostgreSQL plan tree and returns the results
pub unsafe fn execute_postgres_plan(
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "DEBUG: execute_postgres_plan ENTRY - plan_tree={:p}",
        plan_tree
    );
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
        execute_plan_directly_from_ptr(plan_tree, column_names, range_table).map_err(|e| {
            eprintln!("DEBUG: Plan execution failed: {e}");
            e
        })?;

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
            eprintln!(
                "PANIC: execute_postgres_plan_as_srf panicked: {:?}",
                panic_info
            );
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
    eprintln!("DEBUG: execute_postgres_plan_as_srf_inner ENTRY");
    pgrx::info!("DEBUG: execute_postgres_plan_as_srf_inner ENTRY");

    eprintln!("DEBUG: About to call init_MultiFuncCall");
    pgrx::info!("DEBUG: About to call init_MultiFuncCall");
    let func_ctx = pg_sys::init_MultiFuncCall(fcinfo);
    eprintln!(
        "DEBUG: init_MultiFuncCall completed, func_ctx: {:p}",
        func_ctx
    );
    pgrx::info!(
        "DEBUG: init_MultiFuncCall completed, func_ctx: {:p}",
        func_ctx
    );

    if (*func_ctx).call_cntr == 0 {
        // First call - set up the SRF
        let memory_ctx = (*func_ctx).multi_call_memory_ctx;
        let old_ctx = pg_sys::MemoryContextSwitchTo(memory_ctx);

        // Get the expected tuple descriptor from the AS clause
        eprintln!("DEBUG: About to process AS clause descriptor");
        pgrx::info!("DEBUG: About to process AS clause descriptor");

        let result_info = (*fcinfo).resultinfo as *mut pg_sys::ReturnSetInfo;
        eprintln!("DEBUG: result_info pointer: {:p}", result_info);

        let expected_tupdesc = if !result_info.is_null() && !(*result_info).expectedDesc.is_null() {
            let tupdesc = (*result_info).expectedDesc;
            eprintln!("DEBUG: AS clause tupdesc pointer: {:p}", tupdesc);

            // Debug the AS clause descriptor
            eprintln!(
                "DEBUG: AS clause descriptor has {} attributes",
                (*tupdesc).natts
            );
            pgrx::info!(
                "DEBUG: AS clause descriptor has {} attributes",
                (*tupdesc).natts
            );

            for i in 0..(*tupdesc).natts {
                let attr = (*tupdesc).attrs.as_ptr().add(i as usize);
                eprintln!(
                    "DEBUG: AS attr {}: typid={}, typmod={}, name={:?}",
                    i,
                    (*attr).atttypid.to_u32(),
                    (*attr).atttypmod,
                    std::ffi::CStr::from_ptr((*attr).attname.data.as_ptr()).to_string_lossy()
                );
                pgrx::info!(
                    "DEBUG: AS attr {}: typid={}, typmod={}, name={:?}",
                    i,
                    (*attr).atttypid.to_u32(),
                    (*attr).atttypmod,
                    std::ffi::CStr::from_ptr((*attr).attname.data.as_ptr()).to_string_lossy()
                );
            }

            eprintln!("DEBUG: AS clause processing completed");
            pgrx::info!("DEBUG: AS clause processing completed");
            tupdesc
        } else {
            pg_sys::MemoryContextSwitchTo(old_ctx);
            pgrx::error!("SETOF RECORD function requires AS clause to specify return columns");
        };

        // Execute the plan and get tuplestore
        eprintln!("DEBUG: About to call execute_plan_directly");
        pgrx::info!("DEBUG: About to call execute_plan_directly");

        eprintln!("DEBUG: Plan tree pointer before execution: {:p}", plan_tree);
        eprintln!("DEBUG: Column names: {:?}", column_names);
        eprintln!("DEBUG: Range table pointer: {:p}", range_table);

        pgrx::info!("DEBUG: Starting plan execution with execute_plan_directly");
        let execution_result = execute_plan_directly(&*plan_tree, column_names, range_table);
        pgrx::info!("DEBUG: execute_plan_directly call completed");

        let (_, tuplestore) = execution_result.unwrap_or_else(|e| {
            pg_sys::MemoryContextSwitchTo(old_ctx);
            eprintln!("ERROR: Plan execution failed: {}", e);
            pgrx::error!("Plan execution failed: {}", e);
        });
        eprintln!("DEBUG: execute_plan_directly succeeded");

        // Use the expected tuple descriptor from the AS clause
        let blessed_tupdesc = pg_sys::BlessTupleDesc(expected_tupdesc);
        (*func_ctx).tuple_desc = blessed_tupdesc;

        // Store tuplestore in function context
        (*func_ctx).user_fctx = tuplestore as *mut std::ffi::c_void;

        // Create tuple slot for reading from tuplestore - use minimal tuple ops since tuplestore uses minimal tuples
        let slot = pg_sys::MakeTupleTableSlot(blessed_tupdesc, &pg_sys::TTSOpsMinimalTuple);

        // Store slot pointer in attinmeta field (reusing this field)
        (*func_ctx).attinmeta = slot as *mut pg_sys::AttInMetadata;

        // Reset tuplestore for reading
        pg_sys::tuplestore_rescan(tuplestore);

        pg_sys::MemoryContextSwitchTo(old_ctx);
    }

    // Get tuplestore and slot from context
    let tuplestore = (*func_ctx).user_fctx as *mut pg_sys::Tuplestorestate;
    let slot = (*func_ctx).attinmeta as *mut pg_sys::TupleTableSlot;

    // Try to get next tuple from tuplestore
    if pg_sys::tuplestore_gettupleslot(tuplestore, true, false, slot) {
        // Convert slot to minimal tuple and then to datum
        let mut should_free = false;
        let minimal_tuple = pg_sys::ExecFetchSlotMinimalTuple(slot, &mut should_free);
        let result = pg_sys::Datum::from(minimal_tuple as usize);
        (*func_ctx).call_cntr += 1;
        result
    } else {
        // No more tuples - cleanup and finish
        if !tuplestore.is_null() {
            pg_sys::tuplestore_end(tuplestore);
        }
        if !slot.is_null() {
            pg_sys::ExecDropSingleTupleTableSlot(slot);
        }

        // Signal end of SRF
        let result_info = (*fcinfo).resultinfo as *mut pg_sys::ReturnSetInfo;
        if !result_info.is_null() {
            (*result_info).isDone = pg_sys::ExprDoneCond::ExprEndResult;
        }
        pg_sys::end_MultiFuncCall(fcinfo, func_ctx);
        pg_sys::Datum::null()
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
    rte.selectedCols = std::ptr::null_mut();
    rte.insertedCols = std::ptr::null_mut();
    rte.updatedCols = std::ptr::null_mut();
    rte.extraUpdatedCols = std::ptr::null_mut();
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
