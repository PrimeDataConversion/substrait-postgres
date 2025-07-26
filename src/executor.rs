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
    let query_desc =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::QueryDesc>()) as *mut pg_sys::QueryDesc;
    pgrx::info!("DEBUG: QueryDesc allocated: {:p}", query_desc);

    // Create a minimal PlannedStmt wrapper
    let planned_stmt =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::PlannedStmt>()) as *mut pg_sys::PlannedStmt;
    (*planned_stmt).type_ = pg_sys::NodeTag::T_PlannedStmt;
    (*planned_stmt).planTree = plan_tree;
    (*planned_stmt).rtable = range_table as *mut pg_sys::List;
    (*planned_stmt).commandType = pg_sys::CmdType::CMD_SELECT;
    pgrx::info!("DEBUG: PlannedStmt created: {:p}", planned_stmt);

    // Set up the QueryDesc
    (*query_desc).operation = pg_sys::CmdType::CMD_SELECT;
    (*query_desc).plannedstmt = planned_stmt;
    (*query_desc).sourceText = std::ptr::null_mut();
    (*query_desc).snapshot = pg_sys::GetActiveSnapshot();
    (*query_desc).crosscheck_snapshot = std::ptr::null_mut();
    (*query_desc).dest = std::ptr::null_mut();
    (*query_desc).params = std::ptr::null_mut();
    (*query_desc).queryEnv = std::ptr::null_mut();
    (*query_desc).instrument_options = 0;
    pgrx::info!("DEBUG: QueryDesc setup complete");

    pgrx::info!("DEBUG: Calling ExecutorStart");

    // Call PostgreSQL's standard ExecutorStart function instead of manual setup
    pg_sys::ExecutorStart(query_desc, 0);

    pgrx::info!("DEBUG: ExecutorStart succeeded!");

    // Get the plan state - ExecutorStart already called ExecInitNode for us!
    let plan_state = (*query_desc).planstate;
    if plan_state.is_null() {
        pg_sys::ExecutorFinish(query_desc);
        pg_sys::ExecutorEnd(query_desc);
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
            pg_sys::ExecutorFinish(query_desc);
            pg_sys::ExecutorEnd(query_desc);
            return Err("Query returned too many rows (> 1M), execution aborted".into());
        }
    }
    pgrx::info!(
        "DEBUG: ExecProcNode loop finished. Total tuples: {}",
        tuple_count
    );

    // Clean up using PostgreSQL's proper ExecutorFinish and ExecutorEnd sequence
    pgrx::info!("DEBUG: Cleaning up with ExecutorFinish and ExecutorEnd");
    pg_sys::ExecutorFinish(query_desc);
    pg_sys::ExecutorEnd(query_desc);
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
    eprintln!(
        "DEBUG: execute_plan_directly called with plan tree type: {:?}",
        plan_tree.type_
    );
    eprintln!("DEBUG: About to call ExecTypeFromTL");

    // Use PostgreSQL's standard execution path for all node types including SeqScan

    // Get the tuple descriptor from the plan's target list
    let tupdesc = pg_sys::ExecTypeFromTL(plan_tree.targetlist);
    eprintln!("DEBUG: ExecTypeFromTL returned tupdesc: {tupdesc:p}");
    if tupdesc.is_null() {
        return Err("Failed to create tuple descriptor from plan".into());
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
    eprintln!("DEBUG: execute_postgres_plan_as_srf ENTRY");
    let func_ctx = pg_sys::init_MultiFuncCall(fcinfo);
    eprintln!("DEBUG: init_MultiFuncCall completed");

    if (*func_ctx).call_cntr == 0 {
        // First call - set up the SRF
        let memory_ctx = (*func_ctx).multi_call_memory_ctx;
        let old_ctx = pg_sys::MemoryContextSwitchTo(memory_ctx);

        // Get the expected tuple descriptor from the AS clause
        let result_info = (*fcinfo).resultinfo as *mut pg_sys::ReturnSetInfo;
        let expected_tupdesc = if !result_info.is_null() && !(*result_info).expectedDesc.is_null() {
            let tupdesc = (*result_info).expectedDesc;

            // Debug the AS clause descriptor
            eprintln!(
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
            }

            tupdesc
        } else {
            pg_sys::MemoryContextSwitchTo(old_ctx);
            pgrx::error!("SETOF RECORD function requires AS clause to specify return columns");
        };

        // Execute the plan and get tuplestore
        let (_, tuplestore) = execute_plan_directly(&*plan_tree, column_names, range_table)
            .unwrap_or_else(|e| {
                pg_sys::MemoryContextSwitchTo(old_ctx);
                pgrx::error!("Plan execution failed: {}", e);
            });

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

    // Create RangeTblEntry
    let rte =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::RangeTblEntry>()) as *mut pg_sys::RangeTblEntry;

    (*rte).type_ = pg_sys::NodeTag::T_RangeTblEntry;
    (*rte).rtekind = pg_sys::RTEKind::RTE_RELATION;
    (*rte).relid = table_oid;
    (*rte).relkind = pg_sys::RELKIND_RELATION as i8;
    (*rte).rellockmode = pg_sys::AccessShareLock as i32;
    (*rte).lateral = false;
    (*rte).inh = true; // Include inheritance
    (*rte).inFromCl = true; // This table is in the FROM clause

    // Create an alias for the table
    let alias = pg_sys::palloc0(std::mem::size_of::<pg_sys::Alias>()) as *mut pg_sys::Alias;
    (*alias).type_ = pg_sys::NodeTag::T_Alias;
    (*alias).aliasname = pg_sys::palloc(rel_name.len() + 1) as *mut std::os::raw::c_char;
    std::ptr::copy_nonoverlapping(
        rel_name.as_ptr(),
        (*alias).aliasname as *mut u8,
        rel_name.len(),
    );
    *((*alias).aliasname.add(rel_name.len())) = 0; // null terminate
    (*alias).colnames = std::ptr::null_mut(); // Will be filled in by planner if needed
    (*rte).eref = alias;
    (*rte).alias = std::ptr::null_mut(); // No explicit alias

    // Initialize other fields
    (*rte).selectedCols = std::ptr::null_mut();
    (*rte).insertedCols = std::ptr::null_mut();
    (*rte).updatedCols = std::ptr::null_mut();
    (*rte).extraUpdatedCols = std::ptr::null_mut();
    (*rte).securityQuals = std::ptr::null_mut();

    eprintln!("DEBUG: Range table entry created successfully for table: {rel_name}");

    Ok(rte)
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
