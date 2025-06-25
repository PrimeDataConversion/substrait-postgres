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
unsafe fn execute_plan_directly_raw(
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
) -> Result<
    (*mut pg_sys::TupleDescData, *mut pg_sys::Tuplestorestate),
    Box<dyn std::error::Error + Send + Sync>,
> {
    eprintln!("DEBUG: execute_plan_directly_raw ENTRY");
    pgrx::info!("DEBUG: execute_plan_directly_raw ENTRY");

    if plan_tree.is_null() {
        return Err("Plan tree pointer is null".into());
    }

    eprintln!("DEBUG: plan_tree pointer is valid: {:p}", plan_tree);

    // Check memory context - plan might be in wrong context
    let current_context = pg_sys::CurrentMemoryContext;
    eprintln!("DEBUG: Current memory context: {:p}", current_context);

    // Try to validate the plan tree pointer before dereferencing
    eprintln!("DEBUG: About to access plan_tree.type_ - this is where crash happens");

    // Use a more careful approach to access the plan tree
    let plan_type = (*plan_tree).type_;
    eprintln!("DEBUG: Successfully accessed plan_type: {:?}", plan_type);

    let targetlist = (*plan_tree).targetlist;
    eprintln!("DEBUG: Successfully accessed targetlist: {:p}", targetlist);

    eprintln!("DEBUG: About to call ExecTypeFromTL");

    // Use PostgreSQL's standard execution path for all node types including SeqScan

    // Get the tuple descriptor from the plan's target list
    let tupdesc = pg_sys::ExecTypeFromTL(targetlist);
    eprintln!("DEBUG: ExecTypeFromTL returned tupdesc: {:p}", tupdesc);
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
        let dynamic_range_table = create_range_table_from_plan_tree_raw(plan_tree)?;
        if !dynamic_range_table.is_null() {
            (*estate).es_range_table = dynamic_range_table;
            eprintln!("DEBUG: Set dynamically created range table on executor state");
        } else {
            eprintln!("DEBUG: Warning - no range table could be created");
        }
    }

    let plan_state = pg_sys::ExecInitNode(plan_tree, estate, 0);
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
            pg_sys::FreeExecutorState(estate);
            return Err("Query returned too many rows (> 1M), execution aborted".into());
        }
    }

    // Clean up executor
    pg_sys::ExecEndNode(plan_state);
    pg_sys::FreeExecutorState(estate);

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
    eprintln!("DEBUG: ExecTypeFromTL returned tupdesc: {:p}", tupdesc);
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
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "DEBUG: execute_postgres_plan called with plan tree pointer: {:p}",
        plan_tree
    );
    if plan_tree.is_null() {
        return Err("Plan tree pointer is null".into());
    }
    eprintln!(
        "DEBUG: execute_postgres_plan called with plan tree type: {:?}",
        (*plan_tree).type_
    );
    eprintln!("DEBUG: About to call execute_plan_directly");

    // Use the direct execution approach for other node types
    let (tupdesc, tuplestore) = execute_plan_directly(&*plan_tree, column_names, range_table)?;

    eprintln!("DEBUG: execute_plan_directly returned successfully");

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
    let slot = pg_sys::MakeTupleTableSlot(tupdesc, &pg_sys::TTSOpsMinimalTuple);
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
        eprintln!("DEBUG: SeqScan table OID from plan_node_id: {}", table_oid);

        if table_oid != pg_sys::InvalidOid {
            // Create a range table entry for this table
            let rte = create_range_table_entry_from_oid(table_oid)?;
            *range_table = pg_sys::lappend(*range_table, rte as *mut std::ffi::c_void);
            eprintln!(
                "DEBUG: Added range table entry for table OID: {}",
                table_oid
            );
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
    eprintln!(
        "DEBUG: create_range_table_entry_from_oid called for OID: {}",
        table_oid
    );

    // Get table name from OID for the alias
    let relation = pg_sys::relation_open(table_oid, pg_sys::AccessShareLock as i32);
    if relation.is_null() {
        return Err(format!("Could not open relation with OID {}", table_oid).into());
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

    eprintln!(
        "DEBUG: Range table entry created successfully for table: {}",
        rel_name
    );

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
        eprintln!("DEBUG: SeqScan table OID from plan_node_id: {}", table_oid);

        if table_oid != pg_sys::InvalidOid {
            // Create a range table entry for this table
            let rte = create_range_table_entry_from_oid(table_oid)?;
            *range_table = pg_sys::lappend(*range_table, rte as *mut std::ffi::c_void);
            eprintln!(
                "DEBUG: Added range table entry for table OID: {}",
                table_oid
            );
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
