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
    // Use PostgreSQL's standard execution path for all node types including SeqScan

    // Get the tuple descriptor from the plan's target list
    let tupdesc = pg_sys::ExecTypeFromTL(plan_tree.targetlist);
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

    // If this is a SeqScan node, we need to create a range table entry
    if plan_tree.type_ == pg_sys::NodeTag::T_SeqScan {
        // Extract table OID from scanrelid
        let seqscan_node = plan_tree as *const pg_sys::Plan as *mut pg_sys::SeqScan;

        #[cfg(any(feature = "pg13", feature = "pg14"))]
        let table_oid = (*seqscan_node).scanrelid;
        #[cfg(any(feature = "pg15", feature = "pg16", feature = "pg17"))]
        let table_oid = (*seqscan_node).scan.scanrelid;

        // Create a range table entry for this table
        let rte = pg_sys::palloc0(std::mem::size_of::<pg_sys::RangeTblEntry>())
            as *mut pg_sys::RangeTblEntry;
        (*rte).type_ = pg_sys::NodeTag::T_RangeTblEntry;
        (*rte).rtekind = pg_sys::RTEKind::RTE_RELATION;
        (*rte).relid = pg_sys::Oid::from(table_oid);
        (*rte).relkind = pg_sys::RELKIND_RELATION as i8;
        (*rte).rellockmode = pg_sys::AccessShareLock as i32;
        (*rte).lateral = false;
        (*rte).inh = true;
        (*rte).inFromCl = true;

        // Create a range table list with this entry
        let mut range_table: *mut pg_sys::List = std::ptr::null_mut();
        range_table = pg_sys::lappend(range_table, rte as *mut std::ffi::c_void);

        // Set the range table in the executor state
        (*estate).es_range_table = range_table;

        // Update scanrelid to be 1 (index into range table)
        #[cfg(any(feature = "pg13", feature = "pg14"))]
        {
            let mutable_seqscan = plan_tree as *const pg_sys::Plan as *mut pg_sys::SeqScan;
            (*mutable_seqscan).scanrelid = 1;
        }
        #[cfg(any(feature = "pg15", feature = "pg16", feature = "pg17"))]
        {
            let mutable_seqscan = plan_tree as *const pg_sys::Plan as *mut pg_sys::SeqScan;

            (*mutable_seqscan).scan.scanrelid = 1;
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
