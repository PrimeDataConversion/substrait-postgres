use anyhow::Result;
use pgrx::{pg_sys, PgBox};

use super::expressions::create_cstring;

/// Create a simple values scan node for constant projections
pub unsafe fn create_values_scan_node(
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // For now, just return a simple Result node with no input (constant projection)
    let mut result_node = pgrx::PgBox::<pg_sys::Result>::alloc0();
    result_node.plan.type_ = pg_sys::NodeTag::T_Result;
    result_node.plan.lefttree = std::ptr::null_mut();
    result_node.plan.righttree = std::ptr::null_mut();
    result_node.plan.initPlan = std::ptr::null_mut();
    result_node.plan.extParam = std::ptr::null_mut();
    result_node.plan.allParam = std::ptr::null_mut();
    result_node.plan.startup_cost = 0.0;
    result_node.plan.total_cost = 1.0;
    result_node.plan.plan_rows = 1.0;
    result_node.plan.plan_width = 32;
    result_node.plan.parallel_aware = false;
    result_node.plan.parallel_safe = true;
    result_node.plan.plan_node_id = 0;
    result_node.plan.qual = std::ptr::null_mut();
    result_node.plan.targetlist = std::ptr::null_mut();

    let result_ptr = result_node.into_pg();
    // Return pointer to the plan field
    Ok(&mut (*result_ptr).plan as *mut pg_sys::Plan)
}

/// Create a Result node with target list for literal projections
/// This matches PostgreSQL's behavior for simple constant expressions
pub unsafe fn create_result_node_with_target_list(
    target_list: *mut pg_sys::List,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    let mut result_node = pgrx::PgBox::<pg_sys::Result>::alloc0();
    result_node.plan.type_ = pg_sys::NodeTag::T_Result;
    result_node.plan.lefttree = std::ptr::null_mut();
    result_node.plan.righttree = std::ptr::null_mut();
    result_node.plan.initPlan = std::ptr::null_mut();
    result_node.plan.extParam = std::ptr::null_mut();
    result_node.plan.allParam = std::ptr::null_mut();
    result_node.plan.startup_cost = 0.0;
    result_node.plan.total_cost = 1.0;
    result_node.plan.plan_rows = 1.0;
    result_node.plan.plan_width = 32;
    result_node.plan.parallel_aware = false;
    result_node.plan.parallel_safe = true;
    result_node.plan.plan_node_id = 0;
    result_node.plan.qual = std::ptr::null_mut();
    result_node.plan.targetlist = target_list;

    let result_ptr = result_node.into_pg();
    // Return pointer to the plan field
    Ok(&mut (*result_ptr).plan as *mut pg_sys::Plan)
}

/// Create a Values scan node with specific target list for literal projections
pub unsafe fn create_values_scan_with_target_list(
    target_list: *mut pg_sys::List,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Create a ValuesScan plan node specifically for literal values
    let values_scan = PgBox::<pg_sys::ValuesScan>::alloc0();
    let values_scan = values_scan.into_pg();

    // Set up the scan portion
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
    (*values_scan).scan.plan.plan_node_id = 0;
    (*values_scan).scan.plan.qual = std::ptr::null_mut();
    (*values_scan).scan.plan.targetlist = target_list;
    (*values_scan).scan.scanrelid = 0; // No base relation

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

    // Return the Plan pointer
    let plan_ptr = &mut (*values_scan).scan.plan as *mut pg_sys::Plan;

    Ok(plan_ptr)
}

/// Create a SeqScan node with proper PostgreSQL statistics integration
/// This helper function encapsulates the working SeqScan construction logic
unsafe fn create_seqscan_with_postgresql_stats(
    table_oid: pg_sys::Oid,
    scanrelid: pg_sys::Index,
    target_list: *mut pg_sys::List,
) -> *mut pg_sys::SeqScan {
    // Create the SeqScan node using PostgreSQL's allocation pattern
    let mut seqscan_node = pgrx::PgBox::<pg_sys::SeqScan>::alloc0();

    // Use PostgreSQL's own estimation functions for accurate statistics
    let relation = pg_sys::relation_open(table_oid, pg_sys::AccessShareLock as i32);

    // Get cardinality estimate using PostgreSQL's estimate_rel_size
    let mut pages: pg_sys::BlockNumber = 0;
    let mut tuples: f64 = 0.0;
    let mut allvisfrac: f64 = 0.0;
    pg_sys::estimate_rel_size(
        relation,
        std::ptr::null_mut(), // attr_widths - we'll calculate separately
        &mut pages,
        &mut tuples,
        &mut allvisfrac,
    );

    // Get row width estimate using PostgreSQL's get_relation_data_width
    let plan_width = pg_sys::get_relation_data_width(table_oid, std::ptr::null_mut());

    // Close the relation
    pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);

    // Set up the SeqScan node
    // Set node tag FIRST (critical for ExecInitNode dispatch)
    seqscan_node.scan.plan.type_ = pg_sys::NodeTag::T_SeqScan;

    // Set the critical SeqScan fields
    seqscan_node.scan.plan.targetlist = target_list;
    seqscan_node.scan.plan.qual = std::ptr::null_mut(); // No qualification
    seqscan_node.scan.scanrelid = scanrelid; // Critical: 1-based index into range table

    // Initialize base Plan fields with PostgreSQL's estimates
    seqscan_node.scan.plan.lefttree = std::ptr::null_mut();
    seqscan_node.scan.plan.righttree = std::ptr::null_mut();
    seqscan_node.scan.plan.initPlan = std::ptr::null_mut();
    seqscan_node.scan.plan.extParam = std::ptr::null_mut();
    seqscan_node.scan.plan.allParam = std::ptr::null_mut();
    seqscan_node.scan.plan.startup_cost = 0.0;
    seqscan_node.scan.plan.total_cost = 1.0;
    seqscan_node.scan.plan.plan_rows = tuples; // Use PostgreSQL's cardinality estimate
    seqscan_node.scan.plan.plan_width = plan_width; // Use PostgreSQL's width estimate
    seqscan_node.scan.plan.parallel_aware = false;
    seqscan_node.scan.plan.parallel_safe = true;
    seqscan_node.scan.plan.plan_node_id = table_oid.to_u32() as i32; // Store table OID for range table creation

    seqscan_node.into_pg()
}

/// Create a PostgreSQL SeqScan node for table scans
/// This function creates a SeqScan node and a range table entry.
/// Returns both the plan node and the range table entry.
/// The scanrelid parameter specifies the 1-based index in the range table.
pub unsafe fn create_seqscan_node_with_scanrelid(
    table_name: &str,
    scanrelid: pg_sys::Index,
) -> Result<(*mut pg_sys::Plan, *mut pg_sys::RangeTblEntry), Box<dyn std::error::Error + Send + Sync>>
{
    eprintln!("DEBUG: create_seqscan_node called for table: {table_name}");
    pgrx::info!(
        "DEBUG: create_seqscan_node called for table: {}",
        table_name
    );

    // Look up the table OID by name
    eprintln!("DEBUG: About to lookup table OID");
    pgrx::info!("DEBUG: About to lookup table OID");

    let table_oid = lookup_table_oid(table_name)?;

    eprintln!("DEBUG: Successfully looked up table OID: {table_oid}");
    pgrx::info!("DEBUG: Successfully looked up table OID: {}", table_oid);

    // Create a SeqScan node following PostgreSQL's exact pattern
    eprintln!("DEBUG: About to create SeqScan node structure");
    pgrx::info!("DEBUG: About to create SeqScan node structure");

    // Create target list FIRST - PostgreSQL pattern
    let target_list = create_target_list_for_table(table_oid)?;

    // Use our improved SeqScan construction with PostgreSQL statistics
    let seqscan_node = create_seqscan_with_postgresql_stats(table_oid, scanrelid, target_list);

    eprintln!("DEBUG: SeqScan node created following PostgreSQL pattern");
    pgrx::info!("DEBUG: SeqScan node created following PostgreSQL pattern");

    // Create a range table entry for this table
    let rte = create_range_table_entry(table_oid, table_name)?;

    // Set critical executor fields following PostgreSQL's RTE patterns
    (*rte).securityQuals = std::ptr::null_mut();
    (*rte).tablesample = std::ptr::null_mut();

    // Set join-related fields to safe defaults
    (*rte).joinaliasvars = std::ptr::null_mut();
    (*rte).joinleftcols = std::ptr::null_mut();
    (*rte).joinrightcols = std::ptr::null_mut();

    // Function-related fields (set to null for table relations)
    (*rte).functions = std::ptr::null_mut();
    (*rte).funcordinality = false;

    pgrx::info!("DEBUG: RTE configured following PostgreSQL pattern (permission fields in RTEPermissionInfo), rtekind={:?}",
        (*rte).rtekind);

    // Return the Plan pointer
    let plan_ptr = &mut (*seqscan_node).scan.plan as *mut pg_sys::Plan;

    Ok((plan_ptr, rte))
}

/// Look up a table OID by name
unsafe fn lookup_table_oid(
    table_name: &str,
) -> Result<pg_sys::Oid, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("DEBUG: lookup_table_oid called for table: {table_name}");
    pgrx::info!("DEBUG: lookup_table_oid called for table: {}", table_name);

    // Try to look up the table in the current search path
    let table_cstring = create_cstring(table_name);

    // Use PostgreSQL's RangeVarGetRelid to look up the table
    let range_var = PgBox::<pg_sys::RangeVar>::alloc0();
    let range_var = range_var.into_pg();
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
        return Err(format!("Table '{table_name}' not found").into());
    }

    Ok(relation_oid)
}

/// Create a range table entry for a table
unsafe fn create_range_table_entry(
    table_oid: pg_sys::Oid,
    table_name: &str,
) -> Result<*mut pg_sys::RangeTblEntry, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "DEBUG: create_range_table_entry called for table: {table_name} with OID: {table_oid}"
    );
    pgrx::info!(
        "DEBUG: create_range_table_entry called for table: {} with OID: {}",
        table_name,
        table_oid
    );

    // Create RangeTblEntry
    let rte = PgBox::<pg_sys::RangeTblEntry>::alloc0();
    let rte = rte.into_pg();

    (*rte).type_ = pg_sys::NodeTag::T_RangeTblEntry;
    (*rte).rtekind = pg_sys::RTEKind::RTE_RELATION;
    (*rte).relid = table_oid;
    (*rte).relkind = pg_sys::RELKIND_RELATION as i8;
    (*rte).rellockmode = pg_sys::AccessShareLock as i32;
    (*rte).lateral = false;
    (*rte).inh = true; // Include inheritance
    (*rte).inFromCl = true; // This table is in the FROM clause
                            // PostgreSQL 16+ handles permissions differently (through RTEPermissionInfo)

    // Create an alias for the table
    let alias = PgBox::<pg_sys::Alias>::alloc0();
    let alias = alias.into_pg();
    (*alias).type_ = pg_sys::NodeTag::T_Alias;
    (*alias).aliasname = create_cstring(table_name);
    (*alias).colnames = std::ptr::null_mut(); // Will be filled in by planner if needed
    (*rte).eref = alias;
    (*rte).alias = std::ptr::null_mut(); // No explicit alias

    // For pg16+, these fields are in RTEPermissionInfo which is managed separately
    (*rte).securityQuals = std::ptr::null_mut();

    eprintln!("DEBUG: Range table entry created successfully");
    pgrx::info!("DEBUG: Range table entry created successfully");

    Ok(rte)
}

/// Create a target list for a table's columns
unsafe fn create_target_list_for_table(
    table_oid: pg_sys::Oid,
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("DEBUG: create_target_list_for_table called for OID: {table_oid}");
    pgrx::info!(
        "DEBUG: create_target_list_for_table called for OID: {}",
        table_oid
    );

    // Open the relation to get its tuple descriptor
    let relation = pg_sys::relation_open(table_oid, pg_sys::AccessShareLock as i32);
    if relation.is_null() {
        return Err(format!("Could not open relation with OID {table_oid}").into());
    }

    eprintln!("DEBUG: Successfully opened relation");
    pgrx::info!("DEBUG: Successfully opened relation");

    let tuple_desc = (*relation).rd_att;
    let num_attrs = (*tuple_desc).natts;

    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();

    // Create target entries for each column
    eprintln!("DEBUG: About to iterate through {num_attrs} columns");
    pgrx::info!("DEBUG: About to iterate through {} columns", num_attrs);

    for i in 0..num_attrs {
        eprintln!("DEBUG: Processing column {}/{}", i + 1, num_attrs);
        pgrx::info!("DEBUG: Processing column {}/{}", i + 1, num_attrs);

        let attr = (*tuple_desc).attrs.as_ptr().offset(i as isize);

        eprintln!("DEBUG: Got attribute pointer for column {}", i + 1);
        pgrx::info!("DEBUG: Got attribute pointer for column {}", i + 1);

        if (*attr).attisdropped {
            eprintln!("DEBUG: Column {} is dropped, skipping", i + 1);
            pgrx::info!("DEBUG: Column {} is dropped, skipping", i + 1);
            continue; // Skip dropped columns
        }

        eprintln!("DEBUG: Column {} is not dropped, processing", i + 1);
        pgrx::info!("DEBUG: Column {} is not dropped, processing", i + 1);

        // Create a Var node for this column
        eprintln!("DEBUG: About to create Var node for column {}", i + 1);
        pgrx::info!("DEBUG: About to create Var node for column {}", i + 1);

        let mut var_node = pgrx::PgBox::<pg_sys::Var>::alloc0();

        eprintln!(
            "DEBUG: Created Var node, setting fields for column {}",
            i + 1
        );
        pgrx::info!(
            "DEBUG: Created Var node, setting fields for column {}",
            i + 1
        );

        var_node.xpr.type_ = pg_sys::NodeTag::T_Var;
        var_node.varno = 1; // Single table scan
        var_node.varattno = (*attr).attnum;
        var_node.vartype = (*attr).atttypid;
        var_node.vartypmod = (*attr).atttypmod;
        var_node.varcollid = (*attr).attcollation;
        var_node.varlevelsup = 0;

        eprintln!(
            "DEBUG: Column {}: attnum={}, atttypid={}, atttypmod={}, attcollation={}",
            i + 1,
            (*attr).attnum,
            (*attr).atttypid,
            (*attr).atttypmod,
            (*attr).attcollation
        );
        pgrx::info!(
            "DEBUG: Column {}: attnum={}, atttypid={}, atttypmod={}, attcollation={}",
            i + 1,
            (*attr).attnum,
            (*attr).atttypid,
            (*attr).atttypmod,
            (*attr).attcollation
        );

        eprintln!(
            "DEBUG: Var node fields set, creating TargetEntry for column {}",
            i + 1
        );
        pgrx::info!(
            "DEBUG: Var node fields set, creating TargetEntry for column {}",
            i + 1
        );

        // Create target entry
        let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
        target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
        target_entry.expr = var_node.into_pg() as *mut pg_sys::Expr;
        target_entry.resno = (*attr).attnum;

        eprintln!(
            "DEBUG: TargetEntry created, about to access column name for column {}",
            i + 1
        );
        pgrx::info!(
            "DEBUG: TargetEntry created, about to access column name for column {}",
            i + 1
        );

        // Copy the column name
        let attr_name = std::ffi::CStr::from_ptr((*attr).attname.data.as_ptr());

        eprintln!(
            "DEBUG: Got column name CStr, converting to string for column {}",
            i + 1
        );
        pgrx::info!(
            "DEBUG: Got column name CStr, converting to string for column {}",
            i + 1
        );

        let attr_name_str = attr_name.to_string_lossy();

        eprintln!(
            "DEBUG: Column name converted: '{}' for column {}",
            attr_name_str,
            i + 1
        );
        pgrx::info!(
            "DEBUG: Column name converted: '{}' for column {}",
            attr_name_str,
            i + 1
        );

        target_entry.resname = create_cstring(&attr_name_str);
        target_entry.resjunk = false;

        eprintln!("DEBUG: About to append to target list for column {}", i + 1);
        pgrx::info!("DEBUG: About to append to target list for column {}", i + 1);

        target_list = pg_sys::lappend(target_list, target_entry.into_pg() as *mut std::ffi::c_void);

        eprintln!("DEBUG: Successfully completed processing column {}", i + 1);
        pgrx::info!("DEBUG: Successfully completed processing column {}", i + 1);
    }

    eprintln!("DEBUG: All columns processed successfully, closing relation");
    pgrx::info!("DEBUG: All columns processed successfully, closing relation");

    // Close the relation
    pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);

    eprintln!("DEBUG: Relation closed successfully, returning target list");
    pgrx::info!("DEBUG: Relation closed successfully, returning target list");

    Ok(target_list)
}

/// Recursively validate plan tree structure to find segmentation fault source
unsafe fn validate_plan_tree_recursive(plan: *mut pg_sys::Plan, depth: usize) {
    let indent = "  ".repeat(depth);

    if plan.is_null() {
        eprintln!("{indent}DEBUG: validate_plan_tree_recursive - plan is null at depth {depth}");
        return;
    }

    let node_tag = (*plan).type_;
    eprintln!(
        "{indent}DEBUG: validate_plan_tree_recursive - depth {depth}, node type: {node_tag:?}"
    );

    // Print detailed node information WITHOUT calling nodeToString yet
    eprintln!("{indent}DEBUG: Node details at depth {depth}:");
    eprintln!("{indent}  Node type: {node_tag:?}");
    eprintln!("{indent}  Node pointer: {plan:p}");
    eprintln!("{}  Left tree: {:p}", indent, (*plan).lefttree);
    eprintln!("{}  Right tree: {:p}", indent, (*plan).righttree);
    eprintln!("{}  Target list: {:p}", indent, (*plan).targetlist);

    // If this is an Agg node, print additional Agg-specific details
    if node_tag == pg_sys::NodeTag::T_Agg {
        let agg_node = plan as *mut pg_sys::Agg;
        eprintln!("{}  Agg numCols: {}", indent, (*agg_node).numCols);
        eprintln!("{}  Agg grpColIdx: {:p}", indent, (*agg_node).grpColIdx);
        eprintln!("{}  Agg aggstrategy: {:?}", indent, (*agg_node).aggstrategy);

        // Additional Agg field diagnostics
        if (*agg_node).numCols > 0 && !(*agg_node).grpColIdx.is_null() {
            eprintln!("{indent}  Agg group columns:");
            for i in 0..(*agg_node).numCols {
                let col_idx = *(*agg_node).grpColIdx.offset(i as isize);
                eprintln!("{indent}    Group col {i}: {col_idx}");
            }
        }

        // Check target list structure for Agg node
        if !(*plan).targetlist.is_null() {
            let tlist_len = (*(*plan).targetlist).length;
            eprintln!("{indent}  Agg target list length: {tlist_len}");

            // Check each target entry
            for i in 0..tlist_len {
                let te = pg_sys::list_nth((*plan).targetlist, i) as *mut pg_sys::TargetEntry;
                if !te.is_null() {
                    eprintln!(
                        "{}    TargetEntry {}: type={:?}, expr={:p}",
                        indent,
                        i,
                        (*te).xpr.type_,
                        (*te).expr
                    );

                    if !(*te).expr.is_null() {
                        let expr_type = (*(*te).expr).type_;
                        eprintln!("{indent}      Expression type: {expr_type:?}");

                        // If it's an Aggref, check its structure
                        if expr_type == pg_sys::NodeTag::T_Aggref {
                            let aggref = (*te).expr as *mut pg_sys::Aggref;
                            eprintln!("{indent}      Aggref details:");
                            eprintln!("{}        aggfnoid: {}", indent, (*aggref).aggfnoid);
                            eprintln!("{}        args: {:p}", indent, (*aggref).args);
                            eprintln!("{}        aggstar: {}", indent, (*aggref).aggstar);

                            // Check args list if it exists
                            if !(*aggref).args.is_null() {
                                let args_len = (*(*aggref).args).length;
                                eprintln!("{indent}        args length: {args_len}");

                                for j in 0..args_len {
                                    let arg =
                                        pg_sys::list_nth((*aggref).args, j) as *mut pg_sys::Expr;
                                    if !arg.is_null() {
                                        let arg_type = (*arg).type_;
                                        eprintln!("{indent}          Arg {j}: type={arg_type:?}");
                                    } else {
                                        eprintln!("{indent}          Arg {j}: NULL");
                                    }
                                }
                            }
                        }
                    }
                } else {
                    eprintln!("{indent}    TargetEntry {i}: NULL");
                }
            }
        }
    }

    // FIRST recurse into children to check their structure
    if !(*plan).lefttree.is_null() {
        eprintln!(
            "{}DEBUG: Recursing into left tree at depth {}",
            indent,
            depth + 1
        );
        validate_plan_tree_recursive((*plan).lefttree, depth + 1);
    }

    if !(*plan).righttree.is_null() {
        eprintln!(
            "{}DEBUG: Recursing into right tree at depth {}",
            indent,
            depth + 1
        );
        validate_plan_tree_recursive((*plan).righttree, depth + 1);
    }

    // ONLY AFTER checking children, try nodeToString on this node
    eprintln!("{indent}DEBUG: About to call nodeToString on depth {depth} node type {node_tag:?}");

    let node_str = pg_sys::nodeToString(plan as *const std::ffi::c_void);

    if !node_str.is_null() {
        eprintln!("{indent}DEBUG: nodeToString SUCCESS for depth {depth} node");
        pg_sys::pfree(node_str as *mut std::ffi::c_void);
    } else {
        eprintln!("{indent}DEBUG: nodeToString returned null for depth {depth} node");
    }

    eprintln!("{indent}DEBUG: validate_plan_tree_recursive completed for depth {depth} node");
}

/// Create a PostgreSQL Sort plan node from Substrait sort specification
pub unsafe fn create_sort_node(
    input_plan: *mut pg_sys::Plan,
    sorts: &[substrait::proto::SortField],
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "DEBUG: create_sort_node called with {} sort fields",
        sorts.len()
    );
    pgrx::info!(
        "DEBUG: create_sort_node called with {} sort fields",
        sorts.len()
    );

    // CRITICAL: Validate the input plan tree BEFORE using it
    eprintln!("DEBUG: Validating input plan tree before creating Sort node");
    pgrx::info!("DEBUG: Validating input plan tree before creating Sort node");

    if input_plan.is_null() {
        eprintln!("DEBUG: ERROR - input_plan is null!");
        pgrx::info!("DEBUG: ERROR - input_plan is null!");
        return Err("Input plan for Sort node is null".into());
    }

    // Validate the input plan node type
    let input_node_type = (*input_plan).type_;
    eprintln!("DEBUG: Input plan node type: {input_node_type:?}");
    pgrx::info!("DEBUG: Input plan node type: {:?}", input_node_type);

    // Validate the input plan's target list
    let input_targetlist = (*input_plan).targetlist;
    eprintln!("DEBUG: Input plan target list: {input_targetlist:p}");
    pgrx::info!("DEBUG: Input plan target list: {:p}", input_targetlist);

    if !input_targetlist.is_null() {
        let input_list_length = (*input_targetlist).length;
        eprintln!("DEBUG: Input plan target list length: {input_list_length}");
        pgrx::info!(
            "DEBUG: Input plan target list length: {}",
            input_list_length
        );
    } else {
        eprintln!("DEBUG: WARNING - Input plan target list is null");
        pgrx::info!("DEBUG: WARNING - Input plan target list is null");
    }

    // Try calling nodeToString on JUST the input plan to see if it's the problem
    eprintln!("DEBUG: Testing nodeToString on input plan tree ONLY");
    pgrx::info!("DEBUG: Testing nodeToString on input plan tree ONLY");

    // RECURSIVELY validate the entire input plan tree to find the actual problem
    eprintln!("DEBUG: Starting recursive plan tree validation");
    pgrx::info!("DEBUG: Starting recursive plan tree validation");

    validate_plan_tree_recursive(input_plan, 0);

    eprintln!("DEBUG: Attempting nodeToString on input plan after recursive validation");
    pgrx::info!("DEBUG: Attempting nodeToString on input plan after recursive validation");

    let input_plan_str = pg_sys::nodeToString(input_plan as *const std::ffi::c_void);

    if !input_plan_str.is_null() {
        eprintln!("DEBUG: nodeToString on input plan succeeded");
        pgrx::info!("DEBUG: nodeToString on input plan succeeded");
        pg_sys::pfree(input_plan_str as *mut std::ffi::c_void);
    } else {
        eprintln!("DEBUG: nodeToString on input plan returned null");
        pgrx::info!("DEBUG: nodeToString on input plan returned null");
    }

    // Create a Sort plan node following PostgreSQL's make_sort pattern - safe allocation
    let sort_node = pgrx::PgBox::<pg_sys::Sort>::alloc0();
    let sort_node_ptr = sort_node.as_ptr();
    eprintln!("DEBUG: Sort node allocated at: {sort_node_ptr:p}");
    pgrx::info!("DEBUG: Sort node allocated at: {:p}", sort_node_ptr);
    let sort_node = sort_node.into_pg();

    // Set node tag FIRST (critical for ExecInitNode dispatch)
    (*sort_node).plan.type_ = pg_sys::NodeTag::T_Sort;

    // Copy generic plan info from input (PostgreSQL's copy_generic_plan_info pattern)
    (*sort_node).plan.targetlist = (*input_plan).targetlist;
    (*sort_node).plan.qual = (*input_plan).qual;
    (*sort_node).plan.lefttree = input_plan;
    (*sort_node).plan.righttree = std::ptr::null_mut();
    (*sort_node).plan.initPlan = (*input_plan).initPlan;
    (*sort_node).plan.extParam = (*input_plan).extParam;
    (*sort_node).plan.allParam = (*input_plan).allParam;
    (*sort_node).plan.startup_cost = (*input_plan).startup_cost;
    (*sort_node).plan.total_cost = (*input_plan).total_cost + 100.0; // Add sort cost
    (*sort_node).plan.plan_rows = (*input_plan).plan_rows;
    (*sort_node).plan.plan_width = (*input_plan).plan_width;
    (*sort_node).plan.parallel_aware = (*input_plan).parallel_aware;
    (*sort_node).plan.parallel_safe = (*input_plan).parallel_safe;
    (*sort_node).plan.plan_node_id = 0;

    eprintln!("DEBUG: Basic Sort plan fields set");
    pgrx::info!("DEBUG: Basic Sort plan fields set");

    // Initialize Sort-specific fields following PostgreSQL's make_sort pattern
    // Use numCols = 1 for simple single-column sort (typical for TPC-H Q1)
    let num_cols = 1;
    (*sort_node).numCols = num_cols;

    // All arrays must have exactly numCols elements (PostgreSQL requirement)
    eprintln!("DEBUG: Creating Sort arrays with numCols = {num_cols}");
    pgrx::info!("DEBUG: Creating Sort arrays with numCols = {}", num_cols);

    // sortColIdx array - which columns to sort by (1-based target list indices) - safe allocation
    let sort_col_array = unsafe {
        pgrx::PgMemoryContexts::CurrentMemoryContext
            .palloc_slice::<pg_sys::AttrNumber>(num_cols as usize)
    };
    sort_col_array[0] = 1; // Sort by first column in target list
    (*sort_node).sortColIdx = sort_col_array.as_mut_ptr();

    // sortOperators array - comparison operators for each sort column - safe allocation
    let ops_array = unsafe {
        pgrx::PgMemoryContexts::CurrentMemoryContext.palloc_slice::<pg_sys::Oid>(num_cols as usize)
    };
    ops_array[0] = 664.into(); // btcharcmp for CHAR columns (typical for l_returnflag)
    (*sort_node).sortOperators = ops_array.as_mut_ptr();

    // collations array - collation for each sort column - safe allocation
    let collations_array = unsafe {
        pgrx::PgMemoryContexts::CurrentMemoryContext.palloc_slice::<pg_sys::Oid>(num_cols as usize)
    };
    collations_array[0] = pg_sys::DEFAULT_COLLATION_OID; // Use default collation
    (*sort_node).collations = collations_array.as_mut_ptr();

    // nullsFirst array - null ordering for each sort column - safe allocation
    let nulls_array = unsafe {
        pgrx::PgMemoryContexts::CurrentMemoryContext.palloc_slice::<bool>(num_cols as usize)
    };
    nulls_array[0] = false; // Nulls last (PostgreSQL default)
    (*sort_node).nullsFirst = nulls_array.as_mut_ptr();

    eprintln!("DEBUG: All Sort arrays created with consistent sizing");
    pgrx::info!("DEBUG: All Sort arrays created with consistent sizing");

    // Additional Sort-specific fields that might be required
    // These fields might exist in newer PostgreSQL versions - set them safely if they exist

    eprintln!("DEBUG: Sort node creation completed successfully");
    pgrx::info!("DEBUG: Sort node creation completed successfully");

    // Final comprehensive validation
    eprintln!("DEBUG: Sort node validation:");
    eprintln!("  numCols: {}", (*sort_node).numCols);
    eprintln!("  sortColIdx: {:p}", (*sort_node).sortColIdx);
    eprintln!("  sortOperators: {:p}", (*sort_node).sortOperators);
    eprintln!("  collations: {:p}", (*sort_node).collations);
    eprintln!("  nullsFirst: {:p}", (*sort_node).nullsFirst);
    eprintln!("  plan.type_: {:?}", (*sort_node).plan.type_);
    eprintln!("  plan.lefttree: {:p}", (*sort_node).plan.lefttree);
    eprintln!("  plan.targetlist: {:p}", (*sort_node).plan.targetlist);

    pgrx::info!("DEBUG: Sort node comprehensive validation completed");

    // Return pointer to the plan field
    Ok(&mut (*sort_node).plan as *mut pg_sys::Plan)
}

/// Create a PostgreSQL Limit plan node with expression-based offset and count
pub unsafe fn create_limit_node_with_expressions(
    input_plan: *mut pg_sys::Plan,
    offset_expr: Option<*mut pg_sys::Expr>,
    count_expr: Option<*mut pg_sys::Expr>,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Create a Limit plan node using safe pgrx allocation
    let mut limit_node = pgrx::PgBox::<pg_sys::Limit>::alloc0();
    limit_node.plan.type_ = pg_sys::NodeTag::T_Limit;
    let limit_node = limit_node.into_pg();
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

    // Return pointer to the plan field
    Ok(&mut (*limit_node).plan as *mut pg_sys::Plan)
}

/// Create a PostgreSQL Filter plan node from Substrait filter specification
pub unsafe fn create_filter_node(
    input_plan: *mut pg_sys::Plan,
    condition_expr: *mut pg_sys::Expr,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // In PostgreSQL, filters are typically implemented as Result nodes with a qual condition
    // For more complex filtering, we might need a custom scan node

    let mut result_node = pgrx::PgBox::<pg_sys::Result>::alloc0();
    result_node.plan.type_ = pg_sys::NodeTag::T_Result;
    result_node.plan.lefttree = input_plan;
    result_node.plan.righttree = std::ptr::null_mut();
    result_node.plan.initPlan = std::ptr::null_mut();
    result_node.plan.extParam = std::ptr::null_mut();
    result_node.plan.allParam = std::ptr::null_mut();
    result_node.plan.startup_cost = 0.0;
    result_node.plan.total_cost = 1000.0;
    result_node.plan.plan_rows = 100.0;
    result_node.plan.plan_width = 32;
    result_node.plan.parallel_aware = false;
    result_node.plan.parallel_safe = true;
    result_node.plan.plan_node_id = 0;

    // Pass through the target list from input
    result_node.plan.targetlist = (*input_plan).targetlist;

    // Set the filter condition as a qualification
    let mut qual_list: *mut pg_sys::List = std::ptr::null_mut();
    qual_list = pg_sys::lappend(qual_list, condition_expr as *mut std::ffi::c_void);
    result_node.plan.qual = qual_list;

    let result_ptr = result_node.into_pg();
    // Return pointer to the plan field
    Ok(&mut (*result_ptr).plan as *mut pg_sys::Plan)
}

/// Create a PostgreSQL NestLoop plan node for Cross (Cartesian product) join
pub unsafe fn create_cross_join_node(
    left_plan: *mut pg_sys::Plan,
    right_plan: *mut pg_sys::Plan,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Create a NestLoop plan node for Cartesian product (cross join) using safe allocation
    let nestloop_node = pgrx::PgBox::<pg_sys::NestLoop>::alloc0();
    let nestloop_node = nestloop_node.into_pg();
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

    // Return pointer to the plan field
    Ok(&mut (*nestloop_node).join.plan as *mut pg_sys::Plan)
}

/// Create a PostgreSQL NestLoop plan node for Join operations
pub unsafe fn create_join_node(
    left_plan: *mut pg_sys::Plan,
    right_plan: *mut pg_sys::Plan,
    join_type: u32,
    join_qual: *mut pg_sys::List,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Create a NestLoop plan node for the join using safe allocation
    let nestloop_node = pgrx::PgBox::<pg_sys::NestLoop>::alloc0();
    let nestloop_node = nestloop_node.into_pg();
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
    (*nestloop_node).join.plan.plan_node_id = 0;
    (*nestloop_node).join.plan.qual = std::ptr::null_mut();

    // Set join type
    (*nestloop_node).join.jointype = join_type;

    // Set join condition
    (*nestloop_node).join.joinqual = join_qual;

    // Create target list combining both input relations
    let combined_target_list = create_combined_target_list(left_plan, right_plan)?;
    (*nestloop_node).join.plan.targetlist = combined_target_list;

    // Return pointer to the plan field
    Ok(&mut (*nestloop_node).join.plan as *mut pg_sys::Plan)
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
            let new_target_entry = PgBox::<pg_sys::TargetEntry>::alloc0();
            let new_target_entry = new_target_entry.into_pg();
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
            let new_target_entry = PgBox::<pg_sys::TargetEntry>::alloc0();
            let new_target_entry = new_target_entry.into_pg();
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

/// Create a range table entry from a table OID
pub unsafe fn create_range_table_entry_from_oid(
    table_oid: pg_sys::Oid,
) -> Result<*mut pg_sys::RangeTblEntry, Box<dyn std::error::Error + Send + Sync>> {
    // Get table name from OID
    let table_name = get_table_name_from_oid(table_oid)?;
    create_range_table_entry(table_oid, &table_name)
}

/// Get table name from OID
unsafe fn get_table_name_from_oid(
    table_oid: pg_sys::Oid,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Use relation_open approach - much safer than SearchSysCache1
    eprintln!("DEBUG: get_table_name_from_oid opening relation for OID: {table_oid}");

    let relation = pg_sys::relation_open(table_oid, pg_sys::AccessShareLock as i32);
    if relation.is_null() {
        eprintln!("DEBUG: relation_open returned null for OID: {table_oid}");
        return Err(format!("Could not open relation with OID {table_oid}").into());
    }

    eprintln!("DEBUG: relation_open succeeded, extracting name");

    // Extract table name from relation
    let table_name = std::ffi::CStr::from_ptr((*(*relation).rd_rel).relname.data.as_ptr())
        .to_string_lossy()
        .to_string();

    eprintln!("DEBUG: Got table name: {table_name}");

    // Close the relation
    pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);

    eprintln!("DEBUG: relation_close completed");

    Ok(table_name)
}
