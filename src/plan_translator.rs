use anyhow::Result;
use pgrx::pg_sys;
use std::collections::HashMap;
use substrait::proto::rel::RelType;
use substrait::proto::{Expression, Plan, PlanRel, Rel};

/// Get a human-readable name for a Substrait relation type
fn get_relation_type_name(rel_type: &RelType) -> &'static str {
    match rel_type {
        RelType::Project(_) => "Project",
        RelType::Read(_) => "Read",
        RelType::Aggregate(_) => "Aggregate",
        RelType::Sort(_) => "Sort",
        RelType::Filter(_) => "Filter",
        RelType::Join(_) => "Join",
        RelType::Cross(_) => "Cross",
        RelType::Fetch(_) => "Fetch",
        RelType::Window(_) => "Window",
        RelType::Exchange(_) => "Exchange",
        RelType::HashJoin(_) => "HashJoin",
        RelType::MergeJoin(_) => "MergeJoin",
        RelType::NestedLoopJoin(_) => "NestedLoopJoin",
        RelType::Set(_) => "Set",
        RelType::ExtensionSingle(_) => "ExtensionSingle",
        RelType::ExtensionMulti(_) => "ExtensionMulti",
        RelType::ExtensionLeaf(_) => "ExtensionLeaf",
        RelType::Ddl(_) => "DDL",
        RelType::Write(_) => "Write",
        RelType::Reference(_) => "Reference",
        RelType::Update(_) => "Update",
        RelType::Expand(_) => "Expand",
    }
}

/// Get a human-readable name for a Substrait expression type
fn get_expression_type_name(rex_type: &substrait::proto::expression::RexType) -> &'static str {
    use substrait::proto::expression::RexType;
    match rex_type {
        RexType::Literal(_) => "Literal",
        RexType::Selection(_) => "Selection",
        RexType::ScalarFunction(_) => "ScalarFunction",
        RexType::WindowFunction(_) => "WindowFunction",
        RexType::IfThen(_) => "IfThen",
        RexType::SwitchExpression(_) => "SwitchExpression",
        RexType::SingularOrList(_) => "SingularOrList",
        RexType::MultiOrList(_) => "MultiOrList",
        RexType::Cast(_) => "Cast",
        RexType::Subquery(_) => "Subquery",
        RexType::Nested(_) => "Nested",
        RexType::Enum(_) => "Enum",
        RexType::DynamicParameter(_) => "DynamicParameter",
    }
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub columns: Vec<ColumnInfo>,
    pub rows: Vec<Vec<pg_sys::Datum>>,
    pub nulls: Vec<Vec<bool>>,
}

#[derive(Debug)]
pub struct ColumnInfo {
    pub name: String,
    pub type_oid: pg_sys::Oid,
    pub type_mod: i32,
    pub attr_number: pg_sys::AttrNumber,
}

/// Translates a Substrait plan to a PostgreSQL plan tree without executing it
pub fn translate_substrait_plan(
    plan: Plan,
) -> Result<(&'static pg_sys::Plan, Vec<String>), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "DEBUG: translate_substrait_plan called with {} relations",
        plan.relations.len()
    );

    // Build function extension map for reference lookup
    let function_map = build_function_extension_map(&plan);
    eprintln!(
        "DEBUG: Built function map with {} functions",
        function_map.len()
    );
    for (ref_id, func_name) in &function_map {
        eprintln!("  Function ref {}: {}", ref_id, func_name);
    }

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
        let plan_tree = convert_plan_relation_to_plan_tree_with_context(relation, &function_map)?;

        // Debug: Print the PostgreSQL plan tree structure
        let plan_str = pg_sys::nodeToString(plan_tree as *const std::ffi::c_void);
        if !plan_str.is_null() {
            let plan_cstr = std::ffi::CStr::from_ptr(plan_str);
            if let Ok(plan_string) = plan_cstr.to_str() {
                eprintln!("DEBUG: PostgreSQL Plan Tree: {}", plan_string);
                pgrx::info!("PostgreSQL Plan Tree: {}", plan_string);
            }
            pg_sys::pfree(plan_str as *mut std::ffi::c_void);
        }

        Ok((&*plan_tree, column_names))
    }
}

/// Executes a PostgreSQL plan tree and returns the results
pub unsafe fn execute_postgres_plan(
    plan_tree: &pg_sys::Plan,
    column_names: Vec<String>,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
    let mut result = crate::executor::execute_plan_tree_structured(plan_tree)?;

    // Update column names with the ones from the plan schema.
    // This ensures the returned schema matches the shape of the Substrait plan.
    // TODO: Make sure this works with complex types.
    for (i, column) in result.columns.iter_mut().enumerate() {
        if i < column_names.len() {
            column.name = column_names[i].clone();
        }
    }

    Ok(result)
}

/// Legacy function for backward compatibility - combines translation and execution
pub fn execute_substrait_plan(
    plan: Plan,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
    let (plan_tree, column_names) = translate_substrait_plan(plan)?;
    unsafe { execute_postgres_plan(plan_tree, column_names) }
}

pub unsafe fn convert_plan_relation_to_plan_tree(
    relation: &PlanRel,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Use an empty function map for backward compatibility
    let empty_function_map = HashMap::new();
    convert_plan_relation_to_plan_tree_with_context(relation, &empty_function_map)
}

pub unsafe fn convert_rel_to_plan_tree(
    rel: &Rel,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // Use an empty function map for backward compatibility
    let empty_function_map = HashMap::new();
    convert_rel_to_plan_tree_with_context(rel, &empty_function_map)
}

pub unsafe fn convert_expressions_to_target_list(
    expressions: &[Expression],
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();

    for (i, expr) in expressions.iter().enumerate() {
        let target_entry = convert_expression_to_target_entry(expr, i)?;
        target_list = pg_sys::lappend(target_list, target_entry as *mut std::ffi::c_void);
    }

    Ok(target_list)
}

unsafe fn convert_expression_to_target_entry(
    expr: &Expression,
    index: usize,
) -> Result<*mut pg_sys::TargetEntry, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::RexType;

    match &expr.rex_type {
        Some(RexType::Literal(literal)) => {
            // Handle literal values
            if let Some(literal_type) = &literal.literal_type {
                let const_expr = match literal_type {
                    substrait::proto::expression::literal::LiteralType::I32(val) => {
                        create_int4_const(*val)?
                    }
                    substrait::proto::expression::literal::LiteralType::I64(val) => {
                        create_int8_const(*val)?
                    }
                    substrait::proto::expression::literal::LiteralType::String(val) => {
                        create_text_const(val)?
                    }
                    _ => {
                        return Err(
                            format!("Unsupported literal type for expression {}", index).into()
                        )
                    }
                };

                // Create TargetEntry
                let target_entry = pg_sys::palloc0(std::mem::size_of::<pg_sys::TargetEntry>())
                    as *mut pg_sys::TargetEntry;
                (*target_entry).expr = const_expr;
                (*target_entry).resno = (index + 1) as pg_sys::AttrNumber;
                (*target_entry).resname = create_cstring(&format!("column_{}", index + 1));
                (*target_entry).resjunk = false;

                Ok(target_entry)
            } else {
                Err(format!("Literal expression {} missing literal type", index).into())
            }
        }
        _ => Err(format!("Unsupported expression type at index {}", index).into()),
    }
}

pub unsafe fn create_int4_const(
    value: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Use the PostgreSQL built-in constant, but validate it first
    let type_oid = pg_sys::INT4OID;

    // Validate that the OID is reasonable (should not be 0 or InvalidOid)
    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
        return Err(format!("Invalid INT4OID: {}", type_oid).into());
    }

    let const_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Const>()) as *mut pg_sys::Const;
    (*const_node).xpr.type_ = pg_sys::NodeTag::T_Const;
    (*const_node).consttype = type_oid;
    (*const_node).consttypmod = -1;
    (*const_node).constcollid = pg_sys::InvalidOid;
    (*const_node).constlen = 4;
    (*const_node).constvalue = pg_sys::Datum::from(value);
    (*const_node).constisnull = false;
    (*const_node).constbyval = true;

    Ok(const_node as *mut pg_sys::Expr)
}

pub unsafe fn create_int8_const(
    value: i64,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Use the PostgreSQL built-in constant, but validate it first
    let type_oid = pg_sys::INT8OID;

    // Validate that the OID is reasonable (should not be 0 or InvalidOid)
    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
        return Err(format!("Invalid INT8OID: {}", type_oid).into());
    }

    let const_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Const>()) as *mut pg_sys::Const;
    (*const_node).xpr.type_ = pg_sys::NodeTag::T_Const;
    (*const_node).consttype = type_oid;
    (*const_node).consttypmod = -1;
    (*const_node).constcollid = pg_sys::InvalidOid;
    (*const_node).constlen = 8;
    (*const_node).constvalue = pg_sys::Datum::from(value);
    (*const_node).constisnull = false;
    (*const_node).constbyval = true;

    Ok(const_node as *mut pg_sys::Expr)
}

pub unsafe fn create_text_const(
    value: &str,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Use the PostgreSQL built-in constant, but validate it first
    let type_oid = pg_sys::TEXTOID;

    // Validate that the OID is reasonable (should not be 0 or InvalidOid)
    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
        return Err(format!("Invalid TEXTOID: {}", type_oid).into());
    }

    let text_datum =
        pg_sys::cstring_to_text_with_len(value.as_ptr() as *const i8, value.len() as i32);

    let const_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Const>()) as *mut pg_sys::Const;
    (*const_node).xpr.type_ = pg_sys::NodeTag::T_Const;
    (*const_node).consttype = type_oid;
    (*const_node).consttypmod = -1;
    (*const_node).constcollid = pg_sys::DEFAULT_COLLATION_OID;
    (*const_node).constlen = -1;
    (*const_node).constvalue = pg_sys::Datum::from(text_datum as *mut std::ffi::c_void);
    (*const_node).constisnull = false;
    (*const_node).constbyval = false;

    Ok(const_node as *mut pg_sys::Expr)
}

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

pub unsafe fn create_cstring(s: &str) -> *mut i8 {
    let cstr = std::ffi::CString::new(s).unwrap();
    let len = cstr.as_bytes_with_nul().len();
    let ptr = pg_sys::palloc(len) as *mut i8;
    std::ptr::copy_nonoverlapping(cstr.as_ptr(), ptr, len);
    ptr
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

/// Create a PostgreSQL Limit plan node from Substrait fetch specification
pub unsafe fn create_limit_node(
    input_plan: *mut pg_sys::Plan,
    offset: i64,
    count: i64,
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

    // Set limit count
    if count > 0 {
        let count_const = create_int8_const(count)?;
        (*limit_node).limitCount = count_const as *mut pg_sys::Node;
    } else {
        (*limit_node).limitCount = std::ptr::null_mut();
    }

    // Set limit offset
    if offset > 0 {
        let offset_const = create_int8_const(offset)?;
        (*limit_node).limitOffset = offset_const as *mut pg_sys::Node;
    } else {
        (*limit_node).limitOffset = std::ptr::null_mut();
    }

    Ok(limit_node as *mut pg_sys::Plan)
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

/// Convert a Substrait expression to a PostgreSQL expression tree
pub unsafe fn convert_expression_to_postgres(
    expr: &Expression,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::RexType;

    match &expr.rex_type {
        Some(RexType::Literal(literal)) => {
            // Handle literal values
            if let Some(literal_type) = &literal.literal_type {
                match literal_type {
                    substrait::proto::expression::literal::LiteralType::I32(val) => {
                        create_int4_const(*val)
                    }
                    substrait::proto::expression::literal::LiteralType::I64(val) => {
                        create_int8_const(*val)
                    }
                    substrait::proto::expression::literal::LiteralType::String(val) => {
                        create_text_const(val)
                    }
                    substrait::proto::expression::literal::LiteralType::Date(val) => {
                        // For now, treat date as int32 (days since epoch)
                        create_int4_const(*val)
                    }
                    substrait::proto::expression::literal::LiteralType::FixedChar(val) => {
                        create_text_const(val)
                    }
                    _ => Err("Unsupported literal type in filter condition".into()),
                }
            } else {
                Err("Literal expression missing literal type".into())
            }
        }
        Some(RexType::Selection(selection)) => {
            // Handle column references - use reference_type directly
            if let Some(ref_type) = &selection.reference_type {
                match ref_type {
                    substrait::proto::expression::field_reference::ReferenceType::DirectReference(direct_ref) => {
                        if let Some(struct_field) = &direct_ref.reference_type {
                            match struct_field {
                                substrait::proto::expression::reference_segment::ReferenceType::StructField(field) => {
                                    create_var_node(field.field as i32 + 1) // 1-based indexing
                                }
                                _ => Err("Unsupported reference type in filter condition".into()),
                            }
                        } else {
                            Err("Missing reference type in direct reference".into())
                        }
                    }
                    _ => Err("Unsupported field reference type in filter condition".into()),
                }
            } else {
                Err("Missing reference type in selection".into())
            }
        }
        Some(RexType::ScalarFunction(func)) => {
            // Handle scalar functions (e.g., comparison operators)
            create_scalar_function_expr(func)
        }
        Some(RexType::Cast(cast)) => {
            // Handle type casts
            let input_expr = if let Some(input) = &cast.input {
                convert_expression_to_postgres(input)?
            } else {
                return Err("Cast expression missing input".into());
            };

            // For now, just return the input expression without casting
            // TODO: Implement proper type casting
            Ok(input_expr)
        }
        _ => Err("Unsupported expression type in filter condition".into()),
    }
}

/// Create a PostgreSQL Var node for column references
pub unsafe fn create_var_node(
    attr_number: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let var_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Var>()) as *mut pg_sys::Var;
    (*var_node).xpr.type_ = pg_sys::NodeTag::T_Var;
    (*var_node).varno = 1; // Single table reference for now
    (*var_node).varattno = attr_number as pg_sys::AttrNumber;
    (*var_node).vartype = pg_sys::UNKNOWNOID; // Will be resolved during planning
    (*var_node).vartypmod = -1;
    (*var_node).varcollid = pg_sys::InvalidOid;
    (*var_node).varlevelsup = 0;

    Ok(var_node as *mut pg_sys::Expr)
}

/// Create a PostgreSQL scalar function expression
pub unsafe fn create_scalar_function_expr(
    func: &substrait::proto::expression::ScalarFunction,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // For now, create a simple comparison operation
    // In a full implementation, we'd need to map Substrait function references to PostgreSQL operators

    // Debug: Extract function information for better error reporting
    let function_reference = func.function_reference;
    let argument_count = func.arguments.len();

    // Debug the actual argument structure
    eprintln!("DEBUG: Scalar function details:");
    eprintln!("  function_reference: {}", function_reference);
    eprintln!("  arguments.len(): {}", argument_count);
    eprintln!("  args field len: {}", func.args.len());
    eprintln!("  Function should be 'lte:date_date' based on plan");

    for (i, arg) in func.arguments.iter().enumerate() {
        eprintln!("  arg[{}]: has_arg_type={}", i, arg.arg_type.is_some());
    }

    if func.arguments.len() == 2 {
        // Binary comparison - assume it's a less-than-equal comparison for dates
        let left_arg = if let Some(arg) = func.arguments.get(0) {
            if let Some(value) = &arg.arg_type {
                match value {
                    substrait::proto::function_argument::ArgType::Value(expr) => {
                        convert_expression_to_postgres(expr)?
                    }
                    _ => return Err("Unsupported argument type in scalar function".into()),
                }
            } else {
                return Err("Missing argument type in scalar function".into());
            }
        } else {
            return Err("Missing left argument in binary function".into());
        };

        let right_arg = if let Some(arg) = func.arguments.get(1) {
            if let Some(value) = &arg.arg_type {
                match value {
                    substrait::proto::function_argument::ArgType::Value(expr) => {
                        convert_expression_to_postgres(expr)?
                    }
                    _ => return Err("Unsupported argument type in scalar function".into()),
                }
            } else {
                return Err("Missing argument type in scalar function".into());
            }
        } else {
            return Err("Missing right argument in binary function".into());
        };

        // Create a binary operation expression (less-than-equal for now)
        create_binary_op_expr(
            left_arg,
            right_arg,
            pg_sys::Oid::from(1058),
            pg_sys::BOOLOID,
        ) // DATE_LE_OP
    } else {
        Err(format!(
            "Unsupported scalar function with non-binary arguments (function_reference={}, args_count={})",
            function_reference, argument_count
        )
        .into())
    }
}

/// Create a PostgreSQL binary operation expression
pub unsafe fn create_binary_op_expr(
    left_arg: *mut pg_sys::Expr,
    right_arg: *mut pg_sys::Expr,
    operator_oid: pg_sys::Oid,
    result_type: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let op_expr = pg_sys::palloc0(std::mem::size_of::<pg_sys::OpExpr>()) as *mut pg_sys::OpExpr;
    (*op_expr).xpr.type_ = pg_sys::NodeTag::T_OpExpr;
    (*op_expr).opno = operator_oid;
    (*op_expr).opfuncid = pg_sys::InvalidOid; // Will be resolved during planning
    (*op_expr).opresulttype = result_type;
    (*op_expr).opretset = false;
    (*op_expr).opcollid = pg_sys::InvalidOid;
    (*op_expr).inputcollid = pg_sys::InvalidOid;

    // Create argument list
    let mut args: *mut pg_sys::List = std::ptr::null_mut();
    args = pg_sys::lappend(args, left_arg as *mut std::ffi::c_void);
    args = pg_sys::lappend(args, right_arg as *mut std::ffi::c_void);
    (*op_expr).args = args;

    Ok(op_expr as *mut pg_sys::Expr)
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

/// Build a map of function references to their names from the plan's extensions
fn build_function_extension_map(plan: &Plan) -> HashMap<u32, String> {
    let mut function_map = HashMap::new();

    for extension in &plan.extensions {
        if let Some(ext_type) = &extension.mapping_type {
            match ext_type {
                substrait::proto::extensions::simple_extension_declaration::MappingType::ExtensionFunction(func) => {
                    function_map.insert(func.function_anchor, func.name.clone());
                }
                _ => {} // Handle other extension types as needed
            }
        }
    }

    function_map
}

/// Convert plan relation with function context
pub unsafe fn convert_plan_relation_to_plan_tree_with_context(
    relation: &PlanRel,
    _function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(rel_type) = &relation.rel_type {
        match rel_type {
            substrait::proto::plan_rel::RelType::Root(root) => {
                if let Some(input) = &root.input {
                    convert_rel_to_plan_tree_with_context(input, _function_map)
                } else {
                    Err("Root relation missing input".into())
                }
            }
            _ => Err("Only root relations are currently supported".into()),
        }
    } else {
        Err("Relation missing rel_type".into())
    }
}

/// Convert relation with function context
pub unsafe fn convert_rel_to_plan_tree_with_context(
    rel: &Rel,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::rel::RelType;

    match &rel.rel_type {
        Some(RelType::Project(project)) => {
            // Handle projection - create a Result node
            if let Some(input) = &project.input {
                // Project with input - create Result node with input as left tree
                let input_plan = convert_rel_to_plan_tree_with_context(input, function_map)?;

                // Convert expressions to PostgreSQL target entries
                let target_list = convert_expressions_to_target_list_with_context(
                    &project.expressions,
                    function_map,
                )?;

                // Create a Result plan node using PostgreSQL's memory allocator
                let result_node =
                    pg_sys::palloc0(std::mem::size_of::<pg_sys::Result>()) as *mut pg_sys::Result;
                (*result_node).plan.type_ = pg_sys::NodeTag::T_Result;
                (*result_node).plan.lefttree = input_plan;
                (*result_node).plan.targetlist = target_list;
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

                Ok(result_node as *mut pg_sys::Plan)
            } else {
                // Project with no input (literal projections) - create Values scan node
                let target_list = convert_expressions_to_target_list_with_context(
                    &project.expressions,
                    function_map,
                )?;

                // Create a ValuesScan plan node for literal projections
                create_values_scan_with_target_list(target_list)
            }
        }
        Some(RelType::Read(read)) => {
            // Handle table reads
            if let Some(read_type) = &read.read_type {
                match read_type {
                    substrait::proto::read_rel::ReadType::VirtualTable(_vt) => {
                        // Virtual table - create a Values scan node
                        create_values_scan_node()
                    }
                    substrait::proto::read_rel::ReadType::NamedTable(nt) => {
                        // Named table - create a SeqScan node
                        let table_name = nt.names.join(".");
                        create_seqscan_node(&table_name)
                    }
                    _ => Err("Unsupported read type".into()),
                }
            } else {
                Err("Read relation missing read type".into())
            }
        }
        Some(RelType::Sort(sort)) => {
            // Handle sort relation - create a Sort node
            let input_plan = if let Some(input) = &sort.input {
                convert_rel_to_plan_tree_with_context(input, function_map)?
            } else {
                return Err("Sort relation missing input".into());
            };

            create_sort_node(input_plan, &sort.sorts)
        }
        Some(RelType::Fetch(fetch)) => {
            // Handle fetch relation - create a Limit node
            let input_plan = if let Some(input) = &fetch.input {
                convert_rel_to_plan_tree_with_context(input, function_map)?
            } else {
                return Err("Fetch relation missing input".into());
            };

            // Extract offset and count from the fetch relation using expression conversion
            let offset_expr = if let Some(offset_mode) = &fetch.offset_mode {
                use substrait::proto::fetch_rel::OffsetMode;
                match offset_mode {
                    OffsetMode::OffsetExpr(expr) => Some(
                        convert_expression_to_postgres_with_context(expr, function_map)?,
                    ),
                    OffsetMode::Offset(_) => {
                        return Err(
                            "Deprecated constant offset not supported, use offset_expr instead"
                                .into(),
                        );
                    }
                }
            } else {
                None // No offset limit
            };

            let count_expr = if let Some(count_mode) = &fetch.count_mode {
                use substrait::proto::fetch_rel::CountMode;
                match count_mode {
                    CountMode::CountExpr(expr) => Some(
                        convert_expression_to_postgres_with_context(expr, function_map)?,
                    ),
                    CountMode::Count(_) => {
                        return Err(
                            "Deprecated constant count not supported, use count_expr instead"
                                .into(),
                        );
                    }
                }
            } else {
                None // No count limit
            };

            create_limit_node_with_expressions(input_plan, offset_expr, count_expr)
        }
        Some(RelType::Filter(filter)) => {
            // Handle filter relation - create a Filter node
            let input_plan = if let Some(input) = &filter.input {
                convert_rel_to_plan_tree_with_context(input, function_map)?
            } else {
                return Err("Filter relation missing input".into());
            };

            // Convert the filter condition to a PostgreSQL expression
            let condition_expr = if let Some(condition) = &filter.condition {
                convert_expression_to_postgres_with_context(condition, function_map)?
            } else {
                return Err("Filter relation missing condition".into());
            };

            create_filter_node(input_plan, condition_expr)
        }
        Some(RelType::Cross(cross)) => {
            // Handle cross relation - create a NestLoop node for Cartesian product
            let left_plan = if let Some(left) = &cross.left {
                convert_rel_to_plan_tree_with_context(left, function_map)?
            } else {
                return Err("Cross relation missing left input".into());
            };

            let right_plan = if let Some(right) = &cross.right {
                convert_rel_to_plan_tree_with_context(right, function_map)?
            } else {
                return Err("Cross relation missing right input".into());
            };

            create_cross_join_node(left_plan, right_plan)
        }
        Some(RelType::Aggregate(aggregate)) => {
            // Handle aggregate relation - create an Agg node for GROUP BY and aggregate functions
            let input_plan = if let Some(input) = &aggregate.input {
                convert_rel_to_plan_tree_with_context(input, function_map)?
            } else {
                return Err("Aggregate relation missing input".into());
            };

            create_aggregate_node(input_plan, aggregate, function_map)
        }
        Some(rel_type) => {
            let type_name = get_relation_type_name(rel_type);
            Err(format!(
                "Unsupported relation type: {} (implementation needed)",
                type_name
            )
            .into())
        }
        None => Err("Relation missing rel_type".into()),
    }
}

/// Convert expressions to target list with function context
pub unsafe fn convert_expressions_to_target_list_with_context(
    expressions: &[Expression],
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();

    for (i, expr) in expressions.iter().enumerate() {
        let target_entry = convert_expression_to_target_entry_with_context(expr, i, function_map)?;
        target_list = pg_sys::lappend(target_list, target_entry as *mut std::ffi::c_void);
    }

    Ok(target_list)
}

/// Convert expression to target entry with function context
unsafe fn convert_expression_to_target_entry_with_context(
    expr: &Expression,
    index: usize,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::TargetEntry, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::RexType;

    match &expr.rex_type {
        Some(RexType::Literal(literal)) => {
            // Handle literal values
            if let Some(literal_type) = &literal.literal_type {
                let const_expr = match literal_type {
                    substrait::proto::expression::literal::LiteralType::I32(val) => {
                        create_int4_const(*val)?
                    }
                    substrait::proto::expression::literal::LiteralType::I64(val) => {
                        create_int8_const(*val)?
                    }
                    substrait::proto::expression::literal::LiteralType::String(val) => {
                        create_text_const(val)?
                    }
                    _ => {
                        return Err(
                            format!("Unsupported literal type for expression {}", index).into()
                        )
                    }
                };

                // Create TargetEntry
                let target_entry = pg_sys::palloc0(std::mem::size_of::<pg_sys::TargetEntry>())
                    as *mut pg_sys::TargetEntry;
                (*target_entry).expr = const_expr;
                (*target_entry).resno = (index + 1) as pg_sys::AttrNumber;
                (*target_entry).resname = create_cstring(&format!("column_{}", index + 1));
                (*target_entry).resjunk = false;

                Ok(target_entry)
            } else {
                Err(format!("Literal expression {} missing literal type", index).into())
            }
        }
        Some(RexType::ScalarFunction(func)) => {
            // Handle scalar function expressions
            let func_expr = create_scalar_function_expr_with_context(func, function_map)?;

            // Create TargetEntry
            let target_entry = pg_sys::palloc0(std::mem::size_of::<pg_sys::TargetEntry>())
                as *mut pg_sys::TargetEntry;
            (*target_entry).expr = func_expr;
            (*target_entry).resno = (index + 1) as pg_sys::AttrNumber;
            (*target_entry).resname = create_cstring(&format!("column_{}", index + 1));
            (*target_entry).resjunk = false;

            Ok(target_entry)
        }
        Some(RexType::Selection(selection)) => {
            // Handle column references
            let selection_expr = convert_selection_to_postgres(selection)?;

            // Create TargetEntry
            let target_entry = pg_sys::palloc0(std::mem::size_of::<pg_sys::TargetEntry>())
                as *mut pg_sys::TargetEntry;
            (*target_entry).expr = selection_expr;
            (*target_entry).resno = (index + 1) as pg_sys::AttrNumber;
            (*target_entry).resname = create_cstring(&format!("column_{}", index + 1));
            (*target_entry).resjunk = false;

            Ok(target_entry)
        }
        _ => Err(format!("Unsupported expression type at index {}", index).into()),
    }
}

/// Convert selection expression to PostgreSQL
unsafe fn convert_selection_to_postgres(
    selection: &substrait::proto::expression::FieldReference,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ref_type) = &selection.reference_type {
        match ref_type {
            substrait::proto::expression::field_reference::ReferenceType::DirectReference(
                direct_ref,
            ) => {
                if let Some(struct_field) = &direct_ref.reference_type {
                    match struct_field {
                        substrait::proto::expression::reference_segment::ReferenceType::StructField(field) => {
                            create_var_node(field.field as i32 + 1) // 1-based indexing
                        }
                        _ => Err("Unsupported reference type in selection".into()),
                    }
                } else {
                    Err("Missing reference type in direct reference".into())
                }
            }
            _ => Err("Unsupported field reference type in selection".into()),
        }
    } else {
        Err("Missing reference type in selection".into())
    }
}

/// Convert expression to PostgreSQL with function context
pub unsafe fn convert_expression_to_postgres_with_context(
    expr: &Expression,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::RexType;

    match &expr.rex_type {
        Some(RexType::Literal(literal)) => {
            // Handle literal values
            if let Some(literal_type) = &literal.literal_type {
                match literal_type {
                    substrait::proto::expression::literal::LiteralType::I32(val) => {
                        create_int4_const(*val)
                    }
                    substrait::proto::expression::literal::LiteralType::I64(val) => {
                        create_int8_const(*val)
                    }
                    substrait::proto::expression::literal::LiteralType::String(val) => {
                        create_text_const(val)
                    }
                    substrait::proto::expression::literal::LiteralType::Date(val) => {
                        // For now, treat date as int32 (days since epoch)
                        create_int4_const(*val)
                    }
                    substrait::proto::expression::literal::LiteralType::FixedChar(val) => {
                        create_text_const(val)
                    }
                    _ => Err("Unsupported literal type in filter condition".into()),
                }
            } else {
                Err("Literal expression missing literal type".into())
            }
        }
        Some(RexType::Selection(selection)) => convert_selection_to_postgres(selection),
        Some(RexType::ScalarFunction(func)) => {
            // Handle scalar functions (e.g., comparison operators)
            create_scalar_function_expr_with_context(func, function_map)
        }
        Some(RexType::Cast(cast)) => {
            // Handle type casts
            let input_expr = if let Some(input) = &cast.input {
                convert_expression_to_postgres_with_context(input, function_map)?
            } else {
                return Err("Cast expression missing input".into());
            };

            // For now, just return the input expression without casting
            // TODO: Implement proper type casting
            Ok(input_expr)
        }
        Some(RexType::Subquery(subquery)) => {
            // Handle subquery expressions
            create_subquery_expr(subquery, function_map)
        }
        Some(rex_type) => {
            let type_name = get_expression_type_name(rex_type);
            Err(format!(
                "Unsupported expression type in filter condition: {}",
                type_name
            )
            .into())
        }
        None => Err("Expression missing rex_type".into()),
    }
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

/// Create scalar function expression with function context
pub unsafe fn create_scalar_function_expr_with_context(
    func: &substrait::proto::expression::ScalarFunction,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let function_reference = func.function_reference;
    let argument_count = func.arguments.len();

    // Look up function name from extension map
    let function_name = function_map
        .get(&function_reference)
        .map(|s| s.as_str())
        .unwrap_or("unknown");

    eprintln!("DEBUG: Scalar function details:");
    eprintln!("  function_reference: {}", function_reference);
    eprintln!("  function_name: {}", function_name);
    eprintln!("  arguments.len(): {}", argument_count);

    // Handle specific function types based on name
    match function_name {
        "lte:date_date" => {
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.get(0) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in lte:date_date function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in lte:date_date function".into());
                    }
                } else {
                    return Err("Missing left argument in lte:date_date function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in lte:date_date function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in lte:date_date function".into());
                    }
                } else {
                    return Err("Missing right argument in lte:date_date function".into());
                };

                // Create a binary operation expression for date less-than-equal
                // PostgreSQL date <= operator OID is 1095 (DATE_LE_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(1095),
                    pg_sys::BOOLOID,
                )
            } else {
                Err(format!(
                    "lte:date_date function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "and:bool" => {
            // Handle variadic logical AND function using PostgreSQL's BoolExpr
            if func.arguments.len() >= 2 {
                // Convert all arguments to PostgreSQL expressions
                let mut pg_args: *mut pg_sys::List = std::ptr::null_mut();
                for arg in &func.arguments {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                let pg_expr = convert_expression_to_postgres_with_context(
                                    expr,
                                    function_map,
                                )?;
                                pg_args =
                                    pg_sys::lappend(pg_args, pg_expr as *mut std::ffi::c_void);
                            }
                            _ => {
                                return Err("Unsupported argument type in and:bool function".into())
                            }
                        }
                    } else {
                        return Err("Missing argument type in and:bool function".into());
                    }
                }

                // Create a BoolExpr node for variadic AND
                let bool_expr = pg_sys::palloc0(std::mem::size_of::<pg_sys::BoolExpr>())
                    as *mut pg_sys::BoolExpr;
                (*bool_expr).xpr.type_ = pg_sys::NodeTag::T_BoolExpr;
                (*bool_expr).boolop = pg_sys::BoolExprType::AND_EXPR;
                (*bool_expr).args = pg_args;

                Ok(bool_expr as *mut pg_sys::Expr)
            } else {
                Err(format!(
                    "and:bool function expects at least 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "equal:any_any" => {
            // Handle equality comparison function
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.get(0) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in equal:any_any function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in equal:any_any function".into());
                    }
                } else {
                    return Err("Missing left argument in equal:any_any function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in equal:any_any function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in equal:any_any function".into());
                    }
                } else {
                    return Err("Missing right argument in equal:any_any function".into());
                };

                // Create a binary operation expression for equality
                // Use a generic equality operator - PostgreSQL will resolve the correct one based on types
                create_binary_op_expr(left_arg, right_arg, pg_sys::Oid::from(96), pg_sys::BOOLOID)
            // INT4EQ_OP as a generic placeholder
            } else {
                Err(format!(
                    "equal:any_any function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "multiply:fp64_fp64" => {
            // Handle floating point multiplication
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.get(0) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in multiply:fp64_fp64 function"
                                        .into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in multiply:fp64_fp64 function".into());
                    }
                } else {
                    return Err("Missing left argument in multiply:fp64_fp64 function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in multiply:fp64_fp64 function"
                                        .into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in multiply:fp64_fp64 function".into());
                    }
                } else {
                    return Err("Missing right argument in multiply:fp64_fp64 function".into());
                };

                // Create a binary operation expression for multiplication
                // PostgreSQL float8 * operator OID is 594 (FLOAT8MUL_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(594),
                    pg_sys::FLOAT8OID,
                )
            } else {
                Err(format!(
                    "multiply:fp64_fp64 function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "subtract:fp64_fp64" => {
            // Handle floating point subtraction
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.get(0) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in subtract:fp64_fp64 function"
                                        .into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in subtract:fp64_fp64 function".into());
                    }
                } else {
                    return Err("Missing left argument in subtract:fp64_fp64 function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in subtract:fp64_fp64 function"
                                        .into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in subtract:fp64_fp64 function".into());
                    }
                } else {
                    return Err("Missing right argument in subtract:fp64_fp64 function".into());
                };

                // Create a binary operation expression for subtraction
                // PostgreSQL float8 - operator OID is 593 (FLOAT8MI_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(593),
                    pg_sys::FLOAT8OID,
                )
            } else {
                Err(format!(
                    "subtract:fp64_fp64 function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "add:fp64_fp64" => {
            // Handle floating point addition
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.get(0) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in add:fp64_fp64 function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in add:fp64_fp64 function".into());
                    }
                } else {
                    return Err("Missing left argument in add:fp64_fp64 function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in add:fp64_fp64 function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in add:fp64_fp64 function".into());
                    }
                } else {
                    return Err("Missing right argument in add:fp64_fp64 function".into());
                };

                // Create a binary operation expression for addition
                // PostgreSQL float8 + operator OID is 591 (FLOAT8PL_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(591),
                    pg_sys::FLOAT8OID,
                )
            } else {
                Err(format!(
                    "add:fp64_fp64 function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "like:str_str" => {
            // Handle string LIKE pattern matching function
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.get(0) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in like:str_str function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in like:str_str function".into());
                    }
                } else {
                    return Err("Missing left argument in like:str_str function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in like:str_str function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in like:str_str function".into());
                    }
                } else {
                    return Err("Missing right argument in like:str_str function".into());
                };

                // Create a binary operation expression for LIKE
                // PostgreSQL LIKE operator OID is 15 (TEXTLIKE_OP)
                create_binary_op_expr(left_arg, right_arg, pg_sys::Oid::from(15), pg_sys::BOOLOID)
            // TEXTLIKE_OP
            } else {
                Err(format!(
                    "like:str_str function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        _ => Err(format!(
            "Unsupported scalar function: {} (function_reference={}, args_count={})",
            function_name, function_reference, argument_count
        )
        .into()),
    }
}

/// Create a PostgreSQL subquery expression from Substrait subquery
pub unsafe fn create_subquery_expr(
    _subquery: &substrait::proto::expression::Subquery,
    _function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // For now, return an error indicating subqueries are not yet implemented
    // In a full implementation, this would:
    // 1. Convert the subquery relation to a PostgreSQL SubPlan
    // 2. Create a SubLink node that references the SubPlan
    // 3. Handle correlation between outer and inner queries
    Err("Subquery expressions are not yet implemented".into())
}
