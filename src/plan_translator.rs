use anyhow::Result;
use pgrx::pg_sys;
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
        let plan_tree = convert_plan_relation_to_plan_tree(relation)?;

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
    if let Some(rel_type) = &relation.rel_type {
        match rel_type {
            substrait::proto::plan_rel::RelType::Root(root) => {
                if let Some(input) = &root.input {
                    convert_rel_to_plan_tree(input)
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

pub unsafe fn convert_rel_to_plan_tree(
    rel: &Rel,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::rel::RelType;

    match &rel.rel_type {
        Some(RelType::Project(project)) => {
            // Handle projection - create a Result node
            let input_plan = if let Some(input) = &project.input {
                convert_rel_to_plan_tree(input)?
            } else {
                std::ptr::null_mut()
            };

            // Convert expressions to PostgreSQL target entries
            let target_list = convert_expressions_to_target_list(&project.expressions)?;

            // Create a Result plan node using PostgreSQL's memory allocator
            let result_node =
                pg_sys::palloc0(std::mem::size_of::<pg_sys::Result>()) as *mut pg_sys::Result;
            (*result_node).plan.type_ = pg_sys::NodeTag::T_Result;
            (*result_node).plan.lefttree = input_plan;
            (*result_node).plan.targetlist = target_list;

            Ok(result_node as *mut pg_sys::Plan)
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
                convert_rel_to_plan_tree(input)?
            } else {
                return Err("Sort relation missing input".into());
            };

            create_sort_node(input_plan, &sort.sorts)
        }
        Some(RelType::Fetch(fetch)) => {
            // Handle fetch relation - create a Limit node
            let input_plan = if let Some(input) = &fetch.input {
                convert_rel_to_plan_tree(input)?
            } else {
                return Err("Fetch relation missing input".into());
            };

            // Extract offset and count from the fetch relation using expression conversion
            let offset_expr = if let Some(offset_mode) = &fetch.offset_mode {
                use substrait::proto::fetch_rel::OffsetMode;
                match offset_mode {
                    OffsetMode::OffsetExpr(expr) => Some(convert_expression_to_postgres(expr)?),
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
                    CountMode::CountExpr(expr) => Some(convert_expression_to_postgres(expr)?),
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
                convert_rel_to_plan_tree(input)?
            } else {
                return Err("Filter relation missing input".into());
            };

            // Convert the filter condition to a PostgreSQL expression
            let condition_expr = if let Some(condition) = &filter.condition {
                convert_expression_to_postgres(condition)?
            } else {
                return Err("Filter relation missing condition".into());
            };

            create_filter_node(input_plan, condition_expr)
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
    (*result_node).plan.targetlist = std::ptr::null_mut();

    Ok(result_node as *mut pg_sys::Plan)
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
        (*seqscan_node).scanrelid = table_oid.into();

        // Create target list for the table's columns
        let target_list = create_target_list_for_table(table_oid)?;
        (*seqscan_node).plan.targetlist = target_list;
    }
    #[cfg(any(feature = "pg15", feature = "pg16", feature = "pg17"))]
    {
        (*seqscan_node).scan.plan.type_ = pg_sys::NodeTag::T_SeqScan;
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
        // For now, return a basic sort node structure
        // A full implementation would need to properly set up sort columns
        pg_sys::palloc0(sorts.len() * std::mem::size_of::<pg_sys::AttrNumber>())
            as *mut pg_sys::AttrNumber
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
        create_binary_op_expr(left_arg, right_arg, pg_sys::Oid::from(1058)) // DATE_LE_OP
    } else {
        Err("Unsupported scalar function with non-binary arguments".into())
    }
}

/// Create a PostgreSQL binary operation expression
pub unsafe fn create_binary_op_expr(
    left_arg: *mut pg_sys::Expr,
    right_arg: *mut pg_sys::Expr,
    operator_oid: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let op_expr = pg_sys::palloc0(std::mem::size_of::<pg_sys::OpExpr>()) as *mut pg_sys::OpExpr;
    (*op_expr).xpr.type_ = pg_sys::NodeTag::T_OpExpr;
    (*op_expr).opno = operator_oid;
    (*op_expr).opfuncid = pg_sys::InvalidOid; // Will be resolved during planning
    (*op_expr).opresulttype = pg_sys::BOOLOID; // Comparison results in boolean
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

    // Pass through the target list from input
    (*result_node).plan.targetlist = (*input_plan).targetlist;

    // Set the filter condition as a qualification
    let mut qual_list: *mut pg_sys::List = std::ptr::null_mut();
    qual_list = pg_sys::lappend(qual_list, condition_expr as *mut std::ffi::c_void);
    (*result_node).plan.qual = qual_list;

    Ok(result_node as *mut pg_sys::Plan)
}
