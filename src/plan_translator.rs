use anyhow::Result;
use pgrx::pg_sys;
use substrait::proto::{Expression, Plan, PlanRel, Rel};

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

pub fn execute_substrait_plan(
    plan: Plan,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
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

    // Convert Substrait relation to PostgreSQL plan tree and execute
    unsafe {
        let plan_tree = convert_relation_to_plan_tree(relation)?;
        let mut result = execute_plan_tree_structured(plan_tree)?;

        // Update column names with the ones from the plan schema
        for (i, column) in result.columns.iter_mut().enumerate() {
            if i < column_names.len() {
                column.name = column_names[i].clone();
            }
        }

        Ok(result)
    }
}

pub unsafe fn convert_relation_to_plan_tree(
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
        _ => Err("Unsupported relation type".into()),
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
    (*seqscan_node).scan.plan.type_ = pg_sys::NodeTag::T_SeqScan;
    (*seqscan_node).scan.scanrelid = table_oid.into();

    // Create target list for the table's columns
    let target_list = create_target_list_for_table(table_oid)?;
    (*seqscan_node).scan.plan.targetlist = target_list;

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

pub unsafe fn execute_plan_tree_structured(
    plan: *mut pg_sys::Plan,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
    if plan.is_null() {
        return Err("null plan".into());
    }

    // For now, handle simple Result nodes directly by extracting their target list
    match (*plan).type_ {
        pg_sys::NodeTag::T_Result => {
            let result_node = plan as *mut pg_sys::Result;
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
                    let col_name = if !(*target_entry).resname.is_null() {
                        let c_str = std::ffi::CStr::from_ptr((*target_entry).resname);
                        c_str.to_string_lossy().to_string()
                    } else {
                        "result".to_string()
                    };

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
            let seqscan_node = plan as *mut pg_sys::SeqScan;
            let target_list = (*seqscan_node).scan.plan.targetlist;
            let relation_oid = (*seqscan_node).scan.scanrelid;

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
                    let col_name = if !(*target_entry).resname.is_null() {
                        let c_str = std::ffi::CStr::from_ptr((*target_entry).resname);
                        c_str.to_string_lossy().to_string()
                    } else {
                        "result".to_string()
                    };

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

            // Execute the actual table scan using PostgreSQL's executor
            let rows_and_nulls = execute_table_scan(relation_oid.into(), &columns)?;

            Ok(ExecutionResult {
                columns,
                rows: rows_and_nulls.0,
                nulls: rows_and_nulls.1,
            })
        }
        _ => Err("Unsupported plan node type for structured execution".into()),
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
