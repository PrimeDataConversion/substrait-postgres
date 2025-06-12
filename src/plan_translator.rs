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

    // Convert Substrait relation to PostgreSQL plan tree and execute
    unsafe {
        let plan_tree = convert_relation_to_plan_tree(relation)?;
        let result = execute_plan_tree_structured(plan_tree)?;
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
    let const_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Const>()) as *mut pg_sys::Const;
    (*const_node).xpr.type_ = pg_sys::NodeTag::T_Const;
    (*const_node).consttype = pg_sys::INT4OID;
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
    let const_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Const>()) as *mut pg_sys::Const;
    (*const_node).xpr.type_ = pg_sys::NodeTag::T_Const;
    (*const_node).consttype = pg_sys::INT8OID;
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
    let text_datum =
        pg_sys::cstring_to_text_with_len(value.as_ptr() as *const i8, value.len() as i32);

    let const_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Const>()) as *mut pg_sys::Const;
    (*const_node).xpr.type_ = pg_sys::NodeTag::T_Const;
    (*const_node).consttype = pg_sys::TEXTOID;
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
    // This is complex as it requires looking up the table OID, etc.
    // For now, return an error
    Err(format!("SeqScan for table '{}' not yet implemented", table_name).into())
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
                        format!("column_{}", i + 1)
                    };

                    // Get column type from the expression
                    let expr = (*target_entry).expr;
                    let (type_oid, type_mod) =
                        if !expr.is_null() && (*expr).type_ == pg_sys::NodeTag::T_Const {
                            let const_node = expr as *mut pg_sys::Const;
                            ((*const_node).consttype, (*const_node).consttypmod)
                        } else {
                            (pg_sys::TEXTOID, -1) // Default to text
                        };

                    columns.push(ColumnInfo {
                        name: col_name,
                        type_oid,
                        type_mod,
                    });
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
                        row_values.push((*const_node).constvalue);
                        row_nulls.push((*const_node).constisnull);
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
        _ => Err("Unsupported plan node type for structured execution".into()),
    }
}
