use anyhow::Result;
use pgrx::pg_sys;
use substrait::proto::{Expression, Plan, PlanRel, Rel, Type};

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

// Schema extraction utilities for Substrait Plans

#[derive(Debug, Clone)]
pub struct SubstraitSchema {
    pub column_names: Vec<String>,
    pub column_types: Vec<SubstraitType>,
}

#[derive(Debug, Clone)]
pub struct SubstraitType {
    pub type_name: String,
    #[allow(dead_code)]
    pub postgres_type_oid: pg_sys::Oid,
    pub nullable: bool,
}

#[derive(Debug, Clone)]
pub struct TableSchema {
    pub table_name: String,
    pub column_names: Vec<String>,
    pub column_types: Vec<SubstraitType>,
}

/// Extract the output schema from a Substrait Plan
/// This gets the column names and types that will be returned by the plan
pub fn extract_plan_output_schema(
    plan: &Plan,
) -> Result<SubstraitSchema, Box<dyn std::error::Error + Send + Sync>> {
    if plan.relations.is_empty() {
        return Err("Plan has no relations".into());
    }

    let relation = &plan.relations[0];
    extract_relation_output_schema(relation)
}

/// Extract the output schema from a PlanRel
fn extract_relation_output_schema(
    relation: &PlanRel,
) -> Result<SubstraitSchema, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(rel_type) = &relation.rel_type {
        match rel_type {
            substrait::proto::plan_rel::RelType::Root(root) => {
                // RelRoot contains the output column names
                let column_names = root.names.clone();

                // To get the types, we need to traverse the input relation tree
                let column_types = if let Some(input) = &root.input {
                    extract_relation_types(input, column_names.len())?
                } else {
                    // If no input, create default types
                    vec![
                        SubstraitType {
                            type_name: "text".to_string(),
                            postgres_type_oid: pg_sys::TEXTOID,
                            nullable: true,
                        };
                        column_names.len()
                    ]
                };

                Ok(SubstraitSchema {
                    column_names,
                    column_types,
                })
            }
            _ => Err("Only Root relations are supported for schema extraction".into()),
        }
    } else {
        Err("Relation missing rel_type".into())
    }
}

/// Extract column types from a relation tree
fn extract_relation_types(
    rel: &Rel,
    expected_count: usize,
) -> Result<Vec<SubstraitType>, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::rel::RelType;

    match &rel.rel_type {
        Some(RelType::Project(project)) => {
            // For project relations, analyze the expressions to determine output types
            let mut types = Vec::new();

            for expr in &project.expressions {
                let substrait_type = extract_expression_type(expr)?;
                types.push(substrait_type);
            }

            // If we don't have enough types, fill with defaults
            while types.len() < expected_count {
                types.push(SubstraitType {
                    type_name: "text".to_string(),
                    postgres_type_oid: pg_sys::TEXTOID,
                    nullable: true,
                });
            }

            Ok(types)
        }
        Some(RelType::Read(read)) => {
            // For read relations, get types from the base schema
            if let Some(base_schema) = &read.base_schema {
                extract_types_from_schema_struct(&base_schema.r#struct, expected_count)
            } else {
                // Create default types if no schema
                Ok(vec![
                    SubstraitType {
                        type_name: "text".to_string(),
                        postgres_type_oid: pg_sys::TEXTOID,
                        nullable: true,
                    };
                    expected_count
                ])
            }
        }
        Some(RelType::Aggregate(_)) => {
            // For aggregate relations, types depend on the aggregation functions
            // For now, default to numeric types commonly used in aggregation
            Ok(vec![
                SubstraitType {
                    type_name: "fp64".to_string(),
                    postgres_type_oid: pg_sys::FLOAT8OID,
                    nullable: true,
                };
                expected_count
            ])
        }
        Some(RelType::Sort(sort)) => {
            // Sort doesn't change types, recurse to input
            if let Some(input) = &sort.input {
                extract_relation_types(input, expected_count)
            } else {
                Ok(vec![
                    SubstraitType {
                        type_name: "text".to_string(),
                        postgres_type_oid: pg_sys::TEXTOID,
                        nullable: true,
                    };
                    expected_count
                ])
            }
        }
        Some(RelType::Filter(filter)) => {
            // Filter doesn't change types, recurse to input
            if let Some(input) = &filter.input {
                extract_relation_types(input, expected_count)
            } else {
                Ok(vec![
                    SubstraitType {
                        type_name: "text".to_string(),
                        postgres_type_oid: pg_sys::TEXTOID,
                        nullable: true,
                    };
                    expected_count
                ])
            }
        }
        _ => {
            // For unsupported relation types, return default types
            Ok(vec![
                SubstraitType {
                    type_name: "text".to_string(),
                    postgres_type_oid: pg_sys::TEXTOID,
                    nullable: true,
                };
                expected_count
            ])
        }
    }
}

/// Extract the type of a Substrait expression
fn extract_expression_type(
    expr: &Expression,
) -> Result<SubstraitType, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::RexType;

    match &expr.rex_type {
        Some(RexType::Literal(literal)) => {
            if let Some(literal_type) = &literal.literal_type {
                match literal_type {
                    substrait::proto::expression::literal::LiteralType::I32(_) => {
                        Ok(SubstraitType {
                            type_name: "i32".to_string(),
                            postgres_type_oid: pg_sys::INT4OID,
                            nullable: literal.nullable,
                        })
                    }
                    substrait::proto::expression::literal::LiteralType::I64(_) => {
                        Ok(SubstraitType {
                            type_name: "i64".to_string(),
                            postgres_type_oid: pg_sys::INT8OID,
                            nullable: literal.nullable,
                        })
                    }
                    substrait::proto::expression::literal::LiteralType::Fp64(_) => {
                        Ok(SubstraitType {
                            type_name: "fp64".to_string(),
                            postgres_type_oid: pg_sys::FLOAT8OID,
                            nullable: literal.nullable,
                        })
                    }
                    substrait::proto::expression::literal::LiteralType::String(_)
                    | substrait::proto::expression::literal::LiteralType::FixedChar(_) => {
                        Ok(SubstraitType {
                            type_name: "string".to_string(),
                            postgres_type_oid: pg_sys::TEXTOID,
                            nullable: literal.nullable,
                        })
                    }
                    substrait::proto::expression::literal::LiteralType::Boolean(_) => {
                        Ok(SubstraitType {
                            type_name: "bool".to_string(),
                            postgres_type_oid: pg_sys::BOOLOID,
                            nullable: literal.nullable,
                        })
                    }
                    _ => Ok(SubstraitType {
                        type_name: "unknown".to_string(),
                        postgres_type_oid: pg_sys::TEXTOID,
                        nullable: true,
                    }),
                }
            } else {
                Err("Literal expression missing literal type".into())
            }
        }
        Some(RexType::Selection(_selection)) => {
            // For field selections, we would need to look up the field type
            // from the input schema. For now, default to text.
            Ok(SubstraitType {
                type_name: "selection".to_string(),
                postgres_type_oid: pg_sys::TEXTOID,
                nullable: true,
            })
        }
        Some(RexType::ScalarFunction(func)) => {
            // For scalar functions, use the output type if available
            if let Some(output_type) = &func.output_type {
                convert_substrait_type_to_postgres(output_type)
            } else {
                Ok(SubstraitType {
                    type_name: "function".to_string(),
                    postgres_type_oid: pg_sys::TEXTOID,
                    nullable: true,
                })
            }
        }
        _ => Ok(SubstraitType {
            type_name: "unknown".to_string(),
            postgres_type_oid: pg_sys::TEXTOID,
            nullable: true,
        }),
    }
}

/// Extract types from a Substrait Struct (base schema)
fn extract_types_from_schema_struct(
    struct_type: &Option<substrait::proto::r#type::Struct>,
    expected_count: usize,
) -> Result<Vec<SubstraitType>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(struct_def) = struct_type {
        let mut types = Vec::new();

        for type_def in &struct_def.types {
            let substrait_type = convert_substrait_type_to_postgres(type_def)?;
            types.push(substrait_type);
        }

        // Ensure we have the expected number of types
        while types.len() < expected_count {
            types.push(SubstraitType {
                type_name: "text".to_string(),
                postgres_type_oid: pg_sys::TEXTOID,
                nullable: true,
            });
        }

        Ok(types)
    } else {
        // No struct definition, return defaults
        Ok(vec![
            SubstraitType {
                type_name: "text".to_string(),
                postgres_type_oid: pg_sys::TEXTOID,
                nullable: true,
            };
            expected_count
        ])
    }
}

/// Convert a Substrait Type to a SubstraitType with PostgreSQL mapping
fn convert_substrait_type_to_postgres(
    substrait_type: &Type,
) -> Result<SubstraitType, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::r#type::Kind;

    // For now, default to nullable - we can enhance this later based on the actual API
    let nullable = true;

    if let Some(kind) = &substrait_type.kind {
        match kind {
            Kind::I32(_) => Ok(SubstraitType {
                type_name: "i32".to_string(),
                postgres_type_oid: pg_sys::INT4OID,
                nullable,
            }),
            Kind::I64(_) => Ok(SubstraitType {
                type_name: "i64".to_string(),
                postgres_type_oid: pg_sys::INT8OID,
                nullable,
            }),
            Kind::Fp64(_) => Ok(SubstraitType {
                type_name: "fp64".to_string(),
                postgres_type_oid: pg_sys::FLOAT8OID,
                nullable,
            }),
            Kind::String(_) => Ok(SubstraitType {
                type_name: "string".to_string(),
                postgres_type_oid: pg_sys::TEXTOID,
                nullable,
            }),
            Kind::Bool(_) => Ok(SubstraitType {
                type_name: "bool".to_string(),
                postgres_type_oid: pg_sys::BOOLOID,
                nullable,
            }),
            Kind::Date(_) => Ok(SubstraitType {
                type_name: "date".to_string(),
                postgres_type_oid: pg_sys::DATEOID,
                nullable,
            }),
            _ => Ok(SubstraitType {
                type_name: "unknown".to_string(),
                postgres_type_oid: pg_sys::TEXTOID,
                nullable,
            }),
        }
    } else {
        Ok(SubstraitType {
            type_name: "unknown".to_string(),
            postgres_type_oid: pg_sys::TEXTOID,
            nullable,
        })
    }
}

/// Extract all table schemas from a Substrait Plan
/// This finds all the base tables and their schemas
pub fn extract_table_schemas_from_plan(
    plan: &Plan,
) -> Result<Vec<TableSchema>, Box<dyn std::error::Error + Send + Sync>> {
    let mut table_schemas = Vec::new();

    for relation in &plan.relations {
        if let Some(rel_type) = &relation.rel_type {
            if let substrait::proto::plan_rel::RelType::Root(root) = rel_type {
                if let Some(input) = &root.input {
                    extract_table_schemas_from_relation(input, &mut table_schemas)?;
                }
            }
        }
    }

    Ok(table_schemas)
}

/// Recursively extract table schemas from a relation tree
fn extract_table_schemas_from_relation(
    rel: &Rel,
    table_schemas: &mut Vec<TableSchema>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::rel::RelType;

    match &rel.rel_type {
        Some(RelType::Read(read)) => {
            // Extract table schema from read relation
            if let Some(read_type) = &read.read_type {
                if let substrait::proto::read_rel::ReadType::NamedTable(named_table) = read_type {
                    let table_name = named_table.names.join(".");

                    let (column_names, column_types) = if let Some(base_schema) = &read.base_schema
                    {
                        let names = base_schema.names.clone();
                        let types =
                            extract_types_from_schema_struct(&base_schema.r#struct, names.len())?;
                        (names, types)
                    } else {
                        (vec![], vec![])
                    };

                    table_schemas.push(TableSchema {
                        table_name,
                        column_names,
                        column_types,
                    });
                }
            }
        }
        Some(RelType::Project(project)) => {
            if let Some(input) = &project.input {
                extract_table_schemas_from_relation(input, table_schemas)?;
            }
        }
        Some(RelType::Filter(filter)) => {
            if let Some(input) = &filter.input {
                extract_table_schemas_from_relation(input, table_schemas)?;
            }
        }
        Some(RelType::Sort(sort)) => {
            if let Some(input) = &sort.input {
                extract_table_schemas_from_relation(input, table_schemas)?;
            }
        }
        Some(RelType::Aggregate(aggregate)) => {
            if let Some(input) = &aggregate.input {
                extract_table_schemas_from_relation(input, table_schemas)?;
            }
        }
        Some(RelType::Join(join)) => {
            if let Some(left) = &join.left {
                extract_table_schemas_from_relation(left, table_schemas)?;
            }
            if let Some(right) = &join.right {
                extract_table_schemas_from_relation(right, table_schemas)?;
            }
        }
        Some(RelType::Cross(cross)) => {
            if let Some(left) = &cross.left {
                extract_table_schemas_from_relation(left, table_schemas)?;
            }
            if let Some(right) = &cross.right {
                extract_table_schemas_from_relation(right, table_schemas)?;
            }
        }
        _ => {
            // For other relation types, we don't extract table schemas
        }
    }

    Ok(())
}
