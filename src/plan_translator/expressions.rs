use anyhow::Result;
use pgrx::pg_sys;
use std::collections::HashMap;
use substrait::proto::Expression;

use super::constants::get_expression_type_name;

use substrait::proto::{r#type::Kind, Type};

/// Get the PostgreSQL type OID for a given Substrait type
fn get_pg_type_oid(
    substrait_type: &Type,
) -> Result<pg_sys::Oid, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(kind) = &substrait_type.kind {
        match kind {
            Kind::Bool(_) => Ok(pg_sys::BOOLOID),
            Kind::I8(_) | Kind::I16(_) | Kind::I32(_) => Ok(pg_sys::INT4OID),
            Kind::I64(_) => Ok(pg_sys::INT8OID),
            Kind::Fp32(_) => Ok(pg_sys::FLOAT4OID),
            Kind::Fp64(_) => Ok(pg_sys::FLOAT8OID),
            Kind::String(_) | Kind::Varchar(_) | Kind::FixedChar(_) => Ok(pg_sys::TEXTOID),
            Kind::Date(_) => Ok(pg_sys::DATEOID),
            Kind::Decimal(d) => {
                // For now, map all decimals to NUMERIC
                // TODO: Handle precision and scale
                Ok(pg_sys::NUMERICOID)
            }
            _ => Err("Unsupported Substrait type for casting".into()),
        }
    } else {
        Err("Substrait type missing kind".into())
    }
}

/// Look up the function OID for a given operator OID
unsafe fn get_operator_function_oid(
    operator_oid: pg_sys::Oid,
) -> Result<pg_sys::Oid, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "DEBUG: Looking up function OID for operator OID: {}",
        operator_oid.to_u32()
    );

    // Use PostgreSQL's system catalog to get the function OID for this operator
    let tuple = pg_sys::SearchSysCache1(
        pg_sys::SysCacheIdentifier::OPEROID as i32,
        pg_sys::Datum::from(operator_oid.to_u32()),
    );

    if tuple.is_null() {
        eprintln!(
            "DEBUG: Operator OID {} not found in system catalog",
            operator_oid.to_u32()
        );
        return Err(format!("Operator OID {} not found in system catalog", operator_oid).into());
    }

    let operator_form = pg_sys::GETSTRUCT(tuple) as *mut pg_sys::FormData_pg_operator;
    let function_oid = (*operator_form).oprcode;

    eprintln!(
        "DEBUG: Operator OID {} maps to function OID: {}",
        operator_oid.to_u32(),
        function_oid.to_u32()
    );

    pg_sys::ReleaseSysCache(tuple);

    if function_oid == pg_sys::InvalidOid || function_oid.to_u32() == 0 {
        eprintln!(
            "DEBUG: Operator OID {} has invalid function OID: {}",
            operator_oid.to_u32(),
            function_oid.to_u32()
        );
        return Err(format!("Operator OID {} has no associated function", operator_oid).into());
    }

    Ok(function_oid)
}

// PostgreSQL's date epoch is 2000-01-01, while Substrait's is 1970-01-01.
// The difference is 10957 days.
const PG_DATE_EPOCH_OFFSET: i32 = 10957;

/// Create a PostgreSQL date constant node
pub unsafe fn create_date_const(
    value: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let type_oid = pg_sys::DATEOID;

    // Validate that the OID is reasonable
    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
        return Err(format!("Invalid DATEOID: {}", type_oid).into());
    }

    let const_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Const>()) as *mut pg_sys::Const;
    (*const_node).xpr.type_ = pg_sys::NodeTag::T_Const;
    (*const_node).consttype = type_oid;
    (*const_node).consttypmod = -1;
    (*const_node).constcollid = pg_sys::DEFAULT_COLLATION_OID;
    (*const_node).constlen = 4;
    (*const_node).constvalue = pg_sys::Datum::from(value - PG_DATE_EPOCH_OFFSET);
    (*const_node).constisnull = false;
    (*const_node).constbyval = true;

    Ok(const_node as *mut pg_sys::Expr)
}

/// Create a PostgreSQL int4 constant node
pub unsafe fn create_int4_const(
    value: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Use the PostgreSQL built-in constant, but validate it first
    let type_oid = pg_sys::INT4OID;

    // Debug: Always print what INT4OID actually is
    eprintln!("DEBUG: pg_sys::INT4OID = {}", type_oid.to_u32());
    eprintln!("DEBUG: pg_sys::TEXTOID = {}", pg_sys::TEXTOID.to_u32());
    eprintln!("DEBUG: pg_sys::BOOLOID = {}", pg_sys::BOOLOID.to_u32());
    eprintln!("DEBUG: pg_sys::FLOAT8OID = {}", pg_sys::FLOAT8OID.to_u32());

    // Validate that the OID is reasonable (should not be 0 or InvalidOid)
    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
        return Err(format!("Invalid INT4OID: {}", type_oid).into());
    }

    // Check if type_oid is suspiciously 124 (pg_type OID)
    if type_oid.to_u32() == 124 {
        eprintln!("ERROR: INT4OID is returning pg_type OID 124 instead of actual int4 type!");
        return Err("INT4OID corrupted to pg_type OID (124)".into());
    }

    let const_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Const>()) as *mut pg_sys::Const;

    // Debug: Check what T_Const actually evaluates to
    let t_const_value = pg_sys::NodeTag::T_Const as u32;
    eprintln!("DEBUG: pg_sys::NodeTag::T_Const value = {}", t_const_value);

    if t_const_value == 124 {
        eprintln!("ERROR: T_Const NodeTag itself is 124! This is wrong - T_Const should not be pg_type OID");
        return Err("T_Const NodeTag has wrong value 124".into());
    }

    (*const_node).xpr.type_ = pg_sys::NodeTag::T_Const;
    (*const_node).consttype = type_oid;

    // Debug: Check for NodeTag corruption right after setting it
    if (*const_node).xpr.type_ as u32 == 124 {
        eprintln!(
            "ERROR: Int4Const node type corrupted to 124 after setting! consttype = {}",
            type_oid.to_u32()
        );
        return Err("Int4Const node type corrupted to pg_type OID (124)".into());
    }

    (*const_node).consttypmod = -1;
    (*const_node).constcollid = pg_sys::DEFAULT_COLLATION_OID;
    (*const_node).constlen = 4;
    (*const_node).constvalue = pg_sys::Datum::from(value);
    (*const_node).constisnull = false;
    (*const_node).constbyval = true;

    Ok(const_node as *mut pg_sys::Expr)
}

/// Create a PostgreSQL int8 constant node
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
    (*const_node).constcollid = pg_sys::DEFAULT_COLLATION_OID;
    (*const_node).constlen = 8;
    (*const_node).constvalue = pg_sys::Datum::from(value);
    (*const_node).constisnull = false;
    (*const_node).constbyval = true;

    Ok(const_node as *mut pg_sys::Expr)
}

/// Create a PostgreSQL text constant node
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

/// Resolve actual column type information from table OID and attribute number
unsafe fn resolve_column_type_info(
    table_oid: pg_sys::Oid,
    attnum: pg_sys::AttrNumber,
) -> Result<(pg_sys::Oid, i32, pg_sys::Oid), Box<dyn std::error::Error + Send + Sync>> {
    // Open the relation to get schema information
    let relation = pg_sys::relation_open(table_oid, pg_sys::AccessShareLock as i32);
    if relation.is_null() {
        return Err(format!("Could not open relation with OID {}", table_oid).into());
    }

    let tuple_desc = (*relation).rd_att;

    // Validate attribute number
    if attnum <= 0 || (attnum as i32) > (*tuple_desc).natts {
        pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);
        return Err(format!(
            "Invalid attribute number {} for relation {}",
            attnum, table_oid
        )
        .into());
    }

    // Get the attribute (1-based indexing, so subtract 1)
    let attr = (*tuple_desc).attrs.as_ptr().offset((attnum - 1) as isize);

    if (*attr).attisdropped {
        pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);
        return Err(format!("Attribute {} is dropped", attnum).into());
    }

    // Extract the actual type information
    let vartype = (*attr).atttypid;
    let vartypmod = (*attr).atttypmod;
    let varcollid = (*attr).attcollation;

    pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);

    Ok((vartype, vartypmod, varcollid))
}

/// Create a PostgreSQL Var node for column references
/// NOTE: This creates a Var with UNKNOWNOID - use create_var_node_with_type for proper typing
pub unsafe fn create_var_node(
    attr_number: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let var_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Var>()) as *mut pg_sys::Var;
    (*var_node).xpr.type_ = pg_sys::NodeTag::T_Var;
    (*var_node).varno = 1; // Single table reference for now
    (*var_node).varattno = attr_number as pg_sys::AttrNumber;
    (*var_node).vartype = pg_sys::TEXTOID; // Use TEXT as default, will be resolved during planning
    (*var_node).vartypmod = -1;
    (*var_node).varcollid = pg_sys::DEFAULT_COLLATION_OID;
    (*var_node).varlevelsup = 0;

    // Debug: Check for corruption right after creation
    if (*var_node).xpr.type_ as u32 == 124 {
        eprintln!(
            "ERROR: Var node corruption detected at creation! type_ = 124, vartype = {}",
            (*var_node).vartype.to_u32()
        );
        return Err("Var node type corrupted to pg_type OID (124)".into());
    }

    Ok(var_node as *mut pg_sys::Expr)
}

/// Create a PostgreSQL Var node with proper type resolution from table schema
pub unsafe fn create_var_node_with_table_schema(
    attr_number: i32,
    table_oid: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let var_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Var>()) as *mut pg_sys::Var;
    (*var_node).xpr.type_ = pg_sys::NodeTag::T_Var;
    (*var_node).varno = 1;
    (*var_node).varattno = attr_number as pg_sys::AttrNumber;

    // Resolve actual column type instead of hardcoding
    let (vartype, vartypmod, varcollid) =
        resolve_column_type_info(table_oid, attr_number as pg_sys::AttrNumber)?;
    (*var_node).vartype = vartype;
    (*var_node).vartypmod = vartypmod;
    (*var_node).varcollid = varcollid;
    (*var_node).varlevelsup = 0;

    Ok(var_node as *mut pg_sys::Expr)
}

/// Create a PostgreSQL Var node with proper type information
pub unsafe fn create_var_node_with_type(
    attr_number: i32,
    vartype: pg_sys::Oid,
    vartypmod: i32,
    varcollid: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let var_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Var>()) as *mut pg_sys::Var;
    (*var_node).xpr.type_ = pg_sys::NodeTag::T_Var;
    (*var_node).varno = 1; // Single table reference for now
    (*var_node).varattno = attr_number as pg_sys::AttrNumber;
    (*var_node).vartype = vartype; // Use actual column type
    (*var_node).vartypmod = vartypmod;
    (*var_node).varcollid = varcollid;
    (*var_node).varlevelsup = 0;

    Ok(var_node as *mut pg_sys::Expr)
}

/// Create a PostgreSQL type cast expression
/// Create a PostgreSQL type cast expression
pub unsafe fn create_cast_expr(
    arg: *mut pg_sys::Expr,
    target_type_oid: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let cast_expr = pg_sys::coerce_type(
        std::ptr::null_mut(),                         // ParseState *pstate
        arg as *mut pg_sys::Node,                     // Node *node
        pg_sys::exprType(arg as *const pg_sys::Node), // Oid inputTypeId
        target_type_oid,                              // Oid targetTypeId
        -1,                                           // int32 targetTypeMod
        pg_sys::CoercionContext::COERCION_EXPLICIT,   // CoercionContext ccontext
        pg_sys::CoercionPathType::COERCION_PATH_FUNC, // CoercionPathType ptype
        -1,                                           // int location
    );

    if cast_expr.is_null() {
        return Err(format!(
            "Failed to coerce type from OID {} to OID {}",
            pg_sys::exprType(arg as *const pg_sys::Node),
            target_type_oid
        )
        .into());
    }

    Ok(cast_expr as *mut pg_sys::Expr)
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
    // Look up the function OID for this operator
    (*op_expr).opfuncid = get_operator_function_oid(operator_oid)?;
    (*op_expr).opresulttype = result_type;
    (*op_expr).opretset = false;
    (*op_expr).opcollid = pg_sys::DEFAULT_COLLATION_OID;
    (*op_expr).inputcollid = pg_sys::DEFAULT_COLLATION_OID;

    // Debug: Check for corruption right after creation
    if (*op_expr).xpr.type_ as u32 == 124 {
        eprintln!(
            "ERROR: OpExpr node corruption detected! type_ = 124, opno = {}, opresulttype = {}",
            operator_oid.to_u32(),
            result_type.to_u32()
        );
        return Err("OpExpr node type corrupted to pg_type OID (124)".into());
    }

    // Create argument list
    let mut args: *mut pg_sys::List = std::ptr::null_mut();
    args = pg_sys::lappend(args, left_arg as *mut std::ffi::c_void);
    args = pg_sys::lappend(args, right_arg as *mut std::ffi::c_void);
    (*op_expr).args = args;

    // Final corruption check
    if (*op_expr).xpr.type_ as u32 == 124 {
        eprintln!("ERROR: OpExpr node corrupted after args setup! type_ = 124");
        return Err("OpExpr node type corrupted after argument setup".into());
    }

    Ok(op_expr as *mut pg_sys::Expr)
}

/// Convert selection expression to PostgreSQL
pub unsafe fn convert_selection_to_postgres(
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
                            create_var_node(field.field + 1) // 1-based indexing
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
                        create_date_const(*val)
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

            if let Some(cast_type) = &cast.r#type {
                let target_oid = get_pg_type_oid(cast_type)?;
                create_cast_expr(input_expr, target_oid)
            } else {
                Err("Cast expression missing type".into())
            }
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
                    substrait::proto::expression::literal::LiteralType::Date(val) => {
                        create_date_const(*val)?
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
                (*target_entry).xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
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
            (*target_entry).xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
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
            (*target_entry).xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            (*target_entry).expr = selection_expr;
            (*target_entry).resno = (index + 1) as pg_sys::AttrNumber;
            (*target_entry).resname = create_cstring(&format!("column_{}", index + 1));
            (*target_entry).resjunk = false;

            Ok(target_entry)
        }
        _ => Err(format!("Unsupported expression type at index {}", index).into()),
    }
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
                let left_arg = if let Some(arg) = func.arguments.first() {
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
                let left_arg = if let Some(arg) = func.arguments.first() {
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
                let left_arg = if let Some(arg) = func.arguments.first() {
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
                let left_arg = if let Some(arg) = func.arguments.first() {
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
                let left_arg = if let Some(arg) = func.arguments.first() {
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
                let left_arg = if let Some(arg) = func.arguments.first() {
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
        "or:bool" => {
            // Handle variadic logical OR function using PostgreSQL's BoolExpr
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
                            _ => return Err("Unsupported argument type in or:bool function".into()),
                        }
                    } else {
                        return Err("Missing argument type in or:bool function".into());
                    }
                }

                // Create a BoolExpr node for variadic OR
                let bool_expr = pg_sys::palloc0(std::mem::size_of::<pg_sys::BoolExpr>())
                    as *mut pg_sys::BoolExpr;
                (*bool_expr).xpr.type_ = pg_sys::NodeTag::T_BoolExpr;
                (*bool_expr).boolop = pg_sys::BoolExprType::OR_EXPR;
                (*bool_expr).args = pg_args;

                Ok(bool_expr as *mut pg_sys::Expr)
            } else {
                Err(format!(
                    "or:bool function expects at least 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "lt:any_any" => {
            // Handle less-than comparison function
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in lt:any_any function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in lt:any_any function".into());
                    }
                } else {
                    return Err("Missing left argument in lt:any_any function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in lt:any_any function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in lt:any_any function".into());
                    }
                } else {
                    return Err("Missing right argument in lt:any_any function".into());
                };

                // Create a binary operation expression for less-than
                // Use generic less-than operator
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(97), // INT4LT_OP, fallback for generic types
                    pg_sys::BOOLOID,
                )
            } else {
                Err(format!(
                    "lt:any_any function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "gte:date_date" => {
            // Handle greater-than-or-equal comparison for dates
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in gte:date_date function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in gte:date_date function".into());
                    }
                } else {
                    return Err("Missing left argument in gte:date_date function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in gte:date_date function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in gte:date_date function".into());
                    }
                } else {
                    return Err("Missing right argument in gte:date_date function".into());
                };

                // Create a binary operation expression for date greater-than-equal
                // PostgreSQL date >= operator OID is 1096 (DATE_GE_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(1096),
                    pg_sys::BOOLOID,
                )
            } else {
                Err(format!(
                    "gte:date_date function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "lt:date_date" => {
            // Handle less-than comparison for dates
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in lt:date_date function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in lt:date_date function".into());
                    }
                } else {
                    return Err("Missing left argument in lt:date_date function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in lt:date_date function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in lt:date_date function".into());
                    }
                } else {
                    return Err("Missing right argument in lt:date_date function".into());
                };

                // Create a binary operation expression for date less-than
                // PostgreSQL date < operator OID is 1094 (DATE_LT_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(1094),
                    pg_sys::BOOLOID,
                )
            } else {
                Err(format!(
                    "lt:date_date function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "not_equal:any_any" => {
            // Handle not-equal comparison function
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in not_equal:any_any function"
                                        .into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in not_equal:any_any function".into());
                    }
                } else {
                    return Err("Missing left argument in not_equal:any_any function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in not_equal:any_any function"
                                        .into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in not_equal:any_any function".into());
                    }
                } else {
                    return Err("Missing right argument in not_equal:any_any function".into());
                };

                // Create a binary operation expression for not-equal
                // Use generic not-equal operator
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(518), // INT4NE_OP, fallback for generic types
                    pg_sys::BOOLOID,
                )
            } else {
                Err(format!(
                    "not_equal:any_any function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "like:vchar_vchar" => {
            // Handle string LIKE pattern matching function for varchar types
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in like:vchar_vchar function".into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in like:vchar_vchar function".into());
                    }
                } else {
                    return Err("Missing left argument in like:vchar_vchar function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in like:vchar_vchar function".into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in like:vchar_vchar function".into());
                    }
                } else {
                    return Err("Missing right argument in like:vchar_vchar function".into());
                };

                // Create a binary operation expression for LIKE
                // PostgreSQL LIKE operator OID is 15 (TEXTLIKE_OP)
                create_binary_op_expr(left_arg, right_arg, pg_sys::Oid::from(15), pg_sys::BOOLOID)
            } else {
                Err(format!(
                    "like:vchar_vchar function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "multiply:dec_dec" => {
            // Handle decimal multiplication
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in multiply:dec_dec function".into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in multiply:dec_dec function".into());
                    }
                } else {
                    return Err("Missing left argument in multiply:dec_dec function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in multiply:dec_dec function".into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in multiply:dec_dec function".into());
                    }
                } else {
                    return Err("Missing right argument in multiply:dec_dec function".into());
                };

                // Create a binary operation expression for decimal multiplication
                // PostgreSQL numeric * operator OID is 1758 (NUMERIC_MUL_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(1758),
                    pg_sys::NUMERICOID,
                )
            } else {
                Err(format!(
                    "multiply:dec_dec function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "subtract:dec_dec" => {
            // Handle decimal subtraction
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in subtract:dec_dec function".into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in subtract:dec_dec function".into());
                    }
                } else {
                    return Err("Missing left argument in subtract:dec_dec function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in subtract:dec_dec function".into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in subtract:dec_dec function".into());
                    }
                } else {
                    return Err("Missing right argument in subtract:dec_dec function".into());
                };

                // Create a binary operation expression for decimal subtraction
                // PostgreSQL numeric - operator OID is 1759 (NUMERIC_SUB_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(1759),
                    pg_sys::NUMERICOID,
                )
            } else {
                Err(format!(
                    "subtract:dec_dec function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "divide:dec_dec" => {
            // Handle decimal division
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in divide:dec_dec function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in divide:dec_dec function".into());
                    }
                } else {
                    return Err("Missing left argument in divide:dec_dec function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in divide:dec_dec function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in divide:dec_dec function".into());
                    }
                } else {
                    return Err("Missing right argument in divide:dec_dec function".into());
                };

                // Create a binary operation expression for decimal division
                // PostgreSQL numeric / operator OID is 1760 (NUMERIC_DIV_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(1760),
                    pg_sys::NUMERICOID,
                )
            } else {
                Err(format!(
                    "divide:dec_dec function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "gt:any_any" => {
            // Handle greater-than comparison function
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in gt:any_any function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in gt:any_any function".into());
                    }
                } else {
                    return Err("Missing left argument in gt:any_any function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in gt:any_any function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in gt:any_any function".into());
                    }
                } else {
                    return Err("Missing right argument in gt:any_any function".into());
                };

                // Create a binary operation expression for greater-than
                // Use generic greater-than operator
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(521), // INT4GT_OP, fallback for generic types
                    pg_sys::BOOLOID,
                )
            } else {
                Err(format!(
                    "gt:any_any function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "add:date_year" => {
            // Handle date + year interval function
            // This typically comes from expressions like date '1994-08-01' + interval '1' month
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in add:date_year function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in add:date_year function".into());
                    }
                } else {
                    return Err("Missing left argument in add:date_year function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in add:date_year function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in add:date_year function".into());
                    }
                } else {
                    return Err("Missing right argument in add:date_year function".into());
                };

                // Create a binary operation expression for date + interval
                // PostgreSQL date + interval operator OID is 1076 (DATE_PL_INTERVAL)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(1076),
                    pg_sys::DATEOID,
                )
            } else {
                Err(format!(
                    "add:date_year function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "gte:any_any" => {
            // Handle greater-than-or-equal comparison function
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in gte:any_any function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in gte:any_any function".into());
                    }
                } else {
                    return Err("Missing left argument in gte:any_any function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in gte:any_any function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in gte:any_any function".into());
                    }
                } else {
                    return Err("Missing right argument in gte:any_any function".into());
                };

                // Create a binary operation expression for greater-than-or-equal
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(525), // INT4GE_OP as generic fallback
                    pg_sys::BOOLOID,
                )
            } else {
                Err(format!(
                    "gte:any_any function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "lte:any_any" => {
            // Handle less-than-or-equal comparison function
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in lte:any_any function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in lte:any_any function".into());
                    }
                } else {
                    return Err("Missing left argument in lte:any_any function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in lte:any_any function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in lte:any_any function".into());
                    }
                } else {
                    return Err("Missing right argument in lte:any_any function".into());
                };

                // Create a binary operation expression for less-than-or-equal
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(523), // INT4LE_OP as generic fallback
                    pg_sys::BOOLOID,
                )
            } else {
                Err(format!(
                    "lte:any_any function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "add:i32_i32" => {
            // Handle integer addition
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in add:i32_i32 function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in add:i32_i32 function".into());
                    }
                } else {
                    return Err("Missing left argument in add:i32_i32 function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in add:i32_i32 function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in add:i32_i32 function".into());
                    }
                } else {
                    return Err("Missing right argument in add:i32_i32 function".into());
                };

                // Create a binary operation expression for integer addition
                // PostgreSQL int4 + operator OID is 551 (INT4PL_OP)
                create_binary_op_expr(left_arg, right_arg, pg_sys::Oid::from(551), pg_sys::INT4OID)
            } else {
                Err(format!(
                    "add:i32_i32 function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "substring:str_i32_i32" => {
            // Handle string substring function
            if func.arguments.len() == 3 {
                let string_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in substring:str_i32_i32 function"
                                        .into(),
                                )
                            }
                        }
                    } else {
                        return Err(
                            "Missing argument type in substring:str_i32_i32 function".into()
                        );
                    }
                } else {
                    return Err("Missing string argument in substring:str_i32_i32 function".into());
                };

                let start_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in substring:str_i32_i32 function"
                                        .into(),
                                )
                            }
                        }
                    } else {
                        return Err(
                            "Missing argument type in substring:str_i32_i32 function".into()
                        );
                    }
                } else {
                    return Err("Missing start argument in substring:str_i32_i32 function".into());
                };

                let length_arg = if let Some(arg) = func.arguments.get(2) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in substring:str_i32_i32 function"
                                        .into(),
                                )
                            }
                        }
                    } else {
                        return Err(
                            "Missing argument type in substring:str_i32_i32 function".into()
                        );
                    }
                } else {
                    return Err("Missing length argument in substring:str_i32_i32 function".into());
                };

                // Create a function call expression for substring
                // PostgreSQL substring function OID is 883 (text_substr)
                create_function_call_expr(
                    pg_sys::Oid::from(883),
                    vec![string_arg, start_arg, length_arg],
                    pg_sys::TEXTOID,
                )
            } else {
                Err(format!(
                    "substring:str_i32_i32 function expects 3 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "not:bool" => {
            // Handle logical NOT function
            if func.arguments.len() == 1 {
                let arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err("Unsupported argument type in not:bool function".into())
                            }
                        }
                    } else {
                        return Err("Missing argument type in not:bool function".into());
                    }
                } else {
                    return Err("Missing argument in not:bool function".into());
                };

                // Create a BoolExpr node for NOT
                let bool_expr = pg_sys::palloc0(std::mem::size_of::<pg_sys::BoolExpr>())
                    as *mut pg_sys::BoolExpr;
                (*bool_expr).xpr.type_ = pg_sys::NodeTag::T_BoolExpr;
                (*bool_expr).boolop = pg_sys::BoolExprType::NOT_EXPR;

                // Create args list with single argument
                let mut pg_args: *mut pg_sys::List = std::ptr::null_mut();
                pg_args = pg_sys::lappend(pg_args, arg as *mut std::ffi::c_void);
                (*bool_expr).args = pg_args;

                Ok(bool_expr as *mut pg_sys::Expr)
            } else {
                Err(format!(
                    "not:bool function expects 1 argument, got {}",
                    argument_count
                )
                .into())
            }
        }
        "gt:date_date" => {
            // Handle date greater-than comparison function
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in gt:date_date function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in gt:date_date function".into());
                    }
                } else {
                    return Err("Missing left argument in gt:date_date function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in gt:date_date function".into()
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in gt:date_date function".into());
                    }
                } else {
                    return Err("Missing right argument in gt:date_date function".into());
                };

                // Create a binary operation expression for date greater-than
                // PostgreSQL date > operator OID is 1093 (DATE_GT_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(1093),
                    pg_sys::BOOLOID,
                )
            } else {
                Err(format!(
                    "gt:date_date function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "divide:fp64_fp64" => {
            // Handle floating point division
            if func.arguments.len() == 2 {
                let left_arg = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in divide:fp64_fp64 function".into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in divide:fp64_fp64 function".into());
                    }
                } else {
                    return Err("Missing left argument in divide:fp64_fp64 function".into());
                };

                let right_arg = if let Some(arg) = func.arguments.get(1) {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Value(expr) => {
                                convert_expression_to_postgres_with_context(expr, function_map)?
                            }
                            _ => {
                                return Err(
                                    "Unsupported argument type in divide:fp64_fp64 function".into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in divide:fp64_fp64 function".into());
                    }
                } else {
                    return Err("Missing right argument in divide:fp64_fp64 function".into());
                };

                // Create a binary operation expression for division
                // PostgreSQL float8 / operator OID is 595 (FLOAT8DIV_OP)
                create_binary_op_expr(
                    left_arg,
                    right_arg,
                    pg_sys::Oid::from(595),
                    pg_sys::FLOAT8OID,
                )
            } else {
                Err(format!(
                    "divide:fp64_fp64 function expects 2 arguments, got {}",
                    argument_count
                )
                .into())
            }
        }
        "extract:req_date" => {
            // Handle date extraction function (EXTRACT(YEAR FROM date))
            if func.arguments.len() == 2 {
                // First argument is the enum specifying what to extract (YEAR, MONTH, etc.)
                let extract_field = if let Some(arg) = func.arguments.first() {
                    if let Some(value) = &arg.arg_type {
                        match value {
                            substrait::proto::function_argument::ArgType::Enum(enum_val) => {
                                enum_val.as_str()
                            }
                            _ => {
                                return Err(
                                    "First argument of extract:req_date function must be enum"
                                        .into(),
                                )
                            }
                        }
                    } else {
                        return Err("Missing argument type in extract:req_date function".into());
                    }
                } else {
                    return Err(
                        "Missing extract field argument in extract:req_date function".into(),
                    );
                };

                // Second argument is the date expression
                let date_arg =
                    if let Some(arg) = func.arguments.get(1) {
                        if let Some(value) = &arg.arg_type {
                            match value {
                                substrait::proto::function_argument::ArgType::Value(expr) => {
                                    convert_expression_to_postgres_with_context(expr, function_map)?
                                }
                                _ => return Err(
                                    "Second argument of extract:req_date function must be value"
                                        .into(),
                                ),
                            }
                        } else {
                            return Err("Missing argument type in extract:req_date function".into());
                        }
                    } else {
                        return Err("Missing date argument in extract:req_date function".into());
                    };

                // Create a function call expression for EXTRACT(field FROM date)
                // PostgreSQL date_part function OID is 1385 (date_part_text_date)
                let field_literal = create_text_const(&extract_field.to_lowercase())?;
                create_function_call_expr(
                    pg_sys::Oid::from(1385),
                    vec![field_literal, date_arg],
                    pg_sys::FLOAT8OID,
                )
            } else {
                Err(format!(
                    "extract:req_date function expects 2 arguments, got {}",
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
    subquery: &substrait::proto::expression::Subquery,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::subquery::SubqueryType;

    match &subquery.subquery_type {
        Some(SubqueryType::Scalar(scalar_subquery)) => {
            // Handle scalar subqueries (returns single value)
            // The scalar_subquery should contain the inner relation
            create_scalar_subquery_expr(scalar_subquery, function_map)
        }
        Some(SubqueryType::InPredicate(_)) => {
            Err("IN predicate subqueries are not yet implemented".into())
        }
        Some(SubqueryType::SetPredicate(set_predicate)) => {
            // Handle EXISTS/UNIQUE predicates
            create_set_predicate_expr(set_predicate, function_map)
        }
        Some(SubqueryType::SetComparison(_)) => {
            Err("Set comparison subqueries are not yet implemented".into())
        }
        None => Err("Subquery missing subquery_type".into()),
    }
}

/// Create a PostgreSQL scalar subquery expression
unsafe fn create_scalar_subquery_expr(
    scalar_subquery: &substrait::proto::expression::subquery::Scalar,
    _function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // scalar_subquery contains the input relation of the scalar subquery
    if scalar_subquery.input.is_none() {
        return Err("Scalar subquery missing input relation".into());
    }

    // For now, we'll implement a simplified version that converts the subquery
    // to a basic SubLink node. A full implementation would need to:
    // 1. Convert the Substrait relation to a PostgreSQL Query/PlannedStmt
    // 2. Handle correlation properly with PARAM_EXEC parameters
    // 3. Set up proper subplan execution context

    // Create a basic SubLink node for scalar subqueries
    let sublink = pg_sys::palloc0(std::mem::size_of::<pg_sys::SubLink>()) as *mut pg_sys::SubLink;
    (*sublink).xpr.type_ = pg_sys::NodeTag::T_SubLink;
    (*sublink).subLinkType = pg_sys::SubLinkType::EXPR_SUBLINK; // Scalar subquery
    (*sublink).subLinkId = 0; // Will be assigned during planning
    (*sublink).testexpr = std::ptr::null_mut(); // No test expression for scalar subqueries
    (*sublink).operName = std::ptr::null_mut(); // No operator for scalar subqueries

    // For now, create a placeholder subselect
    // In a real implementation, this would convert the Substrait relation to a Query
    let placeholder_query = create_placeholder_query_for_subquery();
    (*sublink).subselect = placeholder_query as *mut pg_sys::Node;

    // Set location to unknown
    (*sublink).location = -1;

    Ok(sublink as *mut pg_sys::Expr)
}

/// Create a PostgreSQL EXISTS/UNIQUE subquery expression from Substrait SetPredicate
unsafe fn create_set_predicate_expr(
    set_predicate: &substrait::proto::expression::subquery::SetPredicate,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::subquery::set_predicate::PredicateOp;

    // Get the predicate operation type
    let predicate_op = PredicateOp::try_from(set_predicate.predicate_op)
        .map_err(|_| format!("Invalid predicate_op: {}", set_predicate.predicate_op))?;

    // Determine the SubLink type based on the predicate operation
    let sublink_type = match predicate_op {
        PredicateOp::Exists => pg_sys::SubLinkType::EXISTS_SUBLINK,
        PredicateOp::Unique => {
            return Err("UNIQUE predicate subqueries are not yet implemented".into());
        }
        PredicateOp::Unspecified => {
            return Err("Unspecified predicate operation not supported".into());
        }
    };

    // Get the subquery relation
    let tuples_relation = set_predicate
        .tuples
        .as_ref()
        .ok_or("SetPredicate missing tuples relation")?;

    // Convert the Substrait relation to a PostgreSQL Query node
    // For now, create a placeholder query - this would need proper relation conversion
    let query = create_placeholder_query_for_subquery();

    // Create the SubLink node
    let sublink = pg_sys::palloc0(std::mem::size_of::<pg_sys::SubLink>()) as *mut pg_sys::SubLink;
    (*sublink).xpr.type_ = pg_sys::NodeTag::T_SubLink;
    (*sublink).subLinkType = sublink_type;
    (*sublink).subLinkId = 0; // Will be assigned during planning
    (*sublink).testexpr = std::ptr::null_mut(); // No test expression for EXISTS/UNIQUE
    (*sublink).operName = std::ptr::null_mut(); // No operator for EXISTS/UNIQUE
    (*sublink).subselect = query as *mut pg_sys::Node;
    (*sublink).location = -1; // Unknown location

    eprintln!("DEBUG: Created {:?} SubLink for SetPredicate", predicate_op);

    Ok(sublink as *mut pg_sys::Expr)
}

/// Create a placeholder query for subquery conversion
/// This is a simplified implementation - in practice, we'd need to convert
/// the full Substrait relation to a PostgreSQL Query node
unsafe fn create_placeholder_query_for_subquery() -> *mut pg_sys::Query {
    // Create a minimal Query node that represents the subquery
    let query = pg_sys::palloc0(std::mem::size_of::<pg_sys::Query>()) as *mut pg_sys::Query;
    (*query).type_ = pg_sys::NodeTag::T_Query;
    (*query).commandType = pg_sys::CmdType::CMD_SELECT;
    (*query).querySource = pg_sys::QuerySource::QSRC_ORIGINAL;
    (*query).canSetTag = true;

    // Initialize empty lists
    (*query).rtable = std::ptr::null_mut();
    (*query).jointree = std::ptr::null_mut();
    (*query).targetList = std::ptr::null_mut();
    (*query).returningList = std::ptr::null_mut();
    (*query).groupClause = std::ptr::null_mut();
    (*query).groupingSets = std::ptr::null_mut();
    (*query).havingQual = std::ptr::null_mut();
    (*query).windowClause = std::ptr::null_mut();
    (*query).distinctClause = std::ptr::null_mut();
    (*query).sortClause = std::ptr::null_mut();
    (*query).limitOffset = std::ptr::null_mut();
    (*query).limitCount = std::ptr::null_mut();
    (*query).rowMarks = std::ptr::null_mut();
    (*query).setOperations = std::ptr::null_mut();
    (*query).constraintDeps = std::ptr::null_mut();
    (*query).withCheckOptions = std::ptr::null_mut();

    // Set up basic properties
    (*query).hasAggs = false;
    (*query).hasWindowFuncs = false;
    (*query).hasTargetSRFs = false;
    (*query).hasSubLinks = false;
    (*query).hasDistinctOn = false;
    (*query).hasRecursive = false;
    (*query).hasModifyingCTE = false;
    (*query).hasForUpdate = false;
    (*query).hasRowSecurity = false;
    (*query).isReturn = false;

    query
}

/// Create a PostgreSQL function call expression
pub unsafe fn create_function_call_expr(
    func_oid: pg_sys::Oid,
    args: Vec<*mut pg_sys::Expr>,
    result_type: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Create a FuncExpr node
    let func_expr =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::FuncExpr>()) as *mut pg_sys::FuncExpr;
    (*func_expr).xpr.type_ = pg_sys::NodeTag::T_FuncExpr;
    (*func_expr).funcid = func_oid;
    (*func_expr).funcresulttype = result_type;
    (*func_expr).funcretset = false;
    (*func_expr).funcvariadic = false;
    (*func_expr).funcformat = pg_sys::CoercionForm::COERCE_EXPLICIT_CALL;
    (*func_expr).funccollid = pg_sys::DEFAULT_COLLATION_OID;
    (*func_expr).inputcollid = pg_sys::DEFAULT_COLLATION_OID;

    // Create args list
    let mut pg_args: *mut pg_sys::List = std::ptr::null_mut();
    for arg in args {
        pg_args = pg_sys::lappend(pg_args, arg as *mut std::ffi::c_void);
    }
    (*func_expr).args = pg_args;

    Ok(func_expr as *mut pg_sys::Expr)
}

/// Helper function to create C strings for PostgreSQL
pub unsafe fn create_cstring(s: &str) -> *mut i8 {
    let cstr = std::ffi::CString::new(s).unwrap();
    let len = cstr.as_bytes_with_nul().len();
    let ptr = pg_sys::palloc(len) as *mut i8;
    std::ptr::copy_nonoverlapping(cstr.as_ptr(), ptr, len);
    ptr
}
