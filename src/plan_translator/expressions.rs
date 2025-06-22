use anyhow::Result;
use pgrx::pg_sys;
use std::collections::HashMap;
use substrait::proto::Expression;

use super::constants::get_expression_type_name;

/// Create a PostgreSQL int4 constant node
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
    (*const_node).constcollid = pg_sys::InvalidOid;
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
        Some(SubqueryType::SetPredicate(_)) => {
            Err("Set predicate subqueries are not yet implemented".into())
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

/// Helper function to create C strings for PostgreSQL
pub unsafe fn create_cstring(s: &str) -> *mut i8 {
    let cstr = std::ffi::CString::new(s).unwrap();
    let len = cstr.as_bytes_with_nul().len();
    let ptr = pg_sys::palloc(len) as *mut i8;
    std::ptr::copy_nonoverlapping(cstr.as_ptr(), ptr, len);
    ptr
}
