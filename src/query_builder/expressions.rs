//! Converts Substrait expressions to PostgreSQL expressions for Query context.

use pgrx::pg_sys;
use substrait::proto::expression::RexType;
use substrait::proto::Expression;

use super::{AvailableColumn, QueryBuildContext};

/// Convert a Substrait expression to a PostgreSQL Expr for use in a Query.
pub unsafe fn convert_expression_for_query(
    expr: &Expression,
    available_columns: &[AvailableColumn],
    ctx: &QueryBuildContext,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    pgrx::info!(
        "DEBUG: convert_expression_for_query - rex_type: {:?}",
        expr.rex_type.as_ref().map(|r| std::mem::discriminant(r))
    );

    match &expr.rex_type {
        Some(RexType::Literal(lit)) => {
            pgrx::info!("DEBUG: Converting Literal");
            convert_literal(lit)
        }
        Some(RexType::Selection(sel)) => {
            pgrx::info!("DEBUG: Converting Selection (field reference)");
            convert_selection(sel, available_columns)
        }
        Some(RexType::ScalarFunction(func)) => {
            pgrx::info!(
                "DEBUG: Converting ScalarFunction, function_reference: {}",
                func.function_reference
            );
            convert_scalar_function(func, available_columns, ctx)
        }
        Some(RexType::Cast(cast)) => {
            pgrx::info!("DEBUG: Converting Cast");
            convert_cast(cast, available_columns, ctx)
        }
        Some(RexType::IfThen(if_then)) => {
            pgrx::info!("DEBUG: Converting IfThen (CASE WHEN)");
            convert_if_then(if_then, available_columns, ctx)
        }
        other => Err(format!("Unsupported expression type: {:?}", other).into()),
    }
}

/// Convert a Substrait literal to a PostgreSQL Const.
unsafe fn convert_literal(
    lit: &substrait::proto::expression::Literal,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::literal::LiteralType;

    pgrx::info!(
        "DEBUG: convert_literal - literal_type discriminant: {:?}",
        lit.literal_type.as_ref().map(|l| std::mem::discriminant(l))
    );

    match &lit.literal_type {
        Some(LiteralType::I32(v)) => {
            pgrx::info!("DEBUG: Creating i32 const: {}", v);
            let c = create_int4_const(*v)?;
            pgrx::info!("DEBUG: i32 const created");
            Ok(c as *mut pg_sys::Expr)
        }
        Some(LiteralType::I64(v)) => {
            pgrx::info!("DEBUG: Creating i64 const: {}", v);
            let c = create_int8_const(*v)?;
            pgrx::info!("DEBUG: i64 const created");
            Ok(c as *mut pg_sys::Expr)
        }
        Some(LiteralType::Fp64(v)) => {
            pgrx::info!("DEBUG: Creating fp64 const: {}", v);
            let c = create_float8_const(*v)?;
            pgrx::info!("DEBUG: fp64 const created");
            Ok(c as *mut pg_sys::Expr)
        }
        Some(LiteralType::String(s)) => {
            pgrx::info!("DEBUG: Creating string const: {}", s);
            let c = create_text_const(s)?;
            pgrx::info!("DEBUG: string const created");
            Ok(c as *mut pg_sys::Expr)
        }
        Some(LiteralType::Boolean(b)) => {
            pgrx::info!("DEBUG: Creating bool const: {}", b);
            let c = create_bool_const(*b)?;
            pgrx::info!("DEBUG: bool const created");
            Ok(c as *mut pg_sys::Expr)
        }
        Some(LiteralType::Date(days)) => {
            pgrx::info!("DEBUG: Creating date const from days: {}", days);
            let c = create_date_const(*days)?;
            pgrx::info!("DEBUG: date const created");
            Ok(c as *mut pg_sys::Expr)
        }
        Some(LiteralType::Decimal(d)) => {
            pgrx::info!(
                "DEBUG: Creating decimal const: precision={}, scale={}",
                d.precision,
                d.scale
            );
            let c = create_numeric_const(&d.value, d.precision as i32, d.scale as i32)?;
            pgrx::info!("DEBUG: decimal const created");
            Ok(c as *mut pg_sys::Expr)
        }
        Some(LiteralType::FixedChar(s)) => {
            pgrx::info!("DEBUG: Creating fixed char const: {}", s);
            let c = create_text_const(s)?;
            pgrx::info!("DEBUG: fixed char const created");
            Ok(c as *mut pg_sys::Expr)
        }
        Some(LiteralType::VarChar(vc)) => {
            pgrx::info!("DEBUG: Creating varchar const: {}", vc.value);
            let c = create_text_const(&vc.value)?;
            pgrx::info!("DEBUG: varchar const created");
            Ok(c as *mut pg_sys::Expr)
        }
        other => Err(format!("Unsupported literal type: {:?}", other).into()),
    }
}

/// Convert a Substrait field selection to a PostgreSQL Var.
unsafe fn convert_selection(
    sel: &substrait::proto::expression::FieldReference,
    available_columns: &[AvailableColumn],
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::field_reference::ReferenceType;
    use substrait::proto::expression::reference_segment::ReferenceType as SegRefType;

    // Get the field index from the selection
    let field_idx = match &sel.reference_type {
        Some(ReferenceType::DirectReference(direct)) => match &direct.reference_type {
            Some(SegRefType::StructField(sf)) => sf.field as usize,
            _ => return Err("Unsupported reference segment type".into()),
        },
        _ => return Err("Unsupported reference type".into()),
    };

    // Look up the column in available columns
    if field_idx >= available_columns.len() {
        return Err(format!(
            "Field index {} out of range (available: {})",
            field_idx,
            available_columns.len()
        )
        .into());
    }

    let col = &available_columns[field_idx];

    // For computed columns (varno=0), copy the stored expression instead of creating a Var
    if col.varno == 0 {
        if let Some(expr_ptr) = col.computed_expr {
            pgrx::info!(
                "DEBUG: Using computed expression for column '{}' (field_idx={})",
                col.name,
                field_idx
            );
            // Copy the expression so we don't share mutable nodes
            let copied =
                pg_sys::copyObjectImpl(expr_ptr as *const std::ffi::c_void) as *mut pg_sys::Expr;
            return Ok(copied);
        } else {
            return Err(format!(
                "Column '{}' has varno=0 but no computed expression stored",
                col.name
            )
            .into());
        }
    }

    // Create Var node for table columns
    let mut var = pgrx::PgBox::<pg_sys::Var>::alloc0();
    var.xpr.type_ = pg_sys::NodeTag::T_Var;
    var.varno = col.varno;
    var.varattno = col.varattno;
    var.vartype = col.type_oid;
    var.vartypmod = col.typmod;
    var.varcollid = col.collation;
    var.varlevelsup = 0;
    // PG17 required fields
    var.varnosyn = col.varno as u32;
    var.varattnosyn = col.varattno;

    pgrx::info!(
        "DEBUG: Created Var node: varno={}, varattno={}, name='{}'",
        col.varno,
        col.varattno,
        col.name
    );

    Ok(var.into_pg() as *mut pg_sys::Expr)
}

/// Convert a Substrait scalar function to a PostgreSQL expression.
unsafe fn convert_scalar_function(
    func: &substrait::proto::expression::ScalarFunction,
    available_columns: &[AvailableColumn],
    ctx: &QueryBuildContext,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Get function name from the function map
    let func_name = ctx
        .function_map
        .get(&func.function_reference)
        .ok_or_else(|| format!("Unknown function reference: {}", func.function_reference))?;

    // Convert arguments
    let mut args: Vec<*mut pg_sys::Expr> = Vec::new();
    for arg in &func.arguments {
        if let Some(substrait::proto::function_argument::ArgType::Value(expr)) = &arg.arg_type {
            let pg_expr = convert_expression_for_query(expr, available_columns, ctx)?;
            args.push(pg_expr);
        }
    }

    // Map function name to PostgreSQL operator/function
    create_function_expr(func_name, &args)
}

/// Create a PostgreSQL expression for a function.
unsafe fn create_function_expr(
    func_name: &str,
    args: &[*mut pg_sys::Expr],
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Parse function name to get base name
    let base_name = func_name.split(':').next().unwrap_or(func_name);

    match base_name {
        // Boolean operators
        "and" => create_bool_expr(
            pg_sys::BoolExprType::AND_EXPR as pg_sys::BoolExprType::Type,
            args,
        ),
        "or" => create_bool_expr(
            pg_sys::BoolExprType::OR_EXPR as pg_sys::BoolExprType::Type,
            args,
        ),
        "not" => create_bool_expr(
            pg_sys::BoolExprType::NOT_EXPR as pg_sys::BoolExprType::Type,
            args,
        ),

        // Comparison operators
        "equal" | "eq" => create_op_expr("=", args),
        "not_equal" | "neq" => create_op_expr("<>", args),
        "lt" => create_op_expr("<", args),
        "lte" | "le" => create_op_expr("<=", args),
        "gt" => create_op_expr(">", args),
        "gte" | "ge" => create_op_expr(">=", args),

        // Arithmetic operators
        "add" => create_op_expr("+", args),
        "subtract" => create_op_expr("-", args),
        "multiply" => create_op_expr("*", args),
        "divide" => create_op_expr("/", args),

        // String functions
        "like" => create_op_expr("~~", args),
        "concat" => create_func_call("concat", args),
        "substring" => create_func_call("substring", args),

        // NULL checks
        "is_null" => create_null_test(args, true),
        "is_not_null" => create_null_test(args, false),

        // Aggregate functions (for future use)
        "sum" => create_func_call("sum", args),
        "count" => create_func_call("count", args),
        "avg" => create_func_call("avg", args),
        "min" => create_func_call("min", args),
        "max" => create_func_call("max", args),

        _ => {
            // Try to use as a PostgreSQL function name
            pgrx::warning!("Unknown function '{}', attempting direct call", func_name);
            create_func_call(base_name, args)
        }
    }
}

/// Create a BoolExpr (AND, OR, NOT).
unsafe fn create_bool_expr(
    boolop: pg_sys::BoolExprType::Type,
    args: &[*mut pg_sys::Expr],
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let mut bool_expr = pgrx::PgBox::<pg_sys::BoolExpr>::alloc0();
    bool_expr.xpr.type_ = pg_sys::NodeTag::T_BoolExpr;
    bool_expr.boolop = boolop;

    let mut arg_list: *mut pg_sys::List = std::ptr::null_mut();
    for arg in args {
        arg_list = pg_sys::lappend(arg_list, *arg as *mut std::ffi::c_void);
    }
    bool_expr.args = arg_list;
    bool_expr.location = -1;

    Ok(bool_expr.into_pg() as *mut pg_sys::Expr)
}

/// Create an OpExpr for binary operators.
unsafe fn create_op_expr(
    op: &str,
    args: &[*mut pg_sys::Expr],
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    if args.len() != 2 {
        return Err(format!("Operator '{}' requires 2 arguments, got {}", op, args.len()).into());
    }

    // Get argument types
    let left_type = pg_sys::exprType(args[0] as *const pg_sys::Node);
    let right_type = pg_sys::exprType(args[1] as *const pg_sys::Node);

    // Look up the operator - build the name list manually since list_make1 is a macro
    let op_cstr = std::ffi::CString::new(op)?;
    let string_node = pg_sys::makeString(op_cstr.as_ptr() as *mut i8);
    let mut op_name_list: *mut pg_sys::List = std::ptr::null_mut();
    op_name_list = pg_sys::lappend(op_name_list, string_node as *mut std::ffi::c_void);

    // First try exact match
    let mut op_oid = pg_sys::OpernameGetOprid(op_name_list, left_type, right_type);

    // If exact match fails, try coercing types to common type
    let mut coerced_left = args[0];
    let mut coerced_right = args[1];
    let mut actual_left_type = left_type;
    let mut actual_right_type = right_type;

    if op_oid == pg_sys::InvalidOid {
        // Try to find a common type for arithmetic operators
        // For FLOAT8 + NUMERIC, coerce NUMERIC to FLOAT8
        // For INT4 + NUMERIC, coerce INT4 to NUMERIC
        let common_type = select_common_type(left_type, right_type);
        if common_type != pg_sys::InvalidOid {
            if left_type != common_type {
                coerced_left = coerce_to_type(args[0], left_type, common_type);
                actual_left_type = common_type;
            }
            if right_type != common_type {
                coerced_right = coerce_to_type(args[1], right_type, common_type);
                actual_right_type = common_type;
            }

            // Try again with coerced types
            op_oid = pg_sys::OpernameGetOprid(op_name_list, actual_left_type, actual_right_type);
        }
    }

    if op_oid == pg_sys::InvalidOid {
        return Err(format!(
            "Operator '{}' not found for types {} and {} (tried coercion)",
            op,
            left_type.to_u32(),
            right_type.to_u32()
        )
        .into());
    }

    // Get operator info
    let op_tuple = pg_sys::SearchSysCache1(
        pg_sys::SysCacheIdentifier::OPEROID as i32,
        pg_sys::ObjectIdGetDatum(op_oid),
    );
    if op_tuple.is_null() {
        return Err(format!("Failed to get operator info for OID {}", op_oid.to_u32()).into());
    }

    let op_form = pg_sys::GETSTRUCT(op_tuple) as pg_sys::Form_pg_operator;
    let result_type = (*op_form).oprresult;
    let op_func = (*op_form).oprcode;

    pg_sys::ReleaseSysCache(op_tuple);

    // Create OpExpr
    let mut op_expr = pgrx::PgBox::<pg_sys::OpExpr>::alloc0();
    op_expr.xpr.type_ = pg_sys::NodeTag::T_OpExpr;
    op_expr.opno = op_oid;
    op_expr.opfuncid = op_func;
    op_expr.opresulttype = result_type;
    op_expr.opretset = false;
    op_expr.opcollid = pg_sys::InvalidOid;
    op_expr.inputcollid = pg_sys::InvalidOid;

    let mut arg_list: *mut pg_sys::List = std::ptr::null_mut();
    arg_list = pg_sys::lappend(arg_list, coerced_left as *mut std::ffi::c_void);
    arg_list = pg_sys::lappend(arg_list, coerced_right as *mut std::ffi::c_void);
    op_expr.args = arg_list;
    op_expr.location = -1;

    Ok(op_expr.into_pg() as *mut pg_sys::Expr)
}

/// Select a common type for arithmetic operations.
fn select_common_type(left: pg_sys::Oid, right: pg_sys::Oid) -> pg_sys::Oid {
    const FLOAT8: pg_sys::Oid = pg_sys::Oid::from_u32(701); // float8
    const FLOAT4: pg_sys::Oid = pg_sys::Oid::from_u32(700); // float4
    const NUMERIC: pg_sys::Oid = pg_sys::Oid::from_u32(1700); // numeric
    const INT8: pg_sys::Oid = pg_sys::Oid::from_u32(20); // int8
    const INT4: pg_sys::Oid = pg_sys::Oid::from_u32(23); // int4
    const INT2: pg_sys::Oid = pg_sys::Oid::from_u32(21); // int2

    // If same type, use it
    if left == right {
        return left;
    }

    // Float8 dominates all
    if left == FLOAT8 || right == FLOAT8 {
        return FLOAT8;
    }

    // Float4 dominates numeric and integers
    if left == FLOAT4 || right == FLOAT4 {
        return FLOAT8; // Promote to float8 for precision
    }

    // Numeric dominates integers
    if left == NUMERIC || right == NUMERIC {
        return NUMERIC;
    }

    // Int8 dominates smaller integers
    if left == INT8 || right == INT8 {
        return INT8;
    }

    // Int4 dominates int2
    if left == INT4 || right == INT4 {
        return INT4;
    }

    pg_sys::InvalidOid
}

/// Coerce an expression to a target type using CoerceViaIO.
unsafe fn coerce_to_type(
    expr: *mut pg_sys::Expr,
    _from_type: pg_sys::Oid,
    to_type: pg_sys::Oid,
) -> *mut pg_sys::Expr {
    let mut coerce = pgrx::PgBox::<pg_sys::CoerceViaIO>::alloc0();
    coerce.xpr.type_ = pg_sys::NodeTag::T_CoerceViaIO;
    coerce.arg = expr;
    coerce.resulttype = to_type;
    coerce.resultcollid = pg_sys::InvalidOid;
    coerce.coerceformat = pg_sys::CoercionForm::COERCE_IMPLICIT_CAST;
    coerce.location = -1;
    coerce.into_pg() as *mut pg_sys::Expr
}

/// Create a FuncExpr for function calls.
unsafe fn create_func_call(
    func_name: &str,
    args: &[*mut pg_sys::Expr],
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Look up the function
    let func_cstr = std::ffi::CString::new(func_name)?;

    // Build argument type array
    let mut arg_types: Vec<pg_sys::Oid> = Vec::new();
    for arg in args {
        arg_types.push(pg_sys::exprType(*arg as *const pg_sys::Node));
    }

    // Build function name list manually (list_make1 is a macro)
    let string_node = pg_sys::makeString(func_cstr.as_ptr() as *mut i8);
    let mut func_name_list: *mut pg_sys::List = std::ptr::null_mut();
    func_name_list = pg_sys::lappend(func_name_list, string_node as *mut std::ffi::c_void);

    // Find the function
    let func_oid = pg_sys::LookupFuncName(
        func_name_list,
        arg_types.len() as i32,
        arg_types.as_ptr(),
        true, // noError
    );

    if func_oid == pg_sys::InvalidOid {
        return Err(format!("Function '{}' not found", func_name).into());
    }

    // Get function return type
    let func_tuple = pg_sys::SearchSysCache1(
        pg_sys::SysCacheIdentifier::PROCOID as i32,
        pg_sys::ObjectIdGetDatum(func_oid),
    );
    if func_tuple.is_null() {
        return Err(format!("Failed to get function info for '{}'", func_name).into());
    }

    let func_form = pg_sys::GETSTRUCT(func_tuple) as pg_sys::Form_pg_proc;
    let result_type = (*func_form).prorettype;

    pg_sys::ReleaseSysCache(func_tuple);

    // Create FuncExpr
    let mut func_expr = pgrx::PgBox::<pg_sys::FuncExpr>::alloc0();
    func_expr.xpr.type_ = pg_sys::NodeTag::T_FuncExpr;
    func_expr.funcid = func_oid;
    func_expr.funcresulttype = result_type;
    func_expr.funcretset = false;
    func_expr.funcvariadic = false;
    func_expr.funcformat = pg_sys::CoercionForm::COERCE_EXPLICIT_CALL;
    func_expr.funccollid = pg_sys::InvalidOid;
    func_expr.inputcollid = pg_sys::InvalidOid;

    let mut arg_list: *mut pg_sys::List = std::ptr::null_mut();
    for arg in args {
        arg_list = pg_sys::lappend(arg_list, *arg as *mut std::ffi::c_void);
    }
    func_expr.args = arg_list;
    func_expr.location = -1;

    Ok(func_expr.into_pg() as *mut pg_sys::Expr)
}

/// Create a NullTest expression.
unsafe fn create_null_test(
    args: &[*mut pg_sys::Expr],
    is_null: bool,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    if args.is_empty() {
        return Err("NullTest requires an argument".into());
    }

    let mut null_test = pgrx::PgBox::<pg_sys::NullTest>::alloc0();
    null_test.xpr.type_ = pg_sys::NodeTag::T_NullTest;
    null_test.arg = args[0];
    null_test.nulltesttype = if is_null {
        pg_sys::NullTestType::IS_NULL
    } else {
        pg_sys::NullTestType::IS_NOT_NULL
    };
    null_test.argisrow = false;
    null_test.location = -1;

    Ok(null_test.into_pg() as *mut pg_sys::Expr)
}

/// Convert a Cast expression.
unsafe fn convert_cast(
    cast: &substrait::proto::expression::Cast,
    available_columns: &[AvailableColumn],
    ctx: &QueryBuildContext,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    pgrx::info!("DEBUG: convert_cast - starting");

    let input_expr = cast.input.as_ref().ok_or("Cast has no input")?;
    pgrx::info!("DEBUG: convert_cast - converting input expression");
    let pg_input = convert_expression_for_query(input_expr, available_columns, ctx)?;
    pgrx::info!(
        "DEBUG: convert_cast - input converted, pg_input: {:p}",
        pg_input
    );

    let target_type = cast.r#type.as_ref().ok_or("Cast has no target type")?;
    pgrx::info!("DEBUG: convert_cast - getting target OID");
    let target_oid = substrait_type_to_pg_oid(target_type)?;
    pgrx::info!("DEBUG: convert_cast - target_oid: {}", target_oid.to_u32());

    // Create a cast using CoerceViaIO or RelabelType
    pgrx::info!("DEBUG: convert_cast - calling exprType");
    let input_type = pg_sys::exprType(pg_input as *const pg_sys::Node);
    pgrx::info!("DEBUG: convert_cast - input_type: {}", input_type.to_u32());

    if input_type == target_oid {
        // No cast needed
        pgrx::info!("DEBUG: convert_cast - types match, no cast needed");
        return Ok(pg_input);
    }

    pgrx::info!(
        "DEBUG: convert_cast - types differ (input={}, target={}), using CoerceViaIO",
        input_type.to_u32(),
        target_oid.to_u32()
    );

    // Use CoerceViaIO for all type conversions - it works via I/O functions
    // which are always available. This avoids catalog lookups that might crash.
    let mut coerce = pgrx::PgBox::<pg_sys::CoerceViaIO>::alloc0();
    coerce.xpr.type_ = pg_sys::NodeTag::T_CoerceViaIO;
    coerce.arg = pg_input;
    coerce.resulttype = target_oid;
    coerce.resultcollid = pg_sys::InvalidOid;
    coerce.coerceformat = pg_sys::CoercionForm::COERCE_EXPLICIT_CAST;
    coerce.location = -1;
    pgrx::info!("DEBUG: convert_cast - CoerceViaIO created");

    Ok(coerce.into_pg() as *mut pg_sys::Expr)
}

/// Convert a Substrait IfThen (CASE WHEN) expression.
unsafe fn convert_if_then(
    if_then: &substrait::proto::expression::IfThen,
    available_columns: &[AvailableColumn],
    ctx: &QueryBuildContext,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let mut case_when_list: *mut pg_sys::List = std::ptr::null_mut();
    let mut result_type: Option<pg_sys::Oid> = None;

    for if_clause in &if_then.ifs {
        // Convert condition
        let condition = if_clause
            .r#if
            .as_ref()
            .ok_or("IfThen clause missing 'if' condition")?;
        let cond_expr = convert_expression_for_query(condition, available_columns, ctx)?;

        // Convert result
        let then_result = if_clause
            .then
            .as_ref()
            .ok_or("IfThen clause missing 'then' result")?;
        let then_expr = convert_expression_for_query(then_result, available_columns, ctx)?;

        if result_type.is_none() {
            result_type = Some(pg_sys::exprType(then_expr as *const pg_sys::Node));
        }

        // Create CaseWhen
        let mut case_when = pgrx::PgBox::<pg_sys::CaseWhen>::alloc0();
        case_when.xpr.type_ = pg_sys::NodeTag::T_CaseWhen;
        case_when.expr = cond_expr;
        case_when.result = then_expr;
        case_when.location = -1;
        let case_when = case_when.into_pg();

        case_when_list = pg_sys::lappend(case_when_list, case_when as *mut std::ffi::c_void);
    }

    // Convert ELSE clause
    let default_result = if let Some(else_expr) = &if_then.r#else {
        convert_expression_for_query(else_expr, available_columns, ctx)?
    } else {
        std::ptr::null_mut()
    };

    let case_type = result_type.unwrap_or(pg_sys::INT4OID);

    // Create CaseExpr
    let mut case_expr = pgrx::PgBox::<pg_sys::CaseExpr>::alloc0();
    case_expr.xpr.type_ = pg_sys::NodeTag::T_CaseExpr;
    case_expr.casetype = case_type;
    case_expr.casecollid = pg_sys::InvalidOid;
    case_expr.arg = std::ptr::null_mut(); // Searched CASE
    case_expr.args = case_when_list;
    case_expr.defresult = default_result;
    case_expr.location = -1;

    Ok(case_expr.into_pg() as *mut pg_sys::Expr)
}

/// Map Substrait type to PostgreSQL OID.
unsafe fn substrait_type_to_pg_oid(
    typ: &substrait::proto::Type,
) -> Result<pg_sys::Oid, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::r#type::Kind;

    match &typ.kind {
        Some(Kind::I32(_)) => Ok(pg_sys::INT4OID),
        Some(Kind::I64(_)) => Ok(pg_sys::INT8OID),
        Some(Kind::Fp32(_)) => Ok(pg_sys::FLOAT4OID),
        Some(Kind::Fp64(_)) => Ok(pg_sys::FLOAT8OID),
        Some(Kind::String(_)) => Ok(pg_sys::TEXTOID),
        Some(Kind::Bool(_)) => Ok(pg_sys::BOOLOID),
        Some(Kind::Date(_)) => Ok(pg_sys::DATEOID),
        Some(Kind::Decimal(_)) => Ok(pg_sys::NUMERICOID),
        Some(Kind::FixedChar(_)) => Ok(pg_sys::BPCHAROID),
        Some(Kind::Varchar(_)) => Ok(pg_sys::VARCHAROID),
        other => Err(format!("Unsupported Substrait type: {:?}", other).into()),
    }
}

// Helper functions to create constants

unsafe fn create_int4_const(
    value: i32,
) -> Result<*mut pg_sys::Const, Box<dyn std::error::Error + Send + Sync>> {
    let mut c = pgrx::PgBox::<pg_sys::Const>::alloc0();
    c.xpr.type_ = pg_sys::NodeTag::T_Const;
    c.consttype = pg_sys::INT4OID;
    c.consttypmod = -1;
    c.constcollid = pg_sys::InvalidOid;
    c.constlen = 4;
    c.constbyval = true;
    c.constisnull = false;
    c.constvalue = pg_sys::Datum::from(value);
    c.location = -1;
    Ok(c.into_pg())
}

unsafe fn create_int8_const(
    value: i64,
) -> Result<*mut pg_sys::Const, Box<dyn std::error::Error + Send + Sync>> {
    let mut c = pgrx::PgBox::<pg_sys::Const>::alloc0();
    c.xpr.type_ = pg_sys::NodeTag::T_Const;
    c.consttype = pg_sys::INT8OID;
    c.consttypmod = -1;
    c.constcollid = pg_sys::InvalidOid;
    c.constlen = 8;
    c.constbyval = true;
    c.constisnull = false;
    c.constvalue = pg_sys::Datum::from(value);
    c.location = -1;
    Ok(c.into_pg())
}

unsafe fn create_float8_const(
    value: f64,
) -> Result<*mut pg_sys::Const, Box<dyn std::error::Error + Send + Sync>> {
    let mut c = pgrx::PgBox::<pg_sys::Const>::alloc0();
    c.xpr.type_ = pg_sys::NodeTag::T_Const;
    c.consttype = pg_sys::FLOAT8OID;
    c.consttypmod = -1;
    c.constcollid = pg_sys::InvalidOid;
    c.constlen = 8;
    c.constbyval = true;
    c.constisnull = false;
    c.constvalue = pg_sys::Datum::from(value.to_bits() as i64);
    c.location = -1;
    Ok(c.into_pg())
}

unsafe fn create_text_const(
    value: &str,
) -> Result<*mut pg_sys::Const, Box<dyn std::error::Error + Send + Sync>> {
    let cstr = std::ffi::CString::new(value)?;
    // Use cstring_to_text to create text datum (CStringGetTextDatum is a macro)
    let text_ptr = pg_sys::cstring_to_text(cstr.as_ptr());
    let text_datum = pg_sys::Datum::from(text_ptr as *mut std::ffi::c_void);

    let mut c = pgrx::PgBox::<pg_sys::Const>::alloc0();
    c.xpr.type_ = pg_sys::NodeTag::T_Const;
    c.consttype = pg_sys::TEXTOID;
    c.consttypmod = -1;
    c.constcollid = pg_sys::DEFAULT_COLLATION_OID;
    c.constlen = -1; // Variable length
    c.constbyval = false;
    c.constisnull = false;
    c.constvalue = text_datum;
    c.location = -1;
    Ok(c.into_pg())
}

unsafe fn create_bool_const(
    value: bool,
) -> Result<*mut pg_sys::Const, Box<dyn std::error::Error + Send + Sync>> {
    let mut c = pgrx::PgBox::<pg_sys::Const>::alloc0();
    c.xpr.type_ = pg_sys::NodeTag::T_Const;
    c.consttype = pg_sys::BOOLOID;
    c.consttypmod = -1;
    c.constcollid = pg_sys::InvalidOid;
    c.constlen = 1;
    c.constbyval = true;
    c.constisnull = false;
    c.constvalue = pg_sys::Datum::from(value);
    c.location = -1;
    Ok(c.into_pg())
}

unsafe fn create_date_const(
    days: i32,
) -> Result<*mut pg_sys::Const, Box<dyn std::error::Error + Send + Sync>> {
    // PostgreSQL dates are days since 2000-01-01
    // Substrait dates are days since 1970-01-01
    // Difference: 10957 days
    let pg_days = days - 10957;

    let mut c = pgrx::PgBox::<pg_sys::Const>::alloc0();
    c.xpr.type_ = pg_sys::NodeTag::T_Const;
    c.consttype = pg_sys::DATEOID;
    c.consttypmod = -1;
    c.constcollid = pg_sys::InvalidOid;
    c.constlen = 4;
    c.constbyval = true;
    c.constisnull = false;
    c.constvalue = pg_sys::Datum::from(pg_days);
    c.location = -1;
    Ok(c.into_pg())
}

unsafe fn create_numeric_const(
    value_bytes: &[u8],
    _precision: i32,
    scale: i32,
) -> Result<*mut pg_sys::Const, Box<dyn std::error::Error + Send + Sync>> {
    // Convert Substrait decimal (little-endian two's complement) to PostgreSQL numeric
    use num_bigint::BigInt;
    use pgrx::{AnyNumeric, IntoDatum};
    use std::str::FromStr;

    let big_int = BigInt::from_signed_bytes_le(value_bytes);

    // Format the BigInt into a string, applying the scale
    let mut numeric_string = big_int.to_string();

    // Apply scaling
    if scale > 0 {
        let len = numeric_string.len() as i32;
        if len <= scale {
            // Pad with leading zeros if necessary
            numeric_string =
                "0.".to_string() + &"0".repeat((scale - len) as usize) + &numeric_string;
        } else {
            // Insert decimal point
            numeric_string.insert((len - scale) as usize, '.');
        }
    } else if scale < 0 {
        // If scale is negative, append zeros
        numeric_string.push_str(&"0".repeat((-scale) as usize));
    }

    let numeric_value: AnyNumeric = AnyNumeric::from_str(&numeric_string)
        .map_err(|e| format!("Failed to parse numeric value from string: {e}"))?;

    let mut c = pgrx::PgBox::<pg_sys::Const>::alloc0();
    c.xpr.type_ = pg_sys::NodeTag::T_Const;
    c.consttype = pg_sys::NUMERICOID;
    c.consttypmod = -1;
    c.constcollid = pg_sys::InvalidOid;
    c.constlen = -1;
    c.constbyval = false;
    c.constisnull = false;
    c.constvalue = numeric_value.into_datum().unwrap();
    c.location = -1;
    Ok(c.into_pg())
}

/// Convert a Substrait aggregate measure to a PostgreSQL Aggref expression.
pub unsafe fn convert_aggregate_measure(
    measure: &substrait::proto::aggregate_rel::Measure,
    available_columns: &[AvailableColumn],
    ctx: &QueryBuildContext,
    agg_index: usize,
) -> Result<*mut pg_sys::Aggref, Box<dyn std::error::Error + Send + Sync>> {
    let func = measure.measure.as_ref().ok_or("Missing measure function")?;

    // Get function name from reference
    let func_name = ctx
        .function_map
        .get(&func.function_reference)
        .map(|s| s.as_str())
        .unwrap_or("");

    // Determine base aggregate function name
    let base_name = if func_name.starts_with("sum:") {
        "sum"
    } else if func_name.starts_with("avg:") {
        "avg"
    } else if func_name.starts_with("count:") {
        "count"
    } else if func_name.starts_with("min:") {
        "min"
    } else if func_name.starts_with("max:") {
        "max"
    } else {
        "count" // Default
    };

    // Determine argument type from the first argument
    let (arg_type, arg_expr) = if func.arguments.is_empty() {
        (pg_sys::InvalidOid, None)
    } else if let Some(substrait::proto::function_argument::ArgType::Value(expr)) =
        &func.arguments[0].arg_type
    {
        let pg_expr = convert_expression_for_query(expr, available_columns, ctx)?;
        let expr_type = pg_sys::exprType(pg_expr as *const pg_sys::Node);
        (expr_type, Some(pg_expr))
    } else {
        (pg_sys::InvalidOid, None)
    };

    // Look up aggregate function OID
    let agg_oid = lookup_agg_oid(base_name, arg_type);
    if agg_oid == pg_sys::InvalidOid {
        return Err(format!(
            "Aggregate function '{}' not found for type {}",
            base_name,
            arg_type.to_u32()
        )
        .into());
    }

    // Get aggregate return and transition types
    let (return_type, trans_type) = get_agg_types(agg_oid);

    // Build Aggref
    let mut agg = pgrx::PgBox::<pg_sys::Aggref>::alloc0();
    agg.xpr.type_ = pg_sys::NodeTag::T_Aggref;
    agg.aggfnoid = agg_oid;
    agg.aggtype = return_type;
    agg.aggcollid = pg_sys::InvalidOid;
    agg.inputcollid = pg_sys::InvalidOid;
    agg.aggtranstype = trans_type;
    agg.aggargtypes = build_arg_type_list(arg_type);
    agg.aggdirectargs = std::ptr::null_mut();
    agg.args = build_agg_args_list(arg_expr, arg_type);
    agg.aggorder = std::ptr::null_mut();
    agg.aggdistinct = std::ptr::null_mut();
    agg.aggfilter = std::ptr::null_mut();
    agg.aggstar = func.arguments.is_empty(); // count(*) has no arguments
    agg.aggvariadic = false;
    agg.aggkind = b'n' as i8; // AGGKIND_NORMAL
    agg.aggpresorted = false;
    agg.agglevelsup = 0;
    agg.aggsplit = pg_sys::AggSplit::AGGSPLIT_SIMPLE;
    agg.aggno = agg_index as i32;
    agg.aggtransno = agg_index as i32;
    agg.location = -1;

    Ok(agg.into_pg())
}

/// Look up aggregate function OID by name and argument type.
unsafe fn lookup_agg_oid(name: &str, arg_type: pg_sys::Oid) -> pg_sys::Oid {
    // For count(*), use the no-argument version
    if name == "count" && arg_type == pg_sys::InvalidOid {
        return pg_sys::Oid::from_u32(2803); // count(*)
    }

    // Build function name list
    let func_cstr = std::ffi::CString::new(name).unwrap();
    let string_node = pg_sys::makeString(func_cstr.as_ptr() as *mut i8);
    let mut func_name_list: *mut pg_sys::List = std::ptr::null_mut();
    func_name_list = pg_sys::lappend(func_name_list, string_node as *mut std::ffi::c_void);

    // Try with the actual argument type
    if arg_type != pg_sys::InvalidOid {
        let func_oid =
            pg_sys::LookupFuncName(func_name_list, 1, &arg_type as *const pg_sys::Oid, true);
        if func_oid != pg_sys::InvalidOid {
            return func_oid;
        }
    }

    // For count, we can use count("any") - OID 2147
    if name == "count" {
        return pg_sys::Oid::from_u32(2147);
    }

    pg_sys::InvalidOid
}

/// Get aggregate return type and transition type from syscache.
unsafe fn get_agg_types(agg_oid: pg_sys::Oid) -> (pg_sys::Oid, pg_sys::Oid) {
    // Get function info for return type
    let proc_tuple = pg_sys::SearchSysCache1(
        pg_sys::SysCacheIdentifier::PROCOID as i32,
        pg_sys::ObjectIdGetDatum(agg_oid),
    );
    if proc_tuple.is_null() {
        return (pg_sys::INT8OID, pg_sys::INT8OID); // Default for count
    }
    let proc_form = pg_sys::GETSTRUCT(proc_tuple) as pg_sys::Form_pg_proc;
    let return_type = (*proc_form).prorettype;
    pg_sys::ReleaseSysCache(proc_tuple);

    // For transition type, use the return type as a reasonable default.
    // The planner will figure out the actual transition type.
    // This is sufficient for Query building - the executor handles details.
    (return_type, return_type)
}

/// Build a list of argument type OIDs.
unsafe fn build_arg_type_list(arg_type: pg_sys::Oid) -> *mut pg_sys::List {
    if arg_type == pg_sys::InvalidOid {
        return std::ptr::null_mut();
    }

    let mut list: *mut pg_sys::List = std::ptr::null_mut();
    list = pg_sys::lappend_oid(list, arg_type);
    list
}

/// Build the args list for Aggref (list of TargetEntry nodes).
unsafe fn build_agg_args_list(
    arg_expr: Option<*mut pg_sys::Expr>,
    _arg_type: pg_sys::Oid,
) -> *mut pg_sys::List {
    let Some(expr) = arg_expr else {
        return std::ptr::null_mut();
    };

    // Wrap in TargetEntry
    let mut te = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
    te.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
    te.expr = expr;
    te.resno = 1;
    te.resname = std::ptr::null_mut();
    te.ressortgroupref = 0;
    te.resorigtbl = pg_sys::InvalidOid;
    te.resorigcol = 0;
    te.resjunk = false;

    let mut list: *mut pg_sys::List = std::ptr::null_mut();
    list = pg_sys::lappend(list, te.into_pg() as *mut std::ffi::c_void);
    list
}
