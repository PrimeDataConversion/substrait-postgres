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
        expr.rex_type.as_ref().map(std::mem::discriminant)
    );

    match &expr.rex_type {
        Some(RexType::Literal(lit)) => {
            pgrx::info!("DEBUG: Converting Literal");
            convert_literal(lit)
        }
        Some(RexType::Selection(sel)) => {
            pgrx::info!("DEBUG: Converting Selection (field reference)");
            convert_selection(sel, available_columns, ctx)
        }
        Some(RexType::Subquery(subquery)) => {
            pgrx::info!("DEBUG: Converting Subquery");
            convert_subquery(subquery, available_columns, ctx)
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
        lit.literal_type.as_ref().map(std::mem::discriminant)
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
            let c = create_numeric_const(&d.value, d.precision, d.scale)?;
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
        Some(LiteralType::IntervalYearToMonth(interval)) => {
            pgrx::info!(
                "DEBUG: Creating interval const: {} years, {} months",
                interval.years,
                interval.months
            );
            // Convert years and months to total months
            let total_months = interval.years * 12 + interval.months;
            // Create an interval constant - PostgreSQL interval is stored as months + days + microseconds
            let c = create_interval_const(total_months, 0, 0)?;
            pgrx::info!("DEBUG: interval const created");
            Ok(c as *mut pg_sys::Expr)
        }
        other => Err(format!("Unsupported literal type: {:?}", other).into()),
    }
}

/// Convert a Substrait field selection to a PostgreSQL Var.
unsafe fn convert_selection(
    sel: &substrait::proto::expression::FieldReference,
    available_columns: &[AvailableColumn],
    ctx: &QueryBuildContext,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::field_reference::ReferenceType;
    use substrait::proto::expression::field_reference::RootType;
    use substrait::proto::expression::reference_segment::ReferenceType as SegRefType;

    // Get the field index from the selection
    let field_idx = match &sel.reference_type {
        Some(ReferenceType::DirectReference(direct)) => match &direct.reference_type {
            Some(SegRefType::StructField(sf)) => sf.field as usize,
            _ => return Err("Unsupported reference segment type".into()),
        },
        _ => return Err("Unsupported reference type".into()),
    };

    // Determine which query level the reference targets. An OuterReference
    // resolves against an enclosing query's columns and becomes a Var with
    // varlevelsup > 0; PostgreSQL's planner turns those into Params when it
    // builds the SubPlan for the containing SubLink.
    let (scope_columns, varlevelsup) = match &sel.root_type {
        Some(RootType::OuterReference(outer)) => {
            let steps_out = outer.steps_out as usize;
            if steps_out == 0 {
                return Err("OuterReference with steps_out=0".into());
            }
            let scope = ctx.outer_scopes.get(steps_out - 1).ok_or_else(|| {
                format!(
                    "OuterReference steps_out={} but only {} enclosing scopes available",
                    steps_out,
                    ctx.outer_scopes.len()
                )
            })?;
            (scope.as_slice(), steps_out as pg_sys::Index)
        }
        _ => (available_columns, 0),
    };

    // Look up the column in the resolved scope
    if field_idx >= scope_columns.len() {
        return Err(format!(
            "Field index {} out of range (available: {})",
            field_idx,
            scope_columns.len()
        )
        .into());
    }

    let col = &scope_columns[field_idx];

    // Computed outer columns would require rewriting varlevelsup inside the
    // stored expression; not supported until a plan needs it.
    if varlevelsup > 0 && col.varno == 0 {
        return Err(format!(
            "Outer reference to computed column '{}' is not supported",
            col.name
        )
        .into());
    }

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
    var.varlevelsup = varlevelsup;
    // PG17 required fields
    var.varnosyn = col.varno as u32;
    var.varattnosyn = col.varattno;

    pgrx::info!(
        "DEBUG: Created Var node: varno={}, varattno={}, varlevelsup={}, name='{}'",
        col.varno,
        col.varattno,
        varlevelsup,
        col.name
    );

    Ok(var.into_pg() as *mut pg_sys::Expr)
}

/// Convert a Substrait subquery expression to a PostgreSQL SubLink.
///
/// SubLinks are the parse-tree representation of subqueries; the standard
/// planner converts them to SubPlans (or pulls them up into joins) and wires
/// up Params for any correlated Vars (varlevelsup > 0), so no manual Param
/// management is needed here.
unsafe fn convert_subquery(
    subquery: &substrait::proto::expression::Subquery,
    available_columns: &[AvailableColumn],
    ctx: &QueryBuildContext,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::subquery::SubqueryType;

    match &subquery.subquery_type {
        Some(SubqueryType::Scalar(scalar)) => {
            let input = scalar
                .input
                .as_ref()
                .ok_or("Scalar subquery has no input")?;
            let subselect = super::relations::build_subquery(input, available_columns, ctx)?;
            create_sublink(
                pg_sys::SubLinkType::EXPR_SUBLINK,
                std::ptr::null_mut(),
                subselect,
                ctx,
            )
        }
        Some(SubqueryType::InPredicate(in_pred)) => {
            let haystack = in_pred
                .haystack
                .as_ref()
                .ok_or("InPredicate subquery has no haystack")?;
            let subselect = super::relations::build_subquery(haystack, available_columns, ctx)?;

            // Build the test expression: needle_i = Param(PARAM_SUBLINK, i).
            // The Params stand in for the subquery's output columns; the
            // planner substitutes the real values when building the SubPlan.
            if in_pred.needles.is_empty() {
                return Err("InPredicate subquery has no needles".into());
            }
            let mut op_exprs: Vec<*mut pg_sys::Expr> = Vec::new();
            for (i, needle) in in_pred.needles.iter().enumerate() {
                let needle_expr = convert_expression_for_query(needle, available_columns, ctx)?;
                let param = create_sublink_param(subselect, i)?;
                op_exprs.push(create_op_expr("=", &[needle_expr, param])?);
            }
            let testexpr = if op_exprs.len() == 1 {
                op_exprs[0]
            } else {
                create_bool_expr(
                    pg_sys::BoolExprType::AND_EXPR as pg_sys::BoolExprType::Type,
                    &op_exprs,
                )?
            };
            create_sublink(
                pg_sys::SubLinkType::ANY_SUBLINK,
                testexpr as *mut pg_sys::Node,
                subselect,
                ctx,
            )
        }
        Some(SubqueryType::SetPredicate(set_pred)) => {
            use substrait::proto::expression::subquery::set_predicate::PredicateOp;

            let tuples = set_pred
                .tuples
                .as_ref()
                .ok_or("SetPredicate subquery has no tuples")?;
            match set_pred.predicate_op() {
                PredicateOp::Exists => {
                    let subselect =
                        super::relations::build_subquery(tuples, available_columns, ctx)?;
                    create_sublink(
                        pg_sys::SubLinkType::EXISTS_SUBLINK,
                        std::ptr::null_mut(),
                        subselect,
                        ctx,
                    )
                }
                other => Err(format!("Unsupported set predicate op: {:?}", other).into()),
            }
        }
        Some(SubqueryType::SetComparison(_)) => {
            Err("SetComparison subqueries not yet supported".into())
        }
        None => Err("Subquery missing subquery_type".into()),
    }
}

/// Create a SubLink node wrapping a sub-Query.
unsafe fn create_sublink(
    link_type: pg_sys::SubLinkType::Type,
    testexpr: *mut pg_sys::Node,
    subselect: *mut pg_sys::Query,
    ctx: &QueryBuildContext,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let mut sublink = pgrx::PgBox::<pg_sys::SubLink>::alloc0();
    sublink.xpr.type_ = pg_sys::NodeTag::T_SubLink;
    sublink.subLinkType = link_type;
    sublink.subLinkId = 0;
    sublink.testexpr = testexpr;
    // operName is only used for display of explicit ANY/ALL operators;
    // IN and scalar subqueries use NIL just as the parser does.
    sublink.operName = std::ptr::null_mut();
    sublink.subselect = subselect as *mut pg_sys::Node;
    sublink.location = -1;

    // The Query containing this SubLink must have hasSubLinks set.
    ctx.has_sublinks.set(true);

    Ok(sublink.into_pg() as *mut pg_sys::Expr)
}

/// Create a PARAM_SUBLINK Param representing the idx-th (0-based) output
/// column of a subquery, for use in a SubLink test expression.
unsafe fn create_sublink_param(
    subselect: *mut pg_sys::Query,
    idx: usize,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let tlist = (*subselect).targetList;
    if tlist.is_null() || idx >= (*tlist).length as usize {
        return Err(format!(
            "Subquery has {} output columns but needle {} requires more",
            if tlist.is_null() { 0 } else { (*tlist).length },
            idx + 1
        )
        .into());
    }
    let te = pg_sys::list_nth(tlist, idx as i32) as *mut pg_sys::TargetEntry;
    let te_expr = (*te).expr as *const pg_sys::Node;

    let mut param = pgrx::PgBox::<pg_sys::Param>::alloc0();
    param.xpr.type_ = pg_sys::NodeTag::T_Param;
    param.paramkind = pg_sys::ParamKind::PARAM_SUBLINK;
    param.paramid = (idx + 1) as i32; // 1-based subquery column position
    param.paramtype = pg_sys::exprType(te_expr);
    param.paramtypmod = pg_sys::exprTypmod(te_expr);
    param.paramcollid = pg_sys::exprCollation(te_expr);
    param.location = -1;

    Ok(param.into_pg() as *mut pg_sys::Expr)
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

    // Convert arguments - handle both Value and Enum types
    let mut args: Vec<*mut pg_sys::Expr> = Vec::new();
    for arg in &func.arguments {
        match &arg.arg_type {
            Some(substrait::proto::function_argument::ArgType::Value(expr)) => {
                let pg_expr = convert_expression_for_query(expr, available_columns, ctx)?;
                args.push(pg_expr);
            }
            Some(substrait::proto::function_argument::ArgType::Enum(enum_val)) => {
                // Convert enum to text constant (e.g., "YEAR" for extract function)
                let text_const = create_text_const(&enum_val.to_lowercase())?;
                args.push(text_const as *mut pg_sys::Expr);
            }
            _ => {}
        }
    }

    // Map function name to PostgreSQL operator/function
    pgrx::info!(
        "DEBUG: create_function_expr for '{}' with {} args",
        func_name,
        args.len()
    );
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

        // Date/time functions - extract uses date_part with args (field_name, date)
        // The field name comes from an enum argument, already converted to text
        "extract" => create_func_call("date_part", args),
        name if name.starts_with("extract:") => {
            // extract:req_date, extract:req_timestamp etc.
            // Args already contain [field_text, date_value] from enum conversion
            create_func_call("date_part", args)
        }

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

    // Set inputcollid for string comparisons
    // Check if either operand is a collatable type
    let left_coll = pg_sys::exprCollation(coerced_left as *const pg_sys::Node);
    let right_coll = pg_sys::exprCollation(coerced_right as *const pg_sys::Node);
    if left_coll != pg_sys::InvalidOid {
        op_expr.inputcollid = left_coll;
    } else if right_coll != pg_sys::InvalidOid {
        op_expr.inputcollid = right_coll;
    } else {
        // Check if types are collatable and need default collation
        let left_type_collatable = pg_sys::type_is_collatable(actual_left_type);
        let right_type_collatable = pg_sys::type_is_collatable(actual_right_type);
        if left_type_collatable || right_type_collatable {
            op_expr.inputcollid = pg_sys::DEFAULT_COLLATION_OID;
        } else {
            op_expr.inputcollid = pg_sys::InvalidOid;
        }
    }

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
    const TEXT: pg_sys::Oid = pg_sys::Oid::from_u32(25); // text
    const BPCHAR: pg_sys::Oid = pg_sys::Oid::from_u32(1042); // bpchar (char(n))
    const VARCHAR: pg_sys::Oid = pg_sys::Oid::from_u32(1043); // varchar

    // String types - text is the common type for all string comparisons
    // This handles varchar ~~ varchar, bpchar = text, etc.
    // Must be checked before the same-type shortcut below
    let left_is_string = left == TEXT || left == BPCHAR || left == VARCHAR;
    let right_is_string = right == TEXT || right == BPCHAR || right == VARCHAR;
    if left_is_string && right_is_string {
        // For any string type combination, use text as the common type
        // This ensures operators like ~~ (LIKE) work correctly
        return TEXT;
    }

    // If same type, use it (for non-string types)
    if left == right {
        return left;
    }

    // Float8 dominates all numeric types
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

/// Coerce an expression to a target type.
///
/// Uses PostgreSQL's own coercion machinery so the registered cast path is
/// applied. This matters for semantics: e.g. bpchar -> text goes through
/// rtrim1() which strips the blank padding, whereas an I/O coercion would
/// keep it and make 'EUROPE'::char(25) compare unequal to 'EUROPE'.
unsafe fn coerce_to_type(
    expr: *mut pg_sys::Expr,
    from_type: pg_sys::Oid,
    to_type: pg_sys::Oid,
) -> *mut pg_sys::Expr {
    let coerced = pg_sys::coerce_to_target_type(
        std::ptr::null_mut(), // pstate - only used for error reporting
        expr as *mut pg_sys::Node,
        from_type,
        to_type,
        -1, // typmod
        pg_sys::CoercionContext::COERCION_IMPLICIT,
        pg_sys::CoercionForm::COERCE_IMPLICIT_CAST,
        -1, // location
    );
    if !coerced.is_null() {
        return coerced as *mut pg_sys::Expr;
    }

    // No implicit cast path exists; fall back to an I/O coercion.
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
    const TEXT: pg_sys::Oid = pg_sys::Oid::from_u32(25);
    const BPCHAR: pg_sys::Oid = pg_sys::Oid::from_u32(1042);
    const VARCHAR: pg_sys::Oid = pg_sys::Oid::from_u32(1043);

    // Look up the function
    let func_cstr = std::ffi::CString::new(func_name)?;

    // Build argument type array, coercing string types to text for better matching
    let mut arg_types: Vec<pg_sys::Oid> = Vec::new();
    let mut coerced_args: Vec<*mut pg_sys::Expr> = Vec::new();

    for arg in args {
        let arg_type = pg_sys::exprType(*arg as *const pg_sys::Node);

        // Coerce varchar/bpchar to text for function lookups
        if arg_type == BPCHAR || arg_type == VARCHAR {
            coerced_args.push(coerce_to_type(*arg, arg_type, TEXT));
            arg_types.push(TEXT);
        } else {
            coerced_args.push(*arg);
            arg_types.push(arg_type);
        }
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
        // Debug: show what types we're looking for
        let type_strs: Vec<String> = arg_types.iter().map(|t| t.to_u32().to_string()).collect();
        return Err(format!(
            "Function '{}' not found with arg types [{}]",
            func_name,
            type_strs.join(", ")
        )
        .into());
    }

    // Use coerced_args instead of original args
    let args = &coerced_args;

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
    // The result collation: sorting or grouping on this expression needs it
    // when the function returns a collatable type (e.g. substring -> text).
    func_expr.funccollid = if pg_sys::type_is_collatable(result_type) {
        pg_sys::DEFAULT_COLLATION_OID
    } else {
        pg_sys::InvalidOid
    };

    // Set inputcollid from arguments if any are collatable
    let mut input_coll = pg_sys::InvalidOid;
    for arg in args {
        let arg_coll = pg_sys::exprCollation(*arg as *const pg_sys::Node);
        if arg_coll != pg_sys::InvalidOid {
            input_coll = arg_coll;
            break;
        }
    }
    // If no explicit collation found, check if any arg types are collatable
    if input_coll == pg_sys::InvalidOid {
        for arg_type in &arg_types {
            if pg_sys::type_is_collatable(*arg_type) {
                input_coll = pg_sys::DEFAULT_COLLATION_OID;
                break;
            }
        }
    }
    func_expr.inputcollid = input_coll;

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

pub(crate) unsafe fn create_int4_const(
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

pub(crate) unsafe fn create_text_const(
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

pub(crate) unsafe fn create_bool_const(
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

unsafe fn create_interval_const(
    months: i32,
    days: i32,
    microseconds: i64,
) -> Result<*mut pg_sys::Const, Box<dyn std::error::Error + Send + Sync>> {
    // PostgreSQL interval is stored as (months, days, time in microseconds)
    // Allocate an Interval struct
    let interval_ptr =
        pg_sys::palloc(std::mem::size_of::<pg_sys::Interval>()) as *mut pg_sys::Interval;
    (*interval_ptr).month = months;
    (*interval_ptr).day = days;
    (*interval_ptr).time = microseconds;

    let mut c = pgrx::PgBox::<pg_sys::Const>::alloc0();
    c.xpr.type_ = pg_sys::NodeTag::T_Const;
    c.consttype = pg_sys::INTERVALOID;
    c.consttypmod = -1;
    c.constcollid = pg_sys::InvalidOid;
    c.constlen = std::mem::size_of::<pg_sys::Interval>() as i32;
    c.constbyval = false;
    c.constisnull = false;
    c.constvalue = pg_sys::Datum::from(interval_ptr);
    c.location = -1;
    Ok(c.into_pg())
}

pub(crate) unsafe fn create_numeric_const(
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
