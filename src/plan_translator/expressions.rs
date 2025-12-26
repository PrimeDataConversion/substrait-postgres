use anyhow::Result;
use pgrx::pg_sys;
use std::collections::HashMap;
use substrait::proto::Expression;

use super::constants::get_expression_type_name;
use super::relations::convert_rel_to_plan_tree_with_context;
use super::schema::{ColumnInfo, RelationSchema};

use pgrx::{AnyNumeric, IntoDatum, PgBox};
use std::str::FromStr;
use substrait::proto::{r#type::Kind, Type};

/// Create a CString from a Rust string
pub fn create_cstring(s: &str) -> *mut std::os::raw::c_char {
    std::ffi::CString::new(s).unwrap().into_raw()
}

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
            Kind::Decimal(_d) => {
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

/// Look up the function OID for a given function name and argument types.
/// This function queries pg_proc to find the OID of a function.
pub unsafe fn lookup_function_oid(
    function_name: &str,
    argument_types: &[pg_sys::Oid],
) -> Result<pg_sys::Oid, Box<dyn std::error::Error + Send + Sync>> {
    pgrx::info!(
        "DEBUG: lookup_function_oid called for '{}' with {} args",
        function_name,
        argument_types.len()
    );

    // Use PostgreSQL's built-in function to look up the function OID.
    // This is safer than SearchSysCache4 which requires proper NameData.
    let func_name_c = std::ffi::CString::new(function_name).unwrap();

    // Build a list with a single function name element.
    let name_string = pg_sys::makeString(func_name_c.as_ptr() as *mut i8);
    let name_list = pg_sys::lappend(std::ptr::null_mut(), name_string as *mut std::ffi::c_void);

    pgrx::info!("DEBUG: lookup_function_oid - calling LookupFuncName");

    let func_oid = pg_sys::LookupFuncName(
        name_list,
        argument_types.len() as i32,
        argument_types.as_ptr(),
        true, // missing_ok
    );

    pgrx::info!(
        "DEBUG: lookup_function_oid - LookupFuncName returned OID: {}",
        func_oid.to_u32()
    );

    if func_oid == pg_sys::InvalidOid {
        return Err(format!(
            "Function '{}' with {} arguments not found in pg_proc",
            function_name,
            argument_types.len()
        )
        .into());
    }

    Ok(func_oid)
}

/// Look up the function OID for a given operator OID.
/// This function queries pg_operator to find the OID of the function.
pub unsafe fn get_operator_function_oid(
    operator_oid: pg_sys::Oid,
) -> Result<pg_sys::Oid, Box<dyn std::error::Error + Send + Sync>> {
    let tuple = pg_sys::SearchSysCache1(
        pg_sys::SysCacheIdentifier::OPEROID as i32,
        pg_sys::Datum::from(operator_oid),
    );

    if tuple.is_null() {
        return Err(format!("Operator with OID '{operator_oid}' not found in pg_operator").into());
    }

    let op_form = pg_sys::GETSTRUCT(tuple) as *mut pg_sys::FormData_pg_operator;
    let function_oid = (*op_form).oprcode;

    pg_sys::ReleaseSysCache(tuple);

    if function_oid == pg_sys::InvalidOid || function_oid.to_u32() == 0 {
        return Err(format!(
            "Operator with OID '{operator_oid}' has no underlying function (oprcode is 0)"
        )
        .into());
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
        return Err(format!("Invalid DATEOID: {type_oid}").into());
    }

    let mut const_node = pgrx::PgBox::<pg_sys::Const>::alloc0();
    const_node.xpr.type_ = pg_sys::NodeTag::T_Const;
    const_node.consttype = type_oid;
    const_node.consttypmod = -1;
    const_node.constcollid = pg_sys::DEFAULT_COLLATION_OID;
    const_node.constlen = 4;
    const_node.constvalue = pg_sys::Datum::from(value - PG_DATE_EPOCH_OFFSET);
    const_node.constisnull = false;
    const_node.constbyval = true;

    Ok(const_node.into_pg() as *mut pg_sys::Expr)
}

/// Create a PostgreSQL int4 constant node with proper catalog decoration
/// Following pg_cuckoo's approach of querying PostgreSQL's catalog for accurate type info
pub unsafe fn create_int4_const(
    value: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Use PostgreSQL's own type resolution following pg_cuckoo's plan decoration approach
    let type_oid = pg_sys::INT4OID;

    // Validate that the OID is reasonable (should not be 0 or InvalidOid)
    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
        return Err(format!("Invalid INT4OID: {type_oid}").into());
    }

    // pg_cuckoo lesson: Query PostgreSQL's catalog for accurate type information
    // This ensures our plan nodes "perfectly mimic regular plans"
    let type_tuple = pg_sys::SearchSysCache1(
        pg_sys::SysCacheIdentifier::TYPEOID as i32,
        pg_sys::Datum::from(type_oid),
    );

    if type_tuple.is_null() {
        return Err(format!("Type OID {type_oid} not found in pg_type catalog").into());
    }

    let type_form = pg_sys::GETSTRUCT(type_tuple) as *mut pg_sys::FormData_pg_type;
    let type_len = (*type_form).typlen as i32;
    let type_by_val = (*type_form).typbyval;

    // Release the cache tuple
    pg_sys::ReleaseSysCache(type_tuple);

    let mut const_node = pgrx::PgBox::<pg_sys::Const>::alloc0();

    // Debug: Check what T_Const actually evaluates to
    let t_const_value = pg_sys::NodeTag::T_Const as u32;

    if t_const_value == 124 {
        eprintln!("ERROR: T_Const NodeTag itself is 124! This is wrong - T_Const should not be pg_type OID");
        return Err("T_Const NodeTag has wrong value 124".into());
    }

    const_node.xpr.type_ = pg_sys::NodeTag::T_Const;
    const_node.consttype = type_oid;
    const_node.consttypmod = -1;
    const_node.constcollid = pg_sys::DEFAULT_COLLATION_OID;
    // Use catalog-derived type information instead of hardcoded values
    const_node.constlen = type_len;
    const_node.constvalue = pg_sys::Datum::from(value);
    const_node.constisnull = false;
    const_node.constbyval = type_by_val;

    // Debug: Check for NodeTag corruption right after setting it
    if const_node.xpr.type_ as u32 == 124 {
        eprintln!(
            "ERROR: Int4Const node type corrupted to 124 after setting! consttype = {}",
            type_oid.to_u32()
        );
        return Err("Int4Const node type corrupted to pg_type OID (124)".into());
    }

    Ok(const_node.into_pg() as *mut pg_sys::Expr)
}

/// Create a PostgreSQL int8 constant node
pub unsafe fn create_int8_const(
    value: i64,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Use the PostgreSQL built-in constant, but validate it first
    let type_oid = pg_sys::INT8OID;

    // Validate that the OID is reasonable (should not be 0 or InvalidOid)
    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
        return Err(format!("Invalid INT8OID: {type_oid}").into());
    }

    let mut const_node = pgrx::PgBox::<pg_sys::Const>::alloc0();
    const_node.xpr.type_ = pg_sys::NodeTag::T_Const;
    const_node.consttype = type_oid;
    const_node.consttypmod = -1;
    const_node.constcollid = pg_sys::DEFAULT_COLLATION_OID;
    const_node.constlen = 8;
    const_node.constvalue = pg_sys::Datum::from(value);
    const_node.constisnull = false;
    const_node.constbyval = true;

    Ok(const_node.into_pg() as *mut pg_sys::Expr)
}

/// Create a PostgreSQL boolean constant node
pub unsafe fn create_bool_const(
    value: bool,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let type_oid = pg_sys::BOOLOID;

    // Validate that the OID is reasonable
    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
        return Err(format!("Invalid BOOLOID: {type_oid}").into());
    }

    let mut const_node = pgrx::PgBox::<pg_sys::Const>::alloc0();
    const_node.xpr.type_ = pg_sys::NodeTag::T_Const;
    const_node.consttype = type_oid;
    const_node.consttypmod = -1;
    const_node.constcollid = pg_sys::DEFAULT_COLLATION_OID;
    const_node.constlen = 1; // Boolean is 1 byte
    const_node.constvalue = pg_sys::Datum::from(value);
    const_node.constisnull = false;
    const_node.constbyval = true;

    Ok(const_node.into_pg() as *mut pg_sys::Expr)
}

/// Create a PostgreSQL text constant node
pub unsafe fn create_text_const(
    value: &str,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!(
        "DEBUG: create_text_const called with value len={}",
        value.len()
    );
    pgrx::info!(
        "DEBUG: create_text_const called with value len={}",
        value.len()
    );

    // Use the PostgreSQL built-in constant, but validate it first
    let type_oid = pg_sys::TEXTOID;

    // Validate that the OID is reasonable (should not be 0 or InvalidOid)
    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
        return Err(format!("Invalid TEXTOID: {type_oid}").into());
    }

    pgrx::info!("DEBUG: About to call cstring_to_text_with_len");
    let text_datum =
        pg_sys::cstring_to_text_with_len(value.as_ptr() as *const i8, value.len() as i32);
    pgrx::info!("DEBUG: cstring_to_text_with_len returned: {:p}", text_datum);

    pgrx::info!("DEBUG: About to alloc Const node");
    let mut const_node = pgrx::PgBox::<pg_sys::Const>::alloc0();
    pgrx::info!("DEBUG: Const node allocated, setting fields");
    const_node.xpr.type_ = pg_sys::NodeTag::T_Const;
    const_node.consttype = type_oid;
    const_node.consttypmod = -1;
    const_node.constcollid = pg_sys::DEFAULT_COLLATION_OID;
    const_node.constlen = -1;
    const_node.constvalue = pg_sys::Datum::from(text_datum as *mut std::ffi::c_void);
    const_node.constisnull = false;
    const_node.constbyval = false;

    pgrx::info!("DEBUG: Const node created successfully");
    Ok(const_node.into_pg() as *mut pg_sys::Expr)
}

/// Create a PostgreSQL numeric constant node
pub unsafe fn create_numeric_const(
    value_bytes: &[u8],
    _precision: i32,
    scale: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // TODO: Start using precision here too.
    let type_oid = pg_sys::NUMERICOID;

    if type_oid == pg_sys::InvalidOid || type_oid == 0.into() {
        return Err(format!("Invalid NUMERICOID: {type_oid}").into());
    }

    // Convert the two's complement byte array to a BigInt
    // The bytes are typically in big-endian order.
    let big_int = num_bigint::BigInt::from_signed_bytes_be(value_bytes);

    // Format the BigInt into a string, applying the scale
    let mut numeric_string = big_int.to_string();

    // Apply scaling
    if scale > 0 {
        let len = numeric_string.len() as i32;
        if len <= scale {
            // Pad with leading zeros if necessary, e.g., 123, scale 5 -> 0.00123
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
    let mut const_node = pgrx::PgBox::<pg_sys::Const>::alloc0();
    const_node.xpr.type_ = pg_sys::NodeTag::T_Const;
    const_node.consttype = type_oid;
    const_node.consttypmod = -1; // Let PostgreSQL determine typmod from value
    const_node.constcollid = pg_sys::DEFAULT_COLLATION_OID;
    const_node.constlen = -1; // Variable length
    const_node.constvalue = numeric_value.into_datum().unwrap();
    const_node.constisnull = false;
    const_node.constbyval = false; // Numeric is not pass-by-value

    Ok(const_node.into_pg() as *mut pg_sys::Expr)
}

/// Resolve actual column type information from table OID and attribute number
pub unsafe fn resolve_column_type_info(
    table_oid: pg_sys::Oid,
    attnum: pg_sys::AttrNumber,
) -> Result<(pg_sys::Oid, i32, pg_sys::Oid), Box<dyn std::error::Error + Send + Sync>> {
    // Open the relation to get schema information
    let relation = pg_sys::relation_open(table_oid, pg_sys::AccessShareLock as i32);
    if relation.is_null() {
        return Err(format!("Could not open relation with OID {table_oid}").into());
    }

    let tuple_desc = (*relation).rd_att;

    // Validate attribute number
    if attnum <= 0 || (attnum as i32) > (*tuple_desc).natts {
        pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);
        return Err(format!("Invalid attribute number {attnum} for relation {table_oid}").into());
    }

    // Get the attribute (1-based indexing, so subtract 1)
    let attr = (*tuple_desc).attrs.as_ptr().offset((attnum - 1) as isize);

    if (*attr).attisdropped {
        pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);
        return Err(format!("Attribute {attnum} is dropped").into());
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
    let mut var_node = pgrx::PgBox::<pg_sys::Var>::alloc0();
    var_node.xpr.type_ = pg_sys::NodeTag::T_Var;
    var_node.varno = 1; // Single table reference for now
    var_node.varattno = attr_number as pg_sys::AttrNumber;
    var_node.vartype = pg_sys::TEXTOID; // Use TEXT as default, will be resolved during planning
    var_node.vartypmod = -1;
    var_node.varcollid = pg_sys::DEFAULT_COLLATION_OID;
    var_node.varlevelsup = 0;

    // Debug: Check for corruption right after creation
    if var_node.xpr.type_ as u32 == 124 {
        eprintln!(
            "ERROR: Var node corruption detected at creation! type_ = 124, vartype = {}",
            var_node.vartype.to_u32()
        );
        return Err("Var node type corrupted to pg_type OID (124)".into());
    }

    Ok(var_node.into_pg() as *mut pg_sys::Expr)
}

/// Create a PostgreSQL Var node with proper type resolution from table schema
pub unsafe fn create_var_node_with_table_schema(
    attr_number: i32,
    table_oid: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let mut var_node = pgrx::PgBox::<pg_sys::Var>::alloc0();
    var_node.xpr.type_ = pg_sys::NodeTag::T_Var;
    var_node.varno = 1;
    var_node.varattno = attr_number as pg_sys::AttrNumber;

    // Resolve actual column type instead of hardcoding
    let (vartype, vartypmod, varcollid) =
        resolve_column_type_info(table_oid, attr_number as pg_sys::AttrNumber)?;
    var_node.vartype = vartype;
    var_node.vartypmod = vartypmod;
    var_node.varcollid = varcollid;
    var_node.varlevelsup = 0;

    Ok(var_node.into_pg() as *mut pg_sys::Expr)
}

/// Create a PostgreSQL Var node with proper type information
pub unsafe fn create_var_node_with_type(
    attr_number: i32,
    vartype: pg_sys::Oid,
    vartypmod: i32,
    varcollid: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let mut var_node = pgrx::PgBox::<pg_sys::Var>::alloc0();
    var_node.xpr.type_ = pg_sys::NodeTag::T_Var;
    var_node.varno = 1; // Single table reference for now
    var_node.varattno = attr_number as pg_sys::AttrNumber;
    var_node.vartype = vartype; // Use actual column type
    var_node.vartypmod = vartypmod;
    var_node.varcollid = varcollid;
    var_node.varlevelsup = 0;

    Ok(var_node.into_pg() as *mut pg_sys::Expr)
}

/// Create a PostgreSQL type cast expression
pub unsafe fn create_cast_expr(
    arg: *mut pg_sys::Expr,
    target_type_oid: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let source_type_oid = pg_sys::exprType(arg as *const pg_sys::Node);
    eprintln!(
        "DEBUG: create_cast_expr called - source OID: {}, target OID: {}",
        source_type_oid.to_u32(),
        target_type_oid.to_u32()
    );
    pgrx::info!(
        "DEBUG: create_cast_expr called - source OID: {}, target OID: {}",
        source_type_oid.to_u32(),
        target_type_oid.to_u32()
    );

    // If source and target types are the same, just return the argument.
    if source_type_oid == target_type_oid {
        eprintln!("DEBUG: create_cast_expr - same type, returning arg as-is");
        pgrx::info!("DEBUG: create_cast_expr - same type, returning arg as-is");
        return Ok(arg);
    }

    eprintln!("DEBUG: create_cast_expr - about to call coerce_type");
    pgrx::info!("DEBUG: create_cast_expr - about to call coerce_type");

    // Use coerce_type with COERCE_EXPLICIT_CAST format (not CoercionPathType!).
    let cast_expr = pg_sys::coerce_type(
        std::ptr::null_mut(),                       // ParseState *pstate
        arg as *mut pg_sys::Node,                   // Node *node
        source_type_oid,                            // Oid inputTypeId
        target_type_oid,                            // Oid targetTypeId
        -1,                                         // int32 targetTypeMod
        pg_sys::CoercionContext::COERCION_EXPLICIT, // CoercionContext ccontext
        pg_sys::CoercionForm::COERCE_EXPLICIT_CAST, // CoercionForm cformat
        -1,                                         // int location
    );

    eprintln!(
        "DEBUG: create_cast_expr - coerce_type returned: {:p}",
        cast_expr
    );
    pgrx::info!(
        "DEBUG: create_cast_expr - coerce_type returned: {:p}",
        cast_expr
    );

    if cast_expr.is_null() {
        return Err(format!(
            "Failed to coerce type from OID {} to OID {}",
            source_type_oid.to_u32(),
            target_type_oid.to_u32()
        )
        .into());
    }

    Ok(cast_expr as *mut pg_sys::Expr)
}

/// Get the PostgreSQL type OID from an expression node.
unsafe fn get_expr_type_oid(
    expr: *mut pg_sys::Expr,
) -> Result<pg_sys::Oid, Box<dyn std::error::Error + Send + Sync>> {
    if expr.is_null() {
        return Err("Expression is null".into());
    }
    let oid = pg_sys::exprType(expr as *const pg_sys::Node);
    eprintln!("DEBUG: get_expr_type_oid returning OID: {}", oid.to_u32());
    Ok(oid)
}

/// Create a PostgreSQL binary operation expression
pub unsafe fn create_binary_op_expr(
    left_arg: *mut pg_sys::Expr,
    right_arg: *mut pg_sys::Expr,
    operator_oid: pg_sys::Oid,
    result_type: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let op_expr = PgBox::<pg_sys::OpExpr>::alloc0();
    let op_expr = op_expr.into_pg();
    (*op_expr).xpr.type_ = pg_sys::NodeTag::T_OpExpr;
    (*op_expr).opno = operator_oid;
    // Look up the function OID for this operator
    (*op_expr).opfuncid = get_operator_function_oid(operator_oid)?;
    (*op_expr).opresulttype = result_type;
    (*op_expr).opretset = false;
    (*op_expr).opcollid = pg_sys::DEFAULT_COLLATION_OID;
    (*op_expr).inputcollid = pg_sys::DEFAULT_COLLATION_OID;

    eprintln!(
        "DEBUG: create_binary_op_expr - op_expr type: {:?}, opno: {}, opfuncid: {}, opresulttype: {}",
        (*op_expr).xpr.type_,
        (*op_expr).opno.to_u32(),
        (*op_expr).opfuncid.to_u32(),
        (*op_expr).opresulttype.to_u32()
    );

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

/// Create a PostgreSQL function call expression
pub unsafe fn create_function_call_expr(
    function_oid: pg_sys::Oid,
    result_type: pg_sys::Oid,
    arguments: &[*mut pg_sys::Expr],
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let func_expr = PgBox::<pg_sys::FuncExpr>::alloc0();
    let func_expr = func_expr.into_pg();
    (*func_expr).xpr.type_ = pg_sys::NodeTag::T_FuncExpr;
    (*func_expr).funcid = function_oid;
    (*func_expr).funcresulttype = result_type;
    (*func_expr).funcretset = false;
    (*func_expr).funcformat = pg_sys::CoercionForm::COERCE_EXPLICIT_CALL;
    (*func_expr).funccollid = pg_sys::DEFAULT_COLLATION_OID;
    (*func_expr).inputcollid = pg_sys::DEFAULT_COLLATION_OID;

    eprintln!(
        "DEBUG: create_function_call_expr - func_expr type: {:?}, funcid: {}, funcresulttype: {}",
        (*func_expr).xpr.type_,
        (*func_expr).funcid.to_u32(),
        (*func_expr).funcresulttype.to_u32()
    );

    let mut args_list: *mut pg_sys::List = std::ptr::null_mut();
    for arg in arguments {
        args_list = pg_sys::lappend(args_list, *arg as *mut std::ffi::c_void);
    }
    (*func_expr).args = args_list;

    Ok(func_expr as *mut pg_sys::Expr)
}

/// Convert selection expression to PostgreSQL
pub unsafe fn convert_selection_to_postgres(
    selection: &substrait::proto::expression::FieldReference,
    current_table_oid: Option<pg_sys::Oid>,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ref_type) = &selection.reference_type {
        match ref_type {
            substrait::proto::expression::field_reference::ReferenceType::DirectReference(
                direct_ref,
            ) => {
                if let Some(struct_field) = &direct_ref.reference_type {
                    match struct_field {
                        substrait::proto::expression::reference_segment::ReferenceType::StructField(field) => {
                            if let Some(table_oid) = current_table_oid {
                                create_var_node_with_table_schema(field.field + 1, table_oid) // 1-based indexing
                            } else {
                                create_var_node(field.field + 1) // 1-based indexing
                            }
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
    current_table_oid: Option<pg_sys::Oid>,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::RexType;

    // Identify the rex_type without printing the full expression
    let rex_type_name = match &expr.rex_type {
        Some(substrait::proto::expression::RexType::Literal(_)) => "Literal",
        Some(substrait::proto::expression::RexType::Selection(_)) => "Selection",
        Some(substrait::proto::expression::RexType::ScalarFunction(_)) => "ScalarFunction",
        Some(substrait::proto::expression::RexType::Cast(_)) => "Cast",
        Some(substrait::proto::expression::RexType::Subquery(_)) => "Subquery",
        Some(_) => "Other",
        None => "None",
    };
    eprintln!(
        "DEBUG: convert_expression_to_postgres_with_context called, rex_type={rex_type_name}"
    );
    pgrx::info!(
        "DEBUG: convert_expression_to_postgres_with_context called, rex_type={}",
        rex_type_name
    );

    match &expr.rex_type {
        Some(RexType::Literal(literal)) => {
            // Handle literal values
            if let Some(literal_type) = &literal.literal_type {
                let type_name = match literal_type {
                    substrait::proto::expression::literal::LiteralType::I32(_) => "I32",
                    substrait::proto::expression::literal::LiteralType::I64(_) => "I64",
                    substrait::proto::expression::literal::LiteralType::String(_) => "String",
                    substrait::proto::expression::literal::LiteralType::Date(_) => "Date",
                    substrait::proto::expression::literal::LiteralType::FixedChar(_) => "FixedChar",
                    substrait::proto::expression::literal::LiteralType::Decimal(_) => "Decimal",
                    _ => "Other",
                };
                eprintln!("DEBUG: Literal type: {type_name}");
                pgrx::info!("DEBUG: Literal type: {}", type_name);
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
                    substrait::proto::expression::literal::LiteralType::Decimal(d) => {
                        create_numeric_const(&d.value, d.precision, d.scale)
                    }
                    _ => Err("Unsupported literal type in filter condition".into()),
                }
            } else {
                Err("Literal expression missing literal type".into())
            }
        }
        Some(RexType::Selection(selection)) => {
            convert_selection_to_postgres(selection, current_table_oid)
        }
        Some(RexType::ScalarFunction(func)) => {
            // Handle scalar functions (e.g., comparison operators)
            create_scalar_function_expr_with_context(func, function_map, current_table_oid)
        }
        Some(RexType::Cast(cast)) => {
            // Handle type casts
            let input_expr = if let Some(input) = &cast.input {
                convert_expression_to_postgres_with_context(input, function_map, current_table_oid)?
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
            create_subquery_expr(subquery, function_map).map(|node| node as *mut pg_sys::Expr)
        }
        Some(rex_type) => {
            let type_name = get_expression_type_name(rex_type);
            Err(format!("Unsupported expression type in filter condition: {type_name}").into())
        }
        None => Err("Expression missing rex_type".into()),
    }
}

/// Create a PostgreSQL subquery expression from Substrait subquery
pub unsafe fn create_subquery_expr(
    subquery: &substrait::proto::expression::Subquery,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::subquery::SubqueryType;

    match &subquery.subquery_type {
        Some(SubqueryType::Scalar(scalar_subquery)) => {
            // The scalar_subquery should contain the inner relation
            create_scalar_subquery_expr(scalar_subquery, function_map)
        }
        Some(SubqueryType::InPredicate(in_predicate)) => {
            create_in_predicate_expr(in_predicate, function_map)
        }
        Some(SubqueryType::SetPredicate(set_predicate)) => {
            // Handle EXISTS/UNIQUE subqueries
            create_set_predicate_expr(set_predicate, function_map)
        }
        Some(SubqueryType::SetComparison(_)) => {
            Err("Set comparison subqueries not yet supported".into())
        }
        None => Err("Subquery missing subquery_type".into()),
    }
}

/// Create a PostgreSQL scalar subquery expression
unsafe fn create_scalar_subquery_expr(
    scalar_subquery: &substrait::proto::expression::subquery::Scalar,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    // scalar_subquery contains the input relation of the scalar subquery
    if scalar_subquery.input.is_none() {
        return Err("Scalar subquery missing input relation".into());
    }

    if let Some(rel) = &scalar_subquery.input {
        let sublink = PgBox::<pg_sys::SubLink>::alloc0();
        let sublink = sublink.into_pg();
        (*sublink).xpr.type_ = pg_sys::NodeTag::T_SubLink;
        (*sublink).subLinkType = pg_sys::SubLinkType::EXPR_SUBLINK;
        (*sublink).subLinkId = 0;
        (*sublink).testexpr = std::ptr::null_mut();
        (*sublink).operName = std::ptr::null_mut();

        let (plan_tree, range_table, _schema) =
            convert_rel_to_plan_tree_with_context(rel, function_map, None)?;
        let query_node = PgBox::<pg_sys::Query>::alloc0();
        let query_node = query_node.into_pg();
        (*query_node).type_ = pg_sys::NodeTag::T_Query;
        (*query_node).commandType = pg_sys::CmdType::CMD_SELECT;
        (*query_node).querySource = pg_sys::QuerySource::QSRC_PARSER;
        (*query_node).canSetTag = true;
        (*query_node).rtable = range_table;
        let from_expr = PgBox::<pg_sys::FromExpr>::alloc0();
        (*query_node).jointree = from_expr.into_pg();
        (*(*query_node).jointree).fromlist = range_table;
        (*(*query_node).jointree).quals = std::ptr::null_mut();
        (*query_node).targetList = (*plan_tree).targetlist;

        (*sublink).subselect = query_node as *mut pg_sys::Node;

        Ok(sublink as *mut pg_sys::Node)
    } else {
        Err("Scalar subquery missing input relation".into())
    }
}

/// Create a PostgreSQL IN predicate expression
unsafe fn create_in_predicate_expr(
    in_predicate: &substrait::proto::expression::subquery::InPredicate,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("DEBUG: create_in_predicate_expr called");

    if in_predicate.haystack.is_none() {
        return Err("IN predicate missing haystack relation".into());
    }

    if in_predicate.needles.is_empty() {
        return Err("IN predicate missing needles expression".into());
    }

    let sublink = PgBox::<pg_sys::SubLink>::alloc0();
    let sublink = sublink.into_pg();
    (*sublink).xpr.type_ = pg_sys::NodeTag::T_SubLink;
    (*sublink).subLinkType = pg_sys::SubLinkType::ANY_SUBLINK; // Use ANY_SUBLINK for IN predicates
    (*sublink).subLinkId = 0;
    (*sublink).operName = std::ptr::null_mut();

    // Translate the haystack (subquery relation)
    let haystack_rel = in_predicate.haystack.as_ref().unwrap();
    let (plan_tree, range_table, _schema) =
        convert_rel_to_plan_tree_with_context(haystack_rel, function_map, None)?;

    let query_node = PgBox::<pg_sys::Query>::alloc0();
    let query_node = query_node.into_pg();
    (*query_node).type_ = pg_sys::NodeTag::T_Query;
    (*query_node).commandType = pg_sys::CmdType::CMD_SELECT;
    (*query_node).querySource = pg_sys::QuerySource::QSRC_PARSER;
    (*query_node).canSetTag = true;
    (*query_node).rtable = range_table; // Use the rtable from the translated plan_tree
    let from_expr = PgBox::<pg_sys::FromExpr>::alloc0();
    (*query_node).jointree = from_expr.into_pg();
    (*(*query_node).jointree).fromlist = range_table; // Use the rtable from the translated plan_tree
    (*(*query_node).jointree).quals = std::ptr::null_mut();
    (*query_node).targetList = (*plan_tree).targetlist;

    (*sublink).subselect = query_node as *mut pg_sys::Node;

    // Translate the needles (expressions to check against the subquery result)
    let pg_needles = convert_expressions_to_target_list_with_context(
        &in_predicate.needles,
        function_map,
        None, // No current_table_oid for needles in IN predicate
    )?;
    (*sublink).testexpr = pg_needles as *mut pg_sys::Node;

    Ok(sublink as *mut pg_sys::Node)
}

/// Create a PostgreSQL EXISTS/UNIQUE subquery expression from Substrait SetPredicate
unsafe fn create_set_predicate_expr(
    set_predicate: &substrait::proto::expression::subquery::SetPredicate,
    _function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::subquery::set_predicate::PredicateOp;

    let sublink = PgBox::<pg_sys::SubLink>::alloc0();
    let sublink = sublink.into_pg();
    (*sublink).xpr.type_ = pg_sys::NodeTag::T_SubLink;
    (*sublink).subLinkId = 0;
    (*sublink).testexpr = std::ptr::null_mut();
    (*sublink).operName = std::ptr::null_mut();

    // Determine the sublink type based on the predicate operation
    match PredicateOp::try_from(set_predicate.predicate_op) {
        Ok(PredicateOp::Exists) => {
            (*sublink).subLinkType = pg_sys::SubLinkType::EXISTS_SUBLINK;
        }
        Ok(PredicateOp::Unique) => {
            (*sublink).subLinkType = pg_sys::SubLinkType::ROWCOMPARE_SUBLINK;
        }
        _ => return Err("Unsupported set predicate operation".into()),
    }

    // Get the subquery relation
    let _tuples_relation = set_predicate
        .tuples
        .as_ref()
        .ok_or("SetPredicate missing tuples relation")?;

    // Create a placeholder Query node for the subselect
    let query = PgBox::<pg_sys::Query>::alloc0();
    let query = query.into_pg();
    (*query).type_ = pg_sys::NodeTag::T_Query;
    (*query).commandType = pg_sys::CmdType::CMD_SELECT;
    (*query).querySource = pg_sys::QuerySource::QSRC_PARSER;
    (*query).canSetTag = true;
    (*query).rtable = std::ptr::null_mut();
    let from_expr = PgBox::<pg_sys::FromExpr>::alloc0();
    (*query).jointree = from_expr.into_pg();
    (*(*query).jointree).fromlist = std::ptr::null_mut();
    (*(*query).jointree).quals = std::ptr::null_mut();
    (*query).targetList = std::ptr::null_mut();

    (*sublink).subselect = query as *mut pg_sys::Node;

    Ok(sublink as *mut pg_sys::Node)
}

/// Convert expressions to target list with function context
pub unsafe fn convert_expressions_to_target_list_with_context(
    expressions: &[Expression],
    function_map: &HashMap<u32, String>,
    current_table_oid: Option<pg_sys::Oid>,
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();

    for (i, expr) in expressions.iter().enumerate() {
        let target_entry = convert_expression_to_target_entry_with_context(
            expr,
            i,
            function_map,
            current_table_oid,
        )?;
        target_list = pg_sys::lappend(target_list, target_entry as *mut std::ffi::c_void);
    }

    Ok(target_list)
}

/// Convert expression to target entry with function context
unsafe fn convert_expression_to_target_entry_with_context(
    expr: &Expression,
    index: usize,
    function_map: &HashMap<u32, String>,
    current_table_oid: Option<pg_sys::Oid>,
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
                            format!("Unsupported literal type for expression {index}").into()
                        )
                    }
                };

                // Create TargetEntry
                let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
                target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
                target_entry.expr = const_expr;
                target_entry.resno = (index + 1) as pg_sys::AttrNumber;
                target_entry.resname = create_cstring(&format!("column_{}", index + 1));
                target_entry.resjunk = false;
                let target_entry = target_entry.into_pg();

                // Debug: Validate that TargetEntry and its expression have correct NodeTags
                if (*target_entry).xpr.type_ as u32 == 124 {
                    eprintln!("ERROR: TargetEntry NodeTag corrupted to 124 after creation!");
                    return Err("TargetEntry NodeTag corrupted to pg_type OID (124)".into());
                }

                if !const_expr.is_null() {
                    let expr_node = const_expr as *const pg_sys::Node;
                    if (*expr_node).type_ as u32 == 124 {
                        eprintln!("ERROR: Const expression NodeTag corrupted to 124 after assignment to TargetEntry!");
                        return Err(
                            "Const expression NodeTag corrupted to pg_type OID (124)".into()
                        );
                    }
                }

                Ok(target_entry)
            } else {
                Err(format!("Literal expression {index} missing literal type").into())
            }
        }
        Some(RexType::ScalarFunction(func)) => {
            // Handle scalar function expressions
            let func_expr =
                create_scalar_function_expr_with_context(func, function_map, current_table_oid)?;

            // Create TargetEntry
            let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            target_entry.expr = func_expr;
            target_entry.resno = (index + 1) as pg_sys::AttrNumber;
            target_entry.resname = create_cstring(&format!("column_{}", index + 1));
            target_entry.resjunk = false;
            let target_entry = target_entry.into_pg();

            // Debug: Validate NodeTags after creation
            if (*target_entry).xpr.type_ as u32 == 124 {
                eprintln!("ERROR: ScalarFunction TargetEntry NodeTag corrupted to 124!");
                return Err(
                    "ScalarFunction TargetEntry NodeTag corrupted to pg_type OID (124)".into(),
                );
            }

            if !func_expr.is_null() {
                let expr_node = func_expr as *const pg_sys::Node;
                if (*expr_node).type_ as u32 == 124 {
                    eprintln!("ERROR: ScalarFunction expression NodeTag corrupted to 124!");
                    return Err(
                        "ScalarFunction expression NodeTag corrupted to pg_type OID (124)".into(),
                    );
                }
            }

            Ok(target_entry)
        }
        Some(RexType::Selection(selection)) => {
            // Handle column references
            let selection_expr = convert_selection_to_postgres(selection, current_table_oid)?;

            // Create TargetEntry
            let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            target_entry.expr = selection_expr;
            target_entry.resno = (index + 1) as pg_sys::AttrNumber;
            target_entry.resname = create_cstring(&format!("column_{}", index + 1));
            target_entry.resjunk = false;
            let target_entry = target_entry.into_pg();

            Ok(target_entry)
        }
        _ => Err(format!("Unsupported expression type at index {index}").into()),
    }
}

/// Extract PostgreSQL expressions from Substrait function arguments.
unsafe fn extract_function_arguments(
    func_arguments: &[substrait::proto::FunctionArgument],
    function_map: &HashMap<u32, String>,
    current_table_oid: Option<pg_sys::Oid>,
) -> Result<Vec<*mut pg_sys::Expr>, Box<dyn std::error::Error + Send + Sync>> {
    let mut pg_args = Vec::with_capacity(func_arguments.len());
    for arg in func_arguments {
        if let Some(value) = &arg.arg_type {
            match value {
                substrait::proto::function_argument::ArgType::Value(expr) => {
                    let pg_expr = convert_expression_to_postgres_with_context(
                        expr,
                        function_map,
                        current_table_oid,
                    )?;
                    pg_args.push(pg_expr);
                }
                _ => {
                    return Err("Unsupported argument type in function".into());
                }
            }
        } else {
            return Err("Missing argument type in function".into());
        }
    }
    Ok(pg_args)
}

/// Create scalar function expression with function context
pub unsafe fn create_scalar_function_expr_with_context(
    func: &substrait::proto::expression::ScalarFunction,
    function_map: &HashMap<u32, String>,
    current_table_oid: Option<pg_sys::Oid>,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let function_reference = func.function_reference;
    let argument_count = func.arguments.len();

    // Look up function name from extension map
    let function_name = function_map
        .get(&function_reference)
        .map(|s| s.as_str())
        .unwrap_or("unknown");

    eprintln!("DEBUG: Scalar function details:");
    eprintln!("  function_reference: {function_reference}");
    eprintln!("  function_name: {function_name}");
    eprintln!("  arguments.len(): {argument_count}");
    pgrx::info!(
        "DEBUG: Scalar function: ref={}, name={}, args={}",
        function_reference,
        function_name,
        argument_count
    );

    // Handle specific function types based on name
    match function_name {
        "lte:date_date" => {
            pgrx::info!("DEBUG: Processing lte:date_date function");
            if func.arguments.len() == 2 {
                pgrx::info!("DEBUG: About to extract 2 arguments for lte:date_date");
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                pgrx::info!("DEBUG: Arguments extracted successfully, creating function call");
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                // Create a binary operation expression for date less-than-equal
                let func_oid = lookup_function_oid("date_le", &[pg_sys::DATEOID, pg_sys::DATEOID])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("lte:date_date function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "and:bool" => {
            // Handle variadic logical AND function using PostgreSQL's BoolExpr
            if func.arguments.len() >= 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;

                // Create a BoolExpr node for variadic AND
                let bool_expr = pgrx::PgBox::<pg_sys::BoolExpr>::alloc0();
                let bool_expr = bool_expr.into_pg();
                (*bool_expr).xpr.type_ = pg_sys::NodeTag::T_BoolExpr;
                (*bool_expr).boolop = pg_sys::BoolExprType::AND_EXPR;

                let mut args_list: *mut pg_sys::List = std::ptr::null_mut();
                for arg in pg_args {
                    args_list = pg_sys::lappend(args_list, arg as *mut std::ffi::c_void);
                }
                (*bool_expr).args = args_list;

                Ok(bool_expr as *mut pg_sys::Expr)
            } else {
                Err(
                    format!("and:bool function expects at least 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "equal:any_any" => {
            // Handle equality comparison function
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("eq", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("equal:any_any function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "multiply:fp64_fp64" => {
            // Handle floating point multiplication.
            // Use FLOAT8OID explicitly since Substrait guarantees fp64 types.
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let func_oid =
                    lookup_function_oid("float8mul", &[pg_sys::FLOAT8OID, pg_sys::FLOAT8OID])?;
                create_function_call_expr(func_oid, pg_sys::FLOAT8OID, &[left_arg, right_arg])
            } else {
                Err(format!(
                    "multiply:fp64_fp64 function expects 2 arguments, got {argument_count}"
                )
                .into())
            }
        }
        "subtract:fp64_fp64" => {
            // Handle floating point subtraction.
            // Use FLOAT8OID explicitly since Substrait guarantees fp64 types.
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let func_oid =
                    lookup_function_oid("float8mi", &[pg_sys::FLOAT8OID, pg_sys::FLOAT8OID])?;
                create_function_call_expr(func_oid, pg_sys::FLOAT8OID, &[left_arg, right_arg])
            } else {
                Err(format!(
                    "subtract:fp64_fp64 function expects 2 arguments, got {argument_count}"
                )
                .into())
            }
        }
        "add:fp64_fp64" => {
            // Handle floating point addition.
            // Use FLOAT8OID explicitly since Substrait guarantees fp64 types.
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let func_oid =
                    lookup_function_oid("float8pl", &[pg_sys::FLOAT8OID, pg_sys::FLOAT8OID])?;
                create_function_call_expr(func_oid, pg_sys::FLOAT8OID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("add:fp64_fp64 function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "like:str_str" => {
            // Handle string LIKE pattern matching function
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("text_like", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("like:str_str function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "or:bool" => {
            // Handle variadic logical OR function using PostgreSQL's BoolExpr
            if func.arguments.len() >= 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;

                // Create a BoolExpr node for variadic OR
                let bool_expr = pgrx::PgBox::<pg_sys::BoolExpr>::alloc0();
                let bool_expr = bool_expr.into_pg();
                (*bool_expr).xpr.type_ = pg_sys::NodeTag::T_BoolExpr;
                (*bool_expr).boolop = pg_sys::BoolExprType::OR_EXPR;

                let mut args_list: *mut pg_sys::List = std::ptr::null_mut();
                for arg in pg_args {
                    args_list = pg_sys::lappend(args_list, arg as *mut std::ffi::c_void);
                }
                (*bool_expr).args = args_list;

                Ok(bool_expr as *mut pg_sys::Expr)
            } else {
                Err(
                    format!("or:bool function expects at least 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "lt:any_any" => {
            // Handle less-than comparison function
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("lt", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(format!("lt:any_any function expects 2 arguments, got {argument_count}").into())
            }
        }
        "gte:date_date" => {
            // Handle greater-than-or-equal comparison for dates
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let func_oid = lookup_function_oid("date_ge", &[pg_sys::DATEOID, pg_sys::DATEOID])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("gte:date_date function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "lt:date_date" => {
            // Handle less-than comparison for dates
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let func_oid = lookup_function_oid("date_lt", &[pg_sys::DATEOID, pg_sys::DATEOID])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("lt:date_date function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "not_equal:any_any" => {
            // Handle not-equal comparison function
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("ne", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("not_equal:any_any function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "like:vchar_vchar" => {
            // Handle string LIKE pattern matching function for varchar types
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("text_like", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("like:vchar_vchar function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "multiply:dec_dec" => {
            // Handle decimal multiplication
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("numeric_mul", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::NUMERICOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("multiply:dec_dec function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "subtract:dec_dec" => {
            // Handle decimal subtraction
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("numeric_sub", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::NUMERICOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("subtract:dec_dec function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "divide:dec_dec" => {
            // Handle decimal division
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("numeric_div", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::NUMERICOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("divide:dec_dec function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "gt:any_any" => {
            // Handle greater-than comparison function
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("gt", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(format!("gt:any_any function expects 2 arguments, got {argument_count}").into())
            }
        }
        "add:date_year" => {
            // Handle date + year interval function
            // This typically comes from expressions like date '1994-08-01' + interval '1' month
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("date_pl_interval", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::DATEOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("add:date_year function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "gte:any_any" => {
            // Handle greater-than-or-equal comparison function
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("ge", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("gte:any_any function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "lte:any_any" => {
            // Handle less-than-or-equal comparison function
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("le", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("lte:any_any function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "add:i32_i32" => {
            // Handle integer addition
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;
                let func_oid = lookup_function_oid("int4pl", &[left_type, right_type])?;
                create_function_call_expr(func_oid, pg_sys::INT4OID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("add:i32_i32 function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "char_substr" => {
            // Handle char_substr function
            if func.arguments.len() == 3 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let string_expr = pg_args[0];
                let start_expr = pg_args[1];
                let count_expr = pg_args[2];

                let string_type = get_expr_type_oid(string_expr)?;
                let start_type = get_expr_type_oid(start_expr)?;
                let count_type = get_expr_type_oid(count_expr)?;

                eprintln!(
                    "DEBUG: char_substr - string_type: {}, start_type: {}, count_type: {}",
                    string_type.to_u32(),
                    start_type.to_u32(),
                    count_type.to_u32()
                );

                let func_oid =
                    lookup_function_oid("char_substr", &[string_type, start_type, count_type])?;
                create_function_call_expr(
                    func_oid,
                    pg_sys::TEXTOID, // Assuming char_substr returns TEXTOID
                    &[string_expr, start_expr, count_expr],
                )
            } else {
                Err(
                    format!("char_substr function expects 3 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "substring:str_i32_i32" => {
            // Handle string substring function
            if func.arguments.len() == 3 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let string_expr = pg_args[0];
                let start_expr = pg_args[1];
                let length_expr = pg_args[2];

                let string_type = get_expr_type_oid(string_expr)?;
                let start_type = get_expr_type_oid(start_expr)?;
                let length_type = get_expr_type_oid(length_expr)?;

                // Dynamically look up the function OID for 'substring'
                let func_oid =
                    lookup_function_oid("substring", &[string_type, start_type, length_type])?;
                create_function_call_expr(
                    func_oid,
                    pg_sys::TEXTOID,
                    &[string_expr, start_expr, length_expr],
                )
            } else {
                Err(format!(
                    "substring:str_i32_i32 function expects 3 arguments, got {argument_count}"
                )
                .into())
            }
        }
        "not:bool" => {
            // Handle logical NOT function
            if func.arguments.len() == 1 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let arg = pg_args[0];

                // Create a BoolExpr node for NOT
                let bool_expr = pgrx::PgBox::<pg_sys::BoolExpr>::alloc0();
                let bool_expr = bool_expr.into_pg();
                (*bool_expr).xpr.type_ = pg_sys::NodeTag::T_BoolExpr;
                (*bool_expr).boolop = pg_sys::BoolExprType::NOT_EXPR;

                // Create args list with single argument
                let mut args_list: *mut pg_sys::List = std::ptr::null_mut();
                args_list = pg_sys::lappend(args_list, arg as *mut std::ffi::c_void);
                (*bool_expr).args = args_list;

                Ok(bool_expr as *mut pg_sys::Expr)
            } else {
                Err(format!("not:bool function expects 1 argument, got {argument_count}").into())
            }
        }
        "gt:date_date" => {
            // Handle date greater-than comparison function
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let func_oid = lookup_function_oid("date_gt", &[pg_sys::DATEOID, pg_sys::DATEOID])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("gt:date_date function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "divide:fp64_fp64" => {
            // Handle floating point division.
            // Use FLOAT8OID explicitly since Substrait guarantees fp64 types.
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let func_oid =
                    lookup_function_oid("float8div", &[pg_sys::FLOAT8OID, pg_sys::FLOAT8OID])?;
                create_function_call_expr(func_oid, pg_sys::FLOAT8OID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("divide:fp64_fp64 function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "extract:req_date" => {
            // Handle extract function (e.g., extract year from date)
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let part_arg = pg_args[0];
                let source_arg = pg_args[1];

                let part_type = get_expr_type_oid(part_arg)?;
                let source_type = get_expr_type_oid(source_arg)?;

                let func_oid = lookup_function_oid("date_part", &[part_type, source_type])?;
                create_function_call_expr(
                    func_oid,
                    pg_sys::FLOAT8OID, // extract returns float8
                    &[part_arg, source_arg],
                )
            } else {
                Err(
                    format!("extract:req_date function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        _ => Err(format!(
            "Unsupported scalar function: {function_name} with {argument_count} arguments"
        )
        .into()),
    }
}

/// Convert expressions to target list with schema-based type resolution
/// Returns both the target list and the output schema for the projection
pub unsafe fn convert_expressions_to_target_list_with_schema(
    expressions: &[Expression],
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
) -> Result<(*mut pg_sys::List, RelationSchema), Box<dyn std::error::Error + Send + Sync>> {
    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();
    let mut output_columns = Vec::new();

    for (i, expr) in expressions.iter().enumerate() {
        let (target_entry, column_info) =
            convert_expression_to_target_entry_with_schema(expr, i, function_map, input_schema)?;
        target_list = pg_sys::lappend(target_list, target_entry as *mut std::ffi::c_void);
        output_columns.push(column_info);
    }

    let output_schema = RelationSchema::with_columns(output_columns);
    Ok((target_list, output_schema))
}

/// Convert expression to target entry with schema-based type resolution
unsafe fn convert_expression_to_target_entry_with_schema(
    expr: &Expression,
    index: usize,
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
) -> Result<(*mut pg_sys::TargetEntry, ColumnInfo), Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::RexType;

    match &expr.rex_type {
        Some(RexType::Selection(selection)) => {
            // Handle column references with proper schema-based type resolution
            let selection_expr =
                convert_selection_to_postgres_with_schema(selection, input_schema)?;

            // Extract type information from the resolved column
            let column_info = extract_column_info_from_selection(selection, input_schema)?;

            // Create TargetEntry
            let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            target_entry.expr = selection_expr;
            target_entry.resno = (index + 1) as pg_sys::AttrNumber;
            target_entry.resname = create_cstring(&format!("column_{}", index + 1));
            target_entry.resjunk = false;
            let target_entry = target_entry.into_pg();

            Ok((target_entry, column_info))
        }
        Some(RexType::Literal(literal)) => {
            // Handle literal values
            if let Some(literal_type) = &literal.literal_type {
                let (const_expr, type_oid) = match literal_type {
                    substrait::proto::expression::literal::LiteralType::I32(val) => {
                        (create_int4_const(*val)?, pg_sys::INT4OID)
                    }
                    substrait::proto::expression::literal::LiteralType::I64(val) => {
                        (create_int8_const(*val)?, pg_sys::INT8OID)
                    }
                    substrait::proto::expression::literal::LiteralType::String(val) => {
                        (create_text_const(val)?, pg_sys::TEXTOID)
                    }
                    substrait::proto::expression::literal::LiteralType::Date(val) => {
                        (create_date_const(*val)?, pg_sys::DATEOID)
                    }
                    _ => {
                        return Err(
                            format!("Unsupported literal type for expression {index}").into()
                        )
                    }
                };

                let column_info = ColumnInfo::with_type(type_oid);

                // Create TargetEntry
                let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
                target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
                target_entry.expr = const_expr;
                target_entry.resno = (index + 1) as pg_sys::AttrNumber;
                target_entry.resname = create_cstring(&format!("column_{}", index + 1));
                target_entry.resjunk = false;
                let target_entry = target_entry.into_pg();

                Ok((target_entry, column_info))
            } else {
                Err(format!("Literal expression {index} missing literal type").into())
            }
        }
        _ => {
            // For other expression types, fall back to the existing context-based approach
            // TODO: Implement schema-based resolution for scalar functions, casts, etc.
            let target_entry = convert_expression_to_target_entry_with_context(
                expr,
                index,
                function_map,
                None, // No table OID since we're using schema
            )?;

            // Create a placeholder column info with TEXT type for now
            let column_info = ColumnInfo::with_type(pg_sys::TEXTOID);

            Ok((target_entry, column_info))
        }
    }
}

/// Convert selection expression to PostgreSQL with schema-based type resolution
pub unsafe fn convert_selection_to_postgres_with_schema(
    selection: &substrait::proto::expression::FieldReference,
    input_schema: &RelationSchema,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ref_type) = &selection.reference_type {
        match ref_type {
            substrait::proto::expression::field_reference::ReferenceType::DirectReference(
                direct_ref,
            ) => {
                if let Some(struct_field) = &direct_ref.reference_type {
                    match struct_field {
                        substrait::proto::expression::reference_segment::ReferenceType::StructField(field) => {
                            let field_index = field.field as usize;

                            // Look up column information from the input schema
                            if let Some(column_info) = input_schema.get_column(field_index) {
                                eprintln!(
                                    "DEBUG: Schema-based Selection field {} resolves to type OID {}",
                                    field_index, column_info.type_oid
                                );

                                create_var_node_with_type(
                                    field.field + 1, // 1-based indexing
                                    column_info.type_oid,
                                    column_info.typmod,
                                    column_info.collid,
                                )
                            } else {
                                Err(format!(
                                    "Field index {} out of bounds for schema with {} columns",
                                    field_index, input_schema.column_count()
                                ).into())
                            }
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

/// Extract column information from a selection expression using schema
fn extract_column_info_from_selection(
    selection: &substrait::proto::expression::FieldReference,
    input_schema: &RelationSchema,
) -> Result<ColumnInfo, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ref_type) = &selection.reference_type {
        match ref_type {
            substrait::proto::expression::field_reference::ReferenceType::DirectReference(
                direct_ref,
            ) => {
                if let Some(struct_field) = &direct_ref.reference_type {
                    match struct_field {
                        substrait::proto::expression::reference_segment::ReferenceType::StructField(field) => {
                            let field_index = field.field as usize;

                            // Look up column information from the input schema
                            if let Some(column_info) = input_schema.get_column(field_index) {
                                Ok(column_info.clone())
                            } else {
                                Err(format!(
                                    "Field index {} out of bounds for schema with {} columns",
                                    field_index, input_schema.column_count()
                                ).into())
                            }
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
