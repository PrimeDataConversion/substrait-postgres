use anyhow::Result;
use pgrx::pg_sys;
use std::collections::HashMap;
use substrait::proto::Expression;

use super::constants::get_expression_type_name;
use super::relations::{convert_rel_to_plan_tree_with_context, ConversionContext};
use super::schema::{ColumnInfo, RelationSchema};

use pgrx::{AnyNumeric, IntoDatum, PgBox};
use std::cell::RefCell;
use std::str::FromStr;
use substrait::proto::{r#type::Kind, Type};

/// Thread-local storage for subplan collection during conversion.
/// This allows nested expression conversion functions to register subplans
/// without threading the ConversionContext through all function signatures.
thread_local! {
    static SUBPLAN_COLLECTOR: RefCell<Option<SubplanCollector>> = const { RefCell::new(None) };
}

/// Collector for subplans during expression conversion.
pub struct SubplanCollector {
    pub function_map: HashMap<u32, String>,
    pub current_table_oid: Option<pg_sys::Oid>,
    subplans: Vec<SubplanEntry>,
    next_plan_id: i32,
    /// Counter for assigning unique scanrelids across main plan and subplans.
    next_scanrelid: u32,
    /// Stack of outer query schemas for resolving outer references in correlated subqueries.
    outer_schemas: Vec<RelationSchema>,
    /// Parameters collected during subquery conversion for outer references.
    param_entries: Vec<ParamEntry>,
    /// Counter for assigning unique parameter IDs.
    next_param_id: i32,
    /// The schema of the current query context, to be pushed when entering a subquery.
    current_outer_schema: Option<RelationSchema>,
}

/// Entry for a collected subplan.
pub struct SubplanEntry {
    pub plan: *mut pg_sys::Plan,
    pub range_table: *mut pg_sys::List,
}

/// Entry for a parameter used in correlated subquery (outer reference).
#[derive(Clone)]
pub struct ParamEntry {
    pub param_id: i32,
    pub field_index: usize,
    pub type_oid: pg_sys::Oid,
    pub typmod: i32,
    pub collid: pg_sys::Oid,
}

impl SubplanCollector {
    pub fn new(function_map: HashMap<u32, String>, current_table_oid: Option<pg_sys::Oid>) -> Self {
        Self {
            function_map,
            current_table_oid,
            subplans: Vec::new(),
            next_plan_id: 1,
            next_scanrelid: 1, // Start at 1 (PostgreSQL scanrelids are 1-based)
            outer_schemas: Vec::new(),
            param_entries: Vec::new(),
            next_param_id: 0, // Start at 0 (PostgreSQL param IDs are 0-based)
            current_outer_schema: None,
        }
    }

    /// Create a collector with a specific starting scanrelid.
    /// Use this when the main plan has already consumed some scanrelids.
    pub fn with_start_scanrelid(
        function_map: HashMap<u32, String>,
        current_table_oid: Option<pg_sys::Oid>,
        start_scanrelid: u32,
    ) -> Self {
        Self {
            function_map,
            current_table_oid,
            subplans: Vec::new(),
            next_plan_id: 1,
            next_scanrelid: start_scanrelid,
            outer_schemas: Vec::new(),
            param_entries: Vec::new(),
            next_param_id: 0,
            current_outer_schema: None,
        }
    }

    /// Set the current outer schema (called before converting expressions that may contain subqueries).
    pub fn set_current_outer_schema(&mut self, schema: Option<RelationSchema>) {
        self.current_outer_schema = schema;
    }

    /// Get the current outer schema to push when entering a subquery.
    pub fn get_current_outer_schema(&self) -> Option<&RelationSchema> {
        self.current_outer_schema.as_ref()
    }

    pub fn register_subplan(
        &mut self,
        plan: *mut pg_sys::Plan,
        range_table: *mut pg_sys::List,
    ) -> i32 {
        let id = self.next_plan_id;
        self.next_plan_id += 1;
        self.subplans.push(SubplanEntry { plan, range_table });
        id
    }

    /// Get the current next_scanrelid value for subplan conversion.
    pub fn get_next_scanrelid(&self) -> u32 {
        self.next_scanrelid
    }

    /// Update the next_scanrelid counter after subplan conversion.
    pub fn set_next_scanrelid(&mut self, value: u32) {
        self.next_scanrelid = value;
    }

    /// Push an outer schema onto the stack (when entering a subquery).
    pub fn push_outer_schema(&mut self, schema: RelationSchema) {
        self.outer_schemas.push(schema);
    }

    /// Pop an outer schema from the stack (when leaving a subquery).
    pub fn pop_outer_schema(&mut self) -> Option<RelationSchema> {
        self.outer_schemas.pop()
    }

    /// Get the outer schema at the specified level (1 = immediate outer, 2 = two levels up, etc).
    pub fn get_outer_schema(&self, steps_out: u32) -> Option<&RelationSchema> {
        if steps_out == 0 || steps_out as usize > self.outer_schemas.len() {
            return None;
        }
        // steps_out=1 means the most recent outer schema (last in the vec)
        let index = self.outer_schemas.len() - steps_out as usize;
        Some(&self.outer_schemas[index])
    }

    /// Register a parameter for an outer reference and return the param ID.
    pub fn register_outer_param(
        &mut self,
        field_index: usize,
        type_oid: pg_sys::Oid,
        typmod: i32,
        collid: pg_sys::Oid,
    ) -> i32 {
        let param_id = self.next_param_id;
        self.next_param_id += 1;
        self.param_entries.push(ParamEntry {
            param_id,
            field_index,
            type_oid,
            typmod,
            collid,
        });
        param_id
    }

    /// Take the collected parameters (clears the list).
    pub fn take_param_entries(&mut self) -> Vec<ParamEntry> {
        std::mem::take(&mut self.param_entries)
    }

    /// Get the current param entries without clearing.
    pub fn get_param_entries(&self) -> &[ParamEntry] {
        &self.param_entries
    }

    pub fn take_subplans(self) -> Vec<SubplanEntry> {
        self.subplans
    }
}

/// Set up the subplan collector for use during conversion.
/// Returns the previous collector (if any) for restoration.
pub fn set_subplan_collector(collector: SubplanCollector) -> Option<SubplanCollector> {
    SUBPLAN_COLLECTOR.with(|c| c.borrow_mut().replace(collector))
}

/// Take the subplan collector, returning ownership to the caller.
pub fn take_subplan_collector() -> Option<SubplanCollector> {
    SUBPLAN_COLLECTOR.with(|c| c.borrow_mut().take())
}

/// Register a subplan with the current collector, if one is active.
/// Returns the plan_id if registered, or None if no collector is active.
fn register_subplan_if_active(
    plan: *mut pg_sys::Plan,
    range_table: *mut pg_sys::List,
) -> Option<i32> {
    SUBPLAN_COLLECTOR.with(|c| {
        c.borrow_mut()
            .as_mut()
            .map(|collector| collector.register_subplan(plan, range_table))
    })
}

/// Check if a subplan collector is active.
fn has_active_collector() -> bool {
    SUBPLAN_COLLECTOR.with(|c| c.borrow().is_some())
}

/// Get a reference to the function map from the active collector.
fn get_collector_function_map() -> Option<HashMap<u32, String>> {
    SUBPLAN_COLLECTOR.with(|c| c.borrow().as_ref().map(|col| col.function_map.clone()))
}

/// Get the current table OID from the active collector.
fn get_collector_table_oid() -> Option<pg_sys::Oid> {
    SUBPLAN_COLLECTOR.with(|c| c.borrow().as_ref().and_then(|col| col.current_table_oid))
}

/// Get the current next_scanrelid value from the active collector.
fn get_collector_next_scanrelid() -> Option<u32> {
    SUBPLAN_COLLECTOR.with(|c| c.borrow().as_ref().map(|col| col.get_next_scanrelid()))
}

/// Update the next_scanrelid value in the active collector.
pub fn set_collector_next_scanrelid(value: u32) {
    SUBPLAN_COLLECTOR.with(|c| {
        if let Some(collector) = c.borrow_mut().as_mut() {
            collector.set_next_scanrelid(value);
        }
    })
}

/// Push an outer schema onto the collector's stack (when entering a subquery).
pub fn push_outer_schema(schema: RelationSchema) {
    SUBPLAN_COLLECTOR.with(|c| {
        if let Some(collector) = c.borrow_mut().as_mut() {
            collector.push_outer_schema(schema);
        }
    })
}

/// Pop an outer schema from the collector's stack (when leaving a subquery).
pub fn pop_outer_schema() -> Option<RelationSchema> {
    SUBPLAN_COLLECTOR.with(|c| {
        c.borrow_mut()
            .as_mut()
            .and_then(|collector| collector.pop_outer_schema())
    })
}

/// Get the outer schema at the specified level from the collector.
fn get_outer_schema(steps_out: u32) -> Option<RelationSchema> {
    SUBPLAN_COLLECTOR.with(|c| {
        c.borrow()
            .as_ref()
            .and_then(|collector| collector.get_outer_schema(steps_out).cloned())
    })
}

/// Register a parameter for an outer reference in the collector.
fn register_outer_param(
    field_index: usize,
    type_oid: pg_sys::Oid,
    typmod: i32,
    collid: pg_sys::Oid,
) -> Option<i32> {
    SUBPLAN_COLLECTOR.with(|c| {
        c.borrow_mut()
            .as_mut()
            .map(|collector| collector.register_outer_param(field_index, type_oid, typmod, collid))
    })
}

/// Take the collected parameters from the collector.
pub fn take_param_entries() -> Vec<ParamEntry> {
    SUBPLAN_COLLECTOR.with(|c| {
        c.borrow_mut()
            .as_mut()
            .map(|collector| collector.take_param_entries())
            .unwrap_or_default()
    })
}

/// Set the current outer schema in the collector.
/// This should be called before converting expressions that may contain subqueries.
pub fn set_current_outer_schema(schema: Option<RelationSchema>) {
    SUBPLAN_COLLECTOR.with(|c| {
        if let Some(collector) = c.borrow_mut().as_mut() {
            collector.set_current_outer_schema(schema);
        }
    })
}

/// Get the current outer schema from the collector (cloned).
fn get_current_outer_schema() -> Option<RelationSchema> {
    SUBPLAN_COLLECTOR.with(|c| {
        c.borrow()
            .as_ref()
            .and_then(|collector| collector.get_current_outer_schema().cloned())
    })
}

/// Get the depth of the outer schema stack.
fn get_outer_schema_stack_depth() -> usize {
    SUBPLAN_COLLECTOR.with(|c| {
        c.borrow()
            .as_ref()
            .map(|collector| collector.outer_schemas.len())
            .unwrap_or(0)
    })
}

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

/// Get the comparison function name for a given type and operation.
/// PostgreSQL uses type-specific function names like int4eq, texteq, etc.
fn get_comparison_func_name(type_oid: pg_sys::Oid, operation: &str) -> String {
    let type_prefix = match type_oid {
        pg_sys::INT2OID => "int2",
        pg_sys::INT4OID => "int4",
        pg_sys::INT8OID => "int8",
        pg_sys::FLOAT4OID => "float4",
        pg_sys::FLOAT8OID => "float8",
        pg_sys::NUMERICOID => "numeric_",
        pg_sys::TEXTOID => "text",
        pg_sys::VARCHAROID => "text", // VARCHAR uses text functions
        pg_sys::BPCHAROID => "bpchar",
        pg_sys::DATEOID => "date_",
        pg_sys::TIMESTAMPOID => "timestamp_",
        pg_sys::TIMESTAMPTZOID => "timestamptz_",
        pg_sys::BOOLOID => "bool",
        pg_sys::OIDOID => "oid",
        _ => "text", // Fallback to text comparison
    };

    // Map operation to PostgreSQL function suffix
    let suffix = match operation {
        "eq" => "eq",
        "ne" => "ne",
        "lt" => "lt",
        "gt" => "gt",
        "le" => "le",
        "ge" => "ge",
        _ => "eq", // Default to equality
    };

    // Handle special cases where there's no underscore
    if type_prefix.ends_with('_') {
        format!("{}{}", type_prefix, suffix)
    } else {
        format!("{}{}", type_prefix, suffix)
    }
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
    const_node.constcollid = pg_sys::InvalidOid; // DATE is not collatable
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
    const_node.constcollid = pg_sys::InvalidOid; // INT4 is not collatable
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
    const_node.constcollid = pg_sys::InvalidOid; // INT8 is not collatable
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
    const_node.constcollid = pg_sys::InvalidOid; // BOOL is not collatable
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

    // Convert the two's complement byte array to a BigInt.
    // Substrait spec: decimal values are little-endian two's complement.
    let big_int = num_bigint::BigInt::from_signed_bytes_le(value_bytes);

    eprintln!(
        "DEBUG: create_numeric_const - bytes={:?}, scale={}, big_int={}",
        value_bytes, scale, big_int
    );
    pgrx::info!(
        "DEBUG: create_numeric_const - big_int={}, scale={}",
        big_int.to_string(),
        scale
    );

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

    eprintln!(
        "DEBUG: create_numeric_const - final numeric_string={}",
        numeric_string
    );
    pgrx::info!(
        "DEBUG: create_numeric_const - final numeric_string={}",
        numeric_string
    );

    let numeric_value: AnyNumeric = AnyNumeric::from_str(&numeric_string)
        .map_err(|e| format!("Failed to parse numeric value from string: {e}"))?;
    let mut const_node = pgrx::PgBox::<pg_sys::Const>::alloc0();
    const_node.xpr.type_ = pg_sys::NodeTag::T_Const;
    const_node.consttype = type_oid;
    const_node.consttypmod = -1; // Let PostgreSQL determine typmod from value
    const_node.constcollid = pg_sys::InvalidOid; // NUMERIC is not collatable
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
/// NOTE: This creates a Var with TEXTOID - use create_var_node_with_type for proper typing
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
    // These fields are required for proper plan execution in PG17
    var_node.varnosyn = 1;
    var_node.varattnosyn = attr_number as pg_sys::AttrNumber;
    var_node.location = -1;

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
    // These fields are required for proper plan execution in PG17
    var_node.varnosyn = 1;
    var_node.varattnosyn = attr_number as pg_sys::AttrNumber;
    var_node.location = -1;

    Ok(var_node.into_pg() as *mut pg_sys::Expr)
}

/// OUTER_VAR constant: references the outer (left) child plan's output in join nodes.
/// In PostgreSQL, OUTER_VAR is -2.
pub const OUTER_VAR: i32 = -2;

/// INNER_VAR constant: references the inner (right) child plan's output in join nodes.
/// In PostgreSQL, INNER_VAR is -1.
pub const INNER_VAR: i32 = -1;

/// Create a PostgreSQL Var node with proper type information
pub unsafe fn create_var_node_with_type(
    attr_number: i32,
    vartype: pg_sys::Oid,
    vartypmod: i32,
    varcollid: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    create_var_node_with_varno(attr_number, vartype, vartypmod, varcollid, 1)
}

/// Create a PostgreSQL Var node that references output from a child plan.
/// Use this for Vars in non-scan nodes (Result, Sort, etc.) that reference child output.
pub unsafe fn create_var_node_for_child_output(
    attr_number: i32,
    vartype: pg_sys::Oid,
    vartypmod: i32,
    varcollid: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    create_var_node_with_varno(attr_number, vartype, vartypmod, varcollid, OUTER_VAR)
}

/// Create a PostgreSQL Var node with specified varno.
pub unsafe fn create_var_node_with_varno(
    attr_number: i32,
    vartype: pg_sys::Oid,
    vartypmod: i32,
    varcollid: pg_sys::Oid,
    varno: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let mut var_node = pgrx::PgBox::<pg_sys::Var>::alloc0();
    var_node.xpr.type_ = pg_sys::NodeTag::T_Var;
    var_node.varno = varno;
    var_node.varattno = attr_number as pg_sys::AttrNumber;
    var_node.vartype = vartype;
    var_node.vartypmod = vartypmod;
    var_node.varcollid = varcollid;
    var_node.varlevelsup = 0;
    // For planner-generated Vars (OUTER_VAR, INNER_VAR, etc.), varnosyn/varattnosyn
    // should be 0 since they don't correspond to simple relation columns.
    // For base table references (varno >= 1), preserve the original values.
    if varno >= 1 {
        var_node.varnosyn = varno as u32;
        var_node.varattnosyn = attr_number as pg_sys::AttrNumber;
    } else {
        var_node.varnosyn = 0;
        var_node.varattnosyn = 0;
    }
    var_node.location = -1;

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

/// Coerce an argument to a target type if needed.
/// Returns the original argument if it already has the target type, or a cast expression otherwise.
unsafe fn coerce_arg_to_type(
    arg: *mut pg_sys::Expr,
    target_type: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let arg_type = pg_sys::exprType(arg as *const pg_sys::Node);
    if arg_type == target_type {
        Ok(arg)
    } else {
        create_cast_expr(arg, target_type)
    }
}

/// Create a PostgreSQL CaseExpr from a Substrait IfThen expression.
/// This implements CASE WHEN ... THEN ... ELSE ... END.
unsafe fn create_case_expr_with_varno(
    if_then: &substrait::proto::expression::IfThen,
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
    varno: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Build the list of CaseWhen nodes.
    let mut case_when_list: *mut pg_sys::List = std::ptr::null_mut();
    let mut result_type: Option<pg_sys::Oid> = None;

    for if_clause in &if_then.ifs {
        // Convert the IF condition.
        let condition = if_clause
            .r#if
            .as_ref()
            .ok_or("IfThen clause missing 'if' condition")?;
        let condition_expr = convert_expression_to_postgres_with_varno(
            condition,
            function_map,
            input_schema,
            varno,
        )?;

        // Convert the THEN result.
        let then_result = if_clause
            .then
            .as_ref()
            .ok_or("IfThen clause missing 'then' result")?;
        let then_expr = convert_expression_to_postgres_with_varno(
            then_result,
            function_map,
            input_schema,
            varno,
        )?;

        // Track the result type from the first THEN clause.
        if result_type.is_none() {
            result_type = Some(pg_sys::exprType(then_expr as *const pg_sys::Node));
        }

        // Create CaseWhen node.
        let mut case_when = pgrx::PgBox::<pg_sys::CaseWhen>::alloc0();
        case_when.xpr.type_ = pg_sys::NodeTag::T_CaseWhen;
        case_when.expr = condition_expr;
        case_when.result = then_expr;
        let case_when = case_when.into_pg();

        case_when_list = pg_sys::lappend(case_when_list, case_when as *mut std::ffi::c_void);
    }

    // Convert the ELSE clause if present.
    let default_result = if let Some(else_expr) = &if_then.r#else {
        convert_expression_to_postgres_with_varno(else_expr, function_map, input_schema, varno)?
    } else {
        // If no ELSE clause, the default result is NULL.
        std::ptr::null_mut()
    };

    // Determine the result type.
    let case_type = result_type.unwrap_or(pg_sys::INT4OID);

    // Create the CaseExpr node.
    let mut case_expr = pgrx::PgBox::<pg_sys::CaseExpr>::alloc0();
    case_expr.xpr.type_ = pg_sys::NodeTag::T_CaseExpr;
    case_expr.casetype = case_type;
    case_expr.casecollid = pg_sys::InvalidOid; // Will be set by PostgreSQL if needed.
    case_expr.arg = std::ptr::null_mut(); // NULL for searched CASE (CASE WHEN ...).
    case_expr.args = case_when_list;
    case_expr.defresult = default_result;
    case_expr.location = -1;

    Ok(case_expr.into_pg() as *mut pg_sys::Expr)
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

/// Check if a type OID represents a collatable type
unsafe fn is_type_collatable(type_oid: pg_sys::Oid) -> bool {
    // Use PostgreSQL's type_is_collatable function
    pg_sys::type_is_collatable(type_oid)
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

    // Set collation based on whether the result type is collatable
    if is_type_collatable(result_type) {
        (*func_expr).funccollid = pg_sys::DEFAULT_COLLATION_OID;
        // For input collation, check if any argument is collatable
        let mut input_collid = pg_sys::InvalidOid;
        for arg in arguments {
            if !(*arg).is_null() {
                let arg_type = pg_sys::exprType(*arg as *const pg_sys::Node);
                if is_type_collatable(arg_type) {
                    input_collid = pg_sys::DEFAULT_COLLATION_OID;
                    break;
                }
            }
        }
        (*func_expr).inputcollid = input_collid;
    } else {
        (*func_expr).funccollid = pg_sys::InvalidOid;
        (*func_expr).inputcollid = pg_sys::InvalidOid;
    }

    eprintln!(
        "DEBUG: create_function_call_expr - funcid: {}, resulttype: {}, funccollid: {}, inputcollid: {}",
        (*func_expr).funcid.to_u32(),
        (*func_expr).funcresulttype.to_u32(),
        (*func_expr).funccollid.to_u32(),
        (*func_expr).inputcollid.to_u32()
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
    // Check if this is an outer reference (correlated subquery reference).
    if let Some(root_type) = &selection.root_type {
        use substrait::proto::expression::field_reference::RootType;
        if let RootType::OuterReference(outer_ref) = root_type {
            let steps_out = outer_ref.steps_out;
            eprintln!(
                "DEBUG: OuterReference detected with steps_out={} (non-schema path)",
                steps_out
            );

            // Get the field index from the direct reference.
            let field_index = if let Some(ref_type) = &selection.reference_type {
                if let substrait::proto::expression::field_reference::ReferenceType::DirectReference(direct_ref) = ref_type {
                    if let Some(struct_field) = &direct_ref.reference_type {
                        if let substrait::proto::expression::reference_segment::ReferenceType::StructField(field) = struct_field {
                            field.field as usize
                        } else {
                            return Err("OuterReference with unsupported reference type".into());
                        }
                    } else {
                        return Err("OuterReference missing struct field".into());
                    }
                } else {
                    return Err("OuterReference with non-direct reference".into());
                }
            } else {
                return Err("OuterReference missing reference_type".into());
            };

            // Get the outer schema at the specified level.
            let outer_schema = get_outer_schema(steps_out).ok_or_else(|| {
                format!(
                    "No outer schema available at steps_out={} (are we in a subquery?)",
                    steps_out
                )
            })?;

            // Look up the column info from the outer schema.
            let column_info = outer_schema.get_column(field_index).ok_or_else(|| {
                format!(
                    "Field index {} out of bounds for outer schema with {} columns",
                    field_index,
                    outer_schema.column_count()
                )
            })?;

            // Register the parameter with the collector.
            let param_id = register_outer_param(
                field_index,
                column_info.type_oid,
                column_info.typmod,
                column_info.collid,
            )
            .ok_or("No active subplan collector for outer reference")?;

            // Create a Param node (PARAM_EXEC type).
            return create_param_node(
                param_id,
                column_info.type_oid,
                column_info.typmod,
                column_info.collid,
            );
        }
    }

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
            // Handle subquery expressions - creates SubLink (parse-time structure)
            // For proper execution, use convert_expression_to_postgres_with_ctx which creates SubPlan
            create_subquery_expr(subquery, function_map).map(|node| node as *mut pg_sys::Expr)
        }
        Some(rex_type) => {
            let type_name = get_expression_type_name(rex_type);
            Err(format!("Unsupported expression type in filter condition: {type_name}").into())
        }
        None => Err("Expression missing rex_type".into()),
    }
}

/// Convert a Substrait expression to PostgreSQL with full ConversionContext.
/// This version creates SubPlan nodes for subqueries instead of SubLink,
/// which are required for execution.
pub unsafe fn convert_expression_to_postgres_with_ctx(
    expr: &Expression,
    ctx: &ConversionContext,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::RexType;

    match &expr.rex_type {
        Some(RexType::Literal(literal)) => {
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
                    substrait::proto::expression::literal::LiteralType::Decimal(d) => {
                        create_numeric_const(&d.value, d.precision, d.scale)
                    }
                    _ => Err("Unsupported literal type in expression".into()),
                }
            } else {
                Err("Literal expression missing literal type".into())
            }
        }
        Some(RexType::Selection(selection)) => {
            convert_selection_to_postgres(selection, ctx.current_table_oid)
        }
        Some(RexType::ScalarFunction(func)) => {
            // Use context-aware scalar function conversion
            create_scalar_function_expr_with_ctx(func, ctx)
        }
        Some(RexType::Cast(cast)) => {
            let input_expr = if let Some(input) = &cast.input {
                convert_expression_to_postgres_with_ctx(input, ctx)?
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
            // Use SubPlan creation with context for proper execution
            create_subquery_expr_with_ctx(subquery, ctx).map(|node| node as *mut pg_sys::Expr)
        }
        Some(rex_type) => {
            let type_name = get_expression_type_name(rex_type);
            Err(format!("Unsupported expression type: {type_name}").into())
        }
        None => Err("Expression missing rex_type".into()),
    }
}

/// Create scalar function expression with ConversionContext.
/// This calls the existing create_scalar_function_expr_with_context but
/// uses context-aware argument extraction to handle nested subqueries.
unsafe fn create_scalar_function_expr_with_ctx(
    func: &substrait::proto::expression::ScalarFunction,
    ctx: &ConversionContext,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // For now, delegate to the existing function that handles all special cases
    // The arguments will be converted recursively and any subqueries in them
    // will be handled by the next call to convert_expression_to_postgres_with_ctx
    create_scalar_function_expr_with_context(func, ctx.function_map, ctx.current_table_oid)
}

/// Create a PostgreSQL subquery expression from Substrait subquery.
/// If a SubplanCollector is active (thread-local), creates SubPlan for execution.
/// Otherwise, creates SubLink (parse-time structure).
pub unsafe fn create_subquery_expr(
    subquery: &substrait::proto::expression::Subquery,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::subquery::SubqueryType;

    // Check if we have an active collector - if so, create SubPlan for execution
    if has_active_collector() {
        eprintln!("DEBUG: create_subquery_expr - using SubPlan path (collector active)");
        return create_subquery_as_subplan(subquery, function_map);
    }

    // No collector - create SubLink (parse-time structure)
    eprintln!("DEBUG: create_subquery_expr - using SubLink path (no collector)");
    match &subquery.subquery_type {
        Some(SubqueryType::Scalar(scalar_subquery)) => {
            create_scalar_subquery_expr(scalar_subquery, function_map)
        }
        Some(SubqueryType::InPredicate(in_predicate)) => {
            create_in_predicate_expr(in_predicate, function_map)
        }
        Some(SubqueryType::SetPredicate(set_predicate)) => {
            create_set_predicate_expr(set_predicate, function_map)
        }
        Some(SubqueryType::SetComparison(_)) => {
            Err("Set comparison subqueries not yet supported".into())
        }
        None => Err("Subquery missing subquery_type".into()),
    }
}

/// Create a SubPlan for a subquery when a collector is active.
unsafe fn create_subquery_as_subplan(
    subquery: &substrait::proto::expression::Subquery,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::subquery::SubqueryType;

    let current_table_oid = get_collector_table_oid();

    match &subquery.subquery_type {
        Some(SubqueryType::Scalar(scalar_subquery)) => {
            create_scalar_subquery_as_subplan(scalar_subquery, function_map, current_table_oid)
        }
        Some(SubqueryType::InPredicate(in_predicate)) => {
            create_in_predicate_as_subplan(in_predicate, function_map, current_table_oid)
        }
        Some(SubqueryType::SetPredicate(set_predicate)) => {
            create_set_predicate_as_subplan(set_predicate, function_map, current_table_oid)
        }
        Some(SubqueryType::SetComparison(_)) => {
            Err("Set comparison subqueries not yet supported".into())
        }
        None => Err("Subquery missing subquery_type".into()),
    }
}

/// Create SubPlan for scalar subquery.
unsafe fn create_scalar_subquery_as_subplan(
    scalar_subquery: &substrait::proto::expression::subquery::Scalar,
    function_map: &HashMap<u32, String>,
    current_table_oid: Option<pg_sys::Oid>,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    if scalar_subquery.input.is_none() {
        return Err("Scalar subquery missing input relation".into());
    }

    // Push the current outer schema onto the stack before converting the subquery.
    // This schema represents what the subquery can reference via OuterReference.
    if let Some(outer_schema) = get_current_outer_schema() {
        pgrx::info!(
            "DEBUG: Pushing outer schema with {} columns for scalar subquery",
            outer_schema.column_count()
        );
        push_outer_schema(outer_schema);
    }

    // Each subplan uses its own 1-based scanrelid sequence and own range table.
    // Scanrelids are adjusted when merging range tables in executor.
    let rel = scalar_subquery.input.as_ref().unwrap();
    let result = convert_rel_to_plan_tree_with_context(rel, function_map, current_table_oid);

    // Pop the outer schema after subquery conversion (even on error).
    pop_outer_schema();

    let (plan_tree, range_table, schema) = result?;

    // Take the parameter entries that were registered during subquery conversion.
    // These are outer references that need to be passed from the outer query.
    let param_entries = take_param_entries();
    eprintln!(
        "DEBUG: Collected {} parameter entries for scalar subquery",
        param_entries.len()
    );

    let plan_id =
        register_subplan_if_active(plan_tree, range_table).ok_or("No active subplan collector")?;

    let subplan = PgBox::<pg_sys::SubPlan>::alloc0();
    let subplan = subplan.into_pg();
    (*subplan).xpr.type_ = pg_sys::NodeTag::T_SubPlan;
    (*subplan).subLinkType = pg_sys::SubLinkType::EXPR_SUBLINK;
    (*subplan).plan_id = plan_id;

    let plan_name = format!("SubPlan {}", plan_id);
    (*subplan).plan_name = create_cstring(&plan_name);

    if !schema.columns.is_empty() {
        let first_col = &schema.columns[0];
        (*subplan).firstColType = first_col.type_oid;
        (*subplan).firstColTypmod = first_col.typmod;
        (*subplan).firstColCollation = first_col.collid;
        pgrx::info!(
            "DEBUG: SubPlan firstColType={} (from schema with {} columns)",
            first_col.type_oid.to_u32(),
            schema.columns.len()
        );
    } else {
        (*subplan).firstColType = pg_sys::INT4OID;
        (*subplan).firstColTypmod = -1;
        (*subplan).firstColCollation = pg_sys::InvalidOid;
        pgrx::info!("DEBUG: SubPlan firstColType=INT4OID (empty schema fallback)");
    }

    (*subplan).testexpr = std::ptr::null_mut();

    // Build parParam and args lists from collected parameter entries.
    // parParam contains the parameter IDs, args contains expressions that
    // evaluate the outer references (Var nodes referencing the outer query).
    if !param_entries.is_empty() {
        let mut par_param_list: *mut pg_sys::List = std::ptr::null_mut();
        let mut args_list: *mut pg_sys::List = std::ptr::null_mut();

        for entry in &param_entries {
            // Add param_id to parParam list.
            par_param_list = pg_sys::lappend_int(par_param_list, entry.param_id);

            // Create a Var node that references the outer query's column.
            // Use OUTER_VAR (-2) as varno since we're referencing the outer tuple slot.
            let mut var = PgBox::<pg_sys::Var>::alloc0();
            var.xpr.type_ = pg_sys::NodeTag::T_Var;
            var.varno = OUTER_VAR;
            var.varattno = (entry.field_index + 1) as pg_sys::AttrNumber; // 1-based
            var.vartype = entry.type_oid;
            var.vartypmod = entry.typmod;
            var.varcollid = entry.collid;
            var.varlevelsup = 0;
            var.varnosyn = 0;
            var.varattnosyn = 0;
            var.location = -1;
            let var_node = var.into_pg();

            args_list = pg_sys::lappend(args_list, var_node as *mut std::ffi::c_void);

            eprintln!(
                "DEBUG: Added param_id={} to parParam, created Var for field {} as arg",
                entry.param_id, entry.field_index
            );
        }

        (*subplan).parParam = par_param_list;
        (*subplan).args = args_list;

        pgrx::info!(
            "DEBUG: SubPlan has {} parameters (correlated subquery)",
            param_entries.len()
        );
    } else {
        (*subplan).parParam = std::ptr::null_mut();
        (*subplan).args = std::ptr::null_mut();
    }

    (*subplan).setParam = std::ptr::null_mut();
    (*subplan).useHashTable = false;
    (*subplan).unknownEqFalse = false;
    (*subplan).parallel_safe = false;
    (*subplan).startup_cost = 0.0;
    (*subplan).per_call_cost = 10.0;

    Ok(subplan as *mut pg_sys::Node)
}

/// Create SubPlan for IN predicate.
unsafe fn create_in_predicate_as_subplan(
    in_predicate: &substrait::proto::expression::subquery::InPredicate,
    function_map: &HashMap<u32, String>,
    current_table_oid: Option<pg_sys::Oid>,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("DEBUG: create_in_predicate_as_subplan called");

    if in_predicate.haystack.is_none() {
        return Err("IN predicate missing haystack relation".into());
    }

    if in_predicate.needles.is_empty() {
        return Err("IN predicate missing needles expression".into());
    }

    // Each subplan uses its own 1-based scanrelid sequence and own range table.
    // Scanrelids are adjusted when merging range tables in executor.
    let haystack_rel = in_predicate.haystack.as_ref().unwrap();
    let (plan_tree, range_table, schema) =
        convert_rel_to_plan_tree_with_context(haystack_rel, function_map, current_table_oid)?;

    let plan_id =
        register_subplan_if_active(plan_tree, range_table).ok_or("No active subplan collector")?;

    let subplan = PgBox::<pg_sys::SubPlan>::alloc0();
    let subplan = subplan.into_pg();
    (*subplan).xpr.type_ = pg_sys::NodeTag::T_SubPlan;
    // Use EXISTS_SUBLINK for now since ANY_SUBLINK requires complex PARAM_EXEC setup
    // EXISTS checks if subquery returns any rows - semantically different but avoids crash
    // TODO: Implement proper ANY_SUBLINK with PARAM_EXEC for correct IN predicate semantics
    (*subplan).subLinkType = pg_sys::SubLinkType::EXISTS_SUBLINK;
    (*subplan).plan_id = plan_id;

    let plan_name = format!("SubPlan {}", plan_id);
    (*subplan).plan_name = create_cstring(&plan_name);

    // For EXISTS_SUBLINK, firstCol* fields are not used but set them anyway
    if !schema.columns.is_empty() {
        let first_col = &schema.columns[0];
        (*subplan).firstColType = first_col.type_oid;
        (*subplan).firstColTypmod = first_col.typmod;
        (*subplan).firstColCollation = first_col.collid;
    } else {
        (*subplan).firstColType = pg_sys::BOOLOID;
        (*subplan).firstColTypmod = -1;
        (*subplan).firstColCollation = pg_sys::InvalidOid;
    }

    (*subplan).parParam = std::ptr::null_mut();
    (*subplan).setParam = std::ptr::null_mut();
    (*subplan).args = std::ptr::null_mut();
    (*subplan).useHashTable = false;
    (*subplan).unknownEqFalse = false;
    (*subplan).parallel_safe = false;
    (*subplan).startup_cost = 0.0;
    (*subplan).per_call_cost = 10.0;

    // For EXISTS_SUBLINK, testexpr should be NULL
    // EXISTS just checks if subquery returns any rows
    (*subplan).testexpr = std::ptr::null_mut();

    eprintln!(
        "DEBUG: Created SubPlan for IN predicate (as EXISTS) with plan_id={}",
        plan_id
    );
    Ok(subplan as *mut pg_sys::Node)
}

/// Create SubPlan for EXISTS/UNIQUE set predicate.
unsafe fn create_set_predicate_as_subplan(
    set_predicate: &substrait::proto::expression::subquery::SetPredicate,
    function_map: &HashMap<u32, String>,
    current_table_oid: Option<pg_sys::Oid>,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::subquery::set_predicate::PredicateOp;

    let tuples_rel = set_predicate
        .tuples
        .as_ref()
        .ok_or("SetPredicate missing tuples relation")?;

    // Push the current outer schema onto the stack before converting the subquery.
    // This allows the subquery to reference columns from the outer query via OuterReference.
    if let Some(outer_schema) = get_current_outer_schema() {
        pgrx::info!(
            "DEBUG: Pushing outer schema with {} columns for EXISTS subquery",
            outer_schema.column_count()
        );
        push_outer_schema(outer_schema);
    }

    // Each subplan uses its own 1-based scanrelid sequence and own range table.
    // Scanrelids are adjusted when merging range tables in executor.
    let result = convert_rel_to_plan_tree_with_context(tuples_rel, function_map, current_table_oid);

    // Pop the outer schema after subquery conversion (even on error).
    pop_outer_schema();

    let (plan_tree, range_table, schema) = result?;

    let plan_id =
        register_subplan_if_active(plan_tree, range_table).ok_or("No active subplan collector")?;

    let subplan = PgBox::<pg_sys::SubPlan>::alloc0();
    let subplan = subplan.into_pg();
    (*subplan).xpr.type_ = pg_sys::NodeTag::T_SubPlan;
    (*subplan).plan_id = plan_id;

    match PredicateOp::try_from(set_predicate.predicate_op) {
        Ok(PredicateOp::Exists) => {
            (*subplan).subLinkType = pg_sys::SubLinkType::EXISTS_SUBLINK;
        }
        Ok(PredicateOp::Unique) => {
            (*subplan).subLinkType = pg_sys::SubLinkType::ROWCOMPARE_SUBLINK;
        }
        _ => return Err("Unsupported set predicate operation".into()),
    }

    let plan_name = format!("SubPlan {}", plan_id);
    (*subplan).plan_name = create_cstring(&plan_name);

    if !schema.columns.is_empty() {
        let first_col = &schema.columns[0];
        (*subplan).firstColType = first_col.type_oid;
        (*subplan).firstColTypmod = first_col.typmod;
        (*subplan).firstColCollation = first_col.collid;
    } else {
        (*subplan).firstColType = pg_sys::BOOLOID;
        (*subplan).firstColTypmod = -1;
        (*subplan).firstColCollation = pg_sys::InvalidOid;
    }

    (*subplan).testexpr = std::ptr::null_mut();
    (*subplan).parParam = std::ptr::null_mut();
    (*subplan).setParam = std::ptr::null_mut();
    (*subplan).args = std::ptr::null_mut();
    (*subplan).useHashTable = false;
    (*subplan).unknownEqFalse = false;
    (*subplan).parallel_safe = false;
    (*subplan).startup_cost = 0.0;
    (*subplan).per_call_cost = 1.0;

    eprintln!(
        "DEBUG: Created SubPlan for set predicate with plan_id={}",
        plan_id
    );
    Ok(subplan as *mut pg_sys::Node)
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

/// Create a PostgreSQL SubPlan for an IN predicate expression.
/// This creates a SubPlan node suitable for execution, not a SubLink.
pub unsafe fn create_in_predicate_subplan(
    in_predicate: &substrait::proto::expression::subquery::InPredicate,
    ctx: &ConversionContext,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("DEBUG: create_in_predicate_subplan called");

    if in_predicate.haystack.is_none() {
        return Err("IN predicate missing haystack relation".into());
    }

    if in_predicate.needles.is_empty() {
        return Err("IN predicate missing needles expression".into());
    }

    // Translate the haystack (subquery relation)
    let haystack_rel = in_predicate.haystack.as_ref().unwrap();
    let (plan_tree, range_table, schema) = convert_rel_to_plan_tree_with_context(
        haystack_rel,
        ctx.function_map,
        ctx.current_table_oid,
    )?;

    // Register this subplan and get its ID
    let plan_id = ctx.register_subplan(plan_tree, range_table);
    eprintln!("DEBUG: Registered subplan with plan_id={}", plan_id);

    // Create SubPlan node
    let subplan = PgBox::<pg_sys::SubPlan>::alloc0();
    let subplan = subplan.into_pg();
    (*subplan).xpr.type_ = pg_sys::NodeTag::T_SubPlan;
    (*subplan).subLinkType = pg_sys::SubLinkType::ANY_SUBLINK;
    (*subplan).plan_id = plan_id;

    // Create plan name for debugging
    let plan_name = format!("SubPlan {}", plan_id);
    (*subplan).plan_name = create_cstring(&plan_name);

    // Get type info from the first column of the subquery result
    if !schema.columns.is_empty() {
        let first_col = &schema.columns[0];
        (*subplan).firstColType = first_col.type_oid;
        (*subplan).firstColTypmod = first_col.typmod;
        (*subplan).firstColCollation = first_col.collid;
    } else {
        (*subplan).firstColType = pg_sys::INT4OID;
        (*subplan).firstColTypmod = -1;
        (*subplan).firstColCollation = pg_sys::InvalidOid;
    }

    // NOT a correlated subplan for simple IN predicates
    (*subplan).parParam = std::ptr::null_mut();
    (*subplan).setParam = std::ptr::null_mut();
    (*subplan).args = std::ptr::null_mut();

    // Use hash table for ANY_SUBLINK for efficiency
    (*subplan).useHashTable = true;
    (*subplan).unknownEqFalse = true;
    (*subplan).parallel_safe = false;

    // Cost estimates
    (*subplan).startup_cost = 0.0;
    (*subplan).per_call_cost = 10.0;

    // Translate the needles (expressions to check against the subquery result)
    // For IN predicate, the test expression compares needle value against subquery result
    if !in_predicate.needles.is_empty() {
        let needle_expr = &in_predicate.needles[0];
        let pg_needle = convert_expression_to_postgres_with_context(
            needle_expr,
            ctx.function_map,
            ctx.current_table_oid,
        )?;
        (*subplan).testexpr = pg_needle as *mut pg_sys::Node;
    }

    eprintln!(
        "DEBUG: SubPlan created successfully with plan_id={}",
        plan_id
    );
    Ok(subplan as *mut pg_sys::Node)
}

/// Create a PostgreSQL subquery expression using SubPlan when context available.
pub unsafe fn create_subquery_expr_with_ctx(
    subquery: &substrait::proto::expression::Subquery,
    ctx: &ConversionContext,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::subquery::SubqueryType;

    match &subquery.subquery_type {
        Some(SubqueryType::Scalar(scalar_subquery)) => {
            // For scalar subqueries, create a SubPlan with EXPR_SUBLINK
            create_scalar_subquery_subplan(scalar_subquery, ctx)
        }
        Some(SubqueryType::InPredicate(in_predicate)) => {
            create_in_predicate_subplan(in_predicate, ctx)
        }
        Some(SubqueryType::SetPredicate(set_predicate)) => {
            // EXISTS/UNIQUE subqueries
            create_set_predicate_subplan(set_predicate, ctx)
        }
        Some(SubqueryType::SetComparison(_)) => {
            Err("Set comparison subqueries not yet supported".into())
        }
        None => Err("Subquery missing subquery_type".into()),
    }
}

/// Create a SubPlan for scalar subquery
unsafe fn create_scalar_subquery_subplan(
    scalar_subquery: &substrait::proto::expression::subquery::Scalar,
    ctx: &ConversionContext,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    if scalar_subquery.input.is_none() {
        return Err("Scalar subquery missing input relation".into());
    }

    let rel = scalar_subquery.input.as_ref().unwrap();
    let (plan_tree, range_table, schema) =
        convert_rel_to_plan_tree_with_context(rel, ctx.function_map, ctx.current_table_oid)?;

    let plan_id = ctx.register_subplan(plan_tree, range_table);

    let subplan = PgBox::<pg_sys::SubPlan>::alloc0();
    let subplan = subplan.into_pg();
    (*subplan).xpr.type_ = pg_sys::NodeTag::T_SubPlan;
    (*subplan).subLinkType = pg_sys::SubLinkType::EXPR_SUBLINK;
    (*subplan).plan_id = plan_id;

    let plan_name = format!("SubPlan {}", plan_id);
    (*subplan).plan_name = create_cstring(&plan_name);

    if !schema.columns.is_empty() {
        let first_col = &schema.columns[0];
        (*subplan).firstColType = first_col.type_oid;
        (*subplan).firstColTypmod = first_col.typmod;
        (*subplan).firstColCollation = first_col.collid;
    } else {
        (*subplan).firstColType = pg_sys::INT4OID;
        (*subplan).firstColTypmod = -1;
        (*subplan).firstColCollation = pg_sys::InvalidOid;
    }

    (*subplan).testexpr = std::ptr::null_mut();
    (*subplan).parParam = std::ptr::null_mut();
    (*subplan).setParam = std::ptr::null_mut();
    (*subplan).args = std::ptr::null_mut();
    (*subplan).useHashTable = false;
    (*subplan).unknownEqFalse = false;
    (*subplan).parallel_safe = false;
    (*subplan).startup_cost = 0.0;
    (*subplan).per_call_cost = 10.0;

    Ok(subplan as *mut pg_sys::Node)
}

/// Create a SubPlan for EXISTS/UNIQUE set predicate
unsafe fn create_set_predicate_subplan(
    set_predicate: &substrait::proto::expression::subquery::SetPredicate,
    ctx: &ConversionContext,
) -> Result<*mut pg_sys::Node, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::subquery::set_predicate::PredicateOp;

    let tuples_rel = set_predicate
        .tuples
        .as_ref()
        .ok_or("SetPredicate missing tuples relation")?;

    let (plan_tree, range_table, schema) =
        convert_rel_to_plan_tree_with_context(tuples_rel, ctx.function_map, ctx.current_table_oid)?;

    let plan_id = ctx.register_subplan(plan_tree, range_table);

    let subplan = PgBox::<pg_sys::SubPlan>::alloc0();
    let subplan = subplan.into_pg();
    (*subplan).xpr.type_ = pg_sys::NodeTag::T_SubPlan;
    (*subplan).plan_id = plan_id;

    match PredicateOp::try_from(set_predicate.predicate_op) {
        Ok(PredicateOp::Exists) => {
            (*subplan).subLinkType = pg_sys::SubLinkType::EXISTS_SUBLINK;
        }
        Ok(PredicateOp::Unique) => {
            (*subplan).subLinkType = pg_sys::SubLinkType::ROWCOMPARE_SUBLINK;
        }
        _ => return Err("Unsupported set predicate operation".into()),
    }

    let plan_name = format!("SubPlan {}", plan_id);
    (*subplan).plan_name = create_cstring(&plan_name);

    if !schema.columns.is_empty() {
        let first_col = &schema.columns[0];
        (*subplan).firstColType = first_col.type_oid;
        (*subplan).firstColTypmod = first_col.typmod;
        (*subplan).firstColCollation = first_col.collid;
    } else {
        (*subplan).firstColType = pg_sys::BOOLOID;
        (*subplan).firstColTypmod = -1;
        (*subplan).firstColCollation = pg_sys::InvalidOid;
    }

    (*subplan).testexpr = std::ptr::null_mut();
    (*subplan).parParam = std::ptr::null_mut();
    (*subplan).setParam = std::ptr::null_mut();
    (*subplan).args = std::ptr::null_mut();
    (*subplan).useHashTable = false;
    (*subplan).unknownEqFalse = false;
    (*subplan).parallel_safe = false;
    (*subplan).startup_cost = 0.0;
    (*subplan).per_call_cost = 1.0;

    Ok(subplan as *mut pg_sys::Node)
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
            // Handle equality comparison function.
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                // Use get_comparison_func_name to get type-specific function (e.g. int4eq, texteq).
                let func_name = get_comparison_func_name(left_type, "eq");
                let func_oid = lookup_function_oid(&func_name, &[left_type, left_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("equal:any_any function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "multiply:fp64_fp64" => {
            // Handle multiplication with type-appropriate function.
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                // Get actual argument types and use appropriate multiply function.
                let left_type = pg_sys::exprType(left_arg as *const pg_sys::Node);
                let right_type = pg_sys::exprType(right_arg as *const pg_sys::Node);

                pgrx::info!(
                    "DEBUG: multiply:fp64_fp64 - left_type={}, right_type={}",
                    left_type.to_u32(),
                    right_type.to_u32()
                );

                // Use type-appropriate multiply function.
                // For NUMERIC, always use hardcoded NUMERICOID to ensure match.
                let (func_name, result_type, arg1_type, arg2_type) =
                    if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                        (
                            "numeric_mul",
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                        )
                    } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                        (
                            "float8mul",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    } else if left_type == pg_sys::FLOAT4OID || right_type == pg_sys::FLOAT4OID {
                        (
                            "float4mul",
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                        )
                    } else if left_type == pg_sys::INT8OID || right_type == pg_sys::INT8OID {
                        ("int8mul", pg_sys::INT8OID, pg_sys::INT8OID, pg_sys::INT8OID)
                    } else if left_type == pg_sys::INT4OID || right_type == pg_sys::INT4OID {
                        ("int4mul", pg_sys::INT4OID, pg_sys::INT4OID, pg_sys::INT4OID)
                    } else {
                        // Default to float8 for fp64 type hint.
                        (
                            "float8mul",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    };

                let func_oid = lookup_function_oid(func_name, &[arg1_type, arg2_type])?;
                create_function_call_expr(func_oid, result_type, &[left_arg, right_arg])
            } else {
                Err(format!(
                    "multiply:fp64_fp64 function expects 2 arguments, got {argument_count}"
                )
                .into())
            }
        }
        "subtract:fp64_fp64" => {
            // Handle subtraction with type-appropriate function.
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                // Get actual argument types and use appropriate subtract function.
                let left_type = pg_sys::exprType(left_arg as *const pg_sys::Node);
                let right_type = pg_sys::exprType(right_arg as *const pg_sys::Node);

                // Use type-appropriate subtract function.
                let (func_name, result_type, arg1_type, arg2_type) =
                    if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                        (
                            "numeric_sub",
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                        )
                    } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                        (
                            "float8mi",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    } else if left_type == pg_sys::FLOAT4OID || right_type == pg_sys::FLOAT4OID {
                        (
                            "float4mi",
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                        )
                    } else if left_type == pg_sys::INT8OID || right_type == pg_sys::INT8OID {
                        ("int8mi", pg_sys::INT8OID, pg_sys::INT8OID, pg_sys::INT8OID)
                    } else if left_type == pg_sys::INT4OID || right_type == pg_sys::INT4OID {
                        ("int4mi", pg_sys::INT4OID, pg_sys::INT4OID, pg_sys::INT4OID)
                    } else {
                        // Default to float8 for fp64 type hint.
                        (
                            "float8mi",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    };

                let func_oid = lookup_function_oid(func_name, &[arg1_type, arg2_type])?;
                create_function_call_expr(func_oid, result_type, &[left_arg, right_arg])
            } else {
                Err(format!(
                    "subtract:fp64_fp64 function expects 2 arguments, got {argument_count}"
                )
                .into())
            }
        }
        "add:fp64_fp64" => {
            // Handle addition with type-appropriate function.
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                // Get actual argument types and use appropriate add function.
                let left_type = pg_sys::exprType(left_arg as *const pg_sys::Node);
                let right_type = pg_sys::exprType(right_arg as *const pg_sys::Node);

                // Use type-appropriate add function.
                let (func_name, result_type, arg1_type, arg2_type) =
                    if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                        (
                            "numeric_add",
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                        )
                    } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                        (
                            "float8pl",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    } else if left_type == pg_sys::FLOAT4OID || right_type == pg_sys::FLOAT4OID {
                        (
                            "float4pl",
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                        )
                    } else if left_type == pg_sys::INT8OID || right_type == pg_sys::INT8OID {
                        ("int8pl", pg_sys::INT8OID, pg_sys::INT8OID, pg_sys::INT8OID)
                    } else if left_type == pg_sys::INT4OID || right_type == pg_sys::INT4OID {
                        ("int4pl", pg_sys::INT4OID, pg_sys::INT4OID, pg_sys::INT4OID)
                    } else {
                        // Default to float8 for fp64 type hint.
                        (
                            "float8pl",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    };

                let func_oid = lookup_function_oid(func_name, &[arg1_type, arg2_type])?;
                create_function_call_expr(func_oid, result_type, &[left_arg, right_arg])
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
                let func_oid = lookup_function_oid("textlike", &[left_type, right_type])?;
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
            // Handle less-than comparison function with type-aware coercion
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;

                // Determine common type and coerce if needed
                let (common_type, coerced_left, coerced_right) = if left_type == right_type {
                    (left_type, left_arg, right_arg)
                } else if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                    // Prefer NUMERIC - coerce non-NUMERIC arg
                    let l = if left_type != pg_sys::NUMERICOID {
                        create_cast_expr(left_arg, pg_sys::NUMERICOID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::NUMERICOID {
                        create_cast_expr(right_arg, pg_sys::NUMERICOID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::NUMERICOID, l, r)
                } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                    // Prefer FLOAT8
                    let l = if left_type != pg_sys::FLOAT8OID {
                        create_cast_expr(left_arg, pg_sys::FLOAT8OID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::FLOAT8OID {
                        create_cast_expr(right_arg, pg_sys::FLOAT8OID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::FLOAT8OID, l, r)
                } else {
                    // Fallback: coerce right to left type
                    let r = create_cast_expr(right_arg, left_type)?;
                    (left_type, left_arg, r)
                };

                let func_name = get_comparison_func_name(common_type, "lt");
                let func_oid = lookup_function_oid(&func_name, &[common_type, common_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[coerced_left, coerced_right])
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
                let func_oid = lookup_function_oid("textlike", &[left_type, right_type])?;
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
            // Handle greater-than comparison function with type-aware coercion
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;

                // Determine common type and coerce if needed
                let (common_type, coerced_left, coerced_right) = if left_type == right_type {
                    (left_type, left_arg, right_arg)
                } else if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                    // Prefer NUMERIC - coerce non-NUMERIC arg
                    let l = if left_type != pg_sys::NUMERICOID {
                        create_cast_expr(left_arg, pg_sys::NUMERICOID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::NUMERICOID {
                        create_cast_expr(right_arg, pg_sys::NUMERICOID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::NUMERICOID, l, r)
                } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                    // Prefer FLOAT8
                    let l = if left_type != pg_sys::FLOAT8OID {
                        create_cast_expr(left_arg, pg_sys::FLOAT8OID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::FLOAT8OID {
                        create_cast_expr(right_arg, pg_sys::FLOAT8OID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::FLOAT8OID, l, r)
                } else {
                    // Fallback: coerce right to left type
                    let r = create_cast_expr(right_arg, left_type)?;
                    (left_type, left_arg, r)
                };

                let func_name = get_comparison_func_name(common_type, "gt");
                let func_oid = lookup_function_oid(&func_name, &[common_type, common_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[coerced_left, coerced_right])
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
            // Handle greater-than-or-equal comparison function with type-aware coercion
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;

                // Determine common type and coerce if needed
                let (common_type, coerced_left, coerced_right) = if left_type == right_type {
                    (left_type, left_arg, right_arg)
                } else if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                    // Prefer NUMERIC - coerce non-NUMERIC arg
                    let l = if left_type != pg_sys::NUMERICOID {
                        create_cast_expr(left_arg, pg_sys::NUMERICOID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::NUMERICOID {
                        create_cast_expr(right_arg, pg_sys::NUMERICOID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::NUMERICOID, l, r)
                } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                    // Prefer FLOAT8
                    let l = if left_type != pg_sys::FLOAT8OID {
                        create_cast_expr(left_arg, pg_sys::FLOAT8OID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::FLOAT8OID {
                        create_cast_expr(right_arg, pg_sys::FLOAT8OID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::FLOAT8OID, l, r)
                } else {
                    // Fallback: coerce right to left type
                    let r = create_cast_expr(right_arg, left_type)?;
                    (left_type, left_arg, r)
                };

                let func_name = get_comparison_func_name(common_type, "ge");
                let func_oid = lookup_function_oid(&func_name, &[common_type, common_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[coerced_left, coerced_right])
            } else {
                Err(
                    format!("gte:any_any function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "lte:any_any" => {
            // Handle less-than-or-equal comparison function with type-aware coercion
            if func.arguments.len() == 2 {
                let pg_args =
                    extract_function_arguments(&func.arguments, function_map, current_table_oid)?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;

                // Determine common type and coerce if needed
                let (common_type, coerced_left, coerced_right) = if left_type == right_type {
                    (left_type, left_arg, right_arg)
                } else if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                    // Prefer NUMERIC - coerce non-NUMERIC arg
                    let l = if left_type != pg_sys::NUMERICOID {
                        create_cast_expr(left_arg, pg_sys::NUMERICOID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::NUMERICOID {
                        create_cast_expr(right_arg, pg_sys::NUMERICOID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::NUMERICOID, l, r)
                } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                    // Prefer FLOAT8
                    let l = if left_type != pg_sys::FLOAT8OID {
                        create_cast_expr(left_arg, pg_sys::FLOAT8OID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::FLOAT8OID {
                        create_cast_expr(right_arg, pg_sys::FLOAT8OID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::FLOAT8OID, l, r)
                } else {
                    // Fallback: coerce right to left type
                    let r = create_cast_expr(right_arg, left_type)?;
                    (left_type, left_arg, r)
                };

                let func_name = get_comparison_func_name(common_type, "le");
                let func_oid = lookup_function_oid(&func_name, &[common_type, common_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[coerced_left, coerced_right])
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

/// Convert Substrait expressions to PostgreSQL target list using OUTER_VAR for Var nodes.
/// Use this for non-scan nodes like Result that reference their child plan's output.
pub unsafe fn convert_expressions_to_target_list_for_child_output(
    expressions: &[Expression],
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
) -> Result<(*mut pg_sys::List, RelationSchema), Box<dyn std::error::Error + Send + Sync>> {
    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();
    let mut output_columns = Vec::new();

    for (i, expr) in expressions.iter().enumerate() {
        let (target_entry, column_info) = convert_expression_to_target_entry_for_child_output(
            expr,
            i,
            function_map,
            input_schema,
        )?;
        target_list = pg_sys::lappend(target_list, target_entry as *mut std::ffi::c_void);
        output_columns.push(column_info);
    }

    let output_schema = RelationSchema::with_columns(output_columns);
    Ok((target_list, output_schema))
}

/// Convert expression to target entry using OUTER_VAR for all Var nodes.
/// Use this for non-scan nodes like Result that reference their child plan's output.
unsafe fn convert_expression_to_target_entry_for_child_output(
    expr: &Expression,
    index: usize,
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
) -> Result<(*mut pg_sys::TargetEntry, ColumnInfo), Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::RexType;

    match &expr.rex_type {
        Some(RexType::Selection(selection)) => {
            // Handle column references using OUTER_VAR for child plan output.
            let selection_expr =
                convert_selection_to_postgres_for_child_output(selection, input_schema)?;

            // Extract type information from the resolved column.
            let column_info = extract_column_info_from_selection(selection, input_schema)?;

            // Create TargetEntry.
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
            // Handle literal values.
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

                // Create TargetEntry.
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
        Some(RexType::ScalarFunction(func)) => {
            // Handle scalar function expressions using OUTER_VAR for all Var nodes.
            let func_expr =
                create_scalar_function_expr_for_child_output(func, function_map, input_schema)?;

            // Get the result type from the created expression.
            let result_type = pg_sys::exprType(func_expr as *const pg_sys::Node);
            let column_info = ColumnInfo::with_type(result_type);

            // Create TargetEntry.
            let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            target_entry.expr = func_expr;
            target_entry.resno = (index + 1) as pg_sys::AttrNumber;
            target_entry.resname = create_cstring(&format!("column_{}", index + 1));
            target_entry.resjunk = false;
            let target_entry = target_entry.into_pg();

            Ok((target_entry, column_info))
        }
        Some(RexType::Cast(cast)) => {
            // Handle cast expressions using OUTER_VAR for nested Var nodes.
            let input_expr = if let Some(input) = &cast.input {
                convert_expression_to_postgres_for_child_output(input, function_map, input_schema)?
            } else {
                return Err("Cast expression missing input".into());
            };

            let (cast_expr, target_oid) = if let Some(cast_type) = &cast.r#type {
                let target_oid = get_pg_type_oid(cast_type)?;
                (create_cast_expr(input_expr, target_oid)?, target_oid)
            } else {
                return Err("Cast expression missing type".into());
            };

            let column_info = ColumnInfo::with_type(target_oid);

            // Create TargetEntry.
            let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            target_entry.expr = cast_expr;
            target_entry.resno = (index + 1) as pg_sys::AttrNumber;
            target_entry.resname = create_cstring(&format!("column_{}", index + 1));
            target_entry.resjunk = false;
            let target_entry = target_entry.into_pg();

            Ok((target_entry, column_info))
        }
        Some(RexType::IfThen(if_then)) => {
            // Handle CASE WHEN expressions using OUTER_VAR for all Var nodes.
            let case_expr =
                create_case_expr_with_varno(if_then, function_map, input_schema, OUTER_VAR)?;

            // Get the result type from the created expression.
            let result_type = pg_sys::exprType(case_expr as *const pg_sys::Node);
            let column_info = ColumnInfo::with_type(result_type);

            // Create TargetEntry.
            let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            target_entry.expr = case_expr;
            target_entry.resno = (index + 1) as pg_sys::AttrNumber;
            target_entry.resname = create_cstring(&format!("column_{}", index + 1));
            target_entry.resjunk = false;
            let target_entry = target_entry.into_pg();

            Ok((target_entry, column_info))
        }
        _ => {
            // For unsupported expression types, return an error.
            Err(
                format!("Unsupported expression type at index {index} in child output conversion")
                    .into(),
            )
        }
    }
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
        Some(RexType::ScalarFunction(func)) => {
            // Handle scalar function expressions with schema-based type resolution
            let func_expr =
                create_scalar_function_expr_with_schema(func, function_map, input_schema)?;

            // Get the result type from the created expression
            let result_type = pg_sys::exprType(func_expr as *const pg_sys::Node);
            let column_info = ColumnInfo::with_type(result_type);

            // Create TargetEntry
            let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            target_entry.expr = func_expr;
            target_entry.resno = (index + 1) as pg_sys::AttrNumber;
            target_entry.resname = create_cstring(&format!("column_{}", index + 1));
            target_entry.resjunk = false;
            let target_entry = target_entry.into_pg();

            Ok((target_entry, column_info))
        }
        Some(RexType::Cast(cast)) => {
            // Handle cast expressions with schema-based type resolution
            let input_expr = if let Some(input) = &cast.input {
                convert_expression_to_postgres_with_schema(input, function_map, input_schema)?
            } else {
                return Err("Cast expression missing input".into());
            };

            let (cast_expr, target_oid) = if let Some(cast_type) = &cast.r#type {
                let target_oid = get_pg_type_oid(cast_type)?;
                (create_cast_expr(input_expr, target_oid)?, target_oid)
            } else {
                return Err("Cast expression missing type".into());
            };

            let column_info = ColumnInfo::with_type(target_oid);

            // Create TargetEntry
            let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            target_entry.expr = cast_expr;
            target_entry.resno = (index + 1) as pg_sys::AttrNumber;
            target_entry.resname = create_cstring(&format!("column_{}", index + 1));
            target_entry.resjunk = false;
            let target_entry = target_entry.into_pg();

            Ok((target_entry, column_info))
        }
        Some(RexType::Subquery(subquery)) => {
            // Handle subquery expressions.
            let subquery_expr = create_subquery_expr(subquery, function_map)?;
            let result_type = pg_sys::exprType(subquery_expr as *const pg_sys::Node);
            let column_info = ColumnInfo::with_type(result_type);

            // Create TargetEntry.
            let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            target_entry.expr = subquery_expr as *mut pg_sys::Expr;
            target_entry.resno = (index + 1) as pg_sys::AttrNumber;
            target_entry.resname = create_cstring(&format!("column_{}", index + 1));
            target_entry.resjunk = false;
            let target_entry = target_entry.into_pg();

            Ok((target_entry, column_info))
        }
        _ => {
            // For unsupported expression types, return an error.
            Err(
                format!("Unsupported expression type at index {index} in schema-based conversion")
                    .into(),
            )
        }
    }
}

/// Convert selection expression to PostgreSQL with schema-based type resolution
pub unsafe fn convert_selection_to_postgres_with_schema(
    selection: &substrait::proto::expression::FieldReference,
    input_schema: &RelationSchema,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    convert_selection_to_postgres_with_schema_and_varno(selection, input_schema, 1)
}

/// Convert selection to Var node using OUTER_VAR for referencing child plan output.
/// Use this for non-scan nodes like Result that reference their child's output.
pub unsafe fn convert_selection_to_postgres_for_child_output(
    selection: &substrait::proto::expression::FieldReference,
    input_schema: &RelationSchema,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    convert_selection_to_postgres_with_schema_and_varno(selection, input_schema, OUTER_VAR)
}

/// Convert selection to Var node with specified varno.
unsafe fn convert_selection_to_postgres_with_schema_and_varno(
    selection: &substrait::proto::expression::FieldReference,
    input_schema: &RelationSchema,
    varno: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    // Check if this is an outer reference (correlated subquery reference).
    // Outer references require special handling with Param nodes.
    if let Some(root_type) = &selection.root_type {
        use substrait::proto::expression::field_reference::RootType;
        match root_type {
            RootType::OuterReference(outer_ref) => {
                // This is a reference to an outer query's column (correlated subquery).
                // We need to create a Param node and register it for later setup in SubPlan.
                let steps_out = outer_ref.steps_out;

                // Get the field index from the direct reference.
                let field_index = if let Some(ref_type) = &selection.reference_type {
                    if let substrait::proto::expression::field_reference::ReferenceType::DirectReference(direct_ref) = ref_type {
                        if let Some(struct_field) = &direct_ref.reference_type {
                            if let substrait::proto::expression::reference_segment::ReferenceType::StructField(field) = struct_field {
                                field.field as usize
                            } else {
                                return Err("OuterReference with unsupported reference type".into());
                            }
                        } else {
                            return Err("OuterReference missing struct field".into());
                        }
                    } else {
                        return Err("OuterReference with non-direct reference".into());
                    }
                } else {
                    return Err("OuterReference missing reference_type".into());
                };

                // Get the outer schema at the specified level.
                let outer_schema = get_outer_schema(steps_out).ok_or_else(|| {
                    format!(
                        "No outer schema available at steps_out={} (are we in a subquery?)",
                        steps_out
                    )
                })?;

                // Look up the column info from the outer schema.
                let column_info = outer_schema.get_column(field_index).ok_or_else(|| {
                    format!(
                        "Field index {} out of bounds for outer schema with {} columns",
                        field_index,
                        outer_schema.column_count()
                    )
                })?;

                // Register the parameter with the collector.
                let param_id = register_outer_param(
                    field_index,
                    column_info.type_oid,
                    column_info.typmod,
                    column_info.collid,
                )
                .ok_or("No active subplan collector for outer reference")?;

                // Create a Param node (PARAM_EXEC type).
                let param_node = create_param_node(
                    param_id,
                    column_info.type_oid,
                    column_info.typmod,
                    column_info.collid,
                )?;
                return Ok(param_node);
            }
            RootType::RootReference(_) => {
                // Normal reference to current relation's schema - proceed below.
            }
            RootType::Expression(_) => {
                // Reference is relative to an expression's output.
                eprintln!(
                    "DEBUG: Expression root type in selection - treating as normal reference"
                );
            }
            RootType::LambdaParameterReference(_) => {
                return Err("Lambda parameter references are not supported".into());
            }
        }
    }

    if let Some(ref_type) = &selection.reference_type {
        match ref_type {
            substrait::proto::expression::field_reference::ReferenceType::DirectReference(
                direct_ref,
            ) => {
                if let Some(struct_field) = &direct_ref.reference_type {
                    match struct_field {
                        substrait::proto::expression::reference_segment::ReferenceType::StructField(field) => {
                            let field_index = field.field as usize;

                            // Look up column information from the input schema.
                            if let Some(column_info) = input_schema.get_column(field_index) {
                                eprintln!(
                                    "DEBUG: Schema-based Selection field {} resolves to type OID {}, using varno={}",
                                    field_index, column_info.type_oid.to_u32(), varno
                                );
                                pgrx::info!(
                                    "DEBUG: Creating Var - field={} varattno={} type={} varno={}",
                                    field_index, field.field + 1, column_info.type_oid.to_u32(), varno
                                );

                                create_var_node_with_varno(
                                    field.field + 1, // 1-based indexing
                                    column_info.type_oid,
                                    column_info.typmod,
                                    column_info.collid,
                                    varno,
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

/// Create a PostgreSQL Param node for executor parameters (used in correlated subqueries).
unsafe fn create_param_node(
    param_id: i32,
    param_type: pg_sys::Oid,
    typmod: i32,
    collid: pg_sys::Oid,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let mut param = PgBox::<pg_sys::Param>::alloc0();
    param.xpr.type_ = pg_sys::NodeTag::T_Param;
    param.paramkind = pg_sys::ParamKind::PARAM_EXEC;
    param.paramid = param_id;
    param.paramtype = param_type;
    param.paramtypmod = typmod;
    param.paramcollid = collid;
    param.location = -1;

    eprintln!(
        "DEBUG: Created Param node: paramid={}, paramtype={}, paramkind=PARAM_EXEC",
        param_id, param_type
    );

    Ok(param.into_pg() as *mut pg_sys::Expr)
}

/// Convert expression to PostgreSQL with schema-based type resolution
/// This is the main entry point for schema-aware expression conversion
pub unsafe fn convert_expression_to_postgres_with_schema(
    expr: &Expression,
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
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
                    substrait::proto::expression::literal::LiteralType::Decimal(d) => {
                        create_numeric_const(&d.value, d.precision, d.scale)
                    }
                    _ => Err("Unsupported literal type in expression".into()),
                }
            } else {
                Err("Literal expression missing literal type".into())
            }
        }
        Some(RexType::Selection(selection)) => {
            convert_selection_to_postgres_with_schema(selection, input_schema)
        }
        Some(RexType::ScalarFunction(func)) => {
            create_scalar_function_expr_with_schema(func, function_map, input_schema)
        }
        Some(RexType::Cast(cast)) => {
            let input_expr = if let Some(input) = &cast.input {
                convert_expression_to_postgres_with_schema(input, function_map, input_schema)?
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
        Some(rex_type) => {
            let type_name = get_expression_type_name(rex_type);
            Err(
                format!("Unsupported expression type in schema-based conversion: {type_name}")
                    .into(),
            )
        }
        None => Err("Expression missing rex_type".into()),
    }
}

/// Convert expression to PostgreSQL using OUTER_VAR for all Var nodes.
/// Use this for non-scan nodes like Result that reference their child plan's output.
pub unsafe fn convert_expression_to_postgres_for_child_output(
    expr: &Expression,
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    convert_expression_to_postgres_with_varno(expr, function_map, input_schema, OUTER_VAR)
}

/// Core expression conversion with explicit varno parameter.
/// Use varno=1 for scan nodes, varno=OUTER_VAR for non-scan nodes referencing child output.
pub unsafe fn convert_expression_to_postgres_with_varno(
    expr: &Expression,
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
    varno: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::expression::RexType;

    match &expr.rex_type {
        Some(RexType::Literal(literal)) => {
            // Literals don't need varno - they're constants.
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
                    substrait::proto::expression::literal::LiteralType::Decimal(d) => {
                        create_numeric_const(&d.value, d.precision, d.scale)
                    }
                    _ => Err("Unsupported literal type in expression".into()),
                }
            } else {
                Err("Literal expression missing literal type".into())
            }
        }
        Some(RexType::Selection(selection)) => {
            // Use specified varno for column references.
            convert_selection_to_postgres_with_schema_and_varno(selection, input_schema, varno)
        }
        Some(RexType::ScalarFunction(func)) => {
            // Create function with specified varno for all nested Var nodes.
            create_scalar_function_expr_with_varno(func, function_map, input_schema, varno)
        }
        Some(RexType::Cast(cast)) => {
            // Recursively convert cast input using specified varno.
            let input_expr = if let Some(input) = &cast.input {
                convert_expression_to_postgres_with_varno(input, function_map, input_schema, varno)?
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
            // Subqueries are independent queries - they don't use the parent's varno.
            create_subquery_expr(subquery, function_map).map(|node| node as *mut pg_sys::Expr)
        }
        Some(RexType::IfThen(if_then)) => {
            // Convert CASE WHEN expression to PostgreSQL CaseExpr.
            create_case_expr_with_varno(if_then, function_map, input_schema, varno)
        }
        Some(rex_type) => {
            let type_name = get_expression_type_name(rex_type);
            Err(
                format!("Unsupported expression type in varno-aware conversion: {type_name}")
                    .into(),
            )
        }
        None => Err("Expression missing rex_type".into()),
    }
}

/// Extract PostgreSQL expressions from Substrait function arguments with specified varno.
unsafe fn extract_function_arguments_with_varno(
    func_arguments: &[substrait::proto::FunctionArgument],
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
    varno: i32,
) -> Result<Vec<*mut pg_sys::Expr>, Box<dyn std::error::Error + Send + Sync>> {
    let mut pg_args = Vec::with_capacity(func_arguments.len());
    for arg in func_arguments.iter() {
        if let Some(value) = &arg.arg_type {
            match value {
                substrait::proto::function_argument::ArgType::Value(expr) => {
                    let pg_expr = convert_expression_to_postgres_with_varno(
                        expr,
                        function_map,
                        input_schema,
                        varno,
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

/// Create scalar function expression with specified varno for all Var nodes.
pub unsafe fn create_scalar_function_expr_with_varno(
    func: &substrait::proto::expression::ScalarFunction,
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
    varno: i32,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let function_reference = func.function_reference;
    let argument_count = func.arguments.len();

    // Look up function name from extension map.
    let function_name = function_map
        .get(&function_reference)
        .map(|s| s.as_str())
        .unwrap_or("unknown");

    eprintln!("DEBUG: Scalar function (varno={varno}): ref={function_reference}, name={function_name}, args={argument_count}");

    // Handle specific function types based on name.
    match function_name {
        "lte:date_date" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
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
            if func.arguments.len() >= 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
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
        "multiply:fp64_fp64" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                // Get actual argument types and use appropriate multiply function.
                let left_type = pg_sys::exprType(left_arg as *const pg_sys::Node);
                let right_type = pg_sys::exprType(right_arg as *const pg_sys::Node);

                // Use type-appropriate multiply function.
                // Capture arg types for lookup to ensure exact match.
                let (func_name, result_type, arg1_type, arg2_type) =
                    if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                        (
                            "numeric_mul",
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                        )
                    } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                        (
                            "float8mul",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    } else if left_type == pg_sys::FLOAT4OID || right_type == pg_sys::FLOAT4OID {
                        (
                            "float4mul",
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                        )
                    } else if left_type == pg_sys::INT8OID || right_type == pg_sys::INT8OID {
                        ("int8mul", pg_sys::INT8OID, pg_sys::INT8OID, pg_sys::INT8OID)
                    } else if left_type == pg_sys::INT4OID || right_type == pg_sys::INT4OID {
                        ("int4mul", pg_sys::INT4OID, pg_sys::INT4OID, pg_sys::INT4OID)
                    } else {
                        // Default to float8 for fp64 type hint.
                        (
                            "float8mul",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    };

                // Coerce arguments to expected types to avoid type mismatch crashes.
                let left_coerced = coerce_arg_to_type(left_arg, arg1_type)?;
                let right_coerced = coerce_arg_to_type(right_arg, arg2_type)?;

                let func_oid = lookup_function_oid(func_name, &[arg1_type, arg2_type])?;
                create_function_call_expr(func_oid, result_type, &[left_coerced, right_coerced])
            } else {
                Err(format!(
                    "multiply:fp64_fp64 function expects 2 arguments, got {argument_count}"
                )
                .into())
            }
        }
        "subtract:fp64_fp64" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                // Get actual argument types and use appropriate subtract function.
                let left_type = pg_sys::exprType(left_arg as *const pg_sys::Node);
                let right_type = pg_sys::exprType(right_arg as *const pg_sys::Node);

                // Use type-appropriate subtract function.
                let (func_name, result_type, arg1_type, arg2_type) =
                    if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                        (
                            "numeric_sub",
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                        )
                    } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                        (
                            "float8mi",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    } else if left_type == pg_sys::FLOAT4OID || right_type == pg_sys::FLOAT4OID {
                        (
                            "float4mi",
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                        )
                    } else if left_type == pg_sys::INT8OID || right_type == pg_sys::INT8OID {
                        ("int8mi", pg_sys::INT8OID, pg_sys::INT8OID, pg_sys::INT8OID)
                    } else if left_type == pg_sys::INT4OID || right_type == pg_sys::INT4OID {
                        ("int4mi", pg_sys::INT4OID, pg_sys::INT4OID, pg_sys::INT4OID)
                    } else {
                        // Default to float8 for fp64 type hint.
                        (
                            "float8mi",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    };

                // Coerce arguments to expected types to avoid type mismatch crashes.
                let left_coerced = coerce_arg_to_type(left_arg, arg1_type)?;
                let right_coerced = coerce_arg_to_type(right_arg, arg2_type)?;

                let func_oid = lookup_function_oid(func_name, &[arg1_type, arg2_type])?;
                create_function_call_expr(func_oid, result_type, &[left_coerced, right_coerced])
            } else {
                Err(format!(
                    "subtract:fp64_fp64 function expects 2 arguments, got {argument_count}"
                )
                .into())
            }
        }
        "add:fp64_fp64" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];

                // Get actual argument types and use appropriate add function.
                let left_type = pg_sys::exprType(left_arg as *const pg_sys::Node);
                let right_type = pg_sys::exprType(right_arg as *const pg_sys::Node);

                // Use type-appropriate add function.
                let (func_name, result_type, arg1_type, arg2_type) =
                    if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                        (
                            "numeric_add",
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                            pg_sys::NUMERICOID,
                        )
                    } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                        (
                            "float8pl",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    } else if left_type == pg_sys::FLOAT4OID || right_type == pg_sys::FLOAT4OID {
                        (
                            "float4pl",
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                            pg_sys::FLOAT4OID,
                        )
                    } else if left_type == pg_sys::INT8OID || right_type == pg_sys::INT8OID {
                        ("int8pl", pg_sys::INT8OID, pg_sys::INT8OID, pg_sys::INT8OID)
                    } else if left_type == pg_sys::INT4OID || right_type == pg_sys::INT4OID {
                        ("int4pl", pg_sys::INT4OID, pg_sys::INT4OID, pg_sys::INT4OID)
                    } else {
                        // Default to float8 for fp64 type hint.
                        (
                            "float8pl",
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                            pg_sys::FLOAT8OID,
                        )
                    };

                // Coerce arguments to expected types to avoid type mismatch crashes.
                let left_coerced = coerce_arg_to_type(left_arg, arg1_type)?;
                let right_coerced = coerce_arg_to_type(right_arg, arg2_type)?;

                let func_oid = lookup_function_oid(func_name, &[arg1_type, arg2_type])?;
                create_function_call_expr(func_oid, result_type, &[left_coerced, right_coerced])
            } else {
                Err(
                    format!("add:fp64_fp64 function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "or:bool" => {
            if func.arguments.len() >= 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
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
        "equal:any_any" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;

                // Determine common type and coerce if needed
                let (common_type, coerced_left, coerced_right) = if left_type == right_type {
                    (left_type, left_arg, right_arg)
                } else if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                    let l = if left_type != pg_sys::NUMERICOID {
                        create_cast_expr(left_arg, pg_sys::NUMERICOID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::NUMERICOID {
                        create_cast_expr(right_arg, pg_sys::NUMERICOID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::NUMERICOID, l, r)
                } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                    let l = if left_type != pg_sys::FLOAT8OID {
                        create_cast_expr(left_arg, pg_sys::FLOAT8OID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::FLOAT8OID {
                        create_cast_expr(right_arg, pg_sys::FLOAT8OID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::FLOAT8OID, l, r)
                } else {
                    let r = create_cast_expr(right_arg, left_type)?;
                    (left_type, left_arg, r)
                };

                let func_name = get_comparison_func_name(common_type, "eq");
                let func_oid = lookup_function_oid(&func_name, &[common_type, common_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[coerced_left, coerced_right])
            } else {
                Err(
                    format!("equal:any_any function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "not_equal:any_any" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;

                // Determine common type and coerce if needed
                let (common_type, coerced_left, coerced_right) = if left_type == right_type {
                    (left_type, left_arg, right_arg)
                } else if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                    let l = if left_type != pg_sys::NUMERICOID {
                        create_cast_expr(left_arg, pg_sys::NUMERICOID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::NUMERICOID {
                        create_cast_expr(right_arg, pg_sys::NUMERICOID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::NUMERICOID, l, r)
                } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                    let l = if left_type != pg_sys::FLOAT8OID {
                        create_cast_expr(left_arg, pg_sys::FLOAT8OID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::FLOAT8OID {
                        create_cast_expr(right_arg, pg_sys::FLOAT8OID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::FLOAT8OID, l, r)
                } else {
                    let r = create_cast_expr(right_arg, left_type)?;
                    (left_type, left_arg, r)
                };

                let func_name = get_comparison_func_name(common_type, "ne");
                let func_oid = lookup_function_oid(&func_name, &[common_type, common_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[coerced_left, coerced_right])
            } else {
                Err(
                    format!("not_equal:any_any function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "lt:any_any" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;

                // Determine common type and coerce if needed
                let (common_type, coerced_left, coerced_right) = if left_type == right_type {
                    (left_type, left_arg, right_arg)
                } else if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                    let l = if left_type != pg_sys::NUMERICOID {
                        create_cast_expr(left_arg, pg_sys::NUMERICOID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::NUMERICOID {
                        create_cast_expr(right_arg, pg_sys::NUMERICOID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::NUMERICOID, l, r)
                } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                    let l = if left_type != pg_sys::FLOAT8OID {
                        create_cast_expr(left_arg, pg_sys::FLOAT8OID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::FLOAT8OID {
                        create_cast_expr(right_arg, pg_sys::FLOAT8OID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::FLOAT8OID, l, r)
                } else {
                    let r = create_cast_expr(right_arg, left_type)?;
                    (left_type, left_arg, r)
                };

                let func_name = get_comparison_func_name(common_type, "lt");
                let func_oid = lookup_function_oid(&func_name, &[common_type, common_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[coerced_left, coerced_right])
            } else {
                Err(format!("lt:any_any function expects 2 arguments, got {argument_count}").into())
            }
        }
        "gt:any_any" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;

                // Determine common type and coerce if needed
                let (common_type, coerced_left, coerced_right) = if left_type == right_type {
                    (left_type, left_arg, right_arg)
                } else if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                    let l = if left_type != pg_sys::NUMERICOID {
                        create_cast_expr(left_arg, pg_sys::NUMERICOID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::NUMERICOID {
                        create_cast_expr(right_arg, pg_sys::NUMERICOID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::NUMERICOID, l, r)
                } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                    let l = if left_type != pg_sys::FLOAT8OID {
                        create_cast_expr(left_arg, pg_sys::FLOAT8OID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::FLOAT8OID {
                        create_cast_expr(right_arg, pg_sys::FLOAT8OID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::FLOAT8OID, l, r)
                } else {
                    let r = create_cast_expr(right_arg, left_type)?;
                    (left_type, left_arg, r)
                };

                let func_name = get_comparison_func_name(common_type, "gt");
                let func_oid = lookup_function_oid(&func_name, &[common_type, common_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[coerced_left, coerced_right])
            } else {
                Err(format!("gt:any_any function expects 2 arguments, got {argument_count}").into())
            }
        }
        "gte:any_any" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;

                eprintln!(
                    "DEBUG: gte:any_any varno handler - left_type={}, right_type={}",
                    left_type.to_u32(),
                    right_type.to_u32()
                );
                pgrx::info!(
                    "DEBUG: gte:any_any varno handler - left_type={}, right_type={}",
                    left_type.to_u32(),
                    right_type.to_u32()
                );

                // Determine common type and coerce if needed
                let (common_type, coerced_left, coerced_right) = if left_type == right_type {
                    eprintln!("DEBUG: gte:any_any - types match, no coercion needed");
                    pgrx::info!("DEBUG: gte:any_any - types match, no coercion needed");
                    (left_type, left_arg, right_arg)
                } else if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                    eprintln!("DEBUG: gte:any_any - coercing to NUMERIC");
                    pgrx::info!("DEBUG: gte:any_any - coercing to NUMERIC");
                    let l = if left_type != pg_sys::NUMERICOID {
                        create_cast_expr(left_arg, pg_sys::NUMERICOID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::NUMERICOID {
                        create_cast_expr(right_arg, pg_sys::NUMERICOID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::NUMERICOID, l, r)
                } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                    eprintln!("DEBUG: gte:any_any - coercing to FLOAT8");
                    pgrx::info!("DEBUG: gte:any_any - coercing to FLOAT8");
                    let l = if left_type != pg_sys::FLOAT8OID {
                        create_cast_expr(left_arg, pg_sys::FLOAT8OID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::FLOAT8OID {
                        create_cast_expr(right_arg, pg_sys::FLOAT8OID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::FLOAT8OID, l, r)
                } else {
                    eprintln!("DEBUG: gte:any_any - fallback coercion to left_type");
                    pgrx::info!("DEBUG: gte:any_any - fallback coercion to left_type");
                    let r = create_cast_expr(right_arg, left_type)?;
                    (left_type, left_arg, r)
                };

                let func_name = get_comparison_func_name(common_type, "ge");
                let func_oid = lookup_function_oid(&func_name, &[common_type, common_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[coerced_left, coerced_right])
            } else {
                Err(
                    format!("gte:any_any function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "lte:any_any" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let left_type = get_expr_type_oid(left_arg)?;
                let right_type = get_expr_type_oid(right_arg)?;

                // Determine common type and coerce if needed
                let (common_type, coerced_left, coerced_right) = if left_type == right_type {
                    (left_type, left_arg, right_arg)
                } else if left_type == pg_sys::NUMERICOID || right_type == pg_sys::NUMERICOID {
                    let l = if left_type != pg_sys::NUMERICOID {
                        create_cast_expr(left_arg, pg_sys::NUMERICOID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::NUMERICOID {
                        create_cast_expr(right_arg, pg_sys::NUMERICOID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::NUMERICOID, l, r)
                } else if left_type == pg_sys::FLOAT8OID || right_type == pg_sys::FLOAT8OID {
                    let l = if left_type != pg_sys::FLOAT8OID {
                        create_cast_expr(left_arg, pg_sys::FLOAT8OID)?
                    } else {
                        left_arg
                    };
                    let r = if right_type != pg_sys::FLOAT8OID {
                        create_cast_expr(right_arg, pg_sys::FLOAT8OID)?
                    } else {
                        right_arg
                    };
                    (pg_sys::FLOAT8OID, l, r)
                } else {
                    let r = create_cast_expr(right_arg, left_type)?;
                    (left_type, left_arg, r)
                };

                let func_name = get_comparison_func_name(common_type, "le");
                let func_oid = lookup_function_oid(&func_name, &[common_type, common_type])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[coerced_left, coerced_right])
            } else {
                Err(
                    format!("lte:any_any function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "like:str_str" | "like:vchar_vchar" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let func_oid =
                    lookup_function_oid("textlike", &[pg_sys::TEXTOID, pg_sys::TEXTOID])?;
                create_function_call_expr(func_oid, pg_sys::BOOLOID, &[left_arg, right_arg])
            } else {
                Err(format!("like function expects 2 arguments, got {argument_count}").into())
            }
        }
        "not:bool" => {
            if func.arguments.len() == 1 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let bool_expr = pgrx::PgBox::<pg_sys::BoolExpr>::alloc0();
                let bool_expr = bool_expr.into_pg();
                (*bool_expr).xpr.type_ = pg_sys::NodeTag::T_BoolExpr;
                (*bool_expr).boolop = pg_sys::BoolExprType::NOT_EXPR;
                let mut args_list: *mut pg_sys::List = std::ptr::null_mut();
                args_list = pg_sys::lappend(args_list, pg_args[0] as *mut std::ffi::c_void);
                (*bool_expr).args = args_list;
                Ok(bool_expr as *mut pg_sys::Expr)
            } else {
                Err(format!("not:bool function expects 1 argument, got {argument_count}").into())
            }
        }
        "gte:date_date" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
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
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
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
        "gt:date_date" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
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
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
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
        "multiply:dec_dec" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let func_oid =
                    lookup_function_oid("numeric_mul", &[pg_sys::NUMERICOID, pg_sys::NUMERICOID])?;
                create_function_call_expr(func_oid, pg_sys::NUMERICOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("multiply:dec_dec function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "subtract:dec_dec" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let func_oid =
                    lookup_function_oid("numeric_sub", &[pg_sys::NUMERICOID, pg_sys::NUMERICOID])?;
                create_function_call_expr(func_oid, pg_sys::NUMERICOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("subtract:dec_dec function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "divide:dec_dec" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let func_oid =
                    lookup_function_oid("numeric_div", &[pg_sys::NUMERICOID, pg_sys::NUMERICOID])?;
                create_function_call_expr(func_oid, pg_sys::NUMERICOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("divide:dec_dec function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "add:dec_dec" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let func_oid =
                    lookup_function_oid("numeric_add", &[pg_sys::NUMERICOID, pg_sys::NUMERICOID])?;
                create_function_call_expr(func_oid, pg_sys::NUMERICOID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("add:dec_dec function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        "add:i32_i32" => {
            if func.arguments.len() == 2 {
                let pg_args = extract_function_arguments_with_varno(
                    &func.arguments,
                    function_map,
                    input_schema,
                    varno,
                )?;
                let left_arg = pg_args[0];
                let right_arg = pg_args[1];
                let func_oid = lookup_function_oid("int4pl", &[pg_sys::INT4OID, pg_sys::INT4OID])?;
                create_function_call_expr(func_oid, pg_sys::INT4OID, &[left_arg, right_arg])
            } else {
                Err(
                    format!("add:i32_i32 function expects 2 arguments, got {argument_count}")
                        .into(),
                )
            }
        }
        _ => {
            // For other functions, return error for now.
            Err(format!(
                "Unsupported function '{}' in expression context",
                function_name
            )
            .into())
        }
    }
}

/// Wrapper: Create scalar function expression using OUTER_VAR for all Var nodes.
pub unsafe fn create_scalar_function_expr_for_child_output(
    func: &substrait::proto::expression::ScalarFunction,
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    create_scalar_function_expr_with_varno(func, function_map, input_schema, OUTER_VAR)
}

/// Wrapper: Extract PostgreSQL expressions from Substrait function arguments with schema-based type resolution.
/// Uses varno=1 for scan nodes.
unsafe fn extract_function_arguments_with_schema(
    func_arguments: &[substrait::proto::FunctionArgument],
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
) -> Result<Vec<*mut pg_sys::Expr>, Box<dyn std::error::Error + Send + Sync>> {
    extract_function_arguments_with_varno(func_arguments, function_map, input_schema, 1)
}

/// Wrapper: Create scalar function expression with schema-based type resolution.
/// Uses varno=1 for scan nodes.
pub unsafe fn create_scalar_function_expr_with_schema(
    func: &substrait::proto::expression::ScalarFunction,
    function_map: &HashMap<u32, String>,
    input_schema: &RelationSchema,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    create_scalar_function_expr_with_varno(func, function_map, input_schema, 1)
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
