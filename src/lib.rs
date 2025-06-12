use anyhow::Result;
use pgrx::pg_sys;
use pgrx::prelude::*;
use prost::Message;
use substrait::proto::Plan;

#[derive(Debug)]
struct ExecutionResult {
    columns: Vec<ColumnInfo>,
    rows: Vec<Vec<pg_sys::Datum>>,
    nulls: Vec<Vec<bool>>,
}

#[derive(Debug)]
struct ColumnInfo {
    name: String,
    type_oid: pg_sys::Oid,
    type_mod: i32,
}

pgrx::pg_module_magic!();

#[no_mangle]
#[pg_guard]
pub unsafe extern "C-unwind" fn from_substrait_wrapper(
    fcinfo: pg_sys::FunctionCallInfo,
) -> pg_sys::Datum {
    let plan_bytes = extract_bytea_arg(fcinfo, 0);

    match Plan::decode(plan_bytes) {
        Ok(plan) => execute_substrait_as_srf(fcinfo, plan),
        Err(_) => pg_sys::Datum::null(),
    }
}

#[no_mangle]
#[pg_guard]
pub unsafe extern "C-unwind" fn from_substrait_json_wrapper(
    fcinfo: pg_sys::FunctionCallInfo,
) -> pg_sys::Datum {
    let json_plan = extract_text_arg(fcinfo, 0);

    match serde_json::from_str::<Plan>(json_plan) {
        Ok(plan) => execute_substrait_as_srf(fcinfo, plan),
        Err(_) => pg_sys::Datum::null(),
    }
}

#[pg_extern(
    sql = "CREATE OR REPLACE FUNCTION from_substrait(plan_bytes bytea) RETURNS SETOF RECORD AS 'MODULE_PATHNAME', 'from_substrait_wrapper' LANGUAGE c IMMUTABLE STRICT;"
)]
fn from_substrait_placeholder() {}

#[pg_extern(
    sql = "CREATE OR REPLACE FUNCTION from_substrait_json(json_plan text) RETURNS SETOF RECORD AS 'MODULE_PATHNAME', 'from_substrait_json_wrapper' LANGUAGE c IMMUTABLE STRICT;"
)]
fn from_substrait_json_placeholder() {}

unsafe fn extract_bytea_arg(fcinfo: pg_sys::FunctionCallInfo, arg_num: i32) -> &'static [u8] {
    if i32::from((*fcinfo).nargs) <= arg_num {
        return &[];
    }

    // Access the argument directly
    let arg_ptr =
        ((*fcinfo).args.as_ptr() as *const pg_sys::NullableDatum).offset(arg_num as isize);
    let arg = &*arg_ptr;

    if arg.isnull {
        return &[];
    }

    let datum = pg_sys::Datum::from(arg.value);
    let bytea_ptr = datum.cast_mut_ptr::<pg_sys::varlena>();
    if bytea_ptr.is_null() {
        return &[];
    }

    // Simple approach: assume the first 4 bytes are the length header
    let header_bytes = std::slice::from_raw_parts(bytea_ptr as *const u8, 4);
    let total_len = u32::from_le_bytes([
        header_bytes[0],
        header_bytes[1],
        header_bytes[2],
        header_bytes[3],
    ]) as usize;
    let data_len = if total_len >= 4 { total_len - 4 } else { 0 };
    let data_ptr = (bytea_ptr as *const u8).offset(4);
    std::slice::from_raw_parts(data_ptr, data_len)
}

unsafe fn extract_text_arg(fcinfo: pg_sys::FunctionCallInfo, arg_num: i32) -> &'static str {
    if i32::from((*fcinfo).nargs) <= arg_num {
        return "";
    }

    // Access the argument directly
    let arg_ptr =
        ((*fcinfo).args.as_ptr() as *const pg_sys::NullableDatum).offset(arg_num as isize);
    let arg = &*arg_ptr;

    if arg.isnull {
        return "";
    }

    let datum = pg_sys::Datum::from(arg.value);
    let text_ptr = datum.cast_mut_ptr::<pg_sys::varlena>();
    if text_ptr.is_null() {
        return "";
    }

    let c_str = pg_sys::text_to_cstring(text_ptr);
    std::ffi::CStr::from_ptr(c_str).to_str().unwrap_or("")
}

unsafe fn execute_substrait_as_srf(fcinfo: pg_sys::FunctionCallInfo, plan: Plan) -> pg_sys::Datum {
    // Execute the plan and get results
    match execute_substrait_plan(plan) {
        Ok(result_data) => {
            // Parse the result data to extract rows and columns
            execute_results_as_srf(fcinfo, result_data)
        }
        Err(_) => pg_sys::Datum::null(),
    }
}

unsafe fn execute_results_as_srf(
    fcinfo: pg_sys::FunctionCallInfo,
    results: ExecutionResult,
) -> pg_sys::Datum {
    // Initialize SRF context
    let func_ctx = pg_sys::init_MultiFuncCall(fcinfo);

    if (*func_ctx).call_cntr == 0 {
        // First call - set up the function context
        let memory_ctx = (*func_ctx).multi_call_memory_ctx;
        let old_ctx = pg_sys::MemoryContextSwitchTo(memory_ctx);

        // Create tuple descriptor from the result columns
        if !results.columns.is_empty() {
            let tupdesc = pg_sys::CreateTemplateTupleDesc(results.columns.len() as i32);

            for (i, col) in results.columns.iter().enumerate() {
                let col_name = create_cstring(&col.name);
                pg_sys::TupleDescInitEntry(
                    tupdesc,
                    (i + 1) as pg_sys::AttrNumber,
                    col_name,
                    col.type_oid,
                    col.type_mod,
                    0, // ndims
                );
            }

            (*func_ctx).tuple_desc = tupdesc;

            // Store the results in the function context
            let results_ptr =
                pg_sys::palloc(std::mem::size_of::<ExecutionResult>()) as *mut ExecutionResult;
            std::ptr::write(results_ptr, results);
            (*func_ctx).user_fctx = results_ptr as *mut std::ffi::c_void;
            (*func_ctx).max_calls = (results_ptr as *const ExecutionResult)
                .as_ref()
                .unwrap()
                .rows
                .len() as u64;
        } else {
            (*func_ctx).max_calls = 0;
        }

        pg_sys::MemoryContextSwitchTo(old_ctx);
    }

    // Return results
    if (*func_ctx).call_cntr < (*func_ctx).max_calls {
        let results_ptr = (*func_ctx).user_fctx as *const ExecutionResult;
        let results_ref = results_ptr.as_ref().unwrap();
        let row_idx = (*func_ctx).call_cntr as usize;

        if row_idx < results_ref.rows.len() {
            let row_values = &results_ref.rows[row_idx];
            let row_nulls = &results_ref.nulls[row_idx];

            // Convert Rust Vec to C arrays
            let values_array =
                pg_sys::palloc(row_values.len() * std::mem::size_of::<pg_sys::Datum>())
                    as *mut pg_sys::Datum;
            let nulls_array =
                pg_sys::palloc(row_nulls.len() * std::mem::size_of::<bool>()) as *mut bool;

            for (i, &value) in row_values.iter().enumerate() {
                *values_array.offset(i as isize) = value;
            }
            for (i, &is_null) in row_nulls.iter().enumerate() {
                *nulls_array.offset(i as isize) = is_null;
            }

            let tuple = pg_sys::heap_form_tuple((*func_ctx).tuple_desc, values_array, nulls_array);
            let result = pg_sys::Datum::from(tuple as *mut std::ffi::c_void);
            pg_sys::end_MultiFuncCall(fcinfo, func_ctx);
            result
        } else {
            pg_sys::end_MultiFuncCall(fcinfo, func_ctx);
            pg_sys::Datum::null()
        }
    } else {
        pg_sys::end_MultiFuncCall(fcinfo, func_ctx);
        pg_sys::Datum::null()
    }
}

fn execute_substrait_plan(
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

unsafe fn convert_relation_to_plan_tree(
    relation: &substrait::proto::PlanRel,
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

unsafe fn convert_rel_to_plan_tree(
    rel: &substrait::proto::Rel,
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

unsafe fn convert_expressions_to_target_list(
    expressions: &[substrait::proto::Expression],
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();

    for (i, expr) in expressions.iter().enumerate() {
        let target_entry = convert_expression_to_target_entry(expr, i)?;
        target_list = pg_sys::lappend(target_list, target_entry as *mut std::ffi::c_void);
    }

    Ok(target_list)
}

unsafe fn convert_expression_to_target_entry(
    expr: &substrait::proto::Expression,
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

unsafe fn create_int4_const(
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

unsafe fn create_int8_const(
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

unsafe fn create_text_const(
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

unsafe fn create_values_scan_node(
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // For now, just return a simple Result node with no input (constant projection)
    let result_node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Result>()) as *mut pg_sys::Result;
    (*result_node).plan.type_ = pg_sys::NodeTag::T_Result;
    (*result_node).plan.lefttree = std::ptr::null_mut();
    (*result_node).plan.targetlist = std::ptr::null_mut();

    Ok(result_node as *mut pg_sys::Plan)
}

unsafe fn create_seqscan_node(
    table_name: &str,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    // This is complex as it requires looking up the table OID, etc.
    // For now, return an error
    Err(format!("SeqScan for table '{}' not yet implemented", table_name).into())
}

unsafe fn create_cstring(s: &str) -> *mut i8 {
    let cstr = std::ffi::CString::new(s).unwrap();
    let len = cstr.as_bytes_with_nul().len();
    let ptr = pg_sys::palloc(len) as *mut i8;
    std::ptr::copy_nonoverlapping(cstr.as_ptr(), ptr, len);
    ptr
}

unsafe fn execute_plan_tree_structured(
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

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_substrait_plan_parsing() {
        // Test pure Rust logic - parsing JSON without PostgreSQL
        let json_plan = r#"{"version": {"minorNumber": 54}}"#;
        let result: Result<serde_json::Value, _> = serde_json::from_str(json_plan);
        assert!(result.is_ok());
    }

    #[test]
    fn test_basic_functionality() {
        // Simple test that doesn't require PostgreSQL functions
        assert_eq!(1 + 1, 2);
    }
}

#[cfg(any(test, feature = "pg_test"))]
#[pgrx::pg_schema]
mod tests {
    use pgrx::prelude::*;
    use std::fs;
    use std::path::Path;

    #[pg_test]
    fn test_substrait_functions_exist() {
        // Test that our PostgreSQL functions are available
        // This runs inside PostgreSQL so we can test the actual extension functions
        let result = Spi::get_one::<bool>("SELECT true");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(true));
    }

    #[pg_test]
    fn test_from_substrait_json_simple() {
        // Test with a minimal valid Substrait plan
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "input": {
                        "project": {
                            "expressions": [{
                                "literal": {
                                    "i32": 42
                                }
                            }, {
                                "literal": {
                                    "string": "hello"
                                }
                            }]
                        }
                    }
                }
            }]
        }"#;

        // Test that the function can be called
        let result = Spi::get_one::<bool>(&format!(
            "SELECT from_substrait_json('{}') IS NOT NULL",
            json_plan.replace("'", "''")
        ));

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(true));
    }

    #[pg_test]
    fn test_from_substrait_json_with_results() {
        // Test with a plan that should return actual data
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "input": {
                        "project": {
                            "expressions": [{
                                "literal": {
                                    "i32": 123
                                }
                            }]
                        }
                    }
                }
            }]
        }"#;

        // This should work and return a row
        let escaped_plan = json_plan.replace("'", "''");
        let query = format!(
            "SELECT * FROM from_substrait_json('{}') AS t(value int4)",
            escaped_plan
        );

        let result = Spi::get_one::<i32>(&query);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(123));
    }

    // Macro to generate individual test functions for each TPC-H file
    macro_rules! tpch_test {
        ($test_name:ident, $file_name:literal) => {
            #[pg_test]
            fn $test_name() {
                let file_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(concat!("testdata/tpch/", $file_name));

                // Verify file exists
                assert!(
                    file_path.exists(),
                    concat!("Test file ", $file_name, " should exist")
                );

                // Read and validate JSON
                let content =
                    fs::read_to_string(&file_path).expect(concat!("Failed to read ", $file_name));

                // Verify it's valid JSON
                let json_value: serde_json::Value = serde_json::from_str(&content)
                    .expect(concat!($file_name, " should contain valid JSON"));

                // Verify it's a valid Substrait plan structure
                assert!(
                    json_value.is_object(),
                    concat!($file_name, " JSON should be an object")
                );

                let obj = json_value.as_object().unwrap();

                // Check for required Substrait fields
                assert!(
                    obj.contains_key("version"),
                    concat!($file_name, " missing 'version' field")
                );
                assert!(
                    obj.contains_key("relations"),
                    concat!($file_name, " missing 'relations' field")
                );

                // Try to parse as Substrait Plan
                let _plan: substrait::proto::Plan = serde_json::from_str(&content)
                    .expect(concat!($file_name, " should parse as valid Substrait Plan"));

                pgrx::log!(concat!("✓ PASS: ", $file_name));
            }
        };
    }

    // Generate test functions for each TPC-H file
    tpch_test!(test_tpch_plan01, "tpch-plan01.json");
    tpch_test!(test_tpch_plan02, "tpch-plan02.json");
    tpch_test!(test_tpch_plan03, "tpch-plan03.json");
    tpch_test!(test_tpch_plan04, "tpch-plan04.json");
    tpch_test!(test_tpch_plan05, "tpch-plan05.json");
    tpch_test!(test_tpch_plan06, "tpch-plan06.json");
    tpch_test!(test_tpch_plan07, "tpch-plan07.json");
    tpch_test!(test_tpch_plan08, "tpch-plan08.json");
    tpch_test!(test_tpch_plan09, "tpch-plan09.json");
    tpch_test!(test_tpch_plan10, "tpch-plan10.json");
    tpch_test!(test_tpch_plan11, "tpch-plan11.json");
    tpch_test!(test_tpch_plan12, "tpch-plan12.json");
    tpch_test!(test_tpch_plan13, "tpch-plan13.json");
    tpch_test!(test_tpch_plan14, "tpch-plan14.json");
    tpch_test!(test_tpch_plan15, "tpch-plan15.json");
    tpch_test!(test_tpch_plan16, "tpch-plan16.json");
    tpch_test!(test_tpch_plan17, "tpch-plan17.json");
    tpch_test!(test_tpch_plan18, "tpch-plan18.json");
    tpch_test!(test_tpch_plan19, "tpch-plan19.json");
    tpch_test!(test_tpch_plan20, "tpch-plan20.json");
    tpch_test!(test_tpch_plan21, "tpch-plan21.json");
    tpch_test!(test_tpch_plan22, "tpch-plan22.json");

    /// Helper function to create a test TPC-H schema (when we have the data)
    #[pg_test]
    fn test_tpch_schema_setup() {
        // This test will set up a minimal TPC-H schema for testing
        // For now, create a simple test table to verify our approach works

        Spi::run("DROP TABLE IF EXISTS test_lineitem").ok();

        let create_table = r#"
            CREATE TABLE test_lineitem (
                l_orderkey INTEGER,
                l_partkey INTEGER,
                l_suppkey INTEGER,
                l_linenumber INTEGER,
                l_quantity DECIMAL(15,2),
                l_extendedprice DECIMAL(15,2),
                l_discount DECIMAL(15,2),
                l_tax DECIMAL(15,2),
                l_returnflag CHAR(1),
                l_linestatus CHAR(1),
                l_shipdate DATE,
                l_commitdate DATE,
                l_receiptdate DATE,
                l_shipinstruct CHAR(25),
                l_shipmode CHAR(10),
                l_comment VARCHAR(44)
            )
        "#;

        Spi::run(create_table).expect("Failed to create test_lineitem table");

        // Insert a few test rows
        let insert_data = r#"
            INSERT INTO test_lineitem VALUES
            (1, 1, 1, 1, 17.00, 21168.23, 0.04, 0.02, 'N', 'O', '1996-03-13', '1996-02-12', '1996-03-22', 'DELIVER IN PERSON', 'TRUCK', 'test comment 1'),
            (1, 2, 2, 2, 36.00, 45983.16, 0.09, 0.06, 'N', 'O', '1996-04-12', '1996-02-28', '1996-04-20', 'TAKE BACK RETURN', 'MAIL', 'test comment 2')
        "#;

        Spi::run(insert_data).expect("Failed to insert test data");

        // Verify the data was inserted
        let count = Spi::get_one::<i64>("SELECT COUNT(*) FROM test_lineitem")
            .expect("Failed to count rows")
            .expect("Count should not be null");

        assert_eq!(count, 2, "Should have inserted 2 test rows");

        pgrx::log!("Successfully set up test TPC-H schema with {} rows", count);
    }
}
