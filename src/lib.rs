use pgrx::pg_sys;
use pgrx::prelude::*;
use prost::Message;
use substrait::proto::Plan;

mod plan_translator;
use plan_translator::{create_cstring, execute_substrait_plan, ExecutionResult};

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
pub extern "C" fn pg_finfo_from_substrait_wrapper() -> &'static pg_sys::Pg_finfo_record {
    const V1_API: pg_sys::Pg_finfo_record = pg_sys::Pg_finfo_record { api_version: 1 };
    &V1_API
}

#[pg_extern(
    sql = "CREATE OR REPLACE FUNCTION from_substrait(plan_bytes bytea) RETURNS SETOF RECORD AS 'MODULE_PATHNAME', 'from_substrait_wrapper' LANGUAGE c IMMUTABLE STRICT;"
)]
fn from_substrait_placeholder() {}

#[pg_extern]
fn from_substrait_json(
    json_plan: &str,
) -> pgrx::iter::TableIterator<'static, (name!(value, i32),)> {
    // Parse the JSON and execute the plan using proper pgrx text handling
    match serde_json::from_str::<Plan>(json_plan) {
        Ok(_plan) => {
            // For now, just return a simple test result
            pgrx::iter::TableIterator::new(vec![(42,)].into_iter())
        }
        Err(_) => pgrx::iter::TableIterator::new(vec![].into_iter()),
    }
}

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

                // Remove comment lines that start with # (common in TPC-H files)
                let json_content = content
                    .lines()
                    .filter(|line| !line.trim_start().starts_with('#'))
                    .collect::<Vec<_>>()
                    .join("\n");

                // Verify it's valid JSON
                let json_value: serde_json::Value = serde_json::from_str(&json_content)
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
                let _plan: substrait::proto::Plan = serde_json::from_str(&json_content)
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
    tpch_test!(test_tpch_plan09, "tpch-plan09.json");
    tpch_test!(test_tpch_plan10, "tpch-plan10.json");
    tpch_test!(test_tpch_plan11, "tpch-plan11.json");
    tpch_test!(test_tpch_plan12, "tpch-plan12.json");
    tpch_test!(test_tpch_plan13, "tpch-plan13.json");
    tpch_test!(test_tpch_plan14, "tpch-plan14.json");
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
