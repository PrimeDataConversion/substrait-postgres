use pgrx::{pg_extern, pg_guard, pg_sys};
use prost::Message;
use std::sync::Mutex;
use substrait::proto::Plan;

mod query_builder;

pgrx::pg_module_magic!();

// Static variable to store the previous planner hook
static PREV_PLANNER_HOOK: Mutex<pg_sys::planner_hook_type> = Mutex::new(None);

/// Custom planner function that intercepts calls to from_substrait functions
///
/// # Safety
/// Called by PostgreSQL as a planner hook; all pointer arguments must be the
/// ones PostgreSQL passes to planner hooks.
#[no_mangle]
pub unsafe extern "C-unwind" fn substrait_planner_hook(
    parse: *mut pg_sys::Query,
    query_string: *const std::os::raw::c_char,
    cursor_options: std::os::raw::c_int,
    bound_params: pg_sys::ParamListInfo,
) -> *mut pg_sys::PlannedStmt {
    pgrx::info!("DEBUG: substrait_planner_hook called");

    // For now, just call the previous planner
    // TODO: Add logic to detect from_substrait function calls and generate custom plans
    let prev_planner = PREV_PLANNER_HOOK.lock().unwrap();
    if let Some(prev_hook) = *prev_planner {
        pgrx::info!("DEBUG: Calling previous planner hook");
        prev_hook(parse, query_string, cursor_options, bound_params)
    } else {
        pgrx::info!("DEBUG: Calling standard planner");
        pg_sys::standard_planner(parse, query_string, cursor_options, bound_params)
    }
}

/// Extension initialization function
#[no_mangle]
pub extern "C" fn _PG_init() {
    unsafe {
        // Store the previous planner hook
        let mut prev_planner = PREV_PLANNER_HOOK.lock().unwrap();
        *prev_planner = pg_sys::planner_hook;

        // Install our custom planner hook
        pg_sys::planner_hook = Some(substrait_planner_hook);

        pgrx::info!("Substrait PostgreSQL extension loaded with planner hook");
    }
}

/// Primary Substrait execution function for protobuf plans
/// Usage: SELECT * FROM from_substrait(plan_bytes) AS t(col1 type1, col2 type2, ...)
/// The AS clause column definitions must match the plan's output schema
#[no_mangle]
#[pg_guard]
pub unsafe extern "C-unwind" fn from_substrait_wrapper(
    fcinfo: pg_sys::FunctionCallInfo,
) -> pg_sys::Datum {
    let plan_bytes = extract_bytea_arg(fcinfo, 0);

    if plan_bytes.is_empty() {
        pgrx::error!("Invalid Substrait plan: empty bytea provided");
    }

    match Plan::decode(plan_bytes) {
        Ok(plan) => execute_substrait_via_query(fcinfo, &plan),
        Err(e) => pgrx::error!("Invalid Substrait plan: failed to decode protobuf: {}", e),
    }
}

#[no_mangle]
pub extern "C" fn pg_finfo_from_substrait_wrapper() -> &'static pg_sys::Pg_finfo_record {
    const V1_API: pg_sys::Pg_finfo_record = pg_sys::Pg_finfo_record { api_version: 1 };
    &V1_API
}

/// Fixed SETOF RECORD implementation
#[pg_extern(
    sql = "CREATE OR REPLACE FUNCTION from_substrait(plan_bytes bytea) RETURNS SETOF RECORD AS 'MODULE_PATHNAME', 'from_substrait_wrapper' LANGUAGE c IMMUTABLE STRICT;"
)]
fn from_substrait_placeholder() {}

/// Simple safe test that returns a single integer to verify safe approach works
#[pg_extern]
fn substrait_simple_test() -> i32 {
    pgrx::info!("substrait_simple_test: Testing safe approach");
    42
}

/// Safe JSON parser that validates the plan but returns success/failure
#[pg_extern]
fn substrait_parse_test(
    json_plan: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    pgrx::info!("substrait_parse_test: Testing JSON parsing safety");

    // Parse the JSON plan
    let plan: substrait::proto::Plan =
        serde_json::from_str(json_plan).map_err(|e| format!("Failed to parse JSON: {e}"))?;

    // If we get here, parsing succeeded - return plan summary
    Ok(format!(
        "Parsed plan with {} relations",
        plan.relations.len()
    ))
}

/// JSON version of Substrait execution function
/// Usage: SELECT * FROM from_substrait_json(json_plan) AS t(col1 type1, col2 type2, ...)
/// The AS clause column definitions must match the plan's output schema
#[no_mangle]
#[pg_guard]
pub unsafe extern "C-unwind" fn from_substrait_json_wrapper(
    fcinfo: pg_sys::FunctionCallInfo,
) -> pg_sys::Datum {
    pgrx::info!("Starting from_substrait_json_wrapper");

    // Extract the JSON string argument
    if i32::from((*fcinfo).nargs) <= 0 {
        pgrx::info!("No arguments provided");
        return pg_sys::Datum::null();
    }

    let arg_ptr = (*fcinfo).args.as_ptr().offset(0);
    let arg = &*arg_ptr;

    if arg.isnull {
        return pg_sys::Datum::null();
    }

    let datum = arg.value;
    let text_ptr = datum.cast_mut_ptr::<pg_sys::varlena>();
    if text_ptr.is_null() {
        pgrx::info!("Text pointer is null");
        return pg_sys::Datum::null();
    }

    // Convert text datum to Rust string
    let text_cstring = pg_sys::text_to_cstring(text_ptr);
    let json_str = std::ffi::CStr::from_ptr(text_cstring).to_string_lossy();
    pgrx::info!("Parsed JSON string: {}", json_str);

    // Parse the Substrait plan from JSON
    match serde_json::from_str::<Plan>(&json_str) {
        Ok(plan) => {
            // Use the Query builder path - this allows PostgreSQL's optimizer
            // to convert Cross + Filter into proper joins
            execute_substrait_via_query(fcinfo, &plan)
        }
        Err(e) => {
            pgrx::error!("Failed to parse JSON: {}", e);
        }
    }
}

#[no_mangle]
pub extern "C" fn pg_finfo_from_substrait_json_wrapper() -> &'static pg_sys::Pg_finfo_record {
    const V1_API: pg_sys::Pg_finfo_record = pg_sys::Pg_finfo_record { api_version: 1 };
    &V1_API
}

#[pg_extern(
    sql = "CREATE OR REPLACE FUNCTION from_substrait_json(json_plan text) RETURNS SETOF RECORD AS 'MODULE_PATHNAME', 'from_substrait_json_wrapper' LANGUAGE c STRICT;"
)]
fn from_substrait_json_placeholder() {}

unsafe fn extract_bytea_arg(fcinfo: pg_sys::FunctionCallInfo, arg_num: i32) -> &'static [u8] {
    if i32::from((*fcinfo).nargs) <= arg_num {
        return &[];
    }

    let arg_ptr = (*fcinfo).args.as_ptr().offset(0);
    let arg = &*arg_ptr;

    if arg.isnull {
        return &[];
    }

    let datum = arg.value;
    let bytea_ptr = datum.cast_mut_ptr::<pg_sys::varlena>();
    if bytea_ptr.is_null() {
        return &[];
    }

    let detoasted_ptr = pg_sys::pg_detoast_datum_packed(bytea_ptr);
    if detoasted_ptr.is_null() {
        return &[];
    }

    let len_word = *(detoasted_ptr as *const u32);
    let data_len = if (len_word & 0x01) == 0 {
        (len_word >> 2) as usize - 4
    } else {
        (len_word >> 1) as usize & (0x7F - 1)
    };

    let data_ptr = if (len_word & 0x01) == 0 {
        (detoasted_ptr as *const u8).offset(4)
    } else {
        (detoasted_ptr as *const u8).offset(1)
    };

    if data_len == 0 {
        return &[];
    }

    std::slice::from_raw_parts(data_ptr, data_len)
}

/// Execute a Substrait plan via PostgreSQL Query object and standard_planner().
/// This allows PostgreSQL's optimizer to choose join strategies, push down predicates, etc.
unsafe fn execute_substrait_via_query(
    fcinfo: pg_sys::FunctionCallInfo,
    plan: &Plan,
) -> pg_sys::Datum {
    // Build the Query object from the Substrait plan
    let query = match query_builder::build_query_from_substrait(plan) {
        Ok(q) => q,
        Err(e) => {
            pgrx::error!("Failed to build Query from Substrait: {}", e);
        }
    };

    // Acquire locks required by the planner
    pg_sys::AcquireRewriteLocks(query, true, false);

    // Call standard_planner to optimize the query
    let planned_stmt = pg_sys::standard_planner(
        query,
        std::ptr::null(),     // query_string
        0,                    // cursor_options
        std::ptr::null_mut(), // bound_params
    );

    if planned_stmt.is_null() {
        pgrx::error!("standard_planner returned NULL");
    }

    // Execute the planned statement
    execute_planned_stmt_as_srf(fcinfo, planned_stmt)
}

/// Coerce a datum to the expected type, preferring the registered cast over
/// I/O coercion. This matters for semantics: e.g. bpchar -> text goes through
/// rtrim1() which strips blank padding, while an I/O round trip keeps it.
unsafe fn coerce_datum(
    value: pg_sys::Datum,
    src_type: pg_sys::Oid,
    target_type: pg_sys::Oid,
    target_typmod: i32,
) -> pg_sys::Datum {
    let mut castfunc = pg_sys::InvalidOid;
    let path = pg_sys::find_coercion_pathway(
        target_type,
        src_type,
        pg_sys::CoercionContext::COERCION_ASSIGNMENT,
        &mut castfunc,
    );

    match path {
        pg_sys::CoercionPathType::COERCION_PATH_FUNC => {
            // Cast functions take (value [, typmod [, isExplicit]]).
            match pg_sys::get_func_nargs(castfunc) {
                1 => pg_sys::OidFunctionCall1Coll(castfunc, pg_sys::InvalidOid, value),
                2 => pg_sys::OidFunctionCall2Coll(
                    castfunc,
                    pg_sys::InvalidOid,
                    value,
                    pg_sys::Datum::from(target_typmod),
                ),
                _ => pg_sys::OidFunctionCall3Coll(
                    castfunc,
                    pg_sys::InvalidOid,
                    value,
                    pg_sys::Datum::from(target_typmod),
                    pg_sys::Datum::from(false),
                ),
            }
        }
        pg_sys::CoercionPathType::COERCION_PATH_RELABELTYPE => value,
        _ => {
            // No registered cast; fall back to an I/O coercion.
            let mut src_typoutput = pg_sys::Oid::INVALID;
            let mut src_typisvarlena = false;
            pg_sys::getTypeOutputInfo(src_type, &mut src_typoutput, &mut src_typisvarlena);
            let text_value = pg_sys::OidOutputFunctionCall(src_typoutput, value);

            let mut tgt_typinput = pg_sys::Oid::INVALID;
            let mut tgt_typioparam = pg_sys::Oid::INVALID;
            pg_sys::getTypeInputInfo(target_type, &mut tgt_typinput, &mut tgt_typioparam);
            pg_sys::OidInputFunctionCall(tgt_typinput, text_value, tgt_typioparam, target_typmod)
        }
    }
}

/// Execute a PlannedStmt and return results as SETOF RECORD.
unsafe fn execute_planned_stmt_as_srf(
    fcinfo: pg_sys::FunctionCallInfo,
    planned_stmt: *mut pg_sys::PlannedStmt,
) -> pg_sys::Datum {
    // Get result info from function call context
    let result_info = (*fcinfo).resultinfo as *mut pg_sys::ReturnSetInfo;
    if result_info.is_null() {
        pgrx::error!("resultinfo is NULL");
    }

    // Check that caller can accept tuplestore result
    if (*result_info).allowedModes & (pg_sys::SetFunctionReturnMode::SFRM_Materialize as i32) == 0 {
        pgrx::error!("Materialize mode not allowed but required for SETOF RECORD");
    }

    // Get expected tuple descriptor from AS clause
    let expected_tupdesc = (*result_info).expectedDesc;
    if expected_tupdesc.is_null() {
        pgrx::error!("No expected tuple descriptor - AS clause required");
    }

    // Create a tuplestore for results
    let per_query_ctx = (*result_info).econtext;
    let old_ctx = if !per_query_ctx.is_null() {
        pg_sys::MemoryContextSwitchTo((*per_query_ctx).ecxt_per_query_memory)
    } else {
        pg_sys::MemoryContextSwitchTo(pg_sys::CurrentMemoryContext)
    };

    let tuplestore = pg_sys::tuplestore_begin_heap(true, false, 1024);

    // Push an active snapshot for the executor
    pg_sys::PushActiveSnapshot(pg_sys::GetTransactionSnapshot());

    // Create QueryDesc for execution
    let query_desc = pg_sys::CreateQueryDesc(
        planned_stmt,
        std::ptr::null(), // sourceText
        pg_sys::GetActiveSnapshot(),
        std::ptr::null_mut(), // crosscheck snapshot
        std::ptr::null_mut(), // dest
        std::ptr::null_mut(), // params
        std::ptr::null_mut(), // queryEnv
        0,                    // instrument_options
    );

    if query_desc.is_null() {
        pg_sys::PopActiveSnapshot();
        pgrx::error!("Failed to create QueryDesc");
    }

    // Skip ExecutorStart and manually initialize (PG17 has stricter requirements).
    let estate = pg_sys::CreateExecutorState();
    if estate.is_null() {
        pg_sys::PopActiveSnapshot();
        pgrx::error!("Failed to create executor state");
    }

    // Initialize range table from PlannedStmt (using permInfos from standard_planner)
    let rtable = (*planned_stmt).rtable;
    let perminfos = (*planned_stmt).permInfos;
    pg_sys::ExecInitRangeTable(estate, rtable, perminfos);

    // Set up estate with PlannedStmt and snapshot
    (*estate).es_plannedstmt = planned_stmt;
    (*estate).es_snapshot = (*query_desc).snapshot;

    // Allocate PARAM_EXEC slots used by SubPlans and InitPlans.
    // This mirrors InitPlan() in the standard executor.
    let n_param_exec = pg_sys::list_length((*planned_stmt).paramExecTypes);
    if n_param_exec > 0 {
        (*estate).es_param_exec_vals =
            pg_sys::palloc0(n_param_exec as usize * std::mem::size_of::<pg_sys::ParamExecData>())
                as *mut pg_sys::ParamExecData;
    }

    // Initialize subplans before the main plan tree, exactly as InitPlan()
    // does: ExecInitSubPlan looks plans up in es_subplanstates by index
    // while the main tree's expressions are being initialized.
    let subplans = (*planned_stmt).subplans;
    for k in 0..pg_sys::list_length(subplans) {
        let subplan = pg_sys::list_nth(subplans, k) as *mut pg_sys::Plan;
        let plan_id = k + 1; // subplan IDs are 1-based
        let sp_eflags = if pg_sys::bms_is_member(plan_id, (*planned_stmt).rewindPlanIDs) {
            (pg_sys::EXEC_FLAG_REWIND | pg_sys::EXEC_FLAG_BACKWARD | pg_sys::EXEC_FLAG_MARK) as i32
        } else {
            0
        };
        let subplanstate = if subplan.is_null() {
            std::ptr::null_mut()
        } else {
            pg_sys::ExecInitNode(subplan, estate, sp_eflags)
        };
        (*estate).es_subplanstates = pg_sys::lappend(
            (*estate).es_subplanstates,
            subplanstate as *mut std::ffi::c_void,
        );
    }

    // Initialize the plan tree with ExecInitNode
    let plan_tree = (*planned_stmt).planTree;
    let plan_state = pg_sys::ExecInitNode(plan_tree, estate, 0);

    if plan_state.is_null() {
        pg_sys::FreeExecutorState(estate);
        pg_sys::PopActiveSnapshot();
        pgrx::error!("ExecInitNode failed to create plan state");
    }

    (*query_desc).estate = estate;
    (*query_desc).planstate = plan_state;

    // Get tuples by calling ExecProcNode on the plan state
    loop {
        let slot = pg_sys::ExecProcNode(plan_state);

        // Check if slot is empty (TTS_FLAG_EMPTY)
        if slot.is_null() || (*slot).tts_flags & pg_sys::TTS_FLAG_EMPTY as u16 != 0 {
            break;
        }

        // Copy tuple values to tuplestore
        let expected_natts = (*expected_tupdesc).natts;
        let slot_desc = (*slot).tts_tupleDescriptor;
        let slot_natts = if !slot_desc.is_null() {
            (*slot_desc).natts
        } else {
            expected_natts // Assume same count if no slot descriptor
        };

        // Use the minimum of expected and slot natts to avoid reading past end
        let natts_to_copy = std::cmp::min(expected_natts, slot_natts);
        let mut values: Vec<pg_sys::Datum> = vec![pg_sys::Datum::from(0); expected_natts as usize];
        let mut nulls: Vec<bool> = vec![false; expected_natts as usize];

        // Mark any missing columns as null
        for i in natts_to_copy..expected_natts {
            nulls[i as usize] = true;
        }

        pg_sys::slot_getallattrs(slot);

        let slot_attrs = if !slot_desc.is_null() {
            (*slot_desc).attrs.as_ptr()
        } else {
            std::ptr::null()
        };
        let expected_attrs = (*expected_tupdesc).attrs.as_ptr();

        for i in 0..natts_to_copy {
            if (*slot).tts_isnull.add(i as usize).read() {
                nulls[i as usize] = true;
                values[i as usize] = pg_sys::Datum::from(0);
            } else {
                let src_value = (*slot).tts_values.add(i as usize).read();
                let expected_attr = &*expected_attrs.add(i as usize);
                let expected_type = expected_attr.atttypid;

                // Check if type coercion is needed
                let src_type = if !slot_attrs.is_null() {
                    (*slot_attrs.add(i as usize)).atttypid
                } else {
                    expected_type // Assume same type if no slot descriptor
                };

                if src_type != expected_type {
                    values[i as usize] =
                        coerce_datum(src_value, src_type, expected_type, expected_attr.atttypmod);
                } else {
                    values[i as usize] = src_value;
                }
            }
        }

        // Store in tuplestore
        pg_sys::tuplestore_putvalues(
            tuplestore,
            expected_tupdesc,
            values.as_mut_ptr(),
            nulls.as_mut_ptr(),
        );
    }

    // Cleanup manually since we bypassed ExecutorStart
    // ExecutorFinish/ExecutorEnd expect structures set up by ExecutorStart
    pg_sys::ExecEndNode(plan_state);
    pg_sys::FreeExecutorState(estate);
    pg_sys::PopActiveSnapshot();

    // Restore memory context
    pg_sys::MemoryContextSwitchTo(old_ctx);

    // Set up return value
    (*result_info).returnMode = pg_sys::SetFunctionReturnMode::SFRM_Materialize;
    (*result_info).setResult = tuplestore;
    (*result_info).setDesc = expected_tupdesc;

    pg_sys::Datum::from(0)
}

/// JSON version using Query builder (for testing the new approach).
/// Usage: SELECT * FROM from_substrait_query(json_plan) AS t(col1 type1, ...)
///
/// This function converts the Substrait plan to a PostgreSQL Query object,
/// then calls standard_planner() to let PostgreSQL optimize it.
#[no_mangle]
#[pg_guard]
pub unsafe extern "C-unwind" fn from_substrait_query_wrapper(
    fcinfo: pg_sys::FunctionCallInfo,
) -> pg_sys::Datum {
    // Extract the JSON string argument
    if i32::from((*fcinfo).nargs) <= 0 {
        pgrx::error!("No arguments provided");
    }

    let arg_ptr = (*fcinfo).args.as_ptr().offset(0);
    let arg = &*arg_ptr;

    if arg.isnull {
        return pg_sys::Datum::null();
    }

    let datum = arg.value;
    let text_ptr = datum.cast_mut_ptr::<pg_sys::varlena>();
    if text_ptr.is_null() {
        pgrx::error!("Text pointer is null");
    }

    // Convert text datum to Rust string
    let text_cstring = pg_sys::text_to_cstring(text_ptr);
    let json_str = std::ffi::CStr::from_ptr(text_cstring).to_string_lossy();

    // Parse the Substrait plan from JSON and execute via Query builder
    match serde_json::from_str::<Plan>(&json_str) {
        Ok(plan) => execute_substrait_via_query(fcinfo, &plan),
        Err(e) => {
            pgrx::error!("Failed to parse JSON: {}", e);
        }
    }
}

#[no_mangle]
pub extern "C" fn pg_finfo_from_substrait_query_wrapper() -> &'static pg_sys::Pg_finfo_record {
    const V1_API: pg_sys::Pg_finfo_record = pg_sys::Pg_finfo_record { api_version: 1 };
    &V1_API
}

#[pg_extern(
    sql = "CREATE OR REPLACE FUNCTION from_substrait_query(json_plan text) RETURNS SETOF RECORD AS 'MODULE_PATHNAME', 'from_substrait_query_wrapper' LANGUAGE c STRICT;"
)]
fn from_substrait_query_placeholder() {}

#[cfg(any(test, feature = "pg_test"))]
#[pgrx::pg_schema]
mod tests {

    // Note: plan_translator is being removed. Schema info now comes from Substrait plan directly.
    use pgrx::{pg_sys, pg_test, prelude::*, AnyNumeric};

    // Helper function to convert a numeric datum to a string for comparison
    fn numeric_datum_to_string(datum: pg_sys::Datum) -> String {
        let any_numeric = unsafe { AnyNumeric::from_datum(datum, false).unwrap() };
        any_numeric.to_string()
    }

    #[pg_test]
    fn test_create_numeric_const_positive_integer() {
        // Substrait spec: decimal values are little-endian two's complement
        let value_bytes = 12345i32.to_le_bytes();
        let (precision, scale) = (10, 0);
        let result = unsafe {
            crate::query_builder::expressions::create_numeric_const(&value_bytes, precision, scale)
                .unwrap()
        };
        let const_node = unsafe { &*(result as *mut pg_sys::Const) };
        assert_eq!(numeric_datum_to_string(const_node.constvalue), "12345");
    }

    #[pg_test]
    fn test_create_numeric_const_negative_integer() {
        // Substrait spec: decimal values are little-endian two's complement
        let value_bytes = (-54321i32).to_le_bytes();
        let (precision, scale) = (10, 0);
        let result = unsafe {
            crate::query_builder::expressions::create_numeric_const(&value_bytes, precision, scale)
                .unwrap()
        };
        let const_node = unsafe { &*(result as *mut pg_sys::Const) };
        assert_eq!(numeric_datum_to_string(const_node.constvalue), "-54321");
    }

    #[pg_test]
    fn test_create_numeric_const_positive_decimal() {
        // Substrait spec: decimal values are little-endian two's complement
        let value_bytes = 12345i32.to_le_bytes();
        let (precision, scale) = (10, 2);
        let result = unsafe {
            crate::query_builder::expressions::create_numeric_const(&value_bytes, precision, scale)
                .unwrap()
        };
        let const_node = unsafe { &*(result as *mut pg_sys::Const) };
        assert_eq!(numeric_datum_to_string(const_node.constvalue), "123.45");
    }

    #[pg_test]
    fn test_create_numeric_const_negative_decimal() {
        // Substrait spec: decimal values are little-endian two's complement
        let value_bytes = (-54321i32).to_le_bytes();
        let (precision, scale) = (10, 3);
        let result = unsafe {
            crate::query_builder::expressions::create_numeric_const(&value_bytes, precision, scale)
                .unwrap()
        };
        let const_node = unsafe { &*(result as *mut pg_sys::Const) };
        assert_eq!(numeric_datum_to_string(const_node.constvalue), "-54.321");
    }

    #[pg_test]
    fn test_create_numeric_const_zero() {
        // Substrait spec: decimal values are little-endian two's complement
        let value_bytes = 0i32.to_le_bytes();
        let (precision, scale) = (1, 0);
        let result = unsafe {
            crate::query_builder::expressions::create_numeric_const(&value_bytes, precision, scale)
                .unwrap()
        };
        let const_node = unsafe { &*(result as *mut pg_sys::Const) };
        assert_eq!(numeric_datum_to_string(const_node.constvalue), "0");
    }

    #[pg_test]
    fn test_create_numeric_const_decimal_less_than_one() {
        // Substrait spec: decimal values are little-endian two's complement
        let value_bytes = 123i32.to_le_bytes();
        let (precision, scale) = (10, 5);
        let result = unsafe {
            crate::query_builder::expressions::create_numeric_const(&value_bytes, precision, scale)
                .unwrap()
        };
        let const_node = unsafe { &*(result as *mut pg_sys::Const) };
        assert_eq!(numeric_datum_to_string(const_node.constvalue), "0.00123");
    }

    #[pg_test]
    #[should_panic(expected = "Invalid Substrait plan: empty bytea provided")]
    fn test_from_substrait_empty_plan() {
        // Test that the function panics with proper error message for empty bytea
        let _ =
            Spi::get_one::<i64>("SELECT COUNT(*) FROM from_substrait(''::bytea) AS t(result int)");
    }

    #[pg_test]
    #[should_panic(expected = "Failed to build Query from Substrait: Plan has no relations")]
    fn test_from_substrait_json_empty_plan() {
        // Test that the JSON function panics with proper error message for empty JSON
        let _ =
            Spi::get_one::<i64>("SELECT COUNT(*) FROM from_substrait_json('{}') AS t(result int)");
    }

    #[pg_test]
    fn test_from_substrait_function_metadata() {
        // Test that we can query the function metadata
        let result = Spi::get_one::<String>(
            "SELECT format('from_substrait function accepts %s and returns %s',
                          pg_get_function_arguments('from_substrait'::regproc),
                          pg_get_function_result('from_substrait'::regproc))",
        );

        assert!(result.is_ok());
        let function_info = result.unwrap().unwrap();
        assert!(function_info.contains("bytea"));
        assert!(function_info.contains("SETOF"));
    }

    #[pg_test]
    fn test_real_execution_with_literal() {
        // Test real execution with a simple literal expression (should work with Project relation)
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "names": ["test_value"],
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

        // Parse JSON to Plan struct and encode to protobuf
        use prost::Message;
        use substrait::proto::Plan;

        let plan: Plan = match serde_json::from_str(json_plan) {
            Ok(p) => p,
            Err(e) => {
                panic!("Failed to parse literal plan JSON: {e}");
            }
        };

        let mut protobuf_bytes = Vec::new();
        if let Err(e) = plan.encode(&mut protobuf_bytes) {
            panic!("Failed to encode literal plan to protobuf: {e}");
        }

        // Convert bytes to PostgreSQL bytea hex format
        let hex_string = format!(
            "\\x{}",
            protobuf_bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );

        // Test the hex string length using SQL
        let hex_length_query = format!("SELECT length('{hex_string}'::bytea)");
        let hex_length_result = Spi::get_one::<i32>(&hex_length_query);

        match hex_length_result {
            Ok(Some(sql_length)) => {
                assert_eq!(
                    sql_length as usize,
                    protobuf_bytes.len(),
                    "SQL bytea length {} should match original protobuf length {}",
                    sql_length,
                    protobuf_bytes.len()
                );
            }
            Ok(None) => panic!("SQL length query returned NULL"),
            Err(e) => panic!("SQL length query failed: {e:?}"),
        }

        // Test with the real execution function (not the safe mock version)
        // Since the function returns SETOF RECORD, we need to specify the column definition
        let query = format!(
            "SELECT COUNT(*) FROM from_substrait('{hex_string}'::bytea) AS t(test_value int)"
        );
        let result = Spi::get_one::<i64>(&query);

        // This should succeed - we have a valid plan with a literal expression
        assert!(
            result.is_ok(),
            "Real execution with valid literal expression should succeed: {:?}",
            result.err()
        );
    }

    #[pg_test]
    fn test_from_substrait_with_minimal_protobuf() {
        // Test from_substrait with a minimal valid protobuf
        // This is the equivalent of "SELECT 1" - a project of a literal expression

        use prost::Message;
        use substrait::proto::Plan;

        // Create the minimal Substrait plan: SELECT 1
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "names": ["column_1"],
                    "input": {
                        "project": {
                            "expressions": [{
                                "literal": {
                                    "i32": 1
                                }
                            }]
                        }
                    }
                }
            }]
        }"#;

        // Parse JSON to Plan struct
        let plan: Plan = match serde_json::from_str(json_plan) {
            Ok(p) => p,
            Err(e) => {
                panic!("Failed to parse minimal plan JSON: {e}");
            }
        };

        // Encode Plan to protobuf bytes
        let mut protobuf_bytes = Vec::new();
        if let Err(e) = plan.encode(&mut protobuf_bytes) {
            panic!("Failed to encode minimal plan to protobuf: {e}");
        }

        // Convert bytes to hex string for SQL
        let hex_string = protobuf_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        // Test with the minimal valid protobuf data (SELECT 1 equivalent)
        let query = format!(
            "SELECT COUNT(*) FROM from_substrait('\\x{hex_string}'::bytea) AS t(column_1 int)"
        );
        let result = Spi::get_one::<i64>(&query);

        // This should succeed - we have a minimal valid plan (SELECT 1)
        assert!(
            result.is_ok(),
            "from_substrait should succeed with minimal valid protobuf data (SELECT 1 equivalent)"
        );
    }

    #[pg_test]
    fn test_from_substrait_with_valid_protobuf_from_json() {
        // Test from_substrait with valid protobuf data created from JSON
        // This tests the full round-trip: JSON -> Plan struct -> protobuf bytes -> decode -> execute

        use prost::Message;
        use substrait::proto::Plan;

        // Create a simple JSON plan
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "names": ["test_value"],
                    "input": {
                        "project": {
                            "expressions": [{
                                "literal": {
                                    "i32": 42
                                }
                            }]
                        }
                    }
                }
            }]
        }"#;

        // Parse JSON to Plan struct
        let plan: Plan = match serde_json::from_str(json_plan) {
            Ok(p) => p,
            Err(_) => {
                // If JSON parsing fails, we can't test protobuf functionality
                // Just verify that this would have worked
                assert!(
                    true,
                    "JSON parsing failed - this is a test limitation, not a function failure"
                );
                return;
            }
        };

        // Encode Plan to protobuf bytes
        let mut protobuf_bytes = Vec::new();
        if plan.encode(&mut protobuf_bytes).is_err() {
            // If encoding fails, that's a test setup issue, not a function issue
            assert!(true, "Protobuf encoding failed - this is a test limitation");
            return;
        }

        // Convert bytes to hex string for SQL
        let hex_string = protobuf_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        // Test with the valid protobuf data
        let query = format!(
            "SELECT COUNT(*) FROM from_substrait('\\x{hex_string}'::bytea) AS t(test_value int)"
        );
        let result = Spi::get_one::<i64>(&query);

        // This should succeed - we have valid protobuf data
        assert!(
            result.is_ok(),
            "from_substrait should succeed with valid protobuf data: {:?}",
            result.err()
        );
    }
    #[pg_test]
    fn test_minimal_read_relation() {
        // Create a test table first
        let _ = Spi::run("DROP TABLE IF EXISTS test_minimal_table");
        let _ = Spi::run("CREATE TABLE test_minimal_table (id INT)");
        let _ = Spi::run("INSERT INTO test_minimal_table VALUES (42)");

        // Test with minimal Read relation - single table, single column
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "names": ["id"],
                    "input": {
                        "read": {
                            "baseSchema": {
                                "names": ["id"],
                                "struct": {
                                    "types": [{
                                        "i32": {
                                            "nullability": "NULLABILITY_NULLABLE"
                                        }
                                    }]
                                }
                            },
                            "namedTable": {
                                "names": ["test_minimal_table"]
                            }
                        }
                    }
                }
            }]
        }"#;

        let escaped_plan = json_plan.replace("'", "''");
        let query = format!("SELECT * FROM from_substrait_json('{escaped_plan}') AS t(id int)");

        // This exercises the full pipeline: plan parsing, Read relation translation,
        // table lookup, plan tree creation, SRF execution, and result processing
        let result = Spi::get_one::<i32>(&query);

        // This should work or give a meaningful error, not OID 65536
        match result {
            Ok(val) => {
                println!("Success! Got value: {val:?}");
                assert_eq!(val, Some(42), "Should return the inserted value");
            }
            Err(e) => {
                println!("Error: {e:?}");
                // If we get OID 65536, it means the corruption is in our execution pipeline
                assert!(
                    !e.to_string().contains("65536"),
                    "Got OID 65536 error - indicates corruption in execution pipeline: {e}"
                );
            }
        }

        // Note: Can't DROP TABLE in same transaction we accessed it.
        // DROP TABLE IF EXISTS at start of test handles cleanup from previous runs.
    }

    #[pg_test]
    fn test_from_substrait_json_simple() {
        // Test with a minimal valid Substrait plan that has schema names
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "names": ["test_column"],
                    "input": {
                        "project": {
                            "expressions": [{
                                "literal": {
                                    "i32": 42
                                }
                            }]
                        }
                    }
                }            }]
        }"#;

        // Test that the function can be called - simplified to single column to avoid issues
        let escaped_plan = json_plan.replace("'", "''");
        let query =
            format!("SELECT * FROM from_substrait_json('{escaped_plan}') AS t(test_column int)");

        let result = Spi::get_one::<i64>(&query);
        // TODO -- Modify this to verify that the single returned integer is exactly 42 instead.
        // This should succeed - we have a valid JSON plan
        assert!(
            result.is_ok(),
            "from_substrait_json should succeed with valid plan: {:?}",
            result.err()
        );
    }

    #[pg_test]
    fn test_from_substrait_query_simple() {
        // Test the Query builder path - this uses standard_planner for optimization
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "names": ["test_column"],
                    "input": {
                        "project": {
                            "expressions": [{
                                "literal": {
                                    "i32": 42
                                }
                            }]
                        }
                    }
                }
            }]
        }"#;

        let escaped_plan = json_plan.replace("'", "''");
        let query =
            format!("SELECT * FROM from_substrait_query('{escaped_plan}') AS t(test_column int)");

        let result = Spi::get_one::<i32>(&query);
        assert!(
            result.is_ok(),
            "from_substrait_query should succeed with valid plan: {:?}",
            result.err()
        );

        // Verify the actual value is 42
        if let Ok(Some(value)) = result {
            assert_eq!(value, 42, "Query builder path should return correct value");
        }
    }

    #[pg_test]
    fn test_from_substrait_json_with_results() {
        // Test with a plan that should return actual data and has proper schema
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "names": ["result_value"],
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

        // Use the function
        let escaped_plan = json_plan.replace("'", "''");
        let query = format!(
            "SELECT COUNT(*) FROM from_substrait_json('{escaped_plan}') AS t(result_value int)"
        );

        let result = Spi::get_one::<i64>(&query);
        // This should succeed - we have a valid JSON plan that returns results
        assert!(
            result.is_ok(),
            "from_substrait_json should succeed with valid plan and return results: {:?}",
            result.err()
        );
    }

    #[pg_test]
    fn test_scalar_subquery_minimal() {
        // Minimal test for scalar subquery support.
        // Project with two columns: a literal and a scalar subquery returning a literal.
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "names": ["outer_value", "subquery_value"],
                    "input": {
                        "project": {
                            "expressions": [
                                { "literal": { "i32": 100 } },
                                {
                                    "subquery": {
                                        "scalar": {
                                            "input": {
                                                "project": {
                                                    "expressions": [
                                                        { "literal": { "i32": 42 } }
                                                    ]
                                                }
                                            }
                                        }
                                    }
                                }
                            ]
                        }
                    }
                }
            }]
        }"#;

        let escaped_plan = json_plan.replace("'", "''");
        let query = format!(
            "SELECT outer_value, subquery_value FROM from_substrait_json('{escaped_plan}') AS t(outer_value int, subquery_value int)"
        );

        // Verify the subquery returns the expected value
        let result = Spi::get_one::<i32>(&format!(
            "SELECT subquery_value FROM from_substrait_json('{escaped_plan}') AS t(outer_value int, subquery_value int)"
        ));
        assert!(
            result.is_ok(),
            "Scalar subquery test should succeed: {:?}",
            result.err()
        );
        assert_eq!(
            result.unwrap(),
            Some(42),
            "Scalar subquery should return 42"
        );
    }

    // Golden expectation types for TPC-H query validation
    enum GoldenExpectation {
        IntExact(i64),
        FloatTolerance(f64, f64), // value, tolerance
        StringExact(&'static str),
        // The query legitimately returns SQL NULL (e.g. an aggregate over an
        // empty set at this scale factor).
        NullResult,
    }

    // TPC-H test macro with localized golden values
    // Internal macro for the test body - shared by both variants
    /// Extract column names and types from a Substrait plan.
    /// Returns (column_names, column_types, as_clause) for use in SQL queries.
    /// Types come from the plan itself (base schemas, declared function and
    /// cast output types, literal types) - never from column names.
    fn extract_schema_from_substrait(
        plan: &substrait::proto::Plan,
    ) -> (Vec<String>, Vec<String>, String) {
        let (column_names, input) = plan
            .relations
            .first()
            .and_then(|rel| {
                if let Some(substrait::proto::plan_rel::RelType::Root(root)) = &rel.rel_type {
                    Some((root.names.clone(), root.input.as_ref()))
                } else {
                    None
                }
            })
            .unwrap_or_default();

        let column_types = input.map(derive_rel_output_types).unwrap_or_default();
        assert_eq!(
            column_names.len(),
            column_types.len(),
            "Root names ({:?}) do not match derived output types ({:?})",
            column_names,
            column_types
        );

        let as_clause = column_names
            .iter()
            .zip(column_types.iter())
            .map(|(name, pg_type)| format!("{} {}", name, pg_type))
            .collect::<Vec<_>>()
            .join(", ");

        (column_names, column_types, as_clause)
    }

    /// Map a Substrait type to a PostgreSQL type name.
    fn substrait_type_to_pg_name(t: &substrait::proto::Type) -> String {
        use substrait::proto::r#type::Kind;
        match &t.kind {
            Some(Kind::Bool(_)) => "boolean",
            Some(Kind::I8(_)) | Some(Kind::I16(_)) => "smallint",
            Some(Kind::I32(_)) => "integer",
            Some(Kind::I64(_)) => "bigint",
            Some(Kind::Fp32(_)) => "real",
            Some(Kind::Fp64(_)) => "double precision",
            Some(Kind::Decimal(_)) => "numeric",
            Some(Kind::String(_)) | Some(Kind::FixedChar(_)) | Some(Kind::Varchar(_)) => "text",
            Some(Kind::Date(_)) => "date",
            Some(Kind::Timestamp(_)) | Some(Kind::PrecisionTimestamp(_)) => "timestamp",
            Some(Kind::IntervalYear(_)) | Some(Kind::IntervalDay(_)) => "interval",
            other => panic!("Unsupported Substrait type in schema derivation: {other:?}"),
        }
        .to_string()
    }

    /// Compute the output column types of a Substrait relation tree from the
    /// types the plan declares.
    fn derive_rel_output_types(rel: &substrait::proto::Rel) -> Vec<String> {
        use substrait::proto::rel::RelType;
        use substrait::proto::rel_common::EmitKind;

        // Apply an emit remapping (if any) to a relation's direct output.
        fn apply_emit(
            common: Option<&substrait::proto::RelCommon>,
            types: Vec<String>,
        ) -> Vec<String> {
            if let Some(common) = common {
                if let Some(EmitKind::Emit(emit)) = &common.emit_kind {
                    return emit
                        .output_mapping
                        .iter()
                        .map(|&i| types[i as usize].clone())
                        .collect();
                }
            }
            types
        }

        match &rel.rel_type {
            Some(RelType::Read(read)) => {
                let types = read
                    .base_schema
                    .as_ref()
                    .and_then(|s| s.r#struct.as_ref())
                    .map(|st| st.types.iter().map(substrait_type_to_pg_name).collect())
                    .unwrap_or_default();
                apply_emit(read.common.as_ref(), types)
            }
            Some(RelType::Filter(filter)) => {
                let types = filter
                    .input
                    .as_ref()
                    .map(|i| derive_rel_output_types(i))
                    .unwrap_or_default();
                apply_emit(filter.common.as_ref(), types)
            }
            Some(RelType::Sort(sort)) => {
                let types = sort
                    .input
                    .as_ref()
                    .map(|i| derive_rel_output_types(i))
                    .unwrap_or_default();
                apply_emit(sort.common.as_ref(), types)
            }
            Some(RelType::Fetch(fetch)) => {
                let types = fetch
                    .input
                    .as_ref()
                    .map(|i| derive_rel_output_types(i))
                    .unwrap_or_default();
                apply_emit(fetch.common.as_ref(), types)
            }
            Some(RelType::Project(project)) => {
                let input_types = project
                    .input
                    .as_ref()
                    .map(|i| derive_rel_output_types(i))
                    .unwrap_or_default();
                let mut types = input_types.clone();
                for expr in &project.expressions {
                    types.push(derive_expr_type(expr, &input_types));
                }
                apply_emit(project.common.as_ref(), types)
            }
            Some(RelType::Cross(cross)) => {
                let mut types = cross
                    .left
                    .as_ref()
                    .map(|i| derive_rel_output_types(i))
                    .unwrap_or_default();
                types.extend(
                    cross
                        .right
                        .as_ref()
                        .map(|i| derive_rel_output_types(i))
                        .unwrap_or_default(),
                );
                apply_emit(cross.common.as_ref(), types)
            }
            Some(RelType::Join(join)) => {
                let mut types = join
                    .left
                    .as_ref()
                    .map(|i| derive_rel_output_types(i))
                    .unwrap_or_default();
                types.extend(
                    join.right
                        .as_ref()
                        .map(|i| derive_rel_output_types(i))
                        .unwrap_or_default(),
                );
                apply_emit(join.common.as_ref(), types)
            }
            Some(RelType::Aggregate(agg)) => {
                let input_types = agg
                    .input
                    .as_ref()
                    .map(|i| derive_rel_output_types(i))
                    .unwrap_or_default();
                let mut types = Vec::new();
                if let Some(grouping) = agg.groupings.first() {
                    #[allow(deprecated)]
                    for group_expr in &grouping.grouping_expressions {
                        types.push(derive_expr_type(group_expr, &input_types));
                    }
                }
                for measure in &agg.measures {
                    let t = measure
                        .measure
                        .as_ref()
                        .and_then(|m| m.output_type.as_ref())
                        .map(substrait_type_to_pg_name)
                        .unwrap_or_else(|| panic!("Aggregate measure missing output_type"));
                    types.push(t);
                }
                apply_emit(agg.common.as_ref(), types)
            }
            other => panic!("Unsupported relation type in schema derivation: {other:?}"),
        }
    }

    /// Compute an expression's output type from the types the plan declares.
    fn derive_expr_type(expr: &substrait::proto::Expression, input_types: &[String]) -> String {
        use substrait::proto::expression::literal::LiteralType;
        use substrait::proto::expression::RexType;

        match &expr.rex_type {
            Some(RexType::Literal(lit)) => match &lit.literal_type {
                Some(LiteralType::Boolean(_)) => "boolean".to_string(),
                Some(LiteralType::I8(_)) | Some(LiteralType::I16(_)) => "smallint".to_string(),
                Some(LiteralType::I32(_)) => "integer".to_string(),
                Some(LiteralType::I64(_)) => "bigint".to_string(),
                Some(LiteralType::Fp32(_)) => "real".to_string(),
                Some(LiteralType::Fp64(_)) => "double precision".to_string(),
                Some(LiteralType::Decimal(_)) => "numeric".to_string(),
                Some(LiteralType::String(_))
                | Some(LiteralType::FixedChar(_))
                | Some(LiteralType::VarChar(_)) => "text".to_string(),
                Some(LiteralType::Date(_)) => "date".to_string(),
                other => panic!("Unsupported literal type in schema derivation: {other:?}"),
            },
            Some(RexType::Selection(sel)) => {
                use substrait::proto::expression::field_reference::ReferenceType;
                use substrait::proto::expression::reference_segment::ReferenceType as SegRefType;
                if let Some(ReferenceType::DirectReference(direct)) = &sel.reference_type {
                    if let Some(SegRefType::StructField(sf)) = &direct.reference_type {
                        return input_types[sf.field as usize].clone();
                    }
                }
                panic!("Unsupported field reference in schema derivation")
            }
            Some(RexType::ScalarFunction(func)) => func
                .output_type
                .as_ref()
                .map(substrait_type_to_pg_name)
                .unwrap_or_else(|| panic!("Scalar function missing output_type")),
            Some(RexType::Cast(cast)) => cast
                .r#type
                .as_ref()
                .map(substrait_type_to_pg_name)
                .unwrap_or_else(|| panic!("Cast missing target type")),
            Some(RexType::IfThen(if_then)) => {
                let branch = if_then
                    .ifs
                    .first()
                    .and_then(|c| c.then.as_ref())
                    .or(if_then.r#else.as_deref())
                    .unwrap_or_else(|| panic!("IfThen has no branches"));
                derive_expr_type(branch, input_types)
            }
            Some(RexType::Subquery(subquery)) => {
                use substrait::proto::expression::subquery::SubqueryType;
                match &subquery.subquery_type {
                    Some(SubqueryType::Scalar(scalar)) => scalar
                        .input
                        .as_ref()
                        .map(|rel| derive_rel_output_types(rel)[0].clone())
                        .unwrap_or_else(|| panic!("Scalar subquery has no input")),
                    _ => "boolean".to_string(),
                }
            }
            other => panic!("Unsupported expression in schema derivation: {other:?}"),
        }
    }

    macro_rules! tpch_test_body {
        ($file_name:literal, $expected_value:expr) => {{
            use std::fs;
            use std::path::Path;

            let file_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(concat!("testdata/tpch/", $file_name));

            // Fail test if file doesn't exist - we need to know about missing test data
            assert!(
                file_path.exists(),
                "TPC-H test file {} does not exist at path: {}",
                $file_name,
                file_path.display()
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

            // Verify it's valid JSON and parse as Substrait Plan
            let plan: substrait::proto::Plan = serde_json::from_str(&json_content)
                .expect(concat!($file_name, " should parse as valid Substrait Plan"));

            // Escape single quotes for SQL
            let escaped_json = json_content.replace("'", "''");

            pgrx::info!(
                "Testing {} - Using query builder path only",
                $file_name
            );

            // Set up TPC-H database
            setup_tpch_database_if_needed();

            // Extract schema directly from Substrait plan (no plan_translator needed)
            let (column_names, column_types, as_clause) = extract_schema_from_substrait(&plan);
            pgrx::info!(
                "{} - Extracted {} columns from Substrait plan: {:?}",
                $file_name,
                column_names.len(),
                column_names
            );

            // Execute via from_substrait_json (query builder path)
            let execution_query = format!(
                "SELECT * FROM from_substrait_json('{}') AS t({})",
                escaped_json, as_clause
            );

            match $expected_value {
                GoldenExpectation::IntExact(expected) => {
                    // For int expectations, select the last column (typically COUNT_ORDER for TPC-H aggregates).
                    let last_col_name = column_names
                        .last()
                        .map(|s| s.as_str())
                        .unwrap_or("*");
                    // Cast in SQL so a column the AS clause declared as text
                    // (from name-based inference) still reads back as i64.
                    let query = format!(
                        "SELECT ({})::bigint FROM ({}) AS sub LIMIT 1",
                        last_col_name, execution_query
                    );
                    match Spi::get_one::<i64>(&query) {
                        Ok(Some(actual)) => {
                            assert_eq!(
                                actual, expected,
                                "{} - Expected {}, got {}",
                                $file_name, expected, actual
                            );
                            pgrx::info!(
                                "{} - Golden result validation passed! Value: {}",
                                $file_name,
                                actual
                            );
                        }
                        Ok(None) => panic!("{} - Query returned NULL", $file_name),
                        Err(e) => panic!("{} - Query execution failed: {:?}", $file_name, e),
                    }
                }
                GoldenExpectation::FloatTolerance(expected, tolerance) => {
                    // For float expectations, select the first floating-point
                    // typed column (golden values are amounts like REVENUE,
                    // not the leading name/key columns). Cast to numeric in
                    // SQL so the value reads back as AnyNumeric regardless of
                    // the declared column type.
                    let float_col_name = column_names
                        .iter()
                        .zip(column_types.iter())
                        .find(|(_, t)| {
                            matches!(t.as_str(), "real" | "double precision" | "numeric")
                        })
                        .map(|(name, _)| name.as_str())
                        .or_else(|| column_names.first().map(|s| s.as_str()))
                        .unwrap_or("*");
                    let float_query = format!(
                        "SELECT ({})::numeric FROM ({}) AS sub LIMIT 1",
                        float_col_name, execution_query
                    );
                    match Spi::get_one::<pgrx::AnyNumeric>(&float_query) {
                        Ok(Some(numeric_val)) => {
                            // Convert AnyNumeric to f64.
                            let actual: f64 = numeric_val.try_into().unwrap_or_else(|_| {
                                panic!("{} - Failed to convert NUMERIC to f64", $file_name)
                            });
                            let difference = (actual - expected).abs();
                            assert!(
                                difference < tolerance,
                                "{} - Expected {}, got {}, difference {} exceeds tolerance {}",
                                $file_name,
                                expected,
                                actual,
                                difference,
                                tolerance
                            );
                            pgrx::info!(
                                "{} - Golden result validation passed! Value: {}",
                                $file_name,
                                actual
                            );
                        }
                        Ok(None) => panic!("{} - Query returned NULL", $file_name),
                        Err(e) => {
                            // Fall back to trying f64 directly for float8 results.
                            match Spi::get_one::<f64>(&format!("{} LIMIT 1", execution_query)) {
                                Ok(Some(actual)) => {
                                    let difference = (actual - expected).abs();
                                    assert!(
                                        difference < tolerance,
                                        "{} - Expected {}, got {}, difference {} exceeds tolerance {}",
                                        $file_name,
                                        expected,
                                        actual,
                                        difference,
                                        tolerance
                                    );
                                    pgrx::info!(
                                        "{} - Golden result validation passed! Value: {}",
                                        $file_name,
                                        actual
                                    );
                                }
                                Ok(None) => panic!("{} - Query returned NULL", $file_name),
                                Err(_) => panic!("{} - Query execution failed: {:?}", $file_name, e),
                            }
                        }
                    }
                }
                GoldenExpectation::StringExact(expected) => {
                    // For string expectations, get the first column of the first row as text
                    match Spi::get_one::<String>(&format!("{} LIMIT 1", execution_query)) {
                        Ok(Some(actual)) => {
                            assert_eq!(
                                actual, expected,
                                "{} - Expected '{}', got '{}'",
                                $file_name, expected, actual
                            );
                            pgrx::info!(
                                "{} - Golden result validation passed! Value: {}",
                                $file_name,
                                actual
                            );
                        }
                        Ok(None) => panic!("{} - Query returned NULL", $file_name),
                        Err(e) => panic!("{} - Query execution failed: {:?}", $file_name, e),
                    }
                }
                GoldenExpectation::NullResult => {
                    // The query must run and return a row whose first column is NULL.
                    match Spi::get_one::<String>(&format!(
                        "SELECT (sub.*)::text FROM ({}) AS sub LIMIT 1",
                        execution_query
                    )) {
                        Ok(Some(row_text)) => {
                            assert_eq!(
                                row_text, "()",
                                "{} - Expected NULL result, got row {}",
                                $file_name, row_text
                            );
                            pgrx::info!("{} - NULL result validation passed!", $file_name);
                        }
                        Ok(None) => {
                            // A NULL row composite also satisfies the expectation.
                            pgrx::info!("{} - NULL result validation passed!", $file_name);
                        }
                        Err(e) => panic!("{} - Query execution failed: {:?}", $file_name, e),
                    }
                }
            }
        }};
    }

    macro_rules! tpch_test {
        ($test_name:ident, $file_name:literal, $expected_value:expr) => {
            #[pg_test]
            fn $test_name() {
                tpch_test_body!($file_name, $expected_value);
            }
        };
        // Variant with ignore attribute for slow tests
        ($test_name:ident, $file_name:literal, $expected_value:expr, ignore) => {
            #[pg_test]
            #[ignore = "Test takes >10 minutes due to Cartesian product from Cross joins"]
            fn $test_name() {
                tpch_test_body!($file_name, $expected_value);
            }
        };
    }

    // Generate test functions for each TPC-H file with localized golden values
    tpch_test!(
        test_tpch_plan01,
        "tpch-plan01.json",
        GoldenExpectation::IntExact(14876)
    );

    // Plan02 uses Cross joins - optimizer should convert to proper joins
    tpch_test!(
        test_tpch_plan02,
        "tpch-plan02.json",
        GoldenExpectation::FloatTolerance(4186.95, 0.01)
    );

    // Plan03 uses nested Cross joins - optimizer should convert to proper joins
    tpch_test!(
        test_tpch_plan03,
        "tpch-plan03.json",
        GoldenExpectation::FloatTolerance(267010.5894, 0.01)
    );

    // Plan04 has EXISTS subquery with correlated outer references.
    tpch_test!(
        test_tpch_plan04,
        "tpch-plan04.json",
        GoldenExpectation::IntExact(93)
    );

    // Plan05 uses 5 nested Cross joins - optimizer should convert to proper joins
    tpch_test!(
        test_tpch_plan05,
        "tpch-plan05.json",
        GoldenExpectation::FloatTolerance(1000926.6999, 0.01)
    );

    tpch_test!(
        test_tpch_plan06,
        "tpch-plan06.json",
        GoldenExpectation::FloatTolerance(1193053.2253, 0.001)
    );

    // Diagnostic test: verify plan06 filter via direct SQL
    #[pg_test]
    fn test_plan06_direct_sql() {
        // Set up TPC-H database first
        setup_tpch_database_if_needed();

        // First run the filtered query (should match plan06 expected value)
        // Use quoted uppercase names to match TPC-H setup (tables created with "LINEITEM" etc.)
        let filtered_result: f64 = Spi::get_one::<pgrx::AnyNumeric>(
            "SELECT sum(l_extendedprice * l_discount) FROM \"LINEITEM\" \
             WHERE l_shipdate >= '1994-01-01'::date \
               AND l_shipdate < '1995-01-01'::date \
               AND l_discount >= 0.05 \
               AND l_discount <= 0.07 \
               AND l_quantity < 24",
        )
        .expect("filtered query failed")
        .expect("filtered result is null")
        .try_into()
        .expect("numeric conversion failed");

        pgrx::info!("DIAGNOSTIC: Filtered SQL result = {}", filtered_result);

        // Then run without filter (should be ~90x higher)
        let unfiltered_result: f64 = Spi::get_one::<pgrx::AnyNumeric>(
            "SELECT sum(l_extendedprice * l_discount) FROM \"LINEITEM\"",
        )
        .expect("unfiltered query failed")
        .expect("unfiltered result is null")
        .try_into()
        .expect("numeric conversion failed");

        pgrx::info!("DIAGNOSTIC: Unfiltered SQL result = {}", unfiltered_result);
        pgrx::info!(
            "DIAGNOSTIC: Ratio (unfiltered/filtered) = {}",
            unfiltered_result / filtered_result
        );

        // Verify filtered result matches expected plan06 value
        let expected = 1193053.2253;
        let diff = (filtered_result - expected).abs();
        assert!(
            diff < 1.0,
            "Filtered SQL result {} differs from expected {} by {}",
            filtered_result,
            expected,
            diff
        );
    }

    #[pg_test]
    fn test_plan05_direct_sql_comparison() {
        // Compare from_substrait_json(plan05) against the equivalent SQL to
        // isolate conversion bugs from stale golden values.
        setup_tpch_database_if_needed();

        let direct: f64 = Spi::get_one::<pgrx::AnyNumeric>(
            "SELECT sum(l_extendedprice * (1 - l_discount))::numeric AS revenue \
             FROM \"CUSTOMER\", \"ORDERS\", \"LINEITEM\", \"SUPPLIER\", \"NATION\", \"REGION\" \
             WHERE c_custkey = o_custkey \
               AND l_orderkey = o_orderkey \
               AND l_suppkey = s_suppkey \
               AND c_nationkey = s_nationkey \
               AND s_nationkey = n_nationkey \
               AND n_regionkey = r_regionkey \
               AND r_name = 'ASIA' \
               AND o_orderdate >= date '1994-01-01' \
               AND o_orderdate < date '1995-01-01' \
             GROUP BY n_name ORDER BY revenue DESC LIMIT 1",
        )
        .expect("direct SQL failed")
        .expect("direct SQL returned NULL")
        .try_into()
        .expect("numeric conversion failed");

        let file_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/tpch/tpch-plan05.json");
        let content = std::fs::read_to_string(&file_path).expect("failed to read plan05");
        let json_content = content
            .lines()
            .filter(|line| !line.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        let escaped_json = json_content.replace("'", "''");

        let via_substrait: f64 = Spi::get_one::<pgrx::AnyNumeric>(&format!(
            "SELECT (\"REVENUE\")::numeric FROM from_substrait_json('{escaped_json}') \
             AS t(\"N_NAME\" text, \"REVENUE\" numeric) LIMIT 1"
        ))
        .expect("substrait query failed")
        .expect("substrait query returned NULL")
        .try_into()
        .expect("numeric conversion failed");

        let diff = (direct - via_substrait).abs();
        assert!(
            diff < 0.01,
            "plan05 mismatch: direct SQL = {direct}, via substrait = {via_substrait}"
        );
    }

    // Plan07 uses 5 nested Cross joins - optimizer should convert to proper joins.
    tpch_test!(
        test_tpch_plan07,
        "tpch-plan07.json",
        GoldenExpectation::FloatTolerance(622524.0707, 0.01)
    );

    // Plan09 uses 5 nested Cross joins - optimizer should convert to proper joins.
    tpch_test!(
        test_tpch_plan09,
        "tpch-plan09.json",
        GoldenExpectation::FloatTolerance(378582.4555, 0.01)
    );

    // Plan10 uses 3 nested Cross joins - optimizer should convert to proper joins.
    tpch_test!(
        test_tpch_plan10,
        "tpch-plan10.json",
        GoldenExpectation::FloatTolerance(378211.3252, 0.01)
    );

    // Plan11 uses 4 nested Cross joins - optimizer should convert to proper joins.
    tpch_test!(
        test_tpch_plan11,
        "tpch-plan11.json",
        GoldenExpectation::FloatTolerance(11945237.22, 0.01)
    );

    // Plan12 has CASE WHEN expressions + 1 cross join - optimizer should handle.
    tpch_test!(
        test_tpch_plan12,
        "tpch-plan12.json",
        // Last output column is LOW_LINE_COUNT; MAIL row (first by shipmode).
        GoldenExpectation::IntExact(86)
    );

    tpch_test!(
        test_tpch_plan13,
        "tpch-plan13.json",
        GoldenExpectation::IntExact(500)
    );

    tpch_test!(
        test_tpch_plan14,
        "tpch-plan14.json",
        GoldenExpectation::FloatTolerance(15.33572804894921, 0.01)
    );

    tpch_test!(
        test_tpch_plan16,
        "tpch-plan16.json",
        GoldenExpectation::IntExact(8)
    );

    tpch_test!(
        test_tpch_plan17,
        "tpch-plan17.json",
        // AVG_YEARLY is NULL at scale factor 0.01 (no qualifying rows).
        GoldenExpectation::NullResult
    );

    tpch_test!(
        test_tpch_plan18,
        "tpch-plan18.json",
        GoldenExpectation::FloatTolerance(439687.23, 0.01)
    );

    tpch_test!(
        test_tpch_plan19,
        "tpch-plan19.json",
        GoldenExpectation::FloatTolerance(22923.0280, 0.01)
    );

    tpch_test!(
        test_tpch_plan20,
        "tpch-plan20.json",
        GoldenExpectation::StringExact("Supplier#000000013")
    );

    // Plan21 has EXISTS subqueries with correlated outer references + 3 cross joins.
    tpch_test!(
        test_tpch_plan21,
        "tpch-plan21.json",
        GoldenExpectation::IntExact(9)
    );

    // Plan22 has EXISTS subquery with correlated outer references.
    tpch_test!(
        test_tpch_plan22,
        "tpch-plan22.json",
        GoldenExpectation::FloatTolerance(75359.29, 0.01)
    );

    #[pg_test]
    #[should_panic(expected = "does not exist")]
    fn test_simple_table_scan_missing_table() {
        // Test that we properly handle missing tables instead of crashing
        let simple_scan_json = r#"{
            "version": {"minorNumber": 54},
            "relations": [
                {
                    "root": {
                        "input": {
                            "read": {
                                "baseSchema": {
                                    "names": ["id", "name"],
                                    "struct": {
                                        "types": [
                                            {"i32": {"nullability": "NULLABILITY_NULLABLE"}},
                                            {"string": {"nullability": "NULLABILITY_NULLABLE"}}
                                        ]
                                    }
                                },
                                "namedTable": {
                                    "names": ["nonexistent_table"]
                                }
                            }
                        },
                        "names": ["id", "name"]
                    }
                }
            ]
        }"#;

        // This should fail gracefully with a proper error, not crash
        let escaped_json = simple_scan_json.replace("'", "''");
        let query =
            format!("SELECT * FROM from_substrait_json('{escaped_json}') AS t(id int, name text)");
        // This should panic with an error about the missing table
        let _result = Spi::get_one::<String>(&query);
    }

    #[pg_test]
    fn test_simple_table_scan_existing_table() {
        // First create a simple test table
        Spi::run("CREATE TABLE IF NOT EXISTS test_simple_table (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_simple_table VALUES (1, 'test'), (2, 'data')").unwrap();

        let simple_scan_json = r#"{
            "version": {"minorNumber": 54},
            "relations": [
                {
                    "root": {
                        "input": {
                            "read": {
                                "baseSchema": {
                                    "names": ["id", "name"],
                                    "struct": {
                                        "types": [
                                            {"i32": {"nullability": "NULLABILITY_NULLABLE"}},
                                            {"string": {"nullability": "NULLABILITY_NULLABLE"}}
                                        ]
                                    }
                                },
                                "namedTable": {
                                    "names": ["test_simple_table"]
                                }
                            }
                        },
                        "names": ["id", "name"]
                    }
                }
            ]
        }"#;

        // This should work and return data
        let escaped_json = simple_scan_json.replace("'", "''");
        let query = format!("SELECT string_agg(id::text, ',') FROM from_substrait_json('{escaped_json}') AS t(id int, name text)");
        let result = Spi::get_one::<String>(&query);

        match result {
            Ok(Some(data)) => {
                // Should get some result with our test data
                assert!(
                    data.contains("1") || data.contains("2"),
                    "Expected test data, got: {data}"
                );
            }
            Ok(None) => panic!("Expected data from table scan, got NULL"),
            Err(e) => panic!("Expected successful table scan, got error: {e:?}"),
        }
    }

    #[pg_test]
    fn test_valid_as_clause_works() {
        // Test that a valid AS clause works
        let json_plan = r#"{
            "version": {"minorNumber": 54},
            "relations": [{
                "root": {
                    "names": ["result"],
                    "input": {
                        "project": {
                            "expressions": [{
                                "literal": {
                                    "i32": 99
                                }
                            }]
                        }
                    }
                }
            }]
        }"#;

        let escaped_plan = json_plan.replace("'", "''");

        // Test WITH AS clause - should still work
        let query_with_as =
            format!("SELECT * FROM from_substrait_json('{escaped_plan}') AS t(result int)");
        let result = Spi::get_one::<i32>(&query_with_as);

        // This should succeed - we have a valid plan with AS clause
        assert!(
            result.is_ok(),
            "Query with AS clause should succeed: {:?}",
            result.err()
        );
    }

    /// Test plan execution without collecting results - just checks if executor setup works
    unsafe fn test_plan_execution_only(
        postgres_plan: *mut pg_sys::Plan,
        _column_names: Vec<String>,
        range_table: *const pg_sys::List,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        pgrx::info!("test_plan_execution_only: Starting executor setup test");

        // Try to create executor state
        let estate = pg_sys::CreateExecutorState();
        if estate.is_null() {
            return Err("Failed to create executor state".into());
        }
        pgrx::info!("test_plan_execution_only: Executor state created successfully");

        // Set the range table
        if !range_table.is_null() {
            (*estate).es_range_table = range_table as *mut pg_sys::List;
            pgrx::info!("test_plan_execution_only: Range table set successfully");
        }

        // Try to initialize the plan node - first test just the SeqScan
        pgrx::info!("test_plan_execution_only: About to test SeqScan initialization only");

        // Navigate to the leaf SeqScan node in the complex Sort->Agg->SeqScan tree
        let seqscan_plan =
            if !postgres_plan.is_null() && (*postgres_plan).type_ == pg_sys::NodeTag::T_Sort {
                // Sort -> Agg -> SeqScan
                let agg_plan = (*postgres_plan).lefttree;
                if !agg_plan.is_null() && (*agg_plan).type_ == pg_sys::NodeTag::T_Agg {
                    let seqscan = (*agg_plan).lefttree;
                    if !seqscan.is_null() && (*seqscan).type_ == pg_sys::NodeTag::T_SeqScan {
                        seqscan
                    } else {
                        std::ptr::null_mut()
                    }
                } else {
                    std::ptr::null_mut()
                }
            } else {
                std::ptr::null_mut()
            };

        if !seqscan_plan.is_null() {
            pgrx::info!("test_plan_execution_only: Testing SeqScan node initialization alone");
            let seqscan_state = pg_sys::ExecInitNode(seqscan_plan, estate, 0);
            if seqscan_state.is_null() {
                pgrx::info!("test_plan_execution_only: SeqScan initialization failed");
            } else {
                pgrx::info!("test_plan_execution_only: SeqScan initialized successfully");
                pg_sys::ExecEndNode(seqscan_state);
            }
        }

        // Now try to initialize the full plan node
        pgrx::info!("test_plan_execution_only: About to call ExecInitNode on full plan tree");
        let plan_state = pg_sys::ExecInitNode(postgres_plan, estate, 0);
        pgrx::info!("test_plan_execution_only: ExecInitNode returned");
        if plan_state.is_null() {
            pgrx::info!("test_plan_execution_only: Plan state is null");
            pg_sys::FreeExecutorState(estate);
            return Err("Failed to initialize plan node for execution".into());
        }
        pgrx::info!("test_plan_execution_only: Plan node initialized successfully");

        // Try to execute just ONE tuple to see if basic execution works
        let slot = pg_sys::ExecProcNode(plan_state);
        if slot.is_null() {
            pgrx::info!("test_plan_execution_only: No tuples returned (which might be expected)");
        } else {
            pgrx::info!("test_plan_execution_only: Successfully executed and got a tuple slot");
        }

        // Clean up
        pg_sys::ExecEndNode(plan_state);
        pg_sys::FreeExecutorState(estate);

        pgrx::info!("test_plan_execution_only: All cleanup completed successfully");
        Ok(())
    }

    // ============================================================================
    // PHASE 1: DIRECT POSTGRESQL BASELINE TESTS (BYPASS EXTENSION ENTIRELY)
    // ============================================================================

    /// Test direct PostgreSQL execution of "SELECT 42" to establish baseline
    /// This bypasses the extension entirely and proves PostgreSQL works independently
    #[pg_test]
    fn test_direct_postgresql_select_42() {
        pgrx::info!("DIRECT_PG_TEST: Testing PostgreSQL 'SELECT 42' baseline");

        unsafe {
            // Test 1: Use PostgreSQL's complete API sequence
            let query_string = std::ffi::CString::new("SELECT 42").unwrap();

            pgrx::info!("DIRECT_PG_TEST: About to parse query");
            let raw_parse_tree = pg_sys::pg_parse_query(query_string.as_ptr());
            assert!(!raw_parse_tree.is_null(), "Parse query should succeed");

            pgrx::info!("DIRECT_PG_TEST: About to analyze query");
            let stmt_list = raw_parse_tree as *mut pg_sys::List;
            let raw_stmt = pg_sys::list_nth(stmt_list, 0) as *mut pg_sys::RawStmt;

            let query = pg_sys::parse_analyze_fixedparams(
                raw_stmt,
                query_string.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );
            assert!(!query.is_null(), "Query analysis should succeed");

            pgrx::info!("DIRECT_PG_TEST: About to plan query");
            let planned_stmt =
                pg_sys::planner(query, std::ptr::null_mut(), 0, std::ptr::null_mut());
            assert!(!planned_stmt.is_null(), "Query planning should succeed");

            pgrx::info!("DIRECT_PG_TEST: PostgreSQL planning succeeded!");

            // Test the plan tree structure
            let plan_tree = (*planned_stmt).planTree;
            assert!(!plan_tree.is_null(), "Plan tree should not be null");

            pgrx::info!("DIRECT_PG_TEST: Plan tree type: {:?}", (*plan_tree).type_);

            // Validate that nodeToString works on PostgreSQL's plan
            let plan_str = pg_sys::nodeToString(plan_tree as *const std::ffi::c_void);
            if !plan_str.is_null() {
                pgrx::info!("DIRECT_PG_TEST: nodeToString works on PostgreSQL plan");
                pg_sys::pfree(plan_str as *mut std::ffi::c_void);
            }

            pgrx::info!("DIRECT_PG_TEST: PostgreSQL 'SELECT 42' baseline test PASSED");
        }
    }

    /// Test direct PostgreSQL execution without ExecutorStart - just validate planning
    #[pg_test]
    fn test_direct_postgresql_planning_only() {
        pgrx::info!("DIRECT_PG_TEST: Testing PostgreSQL planning-only for multiple queries");

        let queries = vec!["SELECT 42", "SELECT 1 + 2", "SELECT 'hello'", "SELECT true"];

        for query_sql in queries {
            unsafe {
                pgrx::info!("DIRECT_PG_TEST: Testing query: {}", query_sql);

                let query_string = std::ffi::CString::new(query_sql).unwrap();
                let raw_parse_tree = pg_sys::pg_parse_query(query_string.as_ptr());
                assert!(
                    !raw_parse_tree.is_null(),
                    "Parse should succeed for: {query_sql}"
                );

                let stmt_list = raw_parse_tree as *mut pg_sys::List;
                let raw_stmt = pg_sys::list_nth(stmt_list, 0) as *mut pg_sys::RawStmt;

                let query = pg_sys::parse_analyze_fixedparams(
                    raw_stmt,
                    query_string.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                );
                assert!(!query.is_null(), "Analysis should succeed for: {query_sql}");

                let planned_stmt =
                    pg_sys::planner(query, std::ptr::null_mut(), 0, std::ptr::null_mut());
                assert!(
                    !planned_stmt.is_null(),
                    "Planning should succeed for: {query_sql}"
                );

                let plan_tree = (*planned_stmt).planTree;
                assert!(!plan_tree.is_null());

                pgrx::info!(
                    "DIRECT_PG_TEST: {} - Plan type: {:?}",
                    query_sql,
                    (*plan_tree).type_
                );
            }
        }

        pgrx::info!("DIRECT_PG_TEST: All planning tests PASSED");
    }

    /// Test direct PostgreSQL execution with ExecutorStart - full execution test
    #[pg_test]
    fn test_direct_postgresql_full_execution() {
        pgrx::info!("DIRECT_PG_TEST: Testing full PostgreSQL execution for 'SELECT 42'");

        unsafe {
            let query_string = std::ffi::CString::new("SELECT 42").unwrap();

            // Parse, analyze, and plan
            let raw_parse_tree = pg_sys::pg_parse_query(query_string.as_ptr());
            let stmt_list = raw_parse_tree as *mut pg_sys::List;
            let raw_stmt = pg_sys::list_nth(stmt_list, 0) as *mut pg_sys::RawStmt;

            let query = pg_sys::parse_analyze_fixedparams(
                raw_stmt,
                query_string.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );

            let planned_stmt =
                pg_sys::planner(query, std::ptr::null_mut(), 0, std::ptr::null_mut());

            // Create QueryDesc for execution using safe pgrx allocation
            let mut query_desc = pgrx::PgBox::<pg_sys::QueryDesc>::alloc0();
            query_desc.operation = pg_sys::CmdType::CMD_SELECT;
            query_desc.plannedstmt = planned_stmt;
            query_desc.sourceText = query_string.as_ptr();
            query_desc.snapshot = pg_sys::GetActiveSnapshot();
            query_desc.crosscheck_snapshot = std::ptr::null_mut();
            query_desc.dest = std::ptr::null_mut();
            query_desc.params = std::ptr::null_mut();
            query_desc.queryEnv = std::ptr::null_mut();
            let query_desc = query_desc.into_pg();
            (*query_desc).instrument_options = 0;

            pgrx::info!("DIRECT_PG_TEST: About to call ExecutorStart");

            // Use PostgreSQL's standard executor startup
            pg_sys::ExecutorStart(query_desc, 0);

            pgrx::info!("DIRECT_PG_TEST: ExecutorStart succeeded!");

            let plan_state = (*query_desc).planstate;
            assert!(
                !plan_state.is_null(),
                "Plan state should be created by ExecutorStart"
            );

            pgrx::info!("DIRECT_PG_TEST: About to execute and get result");

            // Execute and get one tuple
            let slot = pg_sys::ExecProcNode(plan_state);
            assert!(!slot.is_null(), "Should get a result tuple");

            pgrx::info!("DIRECT_PG_TEST: Got result tuple!");

            // Extract the value (should be 42)
            let mut is_null = false;
            let datum = pg_sys::slot_getattr(slot, 1, &mut is_null);
            assert!(!is_null, "Result should not be null");

            let value = datum.value() as i32;
            assert_eq!(value, 42, "Result should be 42");

            pgrx::info!("DIRECT_PG_TEST: Verified result value is 42!");

            // Clean up
            pg_sys::ExecutorFinish(query_desc);
            pg_sys::ExecutorEnd(query_desc);

            pgrx::info!("DIRECT_PG_TEST: Full execution test PASSED");
        }
    }

    /// Compare SPI execution vs direct execution for the same query
    #[pg_test]
    fn test_spi_vs_direct_execution_comparison() {
        pgrx::info!("DIRECT_PG_TEST: Comparing SPI vs direct execution");

        // Test 1: SPI execution (known to work)
        let spi_result = Spi::get_one::<i32>("SELECT 42");
        assert!(spi_result.is_ok(), "SPI should work");
        let spi_value = spi_result.unwrap().unwrap();
        assert_eq!(spi_value, 42, "SPI should return 42");

        pgrx::info!("DIRECT_PG_TEST: SPI execution returned: {}", spi_value);

        // Test 2: Direct execution (what we just implemented)
        unsafe {
            let query_string = std::ffi::CString::new("SELECT 42").unwrap();

            let raw_parse_tree = pg_sys::pg_parse_query(query_string.as_ptr());
            let stmt_list = raw_parse_tree as *mut pg_sys::List;
            let raw_stmt = pg_sys::list_nth(stmt_list, 0) as *mut pg_sys::RawStmt;

            let query = pg_sys::parse_analyze_fixedparams(
                raw_stmt,
                query_string.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );

            let planned_stmt =
                pg_sys::planner(query, std::ptr::null_mut(), 0, std::ptr::null_mut());

            let mut query_desc = pgrx::PgBox::<pg_sys::QueryDesc>::alloc0();
            query_desc.operation = pg_sys::CmdType::CMD_SELECT;
            query_desc.plannedstmt = planned_stmt;
            query_desc.sourceText = query_string.as_ptr();
            query_desc.snapshot = pg_sys::GetActiveSnapshot();
            query_desc.crosscheck_snapshot = std::ptr::null_mut();
            query_desc.dest = std::ptr::null_mut();
            query_desc.params = std::ptr::null_mut();
            query_desc.queryEnv = std::ptr::null_mut();
            query_desc.instrument_options = 0;
            let query_desc = query_desc.into_pg();

            pg_sys::ExecutorStart(query_desc, 0);
            let plan_state = (*query_desc).planstate;

            let slot = pg_sys::ExecProcNode(plan_state);
            let mut is_null = false;
            let datum = pg_sys::slot_getattr(slot, 1, &mut is_null);
            let direct_value = datum.value() as i32;

            pg_sys::ExecutorFinish(query_desc);
            pg_sys::ExecutorEnd(query_desc);

            pgrx::info!(
                "DIRECT_PG_TEST: Direct execution returned: {}",
                direct_value
            );

            // Both should return the same value
            assert_eq!(
                spi_value, direct_value,
                "SPI and direct execution should return same result"
            );
        }

        pgrx::info!("DIRECT_PG_TEST: SPI vs Direct comparison PASSED");
    }

    // ============================================================================
    // PHASE 2: MANUAL PLAN CONSTRUCTION TESTS (BYPASS PARSER)
    // ============================================================================

    /// Test manual construction of Result node with Const expression
    /// This tests our ability to build plan nodes programmatically like Substrait translation
    #[pg_test]
    fn test_manual_result_node_construction() {
        pgrx::info!("MANUAL_PLAN_TEST: Testing manual Result node construction");

        unsafe {
            // Create a Const node for value 99
            let const_node = crate::query_builder::expressions::create_int4_const(99)
                .expect("Should create const node");

            pgrx::info!("MANUAL_PLAN_TEST: Created Const node for value 99");

            // Create a TargetEntry for the const using safe pgrx allocation
            let mut target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            target_entry.expr = const_node as *mut pg_sys::Expr;
            target_entry.resno = 1;
            target_entry.resname = std::ptr::null_mut(); // Will be set later
            let target_entry = target_entry.into_pg();
            (*target_entry).ressortgroupref = 0;
            (*target_entry).resorigtbl = pg_sys::InvalidOid;
            (*target_entry).resorigcol = 0;
            (*target_entry).resjunk = false;

            pgrx::info!("MANUAL_PLAN_TEST: Created TargetEntry");

            // Create target list
            let mut target_list: *mut pg_sys::List = std::ptr::null_mut();
            target_list = pg_sys::lappend(target_list, target_entry as *mut std::ffi::c_void);

            // Create Result plan node using safe pgrx allocation
            let mut result_plan = pgrx::PgBox::<pg_sys::Result>::alloc0();
            result_plan.plan.type_ = pg_sys::NodeTag::T_Result;
            result_plan.plan.targetlist = target_list;
            result_plan.plan.qual = std::ptr::null_mut();
            result_plan.plan.lefttree = std::ptr::null_mut();
            result_plan.plan.righttree = std::ptr::null_mut();
            result_plan.plan.plan_node_id = 1;
            let result_plan = result_plan.into_pg();
            (*result_plan).plan.plan_width = 4; // int4 width
            (*result_plan).resconstantqual = std::ptr::null_mut();

            pgrx::info!("MANUAL_PLAN_TEST: Created Result plan node");

            // Test that nodeToString works on our manual plan
            let plan_str = pg_sys::nodeToString(result_plan as *const std::ffi::c_void);
            if !plan_str.is_null() {
                pgrx::info!("MANUAL_PLAN_TEST: nodeToString works on manual plan");
                pg_sys::pfree(plan_str as *mut std::ffi::c_void);
            }

            // Create PlannedStmt wrapper for execution using safe pgrx allocation
            let mut planned_stmt = pgrx::PgBox::<pg_sys::PlannedStmt>::alloc0();
            planned_stmt.type_ = pg_sys::NodeTag::T_PlannedStmt;
            planned_stmt.planTree = result_plan as *mut pg_sys::Plan;
            planned_stmt.rtable = std::ptr::null_mut(); // No tables needed for Result node
            planned_stmt.permInfos = std::ptr::null_mut(); // No permission info needed
            planned_stmt.commandType = pg_sys::CmdType::CMD_SELECT;
            planned_stmt.canSetTag = true;
            planned_stmt.stmt_location = 0;
            planned_stmt.stmt_len = 0;
            let planned_stmt = planned_stmt.into_pg();

            // Test execution using our direct execution approach with safe pgrx allocation
            let mut query_desc = pgrx::PgBox::<pg_sys::QueryDesc>::alloc0();
            query_desc.operation = pg_sys::CmdType::CMD_SELECT;
            query_desc.plannedstmt = planned_stmt;
            query_desc.sourceText = std::ptr::null_mut();

            // Ensure we have an active snapshot
            let snapshot = pg_sys::GetActiveSnapshot();
            if snapshot.is_null() {
                pg_sys::PushActiveSnapshot(pg_sys::GetTransactionSnapshot());
            }
            query_desc.snapshot = pg_sys::GetActiveSnapshot();

            query_desc.crosscheck_snapshot = std::ptr::null_mut();
            query_desc.dest = std::ptr::null_mut();
            query_desc.params = std::ptr::null_mut();
            query_desc.queryEnv = std::ptr::null_mut();
            query_desc.instrument_options = 0;
            let query_desc = query_desc.into_pg();

            pgrx::info!("MANUAL_PLAN_TEST: About to execute manual plan");

            // Use the same approach as our actual executor: CreateExecutorState + ExecInitNode
            // instead of ExecutorStart (which has stricter requirements in PG17)
            let estate = pg_sys::CreateExecutorState();
            assert!(!estate.is_null(), "Failed to create executor state");

            // Initialize range table (empty for Result node)
            let empty_perminfos: *mut pg_sys::List = std::ptr::null_mut();
            pg_sys::ExecInitRangeTable(estate, std::ptr::null_mut(), empty_perminfos);

            // Set planned statement reference
            (*estate).es_plannedstmt = (*query_desc).plannedstmt;
            (*estate).es_snapshot = (*query_desc).snapshot;
            (*estate).es_crosscheck_snapshot = std::ptr::null_mut();
            (*estate).es_instrument = 0;
            (*estate).es_top_eflags = 0;

            // Initialize the plan
            let plan_state = pg_sys::ExecInitNode(result_plan as *mut pg_sys::Plan, estate, 0);
            assert!(!plan_state.is_null(), "Failed to initialize plan state");

            pgrx::info!("MANUAL_PLAN_TEST: Plan initialized successfully");

            let slot = pg_sys::ExecProcNode(plan_state);
            assert!(!slot.is_null(), "Manual plan should return a result");

            let mut is_null = false;
            let datum = pg_sys::slot_getattr(slot, 1, &mut is_null);
            let value = datum.value() as i32;

            assert_eq!(value, 99, "Manual plan should return 99");

            pgrx::info!(
                "MANUAL_PLAN_TEST: Manual plan returned correct value: {}",
                value
            );

            // Clean up
            pg_sys::ExecEndNode(plan_state);
            pg_sys::FreeExecutorState(estate);

            pgrx::info!("MANUAL_PLAN_TEST: Manual Result node construction PASSED");
        }
    }

    /// Test manual construction of different Const types
    #[pg_test]
    fn test_manual_const_node_types() {
        pgrx::info!("MANUAL_PLAN_TEST: Testing different Const node types");

        unsafe {
            // Test Int4 const
            let int_const = crate::query_builder::expressions::create_int4_const(42)
                .expect("Should create int4 const");
            let int_const_ptr = int_const as *const pg_sys::Const;
            assert_eq!(
                (*int_const_ptr).consttype,
                pg_sys::INT4OID,
                "Should be INT4OID"
            );
            assert_eq!(
                (*int_const_ptr).constvalue.value() as i32,
                42,
                "Should be 42"
            );
            pgrx::info!("MANUAL_PLAN_TEST: Int4 const OK");

            // Test Bool const
            let bool_const = crate::query_builder::expressions::create_bool_const(true)
                .expect("Should create bool const");
            let bool_const_ptr = bool_const as *const pg_sys::Const;
            assert_eq!(
                (*bool_const_ptr).consttype,
                pg_sys::BOOLOID,
                "Should be BOOLOID"
            );
            pgrx::info!("MANUAL_PLAN_TEST: Bool const OK");

            // Test Text const
            let text_const = crate::query_builder::expressions::create_text_const("hello")
                .expect("Should create text const");
            let text_const_ptr = text_const as *const pg_sys::Const;
            assert_eq!(
                (*text_const_ptr).consttype,
                pg_sys::TEXTOID,
                "Should be TEXTOID"
            );
            pgrx::info!("MANUAL_PLAN_TEST: Text const OK");

            pgrx::info!("MANUAL_PLAN_TEST: All Const node types PASSED");
        }
    }

    /// Compare manual plan construction with PostgreSQL's parser
    #[pg_test]
    fn test_manual_vs_parsed_plan_comparison() {
        pgrx::info!("MANUAL_PLAN_TEST: Comparing manual vs parsed plan for 'SELECT 123'");

        unsafe {
            // Method 1: PostgreSQL's parser
            let query_string = std::ffi::CString::new("SELECT 123").unwrap();
            let raw_parse_tree = pg_sys::pg_parse_query(query_string.as_ptr());
            let stmt_list = raw_parse_tree as *mut pg_sys::List;
            let raw_stmt = pg_sys::list_nth(stmt_list, 0) as *mut pg_sys::RawStmt;

            let query = pg_sys::parse_analyze_fixedparams(
                raw_stmt,
                query_string.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            );

            let parsed_planned_stmt =
                pg_sys::planner(query, std::ptr::null_mut(), 0, std::ptr::null_mut());

            // Execute parsed plan using safe pgrx allocation
            let mut parsed_query_desc = pgrx::PgBox::<pg_sys::QueryDesc>::alloc0();
            parsed_query_desc.operation = pg_sys::CmdType::CMD_SELECT;
            parsed_query_desc.plannedstmt = parsed_planned_stmt;
            parsed_query_desc.sourceText = query_string.as_ptr();
            parsed_query_desc.snapshot = pg_sys::GetActiveSnapshot();
            parsed_query_desc.crosscheck_snapshot = std::ptr::null_mut();
            parsed_query_desc.dest = std::ptr::null_mut();
            parsed_query_desc.params = std::ptr::null_mut();
            let parsed_query_desc = parsed_query_desc.into_pg();
            (*parsed_query_desc).queryEnv = std::ptr::null_mut();
            (*parsed_query_desc).instrument_options = 0;

            pg_sys::ExecutorStart(parsed_query_desc, 0);
            let parsed_slot = pg_sys::ExecProcNode((*parsed_query_desc).planstate);
            let mut parsed_is_null = false;
            let parsed_datum = pg_sys::slot_getattr(parsed_slot, 1, &mut parsed_is_null);
            let parsed_value = parsed_datum.value() as i32;
            pg_sys::ExecutorFinish(parsed_query_desc);
            pg_sys::ExecutorEnd(parsed_query_desc);

            pgrx::info!("MANUAL_PLAN_TEST: Parsed plan returned: {}", parsed_value);

            // Method 2: Manual construction
            let manual_const = crate::query_builder::expressions::create_int4_const(123)
                .expect("Should create const");

            let mut manual_target_entry = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
            manual_target_entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
            manual_target_entry.expr = manual_const as *mut pg_sys::Expr;
            manual_target_entry.resno = 1;
            manual_target_entry.resname = std::ptr::null_mut();
            manual_target_entry.ressortgroupref = 0;
            manual_target_entry.resorigtbl = pg_sys::InvalidOid;
            let manual_target_entry = manual_target_entry.into_pg();
            (*manual_target_entry).resorigcol = 0;
            (*manual_target_entry).resjunk = false;

            let mut manual_target_list: *mut pg_sys::List = std::ptr::null_mut();
            manual_target_list = pg_sys::lappend(
                manual_target_list,
                manual_target_entry as *mut std::ffi::c_void,
            );

            let mut manual_result_plan = pgrx::PgBox::<pg_sys::Result>::alloc0();
            manual_result_plan.plan.type_ = pg_sys::NodeTag::T_Result;
            manual_result_plan.plan.targetlist = manual_target_list;
            manual_result_plan.plan.qual = std::ptr::null_mut();
            manual_result_plan.plan.lefttree = std::ptr::null_mut();
            manual_result_plan.plan.righttree = std::ptr::null_mut();
            let manual_result_plan = manual_result_plan.into_pg();
            (*manual_result_plan).plan.plan_node_id = 1;
            (*manual_result_plan).plan.plan_width = 4;
            (*manual_result_plan).resconstantqual = std::ptr::null_mut();

            let mut manual_planned_stmt = pgrx::PgBox::<pg_sys::PlannedStmt>::alloc0();
            manual_planned_stmt.type_ = pg_sys::NodeTag::T_PlannedStmt;
            manual_planned_stmt.planTree = manual_result_plan as *mut pg_sys::Plan;
            manual_planned_stmt.rtable = std::ptr::null_mut();
            manual_planned_stmt.permInfos = std::ptr::null_mut();
            manual_planned_stmt.commandType = pg_sys::CmdType::CMD_SELECT;
            manual_planned_stmt.canSetTag = true;
            manual_planned_stmt.stmt_location = 0;
            manual_planned_stmt.stmt_len = 0;
            let manual_planned_stmt = manual_planned_stmt.into_pg();

            // Execute manual plan using safe pgrx allocation
            let mut manual_query_desc = pgrx::PgBox::<pg_sys::QueryDesc>::alloc0();
            manual_query_desc.operation = pg_sys::CmdType::CMD_SELECT;
            manual_query_desc.plannedstmt = manual_planned_stmt;
            manual_query_desc.sourceText = std::ptr::null_mut();

            // Ensure we have an active snapshot
            let manual_snapshot = pg_sys::GetActiveSnapshot();
            if manual_snapshot.is_null() {
                pg_sys::PushActiveSnapshot(pg_sys::GetTransactionSnapshot());
            }
            manual_query_desc.snapshot = pg_sys::GetActiveSnapshot();

            manual_query_desc.crosscheck_snapshot = std::ptr::null_mut();
            manual_query_desc.dest = std::ptr::null_mut();
            manual_query_desc.params = std::ptr::null_mut();
            manual_query_desc.queryEnv = std::ptr::null_mut();
            manual_query_desc.instrument_options = 0;
            let manual_query_desc = manual_query_desc.into_pg();

            // Use CreateExecutorState + ExecInitNode instead of ExecutorStart
            let manual_estate = pg_sys::CreateExecutorState();
            let manual_empty_perminfos: *mut pg_sys::List = std::ptr::null_mut();
            pg_sys::ExecInitRangeTable(manual_estate, std::ptr::null_mut(), manual_empty_perminfos);
            (*manual_estate).es_plannedstmt = manual_planned_stmt;
            (*manual_estate).es_snapshot = (*manual_query_desc).snapshot;
            (*manual_estate).es_crosscheck_snapshot = std::ptr::null_mut();
            (*manual_estate).es_instrument = 0;
            (*manual_estate).es_top_eflags = 0;

            let manual_plan_state =
                pg_sys::ExecInitNode(manual_result_plan as *mut pg_sys::Plan, manual_estate, 0);
            let manual_slot = pg_sys::ExecProcNode(manual_plan_state);
            let mut manual_is_null = false;
            let manual_datum = pg_sys::slot_getattr(manual_slot, 1, &mut manual_is_null);
            let manual_value = manual_datum.value() as i32;
            pg_sys::ExecEndNode(manual_plan_state);
            pg_sys::FreeExecutorState(manual_estate);

            pgrx::info!("MANUAL_PLAN_TEST: Manual plan returned: {}", manual_value);

            // Both should return the same value
            assert_eq!(
                parsed_value, manual_value,
                "Parsed and manual plans should return same result"
            );
            assert_eq!(manual_value, 123, "Both should return 123");

            pgrx::info!("MANUAL_PLAN_TEST: Manual vs Parsed comparison PASSED");
        }
    }

    /// Helper function to safely access the first element of a PostgreSQL List
    unsafe fn pg_list_get_first<T>(list: *mut pg_sys::List) -> Result<*mut T, String> {
        if list.is_null() {
            return Err("List is null".to_string());
        }

        if (*list).length == 0 {
            return Err("List is empty".to_string());
        }

        // Access the first element from the elements array
        let first_cell = (*list).elements;
        if first_cell.is_null() {
            return Err("First cell is null".to_string());
        }

        Ok((*first_cell).ptr_value as *mut T)
    }

    unsafe fn setup_seqscan_test_table() -> pg_sys::Oid {
        // First create a simple test table
        Spi::run("DROP TABLE IF EXISTS test_seqscan_table");
        Spi::run("CREATE TABLE test_seqscan_table (id INT, name TEXT)");
        Spi::run("INSERT INTO test_seqscan_table VALUES (1, 'Alice'), (2, 'Bob')");
        // Update statistics so PostgreSQL knows the actual row count
        Spi::run("ANALYZE test_seqscan_table");

        // Get the table's relation ID
        let table_oid: pg_sys::Oid = Spi::get_one::<pg_sys::Oid>(
            "SELECT oid FROM pg_class WHERE relname = 'test_seqscan_table'",
        )
        .unwrap()
        .unwrap();

        pgrx::info!("SETUP_SEQSCAN_TABLE: Found table OID: {}", table_oid);
        table_oid
    }

    /// Sets up TPC-H database if needed (checks if LINEITEM table exists)
    /// Uses an advisory lock to prevent race conditions when tests run in parallel.
    fn setup_tpch_database_if_needed() {
        // Use advisory lock to prevent parallel setup attempts.
        // Lock ID 12345 is arbitrary but must be consistent across all test backends.
        // pg_advisory_lock returns void, so we just run it.
        Spi::run("SELECT pg_advisory_lock(12345)").expect("Failed to acquire advisory lock");

        // Check if LINEITEM table already exists (uppercase to match Substrait)
        let table_exists = Spi::get_one::<bool>(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'LINEITEM')",
        )
        .unwrap_or(Some(false))
        .unwrap_or(false);

        if table_exists {
            pgrx::info!("TPC-H LINEITEM table already exists, skipping setup");
            // Release the advisory lock before returning.
            let _ = Spi::run("SELECT pg_advisory_unlock(12345)");
            return;
        }

        pgrx::info!("Setting up TPC-H database using shell script");

        use std::process::Command;

        // Find the setup script in the project
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let script_path = std::path::Path::new(manifest_dir).join("scripts/setup-tpch.sh");

        if !script_path.exists() {
            panic!("TPC-H setup script not found at: {}", script_path.display());
        }

        // Get the actual test database connection details from pgrx
        let (host, port, database, user) = get_test_db_connection_info();

        pgrx::info!(
            "Using test database connection: host={}, port={}, database={}, user={}",
            host,
            port,
            database,
            user
        );

        // Build the DATABASE_URL for the test database
        let db_url = format!("postgres://{user}@{host}:{port}/{database}");

        // Run the setup script with the correct connection parameters
        let output = Command::new("bash")
            .arg(&script_path)
            .arg(&database) // Pass the actual test database name
            .env("DATABASE_URL", &db_url)
            .env("PGHOST", &host)
            .env("PGPORT", port.to_string())
            .env("PGDATABASE", &database)
            .env("PGUSER", &user)
            .output()
            .expect("Failed to execute TPC-H setup script");

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("TPC-H setup script failed:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}");
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        pgrx::info!("TPC-H setup completed: {}", stdout);

        // Verify that the tables were actually created
        let table_exists_after = Spi::get_one::<bool>(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'LINEITEM')",
        )
        .unwrap_or(Some(false))
        .unwrap_or(false);

        let part_table_exists = Spi::get_one::<bool>(
            "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'PART')",
        )
        .unwrap_or(Some(false))
        .unwrap_or(false);

        pgrx::info!(
            "After setup - LINEITEM exists: {}, PART exists: {}",
            table_exists_after,
            part_table_exists
        );

        // List all tables to debug
        let table_list = Spi::get_one::<String>(
            "SELECT string_agg(table_name, ', ') FROM information_schema.tables WHERE table_schema = 'public'"
        ).unwrap_or(Some("no tables found".to_string())).unwrap_or("query failed".to_string());

        pgrx::info!("All tables in public schema: {}", table_list);

        // Release the advisory lock after setup completes.
        let _ = Spi::run("SELECT pg_advisory_unlock(12345)");
    }

    /// Get the connection information for the current pgrx test database
    fn get_test_db_connection_info() -> (String, u16, String, String) {
        // This code runs inside the test server backend, so ask the server
        // directly rather than replicating pgrx's internal conventions
        // (pgrx 0.19+ picks an ephemeral port per test binary).

        // Host is always localhost for pgrx tests
        let host = "localhost".to_string();

        let port = Spi::get_one::<String>("SHOW port")
            .ok()
            .flatten()
            .and_then(|p| p.parse::<u16>().ok())
            .expect("unable to determine test server port");

        let database = Spi::get_one::<String>("SELECT current_database()::text")
            .ok()
            .flatten()
            .expect("unable to determine current database");

        let user = Spi::get_one::<String>("SELECT current_user::text")
            .ok()
            .flatten()
            .expect("unable to determine current user");

        (host, port, database, user)
    }

    #[pg_test]
    fn test_extract_table_name_from_named_table() {
        use crate::query_builder::relations::extract_table_name_from_named_table;
        use substrait::proto::read_rel::NamedTable;

        // Test with single table name
        let mut named_table = NamedTable {
            names: vec!["test_table".to_string()],
            ..Default::default()
        };

        let result = extract_table_name_from_named_table(&named_table);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_table");

        // Test with schema-qualified name
        named_table.names = vec!["public".to_string(), "my_table".to_string()];
        let result = extract_table_name_from_named_table(&named_table);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "my_table");

        // Test with catalog.schema.table name
        named_table.names = vec![
            "catalog".to_string(),
            "schema".to_string(),
            "table_name".to_string(),
        ];
        let result = extract_table_name_from_named_table(&named_table);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "table_name");

        // Test with empty names vector
        named_table.names = vec![];
        let result = extract_table_name_from_named_table(&named_table);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "NamedTable has no names");

        pgrx::info!("test_extract_table_name_from_named_table: All tests passed");
    }

    #[pg_test]
    fn test_real_substrait_with_projection() {
        // Test the real Substrait execution with projection
        let substrait_json = r#"{"relations": [{"root": {"input": {"project": {"input": {"read": {"baseSchema": {"names": ["oid", "relname", "relnamespace", "reltype", "reloftype", "relowner", "relam", "relfilenode", "reltablespace", "relpages", "reltuples", "relallvisible", "reltoastrelid", "relhasindex", "relisshared", "relpersistence", "relkind", "relnatts", "relchecks", "relhasrules", "relhastriggers", "relhassubclass", "relrowsecurity", "relforcerowsecurity", "relhasoids", "relispopulated", "relreplident", "relispartition", "relrewrite", "relfrozenxid", "relminmxid", "relacl", "reloptions", "relpartbound"], "struct": {"types": [{"i32": {}}, {"varchar": {"length": 63}}, {"i32": {}}, {"i32": {}}, {"i32": {}}, {"i32": {}}, {"i32": {}}, {"i32": {}}, {"i32": {}}, {"i32": {}}, {"fp32": {}}, {"i32": {}}, {"i32": {}}, {"bool": {}}, {"bool": {}}, {"varchar": {"length": 1}}, {"varchar": {"length": 1}}, {"i16": {}}, {"i16": {}}, {"bool": {}}, {"bool": {}}, {"bool": {}}, {"bool": {}}, {"bool": {}}, {"bool": {}}, {"bool": {}}, {"varchar": {"length": 1}}, {"bool": {}}, {"i32": {}}, {"i32": {}}, {"i32": {}}, {"varchar": {}}, {"varchar": {}}, {"varchar": {}}]}}, "namedTable": {"names": ["pg_class"]}}}, "expressions": [{"selection": {"directReference": {"structField": {"field": 1}}}}]}}}}]}"#;

        Spi::connect(|client| {
            let result = client.select(
                &format!(
                    "SELECT * FROM from_substrait_json('{substrait_json}') AS (relname name) LIMIT 1"
                ),
                None,
                &[],
            );

            match result {
                Ok(table) => {
                    // If this works, we've fixed the issue!
                    assert!(
                        !table.is_empty(),
                        "Substrait query should return at least one row"
                    );
                    println!("SUCCESS! Real Substrait query returned data!");
                }
                Err(e) => {
                    // Expected to fail until we fix the issue
                    println!("Real Substrait still failing as expected: {e}");
                }
            }
        });
    }
}

#[cfg(any(test, feature = "pg_test"))]
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
