use anyhow::Result;
use pgrx::pg_sys::{self, SysCacheIdentifier::PROCOID};
use pgrx::prelude::*;
use prost::Message;
use std::ffi::CString;
use substrait::proto::Plan;

/// Static storage for the previous post_parse_analyze_hook
static mut PREV_POST_PARSE_ANALYZE_HOOK: Option<pg_sys::post_parse_analyze_hook_type> = None;

/// Schema information extracted from Substrait plans
#[derive(Debug, Clone)]
pub struct SubstraitSchema {
    pub columns: Vec<SubstraitColumn>,
}

#[derive(Debug, Clone)]
pub struct SubstraitColumn {
    pub name: String,
    pub postgres_type: String,
    pub type_oid: pg_sys::Oid,
}

/// Initialize parser hooks during extension loading
pub unsafe fn initialize_parse_hooks() {
    // Store the previous hook if it exists
    PREV_POST_PARSE_ANALYZE_HOOK = Some(pg_sys::post_parse_analyze_hook);

    // Install our custom hook
    pg_sys::post_parse_analyze_hook = Some(substrait_post_parse_analyze_hook);

    pgrx::info!("Substrait parser hooks initialized");
}

/// Custom post-parse analysis hook to detect and modify from_substrait calls
#[pg_guard]
unsafe extern "C-unwind" fn substrait_post_parse_analyze_hook(
    pstate: *mut pg_sys::ParseState,
    query: *mut pg_sys::Query,
    _jstate: *mut pg_sys::JumbleState,
) {
    // Process the query to find from_substrait function calls with literal arguments
    if !query.is_null() {
        process_query_for_substrait_calls(query);
    }

    // Call the previous hook if it exists
    if let Some(Some(prev_hook)) = PREV_POST_PARSE_ANALYZE_HOOK {
        prev_hook(pstate, query, _jstate);
    }
}

/// Process a query to find and modify from_substrait function calls
unsafe fn process_query_for_substrait_calls(query: *mut pg_sys::Query) {
    if query.is_null() {
        return;
    }

    let query_ref = &mut *query;

    // Handle different query types
    match query_ref.commandType {
        pg_sys::CmdType::CMD_SELECT => {
            // Process SELECT queries for function calls in FROM clauses
            if !query_ref.rtable.is_null() {
                process_range_table_for_substrait_calls(query_ref.rtable);
            }
        }
        _ => {
            // For now, we only handle SELECT queries
        }
    }
}

/// Process range table entries to find function calls
unsafe fn process_range_table_for_substrait_calls(rtable: *mut pg_sys::List) {
    if rtable.is_null() {
        return;
    }

    let list_length = pg_sys::list_length(rtable);

    for i in 0..list_length {
        let rte_node = pg_sys::list_nth(rtable, i);
        if rte_node.is_null() {
            continue;
        }

        let rte = rte_node as *mut pg_sys::RangeTblEntry;
        if rte.is_null() {
            continue;
        }

        let rte_ref = &mut *rte;

        // Check if this is a function RTE
        if rte_ref.rtekind == pg_sys::RTEKind::RTE_FUNCTION {
            process_function_rte_for_substrait(rte_ref);
        }
    }
}

/// Process a function RTE to detect from_substrait calls
unsafe fn process_function_rte_for_substrait(rte: &mut pg_sys::RangeTblEntry) {
    if rte.functions.is_null() {
        return;
    }

    let functions_list = rte.functions;
    let list_length = pg_sys::list_length(functions_list);

    for i in 0..list_length {
        let func_node = pg_sys::list_nth(functions_list, i);
        if func_node.is_null() {
            continue;
        }

        let range_func = func_node as *mut pg_sys::RangeTblFunction;
        if range_func.is_null() {
            continue;
        }

        let range_func_ref = &*range_func;

        // Check if the function expression is a FuncExpr
        if !range_func_ref.funcexpr.is_null() {
            let node = range_func_ref.funcexpr;
            if !node.is_null() {
                let node_ref = &*node;

                if node_ref.type_ == pg_sys::NodeTag::T_FuncExpr {
                    let func_expr = node as *mut pg_sys::FuncExpr;
                    if !func_expr.is_null() {
                        process_func_expr_for_substrait(func_expr, rte);
                    }
                }
            }
        }
    }
}

/// Process a FuncExpr to detect from_substrait calls and extract schema
unsafe fn process_func_expr_for_substrait(
    func_expr: *mut pg_sys::FuncExpr,
    rte: &mut pg_sys::RangeTblEntry,
) {
    if func_expr.is_null() {
        return;
    }

    let func_expr_ref = &*func_expr;

    // Get the function name to check if it's from_substrait or from_substrait_json
    let func_name = get_function_name(func_expr_ref.funcid);

    if func_name != "from_substrait" && func_name != "from_substrait_json" {
        return;
    }

    pgrx::info!("Found from_substrait function call, attempting schema extraction");

    // Extract the argument based on function type
    let schema_result = if func_name == "from_substrait_json" {
        // Extract text literal argument for JSON functions
        match extract_text_literal_from_args(func_expr_ref.args) {
            Some(json_text) => extract_schema_from_json(&json_text),
            None => {
                pgrx::warning!("Could not extract text literal from from_substrait_json arguments");
                Err(anyhow::anyhow!("No text literal found"))
            }
        }
    } else {
        // Extract bytea literal argument for binary functions
        match extract_bytea_literal_from_args(func_expr_ref.args) {
            Some(bytea_data) => extract_schema_from_bytea(&bytea_data),
            None => {
                pgrx::warning!("Could not extract bytea literal from from_substrait arguments");
                Err(anyhow::anyhow!("No bytea literal found"))
            }
        }
    };

    match schema_result {
        Ok(schema) => {
            if schema.columns.is_empty() {
                pgrx::warning!("Substrait plan produced empty schema");
                inject_default_schema(rte);
                return;
            }

            pgrx::info!(
                "Successfully extracted schema with {} columns",
                schema.columns.len()
            );

            // Modify the RTE to include the inferred column definitions
            if let Err(e) = inject_column_definitions_into_rte_safe(rte, &schema) {
                pgrx::error!("Failed to inject column definitions: {}", e);
            }
        }
        Err(e) => {
            pgrx::warning!("Failed to extract schema from Substrait plan: {}", e);
            // For robustness, inject a default schema
            inject_default_schema(rte);
        }
    }
}

/// Get function name from function OID
unsafe fn get_function_name(func_oid: pg_sys::Oid) -> String {
    let proc_tuple = pg_sys::SearchSysCache1(PROCOID as i32, func_oid.into());

    if proc_tuple.is_null() {
        return String::new();
    }

    let proc_form = pg_sys::GETSTRUCT(proc_tuple) as *mut pg_sys::Form_pg_proc;
    if proc_form.is_null() {
        pg_sys::ReleaseSysCache(proc_tuple);
        return String::new();
    }

    let name_data = &(**proc_form).proname;
    let name_cstr = std::ffi::CStr::from_ptr(name_data.data.as_ptr());
    let name = name_cstr.to_string_lossy().to_string();

    pg_sys::ReleaseSysCache(proc_tuple);
    name
}

/// Extract text literal from function arguments (for JSON functions)
unsafe fn extract_text_literal_from_args(args: *mut pg_sys::List) -> Option<String> {
    if args.is_null() {
        return None;
    }

    let list_length = pg_sys::list_length(args);
    if list_length == 0 {
        return None;
    }

    // Get the first argument (should be the text literal)
    let first_arg_node = pg_sys::list_nth(args, 0);
    if first_arg_node.is_null() {
        return None;
    }

    let node = first_arg_node as *mut pg_sys::Node;
    if node.is_null() {
        return None;
    }

    let node_ref = &*node;

    // Check if it's a constant (literal)
    if node_ref.type_ == pg_sys::NodeTag::T_Const {
        let const_node = node as *mut pg_sys::Const;
        if const_node.is_null() {
            return None;
        }

        let const_ref = &*const_node;

        // Check if it's a text type
        if const_ref.consttype == pg_sys::TEXTOID {
            return extract_text_from_datum(const_ref.constvalue);
        }
    }

    None
}

/// Extract bytea literal from function arguments
unsafe fn extract_bytea_literal_from_args(args: *mut pg_sys::List) -> Option<Vec<u8>> {
    if args.is_null() {
        return None;
    }

    let list_length = pg_sys::list_length(args);
    if list_length == 0 {
        return None;
    }

    // Get the first argument (should be the bytea literal)
    let first_arg_node = pg_sys::list_nth(args, 0);
    if first_arg_node.is_null() {
        return None;
    }

    let node = first_arg_node as *mut pg_sys::Node;
    if node.is_null() {
        return None;
    }

    let node_ref = &*node;

    // Check if it's a constant (literal)
    if node_ref.type_ == pg_sys::NodeTag::T_Const {
        let const_node = node as *mut pg_sys::Const;
        if const_node.is_null() {
            return None;
        }

        let const_ref = &*const_node;

        // Check if it's a bytea type
        if const_ref.consttype == pg_sys::BYTEAOID {
            return extract_bytea_from_datum(const_ref.constvalue);
        }
    }

    None
}

/// Extract text data from a PostgreSQL Datum
unsafe fn extract_text_from_datum(datum: pg_sys::Datum) -> Option<String> {
    if datum.value() == 0 {
        return None;
    }

    let text_ptr = datum.cast_mut_ptr::<pg_sys::varlena>();
    if text_ptr.is_null() {
        return None;
    }

    let detoasted_ptr = pg_sys::pg_detoast_datum_packed(text_ptr);
    if detoasted_ptr.is_null() {
        return None;
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
        return Some(String::new());
    }

    let slice = std::slice::from_raw_parts(data_ptr, data_len);
    // Convert bytes to string, handling potential UTF-8 issues
    String::from_utf8(slice.to_vec()).ok()
}

/// Extract bytea data from a PostgreSQL Datum
unsafe fn extract_bytea_from_datum(datum: pg_sys::Datum) -> Option<Vec<u8>> {
    if datum.value() == 0 {
        return None;
    }

    let bytea_ptr = datum.cast_mut_ptr::<pg_sys::varlena>();
    if bytea_ptr.is_null() {
        return None;
    }

    let detoasted_ptr = pg_sys::pg_detoast_datum_packed(bytea_ptr);
    if detoasted_ptr.is_null() {
        return None;
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
        return None;
    }

    let slice = std::slice::from_raw_parts(data_ptr, data_len);
    Some(slice.to_vec())
}

/// Extract schema information from JSON string containing a Substrait plan
fn extract_schema_from_json(json_data: &str) -> Result<SubstraitSchema> {
    // Parse the JSON to a Substrait plan
    let plan = serde_json::from_str::<Plan>(json_data)
        .map_err(|e| anyhow::anyhow!("Failed to parse JSON as Substrait plan: {}", e))?;

    // Use the existing plan execution logic to extract schema
    let result_data = crate::plan_translator::execute_substrait_plan(plan)
        .map_err(|e| anyhow::anyhow!("Failed to execute plan for schema: {}", e))?;

    // Convert to our schema format
    let columns = result_data
        .columns
        .into_iter()
        .map(|col| SubstraitColumn {
            name: col.name,
            postgres_type: match col.type_oid {
                pg_sys::INT4OID => "integer".to_string(),
                pg_sys::INT8OID => "bigint".to_string(),
                pg_sys::TEXTOID => "text".to_string(),
                pg_sys::FLOAT4OID => "real".to_string(),
                pg_sys::FLOAT8OID => "double precision".to_string(),
                pg_sys::BOOLOID => "boolean".to_string(),
                _ => "text".to_string(), // Default fallback
            },
            type_oid: col.type_oid,
        })
        .collect();

    Ok(SubstraitSchema { columns })
}

/// Extract schema information from bytea data containing a Substrait plan
fn extract_schema_from_bytea(bytea_data: &[u8]) -> Result<SubstraitSchema> {
    // Decode the Substrait plan from protobuf
    let plan = Plan::decode(bytea_data)
        .map_err(|e| anyhow::anyhow!("Failed to decode Substrait plan: {}", e))?;

    // Use the existing plan execution logic to extract schema
    let result_data = crate::plan_translator::execute_substrait_plan(plan)
        .map_err(|e| anyhow::anyhow!("Failed to execute plan for schema: {}", e))?;

    // Convert to our schema format
    let columns = result_data
        .columns
        .into_iter()
        .map(|col| SubstraitColumn {
            name: col.name,
            postgres_type: match col.type_oid {
                pg_sys::INT4OID => "integer".to_string(),
                pg_sys::INT8OID => "bigint".to_string(),
                pg_sys::TEXTOID => "text".to_string(),
                pg_sys::FLOAT4OID => "real".to_string(),
                pg_sys::FLOAT8OID => "double precision".to_string(),
                pg_sys::BOOLOID => "boolean".to_string(),
                _ => "text".to_string(), // Default fallback
            },
            type_oid: col.type_oid,
        })
        .collect();

    Ok(SubstraitSchema { columns })
}

/// Safe wrapper for injecting column definitions
unsafe fn inject_column_definitions_into_rte_safe(
    rte: &mut pg_sys::RangeTblEntry,
    schema: &SubstraitSchema,
) -> Result<()> {
    inject_column_definitions_into_rte(rte, schema)
        .map_err(|e| anyhow::anyhow!("Column injection failed: {}", e))
}

/// Inject column definitions into a RangeTblEntry
unsafe fn inject_column_definitions_into_rte(
    rte: &mut pg_sys::RangeTblEntry,
    schema: &SubstraitSchema,
) -> Result<()> {
    // Create column aliases and types
    let num_cols = schema.columns.len();

    // Create eref (alias information)
    if rte.eref.is_null() {
        // Create a new alias if none exists
        let alias = pg_sys::palloc0(std::mem::size_of::<pg_sys::Alias>()) as *mut pg_sys::Alias;
        (*alias).aliasname = create_cstring("substrait_result");
        (*alias).colnames = std::ptr::null_mut();
        rte.eref = alias;
    }

    let eref = &mut *rte.eref;

    // Clear existing column names
    eref.colnames = std::ptr::null_mut();

    // Add column names from schema
    for column in &schema.columns {
        let colname_value = create_cstring(&column.name);
        let colname_node = pg_sys::makeString(colname_value);
        eref.colnames = pg_sys::lappend(eref.colnames, colname_node as *mut std::ffi::c_void);
    }

    // Create function column information if needed
    // This ensures PostgreSQL knows about the column types
    create_function_column_info(rte, schema);

    pgrx::info!("Injected {} column definitions into RTE", num_cols);
    Ok(())
}

/// Create function column information for the RTE
unsafe fn create_function_column_info(rte: &mut pg_sys::RangeTblEntry, schema: &SubstraitSchema) {
    // Create a list of column definition information
    // This helps PostgreSQL understand the structure of the function result

    if !rte.functions.is_null() {
        let functions_list = rte.functions;
        let list_length = pg_sys::list_length(functions_list);

        for i in 0..list_length {
            let func_node = pg_sys::list_nth(functions_list, i);
            if func_node.is_null() {
                continue;
            }

            let range_func = func_node as *mut pg_sys::RangeTblFunction;
            if range_func.is_null() {
                continue;
            }

            let range_func_ref = &mut *range_func;

            // Create column definition list
            let mut coldeflist = std::ptr::null_mut();

            for (idx, column) in schema.columns.iter().enumerate() {
                // Create a column definition
                let coldef = create_column_definition(column, idx as i16 + 1);
                coldeflist = pg_sys::lappend(coldeflist, coldef as *mut std::ffi::c_void);
            }

            // Store the column definitions
            range_func_ref.funccolnames = coldeflist;
        }
    }
}

/// Create a column definition for a schema column
unsafe fn create_column_definition(
    column: &SubstraitColumn,
    _attr_number: i16,
) -> *mut pg_sys::ColumnDef {
    let coldef =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::ColumnDef>()) as *mut pg_sys::ColumnDef;

    (*coldef).type_ = pg_sys::NodeTag::T_ColumnDef;
    (*coldef).colname = create_cstring(&column.name);

    // Create type name
    let typename =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::TypeName>()) as *mut pg_sys::TypeName;
    (*typename).type_ = pg_sys::NodeTag::T_TypeName;

    // Set type names based on the PostgreSQL type
    let type_parts = match column.postgres_type.as_str() {
        "integer" => vec!["pg_catalog", "int4"],
        "bigint" => vec!["pg_catalog", "int8"],
        "text" => vec!["pg_catalog", "text"],
        "real" => vec!["pg_catalog", "float4"],
        "double precision" => vec!["pg_catalog", "float8"],
        "boolean" => vec!["pg_catalog", "bool"],
        _ => vec!["pg_catalog", "text"],
    };

    let mut names_list = std::ptr::null_mut();
    for part in type_parts {
        let name_str = create_cstring(part);
        let name_node = pg_sys::makeString(name_str);
        names_list = pg_sys::lappend(names_list, name_node as *mut std::ffi::c_void);
    }

    (*typename).names = names_list;
    (*typename).typeOid = column.type_oid;

    (*coldef).typeName = typename;

    coldef
}

/// Inject a default schema when schema extraction fails
unsafe fn inject_default_schema(rte: &mut pg_sys::RangeTblEntry) {
    let default_schema = SubstraitSchema {
        columns: vec![SubstraitColumn {
            name: "result".to_string(),
            postgres_type: "text".to_string(),
            type_oid: pg_sys::TEXTOID,
        }],
    };

    pgrx::info!("Injecting default schema for failed schema extraction");

    if let Err(e) = inject_column_definitions_into_rte(rte, &default_schema) {
        pgrx::error!("Failed to inject default schema: {:?}", e);
    }
}

/// Helper function to create a C string (from existing lib.rs)
fn create_cstring(s: &str) -> *mut std::os::raw::c_char {
    let cstring = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
    unsafe {
        let len = cstring.as_bytes_with_nul().len();
        let ptr = pg_sys::palloc(len) as *mut std::os::raw::c_char;
        std::ptr::copy_nonoverlapping(cstring.as_ptr(), ptr, len);
        ptr
    }
}
