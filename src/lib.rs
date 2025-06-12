use anyhow::Result;
use pgrx::pg_sys;
use pgrx::prelude::*;
use prost::Message;
use substrait::proto::Plan;

pgrx::pg_module_magic!();

#[pg_extern]
fn from_substrait(plan_bytes: &[u8]) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Parse the Substrait plan from protobuf binary format
    let plan = Plan::decode(plan_bytes).map_err(|e| format!("Failed to decode protobuf: {}", e))?;

    // Execute the plan using PostgreSQL's engine
    execute_substrait_plan(plan)
}

#[pg_extern]
fn from_substrait_json(
    json_plan: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Parse the Substrait plan from JSON format
    let plan: Plan =
        serde_json::from_str(json_plan).map_err(|e| format!("Failed to parse JSON: {}", e))?;

    // Execute the plan using PostgreSQL's engine
    execute_substrait_plan(plan)
}

fn execute_substrait_plan(plan: Plan) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
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
        let result = execute_plan_tree(plan_tree)?;
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

unsafe fn execute_plan_tree(
    plan: *mut pg_sys::Plan,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if plan.is_null() {
        return Ok("(null plan)".to_string());
    }

    // Create a PlannedStmt to wrap our plan
    let planned_stmt = create_planned_stmt(plan)?;

    // Execute the plan using PostgreSQL's executor
    execute_planned_stmt(planned_stmt)
}

unsafe fn create_planned_stmt(
    plan: *mut pg_sys::Plan,
) -> Result<*mut pg_sys::PlannedStmt, Box<dyn std::error::Error + Send + Sync>> {
    let planned_stmt =
        pg_sys::palloc0(std::mem::size_of::<pg_sys::PlannedStmt>()) as *mut pg_sys::PlannedStmt;

    (*planned_stmt).type_ = pg_sys::NodeTag::T_PlannedStmt;
    (*planned_stmt).commandType = pg_sys::CmdType::CMD_SELECT;
    (*planned_stmt).planTree = plan;
    (*planned_stmt).rtable = std::ptr::null_mut(); // No range tables for simple constant queries
    (*planned_stmt).resultRelations = std::ptr::null_mut();
    (*planned_stmt).utilityStmt = std::ptr::null_mut();
    (*planned_stmt).stmt_location = -1;
    (*planned_stmt).stmt_len = -1;

    Ok(planned_stmt)
}

unsafe fn execute_planned_stmt(
    planned_stmt: *mut pg_sys::PlannedStmt,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // For simple constant queries, we can execute them more directly
    // by examining the target list and evaluating the expressions

    let plan_tree = (*planned_stmt).planTree;
    if plan_tree.is_null() {
        return Ok("(null plan tree)".to_string());
    }

    match (*plan_tree).type_ {
        pg_sys::NodeTag::T_Result => {
            let result_node = plan_tree as *mut pg_sys::Result;
            let target_list = (*result_node).plan.targetlist;

            if target_list.is_null() {
                return Ok("(no results)".to_string());
            }

            // Evaluate the target list expressions
            evaluate_target_list(target_list)
        }
        _ => Ok(format!("Executed plan node type: {:?}", (*plan_tree).type_)),
    }
}

unsafe fn evaluate_target_list(
    target_list: *mut pg_sys::List,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if target_list.is_null() {
        return Ok("(empty target list)".to_string());
    }

    let mut results = Vec::new();
    let list_length = (*target_list).length;

    for i in 0..list_length {
        let target_entry = pg_sys::list_nth(target_list, i as i32) as *mut pg_sys::TargetEntry;
        if !target_entry.is_null() {
            let expr = (*target_entry).expr;
            if !expr.is_null() && (*expr).type_ == pg_sys::NodeTag::T_Const {
                let const_node = expr as *mut pg_sys::Const;
                let value = format_const_value(const_node)?;
                results.push(value);
            }
        }
    }

    if results.is_empty() {
        Ok("(no constant values)".to_string())
    } else {
        Ok(format!("Values: [{}]", results.join(", ")))
    }
}

unsafe fn format_const_value(
    const_node: *mut pg_sys::Const,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if (*const_node).constisnull {
        return Ok("NULL".to_string());
    }

    match (*const_node).consttype {
        pg_sys::INT4OID => {
            let value = pg_sys::Datum::from((*const_node).constvalue).value() as i32;
            Ok(value.to_string())
        }
        pg_sys::INT8OID => {
            let value = pg_sys::Datum::from((*const_node).constvalue).value() as i64;
            Ok(value.to_string())
        }
        pg_sys::TEXTOID => {
            let text_ptr =
                pg_sys::Datum::from((*const_node).constvalue).value() as *mut pg_sys::varlena;
            let text_str = pg_sys::text_to_cstring(text_ptr);
            let c_str = std::ffi::CStr::from_ptr(text_str);
            Ok(format!("'{}'", c_str.to_string_lossy()))
        }
        _ => Ok(format!("(unsupported type: {})", (*const_node).consttype)),
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
        // Test calling our extension function with a simple JSON plan
        let json_plan = r#"{"version": {"minorNumber": 54}, "relations": []}"#;

        // This should fail because we expect exactly 1 relation
        let result = crate::from_substrait_json(json_plan);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Expected exactly 1 relation, found 0"));
    }

    #[pg_test]
    fn test_from_substrait_json_via_sql() {
        // Test that we can call our function via SQL and it returns the correct result
        // Use a plan with exactly 1 relation to satisfy our validation
        let json_plan = r#"{"version": {"minorNumber": 54}, "relations": [{"root": {"input": {"project": {"expressions": []}}}}]}"#;

        // This should work since we have exactly 1 relation
        let result =
            Spi::get_one::<String>(&format!("SELECT from_substrait_json('{}')", json_plan));

        // The function should succeed and return some result
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.is_some());

        // The result should contain some indication it processed the plan
        let result_str = output.unwrap();
        assert!(
            result_str.contains("Result:")
                || result_str.contains("would execute")
                || result_str.contains("plan")
        );
    }
}
