use anyhow::Result;
use pgrx::pg_sys;
use std::collections::HashMap;
use substrait::proto::{Plan, PlanRel, Rel};

use super::constants::get_relation_type_name;
use super::expressions::{
    convert_expression_to_postgres_with_context, convert_expressions_to_target_list_with_context,
};
use super::plan_nodes::*;

/// Build a map of function references to their names from the plan's extensions
pub fn build_function_extension_map(plan: &Plan) -> HashMap<u32, String> {
    let mut function_map = HashMap::new();

    for extension in &plan.extensions {
        if let Some(ext_type) = &extension.mapping_type {
            match ext_type {
                substrait::proto::extensions::simple_extension_declaration::MappingType::ExtensionFunction(func) => {
                    function_map.insert(func.function_anchor, func.name.clone());
                }
                _ => {} // Handle other extension types as needed
            }
        }
    }

    function_map
}

/// Convert plan relation with function context
pub unsafe fn convert_plan_relation_to_plan_tree_with_context(
    relation: &PlanRel,
    _function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(rel_type) = &relation.rel_type {
        match rel_type {
            substrait::proto::plan_rel::RelType::Root(root) => {
                if let Some(input) = &root.input {
                    convert_rel_to_plan_tree_with_context(input, _function_map)
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

/// Convert relation with function context
pub unsafe fn convert_rel_to_plan_tree_with_context(
    rel: &Rel,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::rel::RelType;

    match &rel.rel_type {
        Some(RelType::Project(project)) => {
            // Handle projection - create a Result node
            if let Some(input) = &project.input {
                // Project with input - create Result node with input as left tree
                let input_plan = convert_rel_to_plan_tree_with_context(input, function_map)?;

                // Convert expressions to PostgreSQL target entries
                let target_list = convert_expressions_to_target_list_with_context(
                    &project.expressions,
                    function_map,
                )?;

                // Create a Result plan node using PostgreSQL's memory allocator
                let result_node =
                    pg_sys::palloc0(std::mem::size_of::<pg_sys::Result>()) as *mut pg_sys::Result;
                (*result_node).plan.type_ = pg_sys::NodeTag::T_Result;
                (*result_node).plan.lefttree = input_plan;
                (*result_node).plan.targetlist = target_list;
                (*result_node).plan.righttree = std::ptr::null_mut();
                (*result_node).plan.initPlan = std::ptr::null_mut();
                (*result_node).plan.extParam = std::ptr::null_mut();
                (*result_node).plan.allParam = std::ptr::null_mut();
                (*result_node).plan.startup_cost = 0.0;
                (*result_node).plan.total_cost = 1.0;
                (*result_node).plan.plan_rows = 1.0;
                (*result_node).plan.plan_width = 32;
                (*result_node).plan.parallel_aware = false;
                (*result_node).plan.parallel_safe = true;
                (*result_node).plan.async_capable = false;
                (*result_node).plan.plan_node_id = 0;
                (*result_node).plan.qual = std::ptr::null_mut();

                Ok(result_node as *mut pg_sys::Plan)
            } else {
                // Project with no input (literal projections) - create Values scan node
                let target_list = convert_expressions_to_target_list_with_context(
                    &project.expressions,
                    function_map,
                )?;

                // Create a ValuesScan plan node for literal projections
                create_values_scan_with_target_list(target_list)
            }
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
        Some(RelType::Sort(sort)) => {
            // Handle sort relation - create a Sort node
            let input_plan = if let Some(input) = &sort.input {
                convert_rel_to_plan_tree_with_context(input, function_map)?
            } else {
                return Err("Sort relation missing input".into());
            };

            create_sort_node(input_plan, &sort.sorts)
        }
        Some(RelType::Fetch(fetch)) => {
            // Handle fetch relation - create a Limit node
            let input_plan = if let Some(input) = &fetch.input {
                convert_rel_to_plan_tree_with_context(input, function_map)?
            } else {
                return Err("Fetch relation missing input".into());
            };

            // Extract offset and count from the fetch relation using expression conversion
            let offset_expr = if let Some(offset_mode) = &fetch.offset_mode {
                use substrait::proto::fetch_rel::OffsetMode;
                match offset_mode {
                    OffsetMode::OffsetExpr(expr) => Some(
                        convert_expression_to_postgres_with_context(expr, function_map)?,
                    ),
                    OffsetMode::Offset(_) => {
                        return Err(
                            "Deprecated constant offset not supported, use offset_expr instead"
                                .into(),
                        );
                    }
                }
            } else {
                None // No offset limit
            };

            let count_expr = if let Some(count_mode) = &fetch.count_mode {
                use substrait::proto::fetch_rel::CountMode;
                match count_mode {
                    CountMode::CountExpr(expr) => Some(
                        convert_expression_to_postgres_with_context(expr, function_map)?,
                    ),
                    CountMode::Count(_) => {
                        return Err(
                            "Deprecated constant count not supported, use count_expr instead"
                                .into(),
                        );
                    }
                }
            } else {
                None // No count limit
            };

            create_limit_node_with_expressions(input_plan, offset_expr, count_expr)
        }
        Some(RelType::Filter(filter)) => {
            // Handle filter relation - create a Filter node
            let input_plan = if let Some(input) = &filter.input {
                convert_rel_to_plan_tree_with_context(input, function_map)?
            } else {
                return Err("Filter relation missing input".into());
            };

            // Convert the filter condition to a PostgreSQL expression
            let condition_expr = if let Some(condition) = &filter.condition {
                convert_expression_to_postgres_with_context(condition, function_map)?
            } else {
                return Err("Filter relation missing condition".into());
            };

            create_filter_node(input_plan, condition_expr)
        }
        Some(RelType::Cross(cross)) => {
            // Handle cross relation - create a NestLoop node for Cartesian product
            let left_plan = if let Some(left) = &cross.left {
                convert_rel_to_plan_tree_with_context(left, function_map)?
            } else {
                return Err("Cross relation missing left input".into());
            };

            let right_plan = if let Some(right) = &cross.right {
                convert_rel_to_plan_tree_with_context(right, function_map)?
            } else {
                return Err("Cross relation missing right input".into());
            };

            create_cross_join_node(left_plan, right_plan)
        }
        Some(RelType::Aggregate(aggregate)) => {
            // Handle aggregate relation - create an Agg node for GROUP BY and aggregate functions
            let input_plan = if let Some(input) = &aggregate.input {
                convert_rel_to_plan_tree_with_context(input, function_map)?
            } else {
                return Err("Aggregate relation missing input".into());
            };

            create_aggregate_node(input_plan, aggregate, function_map)
        }
        Some(rel_type) => {
            let type_name = get_relation_type_name(rel_type);
            Err(format!(
                "Unsupported relation type: {} (implementation needed)",
                type_name
            )
            .into())
        }
        None => Err("Relation missing rel_type".into()),
    }
}
