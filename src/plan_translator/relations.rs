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
/// This function directly accesses protobuf data without PostgreSQL memory context issues
pub fn build_function_extension_map(plan: Plan) -> HashMap<u32, String> {
    let mut function_map = HashMap::new();

    eprintln!(
        "DEBUG: build_function_extension_map called with {} extensions",
        plan.extensions.len()
    );

    // Direct access to plan extensions - this should be safe as it's just reading protobuf data
    for (index, extension) in plan.extensions.iter().enumerate() {
        eprintln!("DEBUG: Processing extension {}", index);

        if let Some(mapping_type) = &extension.mapping_type {
            match mapping_type {
                substrait::proto::extensions::simple_extension_declaration::MappingType::ExtensionFunction(func) => {
                    eprintln!("DEBUG: Found function '{}' with anchor {}", func.name, func.function_anchor);
                    function_map.insert(func.function_anchor, func.name.clone());
                }
                _ => {
                    eprintln!("DEBUG: Extension {} has non-function mapping type", index);
                }
            }
        } else {
            eprintln!("DEBUG: Extension {} has no mapping_type", index);
        }
    }

    eprintln!(
        "DEBUG: Built function map with {} functions",
        function_map.len()
    );
    for (anchor, name) in &function_map {
        eprintln!("DEBUG: Function {}: {}", anchor, name);
    }

    function_map
}

/// Convert plan relation with function context
pub unsafe fn convert_plan_relation_to_plan_tree_with_context(
    relation: &PlanRel,
    _function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("DEBUG: convert_plan_relation_to_plan_tree_with_context called");
    pgrx::info!("DEBUG: convert_plan_relation_to_plan_tree_with_context called");

    if let Some(rel_type) = &relation.rel_type {
        eprintln!("DEBUG: Found relation rel_type");
        pgrx::info!("DEBUG: Found relation rel_type");

        match rel_type {
            substrait::proto::plan_rel::RelType::Root(root) => {
                eprintln!("DEBUG: Processing Root relation");
                pgrx::info!("DEBUG: Processing Root relation");

                if let Some(input) = &root.input {
                    eprintln!(
                        "DEBUG: Root has input, calling convert_rel_to_plan_tree_with_context"
                    );
                    pgrx::info!(
                        "DEBUG: Root has input, calling convert_rel_to_plan_tree_with_context"
                    );

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

    eprintln!("DEBUG: convert_rel_to_plan_tree_with_context called");
    pgrx::info!("DEBUG: convert_rel_to_plan_tree_with_context called");

    // Debug what relation type we're about to process
    let relation_type_name = match &rel.rel_type {
        Some(rel_type) => get_relation_type_name(rel_type),
        None => "None",
    };
    eprintln!(
        "DEBUG: About to process relation type: {}",
        relation_type_name
    );
    pgrx::info!(
        "DEBUG: About to process relation type: {}",
        relation_type_name
    );

    // The common field with emit/output_mapping is on the specific relation types
    eprintln!("DEBUG: Checking for common/emit fields on specific relation types");
    pgrx::info!("DEBUG: Checking for common/emit fields on specific relation types");

    let result = match &rel.rel_type {
        Some(RelType::Project(project)) => {
            // Handle projection - create a Result node
            eprintln!("DEBUG: ✅ Project relation - starts processing");
            pgrx::info!("DEBUG: ✅ Project relation - starts processing");

            // Check for common field with emit/output_mapping on ProjectRel
            if let Some(common) = &project.common {
                eprintln!("DEBUG: Project relation has common field");
                pgrx::info!("DEBUG: Project relation has common field");

                // Check the emit_kind field structure
                if let Some(emit_kind) = &common.emit_kind {
                    match emit_kind {
                        substrait::proto::rel_common::EmitKind::Emit(emit) => {
                            eprintln!(
                                "DEBUG: Project common has emit with {} output mappings",
                                emit.output_mapping.len()
                            );
                            pgrx::info!(
                                "DEBUG: Project common has emit with {} output mappings",
                                emit.output_mapping.len()
                            );

                            for (i, mapping) in emit.output_mapping.iter().enumerate() {
                                eprintln!("DEBUG: Project output mapping {}: {}", i, mapping);
                                pgrx::info!("DEBUG: Project output mapping {}: {}", i, mapping);
                            }
                        }
                        substrait::proto::rel_common::EmitKind::Direct(_) => {
                            eprintln!("DEBUG: Project common has direct emit (no output mapping)");
                            pgrx::info!(
                                "DEBUG: Project common has direct emit (no output mapping)"
                            );
                        }
                    }
                } else {
                    eprintln!("DEBUG: Project common field has no emit_kind");
                    pgrx::info!("DEBUG: Project common field has no emit_kind");
                }
            } else {
                eprintln!("DEBUG: Project relation has no common field");
                pgrx::info!("DEBUG: Project relation has no common field");
            }

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
            eprintln!("DEBUG: ✅ Read relation - starts processing");
            pgrx::info!("DEBUG: ✅ Read relation - starts processing");

            // Check for common field with emit/output_mapping on ReadRel
            if let Some(common) = &read.common {
                eprintln!("DEBUG: Read relation has common field");
                pgrx::info!("DEBUG: Read relation has common field");

                // Check the emit_kind field structure
                if let Some(emit_kind) = &common.emit_kind {
                    match emit_kind {
                        substrait::proto::rel_common::EmitKind::Emit(emit) => {
                            eprintln!(
                                "DEBUG: Read common has emit with {} output mappings",
                                emit.output_mapping.len()
                            );
                            pgrx::info!(
                                "DEBUG: Read common has emit with {} output mappings",
                                emit.output_mapping.len()
                            );

                            for (i, mapping) in emit.output_mapping.iter().enumerate() {
                                eprintln!("DEBUG: Read output mapping {}: {}", i, mapping);
                                pgrx::info!("DEBUG: Read output mapping {}: {}", i, mapping);
                            }
                        }
                        substrait::proto::rel_common::EmitKind::Direct(_) => {
                            eprintln!("DEBUG: Read common has direct emit (no output mapping)");
                            pgrx::info!("DEBUG: Read common has direct emit (no output mapping)");
                        }
                    }
                } else {
                    eprintln!("DEBUG: Read common field has no emit_kind");
                    pgrx::info!("DEBUG: Read common field has no emit_kind");
                }
            } else {
                eprintln!("DEBUG: Read relation has no common field");
                pgrx::info!("DEBUG: Read relation has no common field");
            }

            if let Some(read_type) = &read.read_type {
                eprintln!("DEBUG: Read relation has read_type");
                pgrx::info!("DEBUG: Read relation has read_type");

                let read_result = match read_type {
                    substrait::proto::read_rel::ReadType::VirtualTable(_vt) => {
                        eprintln!("DEBUG: Processing VirtualTable read type");
                        pgrx::info!("DEBUG: Processing VirtualTable read type");
                        // Virtual table - create a Values scan node
                        create_values_scan_node()
                    }
                    substrait::proto::read_rel::ReadType::NamedTable(nt) => {
                        eprintln!("DEBUG: Processing NamedTable read type");
                        pgrx::info!("DEBUG: Processing NamedTable read type");
                        // Named table - create a SeqScan node
                        let table_name = nt.names.join(".");
                        eprintln!(
                            "DEBUG: About to create SeqScan node for table: {}",
                            table_name
                        );
                        pgrx::info!(
                            "DEBUG: About to create SeqScan node for table: {}",
                            table_name
                        );

                        let (plan, _rte) = create_seqscan_node_with_scanrelid(&table_name, 1)?;

                        eprintln!(
                            "DEBUG: SeqScan node creation completed for table: {}",
                            table_name
                        );
                        pgrx::info!(
                            "DEBUG: SeqScan node creation completed for table: {}",
                            table_name
                        );

                        eprintln!("DEBUG: About to return from NamedTable processing");
                        pgrx::info!("DEBUG: About to return from NamedTable processing");

                        Ok(plan)
                    }
                    _ => {
                        eprintln!("DEBUG: Unsupported read type encountered");
                        pgrx::info!("DEBUG: Unsupported read type encountered");
                        Err("Unsupported read type".into())
                    }
                };

                eprintln!("DEBUG: Read relation processing completed, about to return result");
                pgrx::info!("DEBUG: Read relation processing completed, about to return result");

                // Check if the read_result is Ok before returning
                match &read_result {
                    Ok(plan_ptr) => {
                        eprintln!("DEBUG: Read result is Ok, plan pointer: {:p}", plan_ptr);
                        pgrx::info!("DEBUG: Read result is Ok, plan pointer: {:p}", plan_ptr);
                    }
                    Err(e) => {
                        eprintln!("DEBUG: Read result is Err: {}", e);
                        pgrx::info!("DEBUG: Read result is Err: {}", e);
                    }
                }

                eprintln!("DEBUG: About to return read_result from Read relation");
                pgrx::info!("DEBUG: About to return read_result from Read relation");

                read_result
            } else {
                eprintln!("DEBUG: Read relation missing read type");
                pgrx::info!("DEBUG: Read relation missing read type");
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
                    OffsetMode::Offset(constant_offset) => {
                        // Support deprecated constant offset by converting to expression
                        eprintln!("WARNING: Using deprecated constant offset field. Consider migrating to offset_expr.");
                        Some(unsafe { super::expressions::create_int8_const(*constant_offset)? })
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
                    CountMode::Count(constant_count) => {
                        // Support deprecated constant count by converting to expression
                        eprintln!("WARNING: Using deprecated constant count field. Consider migrating to count_expr.");
                        Some(unsafe { super::expressions::create_int8_const(*constant_count)? })
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
    };

    eprintln!("DEBUG: About to return from convert_rel_to_plan_tree_with_context");
    pgrx::info!("DEBUG: About to return from convert_rel_to_plan_tree_with_context");

    // Debug the result before returning
    match &result {
        Ok(plan_ptr) => {
            eprintln!("DEBUG: Function result is Ok, plan pointer: {:p}", plan_ptr);
            pgrx::info!("DEBUG: Function result is Ok, plan pointer: {:p}", plan_ptr);
        }
        Err(e) => {
            eprintln!("DEBUG: Function result is Err: {}", e);
            pgrx::info!("DEBUG: Function result is Err: {}", e);
        }
    }

    result
}
