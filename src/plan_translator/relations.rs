use super::constants::get_relation_type_name;
use super::expressions::{
    convert_expression_to_postgres_with_context, convert_expression_to_postgres_with_schema,
    convert_expressions_to_target_list_with_schema,
};
use super::plan_nodes::*;
use super::schema::RelationSchema;
use crate::plan_translator::aggregate::create_aggregate_node;
use anyhow::Result;
use pgrx::pg_sys;
use std::collections::HashMap;
use substrait::proto::{Plan, PlanRel, Rel};

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
        eprintln!("DEBUG: Processing extension {index}");

        if let Some(mapping_type) = &extension.mapping_type {
            match mapping_type {
                substrait::proto::extensions::simple_extension_declaration::MappingType::ExtensionFunction(func) => {
                    eprintln!("DEBUG: Found function '{}' with anchor {}", func.name, func.function_anchor);
                    function_map.insert(func.function_anchor, func.name.clone());
                }
                _ => {
                    eprintln!("DEBUG: Extension {index} has non-function mapping type");
                }
            }
        } else {
            eprintln!("DEBUG: Extension {index} has no mapping_type");
        }
    }

    eprintln!(
        "DEBUG: Built function map with {} functions",
        function_map.len()
    );
    for (anchor, name) in &function_map {
        eprintln!("DEBUG: Function {anchor}: {name}");
    }

    function_map
}

/// Convert plan relation with function context
pub unsafe fn convert_plan_relation_to_plan_tree_with_context(
    relation: &PlanRel,
    _function_map: &HashMap<u32, String>,
    current_table_oid: Option<pg_sys::Oid>,
) -> Result<
    (*mut pg_sys::Plan, *mut pg_sys::List, RelationSchema),
    Box<dyn std::error::Error + Send + Sync>,
> {
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

                    let result = convert_rel_to_plan_tree_with_context(
                        input,
                        _function_map,
                        current_table_oid,
                    );

                    eprintln!("DEBUG: convert_rel_to_plan_tree_with_context returned to caller");
                    pgrx::info!("DEBUG: convert_rel_to_plan_tree_with_context returned to caller");

                    let (plan, range_table, schema) = result?;

                    eprintln!("DEBUG: Unpacked result successfully, plan={:p}", plan);
                    pgrx::info!("DEBUG: Unpacked result successfully, plan={:p}", plan);

                    Ok((plan, range_table, schema))
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

/// Extract table name from a NamedTable
pub fn extract_table_name_from_named_table(
    named_table: &substrait::proto::read_rel::NamedTable,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    if named_table.names.is_empty() {
        return Err("NamedTable has no names".into());
    }

    // Get the last name in the hierarchy (the actual table name)
    let table_name = named_table
        .names
        .last()
        .ok_or("NamedTable names list is empty")?
        .clone();

    eprintln!("DEBUG: Extracted table name: {table_name}");
    pgrx::info!("DEBUG: Extracted table name: {}", table_name);

    Ok(table_name)
}

/// Convert relation with function context
pub unsafe fn convert_rel_to_plan_tree_with_context(
    rel: &Rel,
    function_map: &HashMap<u32, String>,
    current_table_oid: Option<pg_sys::Oid>,
) -> Result<
    (*mut pg_sys::Plan, *mut pg_sys::List, RelationSchema),
    Box<dyn std::error::Error + Send + Sync>,
> {
    use substrait::proto::rel::RelType;

    eprintln!("DEBUG: convert_rel_to_plan_tree_with_context called");
    pgrx::info!("DEBUG: convert_rel_to_plan_tree_with_context called");

    // Debug what relation type we're about to process
    let relation_type_name = match &rel.rel_type {
        Some(rel_type) => get_relation_type_name(rel_type),
        None => "None",
    };
    eprintln!("DEBUG: About to process relation type: {relation_type_name}");
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
                                eprintln!("DEBUG: Project output mapping {i}: {mapping}");
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
                let (input_plan, input_range_table, input_schema) =
                    convert_rel_to_plan_tree_with_context(input, function_map, current_table_oid)?;

                eprintln!(
                    "DEBUG: Project relation input schema has {} columns",
                    input_schema.column_count()
                );
                pgrx::info!(
                    "DEBUG: Project relation input schema has {} columns",
                    input_schema.column_count()
                );

                // Convert expressions to PostgreSQL target entries using the input schema
                let (target_list, output_schema) = convert_expressions_to_target_list_with_schema(
                    &project.expressions,
                    function_map,
                    &input_schema,
                )?;

                // Create a Result plan node using PostgreSQL's memory allocator
                let mut result_node = pgrx::PgBox::<pg_sys::Result>::alloc0();
                result_node.plan.type_ = pg_sys::NodeTag::T_Result;
                result_node.plan.lefttree = input_plan;
                result_node.plan.targetlist = target_list;
                result_node.plan.righttree = std::ptr::null_mut();
                result_node.plan.initPlan = std::ptr::null_mut();
                result_node.plan.extParam = std::ptr::null_mut();
                result_node.plan.allParam = std::ptr::null_mut();
                result_node.plan.startup_cost = 0.0;
                result_node.plan.total_cost = 1.0;
                result_node.plan.plan_rows = 1.0;
                result_node.plan.plan_width = 32;
                result_node.plan.parallel_aware = false;
                result_node.plan.parallel_safe = true;
                result_node.plan.plan_node_id = 0;
                result_node.plan.qual = std::ptr::null_mut();

                let result_ptr = result_node.into_pg();
                // Return pointer to the plan field with output schema
                Ok((
                    &mut (*result_ptr).plan as *mut pg_sys::Plan,
                    input_range_table,
                    output_schema,
                ))
            } else {
                // Project with no input (literal projections) - create Result node
                // For literal projections, use empty input schema
                let empty_schema = RelationSchema::new();
                let (target_list, output_schema) = convert_expressions_to_target_list_with_schema(
                    &project.expressions,
                    function_map,
                    &empty_schema,
                )?;

                // Create a Result plan node for literal projections (matches PostgreSQL behavior)
                let result_plan = create_result_node_with_target_list(target_list)?;
                Ok((result_plan, std::ptr::null_mut(), output_schema))
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
                                eprintln!("DEBUG: Read output mapping {i}: {mapping}");
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

                match read_type {
                    substrait::proto::read_rel::ReadType::VirtualTable(_vt) => {
                        eprintln!("DEBUG: Processing VirtualTable read type");
                        pgrx::info!("DEBUG: Processing VirtualTable read type");
                        // Virtual table - create a Values scan node
                        let plan = create_values_scan_node()?;
                        // For virtual tables, create an empty schema for now
                        // TODO: Extract schema from virtual table data
                        let schema = RelationSchema::new();
                        Ok((plan, std::ptr::null_mut(), schema))
                    }
                    substrait::proto::read_rel::ReadType::NamedTable(nt) => {
                        eprintln!(
                            "DEBUG: Processing NamedTable read type - CREATING PROPER SEQSCAN"
                        );
                        pgrx::info!(
                            "DEBUG: Processing NamedTable read type - CREATING PROPER SEQSCAN"
                        );

                        // Extract table name from the NamedTable
                        let table_name = extract_table_name_from_named_table(nt)?;

                        // Create a proper SeqScan node with range table entry
                        // We use scanrelid 1 as this will be the first (and possibly only) table
                        let (seqscan_plan, range_table_entry) =
                            create_seqscan_node_with_scanrelid(&table_name, 1)?;

                        // Extract table OID from the range table entry to build schema
                        let table_oid = (*range_table_entry).relid;
                        let base_schema = RelationSchema::from_table_oid(table_oid)?;

                        // Create a range table list with our single entry
                        let mut range_table_list: *mut pg_sys::List = std::ptr::null_mut();
                        range_table_list = pg_sys::lappend(
                            range_table_list,
                            range_table_entry as *mut std::ffi::c_void,
                        );

                        eprintln!(
                            "DEBUG: Created SeqScan plan: {:p} with range table, schema has {} columns",
                            seqscan_plan, base_schema.column_count()
                        );
                        pgrx::info!(
                            "DEBUG: Created SeqScan plan: {:p} with range table, schema has {} columns",
                            seqscan_plan, base_schema.column_count()
                        );

                        Ok((seqscan_plan, range_table_list, base_schema))
                    }
                    _ => {
                        eprintln!("DEBUG: Unsupported read type encountered");
                        pgrx::info!("DEBUG: Unsupported read type encountered");
                        Err("Unsupported read type".into())
                    }
                }
            } else {
                eprintln!("DEBUG: Read relation missing read type");
                pgrx::info!("DEBUG: Read relation missing read type");
                Err("Read relation missing read type".into())
            }
        }
        Some(RelType::Sort(sort)) => {
            // Handle sort relation - create a Sort node
            let (input_plan, input_range_table, input_schema) = if let Some(input) = &sort.input {
                convert_rel_to_plan_tree_with_context(input, function_map, current_table_oid)?
            } else {
                return Err("Sort relation missing input".into());
            };

            // Sort passes through input schema and range table unchanged
            Ok((
                create_sort_node(input_plan, &sort.sorts)?,
                input_range_table,
                input_schema,
            ))
        }
        Some(RelType::Fetch(fetch)) => {
            // Handle fetch relation - create a Limit node
            let (input_plan, input_range_table, input_schema) = if let Some(input) = &fetch.input {
                convert_rel_to_plan_tree_with_context(input, function_map, current_table_oid)?
            } else {
                return Err("Fetch relation missing input".into());
            };

            // Extract offset and count from the fetch relation using expression conversion
            let offset_expr = if let Some(offset_mode) = &fetch.offset_mode {
                use substrait::proto::fetch_rel::OffsetMode;
                match offset_mode {
                    OffsetMode::OffsetExpr(expr) => {
                        Some(convert_expression_to_postgres_with_context(
                            expr,
                            function_map,
                            current_table_oid,
                        )?)
                    }
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
                    CountMode::CountExpr(expr) => {
                        Some(convert_expression_to_postgres_with_context(
                            expr,
                            function_map,
                            current_table_oid,
                        )?)
                    }
                    CountMode::Count(constant_count) => {
                        // Support deprecated constant count by converting to expression
                        eprintln!("WARNING: Using deprecated constant count field. Consider migrating to count_expr.");
                        Some(unsafe { super::expressions::create_int8_const(*constant_count)? })
                    }
                }
            } else {
                None // No count limit
            };

            // Fetch/Limit passes through input schema and range table unchanged
            Ok((
                create_limit_node_with_expressions(input_plan, offset_expr, count_expr)?,
                input_range_table,
                input_schema,
            ))
        }
        Some(RelType::Filter(filter)) => {
            // Handle filter relation - create a Filter node
            eprintln!("DEBUG: Filter - about to process input");
            pgrx::info!("DEBUG: Filter - about to process input");

            let (input_plan, input_range_table, input_schema) = if let Some(input) = &filter.input {
                eprintln!(
                    "DEBUG: Filter - calling recursive convert_rel_to_plan_tree_with_context"
                );
                pgrx::info!(
                    "DEBUG: Filter - calling recursive convert_rel_to_plan_tree_with_context"
                );

                let res =
                    convert_rel_to_plan_tree_with_context(input, function_map, current_table_oid)?;

                eprintln!("DEBUG: Filter - recursive call returned!");
                pgrx::info!("DEBUG: Filter - recursive call returned!");

                res
            } else {
                return Err("Filter relation missing input".into());
            };

            eprintln!("DEBUG: Filter - about to convert condition");
            pgrx::info!("DEBUG: Filter - about to convert condition");

            // Convert the filter condition to a PostgreSQL expression using schema-based type resolution
            let condition_expr = if let Some(condition) = &filter.condition {
                eprintln!("DEBUG: Filter - calling convert_expression_to_postgres_with_schema");
                pgrx::info!("DEBUG: Filter - calling convert_expression_to_postgres_with_schema");

                convert_expression_to_postgres_with_schema(condition, function_map, &input_schema)?
            } else {
                return Err("Filter relation missing condition".into());
            };

            eprintln!("DEBUG: Filter - condition converted with schema-based types");
            pgrx::info!("DEBUG: Filter - condition converted with schema-based types");

            // Filter passes through input schema and range table unchanged
            Ok((
                create_filter_node(input_plan, condition_expr)?,
                input_range_table, // Pass through range table from input
                input_schema,
            ))
        }
        Some(RelType::Cross(cross)) => {
            // Handle cross relation - create a NestLoop node for Cartesian product
            let (left_plan, left_range_table, left_schema) = if let Some(left) = &cross.left {
                convert_rel_to_plan_tree_with_context(left, function_map, current_table_oid)?
            } else {
                return Err("Cross relation missing left input".into());
            };

            let (right_plan, right_range_table, right_schema) = if let Some(right) = &cross.right {
                convert_rel_to_plan_tree_with_context(right, function_map, current_table_oid)?
            } else {
                return Err("Cross relation missing right input".into());
            };

            // Cross join combines left and right schemas
            let mut combined_schema = left_schema;
            for column in right_schema.columns {
                combined_schema.add_column(column);
            }

            // Combine range tables from left and right
            let combined_range_table = pg_sys::list_concat(left_range_table, right_range_table);

            Ok((
                create_cross_join_node(left_plan, right_plan)?,
                combined_range_table,
                combined_schema,
            ))
        }
        Some(RelType::Aggregate(aggregate)) => {
            // Handle aggregate relation - create an Agg node for GROUP BY and aggregate functions
            let (input_plan, input_range_table, _input_schema) =
                if let Some(input) = &aggregate.input {
                    convert_rel_to_plan_tree_with_context(input, function_map, current_table_oid)?
                } else {
                    return Err("Aggregate relation missing input".into());
                };

            // TODO: Implement proper aggregate schema derivation
            // For now, create a placeholder schema
            // The schema should contain grouping columns + aggregate results
            let aggregate_schema = RelationSchema::new();

            Ok((
                create_aggregate_node(input_plan, aggregate, function_map)?,
                input_range_table, // Pass through range table from input
                aggregate_schema,
            ))
        }
        Some(RelType::Join(join)) => {
            // Handle join relation
            let (left_plan, left_range_table, left_schema) = if let Some(left) = &join.left {
                convert_rel_to_plan_tree_with_context(left, function_map, current_table_oid)?
            } else {
                return Err("Join relation missing left input".into());
            };

            let (right_plan, right_range_table, right_schema) = if let Some(right) = &join.right {
                convert_rel_to_plan_tree_with_context(right, function_map, current_table_oid)?
            } else {
                return Err("Join relation missing right input".into());
            };

            let join_type = match join.r#type {
                0 => pg_sys::JoinType::JOIN_INNER,
                1 => pg_sys::JoinType::JOIN_LEFT,
                2 => pg_sys::JoinType::JOIN_RIGHT,
                3 => pg_sys::JoinType::JOIN_FULL,
                _ => return Err("Unsupported join type".into()),
            };

            let join_qual = if let Some(expr) = &join.expression {
                let mut qual_list: *mut pg_sys::List = std::ptr::null_mut();
                let qual_expr = convert_expression_to_postgres_with_context(
                    expr,
                    function_map,
                    current_table_oid,
                )?;
                qual_list = pg_sys::lappend(qual_list, qual_expr as *mut std::ffi::c_void);
                qual_list
            } else {
                std::ptr::null_mut()
            };

            // Join combines left and right schemas
            let mut combined_schema = left_schema;
            for column in right_schema.columns {
                combined_schema.add_column(column);
            }

            // Combine range tables from left and right
            let combined_range_table = pg_sys::list_concat(left_range_table, right_range_table);

            Ok((
                create_join_node(left_plan, right_plan, join_type, join_qual)?,
                combined_range_table,
                combined_schema,
            ))
        }
        Some(rel_type) => {
            let type_name = get_relation_type_name(rel_type);
            Err(format!("Unsupported relation type: {type_name} (implementation needed)").into())
        }
        None => Err("Relation missing rel_type".into()),
    };

    pgrx::info!("DEBUG: About to return from convert_rel_to_plan_tree_with_context");

    // Validate result before returning
    if let Ok((plan, range_table, ref schema)) = &result {
        eprintln!(
            "DEBUG: Result is Ok - plan={:p}, range_table={:p}, schema_columns={}",
            *plan,
            *range_table,
            schema.column_count()
        );
        pgrx::info!(
            "DEBUG: Result is Ok - plan={:p}, range_table={:p}, schema_columns={}",
            *plan,
            *range_table,
            schema.column_count()
        );

        // Validate plan pointer
        if !plan.is_null() {
            let plan_type = (**plan).type_;
            eprintln!("DEBUG: Plan node type: {:?}", plan_type);
            pgrx::info!("DEBUG: Plan node type: {:?}", plan_type);
        }
    } else if let Err(ref e) = result {
        eprintln!("DEBUG: Result is Err: {}", e);
        pgrx::info!("DEBUG: Result is Err: {}", e);
    }

    eprintln!("DEBUG: About to return result from function");
    pgrx::info!("DEBUG: About to return result from function");

    result
}
