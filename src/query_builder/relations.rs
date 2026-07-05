//! Converts Substrait relations to PostgreSQL Query structure.

use pgrx::pg_sys;
use std::collections::HashMap;
use substrait::proto::rel::RelType;
use substrait::proto::{Plan, Rel};

use super::expressions::{convert_aggregate_measure, convert_expression_for_query};
use super::{AvailableColumn, ColumnRef, QueryBuildContext, QueryParts};

/// Build a function extension map from Substrait plan extensions.
/// Maps function reference IDs to function names.
pub fn build_function_extension_map(plan: &Plan) -> HashMap<u32, String> {
    let mut function_map = HashMap::new();

    for extension in &plan.extensions {
        if let Some(mapping_type) = &extension.mapping_type {
            if let substrait::proto::extensions::simple_extension_declaration::MappingType::ExtensionFunction(func) = mapping_type {
                function_map.insert(func.function_anchor, func.name.clone());
            }
        }
    }

    function_map
}

/// Build a PostgreSQL Query from a Substrait Plan.
pub unsafe fn build_query_from_substrait(
    plan: &Plan,
) -> Result<*mut pg_sys::Query, Box<dyn std::error::Error + Send + Sync>> {
    pgrx::info!("DEBUG: build_query_from_substrait - starting");

    // Build function map from extensions
    pgrx::info!("DEBUG: Building function map from extensions");
    let function_map = build_function_extension_map(plan);
    pgrx::info!(
        "DEBUG: Function map built with {} functions",
        function_map.len()
    );

    // Create context
    let mut ctx = QueryBuildContext::new(function_map);
    pgrx::info!("DEBUG: QueryBuildContext created");

    // Get the root relation from the plan
    pgrx::info!("DEBUG: Getting root relation");
    let root_rel = get_root_relation(plan)?;
    pgrx::info!("DEBUG: Got root relation");

    // Convert the relation tree to query parts
    pgrx::info!("DEBUG: Converting relation tree to query parts");
    let parts = convert_rel_to_query_parts(root_rel, &mut ctx)?;
    pgrx::info!("DEBUG: Relation tree converted successfully");

    // Build the Query object
    pgrx::info!("DEBUG: Building Query object from parts");
    let query = build_query_from_parts(&parts, &mut ctx)?;
    pgrx::info!("DEBUG: Query object built successfully");

    Ok(query)
}

/// Build a sub-Query for a SubLink from a Substrait relation.
///
/// The subquery gets its own build context (and thus its own range table),
/// since each Query level in PostgreSQL has an independent rtable. The
/// enclosing query levels' columns are pushed onto the outer scope stack so
/// OuterReference field references resolve to Vars with varlevelsup > 0.
pub(super) unsafe fn build_subquery(
    rel: &Rel,
    outer_columns: &[AvailableColumn],
    outer_ctx: &QueryBuildContext,
) -> Result<*mut pg_sys::Query, Box<dyn std::error::Error + Send + Sync>> {
    let mut sub_ctx = QueryBuildContext::new(outer_ctx.function_map.clone());
    sub_ctx.outer_scopes.push(outer_columns.to_vec());
    sub_ctx
        .outer_scopes
        .extend(outer_ctx.outer_scopes.iter().cloned());

    let parts = convert_rel_to_query_parts(rel, &mut sub_ctx)?;
    build_query_from_parts(&parts, &mut sub_ctx)
}

/// Extract the root relation from a Substrait plan.
fn get_root_relation(plan: &Plan) -> Result<&Rel, Box<dyn std::error::Error + Send + Sync>> {
    let plan_rel = plan.relations.first().ok_or("Plan has no relations")?;

    use substrait::proto::plan_rel::RelType as PlanRelType;
    match &plan_rel.rel_type {
        Some(PlanRelType::Root(root)) => root
            .input
            .as_ref()
            .ok_or_else(|| "Root relation has no input".into()),
        Some(PlanRelType::Rel(rel)) => Ok(rel),
        None => Err("Plan relation has no rel_type".into()),
    }
}

/// Convert a Substrait Rel to QueryParts.
unsafe fn convert_rel_to_query_parts(
    rel: &Rel,
    ctx: &mut QueryBuildContext,
) -> Result<QueryParts, Box<dyn std::error::Error + Send + Sync>> {
    // Get the relation type name for logging
    let rel_type_name = match &rel.rel_type {
        Some(RelType::Read(_)) => "Read",
        Some(RelType::Filter(_)) => "Filter",
        Some(RelType::Project(_)) => "Project",
        Some(RelType::Join(_)) => "Join",
        Some(RelType::Cross(_)) => "Cross",
        Some(RelType::Aggregate(_)) => "Aggregate",
        Some(RelType::Sort(_)) => "Sort",
        Some(RelType::Fetch(_)) => "Fetch",
        _ => "Unknown",
    };
    pgrx::info!(
        "DEBUG: >>> ENTERING convert_rel_to_query_parts - {}",
        rel_type_name
    );

    let result = match &rel.rel_type {
        Some(RelType::Read(read)) => convert_read_to_query_parts(read, ctx),
        Some(RelType::Filter(filter)) => convert_filter_to_query_parts(filter, ctx),
        Some(RelType::Project(project)) => convert_project_to_query_parts(project, ctx),
        Some(RelType::Join(join)) => convert_join_to_query_parts(join, ctx),
        Some(RelType::Cross(cross)) => convert_cross_to_query_parts(cross, ctx),
        Some(RelType::Aggregate(agg)) => convert_aggregate_to_query_parts(agg, ctx),
        Some(RelType::Sort(sort)) => convert_sort_to_query_parts(sort, ctx),
        Some(RelType::Fetch(fetch)) => convert_fetch_to_query_parts(fetch, ctx),
        other => Err(format!("Unsupported relation type: {:?}", other).into()),
    };

    if let Ok(ref parts) = result {
        pgrx::info!(
            "DEBUG: <<< LEAVING {} - available_columns={}, has_aggs={}",
            rel_type_name,
            parts.available_columns.len(),
            parts.has_aggs
        );
    }

    result
}

/// Convert a Read relation (table scan) to QueryParts.
unsafe fn convert_read_to_query_parts(
    read: &substrait::proto::ReadRel,
    ctx: &mut QueryBuildContext,
) -> Result<QueryParts, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::read_rel::ReadType;
    pgrx::info!("DEBUG: convert_read_to_query_parts - starting");

    let table_name = match &read.read_type {
        Some(ReadType::NamedTable(named)) => {
            let name = named.names.last().ok_or("NamedTable has no names")?.clone();
            pgrx::info!("DEBUG: Table name from NamedTable: {}", name);
            name
        }
        Some(ReadType::VirtualTable(_)) => {
            return Err("VirtualTable not yet supported in Query builder".into());
        }
        _ => return Err("Unsupported read type".into()),
    };

    // Look up the table in PostgreSQL catalog
    pgrx::info!("DEBUG: Looking up table OID for: {}", table_name);
    let table_name_cstr = std::ffi::CString::new(table_name.clone())?;
    let table_oid = pg_sys::RelnameGetRelid(table_name_cstr.as_ptr());
    pgrx::info!("DEBUG: Table OID: {}", table_oid.to_u32());
    if table_oid == pg_sys::InvalidOid {
        return Err(format!("relation \"{}\" does not exist", table_name).into());
    }

    // Create RangeTblEntry for this table
    pgrx::info!("DEBUG: Creating RangeTblEntry");
    let rte = create_range_table_entry(table_oid, &table_name)?;
    pgrx::info!("DEBUG: RangeTblEntry created, adding to context");
    let rtindex = ctx.add_table(rte, &table_name, table_oid);
    pgrx::info!("DEBUG: Table added with rtindex: {}", rtindex);

    // Get column information from the table
    pgrx::info!("DEBUG: Getting table columns");
    let columns = get_table_columns(table_oid, rtindex)?;
    pgrx::info!("DEBUG: Got {} columns", columns.len());

    pgrx::info!("DEBUG: Building available_columns Vec");
    let available_columns: Vec<AvailableColumn> = columns
        .iter()
        .map(|c| AvailableColumn {
            varno: rtindex,
            varattno: c.attnum,
            name: c.name.clone(),
            type_oid: c.type_oid,
            typmod: c.typmod,
            collation: c.collation,
            computed_expr: None, // Table columns are not computed
            ressortgroupref: 0,
        })
        .collect();
    pgrx::info!("DEBUG: Built {} available_columns", available_columns.len());

    pgrx::info!("DEBUG: Setting columns in context");
    ctx.set_columns(rtindex, columns);
    pgrx::info!("DEBUG: Columns set in context");

    // Create RangeTblRef pointing to this entry
    pgrx::info!("DEBUG: Creating RangeTblRef");
    let mut rtref = pgrx::PgBox::<pg_sys::RangeTblRef>::alloc0();
    rtref.type_ = pg_sys::NodeTag::T_RangeTblRef;
    rtref.rtindex = rtindex;
    let rtref_ptr = rtref.into_pg() as *mut pg_sys::Node;
    pgrx::info!("DEBUG: RangeTblRef created");

    pgrx::info!("DEBUG: Returning QueryParts from convert_read_to_query_parts");
    Ok(QueryParts {
        from_item: rtref_ptr,
        available_columns,
        where_quals: None,
        having_qual: None,
        target_list: None,
        group_clause: None,
        aggregates: Vec::new(),
        sort_clause: None,
        limit_count: None,
        limit_offset: None,
        has_aggs: false,
    })
}

/// Create a RangeTblEntry for a table.
unsafe fn create_range_table_entry(
    table_oid: pg_sys::Oid,
    table_name: &str,
) -> Result<*mut pg_sys::RangeTblEntry, Box<dyn std::error::Error + Send + Sync>> {
    let rte = pgrx::PgBox::<pg_sys::RangeTblEntry>::alloc0();
    let rte = rte.into_pg();

    (*rte).type_ = pg_sys::NodeTag::T_RangeTblEntry;
    (*rte).rtekind = pg_sys::RTEKind::RTE_RELATION;
    (*rte).relid = table_oid;
    (*rte).rellockmode = pg_sys::AccessShareLock as i32;
    (*rte).lateral = false;
    (*rte).inh = true; // Include inheritance
    (*rte).inFromCl = true; // In FROM clause

    // Get actual relkind and column names from the relation
    let relation = pg_sys::relation_open(table_oid, pg_sys::AccessShareLock as i32);
    if !relation.is_null() {
        (*rte).relkind = (*relation)
            .rd_rel
            .as_ref()
            .map_or(pg_sys::RELKIND_RELATION as i8, |rel| rel.relkind as i8);

        // Build column names list for eref
        let tupdesc = (*relation).rd_att;
        let natts = (*tupdesc).natts;
        let mut colnames: *mut pg_sys::List = std::ptr::null_mut();
        for i in 0..natts {
            let attr = (*tupdesc).attrs.as_ptr().add(i as usize);
            if !(*attr).attisdropped {
                let name_ptr = (*attr).attname.data.as_ptr();
                let name_cstr = std::ffi::CStr::from_ptr(name_ptr);
                let name_val =
                    pg_sys::makeString(create_cstring(name_cstr.to_string_lossy().as_ref()));
                colnames = pg_sys::lappend(colnames, name_val as *mut std::ffi::c_void);
            }
        }

        pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);

        // Create alias with column names
        let alias = pgrx::PgBox::<pg_sys::Alias>::alloc0();
        let alias = alias.into_pg();
        (*alias).type_ = pg_sys::NodeTag::T_Alias;
        (*alias).aliasname = create_cstring(table_name);
        (*alias).colnames = colnames;
        (*rte).eref = alias;
    } else {
        // Fallback without column names
        (*rte).relkind = pg_sys::RELKIND_RELATION as i8;
        let alias = pgrx::PgBox::<pg_sys::Alias>::alloc0();
        let alias = alias.into_pg();
        (*alias).type_ = pg_sys::NodeTag::T_Alias;
        (*alias).aliasname = create_cstring(table_name);
        (*rte).eref = alias;
    }

    (*rte).alias = std::ptr::null_mut();

    Ok(rte)
}

/// Get column information from a table.
unsafe fn get_table_columns(
    table_oid: pg_sys::Oid,
    _rtindex: i32,
) -> Result<Vec<ColumnRef>, Box<dyn std::error::Error + Send + Sync>> {
    let relation = pg_sys::relation_open(table_oid, pg_sys::AccessShareLock as i32);
    if relation.is_null() {
        return Err(format!("Failed to open relation OID {}", table_oid.to_u32()).into());
    }

    let tupdesc = (*relation).rd_att;
    let natts = (*tupdesc).natts;

    let mut columns = Vec::new();
    for i in 0..natts {
        let attr = (*tupdesc).attrs.as_ptr().add(i as usize);
        if (*attr).attisdropped {
            continue;
        }

        let name_ptr = (*attr).attname.data.as_ptr();
        let name = std::ffi::CStr::from_ptr(name_ptr)
            .to_string_lossy()
            .to_string();

        columns.push(ColumnRef {
            name,
            type_oid: (*attr).atttypid,
            attnum: (*attr).attnum,
            typmod: (*attr).atttypmod,
            collation: (*attr).attcollation,
        });
    }

    pg_sys::relation_close(relation, pg_sys::AccessShareLock as i32);

    Ok(columns)
}

/// Convert a Filter relation to QueryParts.
unsafe fn convert_filter_to_query_parts(
    filter: &substrait::proto::FilterRel,
    ctx: &mut QueryBuildContext,
) -> Result<QueryParts, Box<dyn std::error::Error + Send + Sync>> {
    pgrx::info!("DEBUG: convert_filter_to_query_parts - starting");

    // First, convert the child relation
    let input = filter.input.as_ref().ok_or("Filter has no input")?;
    pgrx::info!("DEBUG: Filter - converting child relation");
    let mut parts = convert_rel_to_query_parts(input, ctx)?;
    pgrx::info!(
        "DEBUG: Filter - child relation converted, {} available_columns",
        parts.available_columns.len()
    );

    // Convert the filter condition
    if let Some(condition) = &filter.condition {
        pgrx::info!("DEBUG: Filter - converting filter condition expression");
        let qual_expr = convert_expression_for_query(condition, &parts.available_columns, ctx)?;
        pgrx::info!("DEBUG: Filter - filter condition converted");

        // A Filter above an Aggregate operates on aggregated rows: that is a
        // HAVING clause. Putting it in the jointree quals would evaluate any
        // Aggrefs in a scan node ("Aggref found in non-Agg plan node").
        if parts.has_aggs {
            pgrx::info!("DEBUG: Filter - input has aggregates, routing to HAVING");
            if let Some(existing) = parts.having_qual {
                let and_expr = create_and_expr(existing, qual_expr)?;
                parts.having_qual = Some(and_expr);
            } else {
                parts.having_qual = Some(qual_expr);
            }
        } else if let Some(existing) = parts.where_quals {
            // Combine with any existing quals (AND them together)
            pgrx::info!("DEBUG: Filter - combining with existing quals");
            let and_expr = create_and_expr(existing, qual_expr)?;
            parts.where_quals = Some(and_expr);
        } else {
            pgrx::info!("DEBUG: Filter - setting as first qual");
            parts.where_quals = Some(qual_expr);
        }
    }

    pgrx::info!("DEBUG: Filter - returning QueryParts");
    Ok(parts)
}

/// Convert a Project relation to QueryParts.
unsafe fn convert_project_to_query_parts(
    project: &substrait::proto::ProjectRel,
    ctx: &mut QueryBuildContext,
) -> Result<QueryParts, Box<dyn std::error::Error + Send + Sync>> {
    pgrx::info!(
        "DEBUG: convert_project_to_query_parts - {} expressions",
        project.expressions.len()
    );

    // Handle case where Project has no input (SELECT literal)
    let mut parts = if let Some(input) = project.input.as_ref() {
        convert_rel_to_query_parts(input, ctx)?
    } else {
        // No input - this is a "SELECT literal" type query
        // PostgreSQL allows empty FROM clause for this case
        QueryParts::empty()
    };

    pgrx::info!(
        "DEBUG: Project child has {} available_columns, has_aggs={}",
        parts.available_columns.len(),
        parts.has_aggs
    );

    // If parent has aggregates and would create Var nodes with varno=0,
    // we need to handle this specially
    let has_computed_columns = parts.available_columns.iter().any(|c| c.varno == 0);
    if has_computed_columns {
        pgrx::info!("DEBUG: Project has computed columns (varno=0) from child - checking if we can reuse target list");

        // Check if project expressions are simple field references that match the child's output
        // In that case, we can just use the child's target list
        let is_simple_passthrough = project.expressions.iter().enumerate().all(|(i, expr)| {
            if let Some(substrait::proto::expression::RexType::Selection(sel)) = &expr.rex_type {
                if let Some(
                    substrait::proto::expression::field_reference::ReferenceType::DirectReference(
                        direct,
                    ),
                ) = &sel.reference_type
                {
                    if let Some(
                        substrait::proto::expression::reference_segment::ReferenceType::StructField(
                            field,
                        ),
                    ) = &direct.reference_type
                    {
                        // Simple passthrough if field index matches position
                        return field.field as usize == i;
                    }
                }
            }
            false
        });

        if is_simple_passthrough && project.expressions.len() == parts.available_columns.len() {
            pgrx::info!(
                "DEBUG: Project is simple passthrough - using child's target list directly"
            );
            // Just return the child's parts unchanged
            return Ok(parts);
        }
    }

    // Build target list from project expressions
    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();
    let mut new_available_columns = Vec::new();

    for (i, expr) in project.expressions.iter().enumerate() {
        let pg_expr = convert_expression_for_query(expr, &parts.available_columns, ctx)?;

        // For field references, preserve ressortgroupref from the source
        // column so a groupClause carried up from an Aggregate below still
        // finds its grouping columns in this new target list.
        let ressortgroupref =
            if let Some(substrait::proto::expression::RexType::Selection(sel)) = &expr.rex_type {
                if let Some(
                    substrait::proto::expression::field_reference::ReferenceType::DirectReference(
                        direct,
                    ),
                ) = &sel.reference_type
                {
                    if let Some(
                        substrait::proto::expression::reference_segment::ReferenceType::StructField(
                            field,
                        ),
                    ) = &direct.reference_type
                    {
                        let field_idx = field.field as usize;
                        if field_idx < parts.available_columns.len() {
                            parts.available_columns[field_idx].ressortgroupref
                        } else {
                            0
                        }
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                0
            };

        // Create TargetEntry
        let mut te = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
        te.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
        te.expr = pg_expr;
        te.resno = (i + 1) as i16;
        te.resname = create_cstring(&format!("col{}", i + 1));
        te.ressortgroupref = ressortgroupref;
        te.resjunk = false;
        let te = te.into_pg();

        target_list = pg_sys::lappend(target_list, te as *mut std::ffi::c_void);

        // Track available columns for parent relations
        // If the expression is a simple field reference, preserve the varno from input
        // For computed expressions (varno=0), store the expression so it can be inlined
        let (varno, varattno, col_name, computed_expr) =
            if let Some(substrait::proto::expression::RexType::Selection(sel)) = &expr.rex_type {
                if let Some(
                    substrait::proto::expression::field_reference::ReferenceType::DirectReference(
                        direct,
                    ),
                ) = &sel.reference_type
                {
                    if let Some(
                        substrait::proto::expression::reference_segment::ReferenceType::StructField(
                            field,
                        ),
                    ) = &direct.reference_type
                    {
                        let field_idx = field.field as usize;
                        if field_idx < parts.available_columns.len() {
                            let src_col = &parts.available_columns[field_idx];
                            // Preserve varno, varattno, and computed_expr from source column
                            (
                                src_col.varno,
                                src_col.varattno,
                                src_col.name.clone(),
                                src_col.computed_expr,
                            )
                        } else {
                            // Field index out of range - copy expression
                            let expr_copy =
                                pg_sys::copyObjectImpl(pg_expr as *const std::ffi::c_void)
                                    as *mut pg_sys::Expr;
                            (0, (i + 1) as i16, format!("col{}", i + 1), Some(expr_copy))
                        }
                    } else {
                        // Copy expression for storage to avoid sharing pointers
                        let expr_copy = pg_sys::copyObjectImpl(pg_expr as *const std::ffi::c_void)
                            as *mut pg_sys::Expr;
                        (0, (i + 1) as i16, format!("col{}", i + 1), Some(expr_copy))
                    }
                } else {
                    let expr_copy = pg_sys::copyObjectImpl(pg_expr as *const std::ffi::c_void)
                        as *mut pg_sys::Expr;
                    (0, (i + 1) as i16, format!("col{}", i + 1), Some(expr_copy))
                }
            } else {
                // Non-field-reference expression - use varno=0 (computed)
                // Copy expression for storage to avoid sharing pointers
                let expr_copy =
                    pg_sys::copyObjectImpl(pg_expr as *const std::ffi::c_void) as *mut pg_sys::Expr;
                (0, (i + 1) as i16, format!("col{}", i + 1), Some(expr_copy))
            };

        let expr_type = pg_sys::exprType(pg_expr as *const pg_sys::Node);
        // Get collation from the expression, or use default for collatable types
        let mut expr_coll = pg_sys::exprCollation(pg_expr as *const pg_sys::Node);
        if expr_coll == pg_sys::InvalidOid && pg_sys::type_is_collatable(expr_type) {
            expr_coll = pg_sys::DEFAULT_COLLATION_OID;
        }

        new_available_columns.push(AvailableColumn {
            varno,
            varattno,
            name: col_name,
            type_oid: expr_type,
            typmod: -1,
            collation: expr_coll,
            computed_expr,
            ressortgroupref,
        });
    }

    // Grouping/sorting columns the projection dropped must stay in the
    // target list as junk entries: the group and sort clauses reference
    // them by ressortgroupref.
    let mut needed_refs: Vec<u32> = Vec::new();
    for clause in [parts.group_clause, parts.sort_clause]
        .into_iter()
        .flatten()
    {
        for k in 0..pg_sys::list_length(clause) {
            let sgc = pg_sys::list_nth(clause, k) as *mut pg_sys::SortGroupClause;
            needed_refs.push((*sgc).tleSortGroupRef);
        }
    }
    if let Some(child_tlist) = parts.target_list {
        for needed in needed_refs {
            let mut present = false;
            for k in 0..pg_sys::list_length(target_list) {
                let te = pg_sys::list_nth(target_list, k) as *mut pg_sys::TargetEntry;
                if (*te).ressortgroupref == needed {
                    present = true;
                    break;
                }
            }
            if present {
                continue;
            }
            for k in 0..pg_sys::list_length(child_tlist) {
                let te = pg_sys::list_nth(child_tlist, k) as *mut pg_sys::TargetEntry;
                if (*te).ressortgroupref == needed {
                    let copy = pg_sys::copyObjectImpl(te as *const std::ffi::c_void)
                        as *mut pg_sys::TargetEntry;
                    (*copy).resno = (pg_sys::list_length(target_list) + 1) as i16;
                    (*copy).resjunk = true;
                    target_list = pg_sys::lappend(target_list, copy as *mut std::ffi::c_void);
                    break;
                }
            }
        }
    }

    parts.target_list = Some(target_list);
    parts.available_columns = new_available_columns;

    Ok(parts)
}

/// Convert a Join relation to QueryParts.
unsafe fn convert_join_to_query_parts(
    join: &substrait::proto::JoinRel,
    ctx: &mut QueryBuildContext,
) -> Result<QueryParts, Box<dyn std::error::Error + Send + Sync>> {
    // Convert left and right children
    let left_input = join.left.as_ref().ok_or("Join has no left input")?;
    let right_input = join.right.as_ref().ok_or("Join has no right input")?;

    let left_parts = convert_rel_to_query_parts(left_input, ctx)?;
    let right_parts = convert_rel_to_query_parts(right_input, ctx)?;

    // Combine available columns from both sides
    let mut combined_columns = left_parts.available_columns.clone();
    combined_columns.extend(right_parts.available_columns.clone());

    // Map Substrait join type to PostgreSQL
    let join_type = match join.r#type() {
        substrait::proto::join_rel::JoinType::Inner => pg_sys::JoinType::JOIN_INNER,
        substrait::proto::join_rel::JoinType::Left => pg_sys::JoinType::JOIN_LEFT,
        substrait::proto::join_rel::JoinType::Right => pg_sys::JoinType::JOIN_RIGHT,
        substrait::proto::join_rel::JoinType::Outer => pg_sys::JoinType::JOIN_FULL,
        substrait::proto::join_rel::JoinType::LeftSemi => pg_sys::JoinType::JOIN_SEMI,
        substrait::proto::join_rel::JoinType::LeftAnti => pg_sys::JoinType::JOIN_ANTI,
        _ => pg_sys::JoinType::JOIN_INNER,
    };

    // Convert join condition
    let join_quals = if let Some(expr) = &join.expression {
        convert_expression_for_query(expr, &combined_columns, ctx)?
    } else {
        std::ptr::null_mut()
    };

    // Create JoinExpr
    let mut join_expr = pgrx::PgBox::<pg_sys::JoinExpr>::alloc0();
    join_expr.type_ = pg_sys::NodeTag::T_JoinExpr;
    join_expr.jointype = join_type;
    join_expr.isNatural = false;
    join_expr.larg = left_parts.from_item;
    join_expr.rarg = right_parts.from_item;
    join_expr.quals = join_quals as *mut pg_sys::Node;
    // rtindex will be set by the planner
    join_expr.rtindex = 0;
    let join_expr = join_expr.into_pg() as *mut pg_sys::Node;

    // Combine WHERE quals from both sides
    let where_quals = combine_quals(left_parts.where_quals, right_parts.where_quals)?;

    Ok(QueryParts {
        from_item: join_expr,
        available_columns: combined_columns,
        where_quals,
        having_qual: combine_quals(left_parts.having_qual, right_parts.having_qual)?,
        target_list: None,
        group_clause: None,
        aggregates: Vec::new(),
        sort_clause: None,
        limit_count: None,
        limit_offset: None,
        has_aggs: left_parts.has_aggs || right_parts.has_aggs,
    })
}

/// Convert a Cross join relation to QueryParts.
/// This becomes an implicit cross join in the FROM clause.
unsafe fn convert_cross_to_query_parts(
    cross: &substrait::proto::CrossRel,
    ctx: &mut QueryBuildContext,
) -> Result<QueryParts, Box<dyn std::error::Error + Send + Sync>> {
    // Convert left and right children
    let left_input = cross.left.as_ref().ok_or("Cross has no left input")?;
    let right_input = cross.right.as_ref().ok_or("Cross has no right input")?;

    let left_parts = convert_rel_to_query_parts(left_input, ctx)?;
    let right_parts = convert_rel_to_query_parts(right_input, ctx)?;

    // Combine available columns from both sides
    let mut combined_columns = left_parts.available_columns.clone();
    combined_columns.extend(right_parts.available_columns.clone());

    // Create JoinExpr for CROSS JOIN (no quals)
    let mut join_expr = pgrx::PgBox::<pg_sys::JoinExpr>::alloc0();
    join_expr.type_ = pg_sys::NodeTag::T_JoinExpr;
    join_expr.jointype = pg_sys::JoinType::JOIN_INNER;
    join_expr.isNatural = false;
    join_expr.larg = left_parts.from_item;
    join_expr.rarg = right_parts.from_item;
    join_expr.quals = std::ptr::null_mut(); // No join condition for CROSS
    join_expr.rtindex = 0;
    let join_expr = join_expr.into_pg() as *mut pg_sys::Node;

    // Combine WHERE quals from both sides
    let where_quals = combine_quals(left_parts.where_quals, right_parts.where_quals)?;

    Ok(QueryParts {
        from_item: join_expr,
        available_columns: combined_columns,
        where_quals,
        having_qual: combine_quals(left_parts.having_qual, right_parts.having_qual)?,
        target_list: None,
        group_clause: None,
        aggregates: Vec::new(),
        sort_clause: None,
        limit_count: None,
        limit_offset: None,
        has_aggs: left_parts.has_aggs || right_parts.has_aggs,
    })
}

/// Check whether a Substrait relation subtree contains an Aggregate.
fn rel_contains_aggregate(rel: &Rel) -> bool {
    match &rel.rel_type {
        Some(RelType::Aggregate(_)) => true,
        Some(RelType::Filter(f)) => f.input.as_deref().is_some_and(rel_contains_aggregate),
        Some(RelType::Project(p)) => p.input.as_deref().is_some_and(rel_contains_aggregate),
        Some(RelType::Sort(s)) => s.input.as_deref().is_some_and(rel_contains_aggregate),
        Some(RelType::Fetch(f)) => f.input.as_deref().is_some_and(rel_contains_aggregate),
        Some(RelType::Join(j)) => {
            j.left.as_deref().is_some_and(rel_contains_aggregate)
                || j.right.as_deref().is_some_and(rel_contains_aggregate)
        }
        Some(RelType::Cross(c)) => {
            c.left.as_deref().is_some_and(rel_contains_aggregate)
                || c.right.as_deref().is_some_and(rel_contains_aggregate)
        }
        _ => false,
    }
}

/// Convert a relation subtree into an RTE_SUBQUERY (derived table).
///
/// Needed when a subtree cannot be flattened into the enclosing Query level,
/// e.g. an Aggregate whose input is itself aggregated (TPC-H Q13). The
/// subtree becomes its own Query with its own range table; the enclosing
/// query sees its output columns through a subquery RTE.
unsafe fn convert_rel_as_subquery_rte(
    rel: &Rel,
    ctx: &mut QueryBuildContext,
) -> Result<QueryParts, Box<dyn std::error::Error + Send + Sync>> {
    let mut sub_ctx = QueryBuildContext::new(ctx.function_map.clone());
    sub_ctx.outer_scopes = ctx.outer_scopes.clone();
    let sub_parts = convert_rel_to_query_parts(rel, &mut sub_ctx)?;
    let subquery = build_query_from_parts(&sub_parts, &mut sub_ctx)?;

    // Collect output column names and build the eref column list.
    let tlist = (*subquery).targetList;
    let mut colnames: *mut pg_sys::List = std::ptr::null_mut();
    let n_cols = pg_sys::list_length(tlist);
    for k in 0..n_cols {
        let te = pg_sys::list_nth(tlist, k) as *mut pg_sys::TargetEntry;
        let name = if (*te).resname.is_null() {
            format!("col{}", k + 1)
        } else {
            std::ffi::CStr::from_ptr((*te).resname)
                .to_string_lossy()
                .to_string()
        };
        let name_val = pg_sys::makeString(create_cstring(&name));
        colnames = pg_sys::lappend(colnames, name_val as *mut std::ffi::c_void);
    }

    // Build the subquery RTE.
    let alias_name = ctx.next_alias();
    let rte = pgrx::PgBox::<pg_sys::RangeTblEntry>::alloc0();
    let rte = rte.into_pg();
    (*rte).type_ = pg_sys::NodeTag::T_RangeTblEntry;
    (*rte).rtekind = pg_sys::RTEKind::RTE_SUBQUERY;
    (*rte).subquery = subquery;
    (*rte).lateral = false;
    (*rte).inFromCl = true;
    let eref = pgrx::PgBox::<pg_sys::Alias>::alloc0();
    let eref = eref.into_pg();
    (*eref).type_ = pg_sys::NodeTag::T_Alias;
    (*eref).aliasname = create_cstring(&alias_name);
    (*eref).colnames = colnames;
    (*rte).eref = eref;
    (*rte).alias = std::ptr::null_mut();

    let rtindex = ctx.add_non_table_rte(rte, &alias_name);

    // Expose the subquery's output columns to the enclosing query.
    let mut available_columns = Vec::new();
    for k in 0..n_cols {
        let te = pg_sys::list_nth(tlist, k) as *mut pg_sys::TargetEntry;
        let te_expr = (*te).expr as *const pg_sys::Node;
        let name = if (*te).resname.is_null() {
            format!("col{}", k + 1)
        } else {
            std::ffi::CStr::from_ptr((*te).resname)
                .to_string_lossy()
                .to_string()
        };
        available_columns.push(AvailableColumn {
            varno: rtindex,
            varattno: (k + 1) as i16,
            name,
            type_oid: pg_sys::exprType(te_expr),
            typmod: pg_sys::exprTypmod(te_expr),
            collation: pg_sys::exprCollation(te_expr),
            computed_expr: None,
            ressortgroupref: 0,
        });
    }

    let mut rtref = pgrx::PgBox::<pg_sys::RangeTblRef>::alloc0();
    rtref.type_ = pg_sys::NodeTag::T_RangeTblRef;
    rtref.rtindex = rtindex;
    let rtref_ptr = rtref.into_pg() as *mut pg_sys::Node;

    Ok(QueryParts {
        from_item: rtref_ptr,
        available_columns,
        where_quals: None,
        having_qual: None,
        target_list: None,
        group_clause: None,
        aggregates: Vec::new(),
        sort_clause: None,
        limit_count: None,
        limit_offset: None,
        has_aggs: false,
    })
}

/// Convert an Aggregate relation to QueryParts.
unsafe fn convert_aggregate_to_query_parts(
    agg: &substrait::proto::AggregateRel,
    ctx: &mut QueryBuildContext,
) -> Result<QueryParts, Box<dyn std::error::Error + Send + Sync>> {
    let input = agg.input.as_ref().ok_or("Aggregate has no input")?;
    // An already-aggregated input cannot share this Query level (its Aggrefs
    // would leak into scan nodes); make it a derived table instead.
    let parts = if rel_contains_aggregate(input) {
        convert_rel_as_subquery_rte(input, ctx)?
    } else {
        convert_rel_to_query_parts(input, ctx)?
    };

    // Build target list with grouping columns and aggregate functions
    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();
    let mut new_available_columns: Vec<AvailableColumn> = Vec::new();
    let mut resno = 1;

    // Add grouping columns first
    // Extract grouping column indices from Substrait groupings
    let mut group_col_indices: Vec<i32> = Vec::new();
    let mut group_clause: *mut pg_sys::List = std::ptr::null_mut();
    let mut sort_group_ref = 1u32;

    if let Some(grouping) = agg.groupings.first() {
        #[allow(deprecated)]
        for group_expr in &grouping.grouping_expressions {
            if let Some(substrait::proto::expression::RexType::Selection(sel)) =
                &group_expr.rex_type
            {
                if let Some(
                    substrait::proto::expression::field_reference::ReferenceType::DirectReference(
                        direct,
                    ),
                ) = &sel.reference_type
                {
                    if let Some(
                        substrait::proto::expression::reference_segment::ReferenceType::StructField(
                            field,
                        ),
                    ) = &direct.reference_type
                    {
                        let field_index = field.field as usize;
                        group_col_indices.push(field_index as i32);

                        // Get column info from available columns
                        if field_index < parts.available_columns.len() {
                            let col = &parts.available_columns[field_index];

                            // For computed columns (varno=0), use the stored expression
                            // For table columns, create a Var node
                            let var_expr = if col.varno == 0 {
                                if let Some(computed) = col.computed_expr {
                                    // Copy the expression to avoid sharing pointers
                                    pg_sys::copyObjectImpl(computed as *const std::ffi::c_void)
                                        as *mut pg_sys::Expr
                                } else {
                                    return Err(format!(
                                        "Grouping column '{}' has varno=0 but no computed expression",
                                        col.name
                                    )
                                    .into());
                                }
                            } else {
                                // Create Var for this grouping column
                                let mut var = pgrx::PgBox::<pg_sys::Var>::alloc0();
                                var.xpr.type_ = pg_sys::NodeTag::T_Var;
                                var.varno = col.varno;
                                var.varattno = col.varattno;
                                var.vartype = col.type_oid;
                                var.vartypmod = col.typmod;
                                var.varcollid = col.collation;
                                var.varlevelsup = 0;
                                var.varnosyn = col.varno as u32;
                                var.varattnosyn = col.varattno;
                                var.location = -1;
                                var.into_pg() as *mut pg_sys::Expr
                            };

                            // Make a copy for AvailableColumn so we don't share pointers
                            let var_expr_copy =
                                pg_sys::copyObjectImpl(var_expr as *const std::ffi::c_void)
                                    as *mut pg_sys::Expr;

                            // Create TargetEntry
                            let mut te = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
                            te.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
                            te.expr = var_expr;
                            te.resno = resno as pg_sys::AttrNumber;
                            let name_cstr = std::ffi::CString::new(col.name.as_str()).unwrap();
                            te.resname = pgrx::pg_sys::pstrdup(name_cstr.as_ptr());
                            te.ressortgroupref = sort_group_ref;
                            te.resorigtbl = pg_sys::InvalidOid;
                            te.resorigcol = 0;
                            te.resjunk = false;

                            target_list =
                                pg_sys::lappend(target_list, te.into_pg() as *mut std::ffi::c_void);

                            // Create SortGroupClause for GROUP BY
                            let mut sgc = pgrx::PgBox::<pg_sys::SortGroupClause>::alloc0();
                            sgc.type_ = pg_sys::NodeTag::T_SortGroupClause;
                            sgc.tleSortGroupRef = sort_group_ref;
                            // Look up equality and sort operators for this type using get_sort_group_operators
                            let mut eqop: pg_sys::Oid = pg_sys::InvalidOid;
                            let mut sortop: pg_sys::Oid = pg_sys::InvalidOid;
                            let mut ltop: pg_sys::Oid = pg_sys::InvalidOid;
                            let mut hashable: bool = false;
                            pg_sys::get_sort_group_operators(
                                col.type_oid,
                                false, // needLT
                                true,  // needEQ
                                false, // needGT
                                &mut ltop,
                                &mut eqop,
                                std::ptr::null_mut(),
                                &mut hashable,
                            );
                            // Get sort operator separately
                            pg_sys::get_sort_group_operators(
                                col.type_oid,
                                true,  // needLT
                                false, // needEQ
                                false, // needGT
                                &mut sortop,
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                                std::ptr::null_mut(),
                            );
                            sgc.eqop = eqop;
                            sgc.sortop = sortop;
                            sgc.nulls_first = false;
                            sgc.hashable = hashable;

                            group_clause = pg_sys::lappend(
                                group_clause,
                                sgc.into_pg() as *mut std::ffi::c_void,
                            );

                            // Add to new available columns
                            // Store the copied Var expression so it can be copied when referenced
                            new_available_columns.push(AvailableColumn {
                                varno: 0, // Aggregate output needs expression inlining
                                varattno: resno as i16,
                                name: col.name.clone(),
                                type_oid: col.type_oid,
                                typmod: col.typmod,
                                collation: col.collation,
                                computed_expr: Some(var_expr_copy),
                                ressortgroupref: sort_group_ref, // Track grouping column ref
                            });

                            resno += 1;
                            sort_group_ref += 1;
                        }
                    }
                }
            }
        }
    }

    // Add aggregate functions
    let mut aggregates: Vec<*mut pg_sys::Aggref> = Vec::new();

    for (i, measure) in agg.measures.iter().enumerate() {
        let aggref = convert_aggregate_measure(measure, &parts.available_columns, ctx, i)?;
        aggregates.push(aggref);

        // Get aggregate return type
        let agg_type = (*aggref).aggtype;

        // Create TargetEntry for this aggregate
        let mut te = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
        te.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
        te.expr = aggref as *mut pg_sys::Expr;
        te.resno = resno as pg_sys::AttrNumber;
        let agg_name = format!("agg_{}", i);
        let name_cstr = std::ffi::CString::new(agg_name.as_str()).unwrap();
        te.resname = pgrx::pg_sys::pstrdup(name_cstr.as_ptr());
        te.ressortgroupref = 0;
        te.resorigtbl = pg_sys::InvalidOid;
        te.resorigcol = 0;
        te.resjunk = false;

        target_list = pg_sys::lappend(target_list, te.into_pg() as *mut std::ffi::c_void);

        // Add to new available columns
        // Store a copy of the Aggref expression so we don't share pointers
        let aggref_copy =
            pg_sys::copyObjectImpl(aggref as *const std::ffi::c_void) as *mut pg_sys::Expr;
        new_available_columns.push(AvailableColumn {
            varno: 0,
            varattno: resno as i16,
            name: agg_name,
            type_oid: agg_type,
            typmod: -1,
            collation: pg_sys::InvalidOid,
            computed_expr: Some(aggref_copy),
            ressortgroupref: 0, // Aggregates are not grouping columns
        });

        resno += 1;
    }

    Ok(QueryParts {
        from_item: parts.from_item,
        available_columns: new_available_columns,
        where_quals: parts.where_quals,
        having_qual: parts.having_qual,
        target_list: if target_list.is_null() {
            None
        } else {
            Some(target_list)
        },
        group_clause: if group_clause.is_null() {
            None
        } else {
            Some(group_clause)
        },
        aggregates,
        sort_clause: None,
        limit_count: None,
        limit_offset: None,
        has_aggs: true,
    })
}

/// Convert a Sort relation to QueryParts.
unsafe fn convert_sort_to_query_parts(
    sort: &substrait::proto::SortRel,
    ctx: &mut QueryBuildContext,
) -> Result<QueryParts, Box<dyn std::error::Error + Send + Sync>> {
    use substrait::proto::sort_field::{SortDirection, SortKind};

    let input = sort.input.as_ref().ok_or("Sort has no input")?;
    let mut parts = convert_rel_to_query_parts(input, ctx)?;

    if sort.sorts.is_empty() {
        return Ok(parts);
    }

    // Sort keys reference target list entries via ressortgroupref, so
    // materialize the implicit SELECT * list if the input didn't build one.
    let target_list = match parts.target_list {
        Some(tl) => tl,
        None => {
            let tl = build_select_star_target_list(&parts.available_columns)?;
            parts.target_list = Some(tl);
            tl
        }
    };

    // Continue numbering after any refs already assigned (e.g. by GROUP BY).
    let mut next_ref: u32 = 1;
    for k in 0..pg_sys::list_length(target_list) {
        let te = pg_sys::list_nth(target_list, k) as *mut pg_sys::TargetEntry;
        if (*te).ressortgroupref >= next_ref {
            next_ref = (*te).ressortgroupref + 1;
        }
    }

    let mut sort_clause: *mut pg_sys::List = std::ptr::null_mut();

    for field in &sort.sorts {
        // Sort keys index the input relation's output columns, which map
        // 1:1 onto the target list built by the input conversion.
        let field_idx = extract_field_index(field.expr.as_ref().ok_or("Sort field has no expr")?)
            .ok_or("Sort key must be a direct field reference")?;
        if field_idx >= pg_sys::list_length(target_list) as usize {
            return Err(format!(
                "Sort field index {} out of range ({} target entries)",
                field_idx,
                pg_sys::list_length(target_list)
            )
            .into());
        }
        let te = pg_sys::list_nth(target_list, field_idx as i32) as *mut pg_sys::TargetEntry;
        if (*te).ressortgroupref == 0 {
            (*te).ressortgroupref = next_ref;
            next_ref += 1;
        }

        // Look up the ordering operators for the sort key's type.
        let expr_type = pg_sys::exprType((*te).expr as *const pg_sys::Node);
        let mut ltop: pg_sys::Oid = pg_sys::InvalidOid;
        let mut eqop: pg_sys::Oid = pg_sys::InvalidOid;
        let mut gtop: pg_sys::Oid = pg_sys::InvalidOid;
        let mut hashable: bool = false;
        pg_sys::get_sort_group_operators(
            expr_type,
            true, // needLT
            true, // needEQ
            true, // needGT
            &mut ltop,
            &mut eqop,
            &mut gtop,
            &mut hashable,
        );

        let direction = match &field.sort_kind {
            Some(SortKind::Direction(d)) => {
                SortDirection::try_from(*d).map_err(|_| format!("Unknown sort direction: {}", d))?
            }
            Some(SortKind::ComparisonFunctionReference(_)) => {
                return Err("Sort by comparison function is not supported".into());
            }
            None => return Err("Sort field has no sort_kind".into()),
        };
        let (sortop, nulls_first) = match direction {
            SortDirection::AscNullsFirst => (ltop, true),
            SortDirection::AscNullsLast | SortDirection::Unspecified => (ltop, false),
            SortDirection::DescNullsFirst => (gtop, true),
            SortDirection::DescNullsLast => (gtop, false),
            SortDirection::Clustered => {
                return Err("Clustered sort direction is not supported".into());
            }
        };

        let mut sgc = pgrx::PgBox::<pg_sys::SortGroupClause>::alloc0();
        sgc.type_ = pg_sys::NodeTag::T_SortGroupClause;
        sgc.tleSortGroupRef = (*te).ressortgroupref;
        sgc.eqop = eqop;
        sgc.sortop = sortop;
        sgc.nulls_first = nulls_first;
        sgc.hashable = hashable;
        sort_clause = pg_sys::lappend(sort_clause, sgc.into_pg() as *mut std::ffi::c_void);
    }

    parts.sort_clause = Some(sort_clause);
    Ok(parts)
}

/// Extract the field index from a direct StructField reference expression.
fn extract_field_index(expr: &substrait::proto::Expression) -> Option<usize> {
    use substrait::proto::expression::field_reference::ReferenceType;
    use substrait::proto::expression::reference_segment::ReferenceType as SegRefType;
    use substrait::proto::expression::RexType;

    if let Some(RexType::Selection(sel)) = &expr.rex_type {
        if let Some(ReferenceType::DirectReference(direct)) = &sel.reference_type {
            if let Some(SegRefType::StructField(sf)) = &direct.reference_type {
                return Some(sf.field as usize);
            }
        }
    }
    None
}

/// Convert a Fetch relation (LIMIT/OFFSET) to QueryParts.
unsafe fn convert_fetch_to_query_parts(
    fetch: &substrait::proto::FetchRel,
    ctx: &mut QueryBuildContext,
) -> Result<QueryParts, Box<dyn std::error::Error + Send + Sync>> {
    let input = fetch.input.as_ref().ok_or("Fetch has no input")?;
    let mut parts = convert_rel_to_query_parts(input, ctx)?;

    // Extract LIMIT from count_mode
    if let Some(count_mode) = &fetch.count_mode {
        use substrait::proto::fetch_rel::CountMode;
        match count_mode {
            CountMode::CountExpr(expr) => {
                let count_expr = super::expressions::convert_expression_for_query(
                    expr,
                    &parts.available_columns,
                    ctx,
                )?;
                parts.limit_count = Some(count_expr as *mut pg_sys::Node);
            }
            CountMode::Count(count) => {
                // Simple integer count
                let count_const = create_int8_const(*count)?;
                parts.limit_count = Some(count_const as *mut pg_sys::Node);
            }
        }
    }

    // Extract OFFSET from offset_mode
    if let Some(offset_mode) = &fetch.offset_mode {
        use substrait::proto::fetch_rel::OffsetMode;
        match offset_mode {
            OffsetMode::OffsetExpr(expr) => {
                let offset_expr = super::expressions::convert_expression_for_query(
                    expr,
                    &parts.available_columns,
                    ctx,
                )?;
                parts.limit_offset = Some(offset_expr as *mut pg_sys::Node);
            }
            OffsetMode::Offset(offset) => {
                // Simple integer offset
                let offset_const = create_int8_const(*offset)?;
                parts.limit_offset = Some(offset_const as *mut pg_sys::Node);
            }
        }
    }

    Ok(parts)
}

/// Build the final Query object from QueryParts.
unsafe fn build_query_from_parts(
    parts: &QueryParts,
    ctx: &mut QueryBuildContext,
) -> Result<*mut pg_sys::Query, Box<dyn std::error::Error + Send + Sync>> {
    let query = pgrx::PgBox::<pg_sys::Query>::alloc0();
    let query = query.into_pg();

    (*query).type_ = pg_sys::NodeTag::T_Query;
    (*query).commandType = pg_sys::CmdType::CMD_SELECT;
    (*query).querySource = pg_sys::QuerySource::QSRC_ORIGINAL;
    (*query).canSetTag = true;

    // Set range table and permission infos (PG17+)
    (*query).rtable = ctx.build_rtable_list();
    (*query).rteperminfos = ctx.build_rteperminfos_list();

    // Build FROM clause (jointree)
    let mut from_expr = pgrx::PgBox::<pg_sys::FromExpr>::alloc0();
    from_expr.type_ = pg_sys::NodeTag::T_FromExpr;

    // Add from_item to fromlist
    let mut fromlist: *mut pg_sys::List = std::ptr::null_mut();
    if !parts.from_item.is_null() {
        fromlist = pg_sys::lappend(fromlist, parts.from_item as *mut std::ffi::c_void);
    }
    from_expr.fromlist = fromlist;

    // Set WHERE clause
    from_expr.quals = if let Some(quals) = parts.where_quals {
        quals as *mut pg_sys::Node
    } else {
        std::ptr::null_mut()
    };

    (*query).jointree = from_expr.into_pg();

    // Set target list (or build default SELECT * if none)
    (*query).targetList = if let Some(tl) = parts.target_list {
        tl
    } else {
        build_select_star_target_list(&parts.available_columns)?
    };

    // Set GROUP BY
    if let Some(gc) = parts.group_clause {
        (*query).groupClause = gc;
    }

    // Set HAVING
    if let Some(hq) = parts.having_qual {
        (*query).havingQual = hq as *mut pg_sys::Node;
    }

    // Set ORDER BY
    if let Some(sc) = parts.sort_clause {
        (*query).sortClause = sc;
    }

    // Set LIMIT/OFFSET
    if let Some(lc) = parts.limit_count {
        (*query).limitCount = lc;
    }
    if let Some(lo) = parts.limit_offset {
        (*query).limitOffset = lo;
    }

    // Set flags
    (*query).hasAggs = parts.has_aggs;
    (*query).hasSubLinks = ctx.has_sublinks.get();

    Ok(query)
}

/// Build a SELECT * target list from available columns.
unsafe fn build_select_star_target_list(
    columns: &[AvailableColumn],
) -> Result<*mut pg_sys::List, Box<dyn std::error::Error + Send + Sync>> {
    let mut target_list: *mut pg_sys::List = std::ptr::null_mut();

    for (i, col) in columns.iter().enumerate() {
        // For computed columns (varno=0), use the stored expression
        // For table columns, create a Var node
        let expr = if col.varno == 0 {
            if let Some(computed) = col.computed_expr {
                // Copy the expression to avoid sharing pointers
                pg_sys::copyObjectImpl(computed as *const std::ffi::c_void) as *mut pg_sys::Expr
            } else {
                return Err(format!(
                    "Column '{}' has varno=0 but no computed expression",
                    col.name
                )
                .into());
            }
        } else {
            // Create Var node for table columns
            let mut var = pgrx::PgBox::<pg_sys::Var>::alloc0();
            var.xpr.type_ = pg_sys::NodeTag::T_Var;
            var.varno = col.varno;
            var.varattno = col.varattno;
            var.vartype = col.type_oid;
            var.vartypmod = col.typmod;
            var.varcollid = col.collation;
            var.varlevelsup = 0;
            // PG17 fields
            var.varnosyn = col.varno as u32;
            var.varattnosyn = col.varattno;
            var.into_pg() as *mut pg_sys::Expr
        };

        // Create TargetEntry
        let mut te = pgrx::PgBox::<pg_sys::TargetEntry>::alloc0();
        te.xpr.type_ = pg_sys::NodeTag::T_TargetEntry;
        te.expr = expr;
        te.resno = (i + 1) as i16;
        te.resname = create_cstring(&col.name);
        te.resjunk = false;
        let te = te.into_pg();

        target_list = pg_sys::lappend(target_list, te as *mut std::ffi::c_void);
    }

    Ok(target_list)
}

/// Create an AND expression combining two quals.
unsafe fn create_and_expr(
    left: *mut pg_sys::Expr,
    right: *mut pg_sys::Expr,
) -> Result<*mut pg_sys::Expr, Box<dyn std::error::Error + Send + Sync>> {
    let mut bool_expr = pgrx::PgBox::<pg_sys::BoolExpr>::alloc0();
    bool_expr.xpr.type_ = pg_sys::NodeTag::T_BoolExpr;
    bool_expr.boolop = pg_sys::BoolExprType::AND_EXPR;

    let mut args: *mut pg_sys::List = std::ptr::null_mut();
    args = pg_sys::lappend(args, left as *mut std::ffi::c_void);
    args = pg_sys::lappend(args, right as *mut std::ffi::c_void);
    bool_expr.args = args;
    bool_expr.location = -1;

    Ok(bool_expr.into_pg() as *mut pg_sys::Expr)
}

/// Combine optional quals with AND.
unsafe fn combine_quals(
    left: Option<*mut pg_sys::Expr>,
    right: Option<*mut pg_sys::Expr>,
) -> Result<Option<*mut pg_sys::Expr>, Box<dyn std::error::Error + Send + Sync>> {
    match (left, right) {
        (Some(l), Some(r)) => Ok(Some(create_and_expr(l, r)?)),
        (Some(l), None) => Ok(Some(l)),
        (None, Some(r)) => Ok(Some(r)),
        (None, None) => Ok(None),
    }
}

/// Create a C string in PostgreSQL memory.
unsafe fn create_cstring(s: &str) -> *mut std::os::raw::c_char {
    let len = s.len() + 1;
    let ptr = pg_sys::palloc(len) as *mut std::os::raw::c_char;
    std::ptr::copy_nonoverlapping(s.as_ptr(), ptr as *mut u8, s.len());
    *ptr.add(s.len()) = 0;
    ptr
}

/// Create an INT8 constant.
unsafe fn create_int8_const(
    value: i64,
) -> Result<*mut pg_sys::Const, Box<dyn std::error::Error + Send + Sync>> {
    let mut const_node = pgrx::PgBox::<pg_sys::Const>::alloc0();
    const_node.xpr.type_ = pg_sys::NodeTag::T_Const;
    const_node.consttype = pg_sys::INT8OID;
    const_node.consttypmod = -1;
    const_node.constcollid = pg_sys::InvalidOid;
    const_node.constlen = 8;
    const_node.constbyval = true;
    const_node.constisnull = false;
    const_node.constvalue = pg_sys::Datum::from(value);
    const_node.location = -1;

    Ok(const_node.into_pg())
}
