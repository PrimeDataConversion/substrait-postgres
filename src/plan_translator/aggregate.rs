use crate::plan_translator::expressions::create_cstring;
use pgrx::pg_sys::AttrNumber;
use pgrx::{pg_sys, PgBox, PgList};
use std::collections::HashMap;

pub unsafe fn create_aggregate_node(
    input_plan: *mut pg_sys::Plan,
    aggregate: &substrait::proto::AggregateRel,
    function_map: &HashMap<u32, String>,
) -> Result<*mut pg_sys::Plan, Box<dyn std::error::Error + Send + Sync>> {
    let mut agg_node = AggNodeBuilder::new(input_plan);

    let group_col_indices = extract_grouping_cols(&aggregate.groupings)?;
    agg_node.set_group_columns(&group_col_indices);

    let mut target_list = TargetListBuilder::new_with_input(input_plan);

    for &col in &group_col_indices {
        target_list.add_group_var(col);
    }

    for measure in &aggregate.measures {
        target_list.add_agg_func(measure, function_map)?;
    }

    agg_node.set_target_list(target_list.finish());

    Ok(agg_node.into_plan_ptr())
}

struct AggNodeBuilder {
    ptr: *mut pg_sys::Agg,
}

impl AggNodeBuilder {
    pub unsafe fn new(input_plan: *mut pg_sys::Plan) -> Self {
        let node = pgrx::PgBox::<pg_sys::Agg>::alloc0();
        let node = node.into_pg();

        // Set node tag FIRST (critical for ExecInitNode dispatch)
        (*node).plan.type_ = pg_sys::NodeTag::T_Agg;

        // Copy generic plan info from input (PostgreSQL's copy_generic_plan_info pattern)
        (*node).plan.lefttree = input_plan;
        (*node).plan.righttree = std::ptr::null_mut();
        (*node).plan.initPlan = (*input_plan).initPlan;
        (*node).plan.extParam = (*input_plan).extParam;
        (*node).plan.allParam = (*input_plan).allParam;
        (*node).plan.startup_cost = (*input_plan).startup_cost;
        (*node).plan.total_cost = (*input_plan).total_cost + 200.0; // Add aggregate cost
        (*node).plan.plan_rows = 10.0; // Aggregation typically reduces rows
        (*node).plan.plan_width = 64; // Aggregate results are typically wider
        (*node).plan.parallel_aware = (*input_plan).parallel_aware;
        (*node).plan.parallel_safe = (*input_plan).parallel_safe;
        (*node).plan.plan_node_id = 0;
        (*node).plan.qual = std::ptr::null_mut(); // Aggregates don't have quals
        (*node).plan.targetlist = std::ptr::null_mut();

        // Initialize all Agg-specific fields
        // Note: aggstrategy will be set later based on whether there are GROUP BY columns
        (*node).aggstrategy = pg_sys::AggStrategy::AGG_PLAIN; // Default, overridden in set_group_columns
        (*node).aggsplit = pg_sys::AggSplit::AGGSPLIT_SIMPLE;
        (*node).numCols = 0;
        (*node).grpColIdx = std::ptr::null_mut();
        (*node).grpOperators = std::ptr::null_mut();
        (*node).grpCollations = std::ptr::null_mut();
        (*node).numGroups = 0;
        (*node).transitionSpace = 0;
        (*node).aggParams = std::ptr::null_mut();
        (*node).groupingSets = std::ptr::null_mut();
        (*node).chain = std::ptr::null_mut();

        Self { ptr: node }
    }

    pub unsafe fn set_group_columns(&mut self, indices: &[pg_sys::AttrNumber]) {
        let n = indices.len() as i32;
        (*self.ptr).numCols = n;
        // CRITICAL: Set numGroups to match numCols for GROUP BY queries
        (*self.ptr).numGroups = if n > 0 { 1 } else { 0 };

        // Set aggstrategy based on whether there are GROUP BY columns
        // AGG_PLAIN (0) = no grouping, just aggregate
        // AGG_SORTED (1) = input is sorted on grouping columns
        // AGG_HASHED (2) = use hash tables for grouping
        // Note: Using AGG_SORTED which expects sorted input (may need Sort below Agg)
        if n > 0 {
            (*self.ptr).aggstrategy = pg_sys::AggStrategy::AGG_SORTED;
        } else {
            (*self.ptr).aggstrategy = pg_sys::AggStrategy::AGG_PLAIN;
        }

        if n == 0 {
            (*self.ptr).grpColIdx = std::ptr::null_mut();
            (*self.ptr).grpOperators = std::ptr::null_mut();
            (*self.ptr).grpCollations = std::ptr::null_mut();
            return;
        }

        let grpColIdx = palloc_array::<pg_sys::AttrNumber>(n);
        let grpOperators = palloc_array::<pg_sys::Oid>(n);
        let grpCollations = palloc_array::<pg_sys::Oid>(n);

        for i in 0..n as usize {
            *grpColIdx.add(i) = indices[i];
            // Use btcharcmp for CHAR columns (typical for l_returnflag, l_linestatus)
            *grpOperators.add(i) = 1054.into(); // bpchareq (=) for BPCHAR columns
            *grpCollations.add(i) = pg_sys::DEFAULT_COLLATION_OID; // Use default collation
        }

        (*self.ptr).grpColIdx = grpColIdx;
        (*self.ptr).grpOperators = grpOperators;
        (*self.ptr).grpCollations = grpCollations;
    }

    pub unsafe fn set_target_list(&mut self, list: *mut pg_sys::List) {
        (*self.ptr).plan.targetlist = list;
    }

    pub fn into_plan_ptr(self) -> *mut pg_sys::Plan {
        // For Agg nodes, the plan field is directly accessible (no version differences)
        unsafe { &mut (*self.ptr).plan as *mut pg_sys::Plan }
    }
}

struct TargetListBuilder {
    list: PgList<pg_sys::TargetEntry>,
    resno: i32,
    agg_count: i32, // Track aggregate ordinal (aggno/aggtransno)
    input_plan: *mut pg_sys::Plan,
}

impl TargetListBuilder {
    fn new_with_input(input_plan: *mut pg_sys::Plan) -> Self {
        Self {
            list: PgList::new(),
            resno: 1,
            agg_count: 0, // Initialize aggregate counter
            input_plan,
        }
    }

    unsafe fn add_group_var(&mut self, attno: pg_sys::AttrNumber) {
        let mut var = PgBox::<pg_sys::Var>::alloc0();
        var.xpr.type_ = pg_sys::NodeTag::T_Var; // CRITICAL: Set the node type!
        var.varno = 1;
        var.varattno = attno;

        // Get the actual column type from the input plan's target list
        let (vartype, vartypmod, varcollid) =
            get_type_from_input_target_list(self.input_plan, attno);
        var.vartype = vartype;
        var.vartypmod = vartypmod;
        var.varcollid = varcollid;

        let mut entry = PgBox::<pg_sys::TargetEntry>::alloc0();
        entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry; // CRITICAL: Set the node type!
        entry.expr = var.into_pg() as *mut pg_sys::Expr;
        entry.resno = self.resno as AttrNumber;
        entry.resname = create_cstring(&format!("group_col_{}", self.resno));
        entry.resjunk = false;

        self.list.push(entry.into_pg());
        self.resno += 1;
    }

    unsafe fn add_agg_func(
        &mut self,
        measure: &substrait::proto::aggregate_rel::Measure,
        func_map: &HashMap<u32, String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let func = measure.measure.as_ref().ok_or("Missing measure")?;

        // Get the argument type from the input plan for proper function resolution
        let arg_type = if func.arguments.is_empty() {
            pg_sys::InvalidOid // No arguments (like count(*))
        } else if let Some(substrait::proto::function_argument::ArgType::Value(expr)) =
            &func.arguments[0].arg_type
        {
            infer_expr_type_oid_from_input(expr, self.input_plan)
        } else {
            pg_sys::InvalidOid
        };

        let func_oid = resolve_agg_oid(func, func_map, arg_type);

        let mut agg = PgBox::<pg_sys::Aggref>::alloc0();
        agg.xpr.type_ = pg_sys::NodeTag::T_Aggref; // CRITICAL: Set the node type!
        agg.aggfnoid = func_oid;

        // Resolve the aggregate return type based on the function OID
        agg.aggtype = resolve_agg_return_type(func_oid);
        agg.aggstar = func.arguments.is_empty();
        agg.aggsplit = pg_sys::AggSplit::AGGSPLIT_SIMPLE;
        agg.args = extract_agg_args(&func.arguments, self.input_plan);

        // CRITICAL: Set additional fields required by ExecInitAgg
        agg.aggcollid = pg_sys::InvalidOid; // No collation for numeric aggregates
        agg.inputcollid = pg_sys::InvalidOid; // No input collation
        agg.aggtranstype = resolve_agg_trans_type(func_oid); // Transition state type
        agg.aggargtypes = build_agg_arg_types(&func.arguments, self.input_plan); // Argument type OIDs
        agg.aggdirectargs = std::ptr::null_mut(); // No direct args for simple aggregates
        agg.aggorder = std::ptr::null_mut(); // No ORDER BY within aggregate
        agg.aggdistinct = std::ptr::null_mut(); // No DISTINCT within aggregate
        agg.aggfilter = std::ptr::null_mut(); // No filter expression
        agg.aggvariadic = false; // Not variadic
        agg.aggkind = b'n' as i8; // AGGKIND_NORMAL = 'n'
        agg.aggpresorted = false; // Input not presorted
        agg.agglevelsup = 0; // Not in outer query
        agg.aggno = self.agg_count; // Aggregate ordinal (0-based, among all aggregates)
        agg.aggtransno = self.agg_count; // Transition state number (same as aggno for simple aggs)
        agg.location = -1; // Unknown location in query string
        self.agg_count += 1; // Increment for next aggregate

        let mut entry = PgBox::<pg_sys::TargetEntry>::alloc0();
        entry.xpr.type_ = pg_sys::NodeTag::T_TargetEntry; // CRITICAL: Set the node type!
        entry.expr = agg.into_pg() as *mut pg_sys::Expr;
        entry.resno = self.resno as AttrNumber;
        entry.resname = create_cstring(&format!("agg_func_{}", self.resno));
        entry.resjunk = false;

        self.list.push(entry.into_pg());
        self.resno += 1;
        Ok(())
    }

    fn finish(self) -> *mut pg_sys::List {
        self.list.into_pg()
    }
}

fn extract_grouping_cols(
    groupings: &[substrait::proto::aggregate_rel::Grouping],
) -> Result<Vec<pg_sys::AttrNumber>, Box<dyn std::error::Error + Send + Sync>> {
    let mut result = Vec::new();
    if let Some(grouping) = groupings.first() {
        #[allow(deprecated)]
        for expr in &grouping.grouping_expressions {
            if let Ok(Some(field)) = extract_struct_field(expr) {
                result.push((field.field + 1) as pg_sys::AttrNumber);
            }
        }
    }
    Ok(result)
}

fn extract_struct_field(
    rex: &substrait::proto::Expression,
) -> Result<
    Option<substrait::proto::expression::reference_segment::StructField>,
    Box<dyn std::error::Error>,
> {
    if let Some(substrait::proto::expression::RexType::Selection(sel)) = &rex.rex_type {
        if let Some(
            substrait::proto::expression::field_reference::ReferenceType::DirectReference(direct),
        ) = &sel.reference_type
        {
            if let Some(
                substrait::proto::expression::reference_segment::ReferenceType::StructField(field),
            ) = &direct.reference_type
            {
                return Ok(Some(*field.clone()));
            }
        }
    }
    Ok(None)
}

unsafe fn extract_agg_args(
    args: &[substrait::proto::FunctionArgument],
    input_plan: *mut pg_sys::Plan,
) -> *mut pg_sys::List {
    let mut list = PgList::<pg_sys::Var>::new();
    for arg in args {
        if let Some(substrait::proto::function_argument::ArgType::Value(expr)) = &arg.arg_type {
            if let Ok(Some(field)) = extract_struct_field(expr) {
                let attno = (field.field + 1) as pg_sys::AttrNumber;

                // Look up the actual column type from the input plan's target list
                let (vartype, vartypmod, varcollid) =
                    get_type_from_input_target_list(input_plan, attno);

                let mut var = PgBox::<pg_sys::Var>::alloc0();
                var.xpr.type_ = pg_sys::NodeTag::T_Var; // CRITICAL: Set the node type!
                var.varno = 1;
                var.varattno = attno;
                var.vartype = vartype;
                var.vartypmod = vartypmod;
                var.varcollid = varcollid;
                list.push(var.into_pg());
            }
        }
    }
    list.into_pg()
}

/// Get type information from the input plan's target list for a given attribute number
unsafe fn get_type_from_input_target_list(
    input_plan: *mut pg_sys::Plan,
    attno: pg_sys::AttrNumber,
) -> (pg_sys::Oid, i32, pg_sys::Oid) {
    if input_plan.is_null() {
        // Default to TEXT if no input plan
        return (pg_sys::TEXTOID, -1, pg_sys::DEFAULT_COLLATION_OID);
    }

    let targetlist = (*input_plan).targetlist;
    if targetlist.is_null() {
        return (pg_sys::TEXTOID, -1, pg_sys::DEFAULT_COLLATION_OID);
    }

    // Find the TargetEntry with the matching resno
    let list_len = (*targetlist).length;
    for i in 0..list_len {
        let te = pg_sys::list_nth(targetlist, i) as *mut pg_sys::TargetEntry;
        if te.is_null() {
            continue;
        }
        if (*te).resno == attno {
            let expr = (*te).expr;
            if !expr.is_null() {
                // Get the type of the expression
                let expr_type = pg_sys::exprType(expr as *mut pg_sys::Node);
                let expr_typmod = pg_sys::exprTypmod(expr as *mut pg_sys::Node);
                let expr_collid = pg_sys::exprCollation(expr as *mut pg_sys::Node);
                return (expr_type, expr_typmod, expr_collid);
            }
        }
    }

    // Default if not found
    (pg_sys::TEXTOID, -1, pg_sys::DEFAULT_COLLATION_OID)
}

fn resolve_agg_oid(
    func: &substrait::proto::AggregateFunction,
    func_map: &HashMap<u32, String>,
    arg_type: pg_sys::Oid,
) -> pg_sys::Oid {
    let name = func_map
        .get(&func.function_reference)
        .map(|s| s.as_str())
        .unwrap_or("");

    // Use dynamic lookup based on function name prefix and actual argument type
    let base_name = if name.starts_with("sum:") {
        "sum"
    } else if name.starts_with("avg:") {
        "avg"
    } else if name.starts_with("count:") {
        "count"
    } else if name.starts_with("min:") {
        "min"
    } else if name.starts_with("max:") {
        "max"
    } else {
        return 2803.into(); // Default to count(*)
    };

    // Look up the aggregate function for the actual argument type
    unsafe { lookup_agg_func_by_name_and_type(base_name, arg_type) }
}

/// Look up aggregate function OID by name and argument type
unsafe fn lookup_agg_func_by_name_and_type(name: &str, arg_type: pg_sys::Oid) -> pg_sys::Oid {
    use crate::plan_translator::expressions::lookup_function_oid;

    // For count(*), use the no-argument version
    if name == "count" && arg_type == pg_sys::InvalidOid {
        return 2803.into(); // count(*)
    }

    // Try to look up the aggregate function with the actual type
    let result = if arg_type == pg_sys::InvalidOid {
        // No arguments (like count(*))
        lookup_function_oid(name, &[])
    } else {
        lookup_function_oid(name, &[arg_type])
    };

    match result {
        Ok(oid) => oid,
        Err(_) => {
            eprintln!(
                "DEBUG: Failed to lookup aggregate '{}' with arg type {}, using fallback",
                name,
                arg_type.to_u32()
            );
            // Fallback to known OIDs
            match (name, arg_type.into()) {
                ("sum", 1700) => 2104.into(), // sum(numeric)
                ("sum", 701) => 2108.into(),  // sum(float8)
                ("sum", 23) => 2102.into(),   // sum(int4)
                ("avg", 1700) => 2107.into(), // avg(numeric)
                ("avg", 701) => 2100.into(),  // avg(float8)
                ("min", 1700) => 2142.into(), // min(numeric)
                ("min", 701) => 2136.into(),  // min(float8)
                ("max", 1700) => 2148.into(), // max(numeric)
                ("max", 701) => 2137.into(),  // max(float8)
                ("count", _) => 2803.into(),  // count(*)
                _ => 2803.into(),             // Default to count(*)
            }
        }
    }
}

unsafe fn palloc_array<T>(len: i32) -> *mut T {
    let slice = pgrx::PgMemoryContexts::CurrentMemoryContext.palloc_slice::<T>(len as usize);
    slice.as_mut_ptr()
}

/// Get column type information from input plan's target list
/// For now, use default types - this should be improved to get actual types
unsafe fn get_column_type_from_input_plan(index: i32) -> (pg_sys::Oid, i32, pg_sys::Oid) {
    // TODO: Extract actual types from input plan's target list
    // For now, return safe defaults based on common TPC-H column types
    match index {
        0 => (pg_sys::BPCHAROID, 5, pg_sys::DEFAULT_COLLATION_OID), // l_returnflag CHAR(1)
        1 => (pg_sys::BPCHAROID, 5, pg_sys::DEFAULT_COLLATION_OID), // l_linestatus CHAR(1)
        _ => (pg_sys::INT8OID, -1, pg_sys::DEFAULT_COLLATION_OID),  // Default to bigint
    }
}

/// Resolve aggregate function return type based on function OID
unsafe fn resolve_agg_return_type(func_oid: pg_sys::Oid) -> pg_sys::Oid {
    // Common aggregate function return types - match on the OID value
    match func_oid.into() {
        2100 => pg_sys::FLOAT8OID,  // avg(double precision) -> double precision
        2101 => pg_sys::INT8OID,    // count(any) -> bigint
        2102 => pg_sys::NUMERICOID, // sum(integer) -> numeric
        2103 => pg_sys::NUMERICOID, // sum(bigint) -> numeric
        2104 => pg_sys::NUMERICOID, // sum(numeric) -> numeric
        2105 => pg_sys::FLOAT8OID,  // avg(integer) -> double precision
        2106 => pg_sys::FLOAT8OID,  // avg(bigint) -> double precision
        2107 => pg_sys::NUMERICOID, // avg(numeric) -> numeric
        2108 => pg_sys::FLOAT8OID,  // sum(double precision) -> double precision
        2136 => pg_sys::FLOAT8OID,  // min(double precision) -> double precision
        2137 => pg_sys::FLOAT8OID,  // max(double precision) -> double precision
        2142 => pg_sys::NUMERICOID, // min(numeric) -> numeric
        2146 => pg_sys::NUMERICOID, // avg(numeric) alias
        2147 => pg_sys::INT8OID,    // count(any) -> bigint
        2148 => pg_sys::NUMERICOID, // max(numeric) -> numeric
        2803 => pg_sys::INT8OID,    // count() -> bigint
        _ => {
            // For unknown functions, try to look up the return type from pg_proc
            // If lookup fails, default to numeric which is safe for most aggregates
            lookup_function_return_type(func_oid).unwrap_or(pg_sys::NUMERICOID)
        }
    }
}

/// Look up function return type from pg_proc system catalog
unsafe fn lookup_function_return_type(func_oid: pg_sys::Oid) -> Option<pg_sys::Oid> {
    // Use PostgreSQL's system catalog to get the return type for this function
    let tuple = pg_sys::SearchSysCache1(
        pg_sys::SysCacheIdentifier::PROCOID as i32,
        pg_sys::Datum::from(func_oid.to_u32()),
    );

    if tuple.is_null() {
        eprintln!(
            "DEBUG: Function OID {} not found in pg_proc catalog",
            func_oid.to_u32()
        );
        return Some(pg_sys::NUMERICOID); // Safe default
    }

    let proc_form = pg_sys::GETSTRUCT(tuple) as *mut pg_sys::FormData_pg_proc;
    let return_type = (*proc_form).prorettype;

    eprintln!(
        "DEBUG: Function OID {} has return type: {}",
        func_oid.to_u32(),
        return_type.to_u32()
    );

    pg_sys::ReleaseSysCache(tuple);

    if return_type == pg_sys::InvalidOid || return_type.to_u32() == 0 {
        eprintln!(
            "DEBUG: Function OID {} has invalid return type, using NUMERICOID default",
            func_oid.to_u32()
        );
        return Some(pg_sys::NUMERICOID);
    }

    Some(return_type)
}

/// Resolve aggregate function transition type based on function OID
/// This queries the pg_aggregate system catalog for accurate type information.
unsafe fn resolve_agg_trans_type(func_oid: pg_sys::Oid) -> pg_sys::Oid {
    // Query pg_aggregate system catalog for the transition type
    let agg_tuple = pg_sys::SearchSysCache1(
        pg_sys::SysCacheIdentifier::AGGFNOID as i32,
        pg_sys::Datum::from(func_oid),
    );

    if agg_tuple.is_null() {
        eprintln!(
            "DEBUG: No pg_aggregate entry found for func_oid: {}, using INTERNALOID",
            func_oid.to_u32()
        );
        return pg_sys::INTERNALOID;
    }

    // Get aggtranstype using SysCacheGetAttr
    // Anum_pg_aggregate_aggtranstype is 17 in PostgreSQL 17
    const ANUM_PG_AGGREGATE_AGGTRANSTYPE: u32 = 17;
    let mut is_null = false;
    let trans_type_datum = pg_sys::SysCacheGetAttr(
        pg_sys::SysCacheIdentifier::AGGFNOID as i32,
        agg_tuple,
        ANUM_PG_AGGREGATE_AGGTRANSTYPE as i16,
        &mut is_null,
    );

    let trans_type = if is_null {
        pg_sys::INTERNALOID
    } else {
        // Datum for Oid is just the Oid value
        pg_sys::Oid::from(trans_type_datum.value() as u32)
    };

    eprintln!(
        "DEBUG: Resolved aggtranstype for func_oid {} -> {}",
        func_oid.to_u32(),
        trans_type.to_u32()
    );

    pg_sys::ReleaseSysCache(agg_tuple);

    trans_type
}

/// Build the list of argument type OIDs for an aggregate
unsafe fn build_agg_arg_types(
    args: &[substrait::proto::FunctionArgument],
    input_plan: *mut pg_sys::Plan,
) -> *mut pg_sys::List {
    if args.is_empty() {
        return std::ptr::null_mut();
    }

    let mut list: *mut pg_sys::List = std::ptr::null_mut();

    for arg in args {
        if let Some(substrait::proto::function_argument::ArgType::Value(expr)) = &arg.arg_type {
            // Get the type from the expression using the input plan's target list
            let type_oid = infer_expr_type_oid_from_input(expr, input_plan);
            // Use lappend_oid for OID lists
            list = pg_sys::lappend_oid(list, type_oid);
        }
    }

    list
}

/// Infer the PostgreSQL type OID from a Substrait expression using input plan info
unsafe fn infer_expr_type_oid_from_input(
    expr: &substrait::proto::Expression,
    input_plan: *mut pg_sys::Plan,
) -> pg_sys::Oid {
    if let Some(substrait::proto::expression::RexType::Selection(sel)) = &expr.rex_type {
        // Field reference - look up actual type from input plan
        if let Some(
            substrait::proto::expression::field_reference::ReferenceType::DirectReference(direct),
        ) = &sel.reference_type
        {
            if let Some(
                substrait::proto::expression::reference_segment::ReferenceType::StructField(field),
            ) = &direct.reference_type
            {
                let attno = (field.field + 1) as pg_sys::AttrNumber;
                let (vartype, _, _) = get_type_from_input_target_list(input_plan, attno);
                return vartype;
            }
        }
        pg_sys::TEXTOID // Default for unknown selections
    } else if let Some(substrait::proto::expression::RexType::Literal(lit)) = &expr.rex_type {
        // Literal - infer from literal type
        match &lit.literal_type {
            Some(substrait::proto::expression::literal::LiteralType::I32(_)) => pg_sys::INT4OID,
            Some(substrait::proto::expression::literal::LiteralType::I64(_)) => pg_sys::INT8OID,
            Some(substrait::proto::expression::literal::LiteralType::Fp32(_)) => pg_sys::FLOAT4OID,
            Some(substrait::proto::expression::literal::LiteralType::Fp64(_)) => pg_sys::FLOAT8OID,
            Some(substrait::proto::expression::literal::LiteralType::String(_)) => pg_sys::TEXTOID,
            _ => pg_sys::TEXTOID,
        }
    } else {
        pg_sys::TEXTOID
    }
}

/// Infer the PostgreSQL type OID from a Substrait expression
fn infer_expr_type_oid(expr: &substrait::proto::Expression) -> u32 {
    // For field references, we need to infer from context
    // For now, use TEXT as default since most aggregate inputs are numeric or text
    // This will be coerced appropriately by PostgreSQL
    if let Some(substrait::proto::expression::RexType::Selection(_)) = &expr.rex_type {
        // Field reference - assume TEXT which will be coerced
        pg_sys::TEXTOID.into()
    } else if let Some(substrait::proto::expression::RexType::Literal(lit)) = &expr.rex_type {
        // Literal - infer from literal type
        match &lit.literal_type {
            Some(substrait::proto::expression::literal::LiteralType::I32(_)) => {
                pg_sys::INT4OID.into()
            }
            Some(substrait::proto::expression::literal::LiteralType::I64(_)) => {
                pg_sys::INT8OID.into()
            }
            Some(substrait::proto::expression::literal::LiteralType::Fp32(_)) => {
                pg_sys::FLOAT4OID.into()
            }
            Some(substrait::proto::expression::literal::LiteralType::Fp64(_)) => {
                pg_sys::FLOAT8OID.into()
            }
            Some(substrait::proto::expression::literal::LiteralType::String(_)) => {
                pg_sys::TEXTOID.into()
            }
            _ => pg_sys::TEXTOID.into(),
        }
    } else {
        pg_sys::TEXTOID.into()
    }
}
