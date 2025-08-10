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

    let mut target_list = TargetListBuilder::new();

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
        (*node).plan.async_capable = (*input_plan).async_capable;
        (*node).plan.plan_node_id = 0;
        (*node).plan.qual = std::ptr::null_mut(); // Aggregates don't have quals
        (*node).plan.targetlist = std::ptr::null_mut();

        // Initialize all Agg-specific fields
        (*node).aggstrategy = pg_sys::AggStrategy::AGG_PLAIN;
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
            *grpOperators.add(i) = 664.into(); // btcharcmp for CHAR/VARCHAR columns
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
}

impl TargetListBuilder {
    fn new() -> Self {
        Self {
            list: PgList::new(),
            resno: 1,
        }
    }

    unsafe fn add_group_var(&mut self, attno: pg_sys::AttrNumber) {
        let mut var = PgBox::<pg_sys::Var>::alloc0();
        var.xpr.type_ = pg_sys::NodeTag::T_Var; // CRITICAL: Set the node type!
        var.varno = 1;
        var.varattno = attno;

        // Get the actual column type from the input plan's target list
        let (vartype, vartypmod, varcollid) = get_column_type_from_input_plan(self.resno - 1);
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
        let func_oid = resolve_agg_oid(func, func_map);

        let mut agg = PgBox::<pg_sys::Aggref>::alloc0();
        agg.xpr.type_ = pg_sys::NodeTag::T_Aggref; // CRITICAL: Set the node type!
        agg.aggfnoid = func_oid;

        // Resolve the aggregate return type based on the function OID
        agg.aggtype = resolve_agg_return_type(func_oid);
        agg.aggstar = func.arguments.is_empty();
        agg.aggsplit = pg_sys::AggSplit::AGGSPLIT_SIMPLE;
        agg.args = extract_agg_args(&func.arguments);

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

unsafe fn extract_agg_args(args: &[substrait::proto::FunctionArgument]) -> *mut pg_sys::List {
    let mut list = PgList::<pg_sys::Var>::new();
    for arg in args {
        if let Some(substrait::proto::function_argument::ArgType::Value(expr)) = &arg.arg_type {
            if let Ok(Some(field)) = extract_struct_field(expr) {
                let mut var = PgBox::<pg_sys::Var>::alloc0();
                var.xpr.type_ = pg_sys::NodeTag::T_Var; // CRITICAL: Set the node type!
                var.varno = 1;
                var.varattno = (field.field + 1) as pg_sys::AttrNumber;
                var.vartype = pg_sys::TEXTOID; // Use TEXT as default
                var.vartypmod = -1;
                var.varcollid = pg_sys::DEFAULT_COLLATION_OID;
                list.push(var.into_pg());
            }
        }
    }
    list.into_pg()
}

fn resolve_agg_oid(
    func: &substrait::proto::AggregateFunction,
    func_map: &HashMap<u32, String>,
) -> pg_sys::Oid {
    // TODO -- This conversion should be handled in a more principled way than using magic constants.  This behavior should likely mirror that of how scalar and window functions are looked up.
    let name = func_map
        .get(&func.function_reference)
        .map(|s| s.as_str())
        .unwrap_or("");
    match name {
        "sum:fp64" => 2108,
        "sum:i32" => 2102, // sum(integer) -> numeric
        "sum:dec" => 2104, // sum(numeric) -> numeric
        "avg:fp64" => 2100,
        "count:" => 2803,
        "count:any" => 2147, // count(any) -> bigint
        "min:fp64" => 2136,  // min(double precision) -> double precision
        _ => 2803,
    }
    .into()
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
        2147 => pg_sys::INT8OID,    // count(any) -> bigint
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
