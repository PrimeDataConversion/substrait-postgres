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
        let node = pg_sys::palloc0(std::mem::size_of::<pg_sys::Agg>()) as *mut pg_sys::Agg;
        (*node).plan.type_ = pg_sys::NodeTag::T_Agg;
        (*node).plan.lefttree = input_plan;
        (*node).plan.total_cost = 1000.0;
        (*node).plan.plan_rows = 100.0;
        (*node).plan.plan_width = 32;
        (*node).aggstrategy = pg_sys::AggStrategy::AGG_PLAIN;
        (*node).aggsplit = pg_sys::AggSplit::AGGSPLIT_SIMPLE;
        Self { ptr: node }
    }

    pub unsafe fn set_group_columns(&mut self, indices: &[pg_sys::AttrNumber]) {
        let n = indices.len() as i32;
        (*self.ptr).numCols = n;

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
            *grpOperators.add(i) = 351.into(); // btint4cmp
            *grpCollations.add(i) = pg_sys::InvalidOid;
        }

        (*self.ptr).grpColIdx = grpColIdx;
        (*self.ptr).grpOperators = grpOperators;
        (*self.ptr).grpCollations = grpCollations;
    }

    pub unsafe fn set_target_list(&mut self, list: *mut pg_sys::List) {
        (*self.ptr).plan.targetlist = list;
    }

    pub fn into_plan_ptr(self) -> *mut pg_sys::Plan {
        self.ptr as *mut pg_sys::Plan
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
        var.varno = 1;
        var.varattno = attno;
        var.vartype = pg_sys::UNKNOWNOID;
        var.vartypmod = -1;
        var.varcollid = pg_sys::InvalidOid;

        let mut entry = PgBox::<pg_sys::TargetEntry>::alloc0();
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
        agg.aggfnoid = func_oid;
        agg.aggtype = pg_sys::UNKNOWNOID;
        agg.aggstar = func.arguments.is_empty();
        agg.aggsplit = pg_sys::AggSplit::AGGSPLIT_SIMPLE;
        agg.args = extract_agg_args(&func.arguments);

        let mut entry = PgBox::<pg_sys::TargetEntry>::alloc0();
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
    if let Some(grouping) = groupings.get(0) {
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
                var.varno = 1;
                var.varattno = (field.field + 1) as pg_sys::AttrNumber;
                var.vartype = pg_sys::UNKNOWNOID;
                var.vartypmod = -1;
                var.varcollid = pg_sys::InvalidOid;
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
        "avg:fp64" => 2100,
        "count:" => 2803,
        _ => 2803,
    }
    .into()
}

unsafe fn palloc_array<T>(len: i32) -> *mut T {
    pg_sys::palloc((len as usize * std::mem::size_of::<T>()) as usize) as *mut T
}

fn create_cstring(s: &str) -> *mut std::os::raw::c_char {
    std::ffi::CString::new(s).unwrap().into_raw()
}
