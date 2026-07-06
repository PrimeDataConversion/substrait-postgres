use anyhow::Result;
use pgrx::pg_sys;

use crate::plan_translator::{ColumnInfo, ExecutionResult};

/// Debug helper to recursively dump expression node structure
unsafe fn debug_dump_expr(node: *mut pg_sys::Node, depth: usize) {
    let indent = "  ".repeat(depth);
    if node.is_null() {
        return;
    }

    let node_type = (*node).type_;
    match node_type {
        pg_sys::NodeTag::T_Var => {
            let var = node as *mut pg_sys::Var;
            pgrx::info!(
                "{}Var: varno={} varattno={} vartype={}",
                indent,
                (*var).varno,
                (*var).varattno,
                (*var).vartype.to_u32()
            );
        }
        pg_sys::NodeTag::T_Const => {
            let c = node as *mut pg_sys::Const;
            pgrx::info!(
                "{}Const: consttype={} constisnull={}",
                indent,
                (*c).consttype.to_u32(),
                (*c).constisnull
            );
        }
        pg_sys::NodeTag::T_OpExpr => {
            let op = node as *mut pg_sys::OpExpr;
            let nargs = if (*op).args.is_null() {
                0
            } else {
                (*(*op).args).length
            };
            pgrx::info!(
                "{}OpExpr: opno={} opfuncid={} nargs={}",
                indent,
                (*op).opno.to_u32(),
                (*op).opfuncid.to_u32(),
                nargs
            );
            if !(*op).args.is_null() {
                for i in 0..nargs.min(4) {
                    let arg = pg_sys::list_nth((*op).args, i) as *mut pg_sys::Node;
                    debug_dump_expr(arg, depth + 1);
                }
            }
        }
        pg_sys::NodeTag::T_BoolExpr => {
            let be = node as *mut pg_sys::BoolExpr;
            let nargs = if (*be).args.is_null() {
                0
            } else {
                (*(*be).args).length
            };
            pgrx::info!(
                "{}BoolExpr: boolop={:?} nargs={}",
                indent,
                (*be).boolop,
                nargs
            );
            if !(*be).args.is_null() {
                for i in 0..nargs.min(6) {
                    let arg = pg_sys::list_nth((*be).args, i) as *mut pg_sys::Node;
                    debug_dump_expr(arg, depth + 1);
                }
            }
        }
        pg_sys::NodeTag::T_FuncExpr => {
            let fe = node as *mut pg_sys::FuncExpr;
            let nargs = if (*fe).args.is_null() {
                0
            } else {
                (*(*fe).args).length
            };
            pgrx::info!(
                "{}FuncExpr: funcid={} nargs={}",
                indent,
                (*fe).funcid.to_u32(),
                nargs
            );
            if !(*fe).args.is_null() {
                for i in 0..nargs.min(4) {
                    let arg = pg_sys::list_nth((*fe).args, i) as *mut pg_sys::Node;
                    debug_dump_expr(arg, depth + 1);
                }
            }
        }
        pg_sys::NodeTag::T_SubPlan => {
            let sp = node as *mut pg_sys::SubPlan;
            pgrx::info!(
                "{}SubPlan: plan_id={} plan_name={:p} subLinkType={:?}",
                indent,
                (*sp).plan_id,
                (*sp).plan_name,
                (*sp).subLinkType
            );
        }
        pg_sys::NodeTag::T_Param => {
            let p = node as *mut pg_sys::Param;
            pgrx::info!(
                "{}Param: paramkind={:?} paramid={} paramtype={}",
                indent,
                (*p).paramkind,
                (*p).paramid,
                (*p).paramtype.to_u32()
            );
        }
        pg_sys::NodeTag::T_Aggref => {
            let ar = node as *mut pg_sys::Aggref;
            pgrx::info!(
                "{}Aggref: aggfnoid={} aggtype={}",
                indent,
                (*ar).aggfnoid.to_u32(),
                (*ar).aggtype.to_u32()
            );
        }
        pg_sys::NodeTag::T_TargetEntry => {
            let te = node as *mut pg_sys::TargetEntry;
            pgrx::info!(
                "{}TargetEntry: resno={} resjunk={}",
                indent,
                (*te).resno,
                (*te).resjunk
            );
            debug_dump_expr((*te).expr as *mut pg_sys::Node, depth + 1);
        }
        pg_sys::NodeTag::T_RelabelType => {
            let rt = node as *mut pg_sys::RelabelType;
            pgrx::info!(
                "{}RelabelType: resulttype={}",
                indent,
                (*rt).resulttype.to_u32()
            );
            debug_dump_expr((*rt).arg as *mut pg_sys::Node, depth + 1);
        }
        pg_sys::NodeTag::T_CoerceViaIO => {
            let cvi = node as *mut pg_sys::CoerceViaIO;
            pgrx::info!(
                "{}CoerceViaIO: resulttype={}",
                indent,
                (*cvi).resulttype.to_u32()
            );
            debug_dump_expr((*cvi).arg as *mut pg_sys::Node, depth + 1);
        }
        pg_sys::NodeTag::T_NullTest => {
            let nt = node as *mut pg_sys::NullTest;
            pgrx::info!("{}NullTest: nulltesttype={:?}", indent, (*nt).nulltesttype);
            debug_dump_expr((*nt).arg as *mut pg_sys::Node, depth + 1);
        }
        _ => {
            pgrx::info!("{}Other: type={:?}", indent, node_type);
        }
    }
}

/// Debug helper to dump plan tree structure before ExecInitNode
unsafe fn debug_dump_plan_tree(plan: *mut pg_sys::Plan, depth: usize) {
    let indent = "  ".repeat(depth);
    if plan.is_null() {
        pgrx::info!("{}PLAN_DUMP: NULL plan at depth {}", indent, depth);
        return;
    }

    let node_tag = (*plan).type_;
    pgrx::info!(
        "{}PLAN_DUMP: depth={} type={:?} ptr={:p}",
        indent,
        depth,
        node_tag,
        plan
    );
    pgrx::info!(
        "{}  targetlist={:p} qual={:p}",
        indent,
        (*plan).targetlist,
        (*plan).qual
    );
    pgrx::info!(
        "{}  lefttree={:p} righttree={:p}",
        indent,
        (*plan).lefttree,
        (*plan).righttree
    );
    // Check initPlan, extParam, allParam - these affect subplan initialization
    pgrx::info!(
        "{}  initPlan={:p} extParam={:p} allParam={:p}",
        indent,
        (*plan).initPlan,
        (*plan).extParam,
        (*plan).allParam
    );

    // Debug plan.qual expression structure (filter conditions)
    if !(*plan).qual.is_null() {
        let qual_list = (*plan).qual;
        pgrx::info!("{}  qual list length={}", indent, (*qual_list).length);
        for qual_idx in 0..(*qual_list).length.min(5) {
            let node = pg_sys::list_nth(qual_list, qual_idx) as *mut pg_sys::Node;
            if !node.is_null() {
                let node_type = (*node).type_;
                pgrx::info!("{}  qual[{}] type={:?}", indent, qual_idx, node_type);
                // Check for Var nodes that might have invalid references
                if node_type == pg_sys::NodeTag::T_FuncExpr {
                    let func_expr = node as *mut pg_sys::FuncExpr;
                    pgrx::info!(
                        "{}    FuncExpr funcid={} args.len={}",
                        indent,
                        (*func_expr).funcid.to_u32(),
                        if (*func_expr).args.is_null() {
                            0
                        } else {
                            (*(*func_expr).args).length
                        }
                    );
                } else if node_type == pg_sys::NodeTag::T_BoolExpr {
                    let bool_expr = node as *mut pg_sys::BoolExpr;
                    let args_len = if (*bool_expr).args.is_null() {
                        0
                    } else {
                        (*(*bool_expr).args).length
                    };
                    pgrx::info!(
                        "{}    BoolExpr boolop={:?} args.len={}",
                        indent,
                        (*bool_expr).boolop,
                        args_len
                    );
                    // Dump each argument of the BoolExpr
                    if !(*bool_expr).args.is_null() {
                        for arg_idx in 0..args_len.min(10) {
                            let arg_node =
                                pg_sys::list_nth((*bool_expr).args, arg_idx) as *mut pg_sys::Node;
                            if !arg_node.is_null() {
                                let arg_type = (*arg_node).type_;
                                if arg_type == pg_sys::NodeTag::T_FuncExpr {
                                    let func = arg_node as *mut pg_sys::FuncExpr;
                                    pgrx::info!(
                                        "{}      arg[{}] FuncExpr funcid={}",
                                        indent,
                                        arg_idx,
                                        (*func).funcid.to_u32()
                                    );
                                    // Inspect Var arguments of the function
                                    if !(*func).args.is_null() {
                                        for func_arg_idx in 0..(*(*func).args).length.min(4) {
                                            let func_arg =
                                                pg_sys::list_nth((*func).args, func_arg_idx)
                                                    as *mut pg_sys::Node;
                                            if !func_arg.is_null()
                                                && (*func_arg).type_ == pg_sys::NodeTag::T_Var
                                            {
                                                let var = func_arg as *mut pg_sys::Var;
                                                pgrx::info!(
                                                    "{}        Var varno={} varattno={} vartype={}",
                                                    indent,
                                                    (*var).varno,
                                                    (*var).varattno,
                                                    (*var).vartype.to_u32()
                                                );
                                            }
                                        }
                                    }
                                } else {
                                    pgrx::info!(
                                        "{}      arg[{}] type={:?}",
                                        indent,
                                        arg_idx,
                                        arg_type
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Agg-specific debug
    if node_tag == pg_sys::NodeTag::T_Agg {
        let agg = plan as *mut pg_sys::Agg;
        pgrx::info!(
            "{}  AGG: aggstrategy={:?} numCols={}",
            indent,
            (*agg).aggstrategy,
            (*agg).numCols
        );
        pgrx::info!(
            "{}  AGG: grpColIdx={:p} grpOperators={:p}",
            indent,
            (*agg).grpColIdx,
            (*agg).grpOperators
        );
        pgrx::info!(
            "{}  AGG: numGroups={} aggParams={:p}",
            indent,
            (*agg).numGroups,
            (*agg).aggParams
        );
        if (*agg).numCols > 0 && !(*agg).grpColIdx.is_null() {
            for i in 0..(*agg).numCols.min(10) {
                let col = *(*agg).grpColIdx.offset(i as isize);
                let op = if !(*agg).grpOperators.is_null() {
                    *(*agg).grpOperators.offset(i as isize)
                } else {
                    pg_sys::InvalidOid
                };
                let coll = if !(*agg).grpCollations.is_null() {
                    *(*agg).grpCollations.offset(i as isize)
                } else {
                    pg_sys::InvalidOid
                };
                pgrx::info!(
                    "{}    grpCol[{}]: idx={} op={} coll={}",
                    indent,
                    i,
                    col,
                    op,
                    coll
                );
            }
        }
        // Check chain list
        pgrx::info!(
            "{}  AGG: chain={:p} aggsplit={:?}",
            indent,
            (*agg).chain,
            (*agg).aggsplit
        );
    }

    // Sort-specific debug
    if node_tag == pg_sys::NodeTag::T_Sort {
        let sort = plan as *mut pg_sys::Sort;
        pgrx::info!("{}  SORT: numCols={}", indent, (*sort).numCols);
        pgrx::info!(
            "{}  SORT: sortColIdx={:p} sortOperators={:p} collations={:p} nullsFirst={:p}",
            indent,
            (*sort).sortColIdx,
            (*sort).sortOperators,
            (*sort).collations,
            (*sort).nullsFirst
        );
        // Dump actual array values
        if (*sort).numCols > 0 && !(*sort).sortColIdx.is_null() {
            for i in 0..(*sort).numCols.min(10) {
                let col_idx = *(*sort).sortColIdx.offset(i as isize);
                let op = if !(*sort).sortOperators.is_null() {
                    *(*sort).sortOperators.offset(i as isize)
                } else {
                    pg_sys::InvalidOid
                };
                let coll = if !(*sort).collations.is_null() {
                    *(*sort).collations.offset(i as isize)
                } else {
                    pg_sys::InvalidOid
                };
                let nulls_first = if !(*sort).nullsFirst.is_null() {
                    *(*sort).nullsFirst.offset(i as isize)
                } else {
                    false
                };
                pgrx::info!(
                    "{}    sortCol[{}]: idx={} op={} coll={} nullsFirst={}",
                    indent,
                    i,
                    col_idx,
                    op.to_u32(),
                    coll.to_u32(),
                    nulls_first
                );
            }
        }
    }

    // SeqScan-specific debug
    if node_tag == pg_sys::NodeTag::T_SeqScan {
        let scan = plan as *mut pg_sys::SeqScan;
        pgrx::info!("{}  SEQSCAN: scanrelid={}", indent, (*scan).scan.scanrelid);
        // Dump targetlist for SeqScan to compare with Result's OUTER_VAR refs
        if !(*plan).targetlist.is_null() {
            let targetlist = (*plan).targetlist;
            let len = (*targetlist).length;
            pgrx::info!("{}  SEQSCAN targetlist has {} entries:", indent, len);
            for i in 0..len.min(20) {
                let te = pg_sys::list_nth(targetlist, i) as *mut pg_sys::TargetEntry;
                if !te.is_null() {
                    let expr = (*te).expr;
                    let expr_type = if !expr.is_null() {
                        (*(expr as *mut pg_sys::Node)).type_
                    } else {
                        pg_sys::NodeTag::T_Invalid
                    };
                    if expr_type == pg_sys::NodeTag::T_Var {
                        let var = expr as *mut pg_sys::Var;
                        pgrx::info!(
                            "{}    TE[{}]: resno={} Var varno={} varattno={} vartype={}",
                            indent,
                            i,
                            (*te).resno,
                            (*var).varno,
                            (*var).varattno,
                            (*var).vartype.to_u32()
                        );
                    } else {
                        pgrx::info!(
                            "{}    TE[{}]: resno={} expr_type={:?}",
                            indent,
                            i,
                            (*te).resno,
                            expr_type
                        );
                    }
                }
            }
        }
    }

    // Result-specific debug
    if node_tag == pg_sys::NodeTag::T_Result {
        let result = plan as *mut pg_sys::Result;
        pgrx::info!(
            "{}  RESULT: resconstantqual={:p}",
            indent,
            (*result).resconstantqual
        );
        // Dump targetlist for Result node to debug Project expressions
        if !(*plan).targetlist.is_null() {
            let targetlist = (*plan).targetlist;
            let len = (*targetlist).length;
            pgrx::info!("{}  RESULT targetlist has {} entries:", indent, len);
            for i in 0..len.min(10) {
                let te = pg_sys::list_nth(targetlist, i) as *mut pg_sys::TargetEntry;
                if !te.is_null() {
                    let expr = (*te).expr;
                    let expr_type = if !expr.is_null() {
                        (*(expr as *mut pg_sys::Node)).type_
                    } else {
                        pg_sys::NodeTag::T_Invalid
                    };
                    pgrx::info!(
                        "{}    TE[{}]: resno={} resname={:p} expr_type={:?}",
                        indent,
                        i,
                        (*te).resno,
                        (*te).resname,
                        expr_type
                    );
                    // If it's a Var, show details
                    if expr_type == pg_sys::NodeTag::T_Var {
                        let var = expr as *mut pg_sys::Var;
                        pgrx::info!(
                            "{}      Var: varno={} varattno={} vartype={}",
                            indent,
                            (*var).varno,
                            (*var).varattno,
                            (*var).vartype.to_u32()
                        );
                    } else if expr_type == pg_sys::NodeTag::T_FuncExpr {
                        let fe = expr as *mut pg_sys::FuncExpr;
                        pgrx::info!(
                            "{}      FuncExpr: funcid={} funcresulttype={}",
                            indent,
                            (*fe).funcid.to_u32(),
                            (*fe).funcresulttype.to_u32()
                        );
                    }
                }
            }
        }
    }

    // NestLoop-specific debug
    if node_tag == pg_sys::NodeTag::T_NestLoop {
        let nestloop = plan as *mut pg_sys::NestLoop;
        pgrx::info!(
            "{}  NESTLOOP: jointype={:?} joinqual={:p} nestParams={:p}",
            indent,
            (*nestloop).join.jointype,
            (*nestloop).join.joinqual,
            (*nestloop).nestParams
        );
        pgrx::info!(
            "{}  NESTLOOP: inner_unique={}",
            indent,
            (*nestloop).join.inner_unique
        );
    }

    // Recurse into children
    if !(*plan).lefttree.is_null() {
        debug_dump_plan_tree((*plan).lefttree, depth + 1);
    }
    if !(*plan).righttree.is_null() {
        debug_dump_plan_tree((*plan).righttree, depth + 1);
    }
}

/// Adjust varno values in an expression node by adding an offset.
/// This recursively walks expression trees to find Var nodes.
unsafe fn adjust_varnos_in_expr(node: *mut pg_sys::Node, offset: u32) {
    if node.is_null() {
        return;
    }

    let node_tag = (*node).type_;

    match node_tag {
        pg_sys::NodeTag::T_Var => {
            let var = node as *mut pg_sys::Var;
            // Only adjust positive varnos (not INNER_VAR=-1, OUTER_VAR=-2, etc.)
            if (*var).varno > 0 {
                let old_varno = (*var).varno;
                (*var).varno += offset as i32;
                // Also adjust varnosyn if it's positive (varnosyn is u32)
                if (*var).varnosyn > 0 {
                    (*var).varnosyn += offset;
                }
                pgrx::info!(
                    "DEBUG: Adjusting Var.varno from {} to {}",
                    old_varno,
                    (*var).varno
                );
            }
        }
        pg_sys::NodeTag::T_OpExpr => {
            let op = node as *mut pg_sys::OpExpr;
            adjust_varnos_in_list((*op).args, offset);
        }
        pg_sys::NodeTag::T_FuncExpr => {
            let func = node as *mut pg_sys::FuncExpr;
            adjust_varnos_in_list((*func).args, offset);
        }
        pg_sys::NodeTag::T_BoolExpr => {
            let bool_expr = node as *mut pg_sys::BoolExpr;
            adjust_varnos_in_list((*bool_expr).args, offset);
        }
        pg_sys::NodeTag::T_TargetEntry => {
            let te = node as *mut pg_sys::TargetEntry;
            adjust_varnos_in_expr((*te).expr as *mut pg_sys::Node, offset);
        }
        pg_sys::NodeTag::T_Aggref => {
            let aggref = node as *mut pg_sys::Aggref;
            adjust_varnos_in_list((*aggref).args, offset);
            adjust_varnos_in_list((*aggref).aggdirectargs, offset);
            adjust_varnos_in_expr((*aggref).aggfilter as *mut pg_sys::Node, offset);
        }
        pg_sys::NodeTag::T_NullTest => {
            let nt = node as *mut pg_sys::NullTest;
            adjust_varnos_in_expr((*nt).arg as *mut pg_sys::Node, offset);
        }
        pg_sys::NodeTag::T_CoalesceExpr => {
            let ce = node as *mut pg_sys::CoalesceExpr;
            adjust_varnos_in_list((*ce).args, offset);
        }
        pg_sys::NodeTag::T_CaseExpr => {
            let case = node as *mut pg_sys::CaseExpr;
            adjust_varnos_in_expr((*case).arg as *mut pg_sys::Node, offset);
            adjust_varnos_in_list((*case).args, offset);
            adjust_varnos_in_expr((*case).defresult as *mut pg_sys::Node, offset);
        }
        pg_sys::NodeTag::T_CaseWhen => {
            let when = node as *mut pg_sys::CaseWhen;
            adjust_varnos_in_expr((*when).expr as *mut pg_sys::Node, offset);
            adjust_varnos_in_expr((*when).result as *mut pg_sys::Node, offset);
        }
        pg_sys::NodeTag::T_ScalarArrayOpExpr => {
            let saop = node as *mut pg_sys::ScalarArrayOpExpr;
            adjust_varnos_in_list((*saop).args, offset);
        }
        _ => {
            // For other node types, we don't recurse (Const, Param, etc. don't have Vars)
        }
    }
}

/// Adjust varnos in a list of expression nodes.
unsafe fn adjust_varnos_in_list(list: *mut pg_sys::List, offset: u32) {
    if list.is_null() {
        return;
    }

    let length = (*list).length;
    for i in 0..length {
        let node = pg_sys::list_nth(list, i) as *mut pg_sys::Node;
        adjust_varnos_in_expr(node, offset);
    }
}

/// Adjust scanrelid values in a plan tree by adding an offset.
/// This is needed when merging subplan range tables into the main range table.
/// Also adjusts varno values in expressions (targetlist, qual).
unsafe fn adjust_scanrelids_in_plan(plan: *mut pg_sys::Plan, offset: u32) {
    if plan.is_null() {
        return;
    }

    let node_tag = (*plan).type_;

    // Adjust scanrelid for scan nodes
    match node_tag {
        pg_sys::NodeTag::T_SeqScan
        | pg_sys::NodeTag::T_IndexScan
        | pg_sys::NodeTag::T_IndexOnlyScan
        | pg_sys::NodeTag::T_BitmapHeapScan
        | pg_sys::NodeTag::T_TidScan
        | pg_sys::NodeTag::T_ForeignScan
        | pg_sys::NodeTag::T_CustomScan => {
            let scan = plan as *mut pg_sys::Scan;
            if (*scan).scanrelid > 0 {
                pgrx::info!(
                    "DEBUG: Adjusting scanrelid from {} to {}",
                    (*scan).scanrelid,
                    (*scan).scanrelid + offset
                );
                (*scan).scanrelid += offset;
            }
        }
        _ => {}
    }

    // Adjust varno values in targetlist and qual expressions
    adjust_varnos_in_list((*plan).targetlist, offset);
    adjust_varnos_in_list((*plan).qual, offset);

    // Recurse into children
    if !(*plan).lefttree.is_null() {
        adjust_scanrelids_in_plan((*plan).lefttree, offset);
    }
    if !(*plan).righttree.is_null() {
        adjust_scanrelids_in_plan((*plan).righttree, offset);
    }
}

/// Executes a PostgreSQL plan tree from a raw pointer without creating invalid references
/// This is the safe version that avoids memory corruption issues.
pub unsafe fn execute_plan_directly_from_ptr(
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
    expected_tupdesc: Option<*mut pg_sys::TupleDescData>,
    subplans: Vec<crate::plan_translator::expressions::SubplanEntry>,
) -> Result<
    (*mut pg_sys::TupleDescData, *mut pg_sys::Tuplestorestate),
    Box<dyn std::error::Error + Send + Sync>,
> {
    eprintln!("DEBUG: execute_plan_directly_from_ptr ENTRY");
    pgrx::info!("DEBUG: execute_plan_directly_from_ptr ENTRY");

    if plan_tree.is_null() {
        return Err("Plan tree pointer is null".into());
    }

    eprintln!("DEBUG: Calling execute_plan_directly_raw with raw pointers");
    pgrx::info!("DEBUG: Calling execute_plan_directly_raw with raw pointers");

    let result = execute_plan_directly_raw(
        plan_tree,
        column_names,
        range_table,
        expected_tupdesc,
        subplans,
    );

    eprintln!("DEBUG: execute_plan_directly_raw returned");
    pgrx::info!("DEBUG: execute_plan_directly_raw returned");

    result
}

/// Raw pointer version that avoids creating invalid references
/// This is the safest approach for PostgreSQL plan tree execution.
pub unsafe fn execute_plan_directly_raw(
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
    _expected_tupdesc: Option<*mut pg_sys::TupleDescData>,
    subplans: Vec<crate::plan_translator::expressions::SubplanEntry>,
) -> Result<
    (*mut pg_sys::TupleDescData, *mut pg_sys::Tuplestorestate),
    Box<dyn std::error::Error + Send + Sync>,
> {
    pgrx::info!("DEBUG: execute_plan_directly_raw ENTRY");
    pgrx::info!(
        "DEBUG: execute_plan_directly_raw: plan_tree={:p}, column_names={:?}, range_table={:p}",
        plan_tree,
        column_names,
        range_table
    );

    if plan_tree.is_null() {
        return Err("Plan tree pointer is null".into());
    }

    pgrx::info!("DEBUG: plan_tree pointer is valid: {:p}", plan_tree);

    // Check memory context - plan might be in wrong context
    let current_context = pg_sys::CurrentMemoryContext;
    pgrx::info!("DEBUG: Current memory context: {:p}", current_context);

    // Try to validate the plan tree pointer before dereferencing
    pgrx::info!("DEBUG: About to access plan_tree.type_");

    // Use a more careful approach to access the plan tree
    let plan_type = (*plan_tree).type_;
    pgrx::info!("DEBUG: Successfully accessed plan_type: {:?}", plan_type);

    let targetlist = (*plan_tree).targetlist;
    pgrx::info!("DEBUG: Successfully accessed targetlist: {:p}", targetlist);

    pgrx::info!("DEBUG: About to call ExecTypeFromTL");

    // Get the tuple descriptor from the plan's target list
    let temp_tupdesc = pg_sys::ExecTypeFromTL(targetlist);
    pgrx::info!("DEBUG: ExecTypeFromTL returned tupdesc: {:p}", temp_tupdesc);
    if temp_tupdesc.is_null() {
        return Err("Failed to create tuple descriptor from plan".into());
    }

    // Create a copy of the tuple descriptor to avoid memory corruption
    let tupdesc = pg_sys::CreateTupleDescCopy(temp_tupdesc);
    pgrx::info!("DEBUG: Created tuple descriptor copy: {:p}", tupdesc);

    // Free the temporary tuple descriptor to prevent memory leaks
    pg_sys::FreeTupleDesc(temp_tupdesc);
    pgrx::info!("DEBUG: Freed temporary tuple descriptor");

    if tupdesc.is_null() {
        return Err("Failed to copy tuple descriptor".into());
    }

    // Debug the tuple descriptor attributes to see what type OIDs were created
    let natts = (*tupdesc).natts;
    pgrx::info!("DEBUG: Tuple descriptor has {} attributes", natts);
    for i in 0..natts as usize {
        let attr = (*tupdesc).attrs.as_ptr().add(i);
        pgrx::info!(
            "DEBUG: Attribute {}: typid={}, typmod={}, attlen={}",
            i,
            (*attr).atttypid.to_u32(),
            (*attr).atttypmod,
            (*attr).attlen
        );
    }

    // Update column names in the tuple descriptor
    let natts = (*tupdesc).natts;
    for i in 0..natts as usize {
        if i < column_names.len() {
            let attr = (*tupdesc).attrs.as_mut_ptr().add(i);
            // Update the attribute name (carefully to avoid buffer overflow)
            let name_data = (*attr).attname.data.as_mut_ptr();
            let src_len = std::cmp::min(column_names[i].len(), (pg_sys::NAMEDATALEN - 1) as usize);
            std::ptr::copy_nonoverlapping(column_names[i].as_ptr(), name_data as *mut u8, src_len);
            *name_data.add(src_len) = 0; // null terminate
        }
    }
    pgrx::info!("DEBUG: Updated column names in tupdesc");

    // Create a tuplestore to collect results
    let tuplestore = pg_sys::tuplestore_begin_heap(true, false, pg_sys::work_mem);
    if tuplestore.is_null() {
        return Err("Failed to create tuplestore".into());
    }
    pgrx::info!("DEBUG: Tuplestore created: {:p}", tuplestore);

    // SURPRISE FIX: Use PostgreSQL's complete executor startup sequence
    pgrx::info!("DEBUG: Implementing surprise fix with ExecutorStart pattern");

    // Ensure we have a valid transaction state and snapshot
    if !pg_sys::IsTransactionState() {
        pgrx::info!("DEBUG: No transaction state - this might cause ExecutorStart to fail");
    }

    // Create a minimal QueryDesc that PostgreSQL's executor expects
    let query_desc = pgrx::PgBox::<pg_sys::QueryDesc>::alloc0();
    let query_desc_ptr = query_desc.into_pg();
    pgrx::info!("DEBUG: QueryDesc allocated: {:p}", query_desc_ptr);

    // Create a minimal PlannedStmt wrapper
    let mut planned_stmt = pgrx::PgBox::<pg_sys::PlannedStmt>::alloc0();
    planned_stmt.type_ = pg_sys::NodeTag::T_PlannedStmt;
    planned_stmt.planTree = plan_tree;
    planned_stmt.rtable = range_table as *mut pg_sys::List;
    planned_stmt.permInfos = std::ptr::null_mut(); // Empty permission info list - we bypass checks
    planned_stmt.commandType = pg_sys::CmdType::CMD_SELECT;
    planned_stmt.canSetTag = true; // Important for SELECT queries
    planned_stmt.utilityStmt = std::ptr::null_mut();
    planned_stmt.stmt_location = 0;
    planned_stmt.stmt_len = 0;

    // Convert subplans vec to pg_sys::List and merge range tables
    if !subplans.is_empty() {
        eprintln!(
            "DEBUG: execute_plan_directly_raw - Adding {} subplans to PlannedStmt",
            subplans.len()
        );
        pgrx::info!(
            "DEBUG: execute_plan_directly_raw - Adding {} subplans to PlannedStmt",
            subplans.len()
        );

        // Get the current length of the main range table
        let _main_rt_len = if range_table.is_null() {
            0
        } else {
            (*range_table).length
        };

        let mut subplan_list: *mut pg_sys::List = std::ptr::null_mut();
        let mut merged_range_table = range_table as *mut pg_sys::List;

        for (i, subplan_entry) in subplans.iter().enumerate() {
            eprintln!("DEBUG: Adding subplan {} at {:p}", i, subplan_entry.plan);

            // Merge subplan's range table into main range table and adjust scanrelids
            if !subplan_entry.range_table.is_null() {
                let subplan_rt = subplan_entry.range_table;
                let subplan_rt_len = (*subplan_rt).length;
                eprintln!(
                    "DEBUG: Subplan {} has {} range table entries",
                    i, subplan_rt_len
                );

                // Calculate offset for this subplan's range table entries
                let offset = if merged_range_table.is_null() {
                    0
                } else {
                    (*merged_range_table).length
                };

                // Append subplan's range table entries to merged range table
                for j in 0..subplan_rt_len {
                    let rte = pg_sys::list_nth(subplan_rt, j) as *mut pg_sys::RangeTblEntry;
                    merged_range_table =
                        pg_sys::lappend(merged_range_table, rte as *mut std::ffi::c_void);
                }

                // Adjust scanrelid values in the subplan's plan tree
                if offset > 0 {
                    adjust_scanrelids_in_plan(subplan_entry.plan, offset as u32);
                }
            }

            subplan_list =
                pg_sys::lappend(subplan_list, subplan_entry.plan as *mut std::ffi::c_void);
        }

        planned_stmt.subplans = subplan_list;
        planned_stmt.rtable = merged_range_table;

        // Debug: Verify the subplan list is properly set
        let subplan_count = if subplan_list.is_null() {
            0
        } else {
            (*subplan_list).length
        };
        let merged_rt_count = if merged_range_table.is_null() {
            0
        } else {
            (*merged_range_table).length
        };
        pgrx::info!(
            "DEBUG: PlannedStmt.subplans list has {} entries, merged rtable has {} entries",
            subplan_count,
            merged_rt_count
        );
        if subplan_count > 0 {
            let first_subplan_ptr = pg_sys::list_nth(subplan_list, 0) as *mut pg_sys::Plan;
            pgrx::info!(
                "DEBUG: First subplan in list at {:p}, type={:?}",
                first_subplan_ptr,
                (*first_subplan_ptr).type_
            );

            // Walk the subplan tree to check scanrelid values
            fn check_scanrelids(plan: *mut pg_sys::Plan, depth: i32, rt_size: i32) {
                unsafe {
                    if plan.is_null() {
                        return;
                    }
                    let node_type = (*plan).type_;
                    match node_type {
                        pg_sys::NodeTag::T_SeqScan | pg_sys::NodeTag::T_IndexScan => {
                            let scan = plan as *mut pg_sys::Scan;
                            let scanrelid = (*scan).scanrelid;
                            if scanrelid as i32 > rt_size || scanrelid == 0 {
                                pgrx::warning!(
                                    "SUBPLAN ISSUE: scanrelid {} out of range (rt_size={})",
                                    scanrelid,
                                    rt_size
                                );
                            } else {
                                pgrx::info!(
                                    "DEBUG: SUBPLAN depth={} {:?} scanrelid={}",
                                    depth,
                                    node_type,
                                    scanrelid
                                );
                            }
                        }
                        _ => {
                            pgrx::info!("DEBUG: SUBPLAN depth={} {:?}", depth, node_type);
                        }
                    }
                    check_scanrelids((*plan).lefttree, depth + 1, rt_size);
                    check_scanrelids((*plan).righttree, depth + 1, rt_size);
                }
            }
            check_scanrelids(first_subplan_ptr, 0, merged_rt_count);
        }
    } else {
        planned_stmt.subplans = std::ptr::null_mut();
    }

    let planned_stmt_ptr = planned_stmt.into_pg();
    pgrx::info!("DEBUG: PlannedStmt created: {:p}", planned_stmt_ptr);

    // Set up the QueryDesc using the raw pointer
    (*query_desc_ptr).operation = pg_sys::CmdType::CMD_SELECT;
    (*query_desc_ptr).plannedstmt = planned_stmt_ptr;
    (*query_desc_ptr).sourceText = std::ptr::null_mut();

    // Get snapshot - if none exists, get a new one
    let snapshot = pg_sys::GetActiveSnapshot();
    if snapshot.is_null() {
        pgrx::info!("DEBUG: No active snapshot, registering a new one");
        pg_sys::PushActiveSnapshot(pg_sys::GetTransactionSnapshot());
    }
    (*query_desc_ptr).snapshot = pg_sys::GetActiveSnapshot();

    (*query_desc_ptr).crosscheck_snapshot = std::ptr::null_mut();
    (*query_desc_ptr).dest = std::ptr::null_mut();
    (*query_desc_ptr).params = std::ptr::null_mut();
    (*query_desc_ptr).queryEnv = std::ptr::null_mut();
    (*query_desc_ptr).instrument_options = 0;
    pgrx::info!("DEBUG: QueryDesc setup complete");

    pgrx::info!("DEBUG: Skipping ExecutorStart, manually initializing instead");

    // Instead of ExecutorStart, manually set up the estate and call ExecInitNode
    let estate = pg_sys::CreateExecutorState();
    if estate.is_null() {
        return Err("Failed to create executor state".into());
    }

    // Use ExecInitRangeTable to properly initialize range table and related arrays.
    // IMPORTANT: Use the range table from planned_stmt, which includes merged subplan RTEs
    // Pass empty permInfos list - we bypass permission checks for Substrait plans.
    let empty_perminfos: *mut pg_sys::List = std::ptr::null_mut();
    let actual_range_table = (*planned_stmt_ptr).rtable;

    // Debug the range table before passing it
    let rt_len = if actual_range_table.is_null() {
        0
    } else {
        (*actual_range_table).length
    };
    pgrx::info!(
        "DEBUG: Range table length before ExecInitRangeTable: {}",
        rt_len
    );

    // If range table exists, debug its contents
    if !actual_range_table.is_null() && rt_len > 0 {
        let rte_ptr = pg_sys::list_nth(actual_range_table, 0);
        let rte = rte_ptr as *mut pg_sys::RangeTblEntry;
        if !rte.is_null() {
            pgrx::info!(
                "DEBUG: RTE[0]: type_={:?}, rtekind={:?}, relid={}",
                (*rte).type_,
                (*rte).rtekind,
                (*rte).relid
            );
        }
    }
    pg_sys::ExecInitRangeTable(estate, actual_range_table, empty_perminfos);
    pgrx::info!("DEBUG: ExecInitRangeTable completed");

    // Debug estate fields after ExecInitRangeTable
    pgrx::info!(
        "DEBUG: After ExecInitRangeTable: es_range_table_size={} es_relations={:p}",
        (*estate).es_range_table_size,
        (*estate).es_relations
    );

    // Open all tables in the MERGED range table before execution.
    // This includes both main plan tables and subplan tables.
    // Store the relation handles in es_relations for scan nodes to use.
    if !actual_range_table.is_null() {
        let rt_list = actual_range_table;
        pgrx::info!(
            "DEBUG: Opening {} relations from merged range table",
            (*rt_list).length
        );
        for i in 0..(*rt_list).length {
            let rte_ptr = pg_sys::list_nth(rt_list, i);
            let rte = rte_ptr as *mut pg_sys::RangeTblEntry;
            if !rte.is_null() && (*rte).rtekind == pg_sys::RTEKind::RTE_RELATION {
                pgrx::info!(
                    "DEBUG: Opening relation OID {} (RTE #{}) with AccessShareLock",
                    (*rte).relid,
                    i + 1
                );
                // Open the relation and store it in es_relations
                let rel = pg_sys::table_open((*rte).relid, pg_sys::AccessShareLock as i32);
                pgrx::info!("DEBUG: Relation opened: {:p}", rel);
                // Store in es_relations at 0-based index
                *(*estate).es_relations.offset(i as isize) = rel;
            }
        }
    }

    // Set the planned statement reference on estate.
    (*estate).es_plannedstmt = planned_stmt_ptr;

    // IMPORTANT: Set EState fields BEFORE subplan initialization - ExecInitNode needs these!
    (*estate).es_output_cid = 0;
    (*estate).es_snapshot = (*query_desc_ptr).snapshot;
    (*estate).es_crosscheck_snapshot = (*query_desc_ptr).crosscheck_snapshot;
    (*estate).es_instrument = 0;
    (*estate).es_top_eflags = 0;
    (*estate).es_processed = 0;
    pgrx::info!(
        "DEBUG: Set EState fields before subplan init, es_snapshot={:p}",
        (*estate).es_snapshot
    );

    // Initialize es_param_exec_vals BEFORE subplans - they may need it during initialization.
    // PostgreSQL 17 uses paramExecTypes (List) instead of nParamExec (int)
    {
        let param_exec_types = (*planned_stmt_ptr).paramExecTypes;
        let n_param_exec = if !param_exec_types.is_null() {
            (*param_exec_types).length as usize
        } else {
            0
        };
        if n_param_exec > 0 {
            let param_exec_size = n_param_exec * std::mem::size_of::<pg_sys::ParamExecData>();
            (*estate).es_param_exec_vals =
                pg_sys::palloc0(param_exec_size) as *mut pg_sys::ParamExecData;
            pgrx::info!(
                "DEBUG: Allocated es_param_exec_vals for {} params (before subplans)",
                n_param_exec
            );
        } else {
            // Even with 0 params, allocate a minimal array to avoid NULL pointer issues
            (*estate).es_param_exec_vals =
                pg_sys::palloc0(std::mem::size_of::<pg_sys::ParamExecData>())
                    as *mut pg_sys::ParamExecData;
            pgrx::info!("DEBUG: Allocated minimal es_param_exec_vals (paramExecTypes empty/null)");
        }
    }

    // Initialize es_subplanstates by pre-initializing all subplans.
    // This is critical: PostgreSQL's ExecInitSubPlan expects the subplan's PlanState
    // to already exist in es_subplanstates when it encounters a SubPlan expression.
    // This mimics the InitPlan() function in PostgreSQL's execMain.c.
    let subplan_list = (*planned_stmt_ptr).subplans;
    if !subplan_list.is_null() && (*subplan_list).length > 0 {
        let num_subplans = (*subplan_list).length;
        pgrx::info!(
            "DEBUG: Pre-initializing {} subplans before main plan",
            num_subplans
        );

        // Initialize es_subplanstates as empty list first
        (*estate).es_subplanstates = std::ptr::null_mut();

        // Initialize each subplan and add its PlanState to es_subplanstates
        for i in 0..num_subplans {
            let subplan_ptr = pg_sys::list_nth(subplan_list, i) as *mut pg_sys::Plan;
            pgrx::info!(
                "DEBUG: Initializing subplan {} at {:p}, type={:?}",
                i,
                subplan_ptr,
                (*subplan_ptr).type_
            );

            // Debug the subplan tree
            debug_dump_plan_tree(subplan_ptr, 0);

            // Debug: Check es_relations array before init
            pgrx::info!(
                "DEBUG: es_relations={:p}, es_range_table_size={}",
                (*estate).es_relations,
                (*estate).es_range_table_size
            );
            if !(*estate).es_relations.is_null() {
                for rel_idx in 0..(*estate).es_range_table_size.min(10) as isize {
                    let rel = *(*estate).es_relations.offset(rel_idx);
                    pgrx::info!("DEBUG: es_relations[{}]={:p}", rel_idx, rel);
                }
            }

            // Debug: Dump Agg targetlist if this is an Agg node
            if (*subplan_ptr).type_ == pg_sys::NodeTag::T_Agg {
                let agg = subplan_ptr as *mut pg_sys::Agg;
                let tl = (*agg).plan.targetlist;
                if !tl.is_null() {
                    pgrx::info!("DEBUG: Agg targetlist has {} entries", (*tl).length);
                    for te_idx in 0..(*tl).length {
                        let te = pg_sys::list_nth(tl, te_idx) as *mut pg_sys::TargetEntry;
                        if !te.is_null() && !(*te).expr.is_null() {
                            let expr_type = (*(*te).expr).type_;
                            pgrx::info!(
                                "DEBUG: Agg targetlist[{}]: resno={} expr_type={:?}",
                                te_idx,
                                (*te).resno,
                                expr_type
                            );
                            if expr_type == pg_sys::NodeTag::T_Aggref {
                                let aggref = (*te).expr as *mut pg_sys::Aggref;
                                pgrx::info!(
                                    "DEBUG:   Aggref: aggfnoid={} aggtype={} aggtranstype={}",
                                    (*aggref).aggfnoid.to_u32(),
                                    (*aggref).aggtype.to_u32(),
                                    (*aggref).aggtranstype.to_u32()
                                );
                                pgrx::info!("DEBUG:   Aggref: aggstar={} aggsplit={:?} aggno={} aggtransno={}",
                                    (*aggref).aggstar, (*aggref).aggsplit, (*aggref).aggno, (*aggref).aggtransno);
                                if !(*aggref).args.is_null() {
                                    let args_count = (*(*aggref).args).length;
                                    pgrx::info!("DEBUG:   Aggref args count={}", args_count);
                                    // Dump each arg
                                    for arg_idx in 0..args_count {
                                        let arg = pg_sys::list_nth((*aggref).args, arg_idx)
                                            as *mut pg_sys::TargetEntry;
                                        if !arg.is_null() {
                                            pgrx::info!(
                                                "DEBUG:   Aggref arg[{}]: TargetEntry resno={}",
                                                arg_idx,
                                                (*arg).resno
                                            );
                                            if !(*arg).expr.is_null() {
                                                let expr_type = (*(*arg).expr).type_;
                                                pgrx::info!(
                                                    "DEBUG:   Aggref arg[{}] expr type={:?}",
                                                    arg_idx,
                                                    expr_type
                                                );
                                                if expr_type == pg_sys::NodeTag::T_Var {
                                                    let var = (*arg).expr as *mut pg_sys::Var;
                                                    pgrx::info!("DEBUG:   Var: varno={} varattno={} vartype={}",
                                                        (*var).varno, (*var).varattno, (*var).vartype.to_u32());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Verify subplan structure with nodeToString before ExecInitNode
            pgrx::info!("DEBUG: Verifying subplan {} with nodeToString", i);
            let plan_str = pg_sys::nodeToString(subplan_ptr as *const std::ffi::c_void);
            if plan_str.is_null() {
                pgrx::warning!("DEBUG: nodeToString returned NULL for subplan {}", i);
            } else {
                let plan_str_len = std::ffi::CStr::from_ptr(plan_str).to_bytes().len();
                pgrx::info!(
                    "DEBUG: nodeToString succeeded for subplan {}, length={}",
                    i,
                    plan_str_len
                );
                pg_sys::pfree(plan_str as *mut std::ffi::c_void);
            }

            // Check Aggref.aggargtypes if this is an Agg node
            if (*subplan_ptr).type_ == pg_sys::NodeTag::T_Agg {
                let agg = subplan_ptr as *mut pg_sys::Agg;
                let tl = (*agg).plan.targetlist;
                if !tl.is_null() && (*tl).length > 0 {
                    let te = pg_sys::list_nth(tl, 0) as *mut pg_sys::TargetEntry;
                    if !te.is_null() && !(*te).expr.is_null() {
                        let expr_type = (*(*te).expr).type_;
                        if expr_type == pg_sys::NodeTag::T_Aggref {
                            let aggref = (*te).expr as *mut pg_sys::Aggref;
                            let aggargtypes = (*aggref).aggargtypes;
                            if aggargtypes.is_null() {
                                pgrx::info!("DEBUG: Aggref.aggargtypes is NULL");
                            } else {
                                pgrx::info!(
                                    "DEBUG: Aggref.aggargtypes has {} entries",
                                    (*aggargtypes).length
                                );
                                for oid_idx in 0..(*aggargtypes).length {
                                    let oid_val = pg_sys::list_nth_oid(aggargtypes, oid_idx);
                                    pgrx::info!("DEBUG: aggargtypes[{}] = {}", oid_idx, oid_val);
                                }
                            }
                        }
                    }
                }
            }

            // Debug: Walk the plan tree and dump all qual expressions
            fn dump_all_quals(plan: *mut pg_sys::Plan, depth: i32) {
                unsafe {
                    if plan.is_null() {
                        return;
                    }
                    let node_type = (*plan).type_;
                    pgrx::info!("QUAL_DUMP depth={} {:?}", depth, node_type);
                    // Dump targetlist too
                    if !(*plan).targetlist.is_null() {
                        let tl = (*plan).targetlist;
                        pgrx::info!("TL_DUMP: targetlist len={}", (*tl).length);
                        for idx in 0..(*tl).length.min(5) {
                            let te = pg_sys::list_nth(tl, idx) as *mut pg_sys::TargetEntry;
                            if !te.is_null() {
                                pgrx::info!("TL_DUMP[{}]: resno={}", idx, (*te).resno);
                                debug_dump_expr(
                                    (*te).expr as *mut pg_sys::Node,
                                    (depth + 2) as usize,
                                );
                            }
                        }
                    }
                    if !(*plan).qual.is_null() {
                        let qual = (*plan).qual;
                        pgrx::info!("QUAL_DUMP: qual list at {:p} len={}", qual, (*qual).length);
                        for idx in 0..(*qual).length {
                            let node = pg_sys::list_nth(qual, idx) as *mut pg_sys::Node;
                            debug_dump_expr(node, (depth + 1) as usize);
                        }
                    }
                    // For Result nodes, also check resconstantqual
                    if node_type == pg_sys::NodeTag::T_Result {
                        let result = plan as *mut pg_sys::Result;
                        if !(*result).resconstantqual.is_null() {
                            pgrx::info!(
                                "QUAL_DUMP: Result.resconstantqual at {:p}",
                                (*result).resconstantqual
                            );
                            debug_dump_expr((*result).resconstantqual, (depth + 1) as usize);
                        }
                    }
                    dump_all_quals((*plan).lefttree, depth + 1);
                    dump_all_quals((*plan).righttree, depth + 1);
                }
            }
            pgrx::info!(
                "DEBUG: Dumping all quals in subplan {} before ExecInitNode",
                i
            );
            dump_all_quals(subplan_ptr, 0);

            // Initialize the subplan with ExecInitNode
            pgrx::info!("DEBUG: About to call ExecInitNode for subplan {}", i);
            let subplan_state = pg_sys::ExecInitNode(subplan_ptr, estate, 0);
            pgrx::info!(
                "DEBUG: Subplan {} initialized, PlanState={:p}",
                i,
                subplan_state
            );

            if subplan_state.is_null() {
                pgrx::warning!("DEBUG: Subplan {} failed to initialize!", i);
            }

            // Append the PlanState to es_subplanstates
            (*estate).es_subplanstates = pg_sys::lappend(
                (*estate).es_subplanstates,
                subplan_state as *mut std::ffi::c_void,
            );
        }

        pgrx::info!("DEBUG: All {} subplans initialized", num_subplans);
    } else {
        (*estate).es_subplanstates = std::ptr::null_mut();
    }

    // Note: es_output_cid, es_snapshot, etc. are initialized earlier, before subplan initialization

    (*query_desc_ptr).estate = estate;

    pgrx::info!(
        "DEBUG: About to call ExecInitNode with plan_tree={:p}, estate={:p}",
        plan_tree,
        estate
    );

    // Verify es_subplanstates before main plan init
    let subplan_states = (*estate).es_subplanstates;
    if !subplan_states.is_null() {
        let n_states = (*subplan_states).length;
        pgrx::info!("DEBUG: es_subplanstates has {} entries", n_states);
        for i in 0..n_states {
            let ps = pg_sys::list_nth(subplan_states, i) as *mut pg_sys::PlanState;
            pgrx::info!(
                "DEBUG:   es_subplanstates[{}] = {:p}, type={:?}",
                i,
                ps,
                if !ps.is_null() {
                    (*ps).type_
                } else {
                    pg_sys::NodeTag::T_Invalid
                }
            );
        }
    } else {
        pgrx::info!("DEBUG: es_subplanstates is NULL");
    }

    // Debug: dump plan tree structure before ExecInitNode
    debug_dump_plan_tree(plan_tree, 0);

    // Final verification - check es_relations array
    pgrx::info!("DEBUG: Final verification before ExecInitNode:");
    pgrx::info!(
        "DEBUG:   es_range_table_size={}",
        (*estate).es_range_table_size
    );
    for i in 0..(*estate).es_range_table_size as isize {
        let rel = *(*estate).es_relations.offset(i);
        pgrx::info!("DEBUG:   es_relations[{}]={:p}", i, rel);
    }

    pgrx::info!("DEBUG: Calling ExecInitNode NOW for main plan...");

    // Now initialize the main plan node (subplans already initialized above)
    let plan_state = pg_sys::ExecInitNode(plan_tree, estate, 0);

    pgrx::info!(
        "DEBUG: ExecInitNode returned successfully: {:p}",
        plan_state
    );

    if plan_state.is_null() {
        return Err("ExecInitNode failed".into());
    }

    // Debug: Walk plan state tree to verify qual initialization on each node
    fn debug_dump_plan_state(ps: *mut pg_sys::PlanState, depth: i32) {
        unsafe {
            if ps.is_null() {
                return;
            }
            let indent = "  ".repeat(depth as usize);
            let node_type = (*ps).type_;
            let qual_ptr = (*ps).qual;
            pgrx::info!(
                "{}PLANSTATE: type={:?} qual={:p}",
                indent,
                node_type,
                qual_ptr
            );

            // Check if this is a Result node and dump additional info
            if node_type == pg_sys::NodeTag::T_ResultState {
                let result_state = ps as *mut pg_sys::ResultState;
                pgrx::info!(
                    "{}  ResultState: resconstantqual={:p} rs_checkqual={}",
                    indent,
                    (*result_state).resconstantqual,
                    (*result_state).rs_checkqual
                );
            }

            // Check the plan node's qual (different from the initialized ExprState qual)
            let plan = (*ps).plan;
            if !plan.is_null() {
                let plan_qual = (*plan).qual;
                pgrx::info!(
                    "{}  Plan.qual={:p} (len={})",
                    indent,
                    plan_qual,
                    if plan_qual.is_null() {
                        0
                    } else {
                        (*plan_qual).length
                    }
                );
            }

            // Recurse to children
            if !(*ps).lefttree.is_null() {
                debug_dump_plan_state((*ps).lefttree, depth + 1);
            }
            if !(*ps).righttree.is_null() {
                debug_dump_plan_state((*ps).righttree, depth + 1);
            }
        }
    }

    pgrx::info!("DEBUG: Dumping PlanState tree after ExecInitNode:");
    debug_dump_plan_state(plan_state, 0);

    (*query_desc_ptr).planstate = plan_state;

    pgrx::info!("DEBUG: Manual initialization succeeded (execute_plan_directly_raw)!");

    // Get the plan state - we called ExecInitNode above.
    let plan_state = (*query_desc_ptr).planstate;
    if plan_state.is_null() {
        // Manual cleanup since we bypassed ExecutorStart
        pg_sys::FreeExecutorState(estate);
        return Err("ExecInitNode failed to create plan state".into());
    }

    pgrx::info!("DEBUG: Plan state from ExecInitNode: {:p}", plan_state);

    // Debug SortState details if this is a Sort node
    if (*plan_state).type_ == pg_sys::NodeTag::T_SortState {
        let sort_state = plan_state as *mut pg_sys::SortState;
        pgrx::info!("DEBUG: SortState details before execution:");
        pgrx::info!(
            "DEBUG:   ss_ScanTupleSlot={:p}",
            (*sort_state).ss.ss_ScanTupleSlot
        );
        pgrx::info!(
            "DEBUG:   ps_ResultTupleSlot={:p}",
            (*sort_state).ss.ps.ps_ResultTupleSlot
        );
        pgrx::info!(
            "DEBUG:   lefttree (child state)={:p}",
            (*sort_state).ss.ps.lefttree
        );
        pgrx::info!("DEBUG:   plan={:p}", (*sort_state).ss.ps.plan);
        pgrx::info!(
            "DEBUG:   tuplesortstate={:p}",
            (*sort_state).tuplesortstate as *const std::ffi::c_void
        );
        pgrx::info!("DEBUG:   randomAccess={}", (*sort_state).randomAccess);
        pgrx::info!("DEBUG:   bounded={}", (*sort_state).bounded);
        pgrx::info!("DEBUG:   bound={}", (*sort_state).bound);
        pgrx::info!("DEBUG:   sort_Done={}", (*sort_state).sort_Done);
        pgrx::info!("DEBUG:   bounded_Done={}", (*sort_state).bounded_Done);
        pgrx::info!("DEBUG:   bound_Done={}", (*sort_state).bound_Done);
        // Check the child plan state
        let child_state = (*sort_state).ss.ps.lefttree;
        if !child_state.is_null() {
            pgrx::info!("DEBUG:   child state type={:?}", (*child_state).type_);
        }

        // Check the ScanTupleSlot's TupleDesc
        let scan_slot = (*sort_state).ss.ss_ScanTupleSlot;
        if !scan_slot.is_null() {
            let scan_tupdesc = (*scan_slot).tts_tupleDescriptor;
            pgrx::info!(
                "DEBUG:   ss_ScanTupleSlot.tts_tupleDescriptor={:p}",
                scan_tupdesc
            );
            if !scan_tupdesc.is_null() {
                pgrx::info!(
                    "DEBUG:   ss_ScanTupleSlot TupleDesc natts={}",
                    (*scan_tupdesc).natts
                );
            }
        }

        // Check ps_ResultTupleSlot's TupleDesc
        let result_slot = (*sort_state).ss.ps.ps_ResultTupleSlot;
        if !result_slot.is_null() {
            let result_tupdesc = (*result_slot).tts_tupleDescriptor;
            pgrx::info!(
                "DEBUG:   ps_ResultTupleSlot.tts_tupleDescriptor={:p}",
                result_tupdesc
            );
            if !result_tupdesc.is_null() {
                pgrx::info!(
                    "DEBUG:   ps_ResultTupleSlot TupleDesc natts={}",
                    (*result_tupdesc).natts
                );
            }
        }

        // Check the Sort plan's targetlist
        let sort_plan = (*sort_state).ss.ps.plan as *mut pg_sys::Sort;
        let targetlist = (*sort_plan).plan.targetlist;
        pgrx::info!("DEBUG:   Sort plan targetlist={:p}", targetlist);
        if !targetlist.is_null() {
            let list_len = (*targetlist).length;
            pgrx::info!("DEBUG:   Sort plan targetlist length={}", list_len);

            // Examine first few target entries
            for i in 0..list_len.min(5) {
                let te = pg_sys::list_nth(targetlist, i) as *mut pg_sys::TargetEntry;
                if !te.is_null() {
                    let expr = (*te).expr;
                    let resno = (*te).resno;
                    let resname = (*te).resname;
                    pgrx::info!(
                        "DEBUG:   TargetEntry[{}]: resno={}, expr={:p}, expr.type={:?}",
                        i,
                        resno,
                        expr,
                        if !expr.is_null() {
                            (*expr).type_
                        } else {
                            pg_sys::NodeTag::T_Invalid
                        }
                    );
                    if !resname.is_null() {
                        let name_str = std::ffi::CStr::from_ptr(resname).to_string_lossy();
                        pgrx::info!("DEBUG:     resname={}", name_str);
                    }
                    // Check if expression is a Var and dump its details
                    if !expr.is_null() && (*expr).type_ == pg_sys::NodeTag::T_Var {
                        let var = expr as *mut pg_sys::Var;
                        pgrx::info!(
                            "DEBUG:     Var: varno={} varattno={} vartype={}",
                            (*var).varno,
                            (*var).varattno,
                            (*var).vartype.to_u32()
                        );
                    }
                }
            }
        }
    }

    // Execute the plan and collect tuples into tuplestore with error handling
    let mut tuple_count = 0u64;

    loop {
        pgrx::info!("DEBUG: Calling ExecProcNode (tuple_count: {})", tuple_count);
        // Use PostgreSQL's PG_TRY/PG_CATCH mechanism for error handling
        let slot = pg_sys::ExecProcNode(plan_state);
        pgrx::info!("DEBUG: ExecProcNode returned slot: {:p}", slot);
        if slot.is_null() {
            break; // No more tuples
        }

        // Check if slot is empty (TTS_EMPTY macro: slot == NULL || TTS_EMPTY(slot))
        // TTS_EMPTY checks if tts_flags has TTS_FLAG_EMPTY set.
        if (*slot).tts_flags & pg_sys::TTS_FLAG_EMPTY as u16 != 0 {
            pgrx::info!("DEBUG: Slot is empty (TTS_EMPTY), ending loop");
            break;
        }

        // Materialize the slot if needed (handles virtual slots).
        // This ensures the slot contains a physical tuple that can be stored.
        pgrx::info!("DEBUG: Materializing slot before storing");
        pg_sys::ExecMaterializeSlot(slot);

        // Store tuple directly in tuplestore
        pg_sys::tuplestore_puttupleslot(tuplestore, slot);
        pgrx::info!("DEBUG: Tuple stored in tuplestore");
        tuple_count += 1;

        // Prevent infinite loops and excessive memory usage
        if tuple_count > 1000000 {
            pgrx::warning!("Query returned too many rows (> 1M), execution aborted");
            // Manual cleanup since we bypassed ExecutorStart
            pg_sys::ExecEndNode(plan_state);
            pg_sys::FreeExecutorState(estate);
            return Err("Query returned too many rows (> 1M), execution aborted".into());
        }
    }
    pgrx::info!(
        "DEBUG: ExecProcNode loop finished. Total tuples: {}",
        tuple_count
    );

    // Clean up manually since we bypassed ExecutorStart.
    // ExecutorFinish/ExecutorEnd expect structures set up by ExecutorStart.
    pgrx::info!("DEBUG: Cleaning up with manual ExecEndNode and FreeExecutorState");
    pg_sys::ExecEndNode(plan_state);
    pg_sys::FreeExecutorState(estate);
    pgrx::info!("DEBUG: Manual cleanup completed");

    Ok((tupdesc, tuplestore))
}

/// Executes a PostgreSQL plan tree using PostgreSQL's native executor
/// and returns the tuple descriptor and tuplestore directly.
/// This is the simplified approach that minimizes unpacking/packing operations.
pub unsafe fn execute_plan_directly(
    plan_tree_ref: &pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
    expected_tupdesc: Option<*mut pg_sys::TupleDescData>,
    subplans: Vec<crate::plan_translator::expressions::SubplanEntry>,
) -> Result<
    (*mut pg_sys::TupleDescData, *mut pg_sys::Tuplestorestate),
    Box<dyn std::error::Error + Send + Sync>,
> {
    eprintln!("DEBUG: execute_plan_directly delegating to execute_plan_directly_raw");
    pgrx::info!("DEBUG: execute_plan_directly delegating to execute_plan_directly_raw");

    // Convert reference to pointer and delegate to the raw version
    let plan_tree = plan_tree_ref as *const pg_sys::Plan as *mut pg_sys::Plan;

    execute_plan_directly_raw(
        plan_tree,
        column_names,
        range_table,
        expected_tupdesc,
        subplans,
    )
}

/// Old execute_plan_directly implementation - keeping for reference but not used
#[allow(dead_code)]
unsafe fn _execute_plan_directly_old(
    plan_tree_ref: &pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
    expected_tupdesc: Option<*mut pg_sys::TupleDescData>,
    subplans: Vec<crate::plan_translator::expressions::SubplanEntry>,
) -> Result<
    (*mut pg_sys::TupleDescData, *mut pg_sys::Tuplestorestate),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // IMMEDIATE ENTRY DEBUG - BEFORE ACCESSING PARAMETERS
    eprintln!("IMMEDIATE: execute_plan_directly ENTERED SUCCESSFULLY");
    pgrx::info!("IMMEDIATE: execute_plan_directly ENTERED SUCCESSFULLY");

    // Convert reference to pointer for use throughout the function
    let plan_tree = plan_tree_ref as *const pg_sys::Plan as *mut pg_sys::Plan;

    eprintln!(
        "DEBUG: execute_plan_directly called with plan tree type: {:?}",
        plan_tree_ref.type_
    );
    pgrx::info!("CRITICAL: execute_plan_directly ENTRY - THIS SHOULD APPEAR IN LOGS");

    eprintln!("DEBUG: About to access plan_tree.targetlist");
    pgrx::info!("DEBUG: About to access plan_tree.targetlist");

    // DEBUG: Inspect target list BEFORE calling ExecTypeFromTL
    let targetlist = plan_tree_ref.targetlist;

    eprintln!("DEBUG: targetlist accessed successfully");
    pgrx::info!("DEBUG: targetlist accessed successfully");

    if targetlist.is_null() {
        eprintln!("ERROR: targetlist is null!");
        return Err("Target list is null".into());
    }

    eprintln!("DEBUG: targetlist pointer: {targetlist:p}");
    eprintln!("DEBUG: About to access targetlist.length");
    pgrx::info!("DEBUG: About to access targetlist.length");

    eprintln!("DEBUG: targetlist length: {}", (*targetlist).length);

    eprintln!("DEBUG: targetlist length accessed successfully");
    pgrx::info!("DEBUG: targetlist length accessed successfully");

    eprintln!("DEBUG: About to access targetlist.elements array");
    pgrx::info!("DEBUG: About to access targetlist.elements array");

    let elements_ptr = (*targetlist).elements;
    eprintln!("DEBUG: elements array pointer: {elements_ptr:p}");
    pgrx::info!("DEBUG: elements array pointer: {:p}", elements_ptr);

    if elements_ptr.is_null() {
        eprintln!("ERROR: elements array is null!");
        return Err("Target list elements array is null".into());
    }

    eprintln!("DEBUG: elements array is valid, about to iterate");
    pgrx::info!("DEBUG: elements array is valid, about to iterate");

    // Use PostgreSQL's list_nth function instead of manual pointer access
    for i in 0..(*targetlist).length {
        eprintln!("DEBUG: Starting iteration {i}");
        pgrx::info!("DEBUG: Starting iteration {}", i);

        // Use PostgreSQL's safe list access function
        let target_entry = pg_sys::list_nth(targetlist, i) as *mut pg_sys::TargetEntry;

        eprintln!("DEBUG: Got TargetEntry from list_nth: {target_entry:p}");
        pgrx::info!("DEBUG: Got TargetEntry from list_nth: {:p}", target_entry);

        if !target_entry.is_null() {
            eprintln!("DEBUG: About to access TargetEntry fields");
            pgrx::info!("DEBUG: About to access TargetEntry fields");

            // Try to access the node type first (should be T_TargetEntry)
            eprintln!("DEBUG: Checking TargetEntry node type");
            pgrx::info!("DEBUG: Checking TargetEntry node type");

            let node_type = (*target_entry).xpr.type_;
            eprintln!("DEBUG: TargetEntry node type: {node_type:?}");
            pgrx::info!("DEBUG: TargetEntry node type: {:?}", node_type);

            eprintln!("DEBUG: About to access resno and resname");
            pgrx::info!("DEBUG: About to access resno and resname");

            let resno = (*target_entry).resno;
            let resname = (*target_entry).resname;
            eprintln!(
                "DEBUG: Successfully accessed TargetEntry[{i}]: resno={resno}, resname={resname:p}"
            );
            eprintln!(
                "DEBUG: TargetEntry[{}] node type: {:?}",
                i,
                (*target_entry).xpr.type_
            );

            // Inspect the expression inside the TargetEntry
            let expr = (*target_entry).expr;
            if !expr.is_null() {
                eprintln!(
                    "DEBUG: TargetEntry[{}] expr node type: {:?}",
                    i,
                    (*expr).type_
                );

                // If it's a Const, check its type
                if (*expr).type_ == pg_sys::NodeTag::T_Const {
                    let const_node = expr as *mut pg_sys::Const;
                    let oid = (*const_node).consttype.to_u32();
                    eprintln!(
                        "DEBUG: CONST NODE OID: {} ({})",
                        oid,
                        if oid == 65536 {
                            "*** THIS IS THE PROBLEM OID! ***"
                        } else {
                            "ok"
                        }
                    );
                    eprintln!(
                        "DEBUG: Const details: len={}, byval={}",
                        (*const_node).constlen,
                        (*const_node).constbyval
                    );
                }

                // Check for Var nodes with potentially corrupt OIDs
                if (*expr).type_ == pg_sys::NodeTag::T_Var {
                    let var_node = expr as *mut pg_sys::Var;
                    let oid = (*var_node).vartype.to_u32();
                    eprintln!(
                        "DEBUG: VAR NODE OID: {} ({})",
                        oid,
                        if oid == 65536 {
                            "*** THIS IS THE PROBLEM OID! ***"
                        } else {
                            "ok"
                        }
                    );
                }
            } else {
                eprintln!("ERROR: TargetEntry[{i}] expr is null!");
            }
        } else {
            eprintln!("ERROR: TargetEntry[{i}] from list_nth is null!");
        }
    }

    eprintln!("DEBUG: GREAT SUCCESS! Completed TargetEntry iteration without crashes - schema propagation fixed the type mismatch!");
    pgrx::info!("DEBUG: GREAT SUCCESS! Completed TargetEntry iteration without crashes - schema propagation fixed the type mismatch!");
    eprintln!("DEBUG: About to get tuple descriptor");
    pgrx::info!("DEBUG: About to get tuple descriptor");

    // Use PostgreSQL's standard execution path for all node types including SeqScan

    // Use the expected tuple descriptor if provided (from AS clause),
    // otherwise generate from plan's target list
    let tupdesc = if let Some(expected_desc) = expected_tupdesc {
        eprintln!("DEBUG: Using provided AS clause tuple descriptor: {expected_desc:p}");
        pgrx::info!(
            "DEBUG: Using provided AS clause tuple descriptor: {:p}",
            expected_desc
        );

        // Create a copy of the AS clause descriptor in current memory context to ensure consistency
        let tupdesc_copy = pg_sys::CreateTupleDescCopy(expected_desc);
        eprintln!("DEBUG: Created copy of AS clause descriptor: {tupdesc_copy:p}");
        pgrx::info!(
            "DEBUG: Created copy of AS clause descriptor: {:p}",
            tupdesc_copy
        );
        tupdesc_copy
    } else {
        eprintln!("DEBUG: Generating tuple descriptor from plan targetlist");
        pgrx::info!("DEBUG: Generating tuple descriptor from plan targetlist");
        let temp_generated_desc = pg_sys::ExecTypeFromTL((*plan_tree).targetlist);
        eprintln!("DEBUG: ExecTypeFromTL completed successfully, tupdesc: {temp_generated_desc:p}");
        pgrx::info!(
            "DEBUG: ExecTypeFromTL completed successfully, tupdesc: {:p}",
            temp_generated_desc
        );

        // Create a copy to prevent memory corruption and free the temporary descriptor
        let generated_desc = if !temp_generated_desc.is_null() {
            let copy_desc = pg_sys::CreateTupleDescCopy(temp_generated_desc);
            pg_sys::FreeTupleDesc(temp_generated_desc);
            pgrx::info!("DEBUG: Freed temporary generated tuple descriptor");
            copy_desc
        } else {
            temp_generated_desc
        };

        generated_desc
    };

    // DEBUG: Examine the tuple descriptor to find invalid type OIDs
    if !tupdesc.is_null() {
        let natts = (*tupdesc).natts;
        eprintln!("DEBUG: Tuple descriptor has {natts} attributes");
        pgrx::info!("DEBUG: Tuple descriptor has {} attributes", natts);

        for i in 0..natts {
            let attr = &mut (*(*tupdesc).attrs.as_mut_ptr().offset(i as isize));
            let type_oid = attr.atttypid;
            let type_mod = attr.atttypmod;
            let attr_name = if attr.attname.data[0] != 0 {
                std::ffi::CStr::from_ptr(attr.attname.data.as_ptr()).to_string_lossy()
            } else {
                "unnamed".into()
            };

            eprintln!(
                "DEBUG: Attribute {}: name='{}', type_oid={}, type_mod={}",
                i,
                attr_name,
                type_oid.to_u32(),
                type_mod
            );
            pgrx::info!(
                "DEBUG: Attribute {}: name='{}', type_oid={}, type_mod={}",
                i,
                attr_name,
                type_oid.to_u32(),
                type_mod
            );

            if type_oid.to_u32() == 65536 {
                eprintln!("DEBUG: FOUND THE PROBLEM! Attribute {i} has invalid OID 65536");
                pgrx::info!(
                    "DEBUG: FOUND THE PROBLEM! Attribute {} has invalid OID 65536",
                    i
                );
            }
        }
    } else {
        eprintln!("DEBUG: Tuple descriptor is null!");
        pgrx::info!("DEBUG: Tuple descriptor is null!");
    }
    eprintln!("DEBUG: ExecTypeFromTL returned tupdesc: {tupdesc:p}");
    if tupdesc.is_null() {
        return Err("Failed to create tuple descriptor from plan".into());
    }

    // Debug the tuple descriptor attributes to see what type OIDs were created
    let natts = (*tupdesc).natts;
    eprintln!("DEBUG: Tuple descriptor has {natts} attributes");
    for i in 0..natts as usize {
        let attr = (*tupdesc).attrs.as_ptr().add(i);
        eprintln!(
            "DEBUG: Attribute {}: typid={}, typmod={}, attlen={}",
            i,
            (*attr).atttypid.to_u32(),
            (*attr).atttypmod,
            (*attr).attlen
        );
    }

    // Update column names in the tuple descriptor
    let natts = (*tupdesc).natts;
    for i in 0..natts as usize {
        if i < column_names.len() {
            let attr = (*tupdesc).attrs.as_mut_ptr().add(i);
            // Update the attribute name (carefully to avoid buffer overflow)
            let name_data = (*attr).attname.data.as_mut_ptr();
            let src_len = std::cmp::min(column_names[i].len(), (pg_sys::NAMEDATALEN - 1) as usize);
            std::ptr::copy_nonoverlapping(column_names[i].as_ptr(), name_data as *mut u8, src_len);
            *name_data.add(src_len) = 0; // null terminate
        }
    }

    eprintln!("DEBUG: About to create tuplestore");
    pgrx::info!("DEBUG: About to create tuplestore");

    // Create a tuplestore to collect results using the correct tuple descriptor
    let tuplestore_desc = expected_tupdesc.unwrap_or(tupdesc);

    let tuplestore = pg_sys::tuplestore_begin_heap(true, false, pg_sys::work_mem);
    if tuplestore.is_null() {
        eprintln!("ERROR: Failed to create tuplestore");
        pgrx::info!("ERROR: Failed to create tuplestore");
        return Err("Failed to create tuplestore".into());
    }

    eprintln!(
        "DEBUG: Tuplestore created successfully with descriptor {tuplestore_desc:p}: {tuplestore:p}"
    );
    pgrx::info!(
        "DEBUG: Tuplestore created successfully with descriptor {:p}: {:p}",
        tuplestore_desc,
        tuplestore
    );

    eprintln!("DEBUG: Using ExecutorStart pattern instead of direct ExecInitNode");
    pgrx::info!("DEBUG: Using ExecutorStart pattern instead of direct ExecInitNode");

    // Create a minimal QueryDesc that PostgreSQL's executor expects (like execute_plan_directly_raw)
    let query_desc = pgrx::PgBox::<pg_sys::QueryDesc>::alloc0();
    let query_desc_ptr = query_desc.into_pg();
    pgrx::info!("DEBUG: QueryDesc allocated: {:p}", query_desc_ptr);

    // Create a minimal PlannedStmt wrapper
    let mut planned_stmt = pgrx::PgBox::<pg_sys::PlannedStmt>::alloc0();
    planned_stmt.type_ = pg_sys::NodeTag::T_PlannedStmt;
    planned_stmt.planTree = plan_tree as *const pg_sys::Plan as *mut pg_sys::Plan;
    planned_stmt.rtable = range_table as *mut pg_sys::List;
    planned_stmt.permInfos = std::ptr::null_mut(); // Empty permission info list - we bypass checks
    planned_stmt.commandType = pg_sys::CmdType::CMD_SELECT;
    planned_stmt.canSetTag = true; // Important for SELECT queries
    planned_stmt.utilityStmt = std::ptr::null_mut();
    planned_stmt.stmt_location = 0;
    planned_stmt.stmt_len = 0;

    // Convert subplans vec to pg_sys::List and merge range tables
    if !subplans.is_empty() {
        eprintln!(
            "DEBUG: execute_plan_directly - Adding {} subplans to PlannedStmt",
            subplans.len()
        );
        pgrx::info!(
            "DEBUG: execute_plan_directly - Adding {} subplans to PlannedStmt",
            subplans.len()
        );

        let mut subplan_list: *mut pg_sys::List = std::ptr::null_mut();
        let mut merged_range_table = range_table as *mut pg_sys::List;

        for (i, subplan_entry) in subplans.iter().enumerate() {
            eprintln!("DEBUG: Adding subplan {} at {:p}", i, subplan_entry.plan);

            // Merge subplan's range table into main range table and adjust scanrelids
            if !subplan_entry.range_table.is_null() {
                let subplan_rt = subplan_entry.range_table;
                let subplan_rt_len = (*subplan_rt).length;
                eprintln!(
                    "DEBUG: Subplan {} has {} range table entries",
                    i, subplan_rt_len
                );

                // Calculate offset for this subplan's range table entries
                let offset = if merged_range_table.is_null() {
                    0
                } else {
                    (*merged_range_table).length
                };

                // Append subplan's range table entries to merged range table
                for j in 0..subplan_rt_len {
                    let rte = pg_sys::list_nth(subplan_rt, j) as *mut pg_sys::RangeTblEntry;
                    merged_range_table =
                        pg_sys::lappend(merged_range_table, rte as *mut std::ffi::c_void);
                }

                // Adjust scanrelid values in the subplan's plan tree
                if offset > 0 {
                    adjust_scanrelids_in_plan(subplan_entry.plan, offset as u32);
                }
            }

            subplan_list =
                pg_sys::lappend(subplan_list, subplan_entry.plan as *mut std::ffi::c_void);
        }

        planned_stmt.subplans = subplan_list;
        planned_stmt.rtable = merged_range_table;

        // Debug: Verify the subplan list is properly set
        let subplan_count = if subplan_list.is_null() {
            0
        } else {
            (*subplan_list).length
        };
        let merged_rt_count = if merged_range_table.is_null() {
            0
        } else {
            (*merged_range_table).length
        };
        pgrx::info!(
            "DEBUG: PlannedStmt.subplans list has {} entries, merged rtable has {} entries",
            subplan_count,
            merged_rt_count
        );
        if subplan_count > 0 {
            let first_subplan_ptr = pg_sys::list_nth(subplan_list, 0) as *mut pg_sys::Plan;
            pgrx::info!(
                "DEBUG: First subplan in list at {:p}, type={:?}",
                first_subplan_ptr,
                (*first_subplan_ptr).type_
            );

            // Walk the subplan tree to check scanrelid values
            fn check_scanrelids(plan: *mut pg_sys::Plan, depth: i32, rt_size: i32) {
                unsafe {
                    if plan.is_null() {
                        return;
                    }
                    let node_type = (*plan).type_;
                    match node_type {
                        pg_sys::NodeTag::T_SeqScan | pg_sys::NodeTag::T_IndexScan => {
                            let scan = plan as *mut pg_sys::Scan;
                            let scanrelid = (*scan).scanrelid;
                            if scanrelid as i32 > rt_size || scanrelid == 0 {
                                pgrx::warning!(
                                    "SUBPLAN ISSUE: scanrelid {} out of range (rt_size={})",
                                    scanrelid,
                                    rt_size
                                );
                            } else {
                                pgrx::info!(
                                    "DEBUG: SUBPLAN depth={} {:?} scanrelid={}",
                                    depth,
                                    node_type,
                                    scanrelid
                                );
                            }
                        }
                        _ => {
                            pgrx::info!("DEBUG: SUBPLAN depth={} {:?}", depth, node_type);
                        }
                    }
                    check_scanrelids((*plan).lefttree, depth + 1, rt_size);
                    check_scanrelids((*plan).righttree, depth + 1, rt_size);
                }
            }
            check_scanrelids(first_subplan_ptr, 0, merged_rt_count);
        }
    } else {
        planned_stmt.subplans = std::ptr::null_mut();
    }

    let planned_stmt_ptr = planned_stmt.into_pg();
    pgrx::info!("DEBUG: PlannedStmt created: {:p}", planned_stmt_ptr);

    // Set up the QueryDesc using the raw pointer
    (*query_desc_ptr).operation = pg_sys::CmdType::CMD_SELECT;
    (*query_desc_ptr).plannedstmt = planned_stmt_ptr;
    (*query_desc_ptr).sourceText = std::ptr::null_mut();

    // Get snapshot - if none exists, get a new one
    let snapshot = pg_sys::GetActiveSnapshot();
    if snapshot.is_null() {
        pgrx::info!("DEBUG: No active snapshot, registering a new one");
        pg_sys::PushActiveSnapshot(pg_sys::GetTransactionSnapshot());
    }
    (*query_desc_ptr).snapshot = pg_sys::GetActiveSnapshot();

    (*query_desc_ptr).crosscheck_snapshot = std::ptr::null_mut();
    (*query_desc_ptr).dest = std::ptr::null_mut();
    (*query_desc_ptr).params = std::ptr::null_mut();
    (*query_desc_ptr).queryEnv = std::ptr::null_mut();
    (*query_desc_ptr).instrument_options = 0;
    pgrx::info!("DEBUG: QueryDesc setup complete");

    pgrx::info!("DEBUG: Skipping ExecutorStart, manually initializing instead");

    // Instead of ExecutorStart, manually set up the estate and call ExecInitNode
    let estate = pg_sys::CreateExecutorState();
    if estate.is_null() {
        return Err("Failed to create executor state".into());
    }

    // Use ExecInitRangeTable to properly initialize range table and related arrays.
    // IMPORTANT: Use the range table from planned_stmt, which includes merged subplan RTEs
    // Pass empty permInfos list - we bypass permission checks for Substrait plans.
    let empty_perminfos: *mut pg_sys::List = std::ptr::null_mut();
    let actual_range_table = (*planned_stmt_ptr).rtable;

    // Debug the range table before passing it
    let rt_len = if actual_range_table.is_null() {
        0
    } else {
        (*actual_range_table).length
    };
    pgrx::info!(
        "DEBUG: Range table length before ExecInitRangeTable: {}",
        rt_len
    );

    // If range table exists, debug its contents
    if !actual_range_table.is_null() && rt_len > 0 {
        let rte_ptr = pg_sys::list_nth(actual_range_table, 0);
        let rte = rte_ptr as *mut pg_sys::RangeTblEntry;
        if !rte.is_null() {
            pgrx::info!(
                "DEBUG: RTE[0]: type_={:?}, rtekind={:?}, relid={}",
                (*rte).type_,
                (*rte).rtekind,
                (*rte).relid
            );
        }
    }
    pg_sys::ExecInitRangeTable(estate, actual_range_table, empty_perminfos);
    pgrx::info!("DEBUG: ExecInitRangeTable completed");

    // Debug estate fields after ExecInitRangeTable
    pgrx::info!(
        "DEBUG: After ExecInitRangeTable: es_range_table_size={} es_relations={:p}",
        (*estate).es_range_table_size,
        (*estate).es_relations
    );

    // Open all tables in the MERGED range table before execution.
    // This includes both main plan tables and subplan tables.
    // Store the relation handles in es_relations for scan nodes to use.
    if !actual_range_table.is_null() {
        let rt_list = actual_range_table;
        pgrx::info!(
            "DEBUG: Opening {} relations from merged range table",
            (*rt_list).length
        );
        for i in 0..(*rt_list).length {
            let rte_ptr = pg_sys::list_nth(rt_list, i);
            let rte = rte_ptr as *mut pg_sys::RangeTblEntry;
            if !rte.is_null() && (*rte).rtekind == pg_sys::RTEKind::RTE_RELATION {
                pgrx::info!(
                    "DEBUG: Opening relation OID {} (RTE #{}) with AccessShareLock",
                    (*rte).relid,
                    i + 1
                );
                // Open the relation and store it in es_relations
                let rel = pg_sys::table_open((*rte).relid, pg_sys::AccessShareLock as i32);
                pgrx::info!("DEBUG: Relation opened: {:p}", rel);
                // Store in es_relations at 0-based index
                *(*estate).es_relations.offset(i as isize) = rel;
            }
        }
    }

    // Set the planned statement reference on estate.
    (*estate).es_plannedstmt = planned_stmt_ptr;

    // IMPORTANT: Set EState fields BEFORE subplan initialization - ExecInitNode needs these!
    (*estate).es_output_cid = 0;
    (*estate).es_snapshot = (*query_desc_ptr).snapshot;
    (*estate).es_crosscheck_snapshot = (*query_desc_ptr).crosscheck_snapshot;
    (*estate).es_instrument = 0;
    (*estate).es_top_eflags = 0;
    (*estate).es_processed = 0;
    pgrx::info!(
        "DEBUG: Set EState fields before subplan init, es_snapshot={:p}",
        (*estate).es_snapshot
    );

    // Initialize es_param_exec_vals BEFORE subplans - they may need it during initialization.
    // PostgreSQL 17 uses paramExecTypes (List) instead of nParamExec (int)
    {
        let param_exec_types = (*planned_stmt_ptr).paramExecTypes;
        let n_param_exec = if !param_exec_types.is_null() {
            (*param_exec_types).length as usize
        } else {
            0
        };
        if n_param_exec > 0 {
            let param_exec_size = n_param_exec * std::mem::size_of::<pg_sys::ParamExecData>();
            (*estate).es_param_exec_vals =
                pg_sys::palloc0(param_exec_size) as *mut pg_sys::ParamExecData;
            pgrx::info!(
                "DEBUG: Allocated es_param_exec_vals for {} params (before subplans)",
                n_param_exec
            );
        } else {
            // Even with 0 params, allocate a minimal array to avoid NULL pointer issues
            (*estate).es_param_exec_vals =
                pg_sys::palloc0(std::mem::size_of::<pg_sys::ParamExecData>())
                    as *mut pg_sys::ParamExecData;
            pgrx::info!("DEBUG: Allocated minimal es_param_exec_vals (paramExecTypes empty/null)");
        }
    }

    // Initialize es_subplanstates by pre-initializing all subplans.
    // This is critical: PostgreSQL's ExecInitSubPlan expects the subplan's PlanState
    // to already exist in es_subplanstates when it encounters a SubPlan expression.
    // This mimics the InitPlan() function in PostgreSQL's execMain.c.
    let subplan_list = (*planned_stmt_ptr).subplans;
    if !subplan_list.is_null() && (*subplan_list).length > 0 {
        let num_subplans = (*subplan_list).length;
        pgrx::info!(
            "DEBUG: Pre-initializing {} subplans before main plan",
            num_subplans
        );

        // Initialize es_subplanstates as empty list first
        (*estate).es_subplanstates = std::ptr::null_mut();

        // Initialize each subplan and add its PlanState to es_subplanstates
        for i in 0..num_subplans {
            let subplan_ptr = pg_sys::list_nth(subplan_list, i) as *mut pg_sys::Plan;
            pgrx::info!(
                "DEBUG: Initializing subplan {} at {:p}, type={:?}",
                i,
                subplan_ptr,
                (*subplan_ptr).type_
            );

            // Debug the subplan tree
            debug_dump_plan_tree(subplan_ptr, 0);

            // Debug: Check es_relations array before init
            pgrx::info!(
                "DEBUG: es_relations={:p}, es_range_table_size={}",
                (*estate).es_relations,
                (*estate).es_range_table_size
            );
            if !(*estate).es_relations.is_null() {
                for rel_idx in 0..(*estate).es_range_table_size.min(10) as isize {
                    let rel = *(*estate).es_relations.offset(rel_idx);
                    pgrx::info!("DEBUG: es_relations[{}]={:p}", rel_idx, rel);
                }
            }

            // Debug: Dump Agg targetlist if this is an Agg node
            if (*subplan_ptr).type_ == pg_sys::NodeTag::T_Agg {
                let agg = subplan_ptr as *mut pg_sys::Agg;
                let tl = (*agg).plan.targetlist;
                if !tl.is_null() {
                    pgrx::info!("DEBUG: Agg targetlist has {} entries", (*tl).length);
                    for te_idx in 0..(*tl).length {
                        let te = pg_sys::list_nth(tl, te_idx) as *mut pg_sys::TargetEntry;
                        if !te.is_null() && !(*te).expr.is_null() {
                            let expr_type = (*(*te).expr).type_;
                            pgrx::info!(
                                "DEBUG: Agg targetlist[{}]: resno={} expr_type={:?}",
                                te_idx,
                                (*te).resno,
                                expr_type
                            );
                            if expr_type == pg_sys::NodeTag::T_Aggref {
                                let aggref = (*te).expr as *mut pg_sys::Aggref;
                                pgrx::info!(
                                    "DEBUG:   Aggref: aggfnoid={} aggtype={} aggtranstype={}",
                                    (*aggref).aggfnoid.to_u32(),
                                    (*aggref).aggtype.to_u32(),
                                    (*aggref).aggtranstype.to_u32()
                                );
                                pgrx::info!("DEBUG:   Aggref: aggstar={} aggsplit={:?} aggno={} aggtransno={}",
                                    (*aggref).aggstar, (*aggref).aggsplit, (*aggref).aggno, (*aggref).aggtransno);
                                if !(*aggref).args.is_null() {
                                    let args_count = (*(*aggref).args).length;
                                    pgrx::info!("DEBUG:   Aggref args count={}", args_count);
                                    // Dump each arg
                                    for arg_idx in 0..args_count {
                                        let arg = pg_sys::list_nth((*aggref).args, arg_idx)
                                            as *mut pg_sys::TargetEntry;
                                        if !arg.is_null() {
                                            pgrx::info!(
                                                "DEBUG:   Aggref arg[{}]: TargetEntry resno={}",
                                                arg_idx,
                                                (*arg).resno
                                            );
                                            if !(*arg).expr.is_null() {
                                                let expr_type = (*(*arg).expr).type_;
                                                pgrx::info!(
                                                    "DEBUG:   Aggref arg[{}] expr type={:?}",
                                                    arg_idx,
                                                    expr_type
                                                );
                                                if expr_type == pg_sys::NodeTag::T_Var {
                                                    let var = (*arg).expr as *mut pg_sys::Var;
                                                    pgrx::info!("DEBUG:   Var: varno={} varattno={} vartype={}",
                                                        (*var).varno, (*var).varattno, (*var).vartype.to_u32());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Verify subplan structure with nodeToString before ExecInitNode
            pgrx::info!("DEBUG: Verifying subplan {} with nodeToString", i);
            let plan_str = pg_sys::nodeToString(subplan_ptr as *const std::ffi::c_void);
            if plan_str.is_null() {
                pgrx::warning!("DEBUG: nodeToString returned NULL for subplan {}", i);
            } else {
                let plan_str_len = std::ffi::CStr::from_ptr(plan_str).to_bytes().len();
                pgrx::info!(
                    "DEBUG: nodeToString succeeded for subplan {}, length={}",
                    i,
                    plan_str_len
                );
                pg_sys::pfree(plan_str as *mut std::ffi::c_void);
            }

            // Check Aggref.aggargtypes if this is an Agg node
            if (*subplan_ptr).type_ == pg_sys::NodeTag::T_Agg {
                let agg = subplan_ptr as *mut pg_sys::Agg;
                let tl = (*agg).plan.targetlist;
                if !tl.is_null() && (*tl).length > 0 {
                    let te = pg_sys::list_nth(tl, 0) as *mut pg_sys::TargetEntry;
                    if !te.is_null() && !(*te).expr.is_null() {
                        let expr_type = (*(*te).expr).type_;
                        if expr_type == pg_sys::NodeTag::T_Aggref {
                            let aggref = (*te).expr as *mut pg_sys::Aggref;
                            let aggargtypes = (*aggref).aggargtypes;
                            if aggargtypes.is_null() {
                                pgrx::info!("DEBUG: Aggref.aggargtypes is NULL");
                            } else {
                                pgrx::info!(
                                    "DEBUG: Aggref.aggargtypes has {} entries",
                                    (*aggargtypes).length
                                );
                                for oid_idx in 0..(*aggargtypes).length {
                                    let oid_val = pg_sys::list_nth_oid(aggargtypes, oid_idx);
                                    pgrx::info!("DEBUG: aggargtypes[{}] = {}", oid_idx, oid_val);
                                }
                            }
                        }
                    }
                }
            }

            // Debug: Walk the plan tree and dump all qual expressions
            fn dump_all_quals(plan: *mut pg_sys::Plan, depth: i32) {
                unsafe {
                    if plan.is_null() {
                        return;
                    }
                    let node_type = (*plan).type_;
                    pgrx::info!("QUAL_DUMP depth={} {:?}", depth, node_type);
                    // Dump targetlist too
                    if !(*plan).targetlist.is_null() {
                        let tl = (*plan).targetlist;
                        pgrx::info!("TL_DUMP: targetlist len={}", (*tl).length);
                        for idx in 0..(*tl).length.min(5) {
                            let te = pg_sys::list_nth(tl, idx) as *mut pg_sys::TargetEntry;
                            if !te.is_null() {
                                pgrx::info!("TL_DUMP[{}]: resno={}", idx, (*te).resno);
                                debug_dump_expr(
                                    (*te).expr as *mut pg_sys::Node,
                                    (depth + 2) as usize,
                                );
                            }
                        }
                    }
                    if !(*plan).qual.is_null() {
                        let qual = (*plan).qual;
                        pgrx::info!("QUAL_DUMP: qual list at {:p} len={}", qual, (*qual).length);
                        for idx in 0..(*qual).length {
                            let node = pg_sys::list_nth(qual, idx) as *mut pg_sys::Node;
                            debug_dump_expr(node, (depth + 1) as usize);
                        }
                    }
                    // For Result nodes, also check resconstantqual
                    if node_type == pg_sys::NodeTag::T_Result {
                        let result = plan as *mut pg_sys::Result;
                        if !(*result).resconstantqual.is_null() {
                            pgrx::info!(
                                "QUAL_DUMP: Result.resconstantqual at {:p}",
                                (*result).resconstantqual
                            );
                            debug_dump_expr((*result).resconstantqual, (depth + 1) as usize);
                        }
                    }
                    dump_all_quals((*plan).lefttree, depth + 1);
                    dump_all_quals((*plan).righttree, depth + 1);
                }
            }
            pgrx::info!(
                "DEBUG: Dumping all quals in subplan {} before ExecInitNode",
                i
            );
            dump_all_quals(subplan_ptr, 0);

            // Initialize the subplan with ExecInitNode
            pgrx::info!("DEBUG: About to call ExecInitNode for subplan {}", i);
            let subplan_state = pg_sys::ExecInitNode(subplan_ptr, estate, 0);
            pgrx::info!(
                "DEBUG: Subplan {} initialized, PlanState={:p}",
                i,
                subplan_state
            );

            if subplan_state.is_null() {
                pgrx::warning!("DEBUG: Subplan {} failed to initialize!", i);
            }

            // Append the PlanState to es_subplanstates
            (*estate).es_subplanstates = pg_sys::lappend(
                (*estate).es_subplanstates,
                subplan_state as *mut std::ffi::c_void,
            );
        }

        pgrx::info!("DEBUG: All {} subplans initialized", num_subplans);
    } else {
        (*estate).es_subplanstates = std::ptr::null_mut();
    }

    // Note: es_output_cid, es_snapshot, etc. are initialized earlier, before subplan initialization

    (*query_desc_ptr).estate = estate;

    pgrx::info!(
        "DEBUG: About to call ExecInitNode with plan_tree={:p}, estate={:p}",
        plan_tree,
        estate
    );

    // Verify es_subplanstates before main plan init
    let subplan_states = (*estate).es_subplanstates;
    if !subplan_states.is_null() {
        let n_states = (*subplan_states).length;
        pgrx::info!("DEBUG: es_subplanstates has {} entries", n_states);
        for i in 0..n_states {
            let ps = pg_sys::list_nth(subplan_states, i) as *mut pg_sys::PlanState;
            pgrx::info!(
                "DEBUG:   es_subplanstates[{}] = {:p}, type={:?}",
                i,
                ps,
                if !ps.is_null() {
                    (*ps).type_
                } else {
                    pg_sys::NodeTag::T_Invalid
                }
            );
        }
    } else {
        pgrx::info!("DEBUG: es_subplanstates is NULL");
    }

    // Debug: dump plan tree structure before ExecInitNode
    debug_dump_plan_tree(plan_tree, 0);

    // Now initialize the main plan node (subplans already initialized above)
    let plan_state = pg_sys::ExecInitNode(plan_tree, estate, 0);

    pgrx::info!("DEBUG: ExecInitNode returned: {:p}", plan_state);

    if plan_state.is_null() {
        return Err("ExecInitNode failed".into());
    }

    (*query_desc_ptr).planstate = plan_state;

    pgrx::info!("DEBUG: Manual initialization succeeded!");

    // Get the plan state - we called ExecInitNode above.
    let plan_state = (*query_desc_ptr).planstate;
    eprintln!("DEBUG: ExecutorStart succeeded, plan_state: {plan_state:p}");
    pgrx::info!(
        "DEBUG: ExecutorStart succeeded, plan_state: {:p}",
        plan_state
    );

    // Debug the plan state structure to understand what's different
    if !plan_state.is_null() {
        eprintln!("DEBUG: Plan state type: {:?}", (*plan_state).type_);
        pgrx::info!("DEBUG: Plan state type: {:?}", (*plan_state).type_);

        // Check if this is a SeqScan
        if (*plan_state).type_ == pg_sys::NodeTag::T_SeqScanState {
            eprintln!("DEBUG: Plan state is SeqScanState");
            pgrx::info!("DEBUG: Plan state is SeqScanState");
        }
    }

    eprintln!("DEBUG: ExecInitNode returned successfully: {plan_state:p}");
    pgrx::info!(
        "DEBUG: ExecInitNode returned successfully: {:p}",
        plan_state
    );

    if plan_state.is_null() {
        eprintln!("ERROR: ExecutorStart returned null plan_state");
        pgrx::info!("ERROR: ExecutorStart returned null plan_state");
        // Manual cleanup since we bypassed ExecutorStart
        pg_sys::FreeExecutorState(estate);
        return Err("Failed to initialize plan node for execution".into());
    }

    // Execute the plan and collect tuples into tuplestore with error handling
    let mut tuple_count = 0u64;

    pgrx::info!("DEBUG: Starting plan execution loop");

    // Debug plan state structure before execution
    pgrx::info!(
        "DEBUG: plan_state={:p}, type={:?}",
        plan_state,
        (*plan_state).type_
    );

    // Check if this is a Sort state and dump its child state
    if (*plan_state).type_ == pg_sys::NodeTag::T_SortState {
        let sort_state = plan_state as *mut pg_sys::SortState;
        pgrx::info!("DEBUG: SortState details:");
        pgrx::info!(
            "DEBUG:   ss_ScanTupleSlot={:p}",
            (*sort_state).ss.ss_ScanTupleSlot
        );
        pgrx::info!(
            "DEBUG:   ps_ResultTupleSlot={:p}",
            (*sort_state).ss.ps.ps_ResultTupleSlot
        );
        pgrx::info!(
            "DEBUG:   lefttree (child state)={:p}",
            (*sort_state).ss.ps.lefttree
        );

        // Check the child plan state (should be AggState)
        let child_state = (*sort_state).ss.ps.lefttree;
        if !child_state.is_null() {
            pgrx::info!("DEBUG:   child state type={:?}", (*child_state).type_);
        }

        // Check tuplesortstate
        pgrx::info!("DEBUG:   tuplesortstate={:p}", (*sort_state).tuplesortstate);
    }

    loop {
        pgrx::info!("DEBUG: Calling ExecProcNode (iteration {})", tuple_count);

        // Use PostgreSQL's PG_TRY/PG_CATCH mechanism for error handling
        let slot = pg_sys::ExecProcNode(plan_state);
        pgrx::info!("DEBUG: ExecProcNode returned slot: {:p}", slot);

        if slot.is_null() {
            eprintln!("DEBUG: No more tuples, breaking loop");
            pgrx::info!("DEBUG: No more tuples, breaking loop");
            break; // No more tuples
        }

        // Debug the slot's tuple descriptor to find OID 65536 source
        eprintln!("DEBUG: Examining execution slot for tuple {tuple_count}");
        pgrx::info!("DEBUG: Examining execution slot for tuple {}", tuple_count);

        // Convert slot to AS clause format if expected descriptor was provided
        eprintln!(
            "DEBUG: Checking if expected_tupdesc is Some: {}",
            expected_tupdesc.is_some()
        );
        pgrx::info!(
            "DEBUG: Checking if expected_tupdesc is Some: {}",
            expected_tupdesc.is_some()
        );

        // Check slot flags before materializing.
        let flags = (*slot).tts_flags;
        pgrx::info!(
            "DEBUG: Slot {:p} flags={}, empty={}",
            slot,
            flags,
            flags & pg_sys::TTS_FLAG_EMPTY as u16 != 0
        );

        // Skip empty slots.
        if flags & pg_sys::TTS_FLAG_EMPTY as u16 != 0 {
            pgrx::info!("DEBUG: Slot is empty, breaking loop");
            break;
        }

        // Materialize the slot if needed (virtual slots need to be materialized).
        pgrx::info!("DEBUG: About to materialize slot {:p}", slot);
        pg_sys::ExecMaterializeSlot(slot);
        pgrx::info!("DEBUG: Slot materialized successfully");

        // Store tuple directly in tuplestore.
        // The tuplestore handles type conversion as needed.
        pgrx::info!("DEBUG: About to store tuple in tuplestore");
        pg_sys::tuplestore_puttupleslot(tuplestore, slot);
        pgrx::info!("DEBUG: Tuple stored successfully");
        tuple_count += 1;

        // Prevent infinite loops and excessive memory usage
        if tuple_count > 1000000 {
            // Manual cleanup since we bypassed ExecutorStart
            pg_sys::ExecEndNode(plan_state);
            pg_sys::FreeExecutorState(estate);
            return Err("Query returned too many rows (> 1M), execution aborted".into());
        }
    }

    // Clean up manually since we bypassed ExecutorStart.
    // ExecutorFinish/ExecutorEnd expect structures set up by ExecutorStart.
    eprintln!("DEBUG: Cleaning up with manual ExecEndNode and FreeExecutorState");
    pgrx::info!("DEBUG: Cleaning up with manual ExecEndNode and FreeExecutorState");
    pg_sys::ExecEndNode(plan_state);
    pg_sys::FreeExecutorState(estate);

    Ok((tupdesc, tuplestore))
}

/// Executes a PostgreSQL plan tree and returns the results
pub unsafe fn execute_postgres_plan(
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *const pg_sys::List,
    subplans: Vec<crate::plan_translator::expressions::SubplanEntry>,
) -> Result<ExecutionResult, Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("DEBUG: execute_postgres_plan ENTRY - plan_tree={plan_tree:p}");
    pgrx::info!(
        "DEBUG: execute_postgres_plan ENTRY - plan_tree={:p}",
        plan_tree
    );

    if plan_tree.is_null() {
        eprintln!("DEBUG: ERROR - plan_tree is null!");
        pgrx::info!("DEBUG: ERROR - plan_tree is null!");
        return Err("Plan tree pointer is null".into());
    }

    eprintln!("DEBUG: plan_tree pointer is valid, about to check node type");
    pgrx::info!("DEBUG: plan_tree pointer is valid, about to check node type");

    // Check for the specific type 124 corruption issue
    let plan_type = (*plan_tree).type_;
    let plan_type_value = plan_type as i32;

    if plan_type_value == 124 {
        pgrx::error!(
            "ERROR: Plan tree has invalid node type 124 - this is a known corruption issue"
        );
    }

    pgrx::info!(
        "DEBUG: Plan tree type: {:?} (value: {})",
        plan_type,
        plan_type_value
    );

    // Execute the plan using PostgreSQL's native executor
    eprintln!("DEBUG: Executing plan using PostgreSQL's native executor");

    // Validate plan tree before execution
    validate_plan_tree_node_types(plan_tree);

    let (tupdesc, tuplestore) =
        execute_plan_directly_from_ptr(plan_tree, column_names, range_table, None, subplans)
            .map_err(|e| {
                eprintln!("DEBUG: Plan execution failed: {e}");
                e
            })?;

    eprintln!("DEBUG: Plan executed successfully, converting results");

    // Convert tuple descriptor to ColumnInfo
    let mut columns = Vec::new();
    let natts = (*tupdesc).natts;
    for i in 0..natts {
        let attr = (*tupdesc).attrs.as_ptr().offset(i as isize);
        let name_cstr = std::ffi::CStr::from_ptr((*attr).attname.data.as_ptr());
        let name = name_cstr.to_string_lossy().to_string();

        columns.push(ColumnInfo {
            name,
            type_oid: (*attr).atttypid,
            type_mod: (*attr).atttypmod,
            attr_number: (*attr).attnum,
        });
    }

    // Extract rows from tuplestore
    let mut rows = Vec::new();
    let mut nulls = Vec::new();

    // Reset tuplestore to beginning
    pg_sys::tuplestore_rescan(tuplestore);

    // Create slot for reading tuples
    let slot = pg_sys::MakeTupleTableSlot(tupdesc, &pg_sys::TTSOpsMinimalTuple);

    // Read all tuples from tuplestore
    while pg_sys::tuplestore_gettupleslot(tuplestore, true, false, slot) {
        let mut row_data = Vec::new();
        let mut row_nulls = Vec::new();

        // Extract values from slot
        for i in 0..natts {
            let mut is_null = false;
            let attr_num = i + 1;
            let datum = pg_sys::slot_getattr(slot, attr_num, &mut is_null);
            row_data.push(datum);
            row_nulls.push(is_null);
        }

        rows.push(row_data);
        nulls.push(row_nulls);
    }

    // Clean up
    pg_sys::ExecDropSingleTupleTableSlot(slot);
    pg_sys::tuplestore_end(tuplestore);

    eprintln!("DEBUG: Extracted {} rows from execution", rows.len());

    Ok(ExecutionResult {
        columns,
        rows,
        nulls,
    })
}

/// Execute PostgreSQL plan as SRF directly without unpacking/repacking
/// This function directly interfaces with PostgreSQL's SRF mechanism
pub unsafe fn execute_postgres_plan_as_srf(
    fcinfo: pg_sys::FunctionCallInfo,
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *mut pg_sys::List,
    subplans: Vec<crate::plan_translator::expressions::SubplanEntry>,
) -> pg_sys::Datum {
    // IMMEDIATE DEBUG - FIRST LINE OF FUNCTION EXECUTION
    eprintln!("IMMEDIATE: execute_postgres_plan_as_srf ENTERED - BEFORE ANY OPERATIONS");
    pgrx::info!("IMMEDIATE: execute_postgres_plan_as_srf ENTERED - BEFORE ANY OPERATIONS");

    // Use std::panic::catch_unwind to catch any panics that might be preventing execution
    let result = std::panic::catch_unwind(|| {
        eprintln!("DEBUG: execute_postgres_plan_as_srf ENTRY - INSIDE PANIC HANDLER");
        pgrx::info!("DEBUG: execute_postgres_plan_as_srf ENTRY - INSIDE PANIC HANDLER");

        execute_postgres_plan_as_srf_inner(fcinfo, plan_tree, column_names, range_table, subplans)
    });

    match result {
        Ok(datum) => {
            eprintln!("DEBUG: SRF executed successfully");
            datum
        }
        Err(panic_info) => {
            // Try to extract the panic message
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                format!("{:?}", panic_info)
            };
            eprintln!("PANIC: execute_postgres_plan_as_srf panicked: {msg}");
            pgrx::error!("Function panicked: {}", msg);
        }
    }
}

unsafe fn execute_postgres_plan_as_srf_inner(
    fcinfo: pg_sys::FunctionCallInfo,
    plan_tree: *mut pg_sys::Plan,
    column_names: Vec<String>,
    range_table: *mut pg_sys::List,
    subplans: Vec<crate::plan_translator::expressions::SubplanEntry>,
) -> pg_sys::Datum {
    eprintln!(
        "DEBUG: execute_postgres_plan_as_srf_inner ENTRY - using pgrx-compatible SRF pattern"
    );
    pgrx::info!(
        "DEBUG: execute_postgres_plan_as_srf_inner ENTRY - using pgrx-compatible SRF pattern"
    );

    // Check if this is the first call
    let funcctx: *mut pg_sys::FuncCallContext;
    if (*fcinfo).flinfo.is_null() || (*(*fcinfo).flinfo).fn_extra.is_null() {
        eprintln!("DEBUG: SRF first call - setting up using init_MultiFuncCall");
        pgrx::info!("DEBUG: SRF first call - setting up using init_MultiFuncCall");

        // Initialize multi-function call context
        funcctx = pg_sys::init_MultiFuncCall(fcinfo);
        let oldcontext = pg_sys::MemoryContextSwitchTo((*funcctx).multi_call_memory_ctx);

        // Get call result type from AS clause - this is the key improvement
        let mut result_type_id: pg_sys::Oid = pg_sys::InvalidOid;
        let mut result_tuple_desc: *mut pg_sys::TupleDescData = std::ptr::null_mut();

        let type_class =
            pg_sys::get_call_result_type(fcinfo, &mut result_type_id, &mut result_tuple_desc);
        eprintln!("DEBUG: get_call_result_type returned: {:?}, result_type_id: {}, result_tuple_desc: {:p}",
                 type_class, result_type_id.to_u32(), result_tuple_desc);
        pgrx::info!("DEBUG: get_call_result_type returned: {:?}, result_type_id: {}, result_tuple_desc: {:p}",
                   type_class, result_type_id.to_u32(), result_tuple_desc);

        if type_class != pg_sys::TypeFuncClass::TYPEFUNC_COMPOSITE {
            pg_sys::MemoryContextSwitchTo(oldcontext);
            pgrx::error!("Function must return a composite type (SETOF RECORD with AS clause)");
        }

        if result_tuple_desc.is_null() {
            pg_sys::MemoryContextSwitchTo(oldcontext);
            pgrx::error!("Could not determine result tuple descriptor from AS clause");
        }

        // Execute the plan using the proper tuple descriptor from AS clause
        let execution_result = execute_plan_directly(
            &*plan_tree,
            column_names,
            range_table,
            Some(result_tuple_desc),
            subplans,
        );
        let (_generated_tupdesc, tuplestore) = execution_result.unwrap_or_else(|e| {
            pg_sys::MemoryContextSwitchTo(oldcontext);
            pgrx::error!("Plan execution failed: {}", e);
        });

        // Store tuplestore in function context
        (*funcctx).user_fctx = tuplestore as *mut std::ffi::c_void;

        // Use the blessed result tuple descriptor from AS clause
        let blessed_desc = pg_sys::BlessTupleDesc(result_tuple_desc);
        (*funcctx).tuple_desc = blessed_desc;

        // DEBUG: Examine the blessed descriptor
        if !blessed_desc.is_null() {
            let blessed_typeid = (*blessed_desc).tdtypeid;
            let blessed_typmod = (*blessed_desc).tdtypmod;
            eprintln!(
                "DEBUG: Blessed descriptor: tdtypeid={}, tdtypmod={}",
                blessed_typeid.to_u32(),
                blessed_typmod
            );
            pgrx::info!(
                "DEBUG: Blessed descriptor: tdtypeid={}, tdtypmod={}",
                blessed_typeid.to_u32(),
                blessed_typmod
            );
        }

        // Set up for indefinite iteration (we don't know tuple count in advance)
        (*funcctx).max_calls = u64::MAX;
        (*funcctx).call_cntr = 0;

        // Reset tuplestore for reading
        pg_sys::tuplestore_rescan(tuplestore);

        pg_sys::MemoryContextSwitchTo(oldcontext);
    } else {
        // Per-call setup
        funcctx = (*(*fcinfo).flinfo).fn_extra as *mut pg_sys::FuncCallContext;
    }

    // Get tuplestore from context
    let tuplestore = (*funcctx).user_fctx as *mut pg_sys::Tuplestorestate;
    // Use the blessed tuple descriptor directly for the slot
    let blessed_desc = (*funcctx).tuple_desc;
    let slot = pg_sys::MakeTupleTableSlot(blessed_desc, &pg_sys::TTSOpsMinimalTuple);

    if pg_sys::tuplestore_gettupleslot(tuplestore, true, false, slot) {
        eprintln!("DEBUG: Retrieved tuple from tuplestore using pgrx-compatible SRF pattern");
        pgrx::info!("DEBUG: Retrieved tuple from tuplestore using pgrx-compatible SRF pattern");

        // DEBUG: Examine the slot before conversion
        let slot_desc = (*slot).tts_tupleDescriptor;
        if !slot_desc.is_null() {
            let natts = (*slot_desc).natts;
            eprintln!("DEBUG: Pre-conversion slot descriptor has {natts} attrs");
            pgrx::info!("DEBUG: Pre-conversion slot descriptor has {} attrs", natts);
            for i in 0..natts {
                let attr = (*slot_desc).attrs.as_ptr().add(i as usize);
                let attr_typeid = (*attr).atttypid;
                eprintln!(
                    "DEBUG: Pre-conversion slot attr {}: typeid={}",
                    i,
                    attr_typeid.to_u32()
                );
                pgrx::info!(
                    "DEBUG: Pre-conversion slot attr {}: typeid={}",
                    i,
                    attr_typeid.to_u32()
                );
            }
        }

        // Convert slot to heap tuple using the blessed tuple descriptor
        eprintln!("DEBUG: About to call ExecCopySlotHeapTuple");
        pgrx::info!("DEBUG: About to call ExecCopySlotHeapTuple");
        let heap_tuple = pg_sys::ExecCopySlotHeapTuple(slot);
        eprintln!("DEBUG: ExecCopySlotHeapTuple returned: {heap_tuple:p}");
        pgrx::info!("DEBUG: ExecCopySlotHeapTuple returned: {:p}", heap_tuple);

        if !heap_tuple.is_null() {
            // DEBUG: Examine the heap tuple header
            let tuple_header = (*heap_tuple).t_data;
            if !tuple_header.is_null() {
                eprintln!("DEBUG: Heap tuple header: {tuple_header:p}");
                pgrx::info!("DEBUG: Heap tuple header: {:p}", tuple_header);

                // Check if this has the datum_typeid field (composite type)
                let heap_tuple_len = (*heap_tuple).t_len;
                eprintln!("DEBUG: Heap tuple length: {heap_tuple_len}");
                pgrx::info!("DEBUG: Heap tuple length: {}", heap_tuple_len);

                // The issue might be in how PostgreSQL interprets this as a composite type
                // Let's see what the tuple descriptor thinks it is
                let tuple_desc = (*funcctx).tuple_desc;
                if !tuple_desc.is_null() {
                    let tdtypeid = (*tuple_desc).tdtypeid;
                    let tdtypmod = (*tuple_desc).tdtypmod;
                    eprintln!(
                        "DEBUG: Function context tuple desc: tdtypeid={}, tdtypmod={}",
                        tdtypeid.to_u32(),
                        tdtypmod
                    );
                    pgrx::info!(
                        "DEBUG: Function context tuple desc: tdtypeid={}, tdtypmod={}",
                        tdtypeid.to_u32(),
                        tdtypmod
                    );
                }
            }

            // Clean up the slot before returning
            pg_sys::ExecDropSingleTupleTableSlot(slot);

            // Increment call counter
            (*funcctx).call_cntr += 1;

            // For composite type SRF, use heap_copy_tuple_as_datum which properly
            // sets up the type information from the tuple descriptor.
            (*fcinfo).isnull = false;

            // Get the blessed tuple descriptor from function context
            let tuple_desc = (*funcctx).tuple_desc;

            eprintln!(
                "DEBUG: Returning heap tuple {:p} via heap_copy_tuple_as_datum with tupdesc {:p}",
                heap_tuple, tuple_desc
            );
            pgrx::info!(
                "DEBUG: Returning heap tuple {:p} via heap_copy_tuple_as_datum with tupdesc {:p}",
                heap_tuple,
                tuple_desc
            );

            // Use heap_copy_tuple_as_datum which sets the proper type info
            pg_sys::heap_copy_tuple_as_datum(heap_tuple, tuple_desc)
        } else {
            pg_sys::ExecDropSingleTupleTableSlot(slot);
            pg_sys::end_MultiFuncCall(fcinfo, funcctx);
            (*fcinfo).isnull = true;
            pg_sys::Datum::from(0)
        }
    } else {
        eprintln!("DEBUG: No more tuples - ending SRF");
        pgrx::info!("DEBUG: No more tuples - ending SRF");

        // Clean up
        pg_sys::ExecDropSingleTupleTableSlot(slot);
        if !tuplestore.is_null() {
            pg_sys::tuplestore_end(tuplestore);
        }

        pg_sys::end_MultiFuncCall(fcinfo, funcctx);
        (*fcinfo).isnull = true;
        pg_sys::Datum::from(0)
    }
}

/// Recursively validate all node types in a plan tree to catch corruption early
unsafe fn validate_plan_tree_node_types(plan: *mut pg_sys::Plan) {
    if plan.is_null() {
        return;
    }

    let node_type = (*plan).type_;
    eprintln!(
        "DEBUG: Validating plan node type: {:?} (value: {})",
        node_type, node_type as i32
    );

    // Check if this is a valid plan node type
    match node_type {
        pg_sys::NodeTag::T_SeqScan
        | pg_sys::NodeTag::T_Sort
        | pg_sys::NodeTag::T_Limit
        | pg_sys::NodeTag::T_Result
        | pg_sys::NodeTag::T_NestLoop
        | pg_sys::NodeTag::T_Agg
        | pg_sys::NodeTag::T_ValuesScan => {
            // Valid plan node type
        }
        _ => {
            eprintln!(
                "ERROR: Invalid plan node type detected: {:?} (value: {})",
                node_type, node_type as i32
            );
            if node_type as i32 == 124 {
                eprintln!("ERROR: Found the problematic node type 124 in plan tree!");
            }
        }
    }

    // Recursively validate child nodes
    if !(*plan).lefttree.is_null() {
        validate_plan_tree_node_types((*plan).lefttree);
    }
    if !(*plan).righttree.is_null() {
        validate_plan_tree_node_types((*plan).righttree);
    }

    // Validate target list expressions if present
    if !(*plan).targetlist.is_null() {
        validate_expression_list_node_types((*plan).targetlist);
    }

    // Validate qual expressions if present
    if !(*plan).qual.is_null() {
        validate_expression_list_node_types((*plan).qual);
    }
}

/// Validate node types in an expression list
unsafe fn validate_expression_list_node_types(list: *mut pg_sys::List) {
    if list.is_null() {
        return;
    }

    // Use PostgreSQL's list iteration for PostgreSQL 15+
    let length = (*list).length;
    for i in 0..length {
        let element = (*list).elements.offset(i as isize);
        if !element.is_null() {
            let node = (*element).ptr_value as *mut pg_sys::Node;
            if !node.is_null() {
                validate_expression_node_types(node);
            }
        }
    }
}

/// Validate node types in expression nodes
unsafe fn validate_expression_node_types(node: *mut pg_sys::Node) {
    if node.is_null() {
        return;
    }

    let node_type = (*node).type_;
    eprintln!(
        "DEBUG: Validating expression node type: {:?} (value: {})",
        node_type, node_type as i32
    );

    match node_type {
        pg_sys::NodeTag::T_TargetEntry
        | pg_sys::NodeTag::T_Var
        | pg_sys::NodeTag::T_Const
        | pg_sys::NodeTag::T_OpExpr
        | pg_sys::NodeTag::T_FuncExpr
        | pg_sys::NodeTag::T_BoolExpr
        | pg_sys::NodeTag::T_SubLink
        | pg_sys::NodeTag::T_Query
        | pg_sys::NodeTag::T_Aggref => {
            // Valid expression node type
        }
        _ => {
            eprintln!(
                "ERROR: Invalid expression node type detected: {:?} (value: {})",
                node_type, node_type as i32
            );
            if node_type as i32 == 124 {
                eprintln!("ERROR: Found the problematic node type 124 in expression!");
            }
        }
    }
}
