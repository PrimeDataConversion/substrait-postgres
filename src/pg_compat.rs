//! Small shims over PostgreSQL APIs that changed between supported versions.

use pgrx::pg_sys;

/// Get attribute `i` (0-based) of a tuple descriptor.
///
/// PostgreSQL 18 moved the attribute array out of `TupleDescData.attrs`;
/// access goes through the `TupleDescAttr()` accessor instead.
#[cfg(any(feature = "pg16", feature = "pg17"))]
pub(crate) unsafe fn tupdesc_attr(
    tupdesc: pg_sys::TupleDesc,
    i: usize,
) -> *mut pg_sys::FormData_pg_attribute {
    (*tupdesc).attrs.as_mut_ptr().add(i)
}

/// Get attribute `i` (0-based) of a tuple descriptor.
#[cfg(feature = "pg18")]
pub(crate) unsafe fn tupdesc_attr(
    tupdesc: pg_sys::TupleDesc,
    i: usize,
) -> *mut pg_sys::FormData_pg_attribute {
    pg_sys::TupleDescAttr(tupdesc, i as i32)
}

/// Initialize the executor's range table.
///
/// PostgreSQL 18 added an `unpruned_relids` parameter tracking which range
/// table entries survived plan-time partition pruning; none of ours are
/// pruned, so all of them are unpruned (matching InitPlan()).
#[cfg(any(feature = "pg16", feature = "pg17"))]
pub(crate) unsafe fn exec_init_range_table(
    estate: *mut pg_sys::EState,
    rtable: *mut pg_sys::List,
    perminfos: *mut pg_sys::List,
) {
    pg_sys::ExecInitRangeTable(estate, rtable, perminfos);
}

/// Initialize the executor's range table.
#[cfg(feature = "pg18")]
pub(crate) unsafe fn exec_init_range_table(
    estate: *mut pg_sys::EState,
    rtable: *mut pg_sys::List,
    perminfos: *mut pg_sys::List,
) {
    let n = pg_sys::list_length(rtable);
    let unpruned_relids = if n > 0 {
        pg_sys::bms_add_range(std::ptr::null_mut(), 1, n)
    } else {
        std::ptr::null_mut()
    };
    pg_sys::ExecInitRangeTable(estate, rtable, perminfos, unpruned_relids);
}

/// Record whether a sort clause's `sortop` is a "greater than" (descending)
/// operator.
///
/// PostgreSQL 18 split the sort direction out of `sortop` into a separate
/// `reverse_sort` flag (`sortop` is now documented as the '<' operator). On
/// earlier versions the direction is carried entirely by `sortop`, so this is
/// a no-op there.
#[cfg(any(feature = "pg16", feature = "pg17"))]
pub(crate) unsafe fn set_sort_reverse(_sgc: *mut pg_sys::SortGroupClause, _reverse: bool) {}

/// Record whether a sort clause's `sortop` is a "greater than" (descending)
/// operator.
#[cfg(feature = "pg18")]
pub(crate) unsafe fn set_sort_reverse(sgc: *mut pg_sys::SortGroupClause, reverse: bool) {
    (*sgc).reverse_sort = reverse;
}
