//! Query Builder Module
//!
//! Converts Substrait plans to PostgreSQL Query objects, which are then
//! passed to `standard_planner()` for optimization. This allows PostgreSQL's
//! optimizer to choose join strategies, push down predicates, and select indexes.

mod expressions;
mod relations;

use pgrx::pg_sys;
use std::collections::HashMap;

pub use relations::build_query_from_substrait;

/// Context for building a Query from a Substrait plan.
/// Tracks state as we traverse the Substrait plan tree and flatten it into
/// PostgreSQL's Query structure.
pub struct QueryBuildContext {
    /// Maps Substrait function reference IDs to function names.
    pub function_map: HashMap<u32, String>,

    /// The range table - list of all tables referenced in the query.
    /// Each entry is a RangeTblEntry pointer.
    pub rtable: Vec<*mut pg_sys::RangeTblEntry>,

    /// Permission info for each table RTE (PostgreSQL 17+).
    /// Each RTE_RELATION entry needs a corresponding RTEPermissionInfo.
    pub rteperminfos: Vec<*mut pg_sys::RTEPermissionInfo>,

    /// Maps table name to rtable index (1-based, as PostgreSQL uses).
    pub table_to_rtindex: HashMap<String, i32>,

    /// Column information for each rtable entry.
    /// rtindex (1-based) -> list of (column_name, type_oid, attnum).
    pub rtable_columns: HashMap<i32, Vec<ColumnRef>>,

    /// Counter for generating unique table aliases.
    alias_counter: u32,
}

/// Reference to a column in the query.
#[derive(Clone, Debug)]
pub struct ColumnRef {
    pub name: String,
    pub type_oid: pg_sys::Oid,
    pub attnum: i16,
    pub typmod: i32,
    pub collation: pg_sys::Oid,
}

impl QueryBuildContext {
    /// Create a new context from a Substrait plan's function extensions.
    pub fn new(function_map: HashMap<u32, String>) -> Self {
        Self {
            function_map,
            rtable: Vec::new(),
            rteperminfos: Vec::new(),
            table_to_rtindex: HashMap::new(),
            rtable_columns: HashMap::new(),
            alias_counter: 0,
        }
    }

    /// Add a table to the range table and return its rtindex (1-based).
    /// Also creates an RTEPermissionInfo entry for PostgreSQL 17+.
    pub unsafe fn add_table(
        &mut self,
        rte: *mut pg_sys::RangeTblEntry,
        name: &str,
        table_oid: pg_sys::Oid,
    ) -> i32 {
        self.rtable.push(rte);
        let rtindex = self.rtable.len() as i32; // 1-based

        // Create RTEPermissionInfo for this table (required in PG17+)
        let perminfo = self.create_rte_permission_info(table_oid, rtindex);
        self.rteperminfos.push(perminfo);

        // Set perminfoindex on the RTE (1-based index into rteperminfos)
        (*rte).perminfoindex = self.rteperminfos.len() as pg_sys::Index;

        self.table_to_rtindex.insert(name.to_string(), rtindex);
        rtindex
    }

    /// Create an RTEPermissionInfo for a table.
    unsafe fn create_rte_permission_info(
        &self,
        table_oid: pg_sys::Oid,
        _rtindex: i32,
    ) -> *mut pg_sys::RTEPermissionInfo {
        let perminfo = pgrx::PgBox::<pg_sys::RTEPermissionInfo>::alloc0();
        let perminfo = perminfo.into_pg();

        (*perminfo).type_ = pg_sys::NodeTag::T_RTEPermissionInfo;
        (*perminfo).relid = table_oid;
        (*perminfo).inh = true;
        (*perminfo).requiredPerms = pg_sys::ACL_SELECT as pg_sys::AclMode;
        (*perminfo).checkAsUser = pg_sys::InvalidOid;
        (*perminfo).selectedCols = std::ptr::null_mut();
        (*perminfo).insertedCols = std::ptr::null_mut();
        (*perminfo).updatedCols = std::ptr::null_mut();

        perminfo
    }

    /// Add a non-table RTE (like RTE_RESULT) that doesn't need permissions.
    pub fn add_non_table_rte(&mut self, rte: *mut pg_sys::RangeTblEntry, name: &str) -> i32 {
        self.rtable.push(rte);
        let rtindex = self.rtable.len() as i32;
        self.table_to_rtindex.insert(name.to_string(), rtindex);
        rtindex
    }

    /// Get the next unique alias for subqueries.
    pub fn next_alias(&mut self) -> String {
        self.alias_counter += 1;
        format!("__sq{}", self.alias_counter)
    }

    /// Build the rtable as a PostgreSQL List.
    pub unsafe fn build_rtable_list(&self) -> *mut pg_sys::List {
        let mut list: *mut pg_sys::List = std::ptr::null_mut();
        for rte in &self.rtable {
            list = pg_sys::lappend(list, *rte as *mut std::ffi::c_void);
        }
        list
    }

    /// Build the rteperminfos as a PostgreSQL List.
    pub unsafe fn build_rteperminfos_list(&self) -> *mut pg_sys::List {
        let mut list: *mut pg_sys::List = std::ptr::null_mut();
        for perminfo in &self.rteperminfos {
            list = pg_sys::lappend(list, *perminfo as *mut std::ffi::c_void);
        }
        list
    }

    /// Store column information for an rtable entry.
    pub fn set_columns(&mut self, rtindex: i32, columns: Vec<ColumnRef>) {
        self.rtable_columns.insert(rtindex, columns);
    }

    /// Get column information for an rtable entry.
    pub fn get_columns(&self, rtindex: i32) -> Option<&Vec<ColumnRef>> {
        self.rtable_columns.get(&rtindex)
    }
}

/// Result of converting a Substrait relation subtree.
/// Contains all the pieces needed to build part of a Query.
pub struct QueryParts {
    /// The FROM clause item - either a RangeTblRef or JoinExpr.
    pub from_item: *mut pg_sys::Node,

    /// Available columns after this relation (for expressions referencing it).
    pub available_columns: Vec<AvailableColumn>,

    /// Additional WHERE conditions from Filter relations.
    pub where_quals: Option<*mut pg_sys::Expr>,

    /// Target list entries (from Project relations).
    pub target_list: Option<*mut pg_sys::List>,

    /// GROUP BY clause (from Aggregate relations).
    pub group_clause: Option<*mut pg_sys::List>,

    /// Aggregate expressions that need to be in targetList.
    pub aggregates: Vec<*mut pg_sys::Aggref>,

    /// ORDER BY clause (from Sort relations).
    pub sort_clause: Option<*mut pg_sys::List>,

    /// LIMIT expression (from Fetch relations).
    pub limit_count: Option<*mut pg_sys::Node>,

    /// OFFSET expression (from Fetch relations).
    pub limit_offset: Option<*mut pg_sys::Node>,

    /// Whether this subtree contains aggregates.
    pub has_aggs: bool,
}

/// A column available for referencing in expressions.
#[derive(Clone, Debug)]
pub struct AvailableColumn {
    /// The rtable index (varno) - 1-based. 0 means computed expression.
    pub varno: i32,
    /// The attribute number (varattno) - 1-based.
    pub varattno: i16,
    /// Column name.
    pub name: String,
    /// PostgreSQL type OID.
    pub type_oid: pg_sys::Oid,
    /// Type modifier.
    pub typmod: i32,
    /// Collation OID.
    pub collation: pg_sys::Oid,
    /// For computed columns (varno=0), the actual expression to inline.
    /// This is a raw pointer that should be copyExpr'd when used.
    pub computed_expr: Option<*mut pg_sys::Expr>,
    /// Sort/group reference for GROUP BY columns. 0 means not a grouping column.
    pub ressortgroupref: u32,
}

impl QueryParts {
    /// Create empty QueryParts.
    pub fn empty() -> Self {
        Self {
            from_item: std::ptr::null_mut(),
            available_columns: Vec::new(),
            where_quals: None,
            target_list: None,
            group_clause: None,
            aggregates: Vec::new(),
            sort_clause: None,
            limit_count: None,
            limit_offset: None,
            has_aggs: false,
        }
    }
}
