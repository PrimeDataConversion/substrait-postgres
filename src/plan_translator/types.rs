use pgrx::pg_sys;

/// Result structure for query execution containing columns and data
#[derive(Debug)]
pub struct ExecutionResult {
    pub columns: Vec<ColumnInfo>,
    pub rows: Vec<Vec<pg_sys::Datum>>,
    pub nulls: Vec<Vec<bool>>,
}

/// Information about a column in the result set
#[derive(Debug)]
pub struct ColumnInfo {
    pub name: String,
    pub type_oid: pg_sys::Oid,
    pub type_mod: i32,
    pub attr_number: pg_sys::AttrNumber,
}
