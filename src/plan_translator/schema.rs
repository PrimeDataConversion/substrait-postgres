use pgrx::pg_sys;

/// Schema information for a relation
/// Contains column type information that flows bottom-up through the plan tree
#[derive(Debug, Clone)]
pub struct RelationSchema {
    /// Column information indexed by column number (0-based)
    pub columns: Vec<ColumnInfo>,
}

/// Information about a single column in a relation
#[derive(Debug, Clone)]
pub struct ColumnInfo {
    /// PostgreSQL type OID
    pub type_oid: pg_sys::Oid,
    /// Type modifier (precision, length, etc.)
    pub typmod: i32,
    /// Collation OID
    pub collid: pg_sys::Oid,
    /// Column name (optional)
    pub name: Option<String>,
}

impl RelationSchema {
    /// Create a new empty schema
    pub fn new() -> Self {
        Self {
            columns: Vec::new(),
        }
    }

    /// Create schema with specified columns
    pub fn with_columns(columns: Vec<ColumnInfo>) -> Self {
        Self { columns }
    }

    /// Get column information by index (0-based)
    pub fn get_column(&self, index: usize) -> Option<&ColumnInfo> {
        self.columns.get(index)
    }

    /// Add a column to the schema
    pub fn add_column(&mut self, column: ColumnInfo) {
        self.columns.push(column);
    }

    /// Get the number of columns in this schema
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Create schema from PostgreSQL table OID by querying system catalogs
    pub unsafe fn from_table_oid(
        table_oid: pg_sys::Oid,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use super::expressions::resolve_column_type_info;

        let mut columns = Vec::new();

        // Get the relation descriptor for the table
        let relation = pg_sys::RelationIdGetRelation(table_oid);
        if relation.is_null() {
            return Err(format!("Table with OID {table_oid} not found").into());
        }

        let tuple_desc = (*relation).rd_att;
        let natts = (*tuple_desc).natts;

        // Iterate through all attributes (columns)
        for i in 0..natts {
            let attr = (*tuple_desc).attrs.as_ptr().offset(i as isize);
            if (*attr).attisdropped {
                continue; // Skip dropped columns
            }

            let attr_num = (*attr).attnum;
            let (type_oid, typmod, collid) = resolve_column_type_info(table_oid, attr_num)?;

            let name = std::ffi::CStr::from_ptr((*attr).attname.data.as_ptr())
                .to_string_lossy()
                .to_string();

            columns.push(ColumnInfo {
                type_oid,
                typmod,
                collid,
                name: Some(name),
            });
        }

        pg_sys::RelationClose(relation);

        Ok(Self::with_columns(columns))
    }
}

impl Default for RelationSchema {
    fn default() -> Self {
        Self::new()
    }
}

impl ColumnInfo {
    /// Create a new column info
    pub fn new(
        type_oid: pg_sys::Oid,
        typmod: i32,
        collid: pg_sys::Oid,
        name: Option<String>,
    ) -> Self {
        Self {
            type_oid,
            typmod,
            collid,
            name,
        }
    }

    /// Create column info with just type (using defaults for typmod and collid)
    pub fn with_type(type_oid: pg_sys::Oid) -> Self {
        Self {
            type_oid,
            typmod: -1, // Default typmod
            collid: pg_sys::DEFAULT_COLLATION_OID,
            name: None,
        }
    }
}
