#!/bin/bash
set -e

# TPC-H Database Setup Script
# This script sets up a TPC-H database with scale factor 0.01 for testing
# Uses DuckDB to generate data and loads it into PostgreSQL via CSV

DB_NAME=${1:-postgres}
SCALE_FACTOR=${2:-0.01}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Setting up TPC-H database: $DB_NAME with scale factor: $SCALE_FACTOR"

# Check if required tools are available
if ! command -v duckdb &> /dev/null; then
    echo "Error: DuckDB is required but not installed"
    echo "Install with: brew install duckdb (macOS) or equivalent for your system"
    exit 1
fi

if ! command -v psql &> /dev/null; then
    echo "Error: PostgreSQL client (psql) is required but not installed"
    exit 1
fi

# Create temporary directory for data generation
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

TPCH_DB_PATH="$TEMP_DIR/tpch.db"
CSV_DIR="$TEMP_DIR/csv"
mkdir -p "$CSV_DIR"

echo "Generating TPC-H data with DuckDB and exporting to CSV..."

# Generate TPC-H data in DuckDB and export as CSV
duckdb "$TPCH_DB_PATH" << EOF
INSTALL tpch;
LOAD tpch;
CALL dbgen(sf = $SCALE_FACTOR);

-- Export all tables as CSV files
COPY lineitem TO '$CSV_DIR/lineitem.csv' (FORMAT CSV, HEADER);
COPY orders TO '$CSV_DIR/orders.csv' (FORMAT CSV, HEADER);
COPY customer TO '$CSV_DIR/customer.csv' (FORMAT CSV, HEADER);
COPY part TO '$CSV_DIR/part.csv' (FORMAT CSV, HEADER);
COPY supplier TO '$CSV_DIR/supplier.csv' (FORMAT CSV, HEADER);
COPY partsupp TO '$CSV_DIR/partsupp.csv' (FORMAT CSV, HEADER);
COPY nation TO '$CSV_DIR/nation.csv' (FORMAT CSV, HEADER);
COPY region TO '$CSV_DIR/region.csv' (FORMAT CSV, HEADER);
EOF

echo "Creating PostgreSQL tables and loading data..."

# Create TPC-H schema in PostgreSQL and load data
psql -d "$DB_NAME" << EOF
-- Drop existing tables if they exist
DROP TABLE IF EXISTS lineitem CASCADE;
DROP TABLE IF EXISTS orders CASCADE;
DROP TABLE IF EXISTS customer CASCADE;
DROP TABLE IF EXISTS part CASCADE;
DROP TABLE IF EXISTS supplier CASCADE;
DROP TABLE IF EXISTS partsupp CASCADE;
DROP TABLE IF EXISTS nation CASCADE;
DROP TABLE IF EXISTS region CASCADE;

-- Create TPC-H tables with proper schema
CREATE TABLE region (
    r_regionkey INTEGER NOT NULL,
    r_name CHAR(25) NOT NULL,
    r_comment VARCHAR(152)
);

CREATE TABLE nation (
    n_nationkey INTEGER NOT NULL,
    n_name CHAR(25) NOT NULL,
    n_regionkey INTEGER NOT NULL,
    n_comment VARCHAR(152)
);

CREATE TABLE supplier (
    s_suppkey INTEGER NOT NULL,
    s_name CHAR(25) NOT NULL,
    s_address VARCHAR(40) NOT NULL,
    s_nationkey INTEGER NOT NULL,
    s_phone CHAR(15) NOT NULL,
    s_acctbal DECIMAL(15,2) NOT NULL,
    s_comment VARCHAR(101) NOT NULL
);

CREATE TABLE customer (
    c_custkey INTEGER NOT NULL,
    c_name VARCHAR(25) NOT NULL,
    c_address VARCHAR(40) NOT NULL,
    c_nationkey INTEGER NOT NULL,
    c_phone CHAR(15) NOT NULL,
    c_acctbal DECIMAL(15,2) NOT NULL,
    c_mktsegment CHAR(10) NOT NULL,
    c_comment VARCHAR(117) NOT NULL
);

CREATE TABLE part (
    p_partkey INTEGER NOT NULL,
    p_name VARCHAR(55) NOT NULL,
    p_mfgr CHAR(25) NOT NULL,
    p_brand CHAR(10) NOT NULL,
    p_type VARCHAR(25) NOT NULL,
    p_size INTEGER NOT NULL,
    p_container CHAR(10) NOT NULL,
    p_retailprice DECIMAL(15,2) NOT NULL,
    p_comment VARCHAR(23) NOT NULL
);

CREATE TABLE partsupp (
    ps_partkey INTEGER NOT NULL,
    ps_suppkey INTEGER NOT NULL,
    ps_availqty INTEGER NOT NULL,
    ps_supplycost DECIMAL(15,2) NOT NULL,
    ps_comment VARCHAR(199) NOT NULL
);

CREATE TABLE orders (
    o_orderkey INTEGER NOT NULL,
    o_custkey INTEGER NOT NULL,
    o_orderstatus CHAR(1) NOT NULL,
    o_totalprice DECIMAL(15,2) NOT NULL,
    o_orderdate DATE NOT NULL,
    o_orderpriority CHAR(15) NOT NULL,
    o_clerk CHAR(15) NOT NULL,
    o_shippriority INTEGER NOT NULL,
    o_comment VARCHAR(79) NOT NULL
);

CREATE TABLE lineitem (
    l_orderkey INTEGER NOT NULL,
    l_partkey INTEGER NOT NULL,
    l_suppkey INTEGER NOT NULL,
    l_linenumber INTEGER NOT NULL,
    l_quantity DECIMAL(15,2) NOT NULL,
    l_extendedprice DECIMAL(15,2) NOT NULL,
    l_discount DECIMAL(15,2) NOT NULL,
    l_tax DECIMAL(15,2) NOT NULL,
    l_returnflag CHAR(1) NOT NULL,
    l_linestatus CHAR(1) NOT NULL,
    l_shipdate DATE NOT NULL,
    l_commitdate DATE NOT NULL,
    l_receiptdate DATE NOT NULL,
    l_shipinstruct CHAR(25) NOT NULL,
    l_shipmode CHAR(10) NOT NULL,
    l_comment VARCHAR(44) NOT NULL
);
EOF

# Load CSV data into PostgreSQL tables
echo "Loading CSV data into PostgreSQL tables..."

for table in region nation supplier customer part partsupp orders lineitem; do
    echo "Loading $table..."
    psql -d "$DB_NAME" -c "\\COPY $table FROM '$CSV_DIR/$table.csv' WITH (FORMAT CSV, HEADER);"
done

# Verify data was loaded
echo "Verifying data load..."
LINEITEM_COUNT=$(psql -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM lineitem;" | tr -d ' ')
echo "Loaded $LINEITEM_COUNT rows into lineitem table"

if [ "$LINEITEM_COUNT" -eq 0 ]; then
    echo "Warning: No data loaded. Check DuckDB and PostgreSQL connection."
    exit 1
fi

echo "TPC-H database setup completed successfully!"
