# Test Data

This directory contains test data for the PostgreSQL Substrait extension.

## TPC-H Test Data

The `tpch/` directory contains Substrait JSON query plans for TPC-H benchmark queries.

### Source
- Downloaded from: https://github.com/substrait-io/substrait-cpp/tree/main/src/substrait/textplan/data
- These are official Substrait query plans corresponding to TPC-H benchmark queries
- Query plans range from tpch-plan01.json to tpch-plan22.json (with some gaps)

### Usage

1. **Run tests**: Use `cargo test` or `cargo pgrx test pg15` to run the test suite
2. **Validate files**: The test suite includes validation of JSON structure and file integrity
3. **Test data**: TPC-H JSON files are included in the repository for immediate testing

### TPC-H Database Setup

To test against actual TPC-H data, you'll need to set up a TPC-H database:

1. **Clone a TPC-H generator**:
   ```bash
   git clone https://github.com/joaomcosta/pg-tpch-dbgen.git
   cd pg-tpch-dbgen
   ```

2. **Generate data**:
   ```bash
   # Compile dbgen
   make

   # Generate 1GB of data (scale factor 1)
   ./dbgen -s 1

   # Convert to PostgreSQL format and load
   # Follow the repository's instructions
   ```

3. **Alternative**: Use the PostgreSQL-optimized version:
   ```bash
   git clone https://github.com/jfeser/tpch-dbgen.git
   ```

### Test Structure

- `test_tpch_queries()` - Validates that TPC-H JSON files are present and well-formed
- `test_tpch_schema_setup()` - Creates minimal TPC-H schema for testing
- `test_from_substrait_json_*()` - Tests basic Substrait plan execution

### Future Enhancements

- [ ] Automated TPC-H database setup
- [ ] Golden result comparisons against other Substrait implementations
- [ ] Performance benchmarking
- [ ] Support for larger scale factors
- [ ] Cross-database result validation
