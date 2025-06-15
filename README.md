# Substrait PostgreSQL Extension

A PostgreSQL extension written in Rust that enables executing Substrait query plans using PostgreSQL's native execution engine, similar to DuckDB's `from_substrait` and `from_substrait_json` functions.

## Features

- `from_substrait(plan)` - Execute Substrait plans from protobuf format
- `from_substrait_json(json_plan)` - Execute Substrait plans from JSON format

## Installation

### Prerequisites

- PostgreSQL 13-17
- Rust toolchain
- cargo-pgrx

### Building

```bash
# Install cargo-pgrx
cargo install cargo-pgrx

# Initialize pgrx (replace pg16 with your PostgreSQL version)
cargo pgrx init --pg16 download

# Build and install the extension
cargo pgrx install --release
```

### Quick Start

#### Option 1: Using pgrx (Development)

```bash
# Install cargo-pgrx if not already installed
cargo install cargo-pgrx --version "=0.14.3"

# Initialize pgrx with your PostgreSQL version
cargo pgrx init --pg15 download  # or --pg16, --pg17

# Start PostgreSQL with the extension loaded
cargo pgrx run

# In another terminal, connect to the database
psql -h localhost -p 28815 -d pg_substrait
```

#### Option 2: Using System PostgreSQL

```bash
# Build and install the extension
cargo pgrx install --release

# Connect to your PostgreSQL database
psql -d your_database
```

#### Option 3: Using Docker

```bash
# Build the extension
cargo pgrx package

# Copy the generated files to your PostgreSQL Docker container
# (See target/release/pg_substrait-pg15/ for the files)
```

### Usage Examples

```sql
-- Create the extension
CREATE EXTENSION IF NOT EXISTS pg_substrait;

-- Test with a simple JSON plan (this will fail as expected - needs exactly 1 relation)
SELECT from_substrait_json('{"version": {"minorNumber": 54}, "relations": []}');
-- Error: Expected exactly 1 relation, found 0

-- Test with a valid JSON plan structure
SELECT from_substrait_json('{"version": {"minorNumber": 54}, "relations": [{"root": {"input": {"project": {"expressions": []}}}}]}');
-- Returns: Result: (empty result)

-- Test with binary protobuf data
SELECT from_substrait('\x00'::bytea);
-- Error: Failed to decode protobuf: failed to decode Protobuf message: invalid tag value: 0
```

### Available Functions

- `from_substrait(plan bytea)` - Execute Substrait plans from protobuf binary format
- `from_substrait_json(json_plan text)` - Execute Substrait plans from JSON format

Both functions return `text` containing the execution result or error message.

## Development

### Running Tests

```bash
# Run all tests
cargo pgrx test

# Run tests for specific PostgreSQL version
cargo pgrx test --features pg16
```

### Code Quality

This project uses pre-commit hooks to ensure code quality:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run hooks manually
pre-commit run --all-files
```
