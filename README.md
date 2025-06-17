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

-- Execute a simple literal plan (AS clause is optional - schema is auto-detected)
SELECT * FROM from_substrait_json('{
  "version": {"minorNumber": 54},
  "relations": [{
    "root": {
      "names": ["result"],
      "input": {
        "project": {
          "expressions": [{
            "literal": {"i32": 42}
          }]
        }
      }
    }
  }]
}');
-- Returns: 42

-- Execute a plan with multiple columns (AS clause still optional)
SELECT * FROM from_substrait_json('{
  "version": {"minorNumber": 54},
  "relations": [{
    "root": {
      "names": ["num", "text"],
      "input": {
        "project": {
          "expressions": [
            {"literal": {"i32": 123}},
            {"literal": {"string": "hello"}}
          ]
        }
      }
    }
  }]
}');
-- Returns: 123 | hello

-- You can still use the AS clause for explicit type control (backward compatibility)
SELECT * FROM from_substrait_json('{
  "version": {"minorNumber": 54},
  "relations": [{
    "root": {
      "names": ["value"],
      "input": {
        "project": {
          "expressions": [{"literal": {"i32": 999}}]
        }
      }
    }
  }]
}') AS t(value int);
-- Returns: 999

-- Execute from binary protobuf (schema auto-detected)
SELECT * FROM from_substrait(decode('...', 'hex'));
```

### Available Functions

- `from_substrait(plan bytea) RETURNS SETOF RECORD` - Execute Substrait plans from protobuf binary format
- `from_substrait_json(json_plan text) RETURNS SETOF RECORD` - Execute Substrait plans from JSON format

Both functions return `SETOF RECORD` with **automatic schema detection**. The extension analyzes the Substrait plan to determine column names and types, so the AS clause is **optional**. You can still provide an AS clause for explicit type control or backward compatibility.

## Development

### Running Tests

```bash
# Run all tests (requires proper locale setup)
cargo pgrx test

# To set locale in your shell profile permanently:
# echo 'export LC_ALL=en_US.UTF-8' >> ~/.zshrc  # for zsh
# echo 'export LC_ALL=en_US.UTF-8' >> ~/.bashrc # for bash
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
