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

### Usage

```sql
-- Create the extension
CREATE EXTENSION substrait;

-- Execute a Substrait plan from JSON
SELECT from_substrait_json('{"version": "0.1", "plans": [...]}');

-- Execute a Substrait plan from protobuf (base64 encoded)
SELECT from_substrait('...');
```

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
