#!/bin/bash
# Manually test the extension: SQL -> Substrait (DuckDB) -> PostgreSQL result.
#
# Usage:
#   ./scripts/manual-test.sh "SELECT n_name, count(*) AS cnt FROM nation GROUP BY n_name ORDER BY cnt DESC LIMIT 3"
#
# Prerequisites (one-time):
#   cargo pgrx run pg17                     # terminal 1: builds, installs, starts server + psql
#   CREATE EXTENSION pg_substrait;          # inside that psql (then \q; server keeps running)
#   PGPORT=28817 ./scripts/setup-tpch.sh pg_substrait   # load TPC-H data
#
# DuckDB's substrait extension is only published for DuckDB 1.2.x, so this
# pins the Python duckdb package rather than using the system CLI.
set -euo pipefail
cd "$(dirname "$0")/.."
exec uv run --quiet --with "duckdb==1.2.2" --with pandas python3 scripts/manual_test.py "$@"
