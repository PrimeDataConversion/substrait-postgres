#!/usr/bin/env python3
"""Manually test the pg_substrait extension with a SQL query.

Converts a SQL query to a Substrait plan with DuckDB's substrait extension,
executes the plan in PostgreSQL via from_substrait_json(), and shows both
results side by side.

Run through the wrapper script so the pinned DuckDB version is used:

    ./scripts/manual-test.sh "SELECT n_name, count(*) FROM nation GROUP BY n_name"

Requires a running pgrx PostgreSQL with the extension and TPC-H data:

    cargo pgrx run pg17          # terminal 1; \\q leaves the server running
    ./scripts/setup-tpch.sh pg_substrait   # with PGPORT=28817

Environment: PGPORT (default 28817), PGDATABASE (default pg_substrait).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DUCKDB_FILE = REPO_ROOT / "target" / "manual-test.duckdb"
TPCH_TABLES = [
    "customer",
    "lineitem",
    "nation",
    "orders",
    "part",
    "partsupp",
    "region",
    "supplier",
]

# ---------------------------------------------------------------------------
# Schema derivation from the Substrait plan (mirrors the Rust test helper
# derive_rel_output_types in src/lib.rs).
# ---------------------------------------------------------------------------

TYPE_MAP = {
    "bool": "boolean",
    "i8": "smallint",
    "i16": "smallint",
    "i32": "integer",
    "i64": "bigint",
    "fp32": "real",
    "fp64": "double precision",
    "decimal": "numeric",
    "string": "text",
    "fixedChar": "text",
    "varchar": "text",
    "date": "date",
    "timestamp": "timestamp",
    "precisionTimestamp": "timestamp",
    "intervalYear": "interval",
    "intervalDay": "interval",
}


def substrait_type_to_pg(t):
    for key, pg in TYPE_MAP.items():
        if key in t:
            return pg
    raise ValueError(f"Unsupported Substrait type: {json.dumps(t)}")


LITERAL_MAP = {
    "boolean": "boolean",
    "i8": "smallint",
    "i16": "smallint",
    "i32": "integer",
    "i64": "bigint",
    "fp32": "real",
    "fp64": "double precision",
    "decimal": "numeric",
    "string": "text",
    "fixedChar": "text",
    "varChar": "text",
    "date": "date",
}


def derive_expr_type(expr, input_types):
    if "literal" in expr:
        for key, pg in LITERAL_MAP.items():
            if key in expr["literal"]:
                return pg
        raise ValueError(f"Unsupported literal: {json.dumps(expr['literal'])}")
    if "selection" in expr:
        field = (
            expr["selection"].get("directReference", {}).get("structField", {}).get("field", 0)
        )
        return input_types[field]
    if "scalarFunction" in expr:
        return substrait_type_to_pg(expr["scalarFunction"]["outputType"])
    if "cast" in expr:
        return substrait_type_to_pg(expr["cast"]["type"])
    if "ifThen" in expr:
        branch = expr["ifThen"]["ifs"][0].get("then") or expr["ifThen"].get("else")
        return derive_expr_type(branch, input_types)
    if "subquery" in expr:
        sq = expr["subquery"]
        if "scalar" in sq:
            return derive_rel_output_types(sq["scalar"]["input"])[0]
        return "boolean"
    raise ValueError(f"Unsupported expression: {json.dumps(expr)[:200]}")


def apply_emit(rel_body, types):
    emit = rel_body.get("common", {}).get("emit")
    if emit:
        return [types[i] for i in emit.get("outputMapping", [])]
    return types


def derive_rel_output_types(rel):
    if "read" in rel:
        body = rel["read"]
        struct = body.get("baseSchema", {}).get("struct", {})
        types = [substrait_type_to_pg(t) for t in struct.get("types", [])]
        # Apply the column projection (mask expression), if present.
        select = body.get("projection", {}).get("select")
        if select:
            types = [types[item.get("field", 0)] for item in select.get("structItems", [])]
        return apply_emit(body, types)
    for kind in ("filter", "sort", "fetch"):
        if kind in rel:
            body = rel[kind]
            return apply_emit(body, derive_rel_output_types(body["input"]))
    if "project" in rel:
        body = rel["project"]
        input_types = derive_rel_output_types(body["input"]) if "input" in body else []
        types = list(input_types)
        for expr in body.get("expressions", []):
            types.append(derive_expr_type(expr, input_types))
        return apply_emit(body, types)
    for kind in ("cross", "join"):
        if kind in rel:
            body = rel[kind]
            types = derive_rel_output_types(body["left"]) + derive_rel_output_types(
                body["right"]
            )
            return apply_emit(body, types)
    if "aggregate" in rel:
        body = rel["aggregate"]
        input_types = derive_rel_output_types(body["input"])
        types = []
        groupings = body.get("groupings", [])
        if groupings:
            for group_expr in groupings[0].get("groupingExpressions", []):
                types.append(derive_expr_type(group_expr, input_types))
        for measure in body.get("measures", []):
            types.append(substrait_type_to_pg(measure["measure"]["outputType"]))
        return apply_emit(body, types)
    raise ValueError(f"Unsupported relation: {list(rel.keys())}")


def derive_as_clause(plan):
    root = plan["relations"][0]["root"]
    names = root["names"]
    types = derive_rel_output_types(root["input"])
    if len(names) != len(types):
        raise ValueError(f"{len(names)} names but {len(types)} derived types")
    cols = ", ".join(f'"{n}" {t}' for n, t in zip(names, types))
    return f"t({cols})"


# ---------------------------------------------------------------------------
# DuckDB: TPC-H data + SQL -> Substrait JSON + reference results.
# ---------------------------------------------------------------------------


def duckdb_connect():
    import duckdb

    DUCKDB_FILE.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(DUCKDB_FILE))
    con.install_extension("substrait", repository="community")
    con.load_extension("substrait")

    existing = {r[0].lower() for r in con.execute("SHOW TABLES").fetchall()}
    if "nation" not in existing:
        print("Generating TPC-H data in DuckDB (sf=0.01)...", file=sys.stderr)
        con.execute("INSTALL tpch; LOAD tpch; CALL dbgen(sf=0.01)")
        # The PostgreSQL TPC-H tables are named in uppercase; rename so the
        # Substrait plans reference the same names. DuckDB resolves unquoted
        # identifiers case-insensitively, so queries can still say `nation`.
        for table in TPCH_TABLES:
            con.execute(f'ALTER TABLE {table} RENAME TO "{table.upper()}"')
    return con


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    sql = sys.argv[1]

    pghost = os.environ.get("PGHOST", "localhost")
    pgport = os.environ.get("PGPORT", "28817")
    pgdatabase = os.environ.get("PGDATABASE", "pg_substrait")

    con = duckdb_connect()

    plan_json = con.execute("FROM get_substrait_json(?)", [sql]).fetchone()[0]
    plan = json.loads(plan_json)
    as_clause = derive_as_clause(plan)

    print("=== Substrait plan (from DuckDB) ===")
    print(json.dumps(plan, indent=1)[:2000])
    if len(plan_json) > 2000:
        print(f"... ({len(plan_json)} bytes total)")
    print()
    print(f"=== AS clause (derived from plan) ===\n{as_clause}\n")

    # psql only interpolates :'var' in script input, not in -c commands,
    # so feed the query via stdin.
    pg_query = f"SELECT * FROM from_substrait_json(:'plan') AS {as_clause};\n"
    print("=== PostgreSQL result (via from_substrait_json) ===")
    sys.stdout.flush()
    result = subprocess.run(
        [
            "psql",
            "-X",
            "-h",
            pghost,
            "-p",
            pgport,
            "-d",
            pgdatabase,
            "-v",
            f"plan={plan_json}",
            "-v",
            "ON_ERROR_STOP=1",
        ],
        input=pg_query,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        print(
            f"\npsql failed. Is the server running (cargo pgrx run pg17, port {pgport}) "
            f"with the extension and TPC-H data loaded (./scripts/setup-tpch.sh {pgdatabase})?",
            file=sys.stderr,
        )
        sys.exit(1)
    # Suppress the extension's DEBUG chatter, keep the result table.
    for line in result.stdout.splitlines():
        if not line.startswith(("INFO:", "DEBUG:")):
            print(line)

    print("=== DuckDB result (reference) ===")
    print(con.execute(sql).fetchdf().to_string(index=False))


if __name__ == "__main__":
    main()
