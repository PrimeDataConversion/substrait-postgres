# Agent Development Notes

Guidance for AI coding agents (Claude, Gemini, etc.) working in this repository.

## Architecture

The extension exposes exactly two SQL functions, both returning `SETOF RECORD`:

- `from_substrait(plan bytea)` — execute a Substrait plan from protobuf
- `from_substrait_json(json_plan text)` — execute a Substrait plan from JSON

Both decode the plan, translate it to a PostgreSQL `Query` tree in the
`query_builder` module, run it through `standard_planner()`, and execute the
resulting plan manually as a set-returning function. Letting the standard
planner do the work is deliberate: it gives us join ordering, predicate
pushdown, index selection, and SubPlan/Param wiring for free.

### Dynamic return types (CRITICAL — DO NOT FORGET)

- `from_substrait()` / `from_substrait_json()` return `SETOF RECORD` with a
  **dynamic** column structure: the columns, types, and names are determined
  at runtime from the Substrait plan.
- **NEVER** create fixed-return-type wrapper functions — this defeats the
  entire purpose. The whole point is dynamic schema inference from the plan.

## Supported PostgreSQL versions

- Support PostgreSQL 16, 17, and 18 (`pg16`, `pg17`, `pg18` Cargo features).
- Older versions are deliberately unsupported: `RTEPermissionInfo` only exists
  in PG16+, and PG15 would require a second permission-handling path.
- Version-specific API differences live in `src/pg_compat.rs`, cfg-gated per
  feature. Add new shims there rather than scattering `#[cfg]` through the code.

## Things to do

1. Run tests before declaring partial victory (`cargo pgrx test pg17`; see
   `HOW_TO_RUN_TESTS.md`).
2. Run pre-commit before declaring a task done (`pre-commit run --all-files`).
3. Keep clippy clean — CI runs `cargo clippy ... -- -D warnings`.
4. Don't end lines with whitespace.
5. Always include a linefeed at the end of a file.
6. End sentence comments with a period.

## Common mistakes to avoid

1. **DO NOT** create wrapper functions with fixed return types.
2. **DO NOT** limit the schema to single columns or fixed structures.
3. **DO NOT** add external SQL functions beyond `from_substrait()` and
   `from_substrait_json()`.
4. **DO NOT** remove functionality to make tests pass.
5. **DO NOT** return an error as a shortcut to avoid implementing requested
   functionality — implement the feature properly.
6. When writing a test for a bug fix, confirm it fails without the fix first,
   then apply the fix and confirm it passes.

## Technical notes

- The executor path uses manual `CreateExecutorState` + `ExecInitNode` /
  `ExecProcNode` rather than `ExecutorStart`, because plans built
  programmatically need stricter setup. Mirror `ExecEndPlan` on teardown:
  `ExecEndNode`, then `ExecResetTupleTable`, then
  `ExecCloseRangeTableRelations`, or relations/descriptors leak.
- Use PostgreSQL API calls instead of hardcoded values when constructing plan
  nodes; after fixing crashes, verify OID handling is still correct.
- Crashes during execution usually come from improper plan/Query construction —
  debug the construction code, not the executor.
- `Aggref.args` must be a list of `TargetEntry` nodes (PG14+), not raw `Var`s.
- Use a `TTS_FLAG_EMPTY` flag check instead of the `TupIsNull` macro
  (`TupIsNull` is a C macro not available through pgrx).
- pg18 changed sort encoding: `SortGroupClause.sortop` is the `<` operator with
  a separate `reverse_sort` flag for DESC (see `pg_compat::set_sort_reverse`).
