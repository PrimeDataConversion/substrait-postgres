# Claude Development Notes

## Key Architecture Decisions

### Dynamic Return Types (CRITICAL - DO NOT FORGET!)
- `from_substrait()` and `from_substrait_json()` return `SETOF RECORD` with **DYNAMIC** column structure
- The columns, types, and names are determined at runtime from the Substrait plan
- **NEVER** create fixed return type wrapper functions - this defeats the entire purpose

### Things to do
1. Run tests before declaring partial victory.
2. Run precommit before declaring victory over a task.
3. Don't end lines with whitespace.
4. Always include a linefeed at the end of a file.
5. End sentence comments with a period.

## Common Mistakes to Avoid
1. **DO NOT** create wrapper functions with fixed return types
2. **DO NOT** limit the schema to single columns or fixed structures
3. **DO NOT** give up on parse hooks - they are the correct solution
4. The whole point is dynamic schema inference from Substrait plans
5. Don't add external functions beyond `from_substrait()` and `from_substrait_json()`
6. **DO NOT** remove functionality to make tests pass.

## Technical Notes
- Use manual `ExecInitNode` initialization instead of `ExecutorStart` when constructing plans programmatically.
- Use PostgreSQL API calls instead of hardcoded values when constructing plan nodes.
- Support only PostgreSQL 17 (pg17), not multiple versions.
- After fixing crashes, verify OID handling is still correct - these issues are related.
- Crashes during execution are caused by improper plan construction - debug the plan construction code.
- AGGREF.args must be a list of TargetEntry nodes in PostgreSQL 14+, not raw Var nodes.
- Use TTS_FLAG_EMPTY flag check instead of TupIsNull macro (TupIsNull is a C macro not available in pgrx).
