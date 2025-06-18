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
