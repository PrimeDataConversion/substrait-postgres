# Claude Development Notes

## Key Architecture Decisions

### Dynamic Return Types (CRITICAL - DO NOT FORGET!)
- `from_substrait()` and `from_substrait_json()` return `SETOF RECORD` with **DYNAMIC** column structure
- The columns, types, and names are determined at runtime from the Substrait plan
- **NEVER** create fixed return type wrapper functions - this defeats the entire purpose
- The goal is to make AS clause optional through parse hooks that inject column definitions automatically
- Parse hooks analyze the Substrait plan at parse time to determine the output schema

### Parse Hooks Strategy
- Parse hooks intercept SQL during PostgreSQL's parsing phase
- Extract literal arguments (bytea for from_substrait, text for from_substrait_json)
- Execute/analyze the Substrait plan to determine output schema
- Inject column definitions into PostgreSQL's range table entry
- This allows PostgreSQL to know the return structure without requiring AS clause

### Current Status
- Parse hooks are implemented but may need debugging
- Functions currently require AS clause until parse hooks are fully working
- Tests exist to validate AS clause becomes optional when parse hooks work

## Common Mistakes to Avoid
1. **DO NOT** create wrapper functions with fixed return types
2. **DO NOT** limit the schema to single columns or fixed structures
3. **DO NOT** give up on parse hooks - they are the correct solution
4. The whole point is dynamic schema inference from Substrait plans
