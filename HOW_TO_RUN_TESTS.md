# How to Run Tests

The correct syntax to run tests with pgrx is:

```bash
cargo pgrx test pg15 test_name_here
```

For example:
- `cargo pgrx test pg15 test_debug_tpch_q1_plan_translation`
- `cargo pgrx test pg15 test_debug_simple_seqscan_creation`

NOT:
- `cargo pgrx test test_name` (missing version)
- `cargo pgrx test --pgver 15 test_name` (wrong flag syntax)
