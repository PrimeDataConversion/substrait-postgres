# How to Run Tests

Tests run through pgrx against a specific PostgreSQL version (16, 17, or 18):

```bash
cargo pgrx test pg17
```

Run a single test by name:

```bash
cargo pgrx test pg17 test_scalar_subquery_minimal
```

Other supported versions:

```bash
cargo pgrx test pg16
cargo pgrx test pg18
```

Notes:
- The version argument is required (`cargo pgrx test test_name` alone will not
  work).
- The first run for a version builds PostgreSQL from source via
  `cargo pgrx init`; subsequent runs reuse it.
