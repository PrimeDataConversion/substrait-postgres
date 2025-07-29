-- Test the pgrx-compatible SRF approach with get_call_result_type and AS clause
\c pg_substrait

-- Create test extension if needed
CREATE EXTENSION IF NOT EXISTS pg_substrait;

-- Test with hardcoded minimal plan (bypasses Substrait translation entirely)
SELECT * FROM test_minimal_srf() AS (result int);
