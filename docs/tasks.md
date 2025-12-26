# Substrait-PostgreSQL Improvement Tasks

This document outlines actionable improvement tasks to enhance the substrait-postgres extension, focusing on making PostgreSQL plan construction and execution easier and more reliable.

## High Priority Tasks - Core Functionality

### [ ] 1. Consolidate Execution Functions in executor.rs
**Problem**: Multiple overlapping execution functions create confusion and potential bugs
**Files**: `src/executor.rs`
**Actions**:
- Merge `execute_plan_directly`, `execute_plan_directly_raw`, and `execute_plan_directly_from_ptr` into a single, well-defined function
- Remove duplicate logic and inconsistent parameter handling
- Establish clear contracts for when to use each execution path
- Add comprehensive documentation for the unified execution interface

### [ ] 2. Implement Comprehensive Error Handling Strategy
**Problem**: Inconsistent error handling across modules makes debugging difficult
**Files**: `src/lib.rs`, `src/executor.rs`, `src/plan_translator/translator.rs`
**Actions**:
- Define custom error types with context information
- Replace generic `Box<dyn Error + Send + Sync>` with structured error types
- Add error codes for different failure scenarios (parsing, translation, execution)
- Implement error recovery mechanisms where appropriate
- Add error logging with sufficient context for debugging

### [ ] 3. Reduce lib.rs Complexity
**Problem**: lib.rs has 4828 lines with extensive test code mixed with production code
**Files**: `src/lib.rs`
**Actions**:
- Extract test functions to separate test modules or integration tests
- Move utility functions to appropriate modules
- Create separate modules for SRF (Set Returning Function) handling
- Reduce main entry point functions to core logic only
- Implement proper separation of concerns

### [ ] 4. Optimize Memory Management in Executor
**Problem**: Potential memory leaks and inefficient resource cleanup
**Files**: `src/executor.rs`
**Actions**:
- Implement RAII patterns for PostgreSQL resources (tuplestore, tupledesc, etc.)
- Add proper cleanup in error paths
- Review and optimize memory allocation patterns
- Add memory usage monitoring for large result sets
- Implement streaming execution for large queries

## Medium Priority Tasks - Architecture & Performance

### [ ] 5. Modularize Large Expression Handling
**Problem**: expressions.rs is 1769 lines with many responsibilities
**Files**: `src/plan_translator/expressions.rs`
**Actions**:
- Split into separate modules: constants, functions, operators, type_conversions
- Extract common utilities to a shared module
- Implement expression visitor pattern for complex transformations
- Add expression caching mechanisms for repeated patterns
- Create expression validation framework

### [ ] 6. Implement Plan Validation Framework
**Problem**: Limited validation of generated PostgreSQL plans
**Files**: `src/plan_translator/translator.rs`, `src/executor.rs`
**Actions**:
- Create comprehensive plan validation before execution
- Add structural integrity checks for plan nodes
- Implement type compatibility validation
- Add range table consistency checks
- Create validation error reporting with plan context

### [ ] 7. Enhance Function Extension Mapping
**Problem**: Function mapping is basic and may not handle complex scenarios
**Files**: `src/plan_translator/relations.rs`
**Actions**:
- Implement function signature validation
- Add support for polymorphic functions
- Create function compatibility matrix
- Add runtime function discovery and registration
- Implement function alias and namespace support

### [ ] 8. Optimize Schema Information Handling
**Problem**: Schema operations may be inefficient for complex queries
**Files**: `src/plan_translator/schema.rs`, `src/plan_translator/types.rs`
**Actions**:
- Implement schema caching mechanisms
- Add lazy loading for schema information
- Optimize column type resolution
- Create schema version compatibility checks
- Add schema evolution support

## Medium Priority Tasks - Code Quality

### [ ] 9. Implement Comprehensive Logging Framework
**Problem**: Debugging relies on print statements and inconsistent logging
**Files**: All source files
**Actions**:
- Replace eprintln! and pgrx::info! with structured logging
- Add configurable log levels (trace, debug, info, warn, error)
- Implement query execution tracing
- Add performance metrics logging
- Create log analysis tools for debugging

### [ ] 10. Add Performance Benchmarking Suite
**Problem**: No systematic performance testing
**Files**: Create new `benches/` directory
**Actions**:
- Create microbenchmarks for expression conversion
- Add query execution performance tests
- Implement memory usage benchmarks
- Create regression testing framework
- Add automated performance monitoring

### [ ] 11. Enhance Type System Integration
**Problem**: Type conversion between Substrait and PostgreSQL may have edge cases
**Files**: `src/plan_translator/types.rs`
**Actions**:
- Add comprehensive type mapping documentation
- Implement bidirectional type conversion validation
- Add support for custom and user-defined types
- Create type coercion rules engine
- Implement type inference improvements

### [ ] 12. Create Plan Optimization Framework
**Problem**: Generated plans may not be optimal for PostgreSQL execution
**Files**: `src/plan_translator/plan_nodes.rs`
**Actions**:
- Implement plan rewrite rules for PostgreSQL optimization
- Add cost-based optimization hints
- Create plan statistics integration
- Implement join order optimization
- Add predicate pushdown optimizations

## Lower Priority Tasks - Developer Experience

### [ ] 13. Expand Test Coverage
**Problem**: Tests are concentrated in lib.rs rather than distributed appropriately
**Files**: Create `tests/` directory structure
**Actions**:
- Create unit tests for each module
- Add integration tests for end-to-end scenarios
- Implement property-based testing for expression conversion
- Create regression test suite for bug fixes
- Add performance regression tests

### [ ] 14. Improve Documentation and Examples
**Problem**: Limited documentation for complex scenarios
**Files**: `README.md`, create `docs/` directory
**Actions**:
- Create developer guide for extending the translator
- Add comprehensive API documentation
- Create example gallery for different query types
- Document troubleshooting common issues
- Add architectural decision records (ADRs)

### [ ] 15. Implement Configuration Management
**Problem**: No runtime configuration options
**Files**: Create new configuration module
**Actions**:
- Add GUC (Grand Unified Configuration) parameters for PostgreSQL
- Implement query timeout configuration
- Add memory limit configuration options
- Create debugging mode switches
- Implement feature flags for experimental functionality

### [ ] 16. Create Development Tooling
**Problem**: Limited development and debugging tools
**Files**: Create `scripts/` and `tools/` directories
**Actions**:
- Create plan visualization tools
- Add query analysis utilities
- Implement debugging helpers
- Create performance profiling scripts
- Add automated testing scripts

### [ ] 17. Enhance Cross-Version Compatibility
**Problem**: PostgreSQL version compatibility may have issues
**Files**: All source files, `Cargo.toml`
**Actions**:
- Test and fix compatibility across PostgreSQL 13-17
- Add version-specific feature detection
- Implement backward compatibility layers
- Create version migration guides
- Add automated multi-version testing

## Specialized Tasks - PostgreSQL Integration

### [ ] 18. Implement Parallel Query Support
**Problem**: No parallel execution support for complex queries
**Files**: `src/executor.rs`, `src/plan_translator/plan_nodes.rs`
**Actions**:
- Add parallel plan generation
- Implement worker process coordination
- Create parallel-safe expression evaluation
- Add parallel aggregation support
- Optimize data transfer between workers

### [ ] 19. Add Transaction and Isolation Support
**Problem**: Limited transaction context awareness
**Files**: `src/executor.rs`
**Actions**:
- Implement proper transaction context handling
- Add isolation level awareness
- Create snapshot consistency mechanisms
- Implement proper locking strategies
- Add distributed transaction support considerations

### [ ] 20. Enhance Security and Permissions
**Problem**: Limited security model integration
**Files**: `src/lib.rs`, create security module
**Actions**:
- Implement row-level security integration
- Add permission checking for table access
- Create secure function execution context
- Add audit logging capabilities
- Implement data masking and filtering

## Progress Tracking

- **Total Tasks**: 20
- **High Priority**: 4 tasks
- **Medium Priority**: 12 tasks
- **Lower Priority**: 4 tasks
- **Completed**: 0 tasks

## Implementation Guidelines

1. **Start with High Priority tasks** - These address core functionality issues that directly impact the goal of easier PostgreSQL plan construction and execution
2. **Test thoroughly** - Each task should include comprehensive testing to ensure reliability
3. **Document changes** - Update documentation and add inline comments for complex logic
4. **Performance considerations** - Always consider the performance impact of changes
5. **Backwards compatibility** - Ensure changes don't break existing functionality unless explicitly planned
6. **Code review** - Have changes reviewed by team members familiar with PostgreSQL internals

## Success Metrics

- Reduced complexity in core execution paths
- Improved error messages and debugging experience
- Better performance for complex queries
- Increased test coverage and reliability
- Enhanced developer documentation and examples
- Easier integration with PostgreSQL ecosystem tools
