# pg_where_guard - PostgreSQL Extension (Rust/pgrx Implementation)

A PostgreSQL extension that prevents dangerous DELETE and UPDATE operations without WHERE clauses, implemented in Rust using the pgrx framework.

## Overview

The pg_where_guard extension protects your database from accidental data loss by:
- Blocking DELETE statements without WHERE clauses
- Blocking UPDATE statements without WHERE clauses
- Recursively checking Common Table Expressions (CTEs)
- Providing runtime configuration through PostgreSQL functions

## Features

- **DELETE Protection**: Prevents `DELETE FROM table` without WHERE clause
- **UPDATE Protection**: Prevents `UPDATE table SET ...` without WHERE clause
- **CTE Support**: Recursively checks Common Table Expressions
- **Hook Integration**: Uses PostgreSQL's `post_parse_analyze_hook` for query interception
- **Function Interface**: Provides functions to check and control the extension
- **Memory Safe**: Written in Rust with pgrx for safety and performance

## Technical Implementation

### Architecture

The extension implements a PostgreSQL hook that intercepts SQL queries after they are parsed and analyzed. It examines the query tree structure to detect DELETE and UPDATE operations that lack WHERE clauses.

### Key Components

1. **Hook Function** (`delete_needs_where_check`):
   - Intercepts queries via `post_parse_analyze_hook`
   - Checks command types (DELETE/UPDATE)
   - Validates presence of WHERE clauses
   - Handles Common Table Expressions recursively

2. **Query Analysis** (`check_query_for_where_clause`):
   - Examines the query's `jointree` structure
   - Looks for `quals` (qualification/WHERE conditions)
   - Throws errors for unqualified modifications

3. **Extension Functions**:
   - `pg_where_guard_is_enabled()`: Check if protection is active
   - `pg_where_guard_enable()`: Enable protection (always returns true in this implementation)

### Implementation Details

The Rust implementation uses pgrx to safely interface with PostgreSQL's C API:

```rust
// Hook registration in _PG_init
PREV_POST_PARSE_ANALYZE_HOOK = pg_sys::post_parse_analyze_hook;
pg_sys::post_parse_analyze_hook = Some(delete_needs_where_check);

// Query checking logic
match query.commandType {
    pg_sys::CmdType::CMD_DELETE => {
        if !query.jointree.is_null() {
            let jointree = &*query.jointree;
            if jointree.quals.is_null() {
                error!("DELETE requires a WHERE clause");
            }
        }
    }
    pg_sys::CmdType::CMD_UPDATE => {
        if !query.jointree.is_null() {
            let jointree = &*query.jointree;
            if jointree.quals.is_null() {
                error!("UPDATE requires a WHERE clause");
            }
        }
    }
    _ => {
        // Other command types are allowed
    }
}
```

## Installation

### Prerequisites

- Rust toolchain (1.70+)
- pgrx framework
- PostgreSQL development headers
- cargo-pgrx

### Build and Install

```bash
# Clone the repository
git clone <repository-url>
cd pg_where_guard

# Install cargo-pgrx if not already installed
cargo install cargo-pgrx

# Initialize pgrx for your PostgreSQL version
cargo pgrx init

# Install the extension
cargo pgrx install
```

### Testing

```bash
# Run the test suite
cargo pgrx test

# Test with specific PostgreSQL version
cargo pgrx test pg13
```

## Usage

### Installation in Database

```sql
-- Create the extension
CREATE EXTENSION pg_where_guard;
```

### Basic Usage

```sql
-- Load the extension
CREATE EXTENSION IF NOT EXISTS pg_where_guard;

-- Create a test table
CREATE TABLE test_table (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    value INTEGER DEFAULT 0
);

-- Insert some test data
INSERT INTO test_table (name, value) VALUES
    ('Alice', 100),
    ('Bob', 200),
    ('Charlie', 300);

-- Show the current data
SELECT * FROM test_table;

-- This should work: UPDATE with WHERE clause
UPDATE test_table SET value = 150 WHERE name = 'Alice';

-- This should work: DELETE with WHERE clause
DELETE FROM test_table WHERE name = 'Charlie';

-- Show the updated data
SELECT * FROM test_table;
-- These commands should FAIL due to pg_where_guard protection:

-- This should fail: UPDATE without WHERE clause
-- Uncomment the next line to test (it will cause an error):
-- UPDATE test_table SET value = 999;

-- This should fail: DELETE without WHERE clause  
-- Uncomment the next line to test (it will cause an error):
-- DELETE FROM test_table;

-- Clean up
DROP TABLE test_table;
DROP EXTENSION pg_where_guard;
```

### Extension Functions

```sql
-- Check if pg_where_guard is enabled
SELECT pg_where_guard_is_enabled();  -- Returns: true
```

## Development

### Project Structure

```
pg_where_guard/
├── Cargo.toml              # Rust project configuration
├── pg_where_guard.control  # PostgreSQL extension control file
├── src/
│   ├── lib.rs             # Main extension code
│   └── bin/
│       └── pgrx_embed.rs  # pgrx schema generation
├── sql/                   # SQL test scripts
└── tests/                 # Test files
```

## License

This project is licensed under the same terms as the original pg-safeupdate extension.

## Future Enhancements

- [ ] Full GUC integration (postgresql.conf configuration)
- [ ] Enhanced CTE handling with complete list traversal
- [ ] Configurable error messages
- [ ] Performance optimizations
- [ ] Support for additional PostgreSQL versions
- [ ] Whitelist functionality for specific tables/operations

---
