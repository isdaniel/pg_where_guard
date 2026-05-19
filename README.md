# pg_where_guard - PostgreSQL Extension (Rust/pgrx Implementation)

A PostgreSQL extension that prevents dangerous DELETE, UPDATE, and TRUNCATE operations without WHERE clauses, implemented in Rust using the pgrx framework.

## Overview

The pg_where_guard extension protects your database from accidental data loss by:
- Blocking DELETE statements without WHERE clauses
- Blocking UPDATE statements without WHERE clauses
- Blocking TRUNCATE statements (configurable)
- Recursively checking Common Table Expressions (CTEs)
- Providing session-level configuration through GUC parameters
- Supporting table/schema allowlists for selective bypass

## Features

- **DELETE Protection**: Prevents `DELETE FROM table` without WHERE clause
- **UPDATE Protection**: Prevents `UPDATE table SET ...` without WHERE clause
- **TRUNCATE Protection**: Blocks `TRUNCATE` statements by default
- **CTE Support**: Recursively checks Common Table Expressions
- **Session-Level Control**: Any user can enable/disable via `SET`
- **Table/Schema Allowlist**: Comma-separated patterns to bypass the guard
- **Hook Integration**: Uses PostgreSQL's `post_parse_analyze_hook` for query interception
- **Memory Safe**: Written in Rust with pgrx for safety and performance

## Supported PostgreSQL Versions

- PostgreSQL 14, 15, 16, 17, 18

## Installation

### Prerequisites

- Rust toolchain (1.70+)
- pgrx framework
- PostgreSQL development headers
- cargo-pgrx

### Build and Install

```bash
git clone <repository-url>
cd pg_where_guard

cargo install cargo-pgrx
cargo pgrx init
cargo pgrx install
```
## Usage

```sql
CREATE EXTENSION pg_where_guard;

-- These will be BLOCKED:
DELETE FROM users;                    -- ERROR: DELETE requires a WHERE clause
UPDATE users SET active = false;     -- ERROR: UPDATE requires a WHERE clause
TRUNCATE users;                      -- ERROR: TRUNCATE is blocked by pg_where_guard

-- These will SUCCEED:
DELETE FROM users WHERE id = 1;
UPDATE users SET active = false WHERE id = 1;
SELECT * FROM users;
```

## Configuration

| GUC Parameter | Type | Default | Context | Description |
|---------------|------|---------|---------|-------------|
| `pg_where_guard.enabled` | bool | `true` | userset | Enable/disable WHERE clause enforcement |
| `pg_where_guard.protect_truncate` | bool | `true` | userset | Block TRUNCATE statements |
| `pg_where_guard.allowlist` | string | `''` | userset | Comma-separated table/schema patterns to bypass (e.g., `staging.*, public.temp`) |

### Examples

```sql
-- Temporarily disable for a migration
SET pg_where_guard.enabled = off;
DELETE FROM old_data;
SET pg_where_guard.enabled = on;

-- Allow all operations on staging schema
SET pg_where_guard.allowlist = 'staging.*';
DELETE FROM staging.raw_data;  -- allowed

-- Allow specific table
SET pg_where_guard.allowlist = 'public.temp_import';
DELETE FROM public.temp_import;  -- allowed

-- Disable TRUNCATE protection
SET pg_where_guard.protect_truncate = off;
TRUNCATE staging_import;
SET pg_where_guard.protect_truncate = on;
```

### Allowlist Format

- `table_name` — match by table name (any schema)
- `schema.table` — match exact schema + table
- `schema.*` — match all tables in a schema
- Multiple patterns: comma-separated (`staging.*, public.temp`)

## Extension Functions

```sql
SELECT pg_where_guard_is_enabled();  -- Returns: true/false
```


## License

This project is licensed under the MIT License.
