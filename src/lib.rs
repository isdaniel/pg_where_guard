use pgrx::pg_sys::JumbleState;
use pgrx::prelude::*;
use pgrx::pg_sys;
use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting};

::pgrx::pg_module_magic!();

// Store the previous hook to maintain the hook chain
static mut PREV_POST_PARSE_ANALYZE_HOOK: pg_sys::post_parse_analyze_hook_type = None;

// GUC variable for pg_where_guard.enabled (default: true)
static PG_WHERE_GUARD_ENABLED: GucSetting<bool> = GucSetting::<bool>::new(true);

//pg_where_guard
unsafe fn pg_list_foreach<T, F>(list_ptr: *mut pg_sys::List, mut closure: F)
where
    F: FnMut(&T),
{
    if list_ptr.is_null() {
        return;
    }
    
    let list_len = pg_sys::list_length(list_ptr);
    for i in 0..list_len {
        let list_cell = pg_sys::list_nth_cell(list_ptr, i);
        if !list_cell.is_null() {
            let item_ptr = (&*list_cell).ptr_value as *mut T;
            if !item_ptr.is_null() {
                let item_ref = &*item_ptr;
                closure(item_ref);
            }
        }
    }
}


/// Hook function that checks if DELETE/UPDATE statements have WHERE clauses
#[pg_guard]
unsafe extern "C-unwind" fn where_checker(
    pstate: *mut pg_sys::ParseState,
    query: *mut pg_sys::Query,
    jstate: *mut JumbleState
) {
        // Check if pg_where_guard is enabled - if not, skip the check
    if !PG_WHERE_GUARD_ENABLED.get() || query.is_null() {
        if let Some(prev_hook) = PREV_POST_PARSE_ANALYZE_HOOK {
            prev_hook(pstate, query, jstate);
        }
        return;
    }

    let query_ref = &*query;

    // Handle Common Table Expressions (CTEs) recursively
    if query_ref.hasModifyingCTE && !query_ref.cteList.is_null() {
        pg_list_foreach::<pg_sys::CommonTableExpr, _>(query_ref.cteList, |cte| {
            if !cte.ctequery.is_null() {
                let cte_query = cte.ctequery as *mut pg_sys::Query;
                // Recursively check the CTE query
                where_checker(pstate, cte_query, jstate);
            }
        });
    }

    // Check the main query based on command type
    match query_ref.commandType {
        pg_sys::CmdType::CMD_DELETE => {
            // Assert that jointree is not null (like in C code)
            if !query_ref.jointree.is_null() {
                let jointree = &*query_ref.jointree;
                if jointree.quals.is_null() {
                    ereport!(
                        ERROR,
                        PgSqlErrorCode::ERRCODE_CARDINALITY_VIOLATION,
                        "DELETE requires a WHERE clause"
                    );
                }
            }
        }
        pg_sys::CmdType::CMD_UPDATE => {
            // Assert that jointree is not null (like in C code)
            if !query_ref.jointree.is_null() {
                let jointree = &*query_ref.jointree;
                if jointree.quals.is_null() {
                    ereport!(
                        ERROR,
                        PgSqlErrorCode::ERRCODE_CARDINALITY_VIOLATION,
                        "UPDATE requires a WHERE clause"
                    );
                }
            }
        }
        _ => {
            // Other command types are allowed
        }
    }

    // Call the previous hook if it exists (AFTER our checks, like in C code)
    if let Some(prev_hook) = PREV_POST_PARSE_ANALYZE_HOOK {
        prev_hook(pstate, query, jstate);
    }
}

/// Extension initialization function (equivalent to _PG_init in C)
#[pg_guard]
pub unsafe extern "C-unwind" fn _PG_init() {
    // Register the GUC variable for pg_where_guard.enabled
    GucRegistry::define_bool_guc(
        c"pg_where_guard.enabled",
        c"Enforce qualified updates",  
        c"Prevent DML without a WHERE clause",
        &PG_WHERE_GUARD_ENABLED,
        GucContext::Suset,  // PGC_SUSET - superuser can set
        GucFlags::default(),
    );

    // Store the previous hook and install our hook
    PREV_POST_PARSE_ANALYZE_HOOK = pg_sys::post_parse_analyze_hook;
    pg_sys::post_parse_analyze_hook = Some(where_checker);
}

/// Extension cleanup function
#[pg_guard]
pub unsafe extern "C-unwind" fn _PG_fini() {
    // Restore the previous hook
    pg_sys::post_parse_analyze_hook = PREV_POST_PARSE_ANALYZE_HOOK;
}

/// Function to check if pg_where_guard is enabled
#[pg_extern]
fn pg_where_guard_is_enabled() -> bool {
    PG_WHERE_GUARD_ENABLED.get()
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    #[pg_test]
    fn test_delete_with_where_should_succeed() {
        // This should succeed
        Spi::run("CREATE TABLE test_table (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_table VALUES (1, 'test')").unwrap();
        
        let result = Spi::run("DELETE FROM test_table WHERE id = 1");
        assert!(result.is_ok(), "DELETE with WHERE should succeed");
        
        Spi::run("DROP TABLE test_table").unwrap();
    }

    #[pg_test]
    fn test_update_with_where_should_succeed() {
        // This should succeed
        Spi::run("CREATE TABLE test_table (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_table VALUES (1, 'test')").unwrap();
        
        let result = Spi::run("UPDATE test_table SET name = 'updated' WHERE id = 1");
        assert!(result.is_ok(), "UPDATE with WHERE should succeed");
        
        Spi::run("DROP TABLE test_table").unwrap();
    }

    #[pg_test]
    fn test_select_should_always_work() {
        // SELECT statements should always work regardless of pg_where_guard setting
        Spi::run("CREATE TABLE test_table (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_table VALUES (1, 'test')").unwrap();
        
        let result = Spi::run("SELECT * FROM test_table");
        assert!(result.is_ok(), "SELECT should always work");
        
        Spi::run("DROP TABLE test_table").unwrap();
    }

    #[pg_test]
    fn test_pg_where_guard_functions() {
        // Test that pg_where_guard is enabled by default
        assert_eq!(crate::pg_where_guard_is_enabled(), true);
    }

    #[pg_test]
    fn test_delete_without_where_should_fail() {
        // This should fail when pg_where_guard is enabled (default)
        Spi::run("CREATE TEMP TABLE test_table (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_table VALUES (1, 'test')").unwrap();
        
        let result = std::panic::catch_unwind(|| {
            Spi::run("DELETE FROM test_table").unwrap();
        });
        
        assert!(result.is_err(), "DELETE without WHERE should fail when pg_where_guard is enabled");
    }

    #[pg_test]
    fn test_update_without_where_should_fail() {
        // This should fail when pg_where_guard is enabled (default)
        Spi::run("CREATE TEMP TABLE test_table2 (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_table2 VALUES (1, 'test')").unwrap();
        
        let result = std::panic::catch_unwind(|| {
            Spi::run("UPDATE test_table2 SET name = 'updated'").unwrap();
        });
        
        assert!(result.is_err(), "UPDATE without WHERE should fail when pg_where_guard is enabled");
    }
}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
