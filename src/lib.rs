use pgrx::pg_sys::JumbleState;
use pgrx::prelude::*;
use pgrx::pg_sys;
use pgrx::guc::{GucContext, GucFlags, GucRegistry, GucSetting};
use std::cell::Cell;
use std::ffi::CString;

::pgrx::pg_module_magic!();

struct HookCell(Cell<pg_sys::post_parse_analyze_hook_type>);
unsafe impl Sync for HookCell {}

static PREV_HOOK: HookCell = HookCell(Cell::new(None));

static PG_WHERE_GUARD_ENABLED: GucSetting<bool> = GucSetting::<bool>::new(true);
static PG_WHERE_GUARD_PROTECT_TRUNCATE: GucSetting<bool> = GucSetting::<bool>::new(true);
static PG_WHERE_GUARD_ALLOWLIST: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(None);

unsafe fn pg_list_foreach<T, F>(list_ptr: *mut pg_sys::List, mut closure: F)
where
    F: FnMut(&T),
{
    if list_ptr.is_null() {
        return;
    }
    let len = pg_sys::list_length(list_ptr);
    if len <= 0 {
        return;
    }
    for i in 0..len {
        let cell = pg_sys::list_nth_cell(list_ptr, i);
        if cell.is_null() {
            continue;
        }
        let ptr = (*cell).ptr_value as *mut T;
        if ptr.is_null() {
            continue;
        }
        closure(&*ptr);
    }
}

unsafe fn is_relation_in_allowlist(query: &pg_sys::Query) -> bool {
    let allowlist_cstring = PG_WHERE_GUARD_ALLOWLIST.get();
    let allowlist_str = match allowlist_cstring.as_ref() {
        Some(cs) => match cs.to_str() {
            Ok(s) => s,
            Err(_) => return false,
        },
        None => return false,
    };
    if allowlist_str.is_empty() {
        return false;
    }

    let rt_index = query.resultRelation;
    if rt_index <= 0 || query.rtable.is_null() {
        return false;
    }

    let rte_ptr = pg_sys::list_nth(query.rtable, rt_index - 1) as *mut pg_sys::RangeTblEntry;
    if rte_ptr.is_null() {
        return false;
    }
    let rte = &*rte_ptr;
    let rel_id = rte.relid;
    if rel_id == pg_sys::Oid::INVALID {
        return false;
    }

    let rel_name_ptr = pg_sys::get_rel_name(rel_id);
    if rel_name_ptr.is_null() {
        return false;
    }
    let rel_name = std::ffi::CStr::from_ptr(rel_name_ptr)
        .to_str()
        .unwrap_or("")
        .to_lowercase();

    let namespace_oid = pg_sys::get_rel_namespace(rel_id);
    let ns_name_ptr = pg_sys::get_namespace_name(namespace_oid);
    let schema_name = if ns_name_ptr.is_null() {
        String::new()
    } else {
        std::ffi::CStr::from_ptr(ns_name_ptr)
            .to_str()
            .unwrap_or("")
            .to_lowercase()
    };

    for entry in allowlist_str.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let entry_lower = entry.to_lowercase();
        if let Some((schema_pat, table_pat)) = entry_lower.split_once('.') {
            if table_pat == "*" {
                if schema_pat == schema_name {
                    return true;
                }
            } else if schema_pat == schema_name && table_pat == rel_name {
                return true;
            }
        } else if entry_lower == rel_name {
            return true;
        }
    }

    false
}

unsafe fn get_target_relation_name(query: &pg_sys::Query) -> String {
    let rt_index = query.resultRelation;
    if rt_index <= 0 || query.rtable.is_null() {
        return String::from("<unknown>");
    }

    let rte_ptr = pg_sys::list_nth(query.rtable, rt_index - 1) as *mut pg_sys::RangeTblEntry;
    if rte_ptr.is_null() {
        return String::from("<unknown>");
    }
    let rte = &*rte_ptr;
    let rel_id = rte.relid;
    if rel_id == pg_sys::Oid::INVALID {
        return String::from("<unknown>");
    }

    let rel_name_ptr = pg_sys::get_rel_name(rel_id);
    if rel_name_ptr.is_null() {
        return String::from("<unknown>");
    }
    let rel_name = std::ffi::CStr::from_ptr(rel_name_ptr)
        .to_str()
        .unwrap_or("<unknown>");

    let namespace_oid = pg_sys::get_rel_namespace(rel_id);
    let ns_name_ptr = pg_sys::get_namespace_name(namespace_oid);
    if ns_name_ptr.is_null() {
        return rel_name.to_string();
    }
    let schema_name = std::ffi::CStr::from_ptr(ns_name_ptr)
        .to_str()
        .unwrap_or("");

    if schema_name.is_empty() || schema_name == "public" {
        rel_name.to_string()
    } else {
        format!("{schema_name}.{rel_name}")
    }
}

unsafe fn where_checker_internal(
    _pstate: *mut pg_sys::ParseState,
    query: *mut pg_sys::Query,
) {
    if query.is_null() || !PG_WHERE_GUARD_ENABLED.get() {
        return;
    }

    let query_ref = &*query;

    // TRUNCATE protection
    if query_ref.commandType == pg_sys::CmdType::CMD_UTILITY
        && !query_ref.utilityStmt.is_null()
        && PG_WHERE_GUARD_PROTECT_TRUNCATE.get()
    {
        let node_tag = (*query_ref.utilityStmt).type_;
        if node_tag == pg_sys::NodeTag::T_TruncateStmt {
            ereport!(
                ERROR,
                PgSqlErrorCode::ERRCODE_CARDINALITY_VIOLATION,
                "TRUNCATE is blocked by pg_where_guard"
            );
        }
    }

    // Handle Common Table Expressions (CTEs) recursively
    if query_ref.hasModifyingCTE && !query_ref.cteList.is_null() {
        pg_list_foreach::<pg_sys::CommonTableExpr, _>(query_ref.cteList, |cte| {
            if !cte.ctequery.is_null() {
                let cte_query = cte.ctequery as *mut pg_sys::Query;
                where_checker_internal(_pstate, cte_query);
            }
        });
    }

    // Check DELETE or UPDATE must have WHERE
    if !query_ref.jointree.is_null() {
        match query_ref.commandType {
            pg_sys::CmdType::CMD_DELETE => {
                let jointree = &*query_ref.jointree;
                if jointree.quals.is_null() {
                    if is_relation_in_allowlist(query_ref) {
                        return;
                    }
                    let msg = format!("DELETE on '{}' requires a WHERE clause", get_target_relation_name(query_ref));
                    ereport!(
                        ERROR,
                        PgSqlErrorCode::ERRCODE_CARDINALITY_VIOLATION,
                        msg.as_str()
                    );
                }
            }
            pg_sys::CmdType::CMD_UPDATE => {
                let jointree = &*query_ref.jointree;
                if jointree.quals.is_null() {
                    if is_relation_in_allowlist(query_ref) {
                        return;
                    }
                    let msg = format!("UPDATE on '{}' requires a WHERE clause", get_target_relation_name(query_ref));
                    ereport!(
                        ERROR,
                        PgSqlErrorCode::ERRCODE_CARDINALITY_VIOLATION,
                        msg.as_str()
                    );
                }
            }
            _ => {}
        }
    }
}

#[pg_guard]
unsafe extern "C-unwind" fn where_checker(
    pstate: *mut pg_sys::ParseState,
    query: *mut pg_sys::Query,
    jstate: *mut JumbleState,
) {
    if !PG_WHERE_GUARD_ENABLED.get() || query.is_null() {
        if let Some(prev_hook) = PREV_HOOK.0.get() {
            prev_hook(pstate, query, jstate);
        }
        return;
    }

    where_checker_internal(pstate, query);

    if let Some(prev_hook) = PREV_HOOK.0.get() {
        prev_hook(pstate, query, jstate);
    }
}

#[pg_guard]
pub unsafe extern "C-unwind" fn _PG_init() {
    GucRegistry::define_bool_guc(
        c"pg_where_guard.enabled",
        c"Enforce qualified updates",
        c"Prevent DML without a WHERE clause",
        &PG_WHERE_GUARD_ENABLED,
        GucContext::Userset,
        GucFlags::default(),
    );

    GucRegistry::define_bool_guc(
        c"pg_where_guard.protect_truncate",
        c"Block TRUNCATE statements",
        c"Prevent TRUNCATE when pg_where_guard is active",
        &PG_WHERE_GUARD_PROTECT_TRUNCATE,
        GucContext::Userset,
        GucFlags::default(),
    );

    GucRegistry::define_string_guc(
        c"pg_where_guard.allowlist",
        c"Tables/schemas to bypass WHERE guard",
        c"Comma-separated list: schema.table or schema.* patterns",
        &PG_WHERE_GUARD_ALLOWLIST,
        GucContext::Userset,
        GucFlags::default(),
    );

    PREV_HOOK.0.set(pg_sys::post_parse_analyze_hook);
    pg_sys::post_parse_analyze_hook = Some(where_checker);
}

#[pg_guard]
pub unsafe extern "C-unwind" fn _PG_fini() {
    pg_sys::post_parse_analyze_hook = PREV_HOOK.0.get();
}

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
        Spi::run("CREATE TABLE test_table (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_table VALUES (1, 'test')").unwrap();
        let result = Spi::run("DELETE FROM test_table WHERE id = 1");
        assert!(result.is_ok(), "DELETE with WHERE should succeed");
        Spi::run("DROP TABLE test_table").unwrap();
    }

    #[pg_test]
    fn test_update_with_where_should_succeed() {
        Spi::run("CREATE TABLE test_table (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_table VALUES (1, 'test')").unwrap();
        let result = Spi::run("UPDATE test_table SET name = 'updated' WHERE id = 1");
        assert!(result.is_ok(), "UPDATE with WHERE should succeed");
        Spi::run("DROP TABLE test_table").unwrap();
    }

    #[pg_test]
    fn test_select_should_always_work() {
        Spi::run("CREATE TABLE test_table (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_table VALUES (1, 'test')").unwrap();
        let result = Spi::run("SELECT * FROM test_table");
        assert!(result.is_ok(), "SELECT should always work");
        Spi::run("DROP TABLE test_table").unwrap();
    }

    #[pg_test]
    fn test_pg_where_guard_functions() {
        assert_eq!(crate::pg_where_guard_is_enabled(), true);
    }

    #[pg_test]
    fn test_delete_without_where_should_fail() {
        Spi::run("CREATE TEMP TABLE test_table (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_table VALUES (1, 'test')").unwrap();
        let result = std::panic::catch_unwind(|| {
            Spi::run("DELETE FROM test_table").unwrap();
        });
        assert!(result.is_err(), "DELETE without WHERE should fail when pg_where_guard is enabled");
    }

    #[pg_test]
    fn test_update_without_where_should_fail() {
        Spi::run("CREATE TEMP TABLE test_table2 (id int, name text)").unwrap();
        Spi::run("INSERT INTO test_table2 VALUES (1, 'test')").unwrap();
        let result = std::panic::catch_unwind(|| {
            Spi::run("UPDATE test_table2 SET name = 'updated'").unwrap();
        });
        assert!(result.is_err(), "UPDATE without WHERE should fail when pg_where_guard is enabled");
    }

    #[pg_test]
    fn test_session_disable_allows_delete() {
        Spi::run("CREATE TEMP TABLE test_sd (id int)").unwrap();
        Spi::run("INSERT INTO test_sd VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.enabled = off").unwrap();
        let result = Spi::run("DELETE FROM test_sd");
        assert!(result.is_ok(), "DELETE without WHERE should succeed when disabled via SET");
        Spi::run("SET pg_where_guard.enabled = on").unwrap();
    }

    #[pg_test]
    fn test_truncate_blocked_by_default() {
        Spi::run("CREATE TEMP TABLE test_trunc (id int)").unwrap();
        Spi::run("INSERT INTO test_trunc VALUES (1)").unwrap();
        let result = std::panic::catch_unwind(|| {
            Spi::run("TRUNCATE test_trunc").unwrap();
        });
        assert!(result.is_err(), "TRUNCATE should be blocked by default");
    }

    #[pg_test]
    fn test_truncate_allowed_when_guc_off() {
        Spi::run("CREATE TEMP TABLE test_trunc2 (id int)").unwrap();
        Spi::run("INSERT INTO test_trunc2 VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.protect_truncate = off").unwrap();
        let result = Spi::run("TRUNCATE test_trunc2");
        assert!(result.is_ok(), "TRUNCATE should succeed when protect_truncate is off");
        Spi::run("SET pg_where_guard.protect_truncate = on").unwrap();
    }

    #[pg_test]
    fn test_allowlist_bypasses_where_guard() {
        Spi::run("CREATE TEMP TABLE test_allow (id int)").unwrap();
        Spi::run("INSERT INTO test_allow VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.allowlist = 'test_allow'").unwrap();
        let result = Spi::run("DELETE FROM test_allow");
        assert!(result.is_ok(), "DELETE without WHERE should succeed for allowlisted table");
        Spi::run("SET pg_where_guard.allowlist = ''").unwrap();
    }

    #[pg_test]
    fn test_allowlist_schema_wildcard() {
        Spi::run("CREATE SCHEMA IF NOT EXISTS test_schema").unwrap();
        Spi::run("CREATE TABLE test_schema.allow_tbl (id int)").unwrap();
        Spi::run("INSERT INTO test_schema.allow_tbl VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.allowlist = 'test_schema.*'").unwrap();
        let result = Spi::run("DELETE FROM test_schema.allow_tbl");
        assert!(result.is_ok(), "DELETE should succeed for schema-wildcarded allowlist");
        Spi::run("SET pg_where_guard.allowlist = ''").unwrap();
        Spi::run("DROP TABLE test_schema.allow_tbl").unwrap();
        Spi::run("DROP SCHEMA test_schema").unwrap();
    }

    #[pg_test]
    fn test_cte_with_modifying_delete_blocked() {
        Spi::run("CREATE TEMP TABLE test_cte (id int)").unwrap();
        Spi::run("INSERT INTO test_cte VALUES (1), (2)").unwrap();
        let result = std::panic::catch_unwind(|| {
            Spi::run("WITH deleted AS (DELETE FROM test_cte RETURNING *) SELECT * FROM deleted").unwrap();
        });
        assert!(result.is_err(), "CTE with DELETE without WHERE should be blocked");
    }

    #[pg_test]
    fn test_cte_with_modifying_update_blocked() {
        Spi::run("CREATE TEMP TABLE test_cte_upd (id int, val int)").unwrap();
        Spi::run("INSERT INTO test_cte_upd VALUES (1, 10), (2, 20)").unwrap();
        let result = std::panic::catch_unwind(|| {
            Spi::run("WITH updated AS (UPDATE test_cte_upd SET val = 0 RETURNING *) SELECT * FROM updated").unwrap();
        });
        assert!(result.is_err(), "CTE with UPDATE without WHERE should be blocked");
    }

    #[pg_test]
    fn test_insert_without_where_should_succeed() {
        Spi::run("CREATE TEMP TABLE test_ins (id int)").unwrap();
        let result = Spi::run("INSERT INTO test_ins VALUES (1), (2), (3)");
        assert!(result.is_ok(), "INSERT should never be blocked by pg_where_guard");
    }

    #[pg_test]
    fn test_session_disable_allows_update() {
        Spi::run("CREATE TEMP TABLE test_sd_upd (id int, val text)").unwrap();
        Spi::run("INSERT INTO test_sd_upd VALUES (1, 'a'), (2, 'b')").unwrap();
        Spi::run("SET pg_where_guard.enabled = off").unwrap();
        let result = Spi::run("UPDATE test_sd_upd SET val = 'x'");
        assert!(result.is_ok(), "UPDATE without WHERE should succeed when disabled via SET");
        Spi::run("SET pg_where_guard.enabled = on").unwrap();
    }

    #[pg_test]
    fn test_session_disable_allows_truncate() {
        Spi::run("CREATE TEMP TABLE test_sd_trunc (id int)").unwrap();
        Spi::run("INSERT INTO test_sd_trunc VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.enabled = off").unwrap();
        let result = Spi::run("TRUNCATE test_sd_trunc");
        assert!(result.is_ok(), "TRUNCATE should succeed when pg_where_guard.enabled is off");
        Spi::run("SET pg_where_guard.enabled = on").unwrap();
    }

    #[pg_test]
    fn test_reenable_blocks_again() {
        Spi::run("CREATE TEMP TABLE test_re (id int)").unwrap();
        Spi::run("INSERT INTO test_re VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.enabled = off").unwrap();
        let _ = Spi::run("DELETE FROM test_re");
        Spi::run("INSERT INTO test_re VALUES (2)").unwrap();
        Spi::run("SET pg_where_guard.enabled = on").unwrap();
        let result = std::panic::catch_unwind(|| {
            Spi::run("DELETE FROM test_re").unwrap();
        });
        assert!(result.is_err(), "DELETE without WHERE should be blocked after re-enabling");
    }

    #[pg_test]
    fn test_allowlist_bypasses_update() {
        Spi::run("CREATE TEMP TABLE test_allow_upd (id int, val text)").unwrap();
        Spi::run("INSERT INTO test_allow_upd VALUES (1, 'a')").unwrap();
        Spi::run("SET pg_where_guard.allowlist = 'test_allow_upd'").unwrap();
        let result = Spi::run("UPDATE test_allow_upd SET val = 'b'");
        assert!(result.is_ok(), "UPDATE without WHERE should succeed for allowlisted table");
        Spi::run("SET pg_where_guard.allowlist = ''").unwrap();
    }

    #[pg_test]
    fn test_allowlist_exact_schema_table_match() {
        Spi::run("CREATE SCHEMA IF NOT EXISTS exact_schema").unwrap();
        Spi::run("CREATE TABLE exact_schema.target (id int)").unwrap();
        Spi::run("INSERT INTO exact_schema.target VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.allowlist = 'exact_schema.target'").unwrap();
        let result = Spi::run("DELETE FROM exact_schema.target");
        assert!(result.is_ok(), "DELETE should succeed for exact schema.table allowlist match");
        Spi::run("SET pg_where_guard.allowlist = ''").unwrap();
        Spi::run("DROP TABLE exact_schema.target").unwrap();
        Spi::run("DROP SCHEMA exact_schema").unwrap();
    }

    #[pg_test]
    fn test_allowlist_does_not_bypass_unlisted_table() {
        Spi::run("CREATE TEMP TABLE listed_tbl (id int)").unwrap();
        Spi::run("CREATE TEMP TABLE unlisted_tbl (id int)").unwrap();
        Spi::run("INSERT INTO unlisted_tbl VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.allowlist = 'listed_tbl'").unwrap();
        let result = std::panic::catch_unwind(|| {
            Spi::run("DELETE FROM unlisted_tbl").unwrap();
        });
        assert!(result.is_err(), "DELETE without WHERE should still fail for non-allowlisted table");
        Spi::run("SET pg_where_guard.allowlist = ''").unwrap();
    }

    #[pg_test]
    fn test_allowlist_multiple_entries() {
        Spi::run("CREATE TEMP TABLE multi_a (id int)").unwrap();
        Spi::run("CREATE TEMP TABLE multi_b (id int)").unwrap();
        Spi::run("INSERT INTO multi_a VALUES (1)").unwrap();
        Spi::run("INSERT INTO multi_b VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.allowlist = 'multi_a, multi_b'").unwrap();
        let result_a = Spi::run("DELETE FROM multi_a");
        let result_b = Spi::run("DELETE FROM multi_b");
        assert!(result_a.is_ok(), "DELETE should succeed for first entry in multi-entry allowlist");
        assert!(result_b.is_ok(), "DELETE should succeed for second entry in multi-entry allowlist");
        Spi::run("SET pg_where_guard.allowlist = ''").unwrap();
    }

    #[pg_test]
    fn test_allowlist_trims_whitespace() {
        Spi::run("CREATE TEMP TABLE spaced_tbl (id int)").unwrap();
        Spi::run("INSERT INTO spaced_tbl VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.allowlist = '  spaced_tbl  '").unwrap();
        let result = Spi::run("DELETE FROM spaced_tbl");
        assert!(result.is_ok(), "Allowlist should trim whitespace around entries");
        Spi::run("SET pg_where_guard.allowlist = ''").unwrap();
    }

    #[pg_test]
    fn test_allowlist_does_not_affect_truncate() {
        Spi::run("CREATE TEMP TABLE trunc_allow (id int)").unwrap();
        Spi::run("INSERT INTO trunc_allow VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.allowlist = 'trunc_allow'").unwrap();
        let result = std::panic::catch_unwind(|| {
            Spi::run("TRUNCATE trunc_allow").unwrap();
        });
        assert!(result.is_err(), "Allowlist should not bypass TRUNCATE protection");
        Spi::run("SET pg_where_guard.allowlist = ''").unwrap();
    }

    #[pg_test]
    fn test_delete_with_subquery_where_succeeds() {
        Spi::run("CREATE TEMP TABLE main_tbl (id int)").unwrap();
        Spi::run("CREATE TEMP TABLE ref_tbl (id int)").unwrap();
        Spi::run("INSERT INTO main_tbl VALUES (1), (2), (3)").unwrap();
        Spi::run("INSERT INTO ref_tbl VALUES (1)").unwrap();
        let result = Spi::run("DELETE FROM main_tbl WHERE id IN (SELECT id FROM ref_tbl)");
        assert!(result.is_ok(), "DELETE with subquery WHERE should succeed");
    }

    #[pg_test]
    fn test_update_with_subquery_where_succeeds() {
        Spi::run("CREATE TEMP TABLE upd_main (id int, val int)").unwrap();
        Spi::run("CREATE TEMP TABLE upd_ref (id int)").unwrap();
        Spi::run("INSERT INTO upd_main VALUES (1, 10), (2, 20)").unwrap();
        Spi::run("INSERT INTO upd_ref VALUES (1)").unwrap();
        let result = Spi::run("UPDATE upd_main SET val = 99 WHERE EXISTS (SELECT 1 FROM upd_ref WHERE upd_ref.id = upd_main.id)");
        assert!(result.is_ok(), "UPDATE with EXISTS subquery WHERE should succeed");
    }

    #[pg_test]
    fn test_delete_with_boolean_true_where_succeeds() {
        Spi::run("CREATE TEMP TABLE bool_tbl (id int)").unwrap();
        Spi::run("INSERT INTO bool_tbl VALUES (1)").unwrap();
        let result = Spi::run("DELETE FROM bool_tbl WHERE true");
        assert!(result.is_ok(), "DELETE with WHERE true should succeed (guard only checks presence of WHERE)");
    }

    #[pg_test]
    fn test_allowlist_case_insensitive() {
        Spi::run("CREATE TEMP TABLE casetbl (id int)").unwrap();
        Spi::run("INSERT INTO casetbl VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.allowlist = 'CASETBL'").unwrap();
        let result = Spi::run("DELETE FROM casetbl");
        assert!(result.is_ok(), "Allowlist matching should be case-insensitive");
        Spi::run("SET pg_where_guard.allowlist = ''").unwrap();
    }

    #[pg_test]
    fn test_empty_allowlist_does_not_bypass() {
        Spi::run("CREATE TEMP TABLE empty_al (id int)").unwrap();
        Spi::run("INSERT INTO empty_al VALUES (1)").unwrap();
        Spi::run("SET pg_where_guard.allowlist = ''").unwrap();
        let result = std::panic::catch_unwind(|| {
            Spi::run("DELETE FROM empty_al").unwrap();
        });
        assert!(result.is_err(), "Empty allowlist should not bypass the guard");
    }

    #[pg_test]
    fn test_cte_with_where_should_succeed() {
        Spi::run("CREATE TEMP TABLE test_cte_ok (id int)").unwrap();
        Spi::run("INSERT INTO test_cte_ok VALUES (1), (2), (3)").unwrap();
        let result = Spi::run("WITH deleted AS (DELETE FROM test_cte_ok WHERE id = 1 RETURNING *) SELECT * FROM deleted");
        assert!(result.is_ok(), "CTE with DELETE that has WHERE should succeed");
    }

    #[pg_test]
    fn test_update_multiple_columns_without_where_blocked() {
        Spi::run("CREATE TEMP TABLE multi_col (id int, a text, b text, c int)").unwrap();
        Spi::run("INSERT INTO multi_col VALUES (1, 'x', 'y', 10)").unwrap();
        let result = std::panic::catch_unwind(|| {
            Spi::run("UPDATE multi_col SET a = 'new', b = 'val', c = 99").unwrap();
        });
        assert!(result.is_err(), "UPDATE multiple columns without WHERE should be blocked");
    }
}

#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec![]
    }
}
