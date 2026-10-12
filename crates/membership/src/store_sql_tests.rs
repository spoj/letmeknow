use super::*;
use rusqlite::{StatementStatus::{FullscanStep, Sort, VmStep}, types::Value, params_from_iter};

#[test]
fn locked_sqlite_uses_bounded_index_ranges_not_limit_scans() {
    assert_eq!(rusqlite::version(), "3.50.2");
    for population in [100, 50_000] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state");
        let store = Store::initialize(&path).unwrap();
        let db = store.db.lock().unwrap();
        db.execute_batch(&format!("BEGIN;
            WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<{population})
            INSERT INTO anchors SELECT CAST(printf('%032d',i) AS BLOB),1,zeroblob(32),1,
                CASE WHEN i%2=0 THEN 0 ELSE 100 END, i%2, i%2 FROM n;
            WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<{population})
            INSERT INTO records SELECT CAST(printf('%032d',i) AS BLOB),1,x'01',zeroblob(32),100 FROM n;
            WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<{population})
            INSERT INTO totals SELECT i,1,1 FROM n;
            COMMIT;")).unwrap();
        let d = vec![7; 32];
        for matches in [false, true] {
            if matches {
                db.execute("INSERT INTO anchors VALUES(?,3,zeroblob(32),1,0,3,3)", [&d]).unwrap();
                for p in 1..=3 {
                    db.execute("INSERT INTO records VALUES(?,?,x'01',zeroblob(32),0)", params![d, p]).unwrap();
                }
            }
            for (sql, values, index) in [
                (PRIVATE_EXPIRY, vec![Value::Integer(10), Value::Integer(EXPIRE_ROWS as i64)], "private_expiry"),
                (PUBLIC_EXPIRY, vec![Value::Integer(10)], "public_expiry"),
                (PUBLIC_RECORDS, vec![Value::Blob(d.clone()), Value::Integer(EXPIRE_ROWS as i64)], "PRIMARY KEY"),
                (READ_RECORDS, vec![Value::Blob(d.clone()), Value::Integer(0), Value::Integer(membership::PAGE_ROWS as i64)], "PRIMARY KEY"),
                (TOTALS, vec![Value::Integer(90), Value::Integer(97)], "INTEGER PRIMARY KEY"),
            ] {
                let plan: Vec<String> = db.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap()
                    .query_map(params_from_iter(&values), |r| r.get(3)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
                let plan = plan.join("; ");
                assert!(plan.contains("SEARCH") && plan.contains(index) && !plan.contains("TEMP"), "{plan}");
                let mut query = db.prepare(sql).unwrap();
                query.query_map(params_from_iter(&values), |_| Ok(())).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
                let work = (query.get_status(VmStep), query.get_status(FullscanStep), query.get_status(Sort));
                println!("population={population} matches={matches} index={index}: {work:?}; {plan}");
                assert!(work.0 < 200 && work.1 == 0 && work.2 == 0, "{work:?}");
            }
        }
        for (sql, values, index) in [
            (PRIVATE_EXPIRY, vec![Value::Integer(10), Value::Integer(EXPIRE_ROWS as i64)], "private_expiry"),
            (PUBLIC_EXPIRY, vec![Value::Integer(10)], "public_expiry"),
        ] {
            db.execute_batch(&format!("DROP INDEX {index}")).unwrap();
            let mut query = db.prepare(sql).unwrap();
            query.query_map(params_from_iter(&values), |_| Ok(())).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
            let work = (query.get_status(VmStep), query.get_status(FullscanStep), query.get_status(Sort));
            println!("negative population={population} removed={index}: {work:?}");
            assert!(work.0 > population * 3 && work.1 >= population && work.2 > 0, "index-removal negative control must discriminate: {work:?}");
        }
        drop(db);
        drop(store);
    }
}
