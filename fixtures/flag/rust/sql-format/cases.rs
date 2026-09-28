// True positive cases for rust/sql-format

fn flag_cases(id: &str, user: &str, table: &str) {
    // Case 1: sqlx::query with format! SELECT
    let _ = sqlx::query(&format!("SELECT * FROM users WHERE name = '{}'", user));

    // Case 2: diesel::sql_query with format! DELETE
    let _ = diesel::sql_query(format!("DELETE FROM orders WHERE id = {}", id));

    // Case 3: sqlx::query_as with format! INSERT
    let _ = sqlx::query_as::<_, User>(&format!("INSERT INTO {} VALUES ('{}')", table, user));

    // Case 4: sqlx::query with format! UPDATE
    let _ = sqlx::query(&format!("UPDATE accounts SET status = 'active' WHERE id = {}", id));

    // Case 5: diesel::sql_query with format! DROP
    let _ = diesel::sql_query(format!("DROP TABLE {}", table));
}
