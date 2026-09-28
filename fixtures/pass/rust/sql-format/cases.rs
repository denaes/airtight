// False positive cases for rust/sql-format

fn pass_cases(id: i64, user: &str) {
    // Case 1: Parameterized query with sqlx bind
    let _ = sqlx::query("SELECT * FROM users WHERE id = $1").bind(id);

    // Case 2: Static diesel query
    let _ = diesel::sql_query("SELECT id, name FROM users");

    // Case 3: format! for non-SQL log message
    let _ = format!("Processing user {}", user);

    // Case 4: Static SQL string literal
    let query_str = "SELECT * FROM products WHERE in_stock = true";
    let _ = sqlx::query(query_str);

    // Case 5: Parameterized insert with diesel
    let _ = diesel::sql_query("INSERT INTO logs (event) VALUES ($1)").bind::<diesel::sql_types::Text, _>("login");

    // Case 6: print statement mentioning SQL
    println!("Running query: SELECT * FROM items");
}
