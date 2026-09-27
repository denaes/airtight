package main

import (
	"context"
	"database/sql"
	"fmt"
)

func vulnerable(ctx context.Context, db *sql.DB, tx *sql.Tx, name, id, email, role, token string) {
	_, _ = db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
	_, _ = db.Exec("DELETE FROM items WHERE id = " + id)
	_ = db.QueryRow(fmt.Sprintf("SELECT id FROM accounts WHERE email = '%s'", email))
	_, _ = tx.Query("UPDATE users SET role = '" + role + "' WHERE id = " + id)
	_, _ = tx.Exec(fmt.Sprintf("INSERT INTO logs (action) VALUES ('%s')", name))
	_ = db.QueryRowContext(ctx, fmt.Sprintf(`SELECT id FROM users WHERE token = '%s'`, token))
}
