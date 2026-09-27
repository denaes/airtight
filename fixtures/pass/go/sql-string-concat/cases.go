package main

import (
	"context"
	"database/sql"
	"fmt"
)

func safe(ctx context.Context, db *sql.DB, name, id, email, suffix string, count int) {
	_, _ = db.Query("SELECT * FROM users WHERE name = ?", name)
	_, _ = db.Exec("DELETE FROM items WHERE id = $1", id)
	_ = db.QueryRow("SELECT id FROM accounts WHERE email = ?", email)
	_ = fmt.Sprintf("Hello %s", name)
	_, _ = db.Query("SELECT * FROM users")
	_, _ = db.Exec("DELETE FROM items")
	const q = "SELECT id FROM users"
	msg := "Update your profile" + suffix
	selected := fmt.Sprintf("Selected %d items from list", count)
	_, _ = db.Query("SELECT id " + "FROM users WHERE id = ?", id)
	_ = q
	_ = msg
	_ = selected
}
