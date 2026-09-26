cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
db.execute("DELETE FROM sessions WHERE token = :tok", {"tok": tok})
q = "UPDATE accounts SET balance = %s WHERE id = %s"
label = f"Found {count} rows"
cur.execute("INSERT INTO logs VALUES (%s)", (msg,))
msg = f"Deleted {n} sessions"
