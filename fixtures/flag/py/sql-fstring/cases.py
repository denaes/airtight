cur.execute(f"SELECT * FROM users WHERE id = {uid}")
db.execute(f"DELETE FROM sessions WHERE token = {tok}")
q = f"UPDATE accounts SET balance = {amt} WHERE id = {uid}"
cur.execute(f"INSERT INTO logs VALUES ({msg})")
