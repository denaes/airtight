const q = "SELECT * FROM users WHERE name = '" + name + "'";
const q2 = "DELETE FROM sessions WHERE id = " + id;
db.query("UPDATE users SET email = " + email);
const q3 = "INSERT INTO t VALUES (" + value + ")";
