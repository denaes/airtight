const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);
await conn.execute(`UPDATE accounts SET balance = ${amt} WHERE id = ${id}`);
const r = await pool.query(`DELETE FROM sessions WHERE token = ${token}`);
const q = `INSERT INTO logs (msg) VALUES (${JSON.stringify(msg)})`;
