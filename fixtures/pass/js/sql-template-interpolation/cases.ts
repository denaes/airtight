const rows = await db.query("SELECT * FROM users WHERE id = $1", [id]);
const rows = await sql`SELECT * FROM users WHERE id = ${id}`;
const q = `SELECT * FROM users WHERE id = $1`;
const label = `Deleted ${count} rows`;
await conn.execute("UPDATE accounts SET balance = ? WHERE id = ?", [amt, id]);
const msg = `Found ${rows.length} results`;
