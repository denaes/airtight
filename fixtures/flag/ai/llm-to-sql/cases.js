const q = `SELECT * FROM users WHERE name = '${completion.text}'`;
await db.query(`DELETE FROM sessions WHERE id = ${response.content}`);
const query = "SELECT * FROM items WHERE id = " + llm_output;
const q2 = f"SELECT * FROM accounts WHERE status = '{response.text}'";
