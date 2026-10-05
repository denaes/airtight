const stmt1 = env.DB.prepare(`SELECT * FROM users WHERE id = ${userId}`);
const stmt2 = env.DB.prepare("SELECT * FROM items WHERE category = '" + category + "'");
const stmt3 = await db.prepare(`DELETE FROM sessions WHERE token = '${token}'`).run();
const stmt4 = env.DATABASE.prepare('SELECT * FROM logs WHERE level = ' + logLevel);
const stmt5 = d1.prepare(prefix + " WHERE active = 1");
