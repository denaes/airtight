const stmt1 = env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(userId);
const stmt2 = env.DB.prepare(`SELECT * FROM users WHERE id = ? AND status = ?`).bind(userId, 'active');
const stmt3 = env.DB.prepare(SELECT_USERS_QUERY).bind(limit);
const stmt4 = await db.prepare('SELECT * FROM items WHERE type = ?').bind(itemType).all();
const stmt5 = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
