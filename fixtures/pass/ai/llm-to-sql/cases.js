await db.query("SELECT * FROM users WHERE id = $1", [response.id]);
const query = f"SELECT * FROM items WHERE id = {user_id}";
const prompt = `Summarize the text: ${completion.text}`;
const label = "SELECT * FROM users";
cursor.execute("SELECT * FROM logs WHERE id = %s", (llm_output,));
