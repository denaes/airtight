export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const target = url.searchParams.get("target");
    if (target) {
      return await fetch(url.searchParams.get("target"));
    }
    const userId = url.searchParams.get("id");
    const stmt = env.DB.prepare(`SELECT * FROM users WHERE id = ${userId}`);
    const res = await stmt.all();
    return new Response(JSON.stringify(res), {
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
      },
    });
  },
};
