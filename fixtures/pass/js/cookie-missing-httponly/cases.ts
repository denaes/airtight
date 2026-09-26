res.cookie("sid", id, { httpOnly: true });
const opts = { httpOnly: true, secure: true, sameSite: "strict" };
session({ cookie: { httpOnly: true } });
res.cookie("theme", theme, { sameSite: "lax" });
const httpOnlyRequired = true;
// httpOnly defaults to true in this wrapper
