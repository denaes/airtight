res.cookie("sid", id, { httpOnly: false });
const opts = { httpOnly: false, secure: true };
session({ cookie: { httpOnly: false } });
res.cookie("token", t, { httpOnly : false, sameSite: "lax" });
