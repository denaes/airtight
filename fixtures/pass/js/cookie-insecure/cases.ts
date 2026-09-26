res.cookie("sid", id, { secure: true });
const opts = { secure: true, httpOnly: true };
session({ cookie: { secure: process.env.NODE_ENV === "production" } });
const isSecure = false;
res.cookie("t", v, { secure: isProduction });
const secureDefault = true;
