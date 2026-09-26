const hash = crypto.createHash("md5").update(password).digest("hex");
const h2 = crypto.createHash("sha1").update(password + salt).digest("hex");
return createHash("sha256").update(password).digest("base64");
const stored = crypto.createHash("sha512").update(passwd).digest("hex");
