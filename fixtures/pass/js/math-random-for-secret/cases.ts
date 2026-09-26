const token = crypto.randomUUID();
const nonce = crypto.randomBytes(16).toString("base64url");
const otp = crypto.randomInt(100000, 999999);
const sessionId = crypto.randomUUID();
const salt = crypto.randomBytes(16);
const csrf = crypto.randomBytes(32).toString("hex");
