const c = crypto.createCipheriv("aes-256-gcm", key, iv);
const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
const iv = crypto.randomBytes(12);
return crypto.createCipheriv(algo, key, iv);
const key = crypto.scryptSync(password, salt, 32);
// createCipher was removed in Node 22
