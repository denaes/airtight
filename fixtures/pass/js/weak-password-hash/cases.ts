const hash = await argon2.hash(password);
const hash2 = await bcrypt.hash(password, 12);
const etag = crypto.createHash("sha256").update(fileBuffer).digest("hex");
const checksum = createHash("md5").update(content).digest("hex");
const ok = await argon2.verify(stored, password);
const fingerprint = createHash("sha1").update(publicKey).digest("hex");
