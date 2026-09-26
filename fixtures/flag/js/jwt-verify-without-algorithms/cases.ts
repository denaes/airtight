const claims = jwt.verify(token, publicKey);
jwt.verify(t, secret, { audience: "api" });
const p = jwt.verify(bearer, key, { issuer: "auth" });
return jwt.verify(token, getKey);
