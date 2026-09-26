const claims = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
jwt.verify(t, secret, { algorithms: ["HS256"], audience: "api" });
const p = jwt.verify(bearer, key, { algorithms: ["ES256"], issuer: "auth" });
const algorithms = ["RS256"];
return jwt.verify(token, getKey, { algorithms });
const decoded = jwt.decode(token);
