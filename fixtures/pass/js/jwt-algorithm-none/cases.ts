jwt.verify(token, key, { algorithms: ["RS256"] });
const opts = { algorithm: "HS256" };
jwt.sign(payload, secret, { algorithm: "RS256" });
verify(t, k, { algorithms: ["ES256"] });
const allowed = ["RS256", "ES256"];
// the none algorithm is explicitly rejected below
