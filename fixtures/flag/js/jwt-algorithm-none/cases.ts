jwt.verify(token, key, { algorithms: ["none"] });
const opts = { algorithm: "none" };
jwt.sign(payload, null, { algorithm: "none" });
verify(t, k, { algorithms : ["none"] });
