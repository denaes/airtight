const r = await fetch(`https://api.example.com/users/${encodeURIComponent(req.params.id)}`);
const allowed = ALLOWLIST[req.query.provider];
const res2 = await axios.get(allowed);
const url = resolveInternal(req.params.id);
got(url).then(handle);
const data = await fetch(CONFIG.endpoint);
