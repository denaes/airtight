const re = new RegExp(escapeRegExp(req.query.pattern));
const filter = /^[a-z0-9-]+$/i;
if (name.includes(req.params.q)) return true;
const r = new RegExp("^" + PREFIX + "$");
const patterns = ALLOWED_PATTERNS[req.query.kind];
const safe = new RegExp(KNOWN_PATTERN);
