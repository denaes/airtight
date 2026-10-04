# Express Security Card

Sources, sinks, authorization patterns, and common failure modes in Express applications.

## Sources (Untrusted Input)

- `req.params`: URL route parameters (e.g., `/api/users/:id`). Always string types. Vulnerable to type assumption bugs if compared directly with numeric IDs without parsing.
- `req.query`: Parsed query string. By default, Express uses the `qs` library (extended query parsing). Enables object and array injection (e.g., `?id[$ne]=1`), causing type confusion or NoSQL injection unless `app.set('query parser', 'simple')` is configured.
- `req.body`: Parsed request payload populated by body-parser middleware (`express.json()`, `express.urlencoded()`, `multer`). Vulnerable to prototype pollution (`__proto__`, `constructor.prototype`) and mass assignment if passed directly to ORMs.
- `req.headers` / `req.rawHeaders`: HTTP request headers (normalized to lowercase). Spoofable proxy headers (`x-forwarded-for`, `x-forwarded-host`, `x-original-url`) cannot be trusted unless `app.set('trust proxy', ...)` is strictly configured with specific upstream proxy CIDRs.
- `req.cookies` / `req.signedCookies`: Populated by `cookie-parser`. Unsigned cookies can be manipulated arbitrarily by the client.

## Dangerous Sinks

- **Command execution**: `child_process.exec()`, `execSync()`, and `spawn()` with `shell: true`.
- **SQL / NoSQL injection**: Raw string interpolation in `pg`, `mysql2`, `sqlite3`, or Sequelize raw queries (`sequelize.query("... " + val)`). MongoDB / Mongoose query objects accepting unsanitized `req.body` or `req.query` without `$where` or operator sanitization.
- **Path traversal / arbitrary file read**: `res.sendFile(path)`, `res.download(path)`, `fs.readFile(path)` when constructed with unvalidated `req.params` or `req.query`.
- **Server-Side Request Forgery (SSRF)**: `fetch()`, `axios.get()`, `request()`, or `http.get()` pointing to user-supplied targets without RFC1918 / cloud metadata validation.
- **Reflected XSS**: `res.send(userInput)` automatically sets `Content-Type: text/html` if given a string, executing script tags in browser contexts. Unescaped template engines (`ejs` with `<%-`, `pug` unescaped `!=`).
- **Open redirect**: `res.redirect(req.query.next)` without validating against an allowed hostname list or enforcing relative paths starting with a single `/`.

## Authorization Idiom

- **Middleware chain ordering**: Middleware executes strictly in the order registered via `app.use()` or router handler lists.
- **Fail-closed middleware contract**: Every authentication or authorization middleware must explicitly terminate the request cycle on failure (`return res.status(401).json(...)` or `return next(err)`). Calling `res.status(401)...` without `return` allows subsequent handlers to execute.
- **Route registration bypasses**: Any route registered before an `app.use(authMiddleware)` boundary is completely unauthenticated. Common bypass: registering `app.use(express.static('public'))` or public health checks before authentication, allowing attackers to access internal static assets or routes.
- **Sub-router boundary leaks**: Mounting a sub-router at `app.use('/api', apiRouter)` requires auth middleware either on the mount point or within the router before all route definitions.

## Top 5 Footguns

1. **Missing `return` on auth middleware failure**: Writing `if (!req.user) res.status(401).json({ error: 'unauthorized' }); next();` instead of `return res.status(401)...`. Express continues execution into the route handler, executing sensitive business logic despite sending a 401 response.
2. **Static route and public middleware bypasses**: Mounting `app.use(express.static('public'))` before authentication middleware. If sensitive files (admin dashboards, reports, backup archives) exist in the public folder, they are served unauthenticated.
3. **Type confusion via `qs` extended query parsing**: `req.query.user` can be an object instead of a string if supplied as `?user[$regex]=.*`. Code doing `User.findOne({ name: req.query.user })` evaluates MongoDB regex queries or crashes synchronous string operations (`req.query.user.trim()`).
4. **Default HTML content type in `res.send()`**: Passing untrusted user strings to `res.send(untrusted)` causes Express to default to `Content-Type: text/html; charset=utf-8`, producing reflected XSS. Use `res.json()` or explicit `res.type('text/plain')`.
5. **Reverse proxy header spoofing (`trust proxy: true`)**: Setting `app.set('trust proxy', true)` trusts `X-Forwarded-*` headers from *any* client, allowing attackers to spoof client IP addresses for rate limiting, IP whitelisting, and multi-tenant domain routing.
