# Cloudflare Workers & Pages Security Card

Sources, sinks, authorization architecture, and common failure modes in Cloudflare Workers and Cloudflare Pages Functions.

## Sources (Untrusted Input)

- `request.url` / `new URL(request.url).searchParams`: URL path and query parameters parsed from incoming HTTP requests.
- `request.headers`: HTTP headers. While Cloudflare-injected headers (`CF-Connecting-IP`, `CF-Ray`, `CF-IPCountry`) can be trusted within the worker, client headers (`Host`, `Origin`, `Authorization`, `Cookie`) are untrusted.
- `request.json()`, `request.formData()`, `request.text()`: HTTP request body payloads.
- Pages Functions parameters: `context.params` dynamic route values (e.g., `functions/api/users/[id].ts` -> `context.params.id`).
- Cloudflare Storage Reads (KV, D1, R2): Any value stored from previous client requests must be treated as untrusted upon read.

## Dangerous Sinks

- **Edge SSRF (`fetch()`)**: `fetch(userInput)` targeting arbitrary URLs. Can probe internal origins, access Cloudflare Service Bindings, or abuse Worker egress IP reputation.
- **D1 SQL injection**: Passing interpolated strings into `env.DB.prepare(\`SELECT ... \${id}\`)` or `db.exec(query)`.
- **KV eventual consistency races**: Relying on KV for authorization state, rate limiting, or token revocation without accounting for edge replication delay (up to 60 seconds).
- **R2 object traversal & public exposure**: Generating unconstrained presigned URLs or serving R2 keys derived from untrusted path parameters without prefix validation.
- **`HTMLRewriter` XSS**: Modifying response streams and inserting unsanitized user content into element attributes or HTML tags.

## Execution Model & Storage Architecture

1. **V8 Isolate Execution Model**:
   - Cloudflare Workers run within lightweight V8 isolates rather than separate Node.js OS processes or containers.
   - There is no persistent filesystem and no `process` global.
   - **Isolate Reuse & State Bleeding**: A single V8 isolate can handle many sequential requests. Global/module-scoped variables (`let currentSession;`) persist across requests handled by that isolate. **Never store per-request or per-user data in global variables.**
2. **Storage & Bindings**:
   - **KV (Key-Value)**: Optimized for read-heavy workloads with eventual consistency. Do not use KV for concurrency control, balance checks, or real-time security locks.
   - **D1 (Serverless SQLite)**: Structured SQL storage. Always use parameterized queries with `.bind()`:
     ```ts
     const stmt = env.DB.prepare('SELECT * FROM users WHERE id = ? AND tenant_id = ?').bind(id, tenantId);
     const result = await stmt.first();
     ```
   - **R2 (Object Storage)**: S3-compatible storage. Validate user access before generating signed URLs or returning objects. Ensure buckets are not publicly exposed unless explicitly designed for public assets.
3. **Environment Configuration (`wrangler.toml` vs Secrets)**:
   - `[vars]` in `wrangler.toml` are plaintext and committed to source control. They should only contain non-sensitive configuration values (e.g., environment names, public URLs).
   - Sensitive credentials (API keys, database tokens, signing keys) must be provisioned using `wrangler secret put <NAME>` or via the Cloudflare dashboard. They are encrypted at rest and injected into `env.<NAME>` at runtime.
4. **Cloudflare Access JWT Validation**:
   - Applications behind Cloudflare Access receive identity via the `Cf-Access-Jwt-Assertion` header.
   - **Never rely solely on the presence or decoded claims of the header.** Workers must cryptographically verify the JWT:
     - Fetch the public keys from `https://<team-name>.cloudflareaccess.com/cdn-cgi/access/certs`.
     - Verify the signature algorithm (RS256).
     - Validate the `aud` claim matches the expected Application Audience (AUD) tag.
     - Validate `iss` matches `https://<team-name>.cloudflareaccess.com`.
     - Validate token expiration (`exp`).

## Top 5 Footguns

1. **Mutable global state bleeding across requests**: Declaring module-scoped variables (`let session;` or `const cache = {};`) to store request context. Because isolates are reused across requests, User A's session or sensitive data stored globally will bleed into User B's request when processed by the same isolate. Always pass context explicitly through parameters or `context.data`.
2. **Secrets stored in `wrangler.toml` `[vars]`**: Hardcoding private keys, webhook secrets, or API tokens in the `[vars]` section of `wrangler.toml`. This exposes credentials in version control and deployment logs. Always use `wrangler secret put`.
3. **D1 SQL injection via template literals**: Constructing SQLite queries with template literals (`env.DB.prepare(\`SELECT * FROM users WHERE email = '${email}'\`)`) instead of `.bind()`. D1 runs SQLite; attackers can execute arbitrary SQL statements and extract the entire database.
4. **Bypassing signature and audience validation on `Cf-Access-Jwt-Assertion`**: Simply decoding the base64 JWT payload without verifying its cryptographic signature and `aud` tag against Cloudflare Access certs. Any attacker can send a fabricated `Cf-Access-Jwt-Assertion` header with arbitrary user email claims if the Worker is reachable directly.
5. **Unvalidated Edge `fetch()` (SSRF)**: Passing user-controlled URLs directly to `fetch()` from edge functions. While Cloudflare isolates block local host connections (127.0.0.1), Workers can be used as open proxies to attack third-party hosts, access origin servers, or reach other Cloudflare bindings without egress restrictions. Always enforce strict URL scheme and domain allowlists.
