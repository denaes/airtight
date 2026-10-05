# Nuxt 3 Security Card

Sources, sinks, Nitro server engine architecture, authorization patterns, and common failure modes in Nuxt 3 applications.

## Sources (Untrusted Input)

- `readBody(event)` / `readRawBody(event)`: Deserializes the JSON or form payload in server routes (`server/api/**`, `server/routes/**`). Unlike client-side forms, incoming payloads are completely unvalidated and can contain prototype pollution keys (`__proto__`, `constructor.prototype`), unexpected types (arrays or objects instead of strings), or missing properties.
- `getQuery(event)`: Parses query string parameters into an object. Vulnerable to type confusion (e.g. multiple parameters parsed as an array, or nested object manipulation) unless validated with a runtime schema (Zod/Valibot).
- `getRouterParam(event, name)` / `getRouterParams(event)`: Dynamic URL route parameters (e.g., `server/api/users/[id].ts`). Always returned as strings (or undefined).
- `getHeader(event, name)` / `getHeaders(event)`: HTTP request headers, including untrusted client headers (`x-forwarded-for`, `referer`, `origin`).
- `parseCookies(event)` / `getCookie(event, name)`: Parsed cookie values. Client-controlled and mutable unless signed or validated against a server-side session store.
- Route parameters & query strings in page components: `useRoute().params`, `useRoute().query`. In SSR mode, executed on the server; in SPA mode, executed in the client browser.

## Dangerous Sinks

- **Raw SQL / NoSQL queries**: String interpolation or concatenation into database query builders or raw drivers (`db.query(...)`, `prisma.$queryRawUnsafe(...)`) using `readBody(event)` or `getQuery(event)` data.
- **Nitro Storage KV traversal / key injection**: Passing unvalidated user input into `useStorage().getItem(key)`, `setItem(key, value)`, or `removeItem(key)`. Keys containing path separators (`/`, `..`) can traverse namespaces or overwrite critical app state, cached auth tokens, or rate limiters.
- **Server command execution**: Passing unvalidated body or query inputs into `child_process.exec()`, `execSync()`, or `spawn()` within server event handlers.
- **Arbitrary file operations**: Using `fs.readFile()` or `fs.writeFile()` with paths derived from `getRouterParam` or `readBody` without path normalization and directory boundary checks.
- **Server-Side Request Forgery (SSRF)**: `$fetch` or `fetch` within Nitro server handlers calling dynamic URLs supplied by the client without IP allowlisting or private range filtering.
- **Unescaped Vue template / HTML injection**: Using `v-html="untrustedContent"` in Vue templates or components, bypassing Vue's default template escaping and enabling cross-site scripting (XSS).
- **Public runtime config leakage**: Placing private API secrets or service credentials in `runtimeConfig.public` instead of root `runtimeConfig`.

## Nitro Server Engine & `defineEventHandler`

- Nuxt 3 decouples server logic into the Nitro engine. Server routes are placed in `server/api/**` (prefixed with `/api/`) and `server/routes/**` (mounted at root).
- Every server route exports `defineEventHandler(async (event) => { ... })`.
- **H3 Event Context**: The `event` object (`H3Event`) wraps Node's `IncomingMessage` and `ServerResponse` (`event.node.req`, `event.node.res`). Utility functions from `h3` (`readBody`, `getQuery`, `getCookie`, `setResponseStatus`, `sendRedirect`) are auto-imported.
- **Validation Discipline**: Nuxt/Nitro does not validate request bodies automatically. Schema validation must be applied explicitly at the entry of `defineEventHandler`:
  ```ts
  import { z } from 'zod';

  const userSchema = z.object({
    name: z.string().min(1).max(100),
    email: z.string().email(),
  });

  export default defineEventHandler(async (event) => {
    const body = await readValidatedBody(event, (b) => userSchema.parse(b));
    // body is now typed, stripped of excess fields, and safe to use
  });
  ```
- **Middleware Boundary**: Server middleware in `server/middleware/**` executes before every server route. However, server middleware runs on every request (including static assets and non-API routes) and does not protect client-side navigation between pages unless paired with client/universal route middleware (`middleware/**`).

## Nuxt Storage KV (`useStorage()`)

- Nitro includes a built-in multi-driver key-value storage layer accessed via `useStorage('namespace')` or `useStorage()`.
- Drivers include memory, redis, fs, http, cloudflare KV, and database backends.
- **Key Injection Hazard**: Keys are structured using colons or slashes as delimiters (e.g. `users:123:profile` or `cache/items`). When user-controlled values are interpolated into keys (`useStorage().getItem(\`sessions:${sessionId}\`)`), characters like `:`, `/`, or `..` can allow attackers to access keys in adjacent namespaces or escape base directories when using the `fs` driver.
- **Namespace isolation**: Always configure isolated base mounts for untrusted data and strictly sanitize keys with an allowlist (e.g. `sessionId.replace(/[^a-zA-Z0-9_-]/g, '')`).

## CSRF Protection in Nuxt 3

- Nuxt 3 does not enable cross-site request forgery (CSRF) protection on server routes by default.
- By default, Nitro server handlers process incoming `POST`, `PUT`, `DELETE` requests regardless of `Origin` or `Sec-Fetch-Site`. If cookie-based authentication is used without `SameSite=Strict`, attackers can trigger state-changing mutations via forged cross-origin forms.
- **Defenses**:
  - Configure `SameSite=Lax` or `SameSite=Strict` on session cookies.
  - Implement origin verification in a global server middleware:
    ```ts
    // server/middleware/csrf.ts
    export default defineEventHandler((event) => {
      const method = event.node.req.method?.toUpperCase();
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method || '')) {
        const origin = getHeader(event, 'origin');
        const host = getHeader(event, 'host');
        if (origin && new URL(origin).host !== host) {
          throw createError({ statusCode: 403, statusMessage: 'Cross-origin request forbidden' });
        }
      }
    });
    ```
  - Alternatively, use the `nuxt-csurf` module or custom anti-CSRF token verification for all mutation routes.

## Top 5 Footguns

1. **Direct interpolation of `readBody(event)` into sinks**: Passing raw properties from `await readBody(event)` directly into raw SQL queries, shell commands, or filesystem paths without schema validation or parameterization.
2. **Secrets exposed in `runtimeConfig.public`**: Placing sensitive server credentials (database URLs, private API keys, payment webhook secrets) under `runtimeConfig.public` in `nuxt.config.ts`. Everything under `.public` is exposed to the browser and bundled into client payloads.
3. **Over-reliance on `server/middleware` for page authorization**: Assuming server middleware in `server/middleware/` protects Vue page routes (`pages/**`). Server middleware only executes when the browser initiates a server request. Once Nuxt hydrates on the client, client-side route transitions do not re-run server middleware, bypassing route checks unless page-level route middleware (`definePageMeta({ middleware: 'auth' })`) is enforced.
4. **Nitro Storage key traversal (`useStorage`)**: Using user-supplied IDs directly as storage keys with the filesystem driver (`useStorage('data').getItem(params.id)`), allowing directory traversal (`../../etc/passwd`) or arbitrary file overwrite.
5. **Missing CSRF verification on Nitro mutation routes**: Accepting cookie-authenticated state mutations via `POST`/`DELETE` in `server/api/**` without verifying `Origin` or enforcing strict CSRF protection, exposing authenticated endpoints to cross-site form submissions.
