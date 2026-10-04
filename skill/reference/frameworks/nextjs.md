# Next.js Security Card

Sources, sinks, authorization architecture, and common failure modes across the Next.js App Router and Pages Router.

## Sources (Untrusted Input)

- `params` / `searchParams`: Dynamic route parameters and query strings in Server Components and Route Handlers. (In Next.js 15+, both are asynchronous Promises that must be awaited).
- `request.nextUrl.searchParams`, `request.json()`, `request.formData()`: In Route Handlers (`app/api/**/route.ts`).
- Server Action arguments & `formData`: In functions marked `'use server'`. Any argument or `formData.get(...)` passed from the client is untrusted and can be forged via direct POST requests.
- `headers()` / `cookies()`: Server-side read access to incoming client headers and cookies.
- Pages Router: `req.query`, `req.body`, `req.cookies` in `pages/api/**`.

## Dangerous Sinks

- **Direct database queries**: Raw SQL queries in Server Actions or Route Handlers via Prisma (`$queryRawUnsafe`), Drizzle (`sql.raw`), or native drivers.
- **RSC / JSX injection**: `dangerouslySetInnerHTML={{ __html: untrusted }}` in Server or Client Components.
- **Server-Side Request Forgery (SSRF)**: `fetch()` inside Server Components, Route Handlers, or Server Actions targeting user-supplied URLs without private IP filtering.
- **Command execution**: `child_process.exec()` or `spawn()` in Server Actions or Route Handlers running in the Node.js runtime.
- **Client state / secret leakage**: Returning sensitive fields or database objects from Server Components into Client Component props, which serializes them into public React Server Component (RSC) payload strings embedded in the HTML.

## Authorization Idiom: Middleware vs Route Handlers vs Server Components

Next.js divides execution across three distinct server layers with different security boundaries:

1. **`middleware.ts` (Edge runtime)**:
   - Evaluated before a request reaches page components or route handlers.
   - Ideal for coarse session detection, tenant routing, and redirection (e.g., redirecting unauthenticated users to `/login`).
   - **Never rely on `middleware.ts` as the sole authorization boundary.** Middleware path matching regexes can be bypassed via URL encoding anomalies, path normalization differences, or internal rewrites.
2. **Server Components (`page.tsx`)**:
   - Render HTML on the server.
   - Must perform explicit authorization checks before querying or displaying sensitive data. Do not assume middleware already enforced authorization.
3. **Server Actions (`'use server'`) & Route Handlers (`route.ts`)**:
   - **Publicly accessible HTTP endpoints.** Every Server Action generates an internal action ID and can be invoked directly with arbitrary POST payloads by anyone on the internet, completely bypassing the UI.
   - **Every Server Action and Route Handler must authenticate the user and verify object-level authorization independently within its own function body.**

## Top 5 Footguns

1. **Server Actions without authorization checks**: Defining a Server Action inside a protected UI page and assuming the page's route protection protects the action. An attacker can POST directly to `/_next/action/...` with any record ID. Authentication and tenant scoping must be verified inside the action.
2. **Secret leakage via `NEXT_PUBLIC_` prefix**: Any environment variable prefixed with `NEXT_PUBLIC_` is inlined into the client JavaScript bundle at build time. Private API keys, database connection strings, and webhook signing secrets must never use this prefix.
3. **Missing CSRF & Origin validation in Route Handlers**: While Next.js provides built-in Origin verification for Server Actions, custom Route Handlers (`app/api/**/route.ts`) processing `POST`/`PUT`/`DELETE` with cookie authentication do not have automatic CSRF defense. They require manual `Origin`/`Host` header validation or anti-CSRF tokens.
4. **Data leakage across the Server/Client Component boundary**: Passing whole ORM objects (`<ProfileCard user={user} />`) from a Server Component to a Client Component (`'use client'`). Next.js serializes the entire object into the RSC payload in the raw page HTML, exposing unrendered fields like `password_hash`, `stripe_customer_id`, or `two_factor_secret`.
5. **Route Segment Config & Cache Bleeding**: Setting `export const dynamic = 'force-static'` or `revalidate` on routes that fetch user-specific data. The server caches user A's private rendered HTML in shared caches (CDN or Vercel Data Cache) and serves it to user B.
