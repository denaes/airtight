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
- **Open redirects**: `redirect()` in Server Components or Server Actions directly taking `searchParams` without relative URL validation.
- **Client state / secret leakage**: Passing database objects from Server Components into Client Component props, which serializes them into public React Server Component (RSC) payload strings in the HTML.
- **Insecure SVG rendering**: Enabling `images.dangerouslyAllowSVG: true` in `next.config` without restricting `contentDispositionType: 'attachment'` or setting a restrictive CSP.

## Authorization Architecture: Middleware vs Server Components vs Server Actions

Next.js divides execution across three distinct server layers with fundamentally different security boundaries:

1. **`middleware.ts` (Edge runtime) & Auth Bypass Patterns**:
   - Evaluated before a request reaches page components or route handlers.
   - Ideal for coarse session detection and routing (e.g., redirecting unauthenticated users to `/login`).
   - **Never rely on `middleware.ts` as the sole authorization boundary.** Middleware path matching can be bypassed via:
     - **Flawed matcher regexes**: Matcher patterns that exclude static assets often inadvertently exclude API routes or dynamic paths (e.g., missing subpaths or extensions).
     - **Path normalization anomalies**: Discrepancies between URL normalization in Edge middleware and routing in Node.js (e.g., case sensitivity `/Admin` vs `/admin`, double slashes `//admin`, or URL-encoded path segments `/%2e%2e/admin`).
     - **RSC flight requests**: Client navigation uses internal RSC data fetches (`RSC: 1` header or `_next/data` requests). If middleware redirects page requests but fails to handle or block data requests, attackers can fetch raw component props directly.
     - **Header spoofing**: Trusting incoming `x-user-id` or `x-roles` headers added by middleware when the upstream reverse proxy does not strip them from external requests.
2. **Server Components (`page.tsx`)**:
   - Render HTML on the server.
   - Must perform explicit authorization checks before querying or displaying sensitive data. Never assume middleware has validated authorization.
3. **Server Actions (`'use server'`)**:
   - **Publicly accessible HTTP POST endpoints.** Next.js compiles every Server Action into an endpoint callable via POST with a `Next-Action` header containing an action ID hash.
   - **Action IDs are not secrets.** They are embedded in client HTML/JS and can be discovered by inspecting network traffic or bundles.
   - **UI hiding does not protect actions.** Even if a button is omitted from the UI for non-admin users, any client can send a POST request with the action ID and arbitrary arguments directly to the server.
   - **Every Server Action must authenticate the user (`auth()`, `getServerSession()`) and verify authorization on every invocation independently.**

## Secret Leakage Prevention & React Experimental Taint APIs

Passing sensitive backend data to the client is a major hazard in the App Router:

1. **RSC Serialization Hazard**:
   - When a Server Component passes props to a Client Component (`'use client'`), Next.js serializes the entire object into the RSC flight payload (the HTML stream).
   - Passing an ORM entity like `<UserProfile user={user} />` exposes all database fields (e.g., `password_hash`, `stripe_customer_id`, `mfa_secret`) to the client, even if the Client Component only renders `user.name`.
2. **React Experimental Taint APIs**:
   - React provides experimental APIs to block sensitive values from ever being passed to the client:
     - `experimental_taintObjectReference(message, object)`: Flags an entire object reference. If any Server Component attempts to pass this object to a Client Component, React throws an immediate runtime error.
       ```ts
       import { experimental_taintObjectReference } from 'react';
       export async function getUser(id: string) {
         const user = await db.user.findUnique({ where: { id } });
         experimental_taintObjectReference('Do not pass raw user records to client components', user);
         return user;
       }
       ```
     - `experimental_taintUniqueValue(message, lifetime, value)`: Flags a unique string or binary value (e.g., API keys, auth tokens) to prevent it from ever reaching the client payload.
   - Use `import 'server-only'` in data access modules so that any accidental import into a Client Component fails the build immediately.

## Top 5 Footguns

1. **Server Actions without authorization checks**: Defining a Server Action inside a protected UI page and assuming the page's route protection protects the action. An attacker can POST directly to any page with the `Next-Action` header and arbitrary IDs. Authentication and tenant scoping must be verified inside the action body.
2. **Secret leakage via `NEXT_PUBLIC_` prefix**: Any environment variable prefixed with `NEXT_PUBLIC_` is inlined into the client JavaScript bundle at build time. Private API keys, database connection strings, and webhook signing secrets must never use this prefix.
3. **Missing CSRF & Origin validation in Route Handlers**: While Next.js provides built-in Origin verification for Server Actions, custom Route Handlers (`app/api/**/route.ts`) processing `POST`/`PUT`/`DELETE` with cookie authentication do not have automatic CSRF defense. They require manual `Origin`/`Host` header validation or anti-CSRF tokens.
4. **Data leakage across the Server/Client Component boundary**: Passing whole ORM objects (`<ProfileCard user={user} />`) from a Server Component to a Client Component (`'use client'`). Next.js serializes the entire object into the RSC payload in the raw page HTML, exposing unrendered fields like `password_hash`, `stripe_customer_id`, or `two_factor_secret`. Use React taint APIs or explicit DTO mapping.
5. **Open redirects via `redirect()` with query parameters**: Calling `redirect(searchParams.get('returnTo'))` in Server Components or Server Actions without verifying that the destination is a safe relative URL (e.g. `dest.startsWith('/') && !dest.startsWith('//')`).
