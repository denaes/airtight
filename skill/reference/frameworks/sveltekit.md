# SvelteKit Security Card

Sources, sinks, authorization patterns, form actions, and common failure modes in SvelteKit applications.

## Sources (Untrusted Input)

- `request.formData()`: Form action and endpoint inputs. Untrusted strings and file objects (`File`). Prone to missing validation, type assumptions, and mass-assignment.
- `request.json()`: JSON payloads in standalone API endpoints (`+server.ts`).
- `params`: Dynamic route parameters (e.g. `src/routes/users/[id]/+page.server.ts`). Always strings; must be validated before numeric database queries.
- `url.searchParams`: URL query string parameters in `load` functions or endpoints.
- `cookies.get(name)`: Cookie values read on the server.
- `event.request.headers`: HTTP headers (including `origin`, `referer`, `x-forwarded-for`).

## Dangerous Sinks

- **Direct database queries without tenancy checks**: Raw SQL queries or ORM queries in `load` functions (`+page.server.ts`) or form actions (`actions`) that retrieve records without filtering by authenticated user or tenant ID.
- **Command execution**: Passing untrusted inputs into `child_process.exec()` or `spawn()` in server endpoints or form actions.
- **Server-Side Request Forgery (SSRF)**: Custom `fetch()` inside server `load` or actions querying attacker-controlled URLs without validating against private RFC1918 networks and cloud metadata endpoints.
- **Arbitrary file access**: `fs.readFile()` or `fs.writeFile()` using filenames or paths derived from `params` or form data without path traversal safeguards.
- **XSS via `{@html ...}`**: Rendering unescaped HTML strings in Svelte templates using the `{@html untrusted}` tag, bypassing Svelte's default string escaping.
- **Client environment variable leakage**: Importing private server secrets into client components. Only variables prefixed with `PUBLIC_` (or from `$env/static/public` / `$env/dynamic/public`) should reach the client.

## Form Actions (`+page.server.ts`) & CSRF Protection

- SvelteKit uses form actions (`export const actions = { default: ..., login: ... }`) in `+page.server.ts` for handling data mutations.
- **Built-in CSRF Protection**: SvelteKit provides automatic CSRF protection for form actions by verifying that the request's `Origin` header matches the server's origin.
  - SvelteKit rejects cross-origin `POST` requests to form actions with a 403 Forbidden status when `Origin` does not match.
  - **Exception**: CSRF protection only applies to form actions submitted with standard HTML forms or client-side `use:enhance`. Custom endpoints (`+server.ts`) handling `POST`, `PUT`, or `DELETE` do **NOT** receive automatic CSRF verification and must validate `Origin` manually.
  - If `csrf.checkOrigin: false` is configured in `svelte.config.js`, all CSRF protection is disabled framework-wide.

## Authorization Architecture: `load` Functions & `event.locals`

SvelteKit divides data loading and mutation between `load` and `actions`:

1. **`event.locals` Session Population (`hooks.server.ts`)**:
   - `hooks.server.ts` intercepts every incoming request via `handle({ event, resolve })`.
   - The handle hook should validate session tokens, authenticate users, and populate `event.locals`:
     ```ts
     // src/hooks.server.ts
     export const handle: Handle = async ({ event, resolve }) => {
       const token = event.cookies.get('session');
       if (token) {
         event.locals.user = await validateSessionToken(token);
       }
       return resolve(event);
     };
     ```
   - **Never rely solely on `hooks.server.ts` for authorization.** While hooks can enforce coarse route gating (e.g. redirecting `/admin/*`), individual page `load` functions and form actions must enforce data-level authorization and tenant scoping.

2. **Server `load` Functions (`+page.server.ts` & `+layout.server.ts`)**:
   - Server `load` functions execute exclusively on the server and return data serialized to the client as JSON.
   - **Hazard**: A server `load` function that queries database records based solely on `params.id` without verifying that `event.locals.user` owns or has permission to view that record creates an Insecure Direct Object Reference (IDOR).
   - Always verify authentication and filter by user/tenant identity:
     ```ts
     // src/routes/invoices/[id]/+page.server.ts
     export const load: PageServerLoad = async ({ params, locals }) => {
       if (!locals.user) {
         throw redirect(303, '/login');
       }
       const invoice = await db.invoice.findFirst({
         where: { id: params.id, tenantId: locals.user.tenantId }
       });
       if (!invoice) {
         throw error(404, 'Invoice not found');
       }
       return { invoice };
     };
     ```
   - **Universal `+page.ts` vs Server `+page.server.ts`**: Universal `load` functions in `+page.ts` run on both the server (SSR) and the browser (client navigation). Never import database clients, private APIs, or secrets into `+page.ts`.

## Cookie Security in SvelteKit

- SvelteKit provides a managed `cookies` API on `RequestEvent` (`cookies.get()`, `cookies.set()`, `cookies.delete()`).
- Always set secure cookie options for authentication and session tokens:
  ```ts
  cookies.set('session', token, {
    path: '/',
    httpOnly: true,                 // Prevents JavaScript access (mitigates XSS exfiltration)
    secure: process.env.NODE_ENV === 'production', // Only transmitted over HTTPS
    sameSite: 'lax',               // Protects against cross-site request forgery
    maxAge: 60 * 60 * 24 * 7,      // Explicit expiration
  });
  ```
- Missing `httpOnly: true` allows any client-side XSS vulnerability to read session tokens directly via `document.cookie`.

## Top 5 Footguns

1. **Server `load` data leaks via unfiltered queries**: Querying sensitive database tables in `+page.server.ts` using `params.id` or `findMany()` without checking `locals.user` or filtering by tenant ID, allowing authenticated or anonymous users to enumerate other users' private data.
2. **Missing CSRF protection in standalone `+server.ts` endpoints**: Relying on SvelteKit's built-in CSRF protection for `+server.ts` routes. SvelteKit's CSRF check only protects form actions in `+page.server.ts`. Standalone API endpoints processing mutations must manually check the `Origin` header.
3. **Database calls or secrets imported in universal `+page.ts`**: Placing backend queries in `+page.ts` instead of `+page.server.ts`. Universal load functions run in the browser on client-side navigation, causing build failures, connection leaks, or credential exposure.
4. **Insecure cookie defaults (`httpOnly: false`)**: Calling `cookies.set(name, value)` without `httpOnly: true` or `sameSite: 'lax'/'strict'`, making session tokens accessible to malicious scripts in the DOM.
5. **Unvalidated Form Action inputs with mass-assignment**: Passing raw objects from `Object.fromEntries(await request.formData())` directly into ORM `create()` or `update()` methods, allowing attackers to overwrite sensitive columns (`role`, `is_admin`, `balance`).
