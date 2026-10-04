# FastAPI Security Card

Sources, sinks, authorization patterns, and common failure modes in FastAPI and Starlette applications.

## Sources (Untrusted Input)

- `Query()`: URL query parameters parsed and validated against type annotations.
- `Path()`: Path parameters extracted from the route pattern.
- `Body()` & Pydantic models: JSON and form request payloads deserialized and validated according to Pydantic field specifications.
- `Header()`: Request headers (normalized to lowercase; hyphens converted to underscores unless configured otherwise).
- `Cookie()`: Request cookies.
- Raw Starlette `Request`: Access to raw parameters (`request.query_params`, `request.headers`, `await request.body()`).

## Dangerous Sinks

- **Database queries**: SQLAlchemy async raw text queries (`session.execute(text(f"... {user_val}"))`), Tortoise ORM raw queries, or asyncpg interpolation.
- **Command execution**: `asyncio.create_subprocess_shell()` or `subprocess.run()` with user-supplied arguments.
- **Server-Side Request Forgery (SSRF)**: `httpx.AsyncClient().get(url)` or `aiohttp.ClientSession().get(url)` fetching untrusted URLs without internal IP filtering.
- **Path traversal**: `FileResponse(path)` or directory lookups with user-controlled path parameters.
- **Reflected XSS**: Returning user-controlled strings inside `HTMLResponse(content=...)` without HTML entity escaping.

## Authorization Idiom: Dependency Injection

- **`Depends()` hierarchy**:
  - FastAPI relies on `Depends()` for authentication and authorization.
  - Can be defined on individual endpoint functions, on `APIRouter(dependencies=[Depends(...)])`, or globally on `FastAPI(dependencies=[Depends(...)])`.
- **Router-level authentication vs Object-level authorization**:
  - A router dependency like `APIRouter(dependencies=[Depends(get_current_user)])` establishes that the caller is authenticated.
  - It does **not** protect against Insecure Direct Object References (IDOR). The endpoint or service layer must verify that the authenticated `current_user` has permission to read or write the specific resource ID requested in `Path()`.
- **Security scopes**: `Security(get_current_user, scopes=["admin:write"])` enforces OAuth2 scopes during token verification.

## Top 5 Footguns

1. **CORS wildcard with credentials**: Setting `allow_origins=["*"]` alongside `allow_credentials=True` in `CORSMiddleware`. While Starlette raises a configuration error for literal `["*"]`, developers frequently bypass this by using regexes (`allow_origin_regex=r".*"`) or echoing back the request's `Origin` header. This allows malicious origins to read credentialed responses cross-origin.
2. **Pydantic mass assignment / unconstrained extra fields**: Using Pydantic schemas that match database models without setting `model_config = ConfigDict(extra='forbid')` (Pydantic v2) or specifying distinct create/update DTOs. Attackers submit payloads containing protected fields like `is_admin`, `is_superuser`, or `tenant_id`, which are passed directly to database update statements (`db_item.update(**payload.model_dump())`).
3. **Blocking synchronous calls in `async def` endpoints**: Calling blocking functions (`time.sleep()`, synchronous `requests.get()`, blocking database queries via `psycopg2`) inside an `async def` route handler. In FastAPI, `async def` runs on the main asyncio event thread; blocking it halts processing of all other concurrent requests for all users, creating a trivial Denial of Service. (Non-async `def` handlers run on a thread pool and do not block the event loop).
4. **Unscoped dependency injection in Sub-Routers**: Mounting admin or internal sub-routers via `app.include_router(admin_router)` without applying permission dependencies, or assuming that an authentication dependency (`get_current_user`) implies administrator authorization.
5. **Path traversal via `FileResponse`**: Constructing file paths with unsanitized path parameters: `FileResponse(f"/var/data/{filename}")`. If `filename` contains `../../etc/passwd`, Starlette's `FileResponse` serves the arbitrary file unless the path is resolved and validated with `pathlib.Path.resolve().is_relative_to(base_dir)`.
