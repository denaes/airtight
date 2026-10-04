# Django & Django REST Framework (DRF) Security Card

Sources, sinks, authorization idioms, and common failure modes in Django and DRF applications.

## Sources (Untrusted Input)

- `request.GET`: `QueryDict` containing URL query parameters.
- `request.POST`: `QueryDict` containing parsed POST form-encoded data.
- `request.data`: In Django REST Framework (DRF), parsed request body (JSON, multipart, form data) handled by parser classes.
- `request.COOKIES`: Dictionary of incoming HTTP cookies.
- `request.META`: Raw CGI-like header environment (e.g., `HTTP_AUTHORIZATION`, `HTTP_X_FORWARDED_FOR`, `REMOTE_ADDR`).
- URL Parameters: `kwargs` / `args` captured by regex or path converters in `urls.py`.

## Dangerous Sinks

- **Raw SQL injection**: `Model.objects.raw()`, `QuerySet.extra()`, `connection.cursor().execute()`, and raw expressions (`RawSQL`) using string formatting (`%`, `f-strings`, `.format()`).
- **Command execution**: `subprocess.run()`, `subprocess.Popen()`, `os.system()` with unsanitized parameters.
- **Unsafe template rendering**: `mark_safe()`, the `|safe` template filter, or dynamic template string construction (`Template(user_string).render()`).
- **Insecure deserialization**: `pickle.loads()`, `yaml.load()` without `yaml.SafeLoader`.
- **Open redirect**: `HttpResponseRedirect(request.GET.get('next'))` without validation via `django.utils.http.url_has_allowed_host_and_scheme()`.
- **Arbitrary file access**: `FileSystemStorage.save(user_filename, content)` without base directory boundary checks.

## Authorization Idiom

- **`@login_required` vs DRF `permission_classes`**:
  - `@login_required` (Django standard) only checks if `request.user.is_authenticated`. It performs **no role, permission, or tenant checks**.
  - In DRF, `permission_classes = [IsAuthenticated]` on an `APIView` or `ViewSet` verifies authentication. It does NOT enforce object-level permissions unless `check_object_permissions(request, obj)` is explicitly called or provided by DRF generic views.
- **QuerySet Tenant Scoping (Crucial)**:
  - Defining `queryset = Item.objects.all()` on a DRF `ModelViewSet` leaves object lookups (`/api/items/<id>/`) vulnerable to IDOR across tenants.
  - **Always override `get_queryset()`** to enforce tenant boundary filtering at the database level:
    ```python
    def get_queryset(self):
        return Item.objects.filter(tenant=self.request.user.tenant)
    ```
- **Object-level permissions**: Custom permissions inheriting from `rest_framework.permissions.BasePermission` must implement `has_object_permission(self, request, view, obj)` in addition to `has_permission(self, request, view)`.

## Top 5 Footguns

1. **`@csrf_exempt` blanket decorator**: Decorating views or API endpoints with `@csrf_exempt` without ensuring that session authentication is completely disabled in favor of stateless, token-based authentication (with custom headers). Applying `@csrf_exempt` to session-authenticated views allows CSRF.
2. **SQL Injection via `raw()` or `extra()`**: Passing user input into raw SQL queries using Python string interpolation (`Item.objects.raw(f"SELECT * FROM items WHERE name = '{name}'")`) rather than parameter passing (`Item.objects.raw("SELECT * FROM items WHERE name = %s", [name])`).
3. **Missing tenant scoping in DRF ViewSets (IDOR)**: Declaring `queryset = OrganizationDocument.objects.all()` on a `ModelViewSet` and relying on the view's permission class. Any authenticated user can access, modify, or delete documents belonging to other organizations by guessing the integer or UUID primary key.
4. **Unvalidated `next` parameter redirects**: Implementing post-login redirects using `redirect(request.GET.get('next'))` without passing the URL through `url_has_allowed_host_and_scheme(url, allowed_hosts=...)`. Attackers redirect users to phishing sites immediately upon authentication.
5. **Host Header Poisoning & Password Reset Hijacking**: Misconfiguring `ALLOWED_HOSTS = ['*']` in production while using `request.get_host()` or `request.build_absolute_uri()` to generate password reset links. Attackers submit reset requests with a poisoned `Host: attacker.com` header, receiving password reset tokens on their server.
