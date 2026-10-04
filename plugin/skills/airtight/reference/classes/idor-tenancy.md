# Insecure Direct Object References (IDOR) & Multi-Tenant Isolation Checklist

Deep-dive audit checklist for object-level authorization and tenant boundaries. Load when reviewing or verifying endpoints that retrieve, modify, or delete resources by ID, or when evaluating multi-tenant isolation.

## Core Invariant

**Every read, write, and delete operation on a tenant-scoped resource must be constrained to the requesting user's tenant at the database query level, not filtered in application memory after retrieval.**

Authentication verifies who the caller is; authorization verifies whether this specific caller is permitted to perform this specific action on this specific record.

## 1. Object-Level Access Control (Horizontal & Vertical)

- [ ] **ID-based lookups require ownership checks**: Does fetching `/api/documents/:id` verify that the document belongs to `current_user` or `current_user.tenant`?
- [ ] **State-changing operations (Write / Delete)**: Does `PUT /api/orders/:id` or `DELETE /api/orders/:id` check object ownership, or does it only check if the user has role `User`?
- [ ] **Parent-Child resource association (Composite IDOR)**: When accessing nested resources (`/api/organizations/:orgId/projects/:projectId`), does the query verify that `projectId` genuinely belongs to `orgId`? Or can an attacker pass their own `orgId` with another tenant's `projectId`?
- [ ] **Direct primary key references**: Are sequential integer IDs or predictable UUIDs used without access control? (Note: UUIDv4 does not replace authorization; unguessability is not a security boundary).

## 2. Multi-Tenant Database & Storage Scoping

- [ ] **QuerySet / Repository level scoping**:
  - Is `tenant_id` included in every `WHERE` clause: `SELECT * FROM items WHERE id = ? AND tenant_id = ?`?
  - Anti-pattern: `item = db.find(id); if (item.tenant_id != user.tenant_id) abort();` (Vulnerable to race conditions, cache poisoning, and memory leaks).
  - Best practice: Global scopes, ORM query filters, or PostgreSQL Row Level Security (RLS) policies enforcing `tenant_id = current_setting('app.current_tenant')`.
- [ ] **Bulk updates and deletes**: Does `DELETE /api/items` with a list of IDs (`[101, 102, 103]`) enforce tenant scoping on every single item in the batch?
- [ ] **Unique constraint collisions across tenants**: Does a uniqueness constraint (e.g. username, slug, SKU) accidentally reveal existence across tenants, or allow tenant A to lock out tenant B from creating a valid slug?
- [ ] **Blob & Object storage isolation (S3, GCS)**: Are file storage keys partitioned by tenant (`s3://bucket/{tenant_id}/{object_id}`)? Are pre-signed URLs generated only after verifying object ownership?

## 3. Caching, Search, & Async Worker Boundaries

- [ ] **Redis / Memcached key namespacing**: Are cache keys prefixed with tenant ID (`cache:tenant_{id}:user_{id}`)? A shared key like `cache:document_{id}` allows cross-tenant cache contamination or leakage.
- [ ] **Search indexes (Elasticsearch, OpenSearch, Meilisearch)**: Does every search query enforce a mandatory `filter: { term: { tenant_id: user.tenant_id } }`? Can an attacker supply search syntax that breaks out of the filter?
- [ ] **Background worker payloads**: When enqueuing asynchronous background tasks (Celery, BullMQ, Sidekiq), is the message stamped with `tenant_id`? Does the worker execute under the tenant's context or assume elevated superuser privileges?

## 4. Export, Reporting, & Administrative Functions

- [ ] **CSV / PDF export endpoints**: Do data export jobs enforce the same tenant filters as pagination endpoints, or do they query the raw table without tenant conditions?
- [ ] **Cross-tenant support impersonation**: If staff impersonation or cross-tenant access exists, is every cross-tenant action logged to an immutable audit trail with both operator and target tenant IDs?
- [ ] **Error messages & timing channels**: Do 404 vs 403 responses leak the existence of resources belonging to another tenant? (Prefer returning 404 Not Found for cross-tenant IDOR to prevent resource enumeration).

## Verification Strategy for Verifier

1. Identify candidate endpoints with `:id`, `:uuid`, or payload IDs.
2. Search for the query executing the fetch: does it bind `tenant_id` / `owner_id` as a parameter?
3. Check if an authenticated user with Tenant A's token can retrieve or mutate Tenant B's resource ID.
4. If the code relies on an in-memory check (`if (record.tenantId !== user.tenantId)`), check whether subsequent side effects (e.g., locking, audit logs, billing counters) execute before the check.
