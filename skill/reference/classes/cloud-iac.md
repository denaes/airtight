# Cloud Infrastructure as Code & Edge Security Checklist

Deep-dive audit checklist for Infrastructure as Code (Terraform, OpenTofu, CloudFormation), container configurations (Docker, Compose), container orchestrators (Kubernetes), serverless edge compute (Cloudflare Workers), and multi-cloud storage/IAM configurations (AWS, GCP, Azure, Cloudflare). Load when auditing cloud infrastructure definitions, deployment manifests, edge worker scripts, or storage policies.

## Core Invariant

**Every cloud and infrastructure definition must enforce least privilege, default-deny boundaries, runtime confinement, and encrypted isolation, preventing unauthenticated external exposure and lateral privilege escalation across services or tenants.**

## 1. Cloudflare Workers & Serverless Edge Security

- [ ] **Plaintext secrets in configuration**: `wrangler.toml` or `wrangler.json` must never declare secrets under `[vars]` or `"vars"`. Use encrypted secrets managed via `wrangler secret put <NAME>` or Cloudflare Secrets Store.
- [ ] **Edge SSRF & request dispatching**: Worker `fetch()` must never invoke unvalidated `request.url`, `req.url`, or query parameters. Always validate destination schemes (`https:`) and verify target hostnames against an explicit domain allowlist before issuing requests.
- [ ] **D1 SQL query parameterization**: Cloudflare D1 queries via `env.DB.prepare()` must use parameter placeholders (`?`) and pass values via `.bind(...)`. Never interpolate template literals (`${...}`) or concatenate strings into prepared statements.
- [ ] **KV, R2, and Vectorize tenant partitioning**: Storage keys in Cloudflare KV or R2 buckets must enforce tenant-scoped prefixes (`tenant_id/object_id`). Verify bindings and namespaces do not leak across staging and production environments.
- [ ] **CORS edge response headers**: Edge handlers must never pair `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Validate incoming `Origin` headers against allowed domains and reflect only permitted origins.
- [ ] **HTMLRewriter & response transformation**: Ensure user inputs interpolated into `HTMLRewriter` or response streams are entity-encoded to prevent edge-injected XSS.

## 2. Multi-Cloud IAM Privilege Escalation

- [ ] **AWS IAM wildcard actions & resources**: Avoid `Action: "*"` or `Action: "iam:*"` with `Resource: "*"`.
- [ ] **AWS IAM escalation primitives**:
  - `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion` (allows creating a new permissive policy version and making it active).
  - `iam:AttachUserPolicy`, `iam:AttachRolePolicy`, `iam:PutUserPolicy`, `iam:PutRolePolicy` (direct assignment of administrative policies).
  - `iam:PassRole` paired with `ec2:RunInstances`, `lambda:CreateFunction` + `lambda:InvokeFunction`, `glue:CreateJob`, or `ecs:RunTask` (passing an elevated role to a compute resource).
  - `sts:AssumeRole` without external ID or MFA conditions for third-party cross-account access.
- [ ] **GCP IAM role bindings**:
  - Avoid primitive roles (`roles/owner`, `roles/editor`) on service accounts.
  - Guard `iam.serviceAccounts.actAs` and `iam.serviceAccounts.signBlob` / `signJwt` (arbitrary token minting).
  - Guard `resourcemanager.projects.setIamPolicy` on service accounts.
- [ ] **Azure RBAC privilege escalation**:
  - Avoid `Owner` or `User Access Administrator` on subscription or resource group scopes.
  - Guard `Microsoft.Authorization/roleAssignments/write` and `Microsoft.Compute/virtualMachines/runCommand/action`.

## 3. Kubernetes Pod Security Standards & Container Hygiene

- [ ] **Pod Security Admission (PSA)**: Namespaces must enforce `pod-security.kubernetes.io/enforce: restricted` or `baseline`.
- [ ] **Rootless execution**:
  - Dockerfile: Set non-root `USER` in the final stage; never run as uid 0.
  - Kubernetes: Set `runAsNonRoot: true` and an explicit non-zero `runAsUser` in `securityContext`.
- [ ] **Privilege escalation & capabilities**:
  - Set `allowPrivilegeEscalation: false`.
  - Drop all capabilities (`drop: ["ALL"]`) and add only specific required capabilities.
- [ ] **Container health monitoring**:
  - Every production Dockerfile with `EXPOSE`, `CMD`, or `ENTRYPOINT` should define a `HEALTHCHECK` instruction so orchestrators can detect hung or deadlocked processes.
- [ ] **Resource exhaustion limits**:
  - Kubernetes: Containers must declare `resources.limits` and `resources.requests` for CPU and memory.
  - Docker Compose: Services must configure `mem_limit` and `cpus`, or `deploy.resources.limits.memory` and `deploy.resources.limits.cpus`.
- [ ] **Read-only root filesystem**: Set `readOnlyRootFilesystem: true` with ephemeral volumes mounted for required temporary write paths (`/tmp`, cache).
- [ ] **Host namespace isolation**: Avoid `hostPID: true`, `hostIPC: true`, `hostNetwork: true`.
- [ ] **Runtime socket protection**: Never mount `/var/run/docker.sock` or `containerd.sock` into application containers.
- [ ] **ServiceAccount tokens**: Set `automountServiceAccountToken: false` on pods that do not communicate directly with the Kubernetes API server.

## 4. Cloud Storage Bucket Exposure & Encryption (S3, GCS, Azure Blob, R2)

- [ ] **AWS S3 Public Access Block**:
  - Every bucket must have an `aws_s3_bucket_public_access_block` resource with `block_public_acls = true`, `block_public_policy = true`, `ignore_public_acls = true`, and `restrict_public_buckets = true`.
  - Bucket ACLs: Prohibit `public-read`, `public-read-write`, and `authenticated-read`.
- [ ] **AWS S3 Encryption**:
  - Enforce server-side encryption via `aws_s3_bucket_server_side_encryption_configuration` using KMS CMK or AES256.
- [ ] **AWS S3 Policy Principals**:
  - Ensure `Principal: "*"` is never granted `s3:GetObject` or `s3:PutObject` without strict IP, VPC endpoint, or organizational conditions.
- [ ] **Google Cloud Storage (GCS)**:
  - Enforce uniform bucket-level access (`uniform_bucket_level_access = true`).
  - Prohibit public IAM members `allUsers` and `allAuthenticatedUsers`.
- [ ] **Azure Blob Storage**:
  - Set `allow_nested_items_to_be_public = false` (or `allow_blob_public_access = false`).
  - Set container access type to `private`.
- [ ] **Cloudflare R2**:
  - Verify public bucket custom domain access is deliberate; never expose buckets storing customer data or credentials.
  - Pre-signed URLs must use short expiration windows (<= 15 minutes) and require tenant authorization prior to URL generation.

## Verification Strategy for Verifier

1. Map all IaC definitions (Terraform, CloudFormation), Dockerfiles, Compose specs, and Cloudflare Worker files.
2. In Cloudflare Workers, check for unencrypted `[vars]`, raw `fetch()` calls, unparameterized `prepare()` SQL statements, and CORS wildcard headers.
3. In IAM definitions, inspect permissions for wildcard actions and verify known privilege escalation chains (`iam:PassRole`, `actAs`, `roleAssignments/write`).
4. In Kubernetes manifests and Dockerfiles, check for root execution, missing `HEALTHCHECK`, missing CPU/memory limits, host namespace mounts, and privileged flags.
5. In cloud storage definitions, verify explicit public access blocks, uniform bucket-level access, and private access types.
