# Benchmark

Every other number in this project is measured against code written by the
same author as the rules, including the fixtures. This page is the exception:
seven real-world repositories nobody wrote for airtight, spanning both
application code and cloud infrastructure.

```bash
node scripts/benchmark.mjs                 # scan all suites (application & infrastructure)
node scripts/benchmark.mjs --suite=infra   # scan infrastructure repositories only
node scripts/benchmark.mjs --suite=app     # scan application repositories only
```

Shallow-clones each repository, scans with `--no-config` so nothing the
repository declares can hide a finding, and exits non-zero if any clean
repository produces a P0.

## Method

Two suites and two kinds of repository, because they answer different questions:

### 1. Application Suite
- **Vulnerable** — does it find what is there?
  - `OWASP/NodeGoat`: OWASP teaching application with documented OWASP Top 10 flaws.
  - `juice-shop/juice-shop`: OWASP flagship modern vulnerable web app (TypeScript, Node.js, Express, Angular).
- **Clean** — does it stay quiet when there is nothing to find?
  - `fastify/fastify`: actively maintained HTTP framework.
  - `expressjs/express`: actively maintained HTTP framework.
  - `gin-gonic/gin`: high-performance Go web framework.
  - `pallets/flask`: actively maintained Python web framework.
  - `psf/requests`: actively maintained HTTP client.

### 2. Infrastructure & Container Suite
- **Vulnerable** — does it catch dangerous IaC and container misconfigurations?
  - `bridgecrewio/terragoat`: Bridgecrew's intentionally vulnerable Terraform benchmark spanning AWS, Azure, and GCP.
  - `bridgecrewio/k8sgoat`: Kubernetes security training benchmark containing vulnerable manifests and cluster misconfigurations.
- **Clean** — does it stay quiet on standard, production-ready infrastructure?
  - `terraform-aws-modules/terraform-aws-vpc`: standard, actively maintained AWS VPC Terraform module used across thousands of production environments.

The clean test matters more. Recall improves by adding rules; precision only
improves by removing them, and a tool that cries wolf on well-maintained code
or production infrastructure is uninstalled long before its recall is ever tested.

## Results

| Repository | Suite | Kind | Files | Findings | P0 | Verdict |
|---|---|---|---:|---:|---:|---|
| OWASP/NodeGoat | app | vulnerable | 93 | 12 | 3 | Flagship injections (eval), open redirect, hardcoded keys |
| juice-shop/juice-shop | app | vulnerable | 1,166 | 122 | 11 | NoSQL $where injection, RSA private key, dynamic eval, unverified JWT |
| bridgecrewio/terragoat | infra | vulnerable | 69 | 31 | 6 | RDS public, open ingress, hardcoded secrets, KMS disabled |
| bridgecrewio/k8sgoat | infra | vulnerable | 154 | 108 | 12 | Privileged containers, docker socket, wildcard RBAC, hostPath |
| fastify/fastify | app | clean | 390 | 17 | 0 | 0 at P0 |
| expressjs/express | app | clean | 214 | 5 | 0 | 0 at P0 |
| gin-gonic/gin | app | clean | 130 | 11 | 0 | 0 at P0 in production Go code (CI actions & test certs) |
| pallets/flask | app | clean | 231 | 7 | 1 | 1 P0 (intentional DEBUG = True in config.py) |
| psf/requests | app | clean | 122 | 9 | 0 | 0 at P0 (7 true certs/unpinned, 2 test FP) |
| terraform-aws-modules/terraform-aws-vpc | infra | clean | 111 | 16 | 0 | Clean IaC: 0 terraform findings, 0 at P0 (CI unpinned actions only) |

**Zero P0 findings across five clean production codebases.** On vulnerable apps
it catches flagship injection flaws, committed credentials, unverified JWTs,
and dangerous infrastructure postures.

### What it catches in Juice Shop (TypeScript & Node.js)

OWASP Juice Shop contains realistic, multi-tier vulnerabilities across authentication, database, and client layers:

- `js/nosql-injection`: Unescaped `$where` JavaScript expressions in MongoDB review and order queries (`routes/chat.ts`, `routes/showProductReviews.ts`, `routes/trackOrder.ts`).
- `secret/private-key-pem`: Hardcoded RSA private key material committed in `lib/insecurity.ts`.
- `js/eval-dynamic`: Dynamic `eval()` and `new Function()` in `routes/captcha.ts`, `routes/userProfile.ts`, and `lib/xml.ts`.
- `js/jwt-verify-without-algorithms` & `js/jwt-decode-unverified`: Unverified JWT decoding in `routes/verify.ts` and token verification without algorithm constraints.
- `js/math-random-for-secret`: `Math.random()` used to generate security tokens in `lib/insecurity.ts`.

### What it catches in NodeGoat

Its flagship injection flaws and unvalidated redirect:

```js
const preTax = eval(req.body.preTax);        // app/routes/contributions.js
return res.redirect(req.query.url);          // app/routes/index.js
```

Plus a committed server key, a `latest` dependency, unpinned base images, and
workflows with no permissions block.

### What it catches in TerraGoat (Terraform)

TerraGoat contains deliberate, real-world cloud infrastructure misconfigurations:

- `terraform/rds-publicly-accessible`: RDS database instances directly exposed to the public internet without VPC boundary constraints.
- `terraform/open-ingress-sensitive-port`: Security groups permitting `0.0.0.0/0` ingress to SSH (22) and database ports.
- `terraform/hardcoded-credential`: Plaintext database passwords and access keys embedded in `.tf` resource declarations.
- `terraform/rds-unencrypted`: Storage volume encryption disabled (`storage_encrypted = false`).
- `terraform/iam-wildcard-resource`: IAM policies granting permissions across unrestricted `*` resources.
- `terraform/kms-rotation-disabled`: Customer Managed Keys configured with key rotation disabled.
- `terraform/lambda-env-secret`: Plaintext secret credentials passed directly via Lambda environment variables.

### What it catches in K8sGoat (Kubernetes & Containers)

Kubernetes Goat exercises cluster configuration weaknesses and container security policies:

- `k8s/privileged-container`: Pods running with `securityContext.privileged: true`.
- `k8s/docker-socket-mount`: Host Docker daemon socket (`/var/run/docker.sock`) mounted into containers.
- `k8s/host-namespace`: Pods sharing the host network, IPC, or PID namespace (`hostNetwork: true`, `hostPID: true`).
- `k8s/cluster-admin-binding`: Service accounts granted cluster-wide `cluster-admin` RBAC privileges.
- `k8s/wildcard-rbac`: RBAC ClusterRole granting `*` verbs on `*` resources.
- `k8s/host-path-volume`: Dangerous host filesystem mounts (`hostPath`).
- `k8s/allow-privilege-escalation`: Containers running without privilege escalation prevention.
- `k8s/writable-root-filesystem`: Containers without read-only root filesystems.
- `k8s/no-resource-limits`: Pods without CPU/memory resource boundaries.
- `container/runs-as-root`: Dockerfiles executing as UID 0 / root user.

### Clean infrastructure reference: terraform-aws-vpc

Scanning `terraform-aws-modules/terraform-aws-vpc` produces **0 findings on Terraform code**.
The rule engine raises zero false alarms against standard, well-structured VPC definitions,
route tables, NAT gateway resources, and subnet configurations. The only reported findings
are low-priority CI workflow recommendations (`ci/unpinned-third-party-action`, `ci/no-explicit-permissions`),
confirming that airtight avoids spurious alerts on battle-tested infrastructure.

### The two false positives in application code

Both in `psf/requests`, both at P1:

```python
conn.cert_reqs = "CERT_NONE"     # src/requests/adapters.py
```

This is the requests library *implementing* the `verify=False` option. A
library implementing an insecure option is indistinguishable from a caller
taking it, which is why the rule is `firm` rather than `confirmed` and says so
in its own text.

The other seven are real: four committed private keys under `tests/certs/`
(test certificates, reported at P1 and marked as being in a test path) and
three unpinned dev requirements.

## What this still does not measure

- **Recall is measured against ground-truth suites**, but real codebases contain
  subtle business-logic flaws, authorization oversights, and multi-step reachability chains.
- **The model layer is measured separately.** The static engine catches the mechanical
  half. For evaluating LLM agent reasoning (`airtight-reviewer` and `airtight-verifier`) on
  complex vulnerabilities (IDOR, TOCTOU races, SSRF redirects, prompt injection, Server Action authz),
  see the [model-layer evaluation harness](eval.md).
