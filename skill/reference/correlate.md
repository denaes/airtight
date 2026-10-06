Correlate infrastructure ingress rules with application HTTP routes and dangerous sinks to trace reachable attack paths from the internet.

Infrastructure misconfigurations (such as open security groups, load balancers, or host-networked containers) are commonly triaged in isolation from application logic, while static code analysis flags injection sinks without knowing whether an endpoint is exposed to the public internet or sequestered behind a private subnet.

Cross-layer exposure correlation bridges infrastructure-as-code manifests (Terraform, AWS CloudFormation, Kubernetes manifests/Helm, Docker Compose) with application framework route maps (Express, Fastify, Next.js, NestJS, Nuxt, SvelteKit, Flask, FastAPI, Django, Spring, Gin). It determines which application ports are exposed to `0.0.0.0/0` and maps those exposures directly to downstream data sinks.

## Run

1. **Extract Ingress Rules**: Scan infrastructure manifests:
   - Terraform: `aws_security_group`, `aws_vpc_security_group_ingress_rule`, `google_compute_firewall`, `azurerm_network_security_rule`.
   - CloudFormation: `AWS::EC2::SecurityGroup`, `AWS::EC2::SecurityGroupIngress`.
   - Kubernetes: `Service` of type `LoadBalancer` or `NodePort`, and `Ingress` resources.
   - Docker Compose: Published `ports` mappings (e.g. `"80:3000"`, `"0.0.0.0:8080:8080"`) or `network_mode: host`.
2. **Discover Application Entry Points**: Scan application source code for route handlers across all supported web frameworks and identify dangerous sinks (raw SQL, shell execution, eval, SSRF fetch, path traversal) in the handler scope.
3. **Resolve Service Ports**: Inspect explicit port listen calls (`app.listen(3000)`, `server.port = 8080`, `Run(":8080")`) or infer from framework standard conventions.
4. **Construct Attack Path Graph**:
   Join public ingress rules with application routes whose service ports match the exposed ingress rules.
5. **Run CLI**:
   - `airtight correlate [paths...]`: Produces human-readable correlation report and ASCII attack path graph. Returns exit code 2 if exposed attack paths exist.
   - `airtight correlate [paths...] --json`: Returns machine-readable `{ ingressRules, servicePorts, attackPaths, summary }`.
   - `airtight map --with-exposure [paths...]`: Annotates route discovery output with infrastructure exposure status.
   - `airtight detect --correlate`: Elevates findings located on internet-facing routes to critical severity.

## Report

```
airtight: cross-layer exposure correlation
  ingress rules: 2 public, 1 internal
  discovered service ports: 3000
  routes analyzed: 12 (4 internet-facing, 8 internal/unmapped)
  correlated attack paths: 1

[!] Discovered Attack Paths:

  [CRITICAL] SQL Sink reachable from Internet
    Exposure: Terraform aws_security_group (0.0.0.0/0 -> port 80)
    Route:    POST /api/search (src/routes/search.js:14)
    Sink:     db.query(...) (src/routes/search.js:18)
    Attack Path Graph:
      Internet [0.0.0.0/0]
      │ (port 80 via Terraform aws_security_group)
      ▼
      POST /api/search (express)
      │
      ▼
      Sink: SQL (src/routes/search.js:18)
```

## Remediation

When an attack path is discovered:
- **Restrict Ingress**: If the service is internal, remove `0.0.0.0/0` from security groups or switch Kubernetes Service type from `LoadBalancer` to `ClusterIP`.
- **Harden the Sink**: Parameterize SQL queries, replace shell execution with child process array execution, or validate SSRF target hosts.
- **Add Authentication**: Ensure authentication and authorization middleware runs before the request reaches the sink.

## The way this command fails

**Treating infrastructure and code as disjoint silos.** Reporting a hundred theoretical SAST findings without identifying which ones an external attacker can actually reach, or reporting open security groups without knowing whether the container behind them is a hardened static file server or an unauthenticated SQL execution endpoint. A correlation engine that fails to verify the exact port linkage and ingress rules produces guesswork rather than an actionable attack graph.
