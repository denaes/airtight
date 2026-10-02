Review infrastructure as code: Terraform, Kubernetes manifests, Dockerfiles, and the CI that applies them.

## Run

`airtight detect --json --pack terraform --pack k8s --pack container .`

## What the rules cannot see

The engine reads files. Infrastructure risk lives in the relationships between them, so read for these yourself:

- **What is actually reachable from the internet?** A security group allowing `0.0.0.0/0` on a resource in a private subnet with no route out is a finding with a compensating control; the same rule on a public-facing load balancer is an incident waiting. Trace the path: route table, subnet, gateway.
- **What can this identity reach if it is stolen?** Follow the IAM role, its attached policies, and what those policies allow. A wildcard action on a role nothing assumes is minor; the same wildcard on the role every pod uses is the whole account.
- **Where does state live?** Terraform state contains every generated password and key in plaintext. It is frequently the most sensitive object in the account and the least protected.
- **What is drift?** Code is not reality. Say plainly that this is a review of the declared configuration, and that anything applied by hand is invisible to it.
- **Is the blast radius bounded?** One account for everything, or separated by environment. One cluster namespace, or per-tenant. A single security group shared by everything.

## Report

```
## Infrastructure review: <scope>

**Start here.** <The exposure an internet scanner would find first.>

### Exposure
What is reachable from outside, and through what path. This section is the
one an incident responder would read first.

### Identity and access
Over-broad grants, ordered by what assumes them.

### Data protection
Encryption at rest and in transit, key management, backup exposure.

### Workload hardening
Container and pod posture: root, capabilities, host namespaces, limits.

### Findings
Per [severity.md](severity.md).

### Coverage
Which providers and file types were read, and what was not: modules not
resolved, live cloud state not queried, resources created outside this code.
```

## The way this command fails

**Grading the file instead of the exposure.** Twenty medium findings about encryption settings on internal resources, and a missed `0.0.0.0/0` on port 22 of the bastion, is a report that scored well and helped nobody. Start from what an attacker reaches first and work inward.
