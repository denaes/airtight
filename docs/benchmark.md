# Benchmark

Every other number in this project is measured against code written by the
same author as the rules, including the fixtures. This page is the exception:
four repositories nobody wrote for airtight.

```bash
node scripts/benchmark.mjs
```

Shallow-clones each repository, scans with `--no-config` so nothing the
repository declares can hide a finding, and exits non-zero if any clean
repository produces a P0.

## Method

Two kinds of repository, because they answer different questions.

**Vulnerable** — does it find what is there? OWASP NodeGoat, a teaching
application with documented OWASP Top 10 flaws.

**Clean** — does it stay quiet when there is nothing to find? fastify,
express, and requests: actively maintained, widely used, security-conscious.

The second matters more. Recall improves by adding rules; precision only
improves by removing them, and a tool that cries wolf on well-maintained code
is uninstalled long before its recall is ever tested.

Every finding below was read and judged by hand. Counting alone would prove
nothing.

## Results

| Repository | Kind | Files | Findings | P0 | Verdict |
|---|---|---:|---:|---:|---|
| OWASP/NodeGoat | vulnerable | 93 | 10 | 1 | 9 true, 1 arguable |
| fastify/fastify | clean | 390 | 0 | 0 | — |
| expressjs/express | clean | 214 | 0 | 0 | — |
| psf/requests | clean | 122 | 9 | 0 | 7 true, 2 false |

**Clean repositories: 9 findings, 2 false positives, zero at P0, zero at
`confirmed` confidence.**

### What it catches in NodeGoat

Its flagship injection flaw and its unvalidated redirect:

```js
const preTax = eval(req.body.preTax);        // app/routes/contributions.js
return res.redirect(req.query.url);          // app/routes/index.js
```

Plus a committed server key, a `latest` dependency, unpinned base images, and
workflows with no permissions block.

### What it misses in NodeGoat

Honestly: most of the list. NoSQL injection, stored XSS, insecure direct
object reference, missing function-level access control, and CSRF all go
unreported. Two of those have no rule yet. The other three need reachability
and authorization reasoning, which is the model layer's job and not something
a benchmark of the engine measures.

**The engine catches the mechanical half. It is not a substitute for
`/airtight review`,** and a benchmark of rules alone will always understate
what the whole tool does and overstate what the engine does.

### The two false positives

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

## The first run was much worse

Before this benchmark existed: **35 findings on the clean repositories, 32 of
them false, 26 at P0.** One dominant cause, and three smaller ones.

**Test files, 24 of 32.** fastify disabling TLS verification against its own
self-signed test server. requests round-tripping `pickle.loads(pickle.dumps(x))`.
Committed test certificates. Every one of those is the correct way to test the
thing it describes.

The fix is not to skip tests — a real credential in a test file is a real
leak, and test code often ships. Rules now declare what test context means for
them: `ignore` where the construct is the standard way to test the thing,
`report` where it is just as bad anywhere, and `downgrade` by default, which
weakens confidence, drops the rule out of the edit-hook tier, and floors
priority at P1. See [severity](severity.md).

**Dangerous constructs quoted as data.** express reported `eval()` four times,
every one inside an XSS test vector written as a string literal. Text rules
can now declare `in_string: false`.

**File-scoped evidence.** `Math.random()` was flagged for generating fake
stock prices, because the word "session" appeared elsewhere in the file. The
evidence has to be on the line — the same bug had already been fixed once, in
the password-hashing rule, and was still present here.

**Scope errors.** package.json's `repository.url` was read as an unpinned git
dependency.

## What this still does not measure

- **Four repositories**, three of them JavaScript or Python HTTP libraries.
  No large application, no monorepo, no Go or Java or Ruby codebase, no real
  Terraform estate or Kubernetes deployment. The infrastructure packs are
  entirely unmeasured against real infrastructure.
- **Recall is eyeballed**, not scored against a labelled ground truth.
- **The model layer is not measured at all.** Everything here is the engine.
