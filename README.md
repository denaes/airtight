# Airtight

Security guidance for AI coding agents. One skill, deterministic rule packs, and
an edit hook that catches the mechanical failures at the edit site.

> **Status:** v0.3.1, installable from npm across 18 harnesses. Engine with 191
> rules, findings store, control register, nine commands, edit hook, installer,
> docs, and a demo. Benchmarked against four real repositories; see
> [measured against real code](#measured-against-real-code) for what that
> covers and what it does not.

**[Documentation](docs/)** · [Getting started](docs/getting-started.md) ·
[Rule reference](docs/rules.md) · [Harnesses](docs/harnesses.md) ·
[Benchmark](docs/benchmark.md) · [Demo](demo/)

## Why

Every model was trained on tutorial code, Stack Overflow answers, and README
snippets, all of which optimize for *it runs* over *it holds*. That produces a
recognizable set of tells, the security equivalent of purple gradients and Inter
everywhere: `eval()` for dynamic dispatch, string-concatenated SQL,
`verify=False` to make the request work, `0.0.0.0/0` to make the deploy work,
the API key inlined "for now."

Airtight splits the work along the line that actually matters. The deterministic
engine owns the mechanical floor: token formats, dangerous sinks, container and
CI misconfiguration. The model layer owns what only reasoning can reach:
whether a sink is reachable with attacker-controlled input, whether the
authorization logic is correct, and where the trust boundaries really sit.

## Install

```bash
npx airtight-security install
```

Detects the harnesses you have and asks before writing. **18 supported** —
Claude Code, Cursor, Codex, Copilot, Gemini, OpenCode, Grok, Hermes and more,
each getting its own frontmatter, agent format, command prefix and hook
manifest. Confidence per harness is recorded rather than implied; see
[harnesses](docs/harnesses.md).

The package is `airtight-security` (`airtight` was taken on npm); the command
it installs is `airtight`.

Claude Code can also install from the plugin marketplace:

```
/plugin marketplace add denaes/airtight
```

Or vendor any harness by copying its directory out of a clone. Needs Node 20
and nothing else: the engine is one bundled file with no runtime dependencies.

Then, inside your project:

```
/airtight init          # write THREATS.md and CONTROLS.md
/airtight audit         # deterministic sweep, scored
/airtight review <x>    # deep reasoning review
/airtight harden <x>    # the only command that edits
```

## See it work

[`demo/vulnerable-shop`](demo/) is a storefront written the way a model writes
code when nobody has asked it about security. Eleven files:

```
total findings:   55
distinct rules:   51
by priority:      24 P0, 16 P1, 11 P2, 4 P3
by pack:          ci=5 container=7 dep=7 go=1 js=9 k8s=10 py=5 secret=4 terraform=7
```

Nothing in it looks careless. `` db.query(`SELECT ... ${req.query.customer}`) ``
is a template literal used with the right method, and it is SQL injection.
`path.join('/var/invoices', req.params.name)` looks like the careful choice and
resolves `../` happily. Those are not the mistakes of someone who does not know
better; they are what *make it work* produces.

## Measured against real code

Four repositories nobody wrote for airtight. Every finding read and judged by
hand — [full method and results](docs/benchmark.md), reproducible with
`node scripts/benchmark.mjs`.

| Repository | Kind | Files | Findings | P0 |
|---|---|---:|---:|---:|
| OWASP/NodeGoat | vulnerable | 93 | 10 | 1 |
| fastify/fastify | clean | 390 | **0** | 0 |
| expressjs/express | clean | 214 | **0** | 0 |
| psf/requests | clean | 122 | 9 | 0 |

**Clean repositories: 9 findings, 2 false positives, zero at P0 and zero at
`confirmed` confidence.** On NodeGoat it catches the flagship injection flaw
(`eval(req.body.preTax)`) and the unvalidated redirect.

Four repositories is a start, not a coverage claim. Three of them are
JavaScript or Python HTTP libraries, so the Terraform and Kubernetes packs —
38 of the 191 rules — have not been run against real infrastructure. Recall is
judged by reading, not scored against labelled ground truth, and this measures
the engine only, not the model layer. [What the benchmark does and does not
cover](docs/benchmark.md#what-this-still-does-not-measure).

## Commands

`skill/` is the source of truth. Nine commands in three categories:

| Command | Category | Does |
|---|---|---|
| `init` | Establish | Write `THREATS.md` and `CONTROLS.md` plus the control register |
| `threat-model` | Establish | STRIDE per trust boundary, before the code exists |
| `review` | Evaluate | Deep reasoning review, dual-subagent, adversarially verified |
| `audit` | Evaluate | Deterministic sweep, scored per domain |
| `secrets` | Evaluate | Working tree and git history, redacted, with a rotation plan |
| `deps` | Evaluate | Advisories with honest reachability reporting |
| `supply-chain` | Evaluate | CI triggers, token scope, action pinning, provenance |
| `infra` | Evaluate | Terraform, Kubernetes, containers |
| `harden` | Fix | The only command that edits |

Both subagents are read-only by construction, and there is a test that fails if
either gains `Write`. They exist to read hostile content and report on it; an
agent that can do both is the shape the prompt-injection invariant exists to
prevent.

## Rule packs

| Pack | Rules | Tier | Covers |
|---|---:|---|---|
| `secret` | 15 | text, js | Provider token formats, private keys, tracked `.env`, entropy |
| `container` | 10 | dockerfile | Root user, mutable tags, baked credentials, pipe-to-shell |
| `ci` | 8 | yaml | `pull_request_target`, script injection, unpinned actions, token scope |
| `dep` | 12 | text | Install scripts, wildcard versions, plaintext registries, unpinned git refs |
| `terraform` | 20 | hcl | Open ingress, wildcard IAM, public storage, unencrypted state |
| `k8s` | 18 | yaml | Privileged pods, host namespaces, wildcard RBAC, runtime socket mounts |
| `js` | 29 | text | Injection sinks, TLS/CORS misconfiguration, prototype pollution, JWT verification, body limits |
| `py` | 34 | text | Deserialization, `shell=True`, SQL injection, SSRF, JWT verification, deprecated SSL |
| `go` | 19 | text | SQL injection, shell exec, TLS verification, temporary files, XXE, SSRF |
| `java` | 18 | text | Command execution, SQL concat, XXE parsers, path traversal, LDAP, SSRF |
| `rust` | 8 | text | Command injection, SQL formatting, insecure temporary files, weak RNG |

## The edit hook

```bash
node engine/src/cli.mjs hooks on        # install for this project
node engine/src/cli.mjs hooks status
```

Two tiers. After each edit the immediate tier runs: the rules that are
mechanical, unambiguous, and cheap to correct right there. On stop, every rule
runs over the files touched that session. A `critical` finding at `confirmed`
confidence blocks the write; everything else advises; a detector failure always
fails open, and so does a missing Node runtime.

Restraint is most of the design. The hook deduplicates within a session, stands
down entirely after six edits to one file, and caps output at five findings and
8000 characters. A hook that interrupts too often gets switched off, and a hook
that is switched off protects nobody.

Two messages it is careful about. A file whose findings were already reported
says *"still has 1 finding reported earlier"*, never *"no findings"* — turning a
deduplication into a false all-clear is worse than staying silent. And a genuinely
clean scan says so while underselling itself: the rules cover known shapes, not
reachability, authorization logic, or business rules.

## Findings persist

A scan answers "what is wrong right now". The store answers the questions that
actually run a security program.

```bash
node engine/src/cli.mjs findings sync .        # scan and reconcile
node engine/src/cli.mjs findings list
node engine/src/cli.mjs findings overdue       # past the severity SLA
node engine/src/cli.mjs findings accept <id> --reason "..." --approver "..." --expires 2026-06-01
```

Findings are identified by rule, file, and a fingerprint of the matched value
rather than by line number, so reformatting does not read as a new
vulnerability and one credential in three files is one key to rotate. A finding
that disappears becomes `fixed` rather than being deleted, which is what makes
the next case detectable: a fixed finding that comes back is `regressed`, not
merely open again. Acceptance requires a named approver and a reason, and when
it carries an expiry the finding returns on its own.

The store is sorted newline-delimited JSON, so two branches that each add a
finding edit different lines and git merges them without a conflict.

## Controls are verified, not asserted

`CONTROLS.md` is prose; `.airtight/controls.json` is its machine form. Each
control names the rules that verify it and its mapping into each framework.

```bash
node engine/src/cli.mjs controls verify
node engine/src/cli.mjs controls coverage --framework soc2
```

Two distinctions the report keeps that a naive pass/fail would lose:

- **`unverifiable` is not `holding`.** A control with no rule verifier is
  reported separately, because "nothing checked this" and "this was checked and
  passed" are the two claims an auditor most needs told apart.
- **A verifier naming a rule that does not exist is `broken`.** It would
  otherwise match nothing, produce no findings, and read as evidence.

A framework reference is satisfied only when every control mapped to it is both
declared enforced *and* verified holding. Zero findings against a control nobody
has implemented yet is not evidence of anything.

## Secrets are handled differently

Impeccable's design hook deliberately skips `.env`, `*.pem`, and `secrets.*`.
Airtight has to read exactly those files, so redaction is enforced inside the
engine rather than at the renderer: a `Finding` never holds the credential, and
a scan-wide vault scrubs every byte of output as a second layer. A build-gating
test plants known secrets and greps every output path for them.

Findings keep a short non-reversible fingerprint of the value, so the same
credential in three files is three edits to make but one key to rotate.

## GitHub Actions & CI

Scan pull requests and push findings to GitHub Code Scanning via the composite action:

```yaml
- uses: denaes/airtight@v0.3.1
  with:
    paths: '.'
    format: 'sarif'
    upload-sarif: 'true'
```

## Development

`skill/` and `engine/` are the authoring surfaces. `.claude/`, `plugin/`, and
`skill/scripts/engine/` are generated and committed — see `AGENTS.md`.

```bash
npm install
npm run build
npm test

node engine/src/cli.mjs detect .                # exit 0 clean, 2 findings
node engine/src/cli.mjs detect --format sarif . # SARIF 2.1.0 for Code Scanning
node engine/src/cli.mjs detect --json .         # machine-readable JSON
node engine/src/cli.mjs rules                   # the loaded taxonomy
```

Rules are data, authored as YAML in `engine/rules/` and compiled to JSON at
build time. The runner ships as one file with no runtime dependencies.

Every rule carries a severity, an independent **confidence**, a CWE, and both a
true-positive and a false-positive fixture corpus. A rule missing either half
does not merge — the false-positive corpus is what earns a finding the right to
interrupt someone's edit.

## Credits

Built on the patterns of [Impeccable](https://github.com/pbakaus/impeccable) by
Paul Bakaus, Apache-2.0. See [NOTICE.md](NOTICE.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
