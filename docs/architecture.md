# Architecture

## The split

A deterministic rule can see that a dangerous sink exists. It cannot tell you
whether attacker-controlled input reaches it, whether the authorization check
above it is correct, or whether the blast radius matters.

How much of a domain is mechanically checkable varies enormously, and that
variation *is* the architecture:

| Domain | Mechanically checkable | The model owns |
|---|---|---|
| Secrets | ~95% | Whether a match is a real credential or a fixture |
| Containers, IaC | ~90% | Whether the exposure matters given the deployment |
| Supply chain | ~70% | Dependency necessity, advisory reachability |
| Application code | ~40% | Reachability, authorization, business logic |

## Pieces

```
engine/src/          the detector. Plain ESM, no runtime dependencies.
  rules.mjs            load and validate; rejects malformed rules at build time
  match/               text · structured (dockerfile, yaml, json, hcl) · custom js
  findings.mjs         severity, confidence, derived priority, SLA
  redact.mjs           secret containment
  store.mjs            the findings lifecycle
  controls.mjs         the control register
  context.mjs          project truth and session directives
  hook.mjs             the edit hook
engine/rules/*.yaml  rule source, compiled and validated to JSON
fixtures/            per-rule corpus: >=4 true positives, >=5 near misses
skill/               the model layer. The only authoring surface.
scripts/             build: rules, engine bundle, 18 harnesses, docs
```

## Rules are data

Authored as YAML, compiled to JSON, validated at build time. The runtime never
parses YAML for its own packs, which is what lets the shipped engine be one
dependency-free file — and what would let a future runtime in another language
consume the identical packs without reauthoring anything.

Rule metadata lives in one place; matchers only ever emit `(id, file, line,
snippet)`. One place to audit the taxonomy, many places to implement
detection.

## Secrets are handled the other way round

Most design-oriented tools skip `.env`, `*.pem` and `secrets.*`. Airtight has
to read exactly those, so containment cannot be a matter of where it looks:

- Redaction happens at `Finding` construction, not at the renderer. The
  findings store and the hook both serialize findings directly, and neither
  should have to remember to scrub.
- A scan-wide vault scrubs every output path as a second layer.
- Inside a file that is credentials by definition, snippets are clamped to the
  match, so a secret no rule recognizes cannot ride out on a neighbouring
  finding's line.
- Findings carry a short non-reversible fingerprint instead of the value, which
  is what correlates one credential across files.

## Reading hostile input

Airtight reads source from unknown authors, dependency metadata, and scanner
output, while holding credentials and edit rights. Scanned content is data,
never instruction; instruction-shaped text found inside it is itself a finding
(`ai/embedded-instruction`), reported rather than followed. Both sub-agents are
read-only by construction, with a test that fails if either gains `Write`.

## What airtight does not do

- **Taint analysis.** No call graph yet, so reachability is reported as
  unknown rather than implied.
- **Runtime or live cloud state.** It reads files. Infrastructure findings
  describe declared configuration, not what is actually deployed.
- **Advisory reachability.** `deps` reports whether a package is vulnerable,
  not whether you call the vulnerable function.
- **Anything offensive.** No scanning of systems, no exploitation. Those
  commands are planned and gated behind an explicit engagement record.
