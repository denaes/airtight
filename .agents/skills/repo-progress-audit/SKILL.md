---
name: repo-progress-audit
description: >-
  Audit the repository state before committing code in airtight. Run this scan
  every time progress is made (adding rules, editing engines, modifying docs,
  updating fixtures) to audit and update documentation, README rule and command
  counts, rules reference, tracked harnesses, demo golden suites, test invariants,
  and package versions.
---

# Airtight Repository Progress Audit

Use this skill whenever progress has been made on the Airtight codebase and you are preparing to commit code.

Airtight enforces strict invariants at build and test time:
1. **README counts must be exact**: Numbers claimed in `README.md` must exactly match the compiled rule count and command count.
2. **Derived documentation must not drift**: `docs/rules.md` must reflect every rule in `engine/build/rules.json`.
3. **Demo golden suite must match live output**: `scripts/demo.mjs --check` must pass, `demo/README.md` must quote the golden, and every pack must be exercised.
4. **All 18 tracked harness directories must stay synchronized**: `.claude/`, `.cursor/`, `.agent/skills/airtight/`, `.agents/`, `.github/`, plugin manifests, etc., must be synced before release/commit.
5. **Security invariants must hold**: `tests/redaction.test.mjs` must pass (no secrets leaked), and subagents in `skill/agents/` must remain read-only.
6. **Package versions must align**: Root `package.json`, `engine/package.json`, and `skill/scripts/VERSION` must agree.

---

## Quick Execution

Run the automated pre-commit audit:

```bash
# Audit repository state (checks docs, readme, harnesses, demo, tests, versions)
npm run audit:progress

# Automatically fix drift across docs, demo golden, and tracked harnesses
npm run audit:progress:fix
```

If `npm run audit:progress` exits with `0`, the repository is clean and ready to commit. If it reports issues, follow the checklist below to resolve them.

---

## Pre-Commit Audit Checklist

### 1. Rules & Engine Compilation
- **Compile rules**: `npm run build:rules`
  - Validates schema, CWEs, why/fix descriptions, and confidence levels.
  - Ensures immediate-tier rules have `confirmed` or `firm` confidence.
- **Build engine bundle**: `npm run build:engine`
  - Bundles the engine into `skill/scripts/engine/airtight.mjs` with the `createRequire` banner shim.

### 2. Documentation Freshness
- **README.md**:
  - Check the claimed rule count (`(\d+)\s+rules`) against `engine/build/rules.json`.
  - Check the claimed command count (`(\d+)\s+commands`) against `skill/scripts/command-metadata.json`.
  - If new language packs were added, ensure they are listed in the Supported Languages/Packs sections.
- **Reference documentation**:
  - Run `npm run build:docs` to regenerate `docs/rules.md`, `commands.md`, `harnesses.md`, and `severity.md`.
- **Roadmap / Coverage Matrix**:
  - Update `docs/plans/coverage-matrix-roadmap.md` with newly implemented rules, updated completion percentages, or newly planned items.
- **Harness instructions**:
  - If new commands, tools, or packs were introduced, check `AGENTS.md` and `CLAUDE.md`.

### 3. Demo Golden & Vulnerable Shop
- **Check demo golden**: `node scripts/demo.mjs --check`
- **Update if changed**: If new rules or fixtures legitimately change what the demo shop catches:
  ```bash
  node scripts/demo.mjs --write
  ```
- **Sync demo README**: Ensure the four summary lines in `demo/README.md` match `demo/expected-findings.txt`:
  - `total findings:`
  - `distinct rules:`
  - `by priority:`
  - `by pack:`
- **Verify pack coverage**: Ensure every active rule pack (e.g., `ci`, `container`, `dep`, `go`, `java`, `js`, `k8s`, `py`, `rust`, `secret`, `terraform`) is exercised in `demo/vulnerable-shop/`.

### 4. Tracked Harnesses Synchronization
- Tracked harness outputs (`.claude/`, `.cursor/`, `.agent/skills/airtight/`, `.agents/`, `.github/`, `plugin/`, `.claude-plugin/`) must match `skill/` and `engine/`.
- Run:
  ```bash
  npm run build:release
  ```
  *(Passes `--sync` to `scripts/build.js`, rewriting all tracked harness directories without touching custom workspace skills).*

### 5. Package Versions & Manifests
- Ensure versions agree across:
  - `package.json`
  - `engine/package.json`
  - `skill/scripts/VERSION`
  - `.claude-plugin/plugin.json`
  - `.claude-plugin/marketplace.json`
  - `plugin/.claude-plugin/plugin.json`

### 6. Tests & Critical Invariants
- **Full test suite**:
  ```bash
  npm test
  ```
- **Redaction invariant**:
  ```bash
  node --test tests/redaction.test.mjs
  ```
  *If this goes red, airtight is leaking secrets. Treat as P0 blocking issue.*
- **Subagents read-only**:
  - Inspect `skill/agents/` to verify no agent gains `Write`, `Edit`, or `NotebookEdit`.

### 7. Git Hygiene
- Run `git status`:
  - Verify no scratch scripts, temporary dumps, or accidental `.gitignore` edits are being committed.
  - Ensure all new fixtures (`fixtures/flag/`, `fixtures/pass/`) are staged.

---

## When Things Fail

| Symptom | Cause | Remedy |
|---|---|---|
| `README claims X rules; there are Y` | Stale rule count in `README.md` | Update rule count in `README.md` to Y, or run `npm run audit:progress:fix` |
| `tests/docs.test.mjs` fails on `docs/rules.md` | Rules were added/modified without rebuilding docs | Run `npm run build:docs` |
| `demo drifted from the golden` | New rules fired on demo shop or demo shop changed | Run `node scripts/demo.mjs --write` and sync lines into `demo/README.md` |
| `the demo triggers no <pack> rules` | A rule pack is not triggered by any sample in demo shop | Add a vulnerable code snippet in `demo/vulnerable-shop/` triggering that pack |
| `tests/build.test.mjs` fails on shipped rules or bundle | Shipped harness scripts drift from engine build | Run `npm run build:release` |
| `tests/redaction.test.mjs` fails | A secret leaked into stdout, logs, or in-memory finding | Stop immediately. Find and redact unmasked credential in engine/CLI |
