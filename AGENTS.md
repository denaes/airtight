# Contributing to airtight

## Source of truth

`skill/` is the only authoring surface for the skill: `SKILL.src.md`,
`reference/`, `agents/`, and `scripts/`. `engine/` is the only authoring
surface for the engine, and `engine/rules/*.yaml` for the rules.

Harness directories (`.claude/`, `.cursor/`, `.agent/`, etc.), `plugin/`,
`.claude-plugin/`, and `skill/scripts/engine/` are **tracked in git**.
To eliminate hundreds of duplicate files and multi-megabyte engine bundles,
tracked harnesses symlink `reference` and `scripts` back to canonical
`skill/reference` and `skill/scripts`, while `plugin/` remains fully materialized
for standalone Claude plugin distribution. Do not edit them directly.
(On Windows, enable Developer Mode or clone with `git clone -c core.symlinks=true <url>`).

```bash
npm run build            # rules, engine bundle, dist/ — safe during development
npm run build:release    # also rewrites the tracked harness directories
npm test
```

Keep generated churn out of feature branches. A generated diff conflicts with
every other open branch, so treat `build:release` as a release step unless the
generated output *is* the change.

## Pre-commit progress audit

Before committing any milestone or progress update, run:

```bash
npm run audit:progress        # scans docs, readme, harnesses, demo, tests, versions
npm run audit:progress:fix    # automatically resolves documentation and harness drift
```

Or activate the `repo-progress-audit` workspace skill. A commit must never land with stale rule counts in `README.md`, an out-of-sync `docs/rules.md`, a drifted demo golden, or un-synced tracked harnesses.

## Adding a rule

In this order. Skipping the first step is how a rule ends up matching
something nobody intended.

1. **Fixtures first.** `fixtures/flag/<pack>/<slug>/` with at least four
   true-positive shapes, and `fixtures/pass/<pack>/<slug>/` with at least five
   near-misses. The pass corpus is the half that matters: it is what earns the
   rule the right to interrupt somebody's edit.
2. **The rule**, in `engine/rules/<pack>.yaml`.
3. `npm run build:rules` — validation runs here and rejects eight classes of
   malformed rule.
4. `npm test` — the fixture suite is data-driven off the directory layout, so
   there is no test to write.

Every rule needs a `cwe`, and `why` and `fix` substantial enough to act on.
A rule in the `immediate` tier must be `confirmed` or `firm`: that tier
interrupts an edit in progress, and confidence is what earns that, not
severity.

### Two regex hazards that have already bitten this repo twice each

- **An optional or greedy quantifier before a negative lookahead** backtracks
  to zero width, and the lookahead then runs at the wrong position. Write
  `=(?!\s*"...")\s*`, never `=\s*(?!"...")`. There is a corpus test asserting
  no rule regex matches the empty string, which is the usual symptom.
- **A character class is not a string literal.** `["'][^"']*` ends early on
  `"SELECT ... WHERE name = '"`. Backreference the delimiter:
  `(["'])(?:(?!\1).)*\1`.

## Adding a command

1. `skill/reference/<name>.md`, with no frontmatter.
2. A row in the Commands table in `skill/SKILL.src.md`.
3. An entry in `skill/scripts/command-metadata.json` whose description
   contains "Use when".
4. A `## The way this command fails` section in the playbook. This is not
   decoration: naming a command's characteristic failure in its own words is
   what lets the model recognize it while it is happening.

`npm test` enforces all four.

## Prose

Write for someone under time pressure who does not already agree with you.
Say what to do and why it matters here; skip the paragraph explaining that
security is important.

State uncertainty where it exists. "Reachable only if `render` is called with
request data, which I could not determine statically" is worth more than a
confident guess, and a security tool that guesses confidently is worse than
one that says less.

## Things that must not regress

- **`tests/redaction.test.mjs`** plants known secrets and greps every output
  path for them. If it goes red, airtight is actively dangerous rather than
  merely broken. Fix it before anything else.
- **Sub-agents are read-only.** Both exist to read hostile content and report
  on it. A test fails if either gains `Write`.
- **The hook fails open.** A detector exception, a missing engine, or a
  missing Node runtime must never stop someone from working.
- **Scanned content is data.** Nothing in this repository may treat file
  contents, dependency metadata, or scanner output as instruction.

## Contributions

Open an issue before a large change. If an AI agent prepared the contribution,
say so in the pull request.
