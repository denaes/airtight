# Working on airtight with Claude Code

Read `AGENTS.md` first; it carries the conventions. This file adds what is
specific to working here with Claude Code.

## Layout

| Path | Role |
|---|---|
| `engine/src/` | The engine. Plain ESM, no runtime dependencies. |
| `engine/rules/*.yaml` | Rule source. Compiled and validated to JSON at build time. |
| `engine/custom/` | Analyzers for rules that cannot be a pattern, registered statically in `engine/src/match/custom.mjs` so the bundle stays one file. |
| `fixtures/` | The rule corpus. Deliberately **not** under `tests/`, because rules that exempt test paths would exclude their own fixtures. |
| `skill/` | The skill. The only authoring surface. |
| `scripts/` | Build. `compile-rules`, `build-engine`, `build`. |
| `.claude/`, `plugin/` | Generated and committed. Do not edit. |

## Landmines

- **`fixtures/` is not `tests/fixtures/`.** It was moved for a reason:
  `py/assert-for-authorization` correctly excludes test paths and so excluded
  its own corpus. Any rule that exempts test directories hits the same wall.
- **The engine bundle needs the `createRequire` banner.** The YAML package's
  CommonJS build calls `require('process')`, which esbuild cannot rewrite into
  an ESM import. Removing the banner produces a bundle that fails at load.
- **The hook manifest uses `[ ! -f X ] || X hook`,** not `X hook || true`. The
  guard makes a missing launcher a no-op while preserving the launcher's exit
  code. `|| true` swallows exit 2, and the blocking path silently stops
  blocking.
- **The launcher avoids `dirname`.** It must resolve itself on a PATH too
  minimal to contain coreutils, so it uses parameter expansion.
- **`SKILL.src.md` is named that way on purpose.** A skill loader discovers a
  skill by finding a literal `SKILL.md`, so the source must not be one.

## Running things

```bash
npm run build && npm test

node engine/src/cli.mjs detect .
node engine/src/cli.mjs findings sync .
node engine/src/cli.mjs controls verify
node engine/src/cli.mjs context

echo '{"session_id":"s","hook_event_name":"PostToolUse","tool_input":{"file_path":"x.js"}}' \
  | node engine/src/cli.mjs hook
```

Exit codes are the contract: `0` clean, `1` the engine failed, `2` findings
present or a control failing.

## Dogfooding

This repository is scanned by its own rules and the self-scan must stay clean.
The synthetic credentials in `tests/redaction.test.mjs` and `tests/hook.test.mjs`
are suppressed by file-scoped inline waivers that name the rules and the reason
— which is also the worked example of how the suppression ladder is meant to be
used.

`.airtight/controls.json` is this project's own control register, including one
control deliberately marked `planned` so the coverage report demonstrates the
distinction between verified-clean and actually-implemented.
