Report and repair drift between this project's airtight artifacts and what the installed version reads. This is maintenance, not security work.

```
.claude/skills/airtight/scripts/airtight doctor --json
.claude/skills/airtight/scripts/airtight doctor --fix
```

## What this owns

Whether THREATS.md and CONTROLS.md exist and parse; whether the control register references rules that still exist; whether the findings store is readable and its records use the current schema; whether the hook is installed and its manifest matches this version; whether config names rules that were renamed or removed.

## What this does not own

Anything about the security of the code. A project can be fully in order by this command's reckoning and thoroughly insecure. Do not let a clean doctor report read as a clean security report.

## Act by severity

The severity says what should happen, not how bad it is.

- **`auto`** — no decision involved. Run `--fix` once, then report in one line what moved. Do not ask first, and do not ask afterwards.
- **`mention`** — the user should know but need not decide now. One sentence each, with the fix you would apply.
- **`route`** — needs a specific command. Name it and the gap it closes. Run it only if the user asks in this turn; `init` is a conversation, not a repair you perform unattended.

## The broken-verifier case

A control whose verification names a rule that no longer exists is the most consequential drift this command finds, and it is `mention`, never `auto`. The control has been reporting as verified while nothing checked it. Say exactly that, name the control, and let the user decide whether the rule was renamed or the control needs rewriting.

An empty findings array is the good outcome. Say so in one line and stop.
