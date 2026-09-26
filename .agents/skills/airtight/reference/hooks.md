Manage the edit hook for this project.

```
$airtight hooks on            install and enable
$airtight hooks off           disable without uninstalling
$airtight hooks status        current state and limits
$airtight hooks ignore-value <rule> "<value>" --reason "<who decided: evidence>"
$airtight hooks ignore-file <glob>     needs the user
$airtight hooks ignore-rule <rule>     needs the user
```

## What the hook does

Two tiers. After an edit, the immediate tier runs: the rules that are mechanical, unambiguous, and cheap to correct right there. On stop, the deep pass runs every rule over the files touched this session.

A `critical` finding at `confirmed` confidence blocks the edit. Everything else advises. A detector failure always fails open — a broken scanner must never stop someone working.

## The suppression ladder

Three rungs, deliberately unequal in who may use them:

- **`ignore-value`** — one value, one rule. **You may add this yourself** when you are confident it is a false positive or a sanctioned exception, provided `--reason` names who decided and on what evidence. Write "user confirmed" only when the user actually confirmed.
- **`ignore-file`** — every rule, including rules written next year, for a path. **Needs the user.**
- **`ignore-rule`** — a rule, project-wide. The bluntest tool here. **Needs the user.**

**Never add a waiver to get past a blocked write.** A waiver records a decision someone made. Using one to silence a finding you did not understand falsifies that record, and the record is the only reason waivers are tolerable at all.

Inline waivers are narrower still and often the right answer for a single line:

```
// airtight-disable-next-line secret/aws-access-key-id -- documented example key
# airtight-disable py/assert-for-authorization -- test file, asserts are the point
```

## Reporting a hook finding

When the hook surfaces findings, triage each and say in your reply what you fixed, what you suppressed, and what you left standing. Leaving a finding standing is a legitimate outcome; leaving it standing silently is not.
