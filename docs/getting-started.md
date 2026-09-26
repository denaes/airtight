# Getting started

## Install

```bash
npx airtight install
```

It detects the harnesses you have and asks before writing. To skip detection:

```bash
npx airtight install --providers=claude-code,cursor --yes
npx airtight install --scope=global        # into ~/<harness dir>
npx airtight install --no-hooks            # skill only
```

Claude Code users can also install from the plugin marketplace:

```
/plugin marketplace add denaes/airtight
```

Any harness can be vendored by copying its directory out of a clone:

```bash
git clone https://github.com/denaes/airtight
cp -r airtight/.cursor your-project/
```

Requires Node 20 or later and nothing else. The engine ships as one bundled
file with no runtime dependencies.

Check what landed:

```bash
npx airtight check
```

## First run

**1. Capture what matters here.**

```
/airtight init
```

This reads the repository, asks only about what the code cannot tell it, and
writes two files:

- `THREATS.md` — assets, actors, trust boundaries, the authn and authz model,
  compensating controls, and what you deliberately do not defend against.
- `CONTROLS.md` plus `.airtight/controls.json` — how *this* project does
  security: which authorization helper, which crypto library, how secrets are
  loaded.

Both are worth the ten minutes. Without `THREATS.md`, findings get ranked by
pattern frequency instead of by risk, and "SQL injection in the billing
service" sorts level with "SQL injection in the changelog generator".

**2. See where you stand.**

```
/airtight audit
```

Broad and shallow: every enabled domain, scored, with findings grouped by
priority and an explicit statement of what was *not* covered.

**3. Go deep on something that matters.**

```
/airtight review src/api/billing
```

Narrow and deep. Two isolated sub-agents — one reading code, one running the
detector — then adversarial verification of every finding before it reaches
the report.

**4. Fix.**

```
/airtight harden src/api/billing
```

The only command that edits.

## The edit hook

If you installed hooks, airtight now runs on every edit. After a write it
checks the immediate tier: the rules that are mechanical, unambiguous, and
cheap to correct right there. At the end of a turn it runs everything over the
files that changed.

A `critical` finding at `confirmed` confidence blocks the write. Everything
else advises. A detector failure, a missing engine, or a missing Node runtime
all fail open — the hook never stops you working.

```bash
airtight hooks status
airtight hooks off      # disable without uninstalling
```

## When it is wrong

It will be. Read [waivers](waivers.md) before reaching for the broadest one:
the narrowest rung is self-service and the broad ones need a human, and that
boundary is the only thing that keeps a waiver meaningful.
