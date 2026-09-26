# CI integration

## Exit codes

| Code | Means |
|---|---|
| `0` | Clean |
| `1` | The engine itself failed |
| `2` | Findings present, or a control failing, or something overdue |

Exit `1` and exit `2` mean different things and should be handled
differently. A `1` is a bug in airtight or a broken install, and failing the
build on it is right. A `2` is airtight working.

## A reasonable gate

```yaml
permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # git history, for the secrets scan
      - uses: actions/setup-node@v4
        with:
          node-version: '24'

      - run: npx airtight-security install --providers=claude-code --yes --no-hooks

      # Block only on what is both severe and certain. Everything else is
      # reported and tracked rather than used to stop a merge.
      - name: Block on confirmed critical findings
        run: .claude/skills/airtight/scripts/airtight detect --tier immediate .

      - name: Track everything
        run: .claude/skills/airtight/scripts/airtight findings sync .

      - name: Remediation deadlines
        run: .claude/skills/airtight/scripts/airtight findings overdue

      - name: Declared controls still hold
        run: .claude/skills/airtight/scripts/airtight controls verify
```

## What to fail on, and what not to

Failing on every finding trains people to add waivers, and a waiver added to
get a build green is worse than the finding it hid.

A defensible split:

- **Fail** on the immediate tier. It is high-confidence and mechanical, and
  the fix is usually one line.
- **Fail** on `findings overdue`. A deadline nobody enforces is not a
  deadline.
- **Fail** on `controls verify`. You declared these.
- **Report** everything else through `findings sync`, and review the store on
  a cadence rather than at merge time.

## Secrets in CI output

Findings are redacted inside the engine, not at the renderer, so a credential
cannot reach CI logs through any output path. There is a build-gating test
that plants known secrets and greps every output mode for them.

Still pass `fetch-depth: 0` if you want history scanned, and remember that a
credential found in history is live until rotated — the CI job cannot do that
part.

## Pre-commit

```bash
airtight detect --tier immediate $(git diff --cached --name-only --diff-filter=ACM)
```

Fast, because the immediate tier is the cheap half. Keep the full sweep in CI.
