# Severity, confidence, and disposition

This file owns these tables. Every other reference links here rather than restating them, so there is exactly one place to change when the model changes.

Three axes, deliberately orthogonal. Collapsing them into a single number is what makes security tooling unusable: it forces you to choose between reporting an unproven catastrophe and a proven annoyance at the same rank, and the reader learns to distrust both.

## Severity — exploitability times impact

| Severity | Means | SLA |
|---|---|---|
| **critical** | Direct path to data loss, account takeover, or code execution. An attacker with no prior access can reach it. | 7 days |
| **high** | Serious impact but needs a precondition: an authenticated session, a specific role, a second bug, or network position. | 30 days |
| **medium** | Meaningful weakening of a control, or a serious issue behind a strong compensating control. | 90 days |
| **low** | Hardening. Real, worth fixing, not worth waking anyone. | 180 days |

Severity describes the finding, not the project. A critical finding in a prototype with no users is still critical; what changes is the urgency, and urgency is the user's call to make with the facts you give them.

## Confidence — how sure you are

| Confidence | Means |
|---|---|
| **confirmed** | The pattern *is* the vulnerability, or you traced the path, or an exploit demonstrated it. |
| **firm** | Almost certainly real. A legitimate explanation exists but is rare and you did not find one here. |
| **tentative** | The dangerous shape is present. Reachability is unproven. |

Never present a tentative finding as though it were confirmed. Write the uncertainty into the finding: "reachable only if `renderTemplate` is ever called with request data, which I could not determine from static reading" is more useful than a confident guess, and it tells the reader exactly what to check.

## Priority — what the reader sees

Priority is **derived**, never authored:

| | confirmed | firm | tentative |
|---|---|---|---|
| **critical** | P0 | P0 | P1 |
| **high** | P1 | P1 | P2 |
| **medium** | P2 | P2 | P3 |
| **low** | P3 | P3 | P3 |

**A tentative finding is never P0.** Dropping everything for something that might not be reachable is how a team learns to ignore P0. Verify it first, then it can be P0.

## Disposition — what should happen next

Says what to do, not how bad it is.

- **`fix`** — remediate it. The default.
- **`verify`** — the finding is real-shaped but unproven. Trace it, or prove it, before anyone spends remediation effort.
- **`accept`** — a human decides to carry the risk. Requires a named approver, a reason, and preferably an expiry. Only the user can accept; you can recommend it.
- **`route`** — not this command's job. Name the command that owns it.

## Ranking

Rank by priority, then by exploit distance: how many things an attacker needs before this becomes useful to them. Unauthenticated and internet-reachable outranks authenticated, which outranks requiring an admin role, which outranks requiring a second unfixed bug.

When two findings tie, the one with a shorter fix goes first. A P1 that is a one-line change and a P1 that is a refactor are not the same ask.

## Scoring a domain

When a command scores a domain out of 4:

| Score | Criteria |
|---|---|
| 0 | No control present; the domain is unaddressed |
| 1 | Token effort; the common case is unprotected |
| 2 | Partial; the happy path is covered, the edges are not |
| 3 | Good; consistent coverage with specific gaps |
| 4 | Strong; consistent, tested, and enforced mechanically |

**Renormalize for non-applicable domains.** The maximum is 4 times the number of domains you actually scored: `/20` for five, `/16` when one is `n/a`. Never print `/20` over a partial set. Rating bands by percentage: 90%+ strong, 70%+ good, 50%+ acceptable, 30%+ weak, below that critical.
