Run the deterministic engine across every enabled domain and report what it found, scored. **Document, do not fix.** `harden` fixes; mixing the two produces a report nobody can check because the code moved underneath it.

Audit is broad and shallow. `review` is narrow and deep. When someone asks "is this secure?", audit is the right first answer and review is the right second one.

## Run

1. `.veto/skills/airtight/scripts/airtight detect --json .`, or scoped to the target when one was given.
2. `.veto/skills/airtight/scripts/airtight controls verify` when a control register exists.
3. `.veto/skills/airtight/scripts/airtight findings sync .` after reporting, so the results enter the store.

Read the JSON. Do not re-derive it by reading files the engine already read.

**Verify before reporting.** Open the file at every `confirmed` critical and high finding and confirm the engine read it the way you would. The engine is deterministic, not omniscient: it does not know that `fixtures/` is a corpus of deliberate examples or that a file is dead code. Findings you believe are false positives stay in the report, marked as such with the reason, rather than being silently dropped. Dropping them means the next audit rediscovers them.

## Report

```
## Security audit: <scope>

**Start here.** <The single highest-value action, and what it prevents.>

### Posture

| # | Domain | Score | Key finding |
|---|--------|-------|-------------|
| 1 | Secrets and credentials | ? | [or "--"] |
| 2 | Application code | ? | |
| 3 | Dependencies and supply chain | ? | |
| 4 | CI/CD pipeline | ? | |
| 5 | Infrastructure and containers | ? | |
| **Total** | | **??/20** | **[band]** |

Domains with nothing to scan are `n/a` and leave the denominator. Scoring and bands: [severity.md](severity.md).

### Findings by priority

Group under P0, P1, P2, P3. Within a group, order by exploit distance.

- **[P?] <rule id> — <what it means here>**
- **Location**: file:line
- **Class**: CWE-nnn
- **Why it matters here**: one line tied to this project, not the generic description
- **Fix**: the specific change

Collapse repeats: fifteen instances of one rule is one entry with a count and up to three example locations. A wall of identical findings buries the single different one.

### Control verification

Per [severity.md](severity.md) dispositions. Report holding, failing, unverifiable, and broken separately. `unverifiable` and `holding` are different claims and must not be merged.

### False positives

Every finding you judged incorrect, with the reason and the waiver command that would suppress it. If there are none, say so.

### Coverage

What was **not** scanned and why: languages with no pack yet, files skipped as too large or binary, domains with no rules. An audit that does not state its coverage implies total coverage, which is the most consequential thing a security report can get wrong.
```

Close with **Recommended actions** in order. Only recommend from `/airtight deps`, `harden`, `infra`, `init`, `review`, `secrets`, `supply-chain`, `threat-model`. End with `/airtight harden` when anything is fixable.

**NEVER**:
- Report a finding without saying what it means *for this project*.
- Present a count as a score. Forty low findings and one critical is not a worse posture than two criticals.
- Imply coverage you do not have.
- Fix anything. Note it and route to `harden`.

## The way this command fails

**Volume presented as rigour.** A hundred findings in priority order looks thorough and is unusable. If the engine returns a hundred, the report's job is to say which five matter and why the other ninety-five are grouped, deferred, or noise. A reader who stops after the first screen should still have the important thing.
