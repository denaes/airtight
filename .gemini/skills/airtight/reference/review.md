### Purpose

Deep security review of a target: reachability, authorization, trust boundaries, and drift from this project's own controls. This is the command that does what a scanner cannot. The engine already found the dangerous shapes; your job is to say which of them an attacker can actually reach, what they get when they do, and which of this project's stated controls is quietly not being followed.

### Hard invariants

- **Assessment A (reasoning) and Assessment B (deterministic evidence) are both required.**
- **A and B MUST run as two isolated sub-agents whenever a sub-agent tool is exposed.** Running them inline is possible and is not permitted; it is a degraded run. Inline is allowed only when no sub-agent tool exists in this session.
- **"Unavailable" means exactly one thing: no sub-agent tool is exposed.** It does not mean inconvenient, slow, or probably-fine-without.
- **If you degrade for any reason, the report's first line MUST be:** `⚠️ DEGRADED: single-context (<reason>)`. A silent degraded review is a failed review. The reason B is isolated is that deterministic findings anchor judgment: once you have read a list of forty rule hits, you review the list instead of the code, and the vulnerability that has no rule stays invisible.
- **Every finding A produces passes through adversarial verification before it reaches the report.** A reasoning model generating plausible vulnerabilities is the failure mode of this entire category of tool.

### Setup

1. **Resolve the target** to concrete paths. "the API" means the route definitions and their handlers; "checkout" means the flow end to end, not one file. Prefer a directory or a coherent surface over a single file, because authorization bugs live in the gap between files.
2. **Read THREATS.md and CONTROLS.md** if `context` reported them. THREATS.md tells you what is worth stealing here, which is what makes ranking possible. CONTROLS.md tells you what "correct" looks like in this codebase, which is what makes drift detectable.
3. **Read the findings store** for this target. A finding already accepted with a reason does not need rediscovering, and a finding marked regressed deserves more attention than a new one, not less.

### Assessment orchestration

Spawn both, then wait for both.

**Assessment A — `airtight-reviewer`.** Give it the resolved target, the contents of THREATS.md and CONTROLS.md, and this instruction: do not run the detector. It reviews code, not rule output.

> Return: entry points and who can reach them; the authorization model as implemented and where it is inconsistent; data flows from untrusted input to dangerous sinks with the intermediate steps named; drift from CONTROLS.md; business-logic and abuse paths; 3-6 priority findings each with a concrete exploit path or an explicit statement that the path is unproven; 2-3 things the codebase does well.

**Assessment B — deterministic evidence.** Run `.gemini/skills/airtight/scripts/airtight detect --json <target>` and, if a control register exists, `.gemini/skills/airtight/scripts/airtight controls verify`.

> Return: findings JSON with counts by priority; controls failing or broken; rules that could not run and why; any finding you believe is a false positive, with the reason.

**Then verify.** Every finding from A that claims exploitability goes to `airtight-verifier` before it enters the report. Findings from B that are `confirmed` skip verification; findings from B that are `tentative` go through it too.

### Synthesis

Merge, do not concatenate. A finding that both assessments found is one finding with two sources of evidence and higher confidence, not two entries.

Where A and B disagree, A wins on reachability and B wins on presence. If B reports a sink that A traced to unreachable code, keep it at `tentative` with A's reasoning recorded, rather than dropping it: "unreachable today" is a property of today's call graph.

### Report

The chat response is the deliverable. Present the whole report in chat. Writing it to a file and linking it is not delivering it.

```
⚠️ DEGRADED: single-context (<reason>)        ← only when degraded
Method: dual-agent (A: <id> · B: <id>)

## Security review: <target>

**Start here.** <One sentence: the single thing to fix first, and what happens if nobody does.>

### Posture

| # | Domain | Score | Key finding |
|---|--------|-------|-------------|
| 1 | Authentication and session | ? | [or "--"] |
| 2 | Authorization and tenancy | ? | |
| 3 | Input handling and injection | ? | |
| 4 | Secrets and cryptography | ? | |
| 5 | Dependencies and supply chain | ? | |
| **Total** | | **??/20** | **[band]** |

Score and renormalize per [severity.md](severity.md). A domain this target genuinely does not contain is `n/a` and leaves the denominator.

### Findings

For each, most severe first:

- **[P?] <what an attacker does, in one line>**
- **Location**: file:line, or the flow across several
- **Class**: CWE-nnn, and the OWASP category if it has one
- **Reach**: who can trigger this — unauthenticated, any user, admin only, requires another bug
- **Impact**: what they get
- **Evidence**: the traced path, the rule that fired, or the verifier's verdict
- **Fix**: the specific change, not the principle
- **Confidence**: confirmed | firm | tentative, and what would settle it if tentative

### Control drift

Where the code does something CONTROLS.md says is done differently. Not a vulnerability by itself, and worth its own section because it is how vulnerabilities get reintroduced after they are fixed.

### What holds up

Two or three things done well, specifically. Not filler: telling someone their tenant scoping is consistent everywhere except one query is what makes them fix that one query.

### Questions

Two or three things you could not determine from the code and a human can answer in a sentence. "Is /internal/metrics reachable from outside the VPC?" is worth more than another tentative finding.
```

Close with **Recommended actions**: the ordered next commands. Only recommend from `/airtight audit`, `deps`, `harden`, `infra`, `init`, `review`, `secrets`, `supply-chain`, `threat-model`. End with `/airtight harden <target>` when there is anything to fix.

### Persist

After delivering in chat, run `.gemini/skills/airtight/scripts/airtight findings sync <target>` so the findings enter the store with their lifecycle. Report the one-line result. If the sync fails, say so and move on; the review is not invalidated by a bookkeeping failure.

### The way this command fails

**Plausible findings.** A reasoning model asked to find vulnerabilities will find them, whether or not they are there, and they will be well written and specific and wrong. The verifier pass exists for exactly this, and skipping it because the findings "look obviously real" is skipping it at the moment it was most needed. A review that reports four real findings is worth more than one that reports twelve of which four are real, because the reader has no way to tell which four.
