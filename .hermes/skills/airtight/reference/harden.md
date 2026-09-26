The one command that edits. Apply remediations in triage order, verify once, and stop.

**Read [security-floor.md](security-floor.md) before the first edit.** Every fix you write is new security-relevant code and is held to the same floor as the code you are fixing.

## 1. Establish the backlog

Take the findings from the store rather than re-deriving them:

```
.hermes/skills/airtight/scripts/airtight findings list --json
```

If the store is empty, run `.hermes/skills/airtight/scripts/airtight findings sync <target>` first. If the user named specific findings, use those and leave the rest.

**Regressed findings come first, regardless of severity.** Something the team already fixed has come back, which means the fix did not reach where it needed to, and repeating it without understanding why will produce the same result.

## 2. Triage

Fix in this order. It is not severity order, because severity does not account for what a fix costs or what it might break.

1. **Live credentials.** Rotation is a clock running; everything else can wait an hour.
2. **Unauthenticated, remotely reachable, confirmed.** Injection, deserialization, authentication bypass.
3. **Authorization gaps**, including tenant scoping. These are usually small edits with large blast radius.
4. **Confirmed findings needing a precondition.**
5. **Configuration hardening** in CI, containers, and IaC. Often one-line, often high value.
6. **Tentative findings.** Verify before fixing. A fix for a vulnerability that was not there is a change with risk and no benefit.

## 3. Fix

For each finding:

- **Fix the cause, not the symptom.** Parameterize the query; do not add an escaping helper. Add the authorization check; do not filter the response after fetching.
- **Use this project's existing mechanism.** CONTROLS.md names it. A correct hand-rolled check next to forty uses of the shared helper is still a defect, because the next change to the helper will not reach it.
- **Fix the class where the class is small.** Three instances of the same missing check get fixed together. Forty instances is a refactor, which you propose rather than perform.
- **Never widen scope silently.** If a fix requires a schema change, a new dependency, or a broader permission, stop and say so.
- **Never weaken a test to make it pass.** A test that only passes with verification disabled is telling you the test encoded the bug.

## 4. Verify, once

Re-run the check that produced each finding — `.hermes/skills/airtight/scripts/airtight detect --json <files>` for rule findings — then `.hermes/skills/airtight/scripts/airtight findings sync` to close them in the store. Run the project's tests if there are any.

One verification pass. If it surfaces something new, fix that in the same batch and confirm with at most one more round. Do not enter a scan-fix-scan loop; it costs the user money to rediscover what the first pass already said.

## 5. Report

State, plainly:

- **Fixed**: each finding, what changed, and the verification that confirms it.
- **Not fixed**: each remaining finding and why — too large, needs a decision, needs a credential you do not have, unverified.
- **Changed beyond the fix**: anything you touched that was not a finding.
- **Needs a human**: rotations, deploys, permission changes, anything outside the repository.

A remediation report that implies completeness it does not have is worse than no report, because it ends the investigation.

## The way this command fails

**Declaring victory on the code and forgetting the world.** Removing a hardcoded key from source is not fixing the leak: the key is still live, still in git history, and still in every clone. The edit is one step of the fix and usually not the important one. Every credential finding closes with a rotation the user must perform, and saying so is part of the fix, not a footnote.
