# Command guidance

## Answering questions without running anything

When the user asks which command to use, what a finding means, or how a vulnerability class works, answer directly. Do not run a scan to answer a question about the tool. If they also ask you to run something, follow that request.

## No-argument routing: the context-aware menu

Read this when the user invokes the skill with no argument. They are asking "what should I do here?" Make the answer specific to this repository, not a reprint of the table.

Setup has already run `.grok/skills/airtight/scripts/airtight context`. Reason over what it reported:

- **`NO_THREATS_MD`** — the project has no captured security context. Lead with `init`, one line on why: ranking findings without knowing what data is sensitive ranks them by pattern frequency instead of by risk. Still show the rest.
- **`findings.active` above zero** — lead with the highest-priority open finding by name and location, and `harden` as the action. An existing backlog outranks discovering more.
- **`findings.regressed` above zero** — lead with that instead, regardless of severity. Something the team already fixed has come back, which usually means the fix did not reach where it needed to, and that is a process signal worth more than another scan.
- **`findings.overdue` above zero** — name the count and the oldest. Deadlines that pass silently stop being deadlines.
- **`controls.failing` above zero** — a declared control is not holding. Name it.
- **A recent scan has never run** — offer `audit` for the whole repo, or `review` scoped to whatever `git.changedFiles` points at if that is a coherent surface.
- **`git.changedFiles` concentrated in one area** — scope `review` to it by name. A review of what someone is actually working on lands better than a review of everything.
- **Domains present that have never been scanned** — if the repo has Terraform or Kubernetes manifests and `infra` has never run, say so.

Lead with **two or three pointed picks**, each with the exact command to type and one line of reason drawn from the signals. Then show the full Commands table grouped by category as the fallback.

**Never auto-run a command.** The recommendation is a suggestion the user confirms. This matters more here than in a design tool: `harden` edits security-relevant code, and the offensive commands in later waves touch systems.

If the context command errored or the repository is very large and slow to scan, skip the signal-reading and present the plain menu with `audit` as the suggested start. Never block the recommendation on a scan completing.
