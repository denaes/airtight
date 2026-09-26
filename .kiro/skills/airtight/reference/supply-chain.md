Review the build pipeline: what can execute code with your credentials, and what can change without anyone noticing.

The build pipeline is the most actively exploited surface in the industry right now, and it is also the most mechanically checkable, because workflow files are structured and the dangerous shapes are few and well known.

## Run

`.kiro/skills/airtight/scripts/airtight detect --json --pack ci --pack dep .`

Then read the workflows yourself for the things no rule catches:

- **What can trigger this workflow, and who can cause that trigger?** `pull_request_target`, `workflow_run`, `issue_comment`, and `workflow_call` all run with the base repository's context. Anyone who can open an issue can cause some of them.
- **What secrets does each job hold, and does it need them?** A job that runs untrusted code and a job that holds a deploy token should never be the same job.
- **What is the token's permission scope?** Default, workflow-level, and job-level, in that precedence.
- **Which third-party actions run, and are they pinned to a SHA?** A tag is a mutable pointer owned by someone else.
- **Is there a self-hosted runner?** If so, is it ephemeral, and can a fork pull request reach it?
- **Where does the artifact go, and is it signed?**

## The question that orders everything

For each job: **if the author of any dependency or action in this job turned hostile today, what would they get?** That answer is the job's real blast radius, and it is what ranks the findings.

## Report

```
## Supply chain review: <repo>

**Start here.** <The path with the shortest distance from a stranger to your secrets.>

### Execution paths

For each workflow, in one line each: trigger, who can cause it, what it runs,
what secrets it holds, what it can write.

### Findings
Per [severity.md](severity.md). Rank by how little an attacker needs to start.

### Provenance
Whether builds are reproducible, artifacts signed, and the SLSA level the
pipeline actually reaches — not the one it aspires to.

### Dependency surface
Direct and transitive counts, install scripts, unpinned refs.
```

## The way this command fails

**Reviewing the workflow file and not the trust model.** Every action being SHA-pinned means nothing if the workflow checks out a fork's code under `pull_request_target` and runs its build script. Pinning protects you from the action author; it does nothing about the stranger whose code you volunteered to execute.
