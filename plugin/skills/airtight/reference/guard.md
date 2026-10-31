# Guard: Active Agent Execution Guardrail

The guardrail evaluates agent tool invocations in real time before execution, preventing destructive system commands, credential exfiltration, workspace breakout, and unsafe database modifications.

## When to run

Run before executing any autonomous tool command (bash command, filesystem write, database query, or remote HTTP request) when operating in agentic mode or evaluating untrusted command strings.

```bash
airtight guard <bash|write|sql|fetch> [args...]
```

Options:
- `--json`: machine-readable evaluation output with verdict, rule, CWE, and recommendation.

Exit codes:
- `0`: execution allowed (clean or non-blocking warning).
- `2`: execution blocked (violates safety invariants).

## What the guard catches

1. **Bash / Shell (`tool=bash`)**:
   - Destructive deletions: `rm -rf /`, `rm -rf ~`, `rm -rf *`
   - Unvetted remote execution: `curl ... | bash`, `wget ... | sh`
   - Raw disk wipes: `mkfs`, `dd if=... of=/dev/sd*`
   - Credential exfiltration: `curl -d @.env`, `nc ... < id_rsa`
   - Force-pushing to production: `git push --force origin main`

2. **File Modifications (`tool=write`)**:
   - VCS tampering: `.git/config`, `.git/hooks/*`
   - SSH identity tampering: `~/.ssh/authorized_keys`, `id_rsa`
   - Host system modifications: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`

3. **Database Queries (`tool=sql`)**:
   - Destructive DDL: `DROP TABLE`, `DROP DATABASE`, `TRUNCATE TABLE`
   - Unbounded mutations: `DELETE FROM table` or `UPDATE table SET ...` without `WHERE`

4. **Network Requests (`tool=fetch`)**:
   - Cloud metadata SSRF: `http://169.254.169.254/`
   - Internal daemon probes: `127.0.0.1:2375` (Docker), `localhost:6379` (Redis)

## The way this command fails

The way this command fails is by treating a blocked tool execution as a generic execution error rather than a security invariant enforcement. When a tool call is blocked with exit code 2, the agent must not attempt to evade the block with shell aliasing or obfuscation (e.g. `eval`, `base64 -d`, or temporary shell scripts). The agent must acknowledge the invariant violation and propose a safe, bounded alternative.
