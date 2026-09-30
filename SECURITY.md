# Security Policy

Airtight is a security tool for AI coding agents. We treat vulnerabilities in Airtight with the same rigor we expect Airtight to enforce on other codebases.

## Supported Versions

Only the latest release track receives security updates and backports.

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3.0 | No        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues or discussions.**

To report a vulnerability:
1. Open a **Private Vulnerability Report** via GitHub Security Advisories at [https://github.com/denaes/airtight/security/advisories/new](https://github.com/denaes/airtight/security/advisories/new).
2. Alternatively, email the maintainer directly at `julien.denaes@gmail.com` with the subject line `[SECURITY] Airtight Vulnerability Report`.

### What to Include

Please provide:
- A clear description of the vulnerability.
- Steps to reproduce or a minimal proof of concept (PoC).
- The affected component (e.g. deterministic engine, specific rule in `engine/rules/`, edit hook, redaction vault, or agent skill).
- Any potential impact or blast radius (e.g. secret leakage, hook bypass, prompt injection reachability).

## Response Commitments

We adhere to our own severity response targets:
- **Initial acknowledgment:** Within 48 hours.
- **Triage & severity assessment:** Within 3 business days.
- **Fix timeline:**
  - `P0 / Critical`: Remediation shipped within 7 calendar days.
  - `P1 / High`: Remediation shipped within 14 calendar days.
  - `P2 / Medium`: Remediation shipped within 30 calendar days.

## Safe Harbor & Research Conduct

We consider security research conducted in good faith to be authorized and protected. When testing Airtight:
- Do not attempt to access private data or environments belonging to other users.
- Do not execute denial-of-service attacks against shared infrastructure.
- Coordinate disclosure timelines with maintainers before publishing advisories.
