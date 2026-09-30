# Changelog

All notable changes to Airtight are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2026-09-30

### Added
- **SARIF 2.1.0 Output Renderer**: `airtight detect --format sarif` outputs compliant OASIS SARIF 2.1.0 JSON with full rule metadata (CWEs, OWASP tags, descriptions, remediation markdown), precision ratings, and location fingerprints (`partialFingerprints.primaryLocationLineHash`) for seamless integration with GitHub Code Scanning, GitLab SAST, and DefectDojo. All SARIF fields scrub through the engine's secret redaction vault.
- **Reusable Composite GitHub Action (`action.yml`)**: Official composite GitHub Action at repository root (`denaes/airtight@v0.3.1`) for automated CI/CD security scanning. Supports configurable scan paths, baseline suppression (`baseline`), git diff scoping (`since`), SARIF reporting, automatic SARIF upload to GitHub Code Scanning via `github/codeql-action/upload-sarif`, and compliance control verification (`verify-controls`).
- **Unified Output Formatting**: Added `--format <text|json|sarif>` to the CLI engine (`--json` preserved as an alias for `--format json`).
- **Redaction Containment Suite**: Extended `tests/redaction.test.mjs` to verify that planted secrets never escape through in-process SARIF rendering or CLI SARIF export.

## [0.3.0] - 2026-09-30

### Added
- **Multi-Language Expansion**: Added 40 deterministic rules across Go, Java, Rust, Python, and JavaScript, expanding rule corpus from 151 to 191 rules (131 immediate tier, 60 deep tier).
- **Go Pack** (19 rules): SQL injection (`sql-string-concat`), shell command execution (`command-exec-shell`), insecure TLS verification (`tls-insecure-skip-verify`), temporary files in `/tmp` (`tempfile-insecure`), custom entity XXE (`xxe-xml-decoder`), SSRF (`ssrf-from-input`), Zip Slip (`zip-slip`), template escaping bypass (`html-template-unescaped`), cookie flags, Gin debug mode.
- **Java Pack** (18 rules): LDAP injection (`ldap-injection`), path traversal from request parameters (`path-traversal`), SSRF (`ssrf-from-input`), Spring Security CSRF disablement (`spring-csrf-disabled`), CORS wildcard with credentials (`cors-wildcard`), insecure deserialization, XXE parsers, SQL concatenation, command exec, weak hash/cipher.
- **Rust Pack** (8 rules): Insecure temporary file creation in shared system directories (`tempfile-insecure`), command injection (`command-injection`), SQL format string interpolation (`sql-format`), path traversal (`path-traversal`), weak RNG (`weak-rng`), TLS skip verify.
- **Python Pack** (34 rules): JWT decoded without signature verification (`jwt-decode-unverified`), deprecated `ssl.wrap_socket` (`ssl-wrap-socket-deprecated`), Zip Slip (`zipfile-extractall`), ReDoS from request input (`re-compile-from-input`), MongoDB `$where` evaluation (`nosql-injection`), Paramiko `AutoAddPolicy`.
- **JavaScript & TypeScript Pack** (29 rules): JWT decoded without signature verification (`jwt-decode-unverified`), excessive body parser request limits (`express-body-parser-large-limit`), prototype pollution, node-serialize, libxml XXE, CSRF ignore methods.
- **CLI Stale Rule Detection**: `engine/src/cli.mjs` checks file modification timestamps on `engine/rules/*.yaml` and warns developers when source YAMLs are newer than the compiled rule bundle.
- **Rule Breakdown Command**: `airtight rules --count-by-pack [--json]` emits per-pack rule distributions.
- **Baseline Filtering Mode**: `airtight detect --baseline <path>` suppresses known findings from historical `.airtight/findings.ndjson` or JSON scans, reporting only new net-delta findings and enabling immediate CI adoption on legacy repositories.
- **Git Diff Mode**: `airtight detect --since <git-ref>` restricts scanner execution to files modified or added since a git reference, drastically speeding up PR analysis.
- **Automated Pack Table Auditing**: Pre-commit progress audit (`npm run audit:progress`) verifies that the README rule packs table and counts exactly match compiled engine state.
- **CI Supply-Chain Hardening**: GitHub Actions workflows pin third-party actions to immutable commit SHAs with semantic version trailing comments, and check all 18 tracked agent harnesses for output drift.

## [0.2.0] - 2026-09-27

### Added
- Multi-language engine support with initial Go (6 rules), Java (7 rules), and Rust (1 rule) sinks.
- Pre-commit progress audit suite (`scripts/progress-audit.mjs` and `npm run audit:progress:fix`) to enforce zero documentation, rule count, or harness drift.
- Secret redaction vault with masking at finding generation time and plant-and-grep output verification tests (`tests/redaction.test.mjs`).
- Findings store (`.airtight/findings.ndjson`) tracking state transitions (`open` &rarr; `fixed` &rarr; `regressed`) and waiver expirations with named approvers.
- Verified compliance controls register (`airtight controls verify`) projecting findings onto SOC 2, ISO 27001, and CIS benchmarks.
- Multi-harness generator supporting 18 AI coding agent environments (Claude, Cursor, Gemini, Copilot, Trae, etc.).

## [0.1.0] - 2026-09-24

### Added
- Initial release of Airtight: deterministic security rule engine, edit-site hook, and review playbooks.
- Core rule packs for secrets (15 formats), Docker containers (10 rules), Kubernetes manifests (18 rules), CI/CD workflows (8 rules), dependencies (12 rules), Terraform (20 rules), JavaScript sinks, and Python sinks.
- Edit-time hook with rate limiting, session deduplication, and fail-open guarantees.
