Ingest, deduplicate, and triage third-party scanner reports (SARIF, Snyk, Dependabot, Trivy). Turn raw scanner alerts into actionable findings ranked by actual reachability.

Third-party scanners are high-volume, low-context tools. They detect patterns and flag CVEs without knowing whether the code is reachable, whether compensating controls exist, or whether the package is a dev-only CLI tool. Triage filters the noise, verifies reachability, and integrates confirmed findings into Airtight's lifecycle.

## Run

1. **Read the report file**: Inspect the format (SARIF 2.1.0 JSON, Snyk CLI JSON, GitHub Dependabot alert export, or Trivy JSON).
2. **Extract raw findings**: Extract rule ID, scanner source, file path, line numbers, CWE, CVSS score, and description.
3. **Filter test paths & vendored noise**: Apply Airtight's test path policy. Test fixtures, mock servers, and demo files are downgraded or suppressed unless they contain real committed secrets.
4. **Deduplicate across tools**: If Trivy, Snyk, and Dependabot all flag CVE-2024-XXXXX in the same lockfile, merge them into a single finding with multiple citations.
5. **Verify reachability**:
   - For SAST findings (SARIF): Inspect the reported source file and line. Is the sink reachable from an untrusted entry point?
   - For SCA / dependency findings: Check whether the vulnerable function is actually imported and invoked, or whether it resides in an unimported sub-module or devDependency.
6. **Assign Airtight priority**: Map scanner severities to P0-P3 based on real impact and reachability per [severity.md](severity.md). An "unreachable Critical" is P3 or informational; a "reachable High" in an auth path is P0.

## Report

```
## Triage report: <report-file> (<scanner-type>)

**Start here.** <The single highest-risk finding that is actually reachable, and what to do about it.>

### Summary

| Ingested | Duplicates merged | Filtered (noise/test) | Reachable P0-P1 | Deferred P2-P3 |
|----------|-------------------|-----------------------|-----------------|----------------|
| N        | N                 | N                     | N               | N              |

### Actionable findings

For each reachable or high-confidence finding, ordered by [severity.md](severity.md):

- **[P?] <title / rule ID> — <summary of real risk>**
- **Scanner**: <Tool name> (<original scanner severity>)
- **Location**: file:line (or package@version)
- **Reachability**: verified reachable at <call site> | plausible | unproven
- **Impact**: what an attacker can actually achieve in this application
- **Fix**: specific remediation (upgrade target, sanitization, config change)

### Grouped & Deferred (Noise / Unreachable)

- **Unreachable dependencies**: List packages flagged by SCA that are not imported in production code paths or are devDependencies.
- **Suppressed / Test paths**: Findings inside test corpora, mocks, or internal documentation.
- **False positives**: Rules that fired on safe idioms or sanitized inputs, with the reason.
```

Close with **Recommended actions**:
- Run `airtight findings sync` to persist actionable findings into the local findings store.
- Run `/airtight harden <target>` to remediate the top triaged vulnerabilities.

## The way this command fails

**Amplifying scanner noise.** Importing raw scanner counts without reachability verification and dumping forty "criticals" onto a team when thirty-nine are in unreachable test utilities. A security triage tool that forwards raw scanner alarmism destroys developer trust faster than having no scanner at all. The entire value of triage is the triage: separating what can be reached from what merely exists in the directory tree.
