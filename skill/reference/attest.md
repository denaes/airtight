Export machine-verified control evidence for security compliance audits (SOC 2 Type II, ISO 27001, HIPAA, PCI-DSS).

Compliance auditors do not want narrative promises; they want dated, verifiable proof that security controls are active, monitored, and technically enforced. `attest` evaluates the current repository state against the project's declared controls, checks finding SLA adherence in the findings store, and emits an audit-ready evidence package.

## Run

1. **Load controls**: Read `CONTROLS.md` and the machine-readable control register via `airtight context`.
2. **Execute automated control verification**: Run `airtight controls verify` to test every automated control against the live repository configuration.
3. **Audit finding SLAs**: Run `airtight findings overdue` to check if any open vulnerability has breached its resolution deadline per [severity.md](severity.md).
4. **Inspect dependency & pipeline posture**:
   - Run `airtight detect --pack dep,ci .` for dependency hygiene and CI pipeline protection.
   - Run `airtight sbom .` to capture the current software bill of materials.
5. **Map to compliance criteria**: Map evaluated controls to target framework requirements:
   - **SOC 2 Type II**: CC6.1 (logical access controls), CC6.6 (boundary protection & injection defenses), CC6.8 (malicious software prevention / dependencies), CC7.1 (vulnerability management SLAs), CC8.1 (change management & CI verification).
   - **ISO/IEC 27001:2022**: A.8.8 (management of technical vulnerabilities), A.8.9 (configuration management), A.8.28 (secure coding).
6. **Compile Evidence Manifest**: Output the machine-verifiable attestation document.

## Report

```
## Security Attestation: <project-name>

**Target Framework**: SOC 2 Type II / ISO 27001:2022
**Commit SHA**: <git commit hash>
**Generated**: <ISO 8601 UTC timestamp>
**Engine Version**: <airtight version>

### Executive Summary

| Total Controls | Passing | Failing | Unverifiable | Overdue SLA Findings |
|----------------|---------|---------|--------------|----------------------|
| N              | N       | N       | N            | N                    |

**Attestation Status**: PASS | CONDITIONAL | FAIL

### Control Evidence Register

For each declared control in CONTROLS.md:

| Control ID | Description | Framework Mapping | Status | Evidence / Verification Method |
|------------|-------------|-------------------|--------|--------------------------------|
| CTL-01     | Automated dependency scanning | SOC 2 CC6.8 / ISO A.8.8 | PASS | Engine rule `dep/osv-advisory` active; CI gate confirmed |
| CTL-02     | Static code security analysis | SOC 2 CC6.6 / ISO A.8.28 | PASS | `airtight detect` executed with 0 critical findings |
| CTL-03     | Vulnerability remediation SLA | SOC 2 CC7.1 / ISO A.8.8 | PASS | 0 overdue findings in findings store |

### Open Findings & SLA Posture

- **Active P0 Findings**: N (Overdue: N)
- **Active P1 Findings**: N (Overdue: N)
- **Active P2 Findings**: N (Overdue: N)
- **Accepted Waivers**: List approved waivers with business reason and expiration date. Expired waivers are flagged as failing controls.

### Supply Chain & Build Integrity

- **SBOM Hash**: SHA-256 of generated CycloneDX 1.5 document.
- **CI Pipeline Controls**: Unpinned third-party actions, excessive permissions (`write-all`), or missing branch protections.
```

## The way this command fails

**Paper compliance over technical truth.** Generating a green attestation report because `CONTROLS.md` describes a security policy, while ignoring that `airtight controls verify` reported three failing controls or that an unpatched P0 has been open for 45 days. An auditor who cross-references a green attestation with the actual repository commit or CI pipeline and finds overdue criticals will reject the entire evidence submission. Attestation must reflect technical reality, not aspiration.
