Surgically patch unambiguous mechanical security findings with unified diff preview.

Where `/airtight harden` is an interactive remediation playbook requiring human and model reasoning across architecture and access control, `/airtight fix` is deterministic: it generates and applies mechanical code patches for high-confidence rules without guessing.

## 1. What is mechanically fixable

Only unambiguous, mechanical rules with single-intent remediation shapes are candidates for automated fixing. Airtight never attempts speculative AST rewrites on complex business logic, query construction, or authorization checks.

Fixable targets:

1. **Docker Compose (`compose/*`)**:
   - `compose/privileged-true`: Strips `privileged: true` declarations.
   - `compose/host-network-mode`: Replaces `network_mode: "host"` with `network_mode: "bridge"`.
2. **CI/CD Supply Chain (`ci/*`)**:
   - `ci/unpinned-third-party-action`: Pins floating mutable action tags (`@v3`, `@main`) to immutable 40-character commit SHAs with trailing version comments.
3. **Secrets & Git Hygiene (`secret/*`)**:
   - `secret/env-file-tracked`: Appends `.env` and `.env.*` to `.gitignore`.
   - `secret/private-key-pem`: Appends `*.pem` to `.gitignore`.
4. **Cloud Infrastructure (`cfn/*`, `terraform/*`)**:
   - `cfn/ebs-unencrypted`: Sets `Encrypted: true` on CloudFormation `AWS::EC2::Volume` resources.
   - `terraform/sqs-unencrypted`: Inserts `sqs_managed_sse_enabled = true` in Terraform `aws_sqs_queue` blocks.
5. **Code Security Flags (`js/*`, `py/*`, `go/*`)**:
   - `js/tls-reject-unauthorized`: Replaces `rejectUnauthorized: false` with `true`.
   - `py/requests-verify-false`: Replaces `verify=False` with `verify=True`.
   - `py/flask-debug-enabled`: Replaces `debug=True` with `debug=False`.
   - `go/tls-insecure-skip-verify`: Replaces `InsecureSkipVerify: true` with `false`.

Findings outside these mechanical rules must be triaged through `/airtight harden` and ranked according to [severity.md](severity.md).

## 2. Previewing with dry-run

Always inspect the planned changes before writing them to disk:

```bash
airtight fix --dry-run
```

This scans the target paths and emits standard Git-compatible unified diffs for every affected file without modifying the workspace.

To filter to a single rule:

```bash
airtight fix --rule compose/privileged-true --dry-run
```

## 3. Applying the fixes

To write the changes to disk:

```bash
airtight fix [paths...]
```

When run without `--dry-run`:
- The engine applies each surgical patch to the target files.
- If `.airtight/findings.ndjson` exists, the engine re-scans the repository and reconciles the store, marking the resolved findings as `fixed` with timestamps.

## 4. Verification

Run a quick follow-up detection pass to verify that no fixable findings remain:

```bash
airtight detect [paths...]
```

If the findings are resolved and the project has a test suite, run the test suite to ensure application behavior remains intact.

## The way this command fails

**Treating automated syntax remediation as semantic security.** Automatically pinning an action SHA or adding `.env` to `.gitignore` eliminates the immediate mechanical hazard, but does not verify whether an unpinned action already ran hostile code in a past workflow run or whether committed credentials in git history were rotated. A mechanical fix closes the door; it does not investigate whether someone already walked through it.
