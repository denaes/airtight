# Security floor

Load this immediately before any edit that touches authentication, authorization, data access, cryptography, deserialization, subprocess execution, template rendering, file paths, or network requests. Not for review-only work.

This is the floor, not the ceiling. Clearing it does not make code secure; failing it makes code insecure regardless of what else is right.

## Verify

Run these against what you actually wrote, once, in one pass.

- **Every new query is parameterized.** Placeholders and a values array. Not escaping, not a quote helper, not "the input is validated upstream".
- **Every new endpoint has an authorization check, and it uses this project's helper.** Find how the neighbouring routes do it and do that. A hand-rolled check next to forty uses of `requireRole()` is a bug even when the logic is right, because the next person changing `requireRole()` will not know to change yours.
- **Every authorization check tests the object, not just the verb.** `canEdit(user)` without `canEdit(user, document)` is the shape of every IDOR ever written.
- **Every new secret is read from the environment or a secret manager.** No literal, no default value that works, no "temporary".
- **Every subprocess takes an argument array.** No shell, no interpolation.
- **Every deserialization of untrusted input uses a safe loader.** `yaml.safe_load`, `JSON.parse`, never `pickle`.
- **Every new path built from input is reduced to a basename, resolved against a fixed root, and asserted to still be under it.** All three.
- **Every new random value used for security comes from a CSPRNG.** `crypto.randomBytes`, `secrets.token_urlsafe`. Never `Math.random` or `random`.
- **Every new error path says less to the user than it logs.** Stack traces, SQL fragments, and internal hostnames go to the log, not the response.
- **Every new log line is checked for what it carries.** Tokens, passwords, full card numbers, and session identifiers do not belong in logs, and a log is a much wider audience than the database it came from.
- **Multi-tenant queries are scoped by tenant in the query itself,** not filtered after fetching. A missing `WHERE tenant_id = ?` is a cross-tenant data breach with no exception thrown.

## Refuse

These are not defaults you can argue past with a brief. They are the line.

- **Do not disable certificate verification.** Not with a comment, not behind an environment flag that defaults off, not "just for the internal call". Install the CA.
- **Do not weaken a control to make a test pass.** Fix the test or fix the code. A test that only passes with `verify=False` is telling you the test is wrong.
- **Do not add a waiver to get past the hook.** A waiver records a decision someone made. Using one to silence a finding you did not understand is falsifying that record.
- **Do not write your own cryptographic primitive, mode, or padding.** Use the library's AEAD. This includes "just XOR it" and "just base64 it", and base64 is not encryption at all.
- **Do not use `assert` for an authorization check in Python.** Optimized builds remove it and every request becomes authorized.
- **Do not log a credential to prove it loaded.** Check its length.
- **Do not widen a permission to make something work without saying so.** If a change needs `*` on an IAM action, that is a finding to raise, not a detail to bury in a diff.
- **Do not claim a finding is fixed without re-running the check that found it.** "Should be fixed now" is not a verification.

## After editing

State plainly what you changed, what you verified, and what you did not. If you fixed three of five findings, say which two remain and why. A remediation report that implies completeness it does not have is worse than no report, because it ends the investigation.
