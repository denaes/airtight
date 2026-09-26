# Controls and compliance

`CONTROLS.md` is prose for humans. `.airtight/controls.json` is its machine
form: one entry per control, naming the rules that verify it and its mapping
into each framework.

```json
{
  "id": "authz.route-guard",
  "name": "Route-level authorization",
  "statement": "Every authenticated route calls requireRole() before handler logic.",
  "implementation": { "helper": "src/auth/requireRole.ts" },
  "verification": ["rule:authz/missing-route-guard", "test:tests/authz.spec.ts"],
  "frameworks": { "soc2": ["CC6.1"], "iso27001": ["A.8.3"], "pci": ["7.2.1"] },
  "status": "enforced"
}
```

```bash
airtight controls verify
airtight controls coverage --framework soc2
```

## Continuously verified controls

This is the claim the structure exists to support. A control whose
`verification` points at a deterministic rule is **proven at every commit**,
with a failing file and line when it breaks.

Compliance automation platforms check that a policy document exists and a
console setting is toggled. That is evidence about your paperwork. This is
evidence about your code.

## Three distinctions a pass/fail would lose

- **`unverifiable` is not `holding`.** A control with no rule verifier is
  reported separately. "Nothing checked this" and "this was checked and
  passed" are the two claims an auditor most needs told apart.
- **`broken` when a verifier names a rule that does not exist.** It would
  otherwise match nothing, produce no findings, and read as evidence. This is
  the compliance version of a rule that silently never fires, and worse,
  because the output is an assurance someone signs. `airtight context`
  surfaces it before anything gets cited.
- **Status and verdict are separate.** A framework reference is satisfied only
  when every control mapped to it is both declared `enforced` *and* verified
  `holding`.

Airtight's own register shows the last one working: its
`ci.workflows-hardened` control verifies clean, but only because there were no
workflow files at the time, so its status is `planned` and SOC 2 CC7.1
correctly reports a gap. A naive tool says "0 findings, control passes".

## One register, many frameworks

SOC 2, ISO 27001, PCI and HIPAA are largely the same controls under different
numbering. Map a control once; render it into every framework you owe.

## Honest limits

Airtight verifies the controls you can express as a rule over files in this
repository. It cannot see your IdP, your cloud console, your vendor
agreements, or whether anyone read the policy. Controls covering those should
be recorded with `status` set truthfully and no rule verifier, so they report
as `unverifiable` rather than as passing.
