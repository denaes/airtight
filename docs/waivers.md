# Waivers

Every scanner is wrong sometimes. What separates a tool people keep from one
they disable is whether being wrong is cheap to correct *narrowly*.

## The ladder

Three rungs, deliberately unequal in who may use them.

### `ignore-value` — one value, one rule

```bash
airtight hooks ignore-value secret/aws-access-key-id \
  --fingerprint a7717c --reason "synthetic fixture, verified by me"
```

**The agent may add this itself**, provided `--reason` names who decided and
on what evidence. A waiver records a decision; a decision with no stated basis
is indistinguishable from nobody having made one.

Redacted findings never carry the raw value, so secrets are waived by
fingerprint. That is also what lets one credential appearing in three files be
waived once.

A bare `"*"` value with no `--file` scope is **refused**: it would suppress the
rule project-wide while looking like the narrow rung.

### `ignore-file` — every rule, one path

```bash
airtight hooks ignore-file "vendor/**"
```

**Needs you.** It suppresses rules that do not exist yet, which is the part
people underestimate.

### `ignore-rule` — one rule, everywhere

```bash
airtight hooks ignore-rule container/unpinned-digest
```

**Needs you.** The bluntest tool here.

## Inline waivers

Often the right answer for a single line, and better than config because the
reason sits where the next reader will look.

```js
// airtight-disable-next-line js/eval-dynamic -- expression is a build-time constant
// airtight-disable-line secret/high-entropy-assignment -- test vector from RFC 7515
```

```python
# airtight-disable py/assert-for-authorization -- test file; asserts are the point
```

File scope, line scope, and next-line scope; any comment syntax; a
comma-separated rule list or `*`; reason after `--` or `:`.

## The rule that matters most

**Never add a waiver to get past a blocked write.**

The hook blocks on `critical` + `confirmed`. If you cannot immediately see why
a finding is wrong, the correct move is to leave it and ask — not to silence
it and continue. Using a waiver to unblock yourself falsifies the record, and
the record is the only reason waivers are tolerable at all.

Leaving a finding standing is a legitimate outcome. Leaving it standing
*silently* is not: say what you left and why.

## Reviewing them

```bash
airtight hooks status      # counts by rung
```

Every waiver carries `createdAt`. Value waivers are worth re-reading whenever
the code they cover changes; file and rule waivers are worth re-reading on a
schedule, because they are the ones that quietly grow.
