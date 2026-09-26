# The findings store

A scan answers *what is wrong right now*. The store answers the questions that
actually run a security programme.

```bash
airtight findings sync .      # scan and reconcile
airtight findings list
airtight findings overdue
airtight findings accept <id> --reason "..." --approver "..." --expires 2026-06-01
```

State lives in `.airtight/findings.ndjson`, sorted newline-delimited JSON. It
is **tracked in git on purpose**: a gitignored store loses the lifecycle on
every clone, so a fixed-then-reintroduced vulnerability would read as new
rather than as a regression. Sorting means two branches that each add a
finding edit different lines, and git merges them without a conflict.

## Identity

A finding is `rule + file + fingerprint of the matched value`, not a line
number. Two consequences:

- Reformatting does not resurrect every finding as new.
- One credential in three files is **three findings** — removing it is three
  edits — that share a fingerprint, so rotating it is one task.

## Lifecycle

```
          ┌──────────────► accepted ──(waiver expires)──┐
          │                                             ▼
   new ──► open ──(gone)──► fixed ──(detected again)──► regressed
            ▲                                             │
            └─────────────────────────────────────────────┘
```

- **`fixed` rather than deleted.** Deleting would lose the history that makes
  the next state detectable.
- **`regressed` is not `open`.** Finding something the first time and finding
  it again after a fix are different events. The second usually means the fix
  did not reach where it needed to, which is a process signal worth more than
  another scan — so `airtight context` leads with regressions regardless of
  severity.
- **`accepted` requires a named approver and a reason.** With an `--expires`
  the finding returns on its own, which is the entire point of time-boxing an
  acceptance. Without one, nothing will ever bring it back for review, and the
  CLI says so.

## Deadlines

`due` is the first sighting plus the severity SLA — 7, 30, 90, or 180 days.
`airtight findings overdue` is a real queue rather than a re-scan, and it
exits 2 when anything is late, so CI can gate on it.

## What it is not

It is not a vulnerability database, a ticketing system, or a source of truth
about anything outside this repository. It records what airtight found here
and what people decided about it.
