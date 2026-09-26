Find committed credentials in the working tree and in git history, and produce a rotation plan. This command treats every match as live until proven otherwise, because the cost of being wrong in that direction is an hour of rotation and the cost of being wrong in the other is a breach.

## Run

1. `.rovodev/skills/airtight/scripts/airtight detect --json --pack secret .`
2. History matters more than the working tree. A credential deleted in a later commit is still in the clone every contributor already has:
   ```
   git log --all --full-history -p -S'<prefix>' -- <path>
   ```
   Search by the non-secret prefix the finding reports (`AKIA`, `ghp_`, `sk-ant-`), **never by the value**, which would put it in your shell history and in the transcript.
3. Check whether the file is tracked at all: a `.env` present locally and correctly gitignored is a different finding from one in the index.

## Handling the values

**Never print a credential.** The engine redacts every finding it produces; do not defeat that by reading the file and quoting the line yourself. Refer to credentials by their fingerprint, which is what the engine emits and what correlates the same value across files.

If the user pastes a credential into the conversation to ask about it, treat it as compromised — it is now in a transcript — and say so before answering anything else.

## Report

```
## Secret scan: <scope>

**Start here.** <Count of live-looking credentials, and the first one to rotate.>

### Rotation queue

Ordered by blast radius, not by severity.

- **<provider> key** — fingerprint `xxxxxx`
- **Locations**: file:line, and whether it is in git history
- **Reach**: what this credential can do if it is live
- **Rotate**: the exact steps, in order
- **Then**: what breaks when it rotates and what has to be updated

### Not credentials

Matches you judged to be examples, fixtures, or placeholders, with the reason and the narrowest waiver that suppresses each.

### Hygiene

Whether `.env` is gitignored, whether `.env.example` exists, whether a pre-commit check is installed.
```

## Rotation order

Blast radius, not severity, because the whole point of the ordering is to shrink the window while it is open:

1. Credentials that can publish or deploy: npm and registry tokens, CI deploy keys, signing keys. One of these compromises everyone downstream, not just you.
2. Cloud provider keys. They tend to reach everything else.
3. Credentials that move money or read customer data.
4. Third-party service keys.
5. Anything else.

**Rotation is not deletion.** Removing the line stops the next leak; it does nothing about the leak that already happened. Say this explicitly on every finding that reached a remote, because it is the single most common misunderstanding in this whole domain. History rewriting is a separate decision with real costs, and the user makes it, not you.

## The way this command fails

**Reporting a leak as fixed because the line is gone.** The line is not where the credential is. It is in every clone, every fork, every CI cache, and the reflog. Until the credential is rotated at the provider, nothing has been fixed.
