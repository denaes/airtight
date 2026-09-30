Review dependency and advisory risk, and be honest about what "vulnerable" means here.

## Run

1. `.agents/skills/airtight/scripts/airtight detect --json --pack dep .` for manifest/lockfile hygiene and deterministic OSV advisory lookup.
2. `.agents/skills/airtight/scripts/airtight sbom .` to generate a CycloneDX 1.5 Software Bill of Materials (SBOM) across npm, PyPI, crates.io, and Go dependencies.
3. Advisory data queries OSV with local disk caching and fails open when offline. When unavailable, hygiene is reported. Never present a hygiene-only run as a clean CVE check.
4. Read the lockfile to distinguish direct from transitive. A transitive advisory you cannot upgrade directly is a different task from a direct one you can.

## Reachability is the whole question

Most advisories in most projects are not exploitable in that project, and treating them all as equal is how a dependency report becomes a thing people close without reading.

Airtight does not have call-graph analysis yet. **Report reachability as `unknown` rather than implying it.** What you can honestly determine by reading:

- Is the package imported anywhere at all, or only present as a transitive dependency of something that does not use the affected code path?
- Does the advisory name a specific function, and does this codebase call it?
- Does the advisory require a configuration this project does not use — a specific parser mode, a server feature that is off?

Say which of these you checked and which you could not. "Reachability unknown; the advisory concerns the XML parser and this project imports the package only for JSON" is a genuinely useful sentence, and it is honest about its limits.

## Report

```
## Dependency review: <scope>

**Start here.** <The upgrade with the best risk-to-effort ratio, and why.>

### Advisories

- **<package> <version> — <advisory id>**
- **Severity**: as published, plus your own read for this project if it differs, with the reason
- **Path**: direct, or the chain that pulls it in
- **Reachable**: yes with the call site | no with the reason | unknown with what you checked
- **Fix**: the target version, and whether it is a breaking change
- **If you cannot upgrade**: the compensating control

### Supply-chain hygiene
Install scripts, wildcard versions, unpinned git refs, plaintext registries.
Each is a standing risk independent of any advisory.

### Not upgradeable
Advisories with no fixed version, with what to do instead.
```

## The way this command fails

**Counting advisories.** "47 vulnerabilities" is not a finding; it is a number that makes people stop reading. Three of those are reachable, one is in the request path, and that one is the report. Lead with it.
