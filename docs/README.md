# Airtight documentation

Security guidance for AI coding agents. A deterministic engine for the
mechanical floor, a model layer for everything that needs reasoning, and an
edit hook so the mechanical part happens while you type rather than in a
report you read later.

## Start here

- **[Getting started](getting-started.md)** — install, `init`, first audit.
- **[Commands](commands.md)** — the nine commands and what each is for.
- **[Harnesses](harnesses.md)** — the 18 supported agents, with honest
  confidence tiers.

## Reference

- **[Rule reference](rules.md)** — all 120 rules, generated from the corpus.
- **[Severity, confidence, priority](severity.md)** — the three axes and why
  they stay separate.
- **[Waivers](waivers.md)** — the suppression ladder, and who may use which
  rung.
- **[The findings store](findings-store.md)** — status lifecycle, regressions,
  deadlines.
- **[Controls and compliance](controls.md)** — continuously verified controls
  and framework mapping.
- **[CI integration](ci.md)** — exit codes, gating, and what to fail on.
- **[Benchmark](benchmark.md)** — measured against four real repositories,
  including what it misses.
- **[Architecture](architecture.md)** — how the pieces fit, and what airtight
  deliberately does not do.

## The one-paragraph version

A deterministic rule can see that a dangerous sink exists. It cannot tell you
whether attacker-controlled input reaches it, whether the authorization check
above it is correct, or whether the blast radius matters. Airtight splits along
that line: the engine owns what is mechanical, unambiguous, and cheap to check
on every edit, and the model layer owns reachability, authorization, and threat
modelling. Findings from both land in one store with one lifecycle.
