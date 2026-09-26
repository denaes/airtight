Threat-model a feature **before it is built**, or an existing surface that has never been modelled. The output is the set of controls the design needs, which is cheaper to act on now than after the code exists.

This is the command with no deterministic equivalent. No rule can tell you that a feature needs an idempotency key or that two tenants will share a cache.

## 1. Establish the surface

Read THREATS.md for the system-level picture. Then, for this feature specifically:

- **What does it do**, in one sentence a non-engineer would accept.
- **What data does it touch**, and which of it is sensitive per THREATS.md.
- **Who can invoke it**, including who can invoke it in ways nobody intended.
- **What does it call**, and what calls it.
- **Where are the boundaries** it crosses.

Ask the user only what the code and THREATS.md cannot answer. For a feature that does not exist yet, that is most of it, so ask well and ask once.

## 2. STRIDE per boundary

Walk each trust boundary. For each, ask all six. Most cells are empty, and the empty ones are worth the seconds they cost because they are how you notice the one that is not.

| | Question | Control family |
|---|---|---|
| **S**poofing | Can something claim to be something it is not? | Authentication, mutual TLS, signed webhooks |
| **T**ampering | Can data be altered in transit or at rest? | Integrity checks, signing, TLS, immutable logs |
| **R**epudiation | Can an actor deny having done it? | Audit logging with actor and timestamp |
| **I**nformation disclosure | Can data leak to someone who should not have it? | Authorization, encryption, error handling, log hygiene |
| **D**enial of service | Can one actor degrade it for others? | Rate limits, quotas, timeouts, bounded work |
| **E**levation of privilege | Can an actor gain rights they were not granted? | Authorization checks, least privilege, input validation |

## 3. Abuse cases

STRIDE finds the classes. Abuse cases find the ones specific to this feature, and they are usually the expensive ones because no scanner will ever have a rule for them.

For each, name the actor, what they do, and what they gain:

- What happens if this is called **twice** with the same input? Ten thousand times?
- What happens if it is called **out of order**, or after the thing it depends on was deleted?
- Can a user make **another user's** resource the target by changing an identifier?
- Can a **tenant** reach another tenant's data through a cache, a search index, a shared queue, or an aggregate count?
- Can someone **enumerate** something they should not: valid usernames, whether an email is registered, which IDs exist?
- Is there anything worth **money or reputation** here that an attacker would want even without a technical vulnerability: free compute, sending mail from your domain, a referral bonus?
- What does the **timing** of the response reveal?

## 4. Output

```
## Threat model: <feature>

**Start here.** <The control that must exist before this ships.>

### What this is
<One paragraph, and the boundaries it crosses.>

### Threats

- **[T?] <threat, as an attacker action>**
- **Category**: STRIDE letter, plus a CWE where one fits
- **Boundary**: where it crosses
- **Actor**: who can do it and what they need first
- **Impact**: what they get
- **Control**: the specific mitigation this design needs
- **Verification**: how you would confirm the control works once built

### Accepted
Threats this design deliberately does not mitigate, with the reason. A threat
model with nothing in this section has not made any decisions.

### Open questions
What has to be decided before the design is complete.
```

Write the model to `.airtight/surfaces/<slug>.md` so the later `review` of the built feature can check it against what was intended, and say in chat that you did.

## The way this command fails

**Producing the OWASP Top 10 with the feature's name pasted in.** Every web feature has an injection risk. The value here is entirely in the threats that are specific to *this* design: the shared cache, the ordering assumption, the identifier that is guessable, the counter that a competitor would pay to read. If the model would apply unchanged to a different feature, it has not been done yet.
