One-time setup. Capture the durable security truth about this project in `THREATS.md`, and the way this project actually does security in `CONTROLS.md`. Every other command reads both.

The reason this exists: ranking findings without knowing what data is sensitive ranks them by pattern frequency instead of by risk. An engine can tell you there is a SQL injection. Only THREATS.md can tell you it is in the billing service.

Avoid `SECURITY.md`; GitHub reserves that filename for vulnerability disclosure policy.

## 1. Inspect before asking

Read the repository first. Ask only about what you genuinely cannot determine. An interview that asks what language the project is in has already lost the user's attention for the questions that matter.

Determine from the code: languages and frameworks; whether there is a database and what kind; authentication mechanism; whether it is multi-tenant; deployment target; whether Terraform, Kubernetes manifests, Dockerfiles, or CI workflows exist; which authorization helper the routes call; which crypto library is imported; how secrets are loaded today.

## 2. Ask only about material gaps

Aim for four to six questions, in one round where possible. The questions worth asking are the ones no amount of reading resolves:

- **What is the worst thing an attacker could do here?** The answer ranks everything afterwards.
- **What data is sensitive, and under what obligation?** Personal data, payment data, health data, customer content, credentials for other systems.
- **Who are the actors?** Anonymous visitors, authenticated users, tenant admins, your own staff, other services. Which of them are you defending against? A tool that treats staff as trusted and one that does not are different tools.
- **What is already compensating?** A WAF, a private network, an API gateway doing authn, a review gate. These change severity honestly and you cannot see them from the code.
- **What obligations apply?** SOC 2, ISO 27001, PCI, HIPAA, GDPR, a customer contract. This determines whether the control register needs framework mappings from day one.

Ask about compliance last. It changes what gets written, not what gets asked.

## 3. Write THREATS.md

```markdown
# Threat model

## What this system is
One paragraph. What it does, who uses it, where it runs.

## Assets
What is worth taking, in priority order. Be concrete: "customer uploaded
documents in S3" not "data".

## Actors
Each with what they can already do and what they must never do.

## Trust boundaries
Where data crosses from less trusted to more trusted. Name the crossing
points: the public API, the webhook receiver, the admin panel, the queue
consumer, the CI runner.

## Authentication
Mechanism, session lifetime, MFA, how service-to-service auth works.

## Authorization
The model in one paragraph: RBAC, ABAC, per-tenant. Where it is enforced.

## Compensating controls
What exists outside this codebase that changes severity here.

## Obligations
Frameworks and contractual commitments, or "none stated".

## Out of scope
What this project deliberately does not defend against, and why. A threat
model without this section is aspirational.
```

## 4. Write CONTROLS.md and its register

`CONTROLS.md` is prose for humans. `.airtight/controls.json` is its machine form, and it is what makes a control checkable at every commit rather than asserted once a year.

For each control the project already has, record: the statement, the helper or mechanism that implements it, the rules that verify it, and its framework mappings. Derive the controls from what the code does now, not from what it should do — a register full of aspirations verifies nothing and teaches the team to ignore it.

A control with no rule verifier is honest and useful: it records the intent and reports as `unverifiable` rather than as passing.

Mark status truthfully: `enforced`, `partial`, `planned`, or `not-applicable`. A control that is `planned` and verifies clean does not satisfy anything, and the coverage report is built to say so.

## 5. Offer the hook, then stop

Offer `$airtight hooks on` in one line and recommend a first command based on what the repo contains. Do not run a scan as part of init. The user asked to be set up, not assessed.

## The way this command fails

**Writing the threat model you would write for any project.** "Attackers may attempt to gain unauthorized access" applies to everything and therefore ranks nothing. If THREATS.md could be pasted into another repository without editing, it is not a threat model, and every command downstream will be ranking by pattern frequency while appearing to rank by risk.
