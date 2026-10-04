# Model-Layer Evaluation Harness

Airtight separates static rule scanning from reasoning agents:
1. **The deterministic engine** evaluates ASTs and regex rules on edit hooks and turn completions. Its precision and recall are benchmarked against real-world repositories in [the benchmark suite](benchmark.md).
2. **The model layer** (`airtight-reviewer` and `airtight-verifier`) reasons over reachability, object-level authorization, concurrency, and application logic.

The model layer cannot be evaluated with the rule engine's corpus. It requires evaluating whether the model identifies complex vulnerabilities that rules cannot detect, and whether it refutes plausible-looking decoys that naive reviewers flag erroneously.

## Evaluation Suite Structure

- `eval/promptfoo.yaml`: Promptfoo evaluation configuration configuring LLM providers, agent prompts (`airtight-reviewer.md` and `airtight-verifier.md`), and test cases.
- `eval/cases/`: Seeded test cases with true positives and decoy non-vulnerabilities.
- `scripts/eval-review.mjs`: Standalone deterministic offline evaluator testing schema validity, prompt file resolution, and assertion logic.

### 1. True Positives (Rule-Blind Vulnerabilities)

These cases test whether the agent discovers architectural and business-logic flaws that regex rules cannot find:

| Case ID | Class | CWE | Description | Why Rules Miss It |
|---|---|---|---|---|
| `vuln-01-idor-tenant` | IDOR / Broken Object-Level Auth | CWE-639 | Missing tenant filter in document query | Valid ORM syntax (`findUnique`) with authentication middleware, but query lacks `tenantId` isolation. |
| `vuln-02-toctou-refund` | Concurrency / Race Condition | CWE-367 | TOCTOU refund race condition | Valid async state check followed by external payment API call without database locks (`SELECT FOR UPDATE`). |
| `vuln-03-ssrf-redirect` | SSRF via HTTP Redirect | CWE-918 | HTTP 302 redirect bypasses initial IP check | Target URL passes pre-request IP filter, but HTTP client follows redirect to AWS metadata (169.254.169.254). |
| `vuln-04-prompt-injection-rag` | Prompt Injection | CWE-77 | Indirect prompt injection in RAG context | Standard OpenAI SDK code; retrieved vector database chunks concatenated into prompt without delimiter boundaries. |
| `vuln-05-server-action-authz` | Broken Authorization | CWE-862 | Next.js Server Action missing session auth | Next.js `'use server'` function directly mutates database; author assumed UI button visibility provided security. |

### 2. Decoy True Negatives (Refuted Non-Vulnerabilities)

These cases test whether `airtight-verifier` successfully refutes false alarms:

| Case ID | Class | CWE | Description | Why It Is Safe |
|---|---|---|---|---|
| `decoy-01-parameterized-query` | SQL Injection Decoy | CWE-89 | Raw SQL query using `Prisma.sql` tagged template | Tagged template literal parameterizes inputs with bind variables ($1, $2); not string concatenation. |
| `decoy-02-boundary-checked-path` | Path Traversal Decoy | CWE-22 | Boundary-confined file download | `targetPath.startsWith(STORAGE_ROOT + path.sep)` strictly prevents directory traversal out of root. |
| `decoy-03-readonly-csrf` | CSRF Decoy | CWE-352 | Read-only analytics GET endpoint without CSRF | Read-only and idempotent per RFC 7231; CSRF protection applies only to state mutations. |
| `decoy-04-intentional-public-endpoint` | Broken Auth Decoy | CWE-306 | OIDC JWKS public key distribution endpoint | Key discovery endpoint is public by design per RFC 7517 to distribute public keys to resource servers. |
| `decoy-05-hmac-timing-safe` | Cryptography Decoy | CWE-208 | Webhook signature verification | `crypto.timingSafeEqual` with buffer length check prevents timing side-channel attacks. |

## Running the Evaluation

### 1. Offline Deterministic Evaluation

You can run the offline evaluation harness without API keys or network calls. It validates YAML schemas, confirms prompt references, and tests assertion logic:

```bash
# Human-readable summary table
node scripts/eval-review.mjs

# Machine-readable JSON output
node scripts/eval-review.mjs --json
```

### 2. Live Model Evaluation with Promptfoo

To execute live model evaluations across configured LLM providers (e.g. Anthropic Claude 3.5 Sonnet, OpenAI GPT-4o):

Ensure your API keys are exported:
```bash
export ANTHROPIC_API_KEY="your-api-key"
export OPENAI_API_KEY="your-api-key"
```

Run promptfoo:
```bash
# Run from repository root
npx promptfoo eval -c eval/promptfoo.yaml

# Or change to the eval directory
cd eval && npx promptfoo eval
```

To view the interactive web matrix of prompt outputs and assertion scores:
```bash
npx promptfoo view
```
