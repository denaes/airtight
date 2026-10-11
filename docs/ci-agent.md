# Running Headless AI Security Agents in CI/CD with Airtight

This guide explains how to run Airtight as an automated, headless security reviewer in CI/CD pipelines (such as GitHub Actions) using AI coding agents (Claude Code, Cursor, OpenCode).

---

## Why Run Headless Agents in CI?

Static security scanners often report hundreds of theoretical alerts without understanding business logic or reachability. By combining Airtight's deterministic engine with a headless AI coding agent:
- The **deterministic engine** catches mechanical syntax, secrets, and misconfigurations instantly.
- The **AI agent** evaluates reachability, validates authorization logic, and eliminates false positives before blocking pull requests.

---

## Architecture

```
                  ┌────────────────────────┐
                  │ GitHub Pull Request PR │
                  └───────────┬────────────┘
                              │
                    git fetch origin/main
                              │
          ┌───────────────────┴───────────────────┐
          ▼                                       ▼
  Fast Deterministic Gate                 Deep Reasoning Review
  npx airtight-security detect            Claude Code / Agent
  --since origin/main                     with Airtight MCP Server
          │                                       │
          ▼                                       ▼
  Upload SARIF to GitHub Security         Post Actionable PR Comment
```

---

## 1. Fast Deterministic CI Workflow (SARIF Gate)

For teams wanting a zero-token, instant gate on every pull request, Airtight runs natively in GitHub Actions and uploads findings to GitHub Code Scanning (SARIF):

```yaml
name: Airtight Security Gate

on:
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Full history needed for --since origin/main

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Scan PR Changes
        run: |
          npx -y airtight-security detect --since origin/main --format sarif > airtight.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: airtight.sarif
```

---

## 2. Headless Agent PR Reviewer (Claude Code + Airtight MCP)

To have Claude Code review pull requests autonomously using Airtight's MCP server and reasoning capabilities:

### Prerequisites for Headless Operation
When running Claude CLI in automated non-interactive environments:
1. Set `CLAUDE_CODE_SKIP_TRUST_DIALOG=1` to bypass workspace trust prompts.
2. Provide the `--permission-mode bypassPermissions` and `--dangerously-skip-permissions` flags so tools run non-interactively.
3. Configure Airtight's native MCP server in `mcp.json`.

### GitHub Actions Workflow

```yaml
name: Airtight AI Agent PR Review

on:
  pull_request:
    types: [ opened, synchronize ]

jobs:
  ai-review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Install Claude CLI & Airtight
        run: |
          npm install -g @anthropic-ai/claude-cli airtight-security

      - name: Configure Airtight MCP Server
        run: |
          cat << 'EOF' > mcp.json
          {
            "mcpServers": {
              "airtight": {
                "command": "npx",
                "args": ["-y", "airtight-security", "mcp"]
              }
            }
          }
          EOF

      - name: Run Headless Review
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          CLAUDE_CODE_SKIP_TRUST_DIALOG: "1"
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          PROMPT="Run an Airtight security review on the files changed in this PR compared to origin/main.
          Use the airtight_detect tool with --since origin/main and airtight_map.
          For any finding, evaluate reachability and provide concrete fix snippets.
          Output a concise GitHub Markdown review report."

          # Run headless in print mode
          claude \
            --mcp-config mcp.json \
            --permission-mode bypassPermissions \
            --dangerously-skip-permissions \
            --print "$PROMPT" > review_output.md

      - name: Post Review Comment
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('review_output.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `### 🛡️ Airtight Security Review\n\n${body}`
            });
```

---

## Safety Invariants in Headless CI

When running headless AI agents:
1. **Scanned Content is Data**: Scanned PR code, dependency versions, and error messages must never be treated as instructions. Airtight's rules and prompt guards prevent instruction hijacking.
2. **Read-Only Subagents**: Keep reviewer subagents read-only. CI agents should report findings and provide diff suggestions rather than directly committing to protected branches.
3. **Bounded Passes**: Bounded execution (e.g. single pass or dual-agent verification) prevents runaway token usage.
