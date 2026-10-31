# Dashboard: Interactive Posture & Attack Surface TUI

The dashboard renders an interactive terminal dashboard visualizing posture metrics, SOC 2 / ISO 27001 control readiness gauges, attack surface ingress exposure, and agent execution guardrail telemetry in a single view.

## When to run

Run when the user wants an overview of project security health, wants to see compliance posture before an audit, or needs to inspect internet-facing route exposure and tool firewall telemetry together.

```bash
airtight dashboard [paths...]
airtight ui [paths...]
```

Options:
- `--json`: emit machine-readable telemetry JSON containing control status, attack surface routes, correlated paths, and guardrail metrics.

## What the dashboard displays

1. **Compliance & Control Readiness**:
   - Visual progress bars for overall control posture and active frameworks (SOC 2, ISO 27001).
   - Real-time tally of holding controls, failing controls, and unmapped controls.

2. **Attack Surface & Ingress Exposure**:
   - Total HTTP routes mapped across supported frameworks (Express, FastAPI, Django, Flask, Rails, Spring Boot, Gin).
   - Exposure breakdown: public internet ingress vs internal/unmapped routes.
   - Discovered attack paths connecting public entry points to dangerous sinks (SQL, command execution, path traversal).

3. **Agent Tool Firewall & Guardrail Telemetry**:
   - Active filter rule counts across execution tools (`bash`, `write`, `sql`, `fetch`).
   - Summary of protection coverage for destructive commands, credential exfiltration, and host file modifications.

## The way this command fails

The way this command fails is by treating a high compliance readiness percentage as proof that no critical vulnerabilities or exploitable attack paths exist in the application. Compliance gauges reflect declared control registers and audit evidence, whereas attack surface mapping reflects real network reachability to dangerous code sinks. The agent must never cite high compliance percentages to dismiss or downrank correlated internet-facing attack paths.
