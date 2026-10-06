# Model Context Protocol (MCP) Server

Airtight includes a zero-dependency, native Model Context Protocol (MCP) server operating over standard JSON-RPC 2.0 stdio.

This allows any MCP-compatible AI coding assistant (Claude Desktop, Cursor, Windsurf, Cline, Zed, LibreChat) to use Airtight's deterministic security scanner, attack surface mapping, cross-layer exposure correlation, and compliance engines directly as tools.

## Quick Start

Start the MCP server with:

```bash
npx airtight-security mcp
```

Or if installed globally:

```bash
airtight mcp
```

The server communicates via standard input/output using JSON-RPC 2.0 line-delimited messages. All logging and diagnostic warnings are sent to `stderr` to ensure protocol streams remain clean.

---

## Client Configuration

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "airtight": {
      "command": "npx",
      "args": ["-y", "airtight-security", "mcp"]
    }
  }
}
```

### Cursor Composer

Add to your project's `.cursor/mcp.json` or user-level configuration:

```json
{
  "mcpServers": {
    "airtight": {
      "command": "npx",
      "args": ["-y", "airtight-security", "mcp"]
    }
  }
}
```

### Cline (VS Code Extension)

In Cline Settings &rarr; MCP Servers &rarr; Edit in `settings.json`:

```json
{
  "mcpServers": {
    "airtight": {
      "command": "npx",
      "args": ["-y", "airtight-security", "mcp"]
    }
  }
}
```

### Windsurf / Cascade

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "airtight": {
      "command": "npx",
      "args": ["-y", "airtight-security", "mcp"]
    }
  }
}
```

### Zed

Add to `~/.config/zed/settings.json`:

```json
{
  "context_servers": {
    "airtight": {
      "command": "npx",
      "args": ["-y", "airtight-security", "mcp"]
    }
  }
}
```

---

## Exposed Tools

| Tool | Purpose | Key Arguments |
|---|---|---|
| `airtight_detect` | Scan codebase for injection sinks, secrets, and IaC flaws | `paths`, `tier`, `packs`, `format` |
| `airtight_map` | Map HTTP routes, handlers, and nearby sinks | `paths` |
| `airtight_correlate` | Correlate IaC ingress with routes to find public attack paths | `paths`, `format` |
| `airtight_rules` | List loaded security rules and CWEs | `packs`, `tier` |
| `airtight_findings` | Inspect and manage tracked findings | `action` (`list`, `sync`, `overdue`), `status` |
| `airtight_controls` | Verify SOC 2 / ISO 27001 compliance controls | `sub` (`verify`, `coverage`), `framework` |
| `airtight_sbom` | Generate CycloneDX 1.5 SBOM in JSON | `path` |

---

## Zero-Dependency Architecture

Unlike heavy SDK implementations, Airtight's MCP server is implemented entirely with Node.js built-ins (`node:readline`, `node:events`, `node:fs`, `node:path`). It requires Node 20+ and adds zero bytes of third-party dependencies to the distribution bundle.
