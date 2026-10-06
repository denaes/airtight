// Model Context Protocol (MCP) Native Server for Airtight.
//
// Exposes Airtight security tools directly to AI coding environments
// (Claude Desktop, Cursor, Windsurf, Cline, Zed) over standard JSON-RPC 2.0 stdio.
//
// Zero external dependencies: pure Node.js ESM using readline and JSON-RPC 2.0.

import { createInterface } from 'node:readline';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { compileAll, immediateTier } from './rules.mjs';
import { collectTargets, scanFiles } from './scan.mjs';
import { loadConfig, buildFilter, loadCustomRules, applySeverityOverrides } from './config.mjs';
import { renderText, renderJson } from './render.mjs';
import { generateAttackSurfaceMap } from './map.mjs';
import { correlateAttackSurface } from './correlate.mjs';
import { generateCycloneDx } from './sbom.mjs';
import { detectLockfiles, parseLockfile } from './lockfile.mjs';
import { queryOsv } from './osv.mjs';
import * as store from './store.mjs';
import { loadControls, verifyControls, frameworkCoverage, frameworksIn } from './controls.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const SERVER_NAME = 'airtight';
export const SERVER_VERSION = '0.5.0';
export const PROTOCOL_VERSION = '2024-11-05';

function loadRulesBundle(env = process.env) {
  if (env.AIRTIGHT_RULES && existsSync(env.AIRTIGHT_RULES)) {
    return compileAll(JSON.parse(readFileSync(env.AIRTIGHT_RULES, 'utf8')));
  }
  const candidates = [
    join(HERE, '..', 'build', 'rules.json'),
    join(HERE, '..', '..', 'skill', 'scripts', 'rules.json'),
    join(HERE, '..', '..', 'rules.json'),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      return compileAll(JSON.parse(readFileSync(p, 'utf8')));
    }
  }
  return [];
}

export const TOOLS = [
  {
    name: 'airtight_detect',
    description: 'Scan codebase for deterministic security findings (injection sinks, secrets, misconfigurations, container/IaC flaws).',
    inputSchema: {
      type: 'object',
      properties: {
        paths: {
          type: 'array',
          items: { type: 'string' },
          description: 'Directories or files to scan (default: ["."])',
        },
        tier: {
          type: 'string',
          enum: ['all', 'immediate'],
          description: 'Rule tier: "all" for deep sweep, "immediate" for hook-level high-confidence rules',
        },
        packs: {
          type: 'array',
          items: { type: 'string' },
          description: 'Restrict to specific rule packs (e.g. ["secret", "terraform", "js", "compose"])',
        },
        format: {
          type: 'string',
          enum: ['text', 'json'],
          description: 'Output format (default: "text")',
        },
      },
    },
  },
  {
    name: 'airtight_map',
    description: 'Map application HTTP routes, controller entry points, and dangerous sinks across web frameworks.',
    inputSchema: {
      type: 'object',
      properties: {
        paths: {
          type: 'array',
          items: { type: 'string' },
          description: 'Directories to map (default: ["."])',
        },
      },
    },
  },
  {
    name: 'airtight_correlate',
    description: 'Correlate infrastructure ingress rules with application routes and sinks, discovering internet-facing attack paths.',
    inputSchema: {
      type: 'object',
      properties: {
        paths: {
          type: 'array',
          items: { type: 'string' },
          description: 'Directories to correlate (default: ["."])',
        },
        format: {
          type: 'string',
          enum: ['text', 'json'],
          description: 'Output format (default: "text")',
        },
      },
    },
  },
  {
    name: 'airtight_rules',
    description: 'List available security rules, severity, confidence levels, and CWE mappings.',
    inputSchema: {
      type: 'object',
      properties: {
        packs: {
          type: 'array',
          items: { type: 'string' },
          description: 'Filter rules by pack',
        },
        tier: {
          type: 'string',
          enum: ['all', 'immediate'],
          description: 'Filter rules by tier',
        },
      },
    },
  },
  {
    name: 'airtight_findings',
    description: 'Inspect and manage tracked security findings in .airtight/findings.ndjson.',
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['list', 'sync', 'overdue'],
          description: 'Action to perform: list findings, sync from scan, or show overdue remediations',
        },
        status: {
          type: 'string',
          enum: ['open', 'accepted', 'fixed'],
          description: 'Filter findings by status (for "list" action)',
        },
      },
      required: ['action'],
    },
  },
  {
    name: 'airtight_controls',
    description: 'Verify declared compliance controls (SOC 2, ISO 27001) against codebase findings.',
    inputSchema: {
      type: 'object',
      properties: {
        sub: {
          type: 'string',
          enum: ['verify', 'coverage'],
          description: 'Subcommand: "verify" controls or evaluate "coverage"',
        },
        framework: {
          type: 'string',
          description: 'Compliance framework name (e.g. "SOC2", "ISO27001")',
        },
      },
    },
  },
  {
    name: 'airtight_sbom',
    description: 'Generate CycloneDX 1.5 Software Bill of Materials (SBOM) in JSON from repository lockfiles.',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Target repository root (default: current directory)',
        },
      },
    },
  },
];

export async function handleToolCall(name, args = {}, { root = process.cwd(), env = process.env } = {}) {
  switch (name) {
    case 'airtight_detect': {
      const paths = args.paths?.length ? args.paths : ['.'];
      let rules = loadRulesBundle(env);
      const config = loadConfig(root);
      const isSuppressed = buildFilter(config);

      if (config.rulePaths?.length > 0) {
        try {
          rules = [...rules, ...loadCustomRules(root, config)];
        } catch {}
      }

      if (args.tier === 'immediate') rules = immediateTier(rules);
      if (args.packs?.length) rules = rules.filter((r) => args.packs.includes(r.pack));

      const files = collectTargets(root, paths.map((p) => resolve(root, p)));
      const scanned = scanFiles({ root, files, rules, config, isSuppressed });
      let findings = scanned.findings;

      if (args.tier !== 'immediate' && (!args.packs?.length || args.packs.includes('dep'))) {
        try {
          const lockfiles = detectLockfiles(root);
          const allDeps = [];
          for (const lf of lockfiles) {
            try {
              const content = readFileSync(lf, 'utf8');
              const parsed = parseLockfile(lf, content);
              if (parsed?.dependencies?.length) allDeps.push(...parsed.dependencies);
            } catch {}
          }
          if (allDeps.length > 0) {
            const advisories = queryOsv(allDeps, {
              cacheDir: join(root, '.airtight', 'cache', 'osv.json'),
              offline: false,
            });
            for (const adv of advisories) {
              if (!isSuppressed || !isSuppressed(adv)) findings.push(adv);
            }
          }
        } catch {}
      }

      if (config.severityOverrides && Object.keys(config.severityOverrides).length > 0) {
        findings = applySeverityOverrides(findings, config.severityOverrides);
      }

      const format = args.format || 'text';
      if (format === 'json') {
        return {
          content: [{ type: 'text', text: renderJson({ findings, vault: scanned.vault, meta: scanned.meta }) }],
        };
      }
      return {
        content: [{ type: 'text', text: renderText({ findings, vault: scanned.vault, meta: scanned.meta }) }],
      };
    }

    case 'airtight_map': {
      const paths = args.paths?.length ? args.paths : ['.'];
      const attackMap = generateAttackSurfaceMap(paths, { root });
      return {
        content: [{ type: 'text', text: JSON.stringify(attackMap, null, 2) }],
      };
    }

    case 'airtight_correlate': {
      const paths = args.paths?.length ? args.paths : ['.'];
      const correlation = correlateAttackSurface(paths, { root });
      if (args.format === 'json') {
        return {
          content: [{ type: 'text', text: JSON.stringify(correlation, null, 2) }],
        };
      }
      const lines = [
        'airtight: cross-layer exposure correlation',
        `  ingress rules: ${correlation.summary.totalPublicIngressRules} public, ${correlation.ingressRules.length - correlation.summary.totalPublicIngressRules} internal`,
        `  discovered service ports: ${correlation.servicePorts.length ? correlation.servicePorts.map((sp) => sp.port).join(', ') : 'none'}`,
        `  routes analyzed: ${correlation.summary.totalRoutes} (${correlation.summary.totalExposedRoutes} internet-facing, ${correlation.summary.totalInternalRoutes} internal/unmapped)`,
        `  correlated attack paths: ${correlation.summary.totalAttackPaths}`,
      ];
      if (correlation.attackPaths.length > 0) {
        lines.push('\n[!] Discovered Attack Paths:');
        for (const ap of correlation.attackPaths) {
          lines.push(`\n  [CRITICAL] ${ap.sinkType.toUpperCase()} Sink reachable from Internet`);
          lines.push(`    Exposure: ${ap.publicIngress.source} (${ap.publicIngress.cidr} -> port ${ap.exposedPort})`);
          lines.push(`    Route:    ${ap.method} ${ap.path} (${ap.routeFile}:${ap.routeLine})`);
          lines.push(`    Sink:     ${ap.sinkSnippet || ap.sinkType} (${ap.routeFile}:${ap.sinkLine})`);
        }
      } else {
        lines.push('\nNo exposed attack paths discovered.');
      }
      return {
        content: [{ type: 'text', text: lines.join('\n') }],
      };
    }

    case 'airtight_rules': {
      let rules = loadRulesBundle(env);
      if (args.tier === 'immediate') rules = immediateTier(rules);
      if (args.packs?.length) rules = rules.filter((r) => args.packs.includes(r.pack));
      const summary = rules.map((r) => ({
        id: r.id,
        name: r.name,
        pack: r.pack,
        severity: r.severity,
        confidence: r.confidence,
        tier: r.tier,
        cwe: r.cwe,
      }));
      return {
        content: [{ type: 'text', text: JSON.stringify(summary, null, 2) }],
      };
    }

    case 'airtight_findings': {
      const action = args.action || 'list';
      if (action === 'list') {
        const records = [...store.load(root).values()]
          .filter((r) => !args.status || r.status === args.status)
          .sort((a, b) => a.severity.localeCompare(b.severity) || a.id.localeCompare(b.id));
        return {
          content: [{ type: 'text', text: JSON.stringify(records, null, 2) }],
        };
      }
      if (action === 'overdue') {
        const late = store.overdue(store.load(root));
        return {
          content: [{ type: 'text', text: JSON.stringify(late, null, 2) }],
        };
      }
      if (action === 'sync') {
        let rules = loadRulesBundle(env);
        const config = loadConfig(root);
        const isSuppressed = buildFilter(config);
        const files = collectTargets(root, [root]);
        const scanned = scanFiles({ root, files, rules, config, isSuppressed });
        const { records, events } = store.reconcile(store.load(root), scanned.findings);
        const written = store.save(root, records);
        return {
          content: [{ type: 'text', text: JSON.stringify({ events, total: written }, null, 2) }],
        };
      }
      throw new Error(`unknown findings action: ${action}`);
    }

    case 'airtight_controls': {
      const sub = args.sub || 'verify';
      const { controls } = loadControls(root);
      if (controls.length === 0) {
        return {
          content: [{ type: 'text', text: 'No controls declared in .airtight/controls.json' }],
        };
      }
      const rules = loadRulesBundle(env);
      const allRuleIds = new Set(rules.map((r) => r.id));
      const config = loadConfig(root);
      const isSuppressed = buildFilter(config);
      const files = collectTargets(root, [root]);
      const scanned = scanFiles({ root, files, rules, config, isSuppressed });
      const results = verifyControls(controls, scanned.findings, allRuleIds);

      if (sub === 'coverage') {
        const framework = args.framework;
        if (!framework) {
          return {
            content: [{ type: 'text', text: `Frameworks declared: ${frameworksIn(controls).join(', ') || 'none'}` }],
          };
        }
        const coverage = frameworkCoverage(controls, framework, results);
        return {
          content: [{ type: 'text', text: JSON.stringify(coverage, null, 2) }],
        };
      }
      return {
        content: [{ type: 'text', text: JSON.stringify(results, null, 2) }],
      };
    }

    case 'airtight_sbom': {
      const target = args.path ? resolve(root, args.path) : root;
      const sbom = generateCycloneDx({ root: target });
      return {
        content: [{ type: 'text', text: sbom }],
      };
    }

    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

export function createMcpServer({ root = process.cwd(), env = process.env, input = process.stdin, output = process.stdout } = {}) {
  const rl = createInterface({
    input,
    crlfDelay: Infinity,
    terminal: false,
  });

  function send(msg) {
    output.write(JSON.stringify(msg) + '\n');
  }

  function sendError(id, code, message, data = null) {
    send({
      jsonrpc: '2.0',
      id: id ?? null,
      error: { code, message, ...(data ? { data } : {}) },
    });
  }

  function sendResult(id, result) {
    send({
      jsonrpc: '2.0',
      id,
      result,
    });
  }

  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    let req;
    try {
      req = JSON.parse(trimmed);
    } catch {
      sendError(null, -32700, 'Parse error: invalid JSON');
      return;
    }

    if (!req || typeof req !== 'object' || req.jsonrpc !== '2.0') {
      sendError(req?.id ?? null, -32600, 'Invalid Request: expected jsonrpc: "2.0"');
      return;
    }

    const { id, method, params } = req;

    // Notifications (no id)
    if (id === undefined || id === null) {
      if (method === 'notifications/initialized') {
        // Handshake confirmed
        return;
      }
      return;
    }

    try {
      switch (method) {
        case 'initialize': {
          sendResult(id, {
            protocolVersion: PROTOCOL_VERSION,
            capabilities: {
              tools: {},
            },
            serverInfo: {
              name: SERVER_NAME,
              version: SERVER_VERSION,
            },
          });
          break;
        }

        case 'ping': {
          sendResult(id, {});
          break;
        }

        case 'tools/list': {
          sendResult(id, {
            tools: TOOLS,
          });
          break;
        }

        case 'tools/call': {
          if (!params?.name) {
            sendError(id, -32602, 'Invalid params: tool name is required');
            return;
          }
          const result = await handleToolCall(params.name, params.arguments || {}, { root, env });
          sendResult(id, result);
          break;
        }

        default: {
          sendError(id, -32601, `Method not found: ${method}`);
          break;
        }
      }
    } catch (err) {
      sendError(id, -32603, `Internal error: ${err.message}`);
    }
  });

  return {
    close: () => rl.close(),
  };
}

export function runMcpServer(io = { out: (s) => process.stdout.write(s) }, env = process.env) {
  return new Promise((resolve) => {
    const server = createMcpServer({
      root: process.cwd(),
      env,
      input: process.stdin,
      output: process.stdout,
    });
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      server.close();
      resolve(0);
    };
    process.stdin.on('close', finish);
    process.stdin.on('end', finish);
  });
}
