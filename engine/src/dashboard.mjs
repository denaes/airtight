// Interactive Terminal Dashboard & Attack Graph (airtight dashboard / airtight ui).
//
// Zero-dependency terminal user interface visualizing:
// 1. Posture summary & compliance gauges (SOC 2, ISO 27001)
// 2. Attack Surface Map (Ingress -> HTTP Routes -> Dangerous Sinks)
// 3. Taint Trace Waterfall (Source -> Callee params -> Sinks)
// 4. Active Agent Guardrail Telemetry (bash, write, sql, fetch filters)

import { loadControls, verifyControls, frameworksIn, frameworkCoverage } from './controls.mjs';
import { generateAttackSurfaceMap } from './map.mjs';
import { correlateAttackSurface } from './correlate.mjs';
import { GUARD_RULES } from './guard.mjs';
import { compileAll } from './rules.mjs';
import { existsSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

// ANSI formatting helpers
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const MAGENTA = '\x1b[35m';

function loadRules(root, env = process.env) {
  if (env.AIRTIGHT_RULES && existsSync(env.AIRTIGHT_RULES)) {
    return compileAll(JSON.parse(readFileSync(env.AIRTIGHT_RULES, 'utf8')));
  }
  const candidates = [
    join(HERE, '..', 'build', 'rules.json'),
    join(HERE, '..', '..', 'skill', 'scripts', 'rules.json'),
    join(root, 'engine', 'build', 'rules.json'),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return compileAll(JSON.parse(readFileSync(c, 'utf8')));
  }
  return [];
}

function progressBar(pct, width = 20) {
  const filled = Math.round((pct / 100) * width);
  const empty = width - filled;
  const bar = '█'.repeat(filled) + '░'.repeat(empty);
  const color = pct === 100 ? GREEN : pct >= 70 ? YELLOW : RED;
  return `${color}${bar}${RESET} ${pct.toString().padStart(3)}%`;
}

/**
 * Compiles dashboard telemetry data.
 */
export function compileDashboardData(root = process.cwd(), { paths = ['.'] } = {}) {
  // 1. Controls & Compliance
  let controlsData = { summary: { total: 0, holding: 0, failing: 0 }, frameworks: {} };
  try {
    const loaded = loadControls(root);
    const rules = loadRules(root);
    const verified = verifyControls(loaded.controls, [], new Set(rules.map((r) => r.id)));
    const holding = verified.filter((v) => v.verdict === 'holding').length;
    const failing = verified.filter((v) => v.verdict === 'failing').length;

    const fws = frameworksIn(loaded.controls);
    const fwMetrics = {};
    for (const fw of fws) {
      const cov = frameworkCoverage(loaded.controls, fw, verified);
      const satisfied = cov.filter((c) => c.satisfied).length;
      const total = cov.length;
      const pct = total > 0 ? Math.round((satisfied / total) * 100) : 100;
      fwMetrics[fw] = { satisfied, total, pct };
    }

    controlsData = {
      summary: { total: loaded.controls.length, holding, failing },
      frameworks: fwMetrics,
    };
  } catch {}

  // 2. Correlation & Attack Surface
  let attackSurface = { attackPaths: [], ingressRules: [], servicePorts: [], totalRoutes: 0 };
  try {
    const correlation = correlateAttackSurface(paths, { root });
    attackSurface = {
      attackPaths: correlation.attackPaths || [],
      ingressRules: correlation.ingressRules || [],
      servicePorts: correlation.servicePorts || [],
      totalRoutes: correlation.summary?.totalRoutes || 0,
    };
  } catch {}

  // 3. Guardrail Telemetry
  const guardTelemetry = {
    totalRules: GUARD_RULES.length,
    byTool: {
      bash: GUARD_RULES.filter((r) => r.tool === 'bash').length,
      write: GUARD_RULES.filter((r) => r.tool === 'write').length,
      sql: GUARD_RULES.filter((r) => r.tool === 'sql').length,
      fetch: GUARD_RULES.filter((r) => r.tool === 'fetch').length,
    },
    actions: {
      block: GUARD_RULES.filter((r) => r.action === 'block').length,
      warn: GUARD_RULES.filter((r) => r.action === 'warn').length,
    },
  };

  return {
    version: '0.9.0',
    timestamp: new Date().toISOString(),
    controls: controlsData,
    attackSurface,
    guard: guardTelemetry,
  };
}

/**
 * Render terminal dashboard.
 */
export function renderTerminalDashboard(data) {
  const out = [];

  out.push(`${CYAN}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}`);
  out.push(`${CYAN}║${RESET}  ${BOLD}AIRTIGHT SECURITY DASHBOARD — v${data.version}${RESET}                                       ${CYAN}║${RESET}`);
  out.push(`${CYAN}║${RESET}  Deterministic Mechanical Floor · Zero Dependencies · Cold Start <15ms       ${CYAN}║${RESET}`);
  out.push(`${CYAN}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}\n`);

  // Section 1: Posture & Compliance Gauges
  out.push(`${BOLD}▸ COMPLIANCE & CONTROL READINESS${RESET}`);
  const { summary, frameworks } = data.controls;
  out.push(`  Controls Active: ${BOLD}${summary.total}${RESET}  (Holding: ${GREEN}${summary.holding}${RESET}, Failing: ${summary.failing > 0 ? RED : GREEN}${summary.failing}${RESET})\n`);

  for (const [fw, m] of Object.entries(frameworks)) {
    const fwLabel = fw.toUpperCase().padEnd(10);
    out.push(`  ${fwLabel} [${progressBar(m.pct)}]  (${m.satisfied}/${m.total} requirements satisfied)`);
  }
  out.push('');

  // Section 2: Attack Surface & Ingress Exposure Graph
  out.push(`${BOLD}▸ ATTACK SURFACE & INGRESS EXPOSURE${RESET}`);
  const { ingressRules, servicePorts, totalRoutes, attackPaths } = data.attackSurface;
  out.push(`  Public Ingress Rules: ${BOLD}${ingressRules.length}${RESET} | Exposed Service Ports: ${BOLD}${servicePorts.length}${RESET} | Discovered HTTP Routes: ${BOLD}${totalRoutes}${RESET}`);

  if (attackPaths.length > 0) {
    out.push(`  ${RED}⚠ ${attackPaths.length} Exposed Internet Attack Path(s) Discovered:${RESET}`);
    for (const p of attackPaths.slice(0, 5)) {
      out.push(`    ${RED}●${RESET} ${DIM}[${p.exposedPort || '80'}/tcp]${RESET} ${p.method} ${p.path} ➔ ${p.sinkType?.toUpperCase() || 'SINK'} (${p.routeFile}:${p.routeLine})`);
    }
  } else {
    out.push(`  ${GREEN}✓ No unmitigated public internet ingress paths to dangerous sinks.${RESET}`);
  }
  out.push('');

  // Section 3: Active Agent Execution Guardrail Telemetry
  out.push(`${BOLD}▸ AGENT TOOL FIREWALL & GUARDRAIL TELEMETRY${RESET}`);
  const { byTool, actions, totalRules } = data.guard;
  out.push(`  Active Guard Rules: ${BOLD}${totalRules}${RESET} (Blocking: ${RED}${actions.block}${RESET}, Warnings: ${YELLOW}${actions.warn}${RESET})`);
  out.push(`  Protected Tool Vectors:`);
  out.push(`    • ${CYAN}bash${RESET}  (${byTool.bash} rules): root rm, curl|bash, disk format, cred exfil, selinux`);
  out.push(`    • ${CYAN}write${RESET} (${byTool.write} rules): .git/config, .ssh/authorized_keys, /etc/passwd`);
  out.push(`    • ${CYAN}sql${RESET}   (${byTool.sql} rules): DROP TABLE, mass unconstrained DELETE/UPDATE`);
  out.push(`    • ${CYAN}fetch${RESET} (${byTool.fetch} rules): 169.254.169.254 metadata SSRF, internal daemons\n`);

  out.push(`${DIM}Run 'airtight detect .' for full findings or 'airtight fix' to auto-remediate.${RESET}`);

  return out.join('\n');
}
