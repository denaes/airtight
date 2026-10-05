#!/usr/bin/env node
// Run airtight against real repositories and report the numbers.
//
// Two kinds of repository, because they answer different questions:
//   vulnerable  does it find what is there?
//   clean       does it stay quiet when there is nothing to find?
//
// The second matters more. Recall can be improved by adding rules; precision
// can only be improved by removing them, and a tool that cries wolf on
// well-maintained code gets uninstalled before its recall is ever tested.
//
// Two suites:
//   app         web applications, libraries, and HTTP services
//   infra       Terraform, Kubernetes, and container configurations
//
// Usage:
//   node scripts/benchmark.mjs                 # clone if needed, scan all suites, report
//   node scripts/benchmark.mjs --suite=infra   # run infrastructure suite only
//   node scripts/benchmark.mjs --suite=app     # run application suite only
//   node scripts/benchmark.mjs --json          # output benchmark report as JSON
//   node scripts/benchmark.mjs --clean         # remove cached clones before running

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, openSync, closeSync, readFileSync, unlinkSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WORK = join(tmpdir(), 'airtight-benchmark');

const REPOS = [
  // Application code benchmarks
  { repo: 'OWASP/NodeGoat', kind: 'vulnerable', suite: 'app', note: 'OWASP teaching app, intentionally vulnerable' },
  { repo: 'juice-shop/juice-shop', kind: 'vulnerable', suite: 'app', note: 'OWASP flagship modern vulnerable web app' },
  { repo: 'fastify/fastify', kind: 'clean', suite: 'app', note: 'actively maintained HTTP framework' },
  { repo: 'expressjs/express', kind: 'clean', suite: 'app', note: 'actively maintained HTTP framework' },
  { repo: 'gin-gonic/gin', kind: 'clean', suite: 'app', note: 'high-performance Go web framework' },
  { repo: 'pallets/flask', kind: 'clean', suite: 'app', note: 'actively maintained Python web framework' },
  { repo: 'psf/requests', kind: 'clean', suite: 'app', note: 'actively maintained HTTP client' },

  // Infrastructure & container benchmarks
  { repo: 'bridgecrewio/terragoat', kind: 'vulnerable', suite: 'infra', note: 'Bridgecrew vulnerable Terraform benchmark' },
  { repo: 'bridgecrewio/k8sgoat', kind: 'vulnerable', suite: 'infra', note: 'Kubernetes intentionally vulnerable benchmark scenarios' },
  { repo: 'terraform-aws-modules/terraform-aws-vpc', kind: 'clean', suite: 'infra', note: 'Standard AWS VPC Terraform module' },
];

const REPO_URL_OVERRIDES = {
  'bridgecrewio/k8sgoat': [
    'https://github.com/bridgecrewio/k8sgoat.git',
    'https://github.com/bridgecrewio/kubernetes-goattest.git',
    'https://github.com/madhuakula/kubernetes-goat.git',
  ],
};

function clone(repo, forceClean = false) {
  const dirName = repo.split('/')[1];
  const dir = join(WORK, dirName);
  if (forceClean && existsSync(dir)) {
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  }
  if (existsSync(dir)) return dir;
  mkdirSync(WORK, { recursive: true });

  const urls = REPO_URL_OVERRIDES[repo] ?? [`https://github.com/${repo}.git`];
  for (const url of urls) {
    const r = spawnSync('git', ['clone', '-q', '--depth', '1', url, dir], { encoding: 'utf8' });
    if (r.status === 0) return dir;
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  }
  console.error(`benchmark: could not clone ${repo}`);
  return null;
}

function scan(dir) {
  // Use a temporary file for stdout to avoid stdio pipe buffer truncations on large reports
  const tmpOut = join(WORK, `scan-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const fd = openSync(tmpOut, 'w');
  try {
    spawnSync(process.execPath,
      [join(ROOT, 'engine/src/cli.mjs'), 'detect', '--no-config', '--json', '.'],
      { cwd: dir, stdio: ['ignore', fd, 'pipe'], maxBuffer: 64 * 1024 * 1024,
        env: { ...process.env, AIRTIGHT_RULES: join(ROOT, 'engine/build/rules.json') } });
    closeSync(fd);
    const content = readFileSync(tmpOut, 'utf8');
    return JSON.parse(content);
  } catch {
    return null;
  } finally {
    try { unlinkSync(tmpOut); } catch {}
  }
}

function main() {
  const args = process.argv.slice(2);
  const suiteArg = args.find((a) => a.startsWith('--suite='))?.split('=')[1];
  const appOnly = args.includes('--app') || suiteArg === 'app';
  const infraOnly = args.includes('--infra') || suiteArg === 'infra';
  const forceClean = args.includes('--clean');
  const asJson = args.includes('--json');

  const selectedRepos = REPOS.filter((r) => {
    if (appOnly) return r.suite === 'app';
    if (infraOnly) return r.suite === 'infra';
    return true;
  });

  const rows = [];
  for (const { repo, kind, suite, note } of selectedRepos) {
    const dir = clone(repo, forceClean);
    if (!dir) continue;
    const result = scan(dir);
    if (!result) { console.error(`benchmark: scan failed for ${repo}`); continue; }

    const pri = {};
    const rules = new Map();
    for (const f of result.findings) {
      pri[f.priority] = (pri[f.priority] ?? 0) + 1;
      rules.set(f.rule, (rules.get(f.rule) ?? 0) + 1);
    }
    rows.push({ repo, kind, suite, note, files: result.filesScanned, total: result.findings.length, pri, rules });
  }

  if (asJson) {
    const jsonOutput = rows.map((r) => ({
      repo: r.repo,
      kind: r.kind,
      suite: r.suite,
      note: r.note,
      files: r.files,
      findings: r.total,
      priorities: r.pri,
      rules: Object.fromEntries(r.rules),
    }));
    console.log(JSON.stringify(jsonOutput, null, 2));
    const cleanP0 = rows.filter((r) => r.kind === 'clean').reduce((n, r) => n + (r.pri.P0 ?? 0), 0);
    return cleanP0 === 0 ? 0 : 2;
  }

  console.log('# airtight benchmark\n');
  console.log('| Repository | Suite | Kind | Files | Findings | P0 | P1 | P2 | P3 |');
  console.log('|---|---|---|---:|---:|---:|---:|---:|---:|');
  for (const r of rows) {
    console.log(`| ${r.repo} | ${r.suite} | ${r.kind} | ${r.files} | ${r.total} | `
      + `${r.pri.P0 ?? 0} | ${r.pri.P1 ?? 0} | ${r.pri.P2 ?? 0} | ${r.pri.P3 ?? 0} |`);
  }

  const clean = rows.filter((r) => r.kind === 'clean');
  const cleanP0 = clean.reduce((n, r) => n + (r.pri.P0 ?? 0), 0);
  const cleanTotal = clean.reduce((n, r) => n + r.total, 0);
  console.log(`\nClean repositories: ${cleanTotal} findings, ${cleanP0} at P0.`);

  const appRows = rows.filter((r) => r.suite === 'app');
  const infraRows = rows.filter((r) => r.suite === 'infra');
  if (appRows.length && infraRows.length) {
    const appVuln = appRows.filter((r) => r.kind === 'vulnerable').reduce((n, r) => n + r.total, 0);
    const infraVuln = infraRows.filter((r) => r.kind === 'vulnerable').reduce((n, r) => n + r.total, 0);
    console.log(`Vulnerable findings: ${appVuln} in application repos, ${infraVuln} in infrastructure repos.`);
  }

  for (const r of rows) {
    if (!r.rules.size) continue;
    console.log(`\n## ${r.repo} (${r.suite} / ${r.kind})\n`);
    for (const [rule, n] of [...r.rules].sort(([a], [b]) => a.localeCompare(b))) {
      console.log(`${String(n).padStart(3)}  ${rule}`);
    }
  }

  // A P0 on a well-maintained repository is the number that decides whether
  // anyone keeps this installed.
  return cleanP0 === 0 ? 0 : 2;
}

process.exit(main());
