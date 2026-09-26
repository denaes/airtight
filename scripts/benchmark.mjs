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
//   node scripts/benchmark.mjs          clone if needed, scan, report
//   node scripts/benchmark.mjs --keep   reuse existing clones

import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WORK = join(tmpdir(), 'airtight-benchmark');

const REPOS = [
  { repo: 'OWASP/NodeGoat', kind: 'vulnerable', note: 'OWASP teaching app, intentionally vulnerable' },
  { repo: 'fastify/fastify', kind: 'clean', note: 'actively maintained HTTP framework' },
  { repo: 'expressjs/express', kind: 'clean', note: 'actively maintained HTTP framework' },
  { repo: 'psf/requests', kind: 'clean', note: 'actively maintained HTTP client' },
];

function clone(repo) {
  const dir = join(WORK, repo.split('/')[1]);
  if (existsSync(dir)) return dir;
  mkdirSync(WORK, { recursive: true });
  const r = spawnSync('git', ['clone', '-q', '--depth', '1', `https://github.com/${repo}.git`, dir],
    { encoding: 'utf8' });
  if (r.status !== 0) { console.error(`benchmark: could not clone ${repo}`); return null; }
  return dir;
}

function scan(dir) {
  // --no-config, so nothing the repository itself declares can hide a finding.
  const r = spawnSync(process.execPath,
    [join(ROOT, 'engine/src/cli.mjs'), 'detect', '--no-config', '--json', '.'],
    { cwd: dir, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, AIRTIGHT_RULES: join(ROOT, 'engine/build/rules.json') } });
  try { return JSON.parse(r.stdout); } catch { return null; }
}

function main() {
  const rows = [];
  for (const { repo, kind, note } of REPOS) {
    const dir = clone(repo);
    if (!dir) continue;
    const result = scan(dir);
    if (!result) { console.error(`benchmark: scan failed for ${repo}`); continue; }

    const pri = {};
    const rules = new Map();
    for (const f of result.findings) {
      pri[f.priority] = (pri[f.priority] ?? 0) + 1;
      rules.set(f.rule, (rules.get(f.rule) ?? 0) + 1);
    }
    rows.push({ repo, kind, note, files: result.filesScanned, total: result.findings.length, pri, rules });
  }

  console.log('# airtight benchmark\n');
  console.log('| Repository | Kind | Files | Findings | P0 | P1 | P2 | P3 |');
  console.log('|---|---|---:|---:|---:|---:|---:|---:|');
  for (const r of rows) {
    console.log(`| ${r.repo} | ${r.kind} | ${r.files} | ${r.total} | `
      + `${r.pri.P0 ?? 0} | ${r.pri.P1 ?? 0} | ${r.pri.P2 ?? 0} | ${r.pri.P3 ?? 0} |`);
  }

  const clean = rows.filter((r) => r.kind === 'clean');
  const cleanP0 = clean.reduce((n, r) => n + (r.pri.P0 ?? 0), 0);
  const cleanTotal = clean.reduce((n, r) => n + r.total, 0);
  console.log(`\nClean repositories: ${cleanTotal} findings, ${cleanP0} at P0.`);

  for (const r of rows) {
    if (!r.rules.size) continue;
    console.log(`\n## ${r.repo}\n`);
    for (const [rule, n] of [...r.rules].sort(([a], [b]) => a.localeCompare(b))) {
      console.log(`${String(n).padStart(3)}  ${rule}`);
    }
  }

  // A P0 on a well-maintained repository is the number that decides whether
  // anyone keeps this installed.
  return cleanP0 === 0 ? 0 : 2;
}

process.exit(main());
