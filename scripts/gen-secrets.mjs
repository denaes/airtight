#!/usr/bin/env node
// Materialize the credential-shaped fixture corpora and demo files.
//
// Nothing credential-shaped is committed. See fixtures/secrets.spec.mjs for
// why, and for the reviewable form of what this produces.
//
// Deterministic: a fixed seed means the fixture suite and the demo golden do
// not churn between runs.

import { mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { corpora, demoTemplates } from '../fixtures/secrets.spec.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEMO = join(ROOT, 'demo', 'vulnerable-shop');

function generator(seed) {
  let s = seed;
  const rnd = () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const UP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const LO = 'abcdefghijklmnopqrstuvwxyz';
  const NUM = '0123456789';
  const pick = (a, n) => Array.from({ length: n }, () => a[Math.floor(rnd() * a.length)]).join('');
  const ALNUM = UP + LO + NUM;
  const URLSAFE = `${ALNUM}_-`;

  return {
    gitlab: () => `glpat-${pick(URLSAFE, 20)}`,
    sendgrid: () => `SG.${pick(URLSAFE, 22)}.${pick(URLSAFE, 43)}`,
    stripe: (p) => `${p}_live_${pick(ALNUM, 24)}`,
    slack: (k) => `xox${k}-${pick(NUM, 12)}-${pick(ALNUM, 12)}`,
    aws: (p = 'AKIA') => p + pick(UP + NUM, 16),
    b64: (n) => pick(`${ALNUM}/+`, n),
    gh: (p) => `${p}_${pick(ALNUM, 36)}`,
    ghPat: () => `github_pat_${pick(`${ALNUM}_`, 82)}`,
    google: () => `AIza${pick(URLSAFE, 35)}`,
    npm: () => `npm_${pick(ALNUM, 36)}`,
    anthropic: () => `sk-ant-${pick(URLSAFE, 40)}`,
    openai: (k) => `sk-${k}-${pick(URLSAFE, 32)}`,
    jwt: () => `eyJ${pick(URLSAFE, 20)}.eyJ${pick(URLSAFE, 40)}.${pick(URLSAFE, 30)}`,
  };
}

function write(path, body) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body.endsWith('\n') ? body : `${body}\n`);
}

function main() {
  const g = generator(20260926);
  let files = 0;

  for (const [ruleId, spec] of Object.entries(corpora)) {
    for (const kind of ['flag', 'pass']) {
      const lines = spec[kind](g);
      write(join(ROOT, 'fixtures', kind, ruleId, spec.file ?? 'cases.txt'), `${lines.join('\n')}\n`);
      files += 1;
    }
  }

  // Demo files are templated rather than generated wholesale, so the
  // committed template stays readable and shows exactly what lands.
  //
  // Templates live outside the app directory on purpose: Dockerfile.tmpl
  // matches `**/Dockerfile*`, so keeping it beside the generated Dockerfile
  // made every container rule fire twice and doubled the demo's counts.
  for (const rel of demoTemplates) {
    const tmpl = join(ROOT, 'demo', 'templates', `${rel.split('/').pop()}.tmpl`);
    if (!existsSync(tmpl)) continue;
    const body = readFileSync(tmpl, 'utf8')
      .replace(/\{\{AWS_KEY\}\}/g, g.aws())
      .replace(/\{\{STRIPE_KEY\}\}/g, g.stripe('sk'));
    write(join(DEMO, rel), body);
    files += 1;
  }

  console.log(`gen-secrets: ${files} generated file(s) (not committed; see fixtures/secrets.spec.mjs)`);
  return 0;
}

process.exit(main());
