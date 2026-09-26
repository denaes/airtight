// Every rule is asserted against its own corpus. The directory layout is the
// manifest: fixtures/<flag|pass>/<pack>/<slug>/ maps to rule "<pack>/<slug>".
//
// A rule without both halves does not merge. The pass corpus is the half that
// matters most — it is what earns the right to interrupt someone's edit.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ROOT, allRules, scanOne } from './helpers.mjs';

const MIN_FLAG_CASES = 4;
const MIN_PASS_CASES = 5;

function ruleDirs(kind) {
  const base = resolve(ROOT, 'fixtures', kind);
  const out = [];
  for (const pack of readdirSync(base)) {
    const packDir = join(base, pack);
    if (!statSync(packDir).isDirectory()) continue;
    for (const slug of readdirSync(packDir)) {
      const dir = join(packDir, slug);
      if (!statSync(dir).isDirectory()) continue;
      out.push({ ruleId: `${pack}/${slug}`, dir });
    }
  }
  return out;
}

// Recursive: structured fixtures need real paths, so a workflow case lives at
// <rule-dir>/.github/workflows/case.yml and a Dockerfile case at <rule-dir>/Dockerfile.
function files(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...files(full));
    else out.push(full);
  }
  return out;
}
const countCases = (paths) =>
  paths.reduce((n, p) => n + readFileSync(p, 'utf8').trim().split('\n').length, 0);

test('every rule has both halves of a fixture corpus', () => {
  const flagged = new Set(ruleDirs('flag').map((r) => r.ruleId));
  const passed = new Set(ruleDirs('pass').map((r) => r.ruleId));
  const missing = allRules()
    .map((r) => r.id)
    .filter((id) => !flagged.has(id) || !passed.has(id));
  assert.deepEqual(missing, [], 'rules missing a flag/ or pass/ fixture directory');
});

for (const { ruleId, dir } of ruleDirs('flag')) {
  test(`${ruleId} fires on its true positives`, () => {
    const hits = [];
    for (const file of files(dir)) {
      const { findings } = scanOne(file);
      hits.push(...findings.filter((f) => f.rule === ruleId));
    }
    assert.ok(
      hits.length >= MIN_FLAG_CASES,
      `expected >=${MIN_FLAG_CASES} findings for ${ruleId}, got ${hits.length}`);
  });
}

for (const { ruleId, dir } of ruleDirs('pass')) {
  test(`${ruleId} stays silent on its false-positive corpus`, () => {
    const fps = [];
    for (const file of files(dir)) {
      const { findings } = scanOne(file);
      fps.push(...findings.filter((f) => f.rule === ruleId).map((f) => `${f.file}:${f.line} ${f.snippet}`));
    }
    assert.deepEqual(fps, [], `${ruleId} fired on lines that must not match`);
  });
}

test('pass corpora are large enough to be meaningful', () => {
  const thin = ruleDirs('pass')
    .map(({ ruleId, dir }) => ({ ruleId, lines: countCases(files(dir)) }))
    .filter(({ lines }) => lines < MIN_PASS_CASES);
  assert.deepEqual(thin, [], `pass corpora need >=${MIN_PASS_CASES} cases`);
});
