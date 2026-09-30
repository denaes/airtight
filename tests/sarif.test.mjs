// SARIF 2.1.0 generation and CLI formatting tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ROOT, allRules } from './helpers.mjs';
import { renderSarif } from '../engine/src/render-sarif.mjs';
import { createVault } from '../engine/src/redact.mjs';

const CLI = resolve(ROOT, 'engine/src/cli.mjs');

test('renderSarif produces valid SARIF 2.1.0 structure', () => {
  const vault = createVault();
  const rules = [
    {
      id: 'secret/stripe-live-key',
      name: 'Stripe live API key in source',
      domain: 'secrets',
      severity: 'critical',
      confidence: 'confirmed',
      priority: 'P0',
      cwe: 'CWE-798',
      owasp: 'A07:2021',
      why: 'A live API key allows unauthorized API access.',
      fix: 'Rotate the key immediately in Stripe dashboard.',
    },
    {
      id: 'injection/sql-concat',
      name: 'Raw SQL query construction',
      domain: 'injection',
      severity: 'high',
      confidence: 'firm',
      priority: 'P1',
      cwe: 'CWE-89',
      why: 'String concatenation into SQL queries allows SQL injection.',
      fix: 'Use parameterized queries.',
    },
  ];

  const findings = [
    {
      rule: 'secret/stripe-live-key',
      priority: 'P0',
      severity: 'critical',
      confidence: 'confirmed',
      message: 'Stripe live API key committed',
      file: 'src/billing.js',
      line: 42,
      column: 15,
      snippet: 'const stripe = "sk_live_12345";',
      fix: 'Rotate the key immediately in Stripe dashboard.',
      valueFingerprint: 'fp_stripe_1',
      cwe: 'CWE-798',
      owasp: 'A07:2021',
    },
  ];

  const rawJson = renderSarif({ findings, vault, meta: { filesScanned: 1, rulesApplied: 2 }, rules });
  const sarif = JSON.parse(rawJson);

  assert.equal(sarif.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);

  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'airtight');
  assert.match(run.tool.driver.semanticVersion, /^\d+\.\d+\.\d+/);
  assert.equal(run.tool.driver.rules.length, 1);

  const rule = run.tool.driver.rules[0];
  assert.equal(rule.id, 'secret/stripe-live-key');
  assert.equal(rule.name, 'secret-stripe-live-key');
  assert.equal(rule.shortDescription.text, 'Stripe live API key in source');
  assert.match(rule.help.markdown, /### Why/);
  assert.match(rule.help.markdown, /### Fix/);
  assert.deepEqual(rule.properties.tags, ['security', 'secrets', 'CWE-798', 'A07:2021']);
  assert.equal(rule.properties.precision, 'very-high');
  assert.equal(rule.defaultConfiguration.level, 'error');

  assert.equal(run.results.length, 1);
  const res = run.results[0];
  assert.equal(res.ruleId, 'secret/stripe-live-key');
  assert.equal(res.level, 'error');
  assert.match(res.message.text, /Stripe live API key committed/);
  assert.equal(res.locations[0].physicalLocation.artifactLocation.uri, 'src/billing.js');
  assert.equal(res.locations[0].physicalLocation.artifactLocation.uriBaseId, '%SRCROOT%');
  assert.equal(res.locations[0].physicalLocation.region.startLine, 42);
  assert.equal(res.locations[0].physicalLocation.region.startColumn, 15);
  assert.equal(res.partialFingerprints.primaryLocationLineHash, 'fp_stripe_1');
});

test('cli detect --format sarif outputs valid SARIF document', () => {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-sarif-test-'));
  try {
    writeFileSync(join(dir, 'test.js'), 'const token = "sk_live_' + '999999999999999999999999";\n');
    const r = spawnSync(process.execPath, [CLI, 'detect', '--no-config', '--format', 'sarif', dir], {
      encoding: 'utf8',
      env: { ...process.env, AIRTIGHT_RULES: resolve(ROOT, 'engine/build/rules.json') },
    });

    assert.equal(r.status, 2, r.stderr || r.stdout);
    const parsed = JSON.parse(r.stdout);
    assert.equal(parsed.version, '2.1.0');
    assert.equal(parsed.runs[0].results.length, 1);
    assert.equal(parsed.runs[0].results[0].ruleId, 'secret/stripe-live-key');
    assert.equal(parsed.runs[0].results[0].level, 'error');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('cli detect rejects unknown format', () => {
  const r = spawnSync(process.execPath, [CLI, 'detect', '--format', 'xml', '.'], {
    encoding: 'utf8',
    env: { ...process.env, AIRTIGHT_RULES: resolve(ROOT, 'engine/build/rules.json') },
  });
  assert.equal(r.status, 1);
  assert.match(r.stderr || r.stdout, /unknown output format/);
});
