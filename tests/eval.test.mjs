// Tests for Airtight Model-Layer Eval Harness & Promptfoo Integration

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { spawnSync } from 'node:child_process';
import {
  evaluateOffline,
  validateCase,
  validatePromptfooConfig,
} from '../scripts/eval-review.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const EVAL_DIR = join(ROOT, 'eval');
const CASES_DIR = join(EVAL_DIR, 'cases');
const PROMPTFOO_PATH = join(EVAL_DIR, 'promptfoo.yaml');

test('eval/promptfoo.yaml is valid YAML and references valid files', () => {
  assert.ok(existsSync(PROMPTFOO_PATH), 'eval/promptfoo.yaml must exist');
  const content = readFileSync(PROMPTFOO_PATH, 'utf8');
  let config;
  assert.doesNotThrow(() => {
    config = parseYaml(content);
  }, 'eval/promptfoo.yaml must be valid YAML');

  assert.ok(config && typeof config === 'object');
  assert.ok(typeof config.description === 'string');
  assert.ok(Array.isArray(config.prompts) && config.prompts.length >= 2);
  assert.ok(Array.isArray(config.providers) && config.providers.length >= 1);
  assert.ok(Array.isArray(config.tests) && config.tests.length >= 10);

  const check = validatePromptfooConfig();
  assert.equal(check.valid, true, `Promptfoo config errors: ${check.errors.join(', ')}`);
});

test('eval/cases/ contains at least 5 vulnerabilities and 5 decoys conforming to schema', () => {
  assert.ok(existsSync(CASES_DIR), 'eval/cases directory must exist');
  const files = readdirSync(CASES_DIR).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  assert.ok(files.length >= 10, `Expected at least 10 case files, found ${files.length}`);

  let vulns = 0;
  let decoys = 0;

  for (const file of files) {
    const fullPath = join(CASES_DIR, file);
    const content = readFileSync(fullPath, 'utf8');
    const result = validateCase(file, content);

    assert.equal(
      result.valid,
      true,
      `Case ${file} failed validation: ${result.errors.join(', ')}`,
    );

    const doc = result.doc;
    if (doc.metadata.type === 'vulnerability') {
      vulns++;
      assert.equal(doc.metadata.expected_verdict, 'confirmed');
    } else if (doc.metadata.type === 'decoy') {
      decoys++;
      assert.equal(doc.metadata.expected_verdict, 'refuted');
    }
  }

  assert.ok(vulns >= 5, `Expected at least 5 vulnerabilities, found ${vulns}`);
  assert.ok(decoys >= 5, `Expected at least 5 decoys, found ${decoys}`);
});

test('vulnerabilities cover required rule-blind security classes', () => {
  const files = readdirSync(CASES_DIR).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
  const categories = new Set();
  const cwes = new Set();

  for (const file of files) {
    const content = readFileSync(join(CASES_DIR, file), 'utf8');
    const doc = parseYaml(content);
    if (doc.metadata?.type === 'vulnerability') {
      categories.add(doc.metadata.category);
      cwes.add(doc.metadata.cwe);
    }
  }

  // Verify coverage of the 5 required classes:
  // IDOR, TOCTOU refund race, SSRF via redirect, prompt injection, server action authz
  assert.ok(categories.has('idor'), 'Missing IDOR vulnerability case');
  assert.ok(categories.has('concurrency'), 'Missing TOCTOU race vulnerability case');
  assert.ok(categories.has('ssrf'), 'Missing SSRF redirect vulnerability case');
  assert.ok(categories.has('prompt-injection'), 'Missing prompt injection vulnerability case');
  assert.ok(categories.has('broken-authz'), 'Missing Server Action authz vulnerability case');

  assert.ok(cwes.has('CWE-639'), 'Missing CWE-639 (IDOR)');
  assert.ok(cwes.has('CWE-367'), 'Missing CWE-367 (TOCTOU)');
  assert.ok(cwes.has('CWE-918'), 'Missing CWE-918 (SSRF)');
  assert.ok(cwes.has('CWE-77'), 'Missing CWE-77 (Prompt Injection / Command Injection)');
  assert.ok(cwes.has('CWE-862'), 'Missing CWE-862 (Missing Authorization)');
});

test('scripts/eval-review.mjs executes cleanly and offline assertions pass', () => {
  const evalResult = evaluateOffline();
  assert.equal(evalResult.passed, true, 'Offline evaluation must pass');
  assert.equal(
    evalResult.summary.passedAssertions,
    evalResult.summary.totalAssertions,
    'All assertions must pass',
  );

  const proc = spawnSync(process.execPath, [join(ROOT, 'scripts/eval-review.mjs')], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.equal(proc.status, 0, `eval-review.mjs failed:\n${proc.stderr}\n${proc.stdout}`);
  assert.match(proc.stdout, /All model evaluation cases valid and assertions passed/);
});
