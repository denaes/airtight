import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { FIXERS, generateUnifiedDiff, applyFixes } from '../engine/src/fix.mjs';
import { compileAll } from '../engine/src/rules.mjs';
import * as store from '../engine/src/store.mjs';
import { ROOT } from './helpers.mjs';

const rules = compileAll(JSON.parse(readFileSync(join(ROOT, 'engine/build/rules.json'), 'utf8')));

test('generateUnifiedDiff generates standard git diff hunk format', () => {
  const oldText = 'line1\nline2\nline3\n';
  const newText = 'line1\nmodified2\nline3\n';
  const diff = generateUnifiedDiff('test.txt', oldText, newText);

  assert.match(diff, /^--- a\/test\.txt/);
  assert.match(diff, /^\+\+\+ b\/test\.txt/m);
  assert.match(diff, /^@@ -\d+,\d+ \+\d+,\d+ @@/m);
  assert.match(diff, /^-line2/m);
  assert.match(diff, /^\+modified2/m);
});

test('FIXERS unit transforms', () => {
  // 1. Compose privileged
  const composePriv = 'services:\n  app:\n    privileged: true\n    image: redis\n';
  const composePrivFixed = FIXERS['compose/privileged-true'].fix(composePriv);
  assert.equal(composePrivFixed, 'services:\n  app:\n    image: redis\n');

  // 2. Compose host network mode
  const composeNet = 'services:\n  web:\n    network_mode: "host"\n';
  const composeNetFixed = FIXERS['compose/host-network-mode'].fix(composeNet);
  assert.equal(composeNetFixed, 'services:\n  web:\n    network_mode: "bridge"\n');

  // 3. CI unpinned third-party action
  const ciUnpinned = 'steps:\n  - uses: some-vendor/deploy@v2\n';
  const ciFixed = FIXERS['ci/unpinned-third-party-action'].fix(ciUnpinned);
  assert.match(ciFixed, /uses: some-vendor\/deploy@[0-9a-f]{40} # v2/);

  // 4. JS TLS reject unauthorized
  const jsTls = 'const agent = new https.Agent({ rejectUnauthorized: false });';
  const jsFixed = FIXERS['js/tls-reject-unauthorized'].fix(jsTls);
  assert.equal(jsFixed, 'const agent = new https.Agent({ rejectUnauthorized: true });');

  // 5. Python requests verify false
  const pyReq = 'r = requests.get(url, verify=False)';
  const pyFixed = FIXERS['py/requests-verify-false'].fix(pyReq);
  assert.equal(pyFixed, 'r = requests.get(url, verify=True)');

  // 6. Python Flask debug
  const pyFlask = 'app.run(debug=True, port=5000)';
  const pyFlaskFixed = FIXERS['py/flask-debug-enabled'].fix(pyFlask);
  assert.equal(pyFlaskFixed, 'app.run(debug=False, port=5000)');

  // 7. Go InsecureSkipVerify
  const goTls = 'tlsConfig := &tls.Config{InsecureSkipVerify: true}';
  const goFixed = FIXERS['go/tls-insecure-skip-verify'].fix(goTls);
  assert.equal(goFixed, 'tlsConfig := &tls.Config{InsecureSkipVerify: false}');

  // 8. Terraform SQS unencrypted
  const tfSqs = 'resource "aws_sqs_queue" "q" {\n  name = "queue"\n}\n';
  const tfFixed = FIXERS['terraform/sqs-unencrypted'].fix(tfSqs);
  assert.match(tfFixed, /sqs_managed_sse_enabled = true/);

  // 9. CloudFormation EBS unencrypted
  const cfnEbs = 'Resources:\n  Vol:\n    Type: AWS::EC2::Volume\n    Properties:\n      Size: 100\n';
  const cfnFixed = FIXERS['cfn/ebs-unencrypted'].fix(cfnEbs);
  assert.match(cfnFixed, /Encrypted: true/);
});

test('applyFixes dryRun produces unified diff without modifying files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-fix-test-'));
  try {
    const filePath = join(dir, 'docker-compose.yml');
    const content = 'version: "3"\nservices:\n  db:\n    image: postgres\n    privileged: true\n';
    writeFileSync(filePath, content, 'utf8');

    const result = applyFixes([dir], { root: dir, dryRun: true, rules });
    assert.strictEqual(result.dryRun, true);
    assert.strictEqual(result.filesCount, 1);
    assert.strictEqual(result.fixedCount, 1);
    assert.match(result.diffs[0].diff, /^-    privileged: true/m);

    // File on disk must remain unchanged
    const after = readFileSync(filePath, 'utf8');
    assert.strictEqual(after, content);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('applyFixes writes changes and updates findings store when present', () => {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-fix-store-test-'));
  try {
    const pyFile = join(dir, 'client.py');
    writeFileSync(pyFile, 'import requests\nres = requests.get("https://example.com", verify=False)\n', 'utf8');

    // Create findings store and sync initial finding
    mkdirSync(join(dir, '.airtight'), { recursive: true });
    const initialRecs = new Map([
      ['f-123', {
        id: 'f-123',
        rule: 'py/requests-verify-false',
        file: 'client.py',
        line: 2,
        status: 'open',
        severity: 'critical',
      }],
    ]);
    store.save(dir, initialRecs);

    // Apply fixes
    const result = applyFixes([dir], { root: dir, dryRun: false, rules });
    assert.strictEqual(result.dryRun, false);
    assert.strictEqual(result.filesCount, 1);
    assert.strictEqual(result.fixedCount, 1);

    // File on disk must be updated
    const after = readFileSync(pyFile, 'utf8');
    assert.match(after, /verify=True/);

    // Store must mark finding as fixed
    const updatedStore = store.load(dir);
    const rec = updatedStore.get('f-123');
    assert.strictEqual(rec.status, 'fixed');
    assert.ok(rec.fixedAt);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('applyFixes updates .gitignore for secret files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-fix-gi-test-'));
  try {
    writeFileSync(join(dir, '.env'), 'SECRET_TOKEN=xyz1234567890abcdef\n', 'utf8');
    writeFileSync(join(dir, '.gitignore'), 'node_modules/\n', 'utf8');

    const result = applyFixes([dir], { root: dir, dryRun: false, rules });
    assert.ok(result.fixedFindings.some((f) => f.rule === 'secret/env-file-tracked'));

    const giContent = readFileSync(join(dir, '.gitignore'), 'utf8');
    assert.match(giContent, /\.env/);
    assert.match(giContent, /\.env\.\*/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
