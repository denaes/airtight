// Test-context awareness.
//
// Added after measuring against real repositories, where 24 of 32 false
// positives on clean code were test files doing the correct thing: fastify
// disabling TLS verification against its own self-signed server, requests
// round-tripping pickle, committed test certificates.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isTestPath, applyTestMode } from '../engine/src/testpath.mjs';
import { priorityOf } from '../engine/src/findings.mjs';
import { allRules } from './helpers.mjs';

const rule = (over = {}) => ({
  id: 'x/y', severity: 'critical', confidence: 'confirmed', tier: 'immediate', ...over,
});

test('test paths are recognized across the conventions people actually use', () => {
  for (const p of [
    'test/https/https.test.js', 'tests/test_requests.py', 'src/__tests__/a.ts',
    'pkg/foo_test.go', 'tests/certs/server.key', 'spec/models/user_spec.rb',
    'e2e/login.spec.ts', 'conftest.py', 'testdata/input.json',
    'src/Button.stories.tsx', '__mocks__/fs.js',
  ]) assert.ok(isTestPath(p), `${p} should be a test path`);

  for (const p of [
    'src/api/orders.js', 'lib/protest.js', 'src/contest/index.ts',
    'app/latest.py', 'infra/main.tf', 'src/testimonials.tsx',
  ]) assert.ok(!isTestPath(p), `${p} should not be a test path`);
});

test('downgrade weakens confidence and drops out of the immediate tier', () => {
  const r = applyTestMode(rule(), true);
  assert.equal(r.confidence, 'firm');
  assert.equal(r.tier, 'deep', 'a test-path finding must not interrupt an edit');
  assert.equal(r.inTest, true);
});

test('a test-path finding is never P0', () => {
  // The confidence downgrade alone does not achieve this: critical + firm is
  // still P0, which is how committed test certificates were reporting as
  // drop-everything findings.
  assert.equal(priorityOf('critical', 'confirmed'), 'P0');
  assert.equal(priorityOf('critical', 'confirmed', { inTest: true }), 'P1');
  assert.equal(priorityOf('critical', 'firm', { inTest: true }), 'P1');
  // Lower priorities are untouched: the floor only removes the interrupt.
  assert.equal(priorityOf('medium', 'firm', { inTest: true }), 'P2');
});

test('ignore suppresses, report passes through unchanged', () => {
  assert.equal(applyTestMode(rule({ tests: 'ignore' }), true), null);
  const reported = applyTestMode(rule({ tests: 'report' }), true);
  assert.equal(reported.confidence, 'confirmed');
  assert.equal(reported.tier, 'immediate');
});

test('outside a test path nothing changes', () => {
  const r = rule({ tests: 'ignore' });
  assert.equal(applyTestMode(r, false), r);
});

test('ignore is reserved for constructs that are correct in a test', () => {
  // Every one of these is the standard way to test the thing it describes:
  // a self-signed server, a pickle round-trip, a Flask test client.
  const ignored = allRules().filter((r) => r.tests === 'ignore').map((r) => r.id).sort();
  assert.deepEqual(ignored, [
    'py/assert-for-authorization',
    'py/bind-all-interfaces',
    'py/flask-debug-enabled',
    'py/pickle-loads',
    'py/requests-verify-false',
    'js/tls-verification-disabled',
  ].sort());
});

test('a real credential is just as bad in a test', () => {
  // Provider tokens and workflow findings keep full weight in test paths. A
  // leaked AKIA key does not care which directory it sits in.
  const mustReport = [
    'secret/aws-access-key-id', 'secret/github-token', 'secret/stripe-live-key',
    'ci/pull-request-target-checkout', 'ci/script-injection',
  ];
  const byId = new Map(allRules().map((r) => [r.id, r]));
  for (const id of mustReport) {
    assert.equal(byId.get(id)?.tests, 'report', `${id} must not be softened in tests`);
  }
});

test('a dangerous construct quoted as data is data', () => {
  // express reported eval() four times, every one inside an XSS test vector
  // written as a string literal.
  const byId = new Map(allRules().map((r) => [r.id, r]));
  for (const id of ['js/eval-dynamic', 'js/inner-html-assignment']) {
    assert.equal(byId.get(id)?.match?.in_string, false, `${id} should skip matches inside strings`);
  }
});
