// The control register, and the claim it exists to support: a control whose
// verifier is a deterministic rule is proven at every commit.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyControls, frameworkCoverage, frameworksIn } from '../engine/src/controls.mjs';

const KNOWN = new Set(['secret/aws-access-key-id', 'secret/github-token', 'js/eval-dynamic']);

const control = (over = {}) => ({
  id: 'c1', name: 'Control one', statement: 's',
  verification: ['rule:secret/aws-access-key-id'],
  frameworks: { soc2: ['CC6.1'] }, status: 'enforced', ...over,
});

const finding = (rule, over = {}) => ({ rule, file: 'a.ts', line: 1, severity: 'critical', ...over });

test('a control with no matching findings is holding', () => {
  const [r] = verifyControls([control()], [], KNOWN);
  assert.equal(r.verdict, 'holding');
});

test('a control with matching findings is failing, and names where', () => {
  const [r] = verifyControls([control()], [finding('secret/aws-access-key-id', { line: 42 })], KNOWN);
  assert.equal(r.verdict, 'failing');
  assert.deepEqual(r.failures, [{ rule: 'secret/aws-access-key-id', at: 'a.ts:42', severity: 'critical' }]);
});

test('a verifier naming a rule that does not exist is broken, never holding', () => {
  // The compliance version of a rule that silently never fires, and worse:
  // the output is an assurance someone signs their name to. A typo in a rule
  // id must not read as evidence.
  const [r] = verifyControls([control({ verification: ['rule:secret/aws-acess-key-id'] })], [], KNOWN);
  assert.equal(r.verdict, 'broken');
  assert.match(r.reason, /do not exist/);
});

test('a control with no rule verifier is unverifiable, not holding', () => {
  // "Nothing checked this" and "this was checked and passed" are the two
  // claims an auditor most needs told apart.
  const [r] = verifyControls([control({ verification: ['test:tests/x.test.mjs'] })], [], KNOWN);
  assert.equal(r.verdict, 'unverifiable');
  assert.deepEqual(r.manual, ['test:tests/x.test.mjs']);

  const [r2] = verifyControls([control({ verification: [] })], [], KNOWN);
  assert.equal(r2.verdict, 'unverifiable');
});

test('a glob verifier covers a whole pack', () => {
  const c = control({ verification: ['rule:secret/*'] });
  assert.equal(verifyControls([c], [], KNOWN)[0].verdict, 'holding');
  assert.equal(verifyControls([c], [finding('secret/github-token')], KNOWN)[0].verdict, 'failing');
  assert.equal(verifyControls([c], [finding('js/eval-dynamic')], KNOWN)[0].verdict, 'holding');
});

test('a glob matching no known rule is broken', () => {
  const [r] = verifyControls([control({ verification: ['rule:kubernetes/*'] })], [], KNOWN);
  assert.equal(r.verdict, 'broken');
});

test('a framework reference needs both an enforced status and a holding verdict', () => {
  // Zero findings against a control nobody has implemented yet is not
  // evidence of anything. Verified-clean and actually-implemented are
  // separate claims and the coverage report keeps them separate.
  const controls = [
    control({ id: 'done', status: 'enforced' }),
    control({ id: 'todo', status: 'planned', frameworks: { soc2: ['CC7.1'] } }),
  ];
  const results = verifyControls(controls, [], KNOWN);
  const coverage = frameworkCoverage(controls, 'soc2', results);

  const cc61 = coverage.find((c) => c.reference === 'CC6.1');
  const cc71 = coverage.find((c) => c.reference === 'CC7.1');
  assert.equal(cc61.satisfied, true);
  assert.equal(cc71.satisfied, false, 'a planned control cannot satisfy a reference by being clean');
});

test('one register projects onto many frameworks', () => {
  // The reason the register is shaped this way: SOC 2, ISO 27001 and PCI are
  // largely the same controls under different numbering. Map once, render many.
  const controls = [control({
    frameworks: { soc2: ['CC6.1'], iso27001: ['A.8.24'], pci: ['3.6.1'] },
  })];
  assert.deepEqual(frameworksIn(controls), ['iso27001', 'pci', 'soc2']);
  for (const fw of ['soc2', 'iso27001', 'pci']) {
    const cov = frameworkCoverage(controls, fw, verifyControls(controls, [], KNOWN));
    assert.equal(cov.length, 1);
    assert.equal(cov[0].satisfied, true);
  }
});

test('one reference covered by several controls needs all of them', () => {
  const controls = [
    control({ id: 'a', status: 'enforced' }),
    control({ id: 'b', status: 'enforced', verification: ['rule:secret/github-token'] }),
  ];
  const results = verifyControls(controls, [finding('secret/github-token')], KNOWN);
  const [cc61] = frameworkCoverage(controls, 'soc2', results);
  assert.equal(cc61.controls.length, 2);
  assert.equal(cc61.satisfied, false);
});
