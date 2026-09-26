// The invariants that are policy rather than pattern matching.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { priorityOf, SLA_DAYS } from '../engine/src/findings.mjs';
import { matchesGlob } from '../engine/src/glob.mjs';
import { buildWaiverIndex } from '../engine/src/waivers.mjs';
import { buildFilter } from '../engine/src/config.mjs';
import { compileRule, RuleError } from '../engine/src/rules.mjs';

test('a tentative finding can never present as P0', () => {
  // The whole point of the confidence axis. Reachability has to be proven by
  // the model layer or by `airtight exploit` before we tell anyone to drop
  // everything, or the tool trains people to ignore P0.
  for (const severity of ['critical', 'high', 'medium', 'low']) {
    assert.notEqual(priorityOf(severity, 'tentative'), 'P0',
      `${severity}/tentative must not be P0`);
  }
  assert.equal(priorityOf('critical', 'confirmed'), 'P0');
  assert.equal(priorityOf('critical', 'tentative'), 'P1');
  assert.equal(priorityOf('low', 'confirmed'), 'P3');
});

test('every severity has an SLA', () => {
  for (const s of ['critical', 'high', 'medium', 'low']) {
    assert.equal(typeof SLA_DAYS[s], 'number');
  }
  assert.ok(SLA_DAYS.critical < SLA_DAYS.high);
});

test('globs anchor the way people expect', () => {
  assert.ok(matchesGlob('infra/prod/main.tf', '**/*.tf'));
  assert.ok(matchesGlob('main.tf', '**/*.tf'), '**/ must match zero directories');
  assert.ok(matchesGlob('.github/workflows/ci.yml', '.github/workflows/*.y*ml'));
  assert.ok(matchesGlob('src/deep/app.ts', '*.ts'), 'a bare pattern matches at any depth');
  assert.ok(!matchesGlob('src/app.ts', 'src/*.tsx'));
  assert.ok(matchesGlob('a/.env.production', '**/.env.*'));
});

test('inline waivers scope correctly', () => {
  const lines = [
    'const a = 1;                       // airtight-disable-next-line secret/aws-access-key-id',
    'const key = "AKIA...";',
    'const b = 2; // airtight-disable-line secret/github-token',
    'const c = 3;',
  ];
  const waived = buildWaiverIndex(lines);
  assert.ok(waived('secret/aws-access-key-id', 2), 'next-line applies to the following line');
  assert.ok(!waived('secret/aws-access-key-id', 4));
  assert.ok(waived('secret/github-token', 3), 'line scope applies to its own line');
  assert.ok(!waived('secret/github-token', 2));
});

test('a file-wide waiver with a reason still parses the rule list', () => {
  const waived = buildWaiverIndex([
    '# airtight-disable secret/jwt-with-claims -- fixture tokens, expired 2024',
  ]);
  assert.ok(waived('secret/jwt-with-claims', 99));
  assert.ok(!waived('secret/aws-access-key-id', 99));
});

test('the suppression ladder refuses a wildcard that is ignoreRule in disguise', () => {
  const finding = {
    rule: 'secret/openai-key', file: 'src/a.ts', snippet: 'x', redacted: true,
    valueFingerprint: 'abc123',
  };

  // "*" with no file scope would silently disable the rule project-wide while
  // looking like a narrow waiver. It has to be declared as ignoreRules instead.
  assert.equal(
    buildFilter({ detector: { ignoreValues: [{ rule: 'secret/openai-key', value: '*' }] } })(finding),
    false);

  assert.equal(
    buildFilter({ detector: {
      ignoreValues: [{ rule: 'secret/openai-key', value: '*', files: ['src/a.ts'] }],
    } })(finding),
    true);

  // Redacted findings hold no raw value, so value waivers match by fingerprint.
  assert.equal(
    buildFilter({ detector: {
      ignoreValues: [{ rule: 'secret/openai-key', value: 'x', fingerprint: 'abc123' }],
    } })(finding),
    true);
});

test('ignoreFiles and ignoreRules work at their stated breadth', () => {
  const finding = { rule: 'secret/openai-key', file: 'legacy/old.ts', snippet: 'x' };
  assert.equal(buildFilter({ detector: { ignoreRules: ['secret/openai-key'] } })(finding), true);
  assert.equal(buildFilter({ detector: { ignoreFiles: ['legacy/**'] } })(finding), true);
  assert.equal(buildFilter({ detector: { ignoreFiles: ['other/**'] } })(finding), false);
});

test('rule validation rejects what would silently never match', () => {
  const valid = {
    id: 'secret/x', name: 'X', domain: 'secrets', severity: 'high', confidence: 'firm',
    message: 'm', why: 'w', fix: 'f', files: ['**/*'], match: { regex: 'a' },
  };
  assert.doesNotThrow(() => compileRule(valid));

  const rejects = {
    'bad id shape': { ...valid, id: 'NotAPack' },
    'unknown severity': { ...valid, severity: 'catastrophic' },
    'unknown confidence': { ...valid, confidence: 'pretty-sure' },
    'missing fix': { ...valid, fix: undefined },
    'empty files': { ...valid, files: [] },
    'text rule with no regex': { ...valid, match: {} },
    'broken regex': { ...valid, match: { regex: '([unclosed' } },
    'unknown snippet mode': { ...valid, snippet: 'paragraph' },
  };
  for (const [why, rule] of Object.entries(rejects)) {
    assert.throws(() => compileRule(rule), RuleError, `should reject: ${why}`);
  }
});

test('inline regex flags are translated rather than rejected', () => {
  const rule = compileRule({
    id: 'secret/y', name: 'Y', domain: 'secrets', severity: 'low', confidence: 'firm',
    message: 'm', why: 'w', fix: 'f', files: ['**/*'], match: { regex: '(?i)SecretKey' },
  });
  assert.ok(rule.re.flags.includes('i'));
  assert.ok(rule.re.test('secretkey'));
});
