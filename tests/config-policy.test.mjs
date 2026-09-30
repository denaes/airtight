// Unit tests for org policy layering, configuration extends, severity overrides,
// custom rules loading, waiver policy enforcement, and .pre-commit-hooks.yaml.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';
import * as config from '../engine/src/config.mjs';
import * as store from '../engine/src/store.mjs';
import { RuleError } from '../engine/src/rules.mjs';
import { ROOT } from './helpers.mjs';

function createTempDir(prefix = 'airtight-test-') {
  return mkdtempSync(join(tmpdir(), prefix));
}

const mockFinding = (over = {}) => ({
  id: 'aaaa1111',
  rule: 'ci/unpinned-third-party-action',
  title: 'Unpinned action',
  domain: 'ci',
  severity: 'medium',
  confidence: 'confirmed',
  disposition: 'fix',
  cwe: 'CWE-829',
  owasp: 'A08:2021',
  file: '.github/workflows/ci.yml',
  line: 12,
  provenance: 'deterministic-rule',
  ...over,
});

test('.pre-commit-hooks.yaml is valid YAML and matches the pre-commit hook specification', () => {
  const hookFile = join(ROOT, '.pre-commit-hooks.yaml');
  assert.ok(existsSync(hookFile), '.pre-commit-hooks.yaml must exist at repo root');

  const content = readFileSync(hookFile, 'utf8');
  const parsed = parseYaml(content);

  assert.ok(Array.isArray(parsed), '.pre-commit-hooks.yaml must be an array of hooks');
  assert.equal(parsed.length, 1);

  const hook = parsed[0];
  assert.equal(hook.id, 'airtight');
  assert.equal(hook.name, 'airtight');
  assert.equal(hook.description, 'Fast, deterministic security scanner and AI agent guardrails');
  assert.equal(hook.entry, 'airtight detect');
  assert.equal(hook.language, 'system');
  assert.equal(hook.pass_filenames, true);
  assert.deepEqual(hook.types, ['text']);
  assert.equal(hook.minimum_pre_commit_version, '2.0.0');
});

test('config extends inherits base settings with child overrides and removes extends key', () => {
  const dir = createTempDir();
  try {
    const base = {
      scan: { maxFileBytes: 500000 },
      detector: {
        ignoreRules: ['secret/generic-api-key'],
        ignoreFiles: ['fixtures/**'],
      },
      severityOverrides: {
        'ci/unpinned-third-party-action': 'high',
        'secret/aws-access-key-id': 'critical',
      },
      waiverPolicy: {
        maxExpiryDays: 90,
      },
    };
    writeFileSync(join(dir, 'base.json'), JSON.stringify(base, null, 2));

    const child = {
      extends: './base.json',
      detector: {
        ignoreFiles: ['test-fixtures/**'],
      },
      severityOverrides: {
        'ci/unpinned-third-party-action': 'critical',
      },
      waiverPolicy: {
        requiredApproverDomain: 'corp.acme.com',
      },
    };
    writeFileSync(join(dir, 'child.json'), JSON.stringify(child, null, 2));

    const resolved = config.readConfigFile(join(dir, 'child.json'));
    assert.equal(resolved.extends, undefined, 'extends key must not be present in resolved config');
    assert.equal(resolved.scan.maxFileBytes, 500000);
    assert.deepEqual(resolved.detector.ignoreRules, ['secret/generic-api-key']);
    assert.deepEqual(resolved.detector.ignoreFiles, ['test-fixtures/**']);
    assert.equal(resolved.severityOverrides['ci/unpinned-third-party-action'], 'critical');
    assert.equal(resolved.severityOverrides['secret/aws-access-key-id'], 'critical');
    assert.equal(resolved.waiverPolicy.maxExpiryDays, 90);
    assert.equal(resolved.waiverPolicy.requiredApproverDomain, 'corp.acme.com');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('config multi-level extends recursively resolves ancestors', () => {
  const dir = createTempDir();
  try {
    writeFileSync(join(dir, 'root.json'), JSON.stringify({
      scan: { maxFileBytes: 1000 },
      severityOverrides: { 'rule-a': 'low' },
    }));

    writeFileSync(join(dir, 'mid.json'), JSON.stringify({
      extends: './root.json',
      severityOverrides: { 'rule-a': 'medium', 'rule-b': 'high' },
    }));

    writeFileSync(join(dir, 'leaf.json'), JSON.stringify({
      extends: './mid.json',
      severityOverrides: { 'rule-b': 'critical', 'rule-c': 'low' },
    }));

    const resolved = config.readConfigFile(join(dir, 'leaf.json'));
    assert.equal(resolved.scan.maxFileBytes, 1000);
    assert.equal(resolved.severityOverrides['rule-a'], 'medium');
    assert.equal(resolved.severityOverrides['rule-b'], 'critical');
    assert.equal(resolved.severityOverrides['rule-c'], 'low');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('circular extends detection prevents infinite recursion', () => {
  const dir = createTempDir();
  try {
    // Self-reference
    writeFileSync(join(dir, 'self.json'), JSON.stringify({
      extends: './self.json',
      severityOverrides: { 'rule-a': 'high' },
    }));

    assert.throws(
      () => config.readConfigFile(join(dir, 'self.json')),
      /circular extends detected/i
    );

    // Mutual cycle A -> B -> A
    writeFileSync(join(dir, 'a.json'), JSON.stringify({
      extends: './b.json',
    }));
    writeFileSync(join(dir, 'b.json'), JSON.stringify({
      extends: './a.json',
    }));

    assert.throws(
      () => config.readConfigFile(join(dir, 'a.json')),
      /circular extends detected/i
    );

    // 3-hop cycle X -> Y -> Z -> X
    writeFileSync(join(dir, 'x.json'), JSON.stringify({ extends: './y.json' }));
    writeFileSync(join(dir, 'y.json'), JSON.stringify({ extends: './z.json' }));
    writeFileSync(join(dir, 'z.json'), JSON.stringify({ extends: './x.json' }));

    assert.throws(
      () => config.readConfigFile(join(dir, 'x.json')),
      /circular extends detected/i
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('severityOverrides can be queried and applied to findings and rules', () => {
  const overrides = {
    'ci/unpinned-third-party-action': 'critical',
    'secret/aws-access-key-id': 'low',
  };

  assert.equal(config.getSeverityOverride('ci/unpinned-third-party-action', overrides), 'critical');
  assert.equal(config.getSeverityOverride('secret/aws-access-key-id', overrides), 'low');
  assert.equal(config.getSeverityOverride('nonexistent/rule', overrides), undefined);

  const findings = [
    mockFinding({ rule: 'ci/unpinned-third-party-action', severity: 'medium' }),
    mockFinding({ id: 'bbbb2222', rule: 'other/rule', severity: 'high' }),
  ];

  const adjusted = config.applySeverityOverrides(findings, overrides);
  assert.equal(adjusted[0].severity, 'critical', 'matching finding severity should be overridden');
  assert.equal(adjusted[1].severity, 'high', 'unaffected finding severity remains untouched');
  assert.equal(findings[0].severity, 'medium', 'original findings array must not be mutated');

  // Also works with rule objects having .id
  const ruleObjs = [
    { id: 'ci/unpinned-third-party-action', severity: 'medium' },
    { id: 'custom/rule', severity: 'low' },
  ];
  const adjustedRules = config.applySeverityOverrides(ruleObjs, overrides);
  assert.equal(adjustedRules[0].severity, 'critical');
  assert.equal(adjustedRules[1].severity, 'low');
});

test('rulePaths and custom rule loading from globs, directories, and files', () => {
  const dir = createTempDir();
  try {
    const rulesDir = join(dir, 'custom-rules');
    mkdirSync(rulesDir, { recursive: true });

    const rule1Yaml = `
id: custom/no-debug-mode
name: No debug mode allowed
domain: logic
message: Do not enable debug mode
why: Debug mode exposes internal state.
fix: Disable debug mode.
severity: high
confidence: firm
parse: text
match:
  regex: 'DEBUG_MODE_FLAG\\s*=\\s*true'
files:
  - '**/*.js'
  - '**/*.ts'
`;
    writeFileSync(join(rulesDir, 'no-debug.yaml'), rule1Yaml);

    const rule2Yaml = `
- id: custom/no-mock-endpoint
  name: No mock endpoint in prod
  domain: network
  message: Mock endpoint detected
  why: Mock endpoints are for testing only.
  fix: Use production endpoints.
  severity: critical
  confidence: confirmed
  parse: text
  match:
    regex: 'MOCK_ENDPOINT\\s*=\\s*https?://'
  files:
    - '**/*.env'
`;
    writeFileSync(join(rulesDir, 'no-mock.yaml'), rule2Yaml);

    // Glob pattern loading
    const cfgWithGlob = { rulePaths: ['./custom-rules/*.yaml'] };
    const loadedFromGlob = config.loadCustomRules(dir, cfgWithGlob);
    assert.equal(loadedFromGlob.length, 2);
    const ids = loadedFromGlob.map((r) => r.id).sort();
    assert.deepEqual(ids, ['custom/no-debug-mode', 'custom/no-mock-endpoint']);

    // Check compiled rule properties
    const noDebug = loadedFromGlob.find((r) => r.id === 'custom/no-debug-mode');
    assert.equal(noDebug.pack, 'custom');
    assert.equal(noDebug.severity, 'high');
    assert.equal(noDebug.confidence, 'firm');
    assert.ok(noDebug.re instanceof RegExp);
    assert.ok(noDebug.re.test('DEBUG_MODE_FLAG = true'));

    // Directory path loading
    const cfgWithDir = { rulePaths: ['./custom-rules'] };
    const loadedFromDir = config.loadCustomRules(dir, cfgWithDir);
    assert.equal(loadedFromDir.length, 2);

    // Specific file loading
    const cfgWithFile = { rulePaths: ['./custom-rules/no-debug.yaml'] };
    const loadedFromFile = config.loadCustomRules(dir, cfgWithFile);
    assert.equal(loadedFromFile.length, 1);
    assert.equal(loadedFromFile[0].id, 'custom/no-debug-mode');

    // resolveRulePaths alias
    const aliasResult = config.resolveRulePaths(dir, cfgWithFile);
    assert.equal(aliasResult.length, 1);
    assert.equal(aliasResult[0].id, 'custom/no-debug-mode');

    // Empty or non-existent rulePaths
    assert.deepEqual(config.loadCustomRules(dir, {}), []);
    assert.deepEqual(config.loadCustomRules(dir, { rulePaths: [] }), []);
    assert.deepEqual(config.loadCustomRules(dir, { rulePaths: ['./nonexistent-rules/*.yaml'] }), []);

    // Malformed custom rule throws RuleError
    const badDir = join(dir, 'bad-rules');
    mkdirSync(badDir, { recursive: true });
    writeFileSync(join(badDir, 'bad.yaml'), `
id: invalid-id-without-slash
name: Bad Rule
domain: test
message: Bad
why: Bad
fix: Bad
severity: high
confidence: firm
parse: text
match:
  regex: 'foo'
files: ['*']
`);
    assert.throws(
      () => config.loadCustomRules(dir, { rulePaths: ['./bad-rules/*.yaml'] }),
      RuleError
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('waiverPolicy enforcement in validateWaiverPolicy and store.accept', () => {
  const T0 = '2026-06-01T00:00:00.000Z';
  const records = new Map([['aaaa1111', mockFinding()]]);

  // 1. maxExpiryDays validation
  const max30Policy = { maxExpiryDays: 30 };

  // Exceeds maxExpiryDays
  const datePlus40 = '2026-07-11T00:00:00.000Z'; // 40 days
  assert.throws(
    () => store.accept(records, 'aaaa1111', {
      reason: 'Temporary deferral',
      approver: 'alice@corp.com',
      expires: datePlus40,
      now: T0,
      waiverPolicy: max30Policy,
    }),
    /exceeds maximum allowed duration of 30 days/i
  );

  // Missing expires when maxExpiryDays is configured
  assert.throws(
    () => store.accept(records, 'aaaa1111', {
      reason: 'Indefinite waiver',
      approver: 'alice@corp.com',
      now: T0,
      waiverPolicy: max30Policy,
    }),
    /requires an expiration date/i
  );

  // Invalid expires date string
  assert.throws(
    () => store.accept(records, 'aaaa1111', {
      reason: 'Malformed date',
      approver: 'alice@corp.com',
      expires: 'not-a-date',
      now: T0,
      waiverPolicy: max30Policy,
    }),
    /invalid waiver expiration date/i
  );

  // 2. requiredApproverDomain validation
  const domainPolicy = { requiredApproverDomain: 'acme.corp' };

  // Approver does not match domain
  assert.throws(
    () => store.accept(records, 'aaaa1111', {
      reason: 'Deferred',
      approver: 'contractor@external.com',
      now: T0,
      waiverPolicy: domainPolicy,
    }),
    /must be from domain @acme.corp/i
  );

  // Approver domain with leading @ in policy
  const domainWithAtPolicy = { requiredApproverDomain: '@acme.corp' };
  assert.throws(
    () => store.accept(records, 'aaaa1111', {
      reason: 'Deferred',
      approver: 'attacker@evil.com',
      now: T0,
      waiverPolicy: domainWithAtPolicy,
    }),
    /must be from domain @acme.corp/i
  );

  // 3. Combined valid waiver policy
  const fullPolicy = {
    maxExpiryDays: 30,
    requiredApproverDomain: 'acme.corp',
  };
  const datePlus14 = '2026-06-15T00:00:00.000Z'; // 14 days
  const updated = store.accept(records, 'aaaa1111', {
    reason: 'Approved migration grace period',
    approver: 'sec-lead@acme.corp',
    expires: datePlus14,
    now: T0,
    waiverPolicy: fullPolicy,
  });

  const acceptedRec = updated.get('aaaa1111');
  assert.equal(acceptedRec.status, 'accepted');
  assert.equal(acceptedRec.waiver.reason, 'Approved migration grace period');
  assert.equal(acceptedRec.waiver.approver, 'sec-lead@acme.corp');
  assert.equal(acceptedRec.waiver.expires, datePlus14);
  assert.equal(acceptedRec.waiver.acceptedAt, T0);

  // 4. Calling store.accept without waiverPolicy still works as standard
  const normalAccept = store.accept(records, 'aaaa1111', {
    reason: 'Standard approval',
    approver: 'any-user@any-domain.com',
    now: T0,
  });
  assert.equal(normalAccept.get('aaaa1111').status, 'accepted');
});
