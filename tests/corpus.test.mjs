// Invariants that hold across the whole rule corpus.
//
// Individual fixtures prove a rule does what it claims. These prove the corpus
// as a whole stays coherent as it grows past a hundred rules, and encode the
// policy decisions that are easy to violate by accident when adding the next
// one.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { allRules } from './helpers.mjs';

test('no rule regex matches the empty string', () => {
  // A regex that matches emptiness fires on every line of every file it is
  // scoped to. It is also the usual symptom of an optional group that
  // swallowed the whole pattern.
  const bad = [];
  for (const r of allRules()) {
    for (const [field, re] of [['match.regex', r.re], ['match.not_regex', r.notRe]]) {
      if (!re) continue;
      re.lastIndex = 0;
      if (re.test('')) bad.push(`${r.id} ${field}`);
    }
  }
  assert.deepEqual(bad, []);
});

test('the immediate tier never contains a tentative rule', () => {
  // The immediate tier interrupts an edit in progress. Interrupting someone
  // over a finding we are not confident in is how a security tool gets
  // switched off, so confidence is the gate, not severity.
  const bad = allRules()
    .filter((r) => r.tier === 'immediate' && r.confidence === 'tentative')
    .map((r) => r.id);
  assert.deepEqual(bad, []);
});

test('every rule carries a CWE', () => {
  const bad = allRules().filter((r) => !r.cwe).map((r) => r.id);
  assert.deepEqual(bad, [], 'a finding without a CWE cannot be mapped to a control or a framework');
});

test('every rule explains itself in its own words', () => {
  // `why` is what makes a finding actionable by someone who does not already
  // know the vulnerability class, and `fix` is what makes it closable.
  const thin = allRules()
    .filter((r) => r.why.length < 60 || r.fix.length < 30)
    .map((r) => r.id);
  assert.deepEqual(thin, []);
});

test('redacting rules never leave the raw line as the snippet', () => {
  // A redact rule whose snippet is the whole line depends on the vault having
  // registered every other secret on that line. Capture scope removes the
  // dependency for rules where the match is the credential.
  const bad = allRules()
    .filter((r) => r.redact && r.parse === 'js' && r.snippet !== 'capture')
    .map((r) => r.id);
  assert.deepEqual(bad, []);
});

test('rule ids are namespaced by pack and unique', () => {
  const ids = allRules().map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, 'duplicate rule id');
  for (const id of ids) assert.match(id, /^[a-z0-9-]+\/[a-z0-9-]+$/);
});

test('structured rules name a parser that matches their assertions', () => {
  const bad = allRules()
    .filter((r) => r.parse !== 'text' && r.parse !== 'js')
    .filter((r) => !(r.assert?.all?.length || r.assert?.any?.length))
    .map((r) => r.id);
  assert.deepEqual(bad, []);
});

test('the corpus covers every domain the packs claim', () => {
  const domains = new Set(allRules().map((r) => r.domain));
  for (const d of ['secrets', 'containers', 'supply-chain', 'infrastructure', 'appsec']) {
    assert.ok(domains.has(d), `no rules for domain "${d}"`);
  }
});

test('rule regexes are valid under standard ES2020 without unsupported modifier groups', () => {
  // (?i:...) modifier groups require V8 12.8 / Node 23.6+. Node 20 and 22 reject them.
  // Rule definitions must use standard (?i) prefixes or flags.
  const bad = [];
  for (const r of allRules()) {
    for (const key of ['regex', 'not_regex', 'require_regex']) {
      const p = r.match?.[key];
      if (!p) continue;
      if (/\(\?[a-z]+:/.test(p)) {
        bad.push(`${r.id} ${key}: uses unsupported modifier group (?i:...)`);
      }
    }
  }
  assert.deepEqual(bad, []);
});
