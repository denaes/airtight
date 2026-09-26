// The findings store: the lifecycle a plain scan cannot express.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as store from '../engine/src/store.mjs';

const finding = (over = {}) => ({
  id: 'aaaa1111', rule: 'secret/aws-access-key-id', title: 'AWS key',
  domain: 'secrets', severity: 'critical', confidence: 'confirmed',
  disposition: 'fix', cwe: 'CWE-798', owasp: 'A07:2021',
  file: 'src/a.ts', line: 3, provenance: 'deterministic-rule', ...over,
});

const T0 = '2026-01-01T00:00:00.000Z';
const T1 = '2026-01-02T00:00:00.000Z';
const T2 = '2026-03-01T00:00:00.000Z';

test('a new finding is recorded as open with a severity-derived deadline', () => {
  const { records, events } = store.reconcile(new Map(), [finding()], { now: T0 });
  assert.equal(events.added, 1);
  const rec = records.get('aaaa1111');
  assert.equal(rec.status, 'open');
  assert.equal(rec.firstSeen, T0);
  // critical carries a 7-day SLA.
  assert.equal(rec.due, '2026-01-08T00:00:00.000Z');
});

test('a finding that disappears is marked fixed, not deleted', () => {
  // Deleting it would lose the history that makes a regression detectable.
  const first = store.reconcile(new Map(), [finding()], { now: T0 }).records;
  const { records, events } = store.reconcile(first, [], { now: T1 });
  assert.equal(events.fixed, 1);
  assert.equal(records.get('aaaa1111').status, 'fixed');
  assert.equal(records.get('aaaa1111').fixedAt, T1);
});

test('a fixed finding that returns is regressed, not merely open again', () => {
  // This is the distinction the whole store exists for. Finding it the first
  // time and finding it again after a fix are different events: the second
  // usually means the fix never reached where it needed to.
  let records = store.reconcile(new Map(), [finding()], { now: T0 }).records;
  records = store.reconcile(records, [], { now: T1 }).records;
  const third = store.reconcile(records, [finding()], { now: T2 });
  assert.equal(third.events.regressed, 1);
  assert.equal(third.events.added, 0);
  assert.equal(third.records.get('aaaa1111').status, 'regressed');
  assert.equal(third.records.get('aaaa1111').firstSeen, T0, 'the original sighting is preserved');
});

test('identity survives the finding moving to another line', () => {
  const moved = finding({ line: 42 });
  const first = store.reconcile(new Map(), [finding()], { now: T0 }).records;
  const { records, events } = store.reconcile(first, [moved], { now: T1 });
  assert.equal(events.added, 0, 'reformatting must not look like a new vulnerability');
  assert.equal(records.get('aaaa1111').location, 'src/a.ts:42');
});

test('accepting a finding requires a named approver and a reason', () => {
  const records = store.reconcile(new Map(), [finding()], { now: T0 }).records;
  assert.throws(() => store.accept(records, 'aaaa1111', { reason: 'x' }), /approver/);
  assert.throws(() => store.accept(records, 'aaaa1111', { approver: 'x' }), /reason/);
  assert.throws(() => store.accept(records, 'nope', { reason: 'a', approver: 'b' }), /no finding/);
});

test('an accepted finding stays quiet until its waiver expires', () => {
  let records = store.reconcile(new Map(), [finding()], { now: T0 }).records;
  records = store.accept(records, 'aaaa1111', {
    reason: 'compensating control at the gateway', approver: 'security-lead',
    expires: '2026-02-01T00:00:00.000Z', now: T0,
  });

  const quiet = store.reconcile(records, [finding()], { now: T1 });
  assert.equal(quiet.records.get('aaaa1111').status, 'accepted');
  assert.equal(quiet.events.waiverExpired, 0);

  // Time-boxing the acceptance is the point: the finding returns by itself.
  const expired = store.reconcile(records, [finding()], { now: T2 });
  assert.equal(expired.events.waiverExpired, 1);
  assert.equal(expired.records.get('aaaa1111').status, 'open');
});

test('overdue reports active findings past their deadline and ignores closed ones', () => {
  let records = store.reconcile(new Map(), [finding()], { now: T0 }).records;
  assert.equal(store.overdue(records, T1).length, 0);
  assert.equal(store.overdue(records, T2).length, 1);

  records = store.reconcile(records, [], { now: T1 }).records;
  assert.equal(store.overdue(records, T2).length, 0, 'a fixed finding is not overdue');
});

test('the store round-trips through disk and stays sorted for clean merges', () => {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-store-'));
  try {
    const { records } = store.reconcile(new Map(), [
      finding({ id: 'cccc3333' }), finding({ id: 'aaaa1111' }), finding({ id: 'bbbb2222' }),
    ], { now: T0 });
    store.save(dir, records);

    const raw = readFileSync(join(dir, store.STORE_PATH), 'utf8').trim().split('\n');
    assert.deepEqual(raw.map((l) => JSON.parse(l).id), ['aaaa1111', 'bbbb2222', 'cccc3333'],
      'sorted so two branches adding findings edit different lines');

    const reloaded = store.load(dir);
    assert.equal(reloaded.size, 3);
    assert.deepEqual(reloaded.get('bbbb2222'), records.get('bbbb2222'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a corrupt line is skipped rather than failing the whole load', () => {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-store-'));
  try {
    const { records } = store.reconcile(new Map(), [finding()], { now: T0 });
    store.save(dir, records);
    const path = join(dir, store.STORE_PATH);
    appendFileSync(path, '{not json\n');
    assert.equal(store.load(dir).size, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
