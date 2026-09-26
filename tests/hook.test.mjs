// The edit hook. Most of these encode a decision about when *not* to speak:
// a hook that interrupts too often gets switched off, and a hook that is
// switched off protects nobody.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { runHook, payload, isStopEvent, resolveHarness, resolveTargets, ENVELOPE } from '../engine/src/hook.mjs';
import { ROOT } from './helpers.mjs';

const RULES = resolve(ROOT, 'engine/build/rules.json');

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-hook-'));
  mkdirSync(join(dir, '.airtight'), { recursive: true });
  writeFileSync(join(dir, '.airtight', 'config.json'), '{}');
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(join(dir, name, '..'), { recursive: true });
    writeFileSync(join(dir, name), body);
  }
  return dir;
}

function fire(dir, input) {
  const out = [];
  const err = [];
  const code = runHook(
    { out: (s) => out.push(s), err: (s) => err.push(s) },
    { CLAUDE_PROJECT_DIR: dir, AIRTIGHT_RULES: RULES },
    JSON.stringify(input),
  );
  const context = out.length ? JSON.parse(out[0]).hookSpecificOutput?.additionalContext ?? '' : '';
  return { code, context, stderr: err.join('\n') };
}

// Synthetic, and real-shaped on purpose: a hook test that plants a key the
// rules do not recognize proves nothing about the blocking path.
// airtight-disable secret/aws-access-key-id -- synthetic fixture value owned by this file
const edit = (file, session = 's') => ({
  session_id: session, hook_event_name: 'PostToolUse', tool_name: 'Edit',
  tool_input: { file_path: file },
});

const AWS_KEY = ['AKIA', 'QYLPM6R4T7XZVN3K'].join('');
const SECRET = `const key = "${AWS_KEY}";\n`;
const ROOTFUL = 'FROM node:20-alpine\nCMD ["node","x.js"]\n';

test('payload speaks each harness contract', () => {
  assert.deepEqual(JSON.parse(payload('x', 'PostToolUse', 'claude')),
    { hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: 'x' } });
  assert.deepEqual(JSON.parse(payload('x', 'PostToolUse', 'cursor')), { additional_context: 'x' });
  assert.deepEqual(JSON.parse(payload('x', 'PostToolUse', 'github')), { additionalContext: 'x' });
  assert.deepEqual(JSON.parse(payload('x', 'Stop', 'codex')), { decision: 'block', reason: 'x' });
  assert.equal(payload('', 'Stop', 'claude'), '', 'nothing to say means say nothing');
});

test('the event and the harness are read off the envelope shape', () => {
  assert.equal(isStopEvent({ hook_event_name: 'Stop' }), true);
  assert.equal(isStopEvent({ hookEventName: 'PostToolUse' }), false);
  assert.equal(resolveHarness({ conversation_id: 'x' }, {}), 'cursor');
  assert.equal(resolveHarness({ toolName: 'x' }, {}), 'github');
  assert.equal(resolveHarness({ turn_id: 'x' }, {}), 'codex');
  assert.equal(resolveHarness({}, {}), 'claude');
  assert.equal(resolveHarness({ conversation_id: 'x' }, { AIRTIGHT_HOOK_HARNESS: 'claude' }), 'claude');
});

test('targets come from every shape a harness uses, including patch commands', () => {
  assert.deepEqual(resolveTargets({ tool_input: { file_path: 'a.ts' } }), ['a.ts']);
  assert.deepEqual(resolveTargets({ toolArgs: { path: 'b.ts' } }), ['b.ts']);
  assert.deepEqual(
    resolveTargets({ tool_input: { command: '*** Update File: c.ts\n*** Add File: d.ts\n' } }),
    ['c.ts', 'd.ts']);
});

test('a confirmed critical blocks the write', () => {
  const dir = project({ 'bad.js': SECRET });
  try {
    const { code, stderr } = fire(dir, edit('bad.js'));
    assert.equal(code, 2, 'exit 2 is what puts this in front of the model and stops the turn');
    assert.match(stderr, /confirmed critical/);
    assert.ok(!stderr.includes(AWS_KEY), 'and it is still redacted on the blocking path');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('anything short of a confirmed critical advises rather than blocks', () => {
  const dir = project({ Dockerfile: ROOTFUL });
  try {
    const { code, context } = fire(dir, edit('Dockerfile'));
    assert.equal(code, 0);
    assert.match(context, /runs-as-root/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a repeat edit does not turn a dedup into a false all-clear', () => {
  // Regression. The second edit reported "no deterministic security findings"
  // for a file that still had one; it had only been reported already. A hook
  // that says "clean" about a file it just flagged is worse than silent.
  const dir = project({ Dockerfile: ROOTFUL });
  try {
    assert.match(fire(dir, edit('Dockerfile')).context, /runs-as-root/);
    const second = fire(dir, edit('Dockerfile')).context;
    assert.ok(!/No deterministic security findings/.test(second));
    assert.match(second, /Still has 1 finding/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a clean file is acknowledged once, and the acknowledgement undersells itself', () => {
  const dir = project({ 'clean.js': 'export const x = 1;\n' });
  try {
    const first = fire(dir, edit('clean.js')).context;
    assert.match(first, /No deterministic security findings/);
    // Anti-complacency: a clean deterministic scan is a narrow claim.
    assert.match(first, /not the same as secure/);
    assert.equal(fire(dir, edit('clean.js')).context, '', 'and only once per file per session');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the deep pass sees rules the immediate tier withholds', () => {
  const dir = project({ Dockerfile: ROOTFUL });
  try {
    fire(dir, edit('Dockerfile'));
    const stop = fire(dir, { session_id: 's', hook_event_name: 'Stop' }).context;
    // unpinned-digest is low/tentative and deliberately not allowed to
    // interrupt an edit, but it belongs in the end-of-turn sweep.
    assert.match(stop, /unpinned-digest/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the hook stands down after a file is edited repeatedly', () => {
  const dir = project({ Dockerfile: ROOTFUL });
  try {
    for (let i = 0; i < 7; i += 1) fire(dir, edit('Dockerfile'));
    // Past the ceiling the file is dropped entirely rather than re-reported.
    // Continuing to interrupt someone mid-iteration is how a hook gets
    // disabled, and a disabled hook protects nothing.
    assert.equal(fire(dir, edit('Dockerfile')).context, '');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('generated and out-of-project paths are never scanned', () => {
  const dir = project({ 'node_modules/p/i.js': SECRET, 'dist/b.js': SECRET, 'a.min.js': SECRET });
  try {
    for (const f of ['node_modules/p/i.js', 'dist/b.js', 'a.min.js', '../escape.js', '/etc/passwd']) {
      assert.equal(fire(dir, edit(f)).code, 0, `${f} must not be scanned`);
      assert.equal(fire(dir, edit(f)).context, '');
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the hook stays silent when disabled, re-entered, or fed nonsense', () => {
  const dir = project({ 'bad.js': SECRET });
  try {
    const quiet = (env, body = JSON.stringify(edit('bad.js'))) => {
      const out = [];
      const code = runHook({ out: (s) => out.push(s), err: () => {} },
        { CLAUDE_PROJECT_DIR: dir, AIRTIGHT_RULES: RULES, ...env }, body);
      return { code, out: out.join('') };
    };
    assert.deepEqual(quiet({ AIRTIGHT_HOOK_DEPTH: '1' }), { code: 0, out: '' });
    assert.deepEqual(quiet({ CLAUDE_HOOK_DEPTH: '1' }), { code: 0, out: '' });
    assert.deepEqual(quiet({ AIRTIGHT_HOOK_DISABLED: 'true' }), { code: 0, out: '' });
    assert.deepEqual(quiet({}, 'not json'), { code: 0, out: '' });
    assert.deepEqual(quiet({}, '[]'), { code: 0, out: '' });

    writeFileSync(join(dir, '.airtight', 'config.json'), JSON.stringify({ hook: { enabled: false } }));
    assert.deepEqual(quiet({}), { code: 0, out: '' });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the finding line carries a pre-filled waiver and the footer carries the ladder', () => {
  const dir = project({ 'bad.js': SECRET });
  try {
    const { stderr } = fire(dir, edit('bad.js'));
    assert.match(stderr, new RegExp(ENVELOPE.replace(/[[\]]/g, '\\$&')));
    // Pre-filled so the agent never has to invent a broader suppression, and
    // by fingerprint because the value itself must not be echoed.
    assert.match(stderr, /ignore-value secret\/aws-access-key-id --fingerprint [0-9a-f]{6}/);
    assert.match(stderr, /Self-service ends at ignore-value/);
    assert.match(stderr, /never be used to push a blocked write through/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
