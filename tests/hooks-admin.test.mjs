// Hook installation and the suppression ladder. The ladder is enforced here as
// well as documented, because the boundary between what an agent may waive and
// what needs a human is the only thing that keeps a waiver meaningful.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as hooks from '../engine/src/hooks-admin.mjs';

const project = () => mkdtempSync(join(tmpdir(), 'airtight-admin-'));
const settings = (dir) => JSON.parse(readFileSync(join(dir, '.claude/settings.json'), 'utf8'));
const config = (dir) => JSON.parse(readFileSync(join(dir, '.airtight/config.json'), 'utf8'));

test('install adds both events and leaves other hooks alone', () => {
  const dir = project();
  try {
    mkdirSync(join(dir, '.claude'), { recursive: true });
    writeFileSync(join(dir, '.claude/settings.json'), JSON.stringify({
      hooks: { PostToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo mine' }] }] },
    }));

    hooks.install(dir);
    const s = settings(dir);
    assert.equal(s.hooks.PostToolUse.length, 2, 'someone else’s hook must survive');
    assert.equal(s.hooks.PostToolUse[0].hooks[0].command, 'echo mine');
    assert.ok(s.hooks.Stop);

    // The guard makes a missing launcher a silent no-op while preserving the
    // launcher's exit code, so exit 2 still reaches the agent. `|| true`
    // would swallow it and the blocking path would silently stop blocking.
    const cmd = s.hooks.PostToolUse[1].hooks[0].command;
    assert.match(cmd, /^\[ ! -f "/);
    assert.ok(!cmd.includes('|| true'));
    assert.equal(s.hooks.PostToolUse[1].hooks[0].timeout, 5);
    assert.equal(s.hooks.Stop[0].hooks[0].timeout, 30, 'the deep pass needs longer than an edit check');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('install is idempotent and uninstall leaves no trace of ours', () => {
  const dir = project();
  try {
    hooks.install(dir);
    hooks.install(dir);
    assert.equal(settings(dir).hooks.PostToolUse.length, 1);
    assert.equal(hooks.status(dir).installed, true);

    hooks.uninstall(dir);
    assert.equal(hooks.status(dir).installed, false);
    assert.deepEqual(settings(dir).hooks, {});
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('disabling is separate from uninstalling', () => {
  // Turning the hook off should not require editing the harness manifest, so
  // it can be done per developer in a gitignored file.
  const dir = project();
  try {
    hooks.install(dir);
    hooks.setEnabled(dir, false);
    const s = hooks.status(dir);
    assert.equal(s.installed, true);
    assert.equal(s.enabled, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a value waiver demands a reason', () => {
  // A waiver records a decision. A decision with no stated basis is
  // indistinguishable from nobody having made one.
  const dir = project();
  try {
    assert.throws(() => hooks.ignoreValue(dir, { rule: 'secret/x', value: 'v' }), /reason/);
    assert.throws(() => hooks.ignoreValue(dir, { value: 'v', reason: 'r' }), /rule id/);
    assert.throws(() => hooks.ignoreValue(dir, { rule: 'secret/x', reason: 'r' }), /value or a --fingerprint/);

    hooks.ignoreValue(dir, { rule: 'secret/x', fingerprint: 'abc123', reason: 'synthetic fixture, verified by me' });
    const [entry] = config(dir).detector.ignoreValues;
    assert.equal(entry.fingerprint, 'abc123');
    assert.match(entry.reason, /synthetic fixture/);
    assert.ok(entry.createdAt, 'a waiver is dated so it can be reviewed later');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a wildcard value with no file scope is refused', () => {
  // It would suppress the rule project-wide while looking like the narrow
  // rung the agent is allowed to use unattended.
  const dir = project();
  try {
    assert.throws(
      () => hooks.ignoreValue(dir, { rule: 'secret/x', value: '*', reason: 'r' }),
      /ignore-rule in disguise/);
    hooks.ignoreValue(dir, { rule: 'secret/x', value: '*', files: ['legacy/**'], reason: 'r' });
    assert.deepEqual(config(dir).detector.ignoreValues[0].files, ['legacy/**']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the broader rungs carry an escalation notice', () => {
  const dir = project();
  try {
    hooks.ignoreFile(dir, 'legacy/**');
    hooks.ignoreRule(dir, 'secret/x');
    hooks.ignoreFile(dir, 'legacy/**');
    assert.deepEqual(config(dir).detector.ignoreFiles, ['legacy/**'], 'idempotent');
    assert.deepEqual(config(dir).detector.ignoreRules, ['secret/x']);

    assert.match(hooks.ESCALATION_NOTICE, /Confirm with the user/);
    assert.match(hooks.ESCALATION_NOTICE, /never run it to get past a blocked write/);
    assert.match(hooks.ESCALATION_NOTICE, /rules that do not exist yet/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
