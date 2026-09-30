// The installer, and the symlink bug that made the shipped engine silent.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync, mkdirSync, readdirSync, rmSync, existsSync, readFileSync, writeFileSync,
  symlinkSync, realpathSync,
} from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ROOT } from './helpers.mjs';

// Synthetic, and real-shaped on purpose: an install test that plants a key
// the rules do not recognize proves nothing about the installed engine.
// airtight-disable secret/aws-access-key-id -- synthetic fixture value owned by this file
const AWS_KEY = ['AKIA', 'QYLPM6R4T7XZVN3K'].join('');
const CLI = resolve(ROOT, 'cli/bin/airtight.js');
const BUNDLE = resolve(ROOT, 'skill/scripts/engine/airtight.mjs');

// spawnSync rather than execFileSync: warnings go to stderr, and
// execFileSync discards stderr on success, which silently hid two assertions.
function run(args, opts = {}) {
  const r = spawnSync(process.execPath, args, { encoding: 'utf8', ...opts });
  return { code: r.status, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

const project = () => {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-cli-'));
  mkdirSync(join(dir, '.git'), { recursive: true });
  return dir;
};

test('the engine runs when invoked through a symlinked path', () => {
  // Regression, and the most consequential bug found in this project.
  //
  // The idiomatic entry-point check, `import.meta.url ===
  // \`file://${process.argv[1]}\``, is false whenever the invocation path
  // crosses a symlink: argv[1] keeps the path as typed while import.meta.url
  // is resolved. /tmp on macOS is a symlink to /private/tmp, /home is often a
  // symlink to /Users, and plenty of people keep projects behind one.
  //
  // The failure was silent: the module loaded, nothing ran, the process exited
  // 0. The launcher succeeded, the hook reported no findings, and a user would
  // have concluded their code was clean. Every other test imports run()
  // directly or spawns from the real repo path, so none of them saw it.
  const real = realpathSync(mkdtempSync(join(tmpdir(), 'airtight-real-')));
  const link = join(realpathSync(tmpdir()), `airtight-link-${process.pid}`);
  try {
    symlinkSync(real, link);
    // Sanity: the link genuinely resolves elsewhere, or the test proves nothing.
    assert.notEqual(link, realpathSync(link));

    const viaLink = join(link, 'engine.mjs');
    writeFileSync(join(real, 'engine.mjs'), readFileSync(BUNDLE));

    const direct = run([join(real, 'engine.mjs'), 'engine-probe']);
    const linked = run([viaLink, 'engine-probe']);
    assert.match(direct.out, /airtight-engine/);
    assert.match(linked.out, /airtight-engine/, 'the engine must run through a symlinked path');
  } finally {
    rmSync(link, { recursive: true, force: true });
    rmSync(real, { recursive: true, force: true });
  }
});

test('install places a working skill and wires the hook', () => {
  const dir = project();
  try {
    const { code, out } = run([CLI, 'install', '--providers=claude-code', '--yes'], { cwd: dir });
    assert.equal(code, 0, out);

    const skill = join(dir, '.claude/skills/airtight');
    for (const f of ['SKILL.md', 'scripts/airtight', 'scripts/engine/airtight.mjs', 'scripts/rules.json']) {
      assert.ok(existsSync(join(skill, f)), `missing ${f}`);
    }
    assert.ok(existsSync(join(dir, '.claude/agents/airtight-reviewer.md')));
    assert.ok(existsSync(join(skill, 'reference/degraded/reviewer.md')));

    const settings = JSON.parse(readFileSync(join(dir, '.claude/settings.json'), 'utf8'));
    assert.ok(settings.hooks.PostToolUse);
    assert.ok(settings.hooks.Stop);

    // The installed launcher has to actually work from the installed location.
    writeFileSync(join(dir, 'app.js'), `const k = "${AWS_KEY}";\n`);
    const scan = run([join(skill, 'scripts/engine/airtight.mjs'), 'detect', '.'], {
      cwd: dir, env: { ...process.env, AIRTIGHT_RULES: join(skill, 'scripts/rules.json') },
    });
    assert.equal(scan.code, 2, 'findings present means exit 2');
    assert.match(scan.out, /aws-access-key-id/);
    assert.ok(!scan.out.includes(AWS_KEY), 'and still redacted from the installed copy');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('install does not clobber hooks the user already had', () => {
  const dir = project();
  try {
    mkdirSync(join(dir, '.claude'), { recursive: true });
    writeFileSync(join(dir, '.claude/settings.json'), JSON.stringify({
      hooks: { PostToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo mine' }] }] },
      model: 'opus',
    }));

    run([CLI, 'install', '--providers=claude-code', '--yes'], { cwd: dir });
    const settings = JSON.parse(readFileSync(join(dir, '.claude/settings.json'), 'utf8'));
    assert.equal(settings.model, 'opus', 'unrelated settings must survive');
    assert.equal(settings.hooks.PostToolUse.length, 2);
    assert.equal(settings.hooks.PostToolUse[0].hooks[0].command, 'echo mine');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a settings file that is not valid JSON is left alone', () => {
  // Rewriting a file we cannot parse would destroy configuration. Skipping the
  // hook is the lesser failure, and it is reported.
  const dir = project();
  try {
    mkdirSync(join(dir, '.claude'), { recursive: true });
    writeFileSync(join(dir, '.claude/settings.json'), '{ not json');
    const { out } = run([CLI, 'install', '--providers=claude-code', '--yes'], { cwd: dir });
    assert.match(out, /not valid JSON/);
    assert.equal(readFileSync(join(dir, '.claude/settings.json'), 'utf8'), '{ not json');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('install is idempotent and update refreshes in place', () => {
  const dir = project();
  try {
    run([CLI, 'install', '--providers=claude-code', '--yes'], { cwd: dir });
    const before = readFileSync(join(dir, '.claude/settings.json'), 'utf8');
    const { code } = run([CLI, 'update', '--providers=claude-code'], { cwd: dir });
    assert.equal(code, 0);
    assert.equal(readFileSync(join(dir, '.claude/settings.json'), 'utf8'), before);
    assert.equal(JSON.parse(before).hooks.PostToolUse.length, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('several harnesses install side by side, each in its own format', () => {
  const dir = project();
  try {
    const { code, out } = run(
      [CLI, 'install', '--providers=claude-code,cursor,codex,copilot', '--yes'], { cwd: dir });
    assert.equal(code, 0, out);
    assert.ok(existsSync(join(dir, '.claude/skills/airtight/SKILL.md')));
    assert.ok(existsSync(join(dir, '.cursor/skills/airtight/SKILL.md')));
    assert.ok(existsSync(join(dir, '.agents/skills/airtight/SKILL.md')));
    assert.ok(existsSync(join(dir, '.github/skills/airtight/SKILL.md')));

    // Each harness's own agent format arrived.
    assert.ok(existsSync(join(dir, '.agents/skills/airtight/agents/airtight_reviewer.toml')));
    assert.ok(existsSync(join(dir, '.github/agents/airtight-reviewer.agent.md')));
    assert.match(readFileSync(join(dir, '.cursor/agents/airtight-reviewer.md'), 'utf8'), /readonly: true/);
    // And Codex's standalone hook manifest, which lives outside its skill dir.
    assert.ok(existsSync(join(dir, '.codex/hooks.json')));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('check reports what is installed, and nothing is not an error state to hide', () => {
  const dir = project();
  try {
    const empty = run([CLI, 'check'], { cwd: dir });
    assert.equal(empty.code, 1);
    assert.match(empty.out, /nothing installed/);

    run([CLI, 'install', '--providers=claude-code', '--yes'], { cwd: dir });
    const after = run([CLI, 'check'], { cwd: dir });
    assert.equal(after.code, 0);
    assert.match(after.out, /\.claude/);
    assert.match(after.out, /hook/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('uninstall removes our files and only ours', () => {
  const dir = project();
  try {
    run([CLI, 'install', '--providers=claude-code', '--yes'], { cwd: dir });
    writeFileSync(join(dir, '.claude/agents/mine.md'), '# my agent\n');

    const { code } = run([CLI, 'uninstall'], { cwd: dir });
    assert.equal(code, 0);
    assert.ok(!existsSync(join(dir, '.claude/skills/airtight')));
    assert.ok(!existsSync(join(dir, '.claude/agents/airtight-reviewer.md')));
    assert.ok(existsSync(join(dir, '.claude/agents/mine.md')), 'the user’s own agent must survive');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('an unknown harness is refused with the list of known ones', () => {
  const dir = project();
  try {
    const { code, out } = run([CLI, 'install', '--providers=notaharness', '--yes'], { cwd: dir });
    assert.equal(code, 1);
    assert.match(out, /unknown harness/);
    assert.match(out, /claude-code/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a global override is honoured inside the home directory and refused outside it', async () => {
  // An installer that writes wherever an environment variable points is a
  // privilege escalation waiting to happen.
  //
  // Tested as a unit rather than by running a global install: that would have
  // written into the real home directory of whoever ran the suite, which is
  // exactly the kind of side effect a test must not have.
  const { globalRoot } = await import('../cli/bin/airtight.js');
  const hermes = { provider: 'hermes', configDir: '.hermes' };
  const inside = join(homedir(), 'nested', 'hermes');

  assert.equal(globalRoot(hermes, { HERMES_HOME: inside }), inside);
  assert.equal(globalRoot(hermes, { HERMES_HOME: '/etc/somewhere-else' }), join(homedir(), '.hermes'));
  assert.equal(globalRoot(hermes, {}), join(homedir(), '.hermes'));
  // A provider with no declared override ignores the variable entirely.
  assert.equal(
    globalRoot({ provider: 'cursor', configDir: '.cursor' }, { HERMES_HOME: inside }),
    join(homedir(), '.cursor'));
});

test('no test performs a global install', () => {
  // A meta-test, added after one did.
  //
  // An earlier version of the override test ran `install --scope=global`,
  // which wrote a real skill into the home directory of whoever ran the suite.
  // It was only noticed because a later `check` test then found it and
  // failed. A test that mutates the machine outside a temp directory is a bug
  // regardless of whether it passes.
  const dir = resolve(ROOT, 'tests');
  const offenders = [];
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.test.mjs'))) {
    const text = readFileSync(join(dir, file), 'utf8');
    // Match an install invocation carrying a global scope on the same line.
    for (const [line] of text.matchAll(/^.*\bCLI\b.*(--scope=global|'--global').*$/gm)) {
      offenders.push(`${file}: ${line.trim()}`);
    }
  }
  assert.deepEqual(offenders, [],
    'test the global path by unit-testing globalRoot, never by installing');
});

test('a directory that already has a harness directory is the project root', () => {
  // Regression, found by installing a packed tarball rather than running from
  // the source tree. A subdirectory with .claude/ in it, whose parent happens
  // to hold a package.json, was installing into the parent.
  const outer = project();
  try {
    writeFileSync(join(outer, 'package.json'), '{"name":"outer"}');
    const inner = join(outer, 'app');
    mkdirSync(join(inner, '.claude'), { recursive: true });

    const { code, out } = run([CLI, 'install', '--providers=claude-code', '--yes'], { cwd: inner });
    assert.equal(code, 0, out);
    assert.ok(existsSync(join(inner, '.claude/skills/airtight/SKILL.md')),
      'must install beside the existing harness directory');
    assert.ok(!existsSync(join(outer, '.claude/skills/airtight/SKILL.md')),
      'and not in the ancestor that merely has a package.json');
  } finally { rmSync(outer, { recursive: true, force: true }); }
});

test('cli delegates engine commands directly', () => {
  const dir = project();
  try {
    // 1. Clean detect exits 0
    const clean = run([CLI, 'detect', '--no-config', dir]);
    assert.equal(clean.code, 0, clean.out);
    assert.match(clean.out, /no findings/);

    // 2. Rules listing runs and reports loaded rules
    const rules = run([CLI, 'rules']);
    assert.equal(rules.code, 0, rules.out);
    assert.match(rules.out, /rule\(s\)/);

    // 2b. Rules count-by-pack breakdown works in text and json mode
    const countText = run([CLI, 'rules', '--count-by-pack']);
    assert.equal(countText.code, 0, countText.out);
    assert.match(countText.out, /\bsecret\s+\d+/);
    assert.match(countText.out, /\btotal:\s+\d+/);

    const countJson = run([CLI, 'rules', '--count-by-pack', '--json']);
    assert.equal(countJson.code, 0, countJson.out);
    const parsed = JSON.parse(countJson.out);
    assert.ok(parsed.secret >= 15);
    assert.ok(parsed.py >= 34);

    // 3. Planting a finding triggers exit code 2
    writeFileSync(join(dir, 'insecure.js'), 'const key = "sk_live_' + '123456789012345678901234";\n');
    const dirty = run([CLI, 'detect', '--no-config', dir]);
    assert.equal(dirty.code, 2, dirty.out);
    assert.match(dirty.out, /secret\/stripe-live-key/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

