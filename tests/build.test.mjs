// The generated output is committed, so these assert properties of what
// actually ships rather than of the build that produced it. A stale or
// malformed generated tree is invisible in review and breaks at install time.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { ROOT } from './helpers.mjs';
import { providerList, placeholdersFor } from '../scripts/lib/providers.js';

const CLAUDE_SKILL = resolve(ROOT, '.claude/skills/airtight');
const PLUGIN = resolve(ROOT, 'plugin');

const walk = (dir) => (existsSync(dir) ? readdirSync(dir).flatMap((e) => {
  const f = join(dir, e);
  return statSync(f).isDirectory() ? walk(f) : [f];
}) : []);
const mds = (dir) => walk(dir).filter((f) => f.endsWith('.md'));
const read = (f) => readFileSync(f, 'utf8');

test('the generated skill exists and is a SKILL.md, not a SKILL.src.md', () => {
  // A loader discovers a skill by finding a literal SKILL.md, which is why the
  // source is named .src.md and must never be shipped.
  assert.ok(existsSync(join(CLAUDE_SKILL, 'SKILL.md')));
  assert.ok(!existsSync(join(CLAUDE_SKILL, 'SKILL.src.md')));
  assert.ok(existsSync(join(CLAUDE_SKILL, 'scripts', 'airtight')));
  assert.ok(existsSync(join(CLAUDE_SKILL, 'scripts', 'engine', 'airtight.mjs')));
  assert.ok(existsSync(join(CLAUDE_SKILL, 'scripts', 'rules.json')));
});

test('no placeholder or conditional block survives into any shipped harness', () => {
  // An unresolved placeholder reaches the user verbatim, at the exact moment
  // the skill is telling them which command to run. This caught every
  // convention-tier harness shipping literal {{command_prefix}} text, because
  // the placeholder map was read raw instead of through its defaults.
  const leftovers = [];
  const dirs = [PLUGIN, ...providerList().map((p) => resolve(ROOT, p.configDir))];
  for (const dir of dirs) {
    for (const f of mds(dir)) {
      const text = read(f);
      for (const [, name] of text.matchAll(/\{\{\s*([a-z_]+)\s*\}\}/g)) {
        leftovers.push(`${f.replace(ROOT, '')}: {{${name}}}`);
      }
      for (const [, tag] of text.matchAll(/^<\/?(claude|claude-code|cursor|codex|agents|github|gemini|copilot|grok|hermes|opencode)>$/gm)) {
        leftovers.push(`${f.replace(ROOT, '')}: <${tag}>`);
      }
    }
  }
  assert.deepEqual(leftovers, []);
});

test('every registered provider has a shipped skill', () => {
  const missing = providerList()
    .map((p) => ({ p, skill: resolve(ROOT, p.configDir, 'skills/airtight/SKILL.md') }))
    .filter(({ skill }) => !existsSync(skill))
    .map(({ p }) => p.provider);
  assert.deepEqual(missing, [], 'a provider in the table with no output is a silent gap');
  assert.ok(providerList().length >= 18);
});

test('each provider emits only frontmatter keys its loader reads', () => {
  // A key a loader rejects breaks the whole skill; a key it ignores costs
  // nothing. Emitting only the allowlist is the conservative side of that.
  const problems = [];
  for (const p of providerList()) {
    const text = read(resolve(ROOT, p.configDir, 'skills/airtight/SKILL.md'));
    const fm = /^---\n([\s\S]*?)\n---\n/.exec(text)[1];
    const keys = [...fm.matchAll(/^([a-z-]+):/gm)].map((m) => m[1]);
    const allowed = new Set(['name', 'description', 'version', 'metadata', ...p.frontmatterFields]);
    for (const k of keys) if (!allowed.has(k)) problems.push(`${p.provider}: ${k}`);
    if (p.versionInMetadata) {
      assert.ok(!keys.includes('version'), `${p.provider}: version must nest under metadata`);
      assert.ok(keys.includes('metadata'), `${p.provider}: metadata block missing`);
    }
  }
  assert.deepEqual(problems, []);
});

test('each provider gets its own command prefix and script path', () => {
  for (const p of providerList()) {
    const text = read(resolve(ROOT, p.configDir, 'skills/airtight/SKILL.md'));
    const prefix = placeholdersFor(p.provider).command_prefix;
    assert.ok(text.includes(`${prefix}airtight hooks`), `${p.provider}: wrong command prefix`);
    assert.ok(text.includes(`${p.configDir}/skills/airtight/scripts`), `${p.provider}: wrong script path`);
  }
});

test('agent formats match what each loader expects', () => {
  const claude = read(resolve(ROOT, '.claude/agents/airtight-reviewer.md'));
  assert.match(claude, /^maxTurns: \d+$/m);

  // Cursor expresses capability as a flag rather than a tool list, and skips
  // effort because its effort option needs an explicit model id.
  const cursor = read(resolve(ROOT, '.cursor/agents/airtight-reviewer.md'));
  assert.match(cursor, /^readonly: true$/m);
  assert.match(cursor, /^is_background: false$/m);
  assert.ok(!/^tools:/m.test(cursor));
  assert.ok(!/^effort:/m.test(cursor));

  // Copilot: omitting tools grants all tools, and its vocabulary differs.
  const copilot = read(resolve(ROOT, '.github/agents/airtight-reviewer.agent.md'));
  assert.ok(!/^tools:/m.test(copilot));
  assert.ok(existsSync(resolve(ROOT, '.github/agents/airtight-verifier.agent.md')));

  // Codex discovers agents nested in the skill, as TOML.
  const toml = read(resolve(ROOT, '.agents/skills/airtight/agents/airtight_reviewer.toml'));
  assert.match(toml, /^name = "airtight_reviewer"$/m, 'underscores, not hyphens');
  assert.match(toml, /^model_reasoning_effort = "high"$/m);
  assert.match(toml, /developer_instructions = '''/);
  assert.ok(existsSync(resolve(ROOT, '.agents/skills/airtight/agents/openai.yaml')));
});

test('hook manifests exist where each harness reads them, and preserve exit codes', () => {
  const manifests = {
    '.codex/hooks.json': /apply_patch/,
    '.cursor/hooks.json': /hook-before-edit/,
    '.github/hooks/airtight.json': /git rev-parse --show-toplevel/,
    '.grok/hooks/airtight.json': /PostToolUse/,
  };
  for (const [rel, shape] of Object.entries(manifests)) {
    const text = read(resolve(ROOT, rel));
    assert.match(text, shape, `${rel}: unexpected shape`);
    // The guard makes a missing launcher a no-op while preserving the
    // launcher's exit code. `|| true` would swallow exit 2 and the blocking
    // path would look installed while protecting nothing.
    assert.match(text, /\[ ! -f /, `${rel}: missing the fail-open guard`);
    assert.ok(!text.includes('|| true'), `${rel}: || true would swallow the blocking signal`);
  }
});

test('the opencode command bridge exists', () => {
  // OpenCode registers skill commands natively but its autocomplete hides
  // them, so the bridge is a discoverability fix, not a second entry point.
  const bridge = read(resolve(ROOT, '.opencode/commands/airtight.md'));
  assert.match(bridge, /skill\(\{ name: "airtight" \}\)/);
});

test('the project copy uses project-relative paths', () => {
  const skill = read(join(CLAUDE_SKILL, 'SKILL.md'));
  assert.match(skill, /\.claude\/skills\/airtight\/scripts\/airtight context/);
  assert.ok(!skill.includes('CLAUDE_SKILL_DIR'));
});

test('the plugin copy is rewritten for a cache install', () => {
  // A plugin lives in a cache directory, so a project-relative script path
  // does not resolve there.
  const skill = read(join(PLUGIN, 'skills/airtight/SKILL.md'));
  assert.match(skill, /\$\{CLAUDE_SKILL_DIR\}\/scripts\/airtight context/);
  assert.ok(!skill.includes('.claude/skills/airtight/scripts'));

  for (const f of mds(join(PLUGIN, 'agents'))) {
    assert.ok(!read(f).includes('.claude/skills/airtight/scripts'), `${f} still project-relative`);
  }
});

test('every relative link in the shipped output resolves', () => {
  const broken = [];
  for (const dir of [CLAUDE_SKILL, PLUGIN]) {
    for (const f of mds(dir)) {
      for (const [, , target] of read(f).matchAll(/\[([^\]]+)\]\((?!https?:)([^)#]+)(?:#[^)]*)?\)/g)) {
        if (!existsSync(resolve(dirname(f), target))) broken.push(`${f} -> ${target}`);
      }
    }
  }
  assert.deepEqual(broken, []);
});

test('agent frontmatter is renamed for the Claude loader and stays read-only', () => {
  const agents = readdirSync(resolve(ROOT, '.claude/agents'));
  assert.equal(agents.length, 2);
  for (const f of agents) {
    const text = read(resolve(ROOT, '.claude/agents', f));
    assert.match(text, /^maxTurns: \d+$/m, 'max-turns is camelCase for this loader');
    assert.ok(!/^max-turns:/m.test(text));
    assert.ok(!/\bWrite\b/.test(/^tools: .*$/m.exec(text)[0]));
  }
});

test('an inline fallback ships for every agent, on every provider', () => {
  // Including providers that do support sub-agents, because a user can
  // decline them and the role still has to be runnable.
  const agents = readdirSync(resolve(ROOT, 'skill/agents')).map((f) => f.replace(/^airtight-/, ''));
  for (const p of providerList()) {
    const dir = resolve(ROOT, p.configDir, 'skills/airtight/reference/degraded');
    assert.deepEqual(readdirSync(dir).sort(), agents.sort(), `${p.provider}: fallbacks missing`);
  }
});

test('the claude inline fallback carries its preamble', () => {
  // A harness with no sub-agent capability still has to be able to run the
  // role, from the same specialized text.
  const agents = readdirSync(resolve(ROOT, 'skill/agents')).map((f) => f.replace(/^airtight-/, ''));
  const degraded = readdirSync(join(CLAUDE_SKILL, 'reference/degraded'));
  assert.deepEqual(degraded.sort(), agents.sort());
  for (const f of degraded) {
    const text = read(join(CLAUDE_SKILL, 'reference/degraded', f));
    assert.match(text, /no sub-agent capability/);
    assert.match(text, /Do not edit; edit the agent definition/);
    assert.ok(!/^---$/m.test(text.split('\n')[0]), 'frontmatter is stripped from a fallback');
  }
});

test('manifests agree on version and avoid the loader traps', () => {
  const pkg = JSON.parse(read(resolve(ROOT, 'package.json')));
  const plugin = JSON.parse(read(resolve(ROOT, '.claude-plugin/plugin.json')));
  const market = JSON.parse(read(resolve(ROOT, '.claude-plugin/marketplace.json')));
  const inner = JSON.parse(read(join(PLUGIN, '.claude-plugin/plugin.json')));

  for (const [name, m] of [['plugin', plugin], ['inner', inner]]) {
    assert.equal(m.version, pkg.version, `${name} manifest version drift`);
    // Declaring `agents` as an array of paths makes some loaders load none.
    assert.ok(!('agents' in m), `${name} manifest must not declare agents`);
    assert.ok(m.skills.endsWith('/'), `${name} manifest skills path needs a trailing slash`);
  }
  assert.equal(market.plugins[0].version, pkg.version);
  assert.equal(market.plugins[0].source, './plugin');
});

test('the engine bundle is genuinely self-contained', () => {
  // The banner shim matters: the YAML package's CommonJS build calls
  // require('process'), and without it the bundle throws at load.
  const bundle = join(CLAUDE_SKILL, 'scripts/engine/airtight.mjs');
  assert.match(read(bundle).slice(0, 600), /createRequire/);

  const out = execFileSync(process.execPath, [bundle, 'engine-probe'], {
    encoding: 'utf8',
    cwd: '/',
    // No AIRTIGHT_RULES: the probe must not need the rule bundle.
  });
  assert.match(out, /airtight-engine/);
});

test('the shipped rule bundle matches the compiled source', () => {
  // If these drift, a plugin install ships rules nobody reviewed.
  assert.equal(
    read(join(CLAUDE_SKILL, 'scripts/rules.json')),
    read(resolve(ROOT, 'engine/build/rules.json')),
  );
});

test('the launcher stays dependency-light and fails open for the hook', () => {
  const sh = read(join(CLAUDE_SKILL, 'scripts/airtight'));
  // It runs on every edit, so it must resolve itself without coreutils.
  // Match an invocation, not the word: the file contains a comment explaining
  // why dirname is avoided, and asserting on the bare word flags that comment.
  assert.ok(!/\$\(\s*dirname|`dirname/.test(sh), 'the launcher must not shell out to dirname');
  assert.match(sh, /fail_open_if_hook/);
  assert.match(sh, /exec "\$node_bin"/);
  assert.ok(existsSync(join(CLAUDE_SKILL, 'scripts/airtight.cmd')));
});
