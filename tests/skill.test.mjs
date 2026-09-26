// The skill surface has to stay coherent as commands are added. These are the
// checks that a human reviewer reliably misses: a table row pointing at a file
// nobody created, a link that rotted, an agent that quietly gained write access.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { parse } from 'yaml';
import { ROOT } from './helpers.mjs';

const SKILL = resolve(ROOT, 'skill');
const src = readFileSync(join(SKILL, 'SKILL.src.md'), 'utf8');

function frontmatter(text) {
  const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
  return m ? { data: parse(m[1]), body: text.slice(m[0].length) } : { data: null, body: text };
}

const referenceFiles = () => readdirSync(join(SKILL, 'reference')).filter((f) => f.endsWith('.md'));

/** Commands table rows: | `name [args]` | Category | Description | [text](path) | */
function commandsTable() {
  const rows = [...src.matchAll(/^\| `([a-z-]+)[^`]*` \| (\w+) \| [^|]+ \| \[[^\]]+\]\(([^)]+)\) \|$/gm)];
  return rows.map(([, name, category, ref]) => ({ name, category, ref }));
}

test('the router has the frontmatter a skill loader requires', () => {
  const { data } = frontmatter(src);
  assert.ok(data, 'SKILL.src.md must open with YAML frontmatter');
  for (const key of ['name', 'description', 'version', 'user-invocable', 'argument-hint', 'license']) {
    assert.ok(data[key] !== undefined, `frontmatter is missing "${key}"`);
  }
  assert.equal(data.name, 'airtight');
  assert.ok(data.description.length <= 1024,
    `description is ${data.description.length} chars; loaders cap it at 1024`);
  // The trigger description is what decides whether the skill is offered at
  // all, so it has to name the work rather than the tool.
  assert.ok(data.description.length > 300, 'description is too thin to route on');
  assert.match(data.description, /Not for/, 'description must state what it is not for');
});

test('reference files carry no frontmatter', () => {
  // Routing is centralized in the router. A reference file with its own
  // frontmatter is a second source of truth for when it applies.
  const withFm = referenceFiles().filter((f) =>
    frontmatter(readFileSync(join(SKILL, 'reference', f), 'utf8')).data !== null);
  assert.deepEqual(withFm, []);
});

test('every command in the table has a reference file that exists', () => {
  const missing = commandsTable().filter(({ ref }) => !existsSync(join(SKILL, ref)));
  assert.deepEqual(missing, []);
});

test('the commands table and command-metadata.json agree', () => {
  const table = commandsTable().map((c) => c.name).sort();
  const meta = Object.keys(JSON.parse(
    readFileSync(join(SKILL, 'scripts', 'command-metadata.json'), 'utf8'))).sort();
  assert.deepEqual(table, meta, 'a command in one and not the other is a command with no help text or no playbook');
  assert.ok(table.length >= 9);
});

test('command metadata describes when to use each command', () => {
  const meta = JSON.parse(readFileSync(join(SKILL, 'scripts', 'command-metadata.json'), 'utf8'));
  for (const [name, entry] of Object.entries(meta)) {
    assert.ok(entry.description.length > 80, `${name}: description too thin to route on`);
    assert.match(entry.description, /Use when/, `${name}: metadata must say when to use it`);
    assert.equal(typeof entry.argumentHint, 'string');
  }
});

test('every relative link across the skill resolves', () => {
  const broken = [];
  const check = (file, text) => {
    for (const [, , target] of text.matchAll(/\[([^\]]+)\]\((?!https?:)([^)#]+)(?:#[^)]*)?\)/g)) {
      if (!existsSync(resolve(dirname(file), target))) broken.push(`${file} -> ${target}`);
    }
  };
  check(join(SKILL, 'SKILL.src.md'), src);
  for (const f of referenceFiles()) {
    const p = join(SKILL, 'reference', f);
    check(p, readFileSync(p, 'utf8'));
  }
  assert.deepEqual(broken, []);
});

test('only known placeholders are used', () => {
  // An unknown placeholder ships to the user verbatim, which reads as a bug in
  // the skill at the exact moment it is telling them to run something.
  const known = new Set(['scripts_path', 'command_prefix', 'model', 'config_file']);
  const unknown = new Set();
  const scan = (text) => {
    for (const [, name] of text.matchAll(/\{\{\s*([a-z_]+)\s*\}\}/g)) {
      if (!known.has(name)) unknown.add(name);
    }
  };
  scan(src);
  for (const f of referenceFiles()) scan(readFileSync(join(SKILL, 'reference', f), 'utf8'));
  for (const f of readdirSync(join(SKILL, 'agents'))) scan(readFileSync(join(SKILL, 'agents', f), 'utf8'));
  assert.deepEqual([...unknown], []);
});

test('subagents are read-only', () => {
  // Both agents exist to read untrusted content and report on it. An agent
  // that can both read hostile input and write files is the exact shape the
  // prompt-injection invariant exists to prevent.
  for (const f of readdirSync(join(SKILL, 'agents'))) {
    const { data } = frontmatter(readFileSync(join(SKILL, 'agents', f), 'utf8'));
    assert.ok(data, `${f}: agents need frontmatter`);
    for (const key of ['name', 'description', 'tools', 'model']) {
      assert.ok(data[key] !== undefined, `${f}: missing "${key}"`);
    }
    const tools = String(data.tools).split(',').map((t) => t.trim());
    for (const forbidden of ['Write', 'Edit', 'NotebookEdit']) {
      assert.ok(!tools.includes(forbidden), `${f}: subagents must not hold ${forbidden}`);
    }
  }
});

test('the prompt-injection invariant is stated in the router and in both agents', () => {
  // It is load-bearing in all three places: the router sets the policy, and
  // each agent is separately exposed to hostile content in its own context.
  assert.match(src, /data, never instruction/i);
  for (const f of readdirSync(join(SKILL, 'agents'))) {
    const text = readFileSync(join(SKILL, 'agents', f), 'utf8');
    assert.match(text, /never instructions?|never as instruction/i, `${f} omits the invariant`);
  }
});

test('severity.md owns the tables and others link to it', () => {
  const sev = readFileSync(join(SKILL, 'reference', 'severity.md'), 'utf8');
  for (const term of ['critical', 'confirmed', 'tentative', 'P0', 'disposition']) {
    assert.match(sev, new RegExp(term, 'i'), `severity.md must define ${term}`);
  }
  // A tentative finding must never be P0, and the table has to say so.
  assert.match(sev, /tentative finding is never P0/i);

  const linkers = referenceFiles()
    .filter((f) => f !== 'severity.md')
    .filter((f) => readFileSync(join(SKILL, 'reference', f), 'utf8').includes('severity.md'));
  assert.ok(linkers.length >= 4, 'the severity model should be referenced, not restated');
});

test('every command playbook names the way it fails', () => {
  // Impeccable's most reusable convention: each playbook names its own
  // characteristic failure, in its own words, so the model recognizes it
  // while it is happening rather than afterwards.
  const commands = new Set(commandsTable().map((c) => `${c.name}.md`));
  const missing = [...commands].filter((f) =>
    !/## The way this command fails/.test(readFileSync(join(SKILL, 'reference', f), 'utf8')));
  assert.deepEqual(missing, []);
});
