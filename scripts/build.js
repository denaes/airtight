#!/usr/bin/env node
// Build orchestrator.
//
// skill/ is the only authoring surface. Everything under .claude/ and plugin/
// is generated and committed, so a git clone or a plugin install both work
// without a build step. Never edit the generated copies.
//
// Default run writes dist/ only. --sync also rewrites the tracked harness
// directories, which is a release action rather than a development one: a
// generated diff in a feature branch conflicts with every other branch.

import {
  cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { PROVIDERS, providerList } from './lib/providers.js';
import { transform } from './lib/transform.js';
import { splitFrontmatter, parseFrontmatter } from './lib/utils.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SKILL = join(ROOT, 'skill');
const DIST = join(ROOT, 'dist');
const SYNC = process.argv.includes('--sync');

const errors = [];
const fail = (msg) => errors.push(msg);

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const walk = (dir) => (existsSync(dir) ? readdirSync(dir).flatMap((e) => {
  const f = join(dir, e);
  return statSync(f).isDirectory() ? walk(f) : [f];
}) : []);

// ------------------------------------------------------------------ manifests

/**
 * The plugin subtree is a second transform on top of the claude-code output.
 * A plugin install lives in a cache directory, so project-relative script
 * paths do not resolve there.
 */
const PLUGIN_SKILL_PATH = '${CLAUDE_SKILL_DIR}/scripts';
const PLUGIN_AGENT_PATH = '${CLAUDE_PLUGIN_ROOT}/skills/airtight/scripts';
const PROJECT_SCRIPTS = '.claude/skills/airtight/scripts';

function stagePlugin(claudeOut, version, pkg) {
  const plugin = join(ROOT, 'plugin');
  rmSync(plugin, { recursive: true, force: true });
  mkdirSync(plugin, { recursive: true });
  cpSync(join(claudeOut, 'skills'), join(plugin, 'skills'), { recursive: true });
  cpSync(join(claudeOut, 'agents'), join(plugin, 'agents'), { recursive: true });

  // SKILL.md and its references get the host-substituted skill dir.
  for (const file of walk(join(plugin, 'skills'))) {
    if (!file.endsWith('.md')) continue;
    const text = readFileSync(file, 'utf8');
    if (text.includes(PROJECT_SCRIPTS)) {
      writeFileSync(file, text.split(PROJECT_SCRIPTS).join(PLUGIN_SKILL_PATH));
    }
  }

  // Agents get the plugin root instead. A spawned agent never loads SKILL.md,
  // so CLAUDE_SKILL_DIR is undefined in the one context that must act on it.
  for (const file of walk(join(plugin, 'agents'))) {
    const text = readFileSync(file, 'utf8');
    writeFileSync(file, text.split(PROJECT_SCRIPTS).join(PLUGIN_AGENT_PATH));
  }

  const manifest = {
    name: 'airtight',
    description: pkg.description,
    version,
    author: { name: pkg.author?.name ?? 'Airtight contributors' },
    homepage: pkg.homepage ?? undefined,
    repository: pkg.repository ?? undefined,
    // Trailing slash matters, and there is deliberately no `agents` key:
    // the host discovers agents/*.md itself, and declaring the key as a list
    // of paths makes some loaders load none.
    skills: './skills/',
  };
  mkdirSync(join(plugin, '.claude-plugin'), { recursive: true });
  writeFileSync(join(plugin, '.claude-plugin', 'plugin.json'), `${JSON.stringify(manifest, null, 2)}\n`);

  // Verify the rewrite actually landed rather than trusting it.
  const skillMd = readFileSync(join(plugin, 'skills', 'airtight', 'SKILL.md'), 'utf8');
  if (skillMd.includes(PROJECT_SCRIPTS)) fail('plugin/: SKILL.md still carries a project-relative script path');
  if (!skillMd.includes(PLUGIN_SKILL_PATH)) fail('plugin/: SKILL.md was not rewritten to ${CLAUDE_SKILL_DIR}');
  // Assert only that nothing project-relative survives. Neither agent
  // currently references the scripts path -- the reviewer is explicitly told
  // not to run the detector -- so requiring the rewritten path to be present
  // would fail on output that is correct.
  for (const file of walk(join(plugin, 'agents'))) {
    if (readFileSync(file, 'utf8').includes(PROJECT_SCRIPTS)) {
      fail(`plugin/: ${relative(ROOT, file)} still carries a project-relative script path`);
    }
  }
  return manifest;
}

function writeRootManifests(version, pkg) {
  const dir = join(ROOT, '.claude-plugin');
  mkdirSync(dir, { recursive: true });

  const plugin = {
    name: 'airtight',
    description: pkg.description,
    version,
    author: { name: pkg.author?.name ?? 'Airtight contributors' },
    skills: './.claude/skills/',
  };
  writeFileSync(join(dir, 'plugin.json'), `${JSON.stringify(plugin, null, 2)}\n`);

  const marketplace = {
    $schema: 'https://anthropic.com/claude-code/marketplace.schema.json',
    name: 'airtight',
    metadata: { description: pkg.description },
    owner: { name: pkg.author?.name ?? 'Airtight contributors' },
    plugins: [{
      name: 'airtight',
      description: pkg.description,
      version,
      source: './plugin',
      category: 'security',
      tags: ['security', 'appsec', 'secrets', 'supply-chain', 'iac', 'skills'],
    }],
  };
  writeFileSync(join(dir, 'marketplace.json'), `${JSON.stringify(marketplace, null, 2)}\n`);
  return { plugin, marketplace };
}

// ----------------------------------------------------------------- validation

function validateCounts(ruleCount, commandCount) {
  const readme = readFileSync(join(ROOT, 'README.md'), 'utf8');
  // Any numeric claim about rules or commands in the README must be current.
  // Impeccable fails its build on stale counts, and the reason is that a
  // README claiming 120 rules when there are 140 is the first thing a reader
  // checks and the first thing that makes them distrust the rest.
  for (const [, n, noun] of readme.matchAll(/(\d+)\s+(rules|commands)\b/g)) {
    const expected = noun === 'rules' ? ruleCount : commandCount;
    if (Number(n) !== expected) fail(`README claims ${n} ${noun}; there are ${expected}`);
  }
}

function validateOutput(skillOut) {
  for (const file of walk(skillOut).filter((f) => f.endsWith('.md'))) {
    const text = readFileSync(file, 'utf8');
    const rel = relative(ROOT, file);

    // An unresolved placeholder ships to the user verbatim, which reads as a
    // bug in the skill at the moment it is telling them to run something.
    for (const [, name] of text.matchAll(/\{\{\s*([a-z_]+)\s*\}\}/g)) {
      fail(`${rel}: unresolved placeholder {{${name}}}`);
    }
    // A leftover conditional block means a tag was misspelled.
    for (const [, tag] of text.matchAll(/^<\/?(claude-code|claude|cursor|codex|agents|github|gemini)>$/gm)) {
      fail(`${rel}: unprocessed provider block <${tag}>`);
    }
    for (const [, , target] of text.matchAll(/\[([^\]]+)\]\((?!https?:)([^)#]+)(?:#[^)]*)?\)/g)) {
      if (!existsSync(resolve(dirname(file), target))) fail(`${rel}: broken link -> ${target}`);
    }
  }

  const skillMd = join(skillOut, 'SKILL.md');
  const { raw } = splitFrontmatter(readFileSync(skillMd, 'utf8'));
  const data = parseFrontmatter(raw);
  // Codex nests the version under metadata because its validator rejects
  // unknown top-level keys, so accept either shape here.
  const hasVersion = data.version !== undefined || data.metadata !== undefined;
  if (!data.name || !data.description || !hasVersion) {
    fail('generated SKILL.md is missing required frontmatter');
  }
  if ((data.description ?? '').length > 1024) fail(`generated description is ${data.description.length} chars; the cap is 1024`);
  if (existsSync(join(skillOut, 'SKILL.src.md'))) fail('generated output must not contain SKILL.src.md');
}

/** Per-provider invariants that only the provider's own row can tell us. */
function validateProvider(config, result) {
  const skillMd = readFileSync(join(result.skillOut, 'SKILL.md'), 'utf8');
  const { raw } = splitFrontmatter(skillMd);
  const data = parseFrontmatter(raw);

  // A key this loader does not read is either ignored or rejected outright,
  // and rejection breaks the whole skill. Emitting only the allowlist is the
  // conservative side of that trade.
  const allowed = new Set(['name', 'description', 'version', 'metadata', ...config.frontmatterFields]);
  for (const key of Object.keys(data)) {
    if (!allowed.has(key)) fail(`${config.provider}: SKILL.md emits "${key}", which this loader does not read`);
  }
  if (config.versionInMetadata && 'version' in data) {
    fail(`${config.provider}: version must be nested under metadata for this loader`);
  }

  // The command prefix has to reach the output, or the skill tells the user to
  // type a command their harness does not have.
  const prefix = result.placeholders.command_prefix;
  if (!skillMd.includes(`${prefix}airtight hooks`)) {
    fail(`${config.provider}: SKILL.md does not use the "${prefix}" command prefix`);
  }

  if (config.agentFormat === 'none' && existsSync(join(result.outRoot, 'agents'))) {
    fail(`${config.provider}: emits agents but declares agentFormat none`);
  }
  if (config.agentFormat !== 'none' && result.agents === 0) {
    fail(`${config.provider}: declares agentFormat ${config.agentFormat} but emitted no agents`);
  }
  // Every provider gets inline fallbacks, including ones that support
  // sub-agents, because a user can decline them.
  if (!existsSync(join(result.skillOut, 'reference', 'degraded'))) {
    fail(`${config.provider}: no inline fallbacks emitted`);
  }
}

function validateManifests(version, { plugin, marketplace }, pluginManifest) {
  if (plugin.version !== version) fail('.claude-plugin/plugin.json version disagrees with package.json');
  if (marketplace.plugins[0].version !== version) fail('marketplace.json version disagrees with package.json');
  if (pluginManifest.version !== version) fail('plugin/.claude-plugin/plugin.json version disagrees');
  // Declaring `agents` as an array of paths makes some loaders load none.
  if ('agents' in pluginManifest) fail('plugin manifest must not declare an `agents` key');
  if (!pluginManifest.skills.endsWith('/')) fail('plugin manifest `skills` needs a trailing slash');
}

// ----------------------------------------------------------------------- main

function main() {
  const pkg = readJson(join(ROOT, 'package.json'));
  const version = pkg.version;

  if (!existsSync(join(SKILL, 'scripts', 'engine', 'airtight.mjs'))) {
    console.error('build: the engine bundle is missing. Run: npm run build:engine');
    return 1;
  }

  const rules = readJson(join(ROOT, 'engine', 'build', 'rules.json'));
  const commands = Object.keys(readJson(join(SKILL, 'scripts', 'command-metadata.json')));

  rmSync(DIST, { recursive: true, force: true });
  const built = [];
  for (const config of providerList()) {
    const result = transform(SKILL, DIST, config, { version });
    validateOutput(result.skillOut);
    validateProvider(config, result);
    built.push({ config, result });
  }

  const claude = built.find(({ config }) => config.provider === 'claude-code');
  const pluginManifest = stagePlugin(claude.result.outRoot, version, pkg);
  const rootManifests = writeRootManifests(version, pkg);

  validateManifests(version, rootManifests, pluginManifest);
  validateCounts(rules.length, commands.length);

  if (SYNC) {
    for (const { config, result } of built) {
      // Copy the whole provider tree rather than named subdirectories, so
      // commands/, hooks/ and any future sibling arrive without the sync
      // needing to know about them.
      for (const entry of readdirSync(join(DIST, config.provider))) {
        const from = join(DIST, config.provider, entry);
        const to = join(ROOT, entry);
        // Only our own subtrees are replaced. A harness directory can contain
        // the user's own files, and .github in particular holds workflows.
        for (const sub of readdirSync(from)) {
          if (sub === 'skills') {
            rmSync(join(to, sub, 'airtight'), { recursive: true, force: true });
            mkdirSync(join(to, sub), { recursive: true });
            cpSync(join(from, sub, 'airtight'), join(to, sub, 'airtight'), { recursive: true });
          } else {
            rmSync(join(to, sub), { recursive: true, force: true });
            mkdirSync(to, { recursive: true });
            cpSync(from, to, { recursive: true });
          }
        }
      }
    }
  }

  if (errors.length) {
    for (const e of errors) console.error(`build: ${e}`);
    console.error(`build: ${errors.length} error(s)`);
    return 1;
  }

  const tiers = { yes: [], documented: [], convention: [] };
  for (const { config } of built) tiers[config.verified].push(config.configDir);

  console.log(`build: ${built.length} providers, ${commands.length} commands, ${rules.length} rules, v${version}`);
  for (const [tier, dirs] of Object.entries(tiers)) {
    if (dirs.length) console.log(`  ${tier.padEnd(11)} ${dirs.join(' ')}`);
  }
  console.log(`build: dist/ written${SYNC ? ', tracked harness directories synced' : ' (pass --sync to rewrite tracked output)'}`);
  return 0;
}

process.exit(main());
