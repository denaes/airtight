#!/usr/bin/env node
// airtight installer.
//
// Deliberately much smaller than impeccable's equivalent, because airtight has
// no native binary: there is nothing to download, no per-platform packages, no
// checksum sidecars, and no release-ordering gate. npm already provides
// integrity for the one artifact that matters, and the engine is a bundled JS
// file that ships inside this package.
//
// The payload is generated at install time from skill/ rather than shipped
// pre-rendered for every harness, which keeps the package near 1.5MB instead
// of 10MB and means only the harnesses you asked for are ever written.

import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { PROVIDERS, providerList } from '../../scripts/lib/providers.js';
import { transform } from '../../scripts/lib/transform.js';
import { claudeSettings } from '../../scripts/lib/hook-manifests.js';

const PKG_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const pkg = JSON.parse(readFileSync(join(PKG_ROOT, 'package.json'), 'utf8'));
const SKILL = 'airtight';

/**
 * Where a harness looks for globally installed skills. Several honour an
 * environment override; each is only accepted when it resolves inside the
 * user's home directory, because an installer that writes wherever an
 * environment variable points is a privilege escalation waiting to happen.
 */
const GLOBAL_OVERRIDES = {
  deepseek: 'DSH_HOME',
  hermes: 'HERMES_HOME',
  opencode: 'OPENCODE_CONFIG_DIR',
};

export function globalRoot(config, env) {
  const override = GLOBAL_OVERRIDES[config.provider] && env[GLOBAL_OVERRIDES[config.provider]];
  if (override) {
    const abs = resolve(override);
    if (abs === homedir() || abs.startsWith(`${homedir()}/`)) return abs;
    // Refuse rather than silently fall back, so the user knows why.
    console.warn(`airtight: ignoring ${GLOBAL_OVERRIDES[config.provider]}=${override} (outside your home directory)`);
  }
  return join(homedir(), config.configDir);
}

// ------------------------------------------------------------------- detect

/** A harness is present if its directory exists here, or its config exists at home. */
function detect(projectRoot) {
  const project = [];
  const global = [];
  for (const config of providerList()) {
    if (existsSync(join(projectRoot, config.configDir))) project.push(config);
    if (existsSync(join(homedir(), config.configDir))) global.push(config);
  }
  return { project, global };
}

/**
 * The nearest ancestor that looks like a project.
 *
 * An existing harness directory counts, and is checked first: a directory that
 * already has .claude/ or .cursor/ in it is unambiguously where the skill
 * belongs. Without that check, running this from a subdirectory whose parent
 * happens to hold a package.json installs into the parent instead -- which is
 * exactly what happened the first time this was tested against a packed
 * tarball.
 */
function findProjectRoot(start) {
  const harnessDirs = providerList().map((p) => p.configDir);
  let dir = resolve(start);
  for (;;) {
    if (harnessDirs.some((d) => existsSync(join(dir, d)))) return dir;
    if (existsSync(join(dir, '.git')) || existsSync(join(dir, 'package.json'))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return resolve(start);
    dir = parent;
  }
}

// ------------------------------------------------------------------ install

/** Render the requested providers into a temp directory, then place them. */
function stage(configs) {
  const dist = mkdtempSync(join(tmpdir(), 'airtight-install-'));
  const staged = [];
  for (const config of configs) {
    const result = transform(join(PKG_ROOT, 'skill'), dist, config, { version: pkg.version });
    staged.push({ config, result, root: join(dist, config.provider) });
  }
  return { dist, staged };
}

/**
 * Merge the hook manifest into a settings file the user also owns, replacing
 * only our own entries. Clobbering someone's hooks to install ours would be a
 * worse failure than not installing at all.
 */
function mergeClaudeSettings(target, configDir) {
  const path = join(target, 'settings.json');
  let settings = {};
  if (existsSync(path)) {
    try { settings = JSON.parse(readFileSync(path, 'utf8')); } catch {
      console.warn(`airtight: ${path} is not valid JSON; leaving it alone and skipping the hook`);
      return false;
    }
  }
  settings.hooks ??= {};
  const isOurs = (e) => JSON.stringify(e).includes(SKILL);
  for (const [event, entries] of Object.entries(claudeSettings(configDir))) {
    settings.hooks[event] = [...(settings.hooks[event] ?? []).filter((e) => !isOurs(e)), ...entries];
  }
  mkdirSync(target, { recursive: true });
  writeFileSync(path, `${JSON.stringify(settings, null, 2)}\n`);
  return true;
}

function place(staged, destRoot, { scope, withHooks }) {
  const placed = [];
  for (const { config, root } of staged) {
    for (const entry of readdirSync(root)) {
      const from = join(root, entry);
      // Global installs land in ~/<configDir>/..., so the config dir is the
      // destination itself rather than a child of it.
      const to = scope === 'global' && entry === config.configDir
        ? globalRoot(config, process.env)
        : join(destRoot, entry);

      for (const sub of readdirSync(from)) {
        // Replace only the subtrees we own. A harness directory holds the
        // user's own files, and .github holds their workflows.
        const subFrom = join(from, sub);
        if (!withHooks && (sub === 'hooks' || sub === 'hooks.json')) continue;
        rmSync(join(to, sub), { recursive: true, force: true });
        mkdirSync(to, { recursive: true });
        cpSync(subFrom, join(to, sub), { recursive: true });
      }
    }

    if (withHooks && config.hooks === 'claude-settings') {
      const target = scope === 'global' ? globalRoot(config, process.env) : join(destRoot, config.configDir);
      mergeClaudeSettings(target, config.configDir);
    }
    placed.push(config);
  }
  return placed;
}

// ---------------------------------------------------------------------- cli

function parse(argv) {
  const opts = { cmd: argv[0] ?? 'help', providers: null, scope: null, yes: false, hooks: true };
  for (const a of argv.slice(1)) {
    if (a === '--yes' || a === '-y') opts.yes = true;
    else if (a === '--no-hooks') opts.hooks = false;
    else if (a.startsWith('--providers=')) opts.providers = a.slice(12).split(',').map((s) => s.trim()).filter(Boolean);
    else if (a.startsWith('--scope=')) opts.scope = a.slice(8);
    else if (a === '--global') opts.scope = 'global';
    else if (a === '--project') opts.scope = 'project';
    else throw new Error(`unknown option: ${a}`);
  }
  return opts;
}

const ENGINE_VERBS = new Set([
  'detect', 'rules', 'map', 'correlate', 'mcp', 'findings', 'controls', 'context',
  'hook', 'hooks', 'engine-probe', 'sbom',
]);

function findEngine() {
  const candidates = [
    process.env.AIRTIGHT_ENGINE,
    join(PKG_ROOT, 'skill', 'scripts', 'engine', 'airtight.mjs'),
    join(PKG_ROOT, 'engine', 'src', 'cli.mjs'),
  ].filter(Boolean);
  return candidates.find((p) => existsSync(p));
}

function resolveRuleBundle() {
  if (process.env.AIRTIGHT_RULES && existsSync(process.env.AIRTIGHT_RULES)) return process.env.AIRTIGHT_RULES;
  const candidates = [
    join(PKG_ROOT, 'skill', 'scripts', 'rules.json'),
    join(PKG_ROOT, 'engine', 'build', 'rules.json'),
    join(PKG_ROOT, 'engine', 'rules.json'),
  ];
  return candidates.find((p) => existsSync(p));
}

async function runEngine(argv) {
  const enginePath = findEngine();
  if (!enginePath) {
    console.error('airtight: engine not found. Run npm run build or reinstall the package.');
    return 1;
  }
  const rulesPath = resolveRuleBundle();
  if (rulesPath && !process.env.AIRTIGHT_RULES) {
    process.env.AIRTIGHT_RULES = rulesPath;
  }
  const mod = await import(pathToFileURL(enginePath).href);
  return mod.run(argv);
}

const USAGE = `airtight ${pkg.version} — security guidance for AI coding agents

Harness management
  npx airtight install      install the skill into this project or globally
  npx airtight update       refresh an existing install in place
  npx airtight check        report what is installed and whether it is current
  npx airtight uninstall    remove the skill from detected harnesses

Analysis and posture
  npx airtight detect [paths]   scan for security findings (default: .)
  npx airtight rules            list loaded rules
  npx airtight map [paths]      map HTTP entry points and nearby sinks
  npx airtight correlate [paths] correlate IaC exposure with application sinks
  npx airtight mcp              start Model Context Protocol (MCP) stdio server
  npx airtight sbom [paths]     generate CycloneDX 1.5 SBOM from lockfiles
  npx airtight findings <sub>   sync | list | accept | overdue
  npx airtight controls <sub>   verify | coverage
  npx airtight context          project truth and session directives
  npx airtight hooks <sub>      on | off | status

Installer options
  --providers=a,b   choose harnesses explicitly (skips detection)
  --scope=project   install into ./<harness dir>   (default when one is present)
  --scope=global    install into ~/<harness dir>
  --no-hooks        skip the edit hook
  --yes, -y         accept the detected set without asking

Harnesses: ${providerList().map((p) => p.provider).join(', ')}
`;

function resolveProviders(names) {
  const chosen = [];
  for (const name of names) {
    const config = PROVIDERS[name] ?? providerList().find((p) => p.configDir === name || p.configDir === `.${name}`);
    if (!config) throw new Error(`unknown harness "${name}". Known: ${Object.keys(PROVIDERS).join(', ')}`);
    chosen.push(config);
  }
  return chosen;
}

async function confirm(question) {
  if (!process.stdin.isTTY) return true;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = (await rl.question(`${question} [Y/n] `)).trim().toLowerCase();
    return answer === '' || answer === 'y' || answer === 'yes';
  } finally {
    rl.close();
  }
}

const label = (c) => `${c.display} (${c.configDir})${c.verified === 'convention' ? ' [untested]' : ''}`;

async function install(opts, { update = false } = {}) {
  const projectRoot = findProjectRoot(process.cwd());
  const found = detect(projectRoot);

  let configs;
  let scope = opts.scope;

  if (opts.providers) {
    configs = resolveProviders(opts.providers);
    scope ??= 'project';
  } else {
    // Prefer whatever is already here; a harness directory in the project is
    // a much stronger signal than one in the home directory.
    if (found.project.length) { configs = found.project; scope ??= 'project'; }
    else if (found.global.length) { configs = found.global; scope ??= 'global'; }
    else {
      console.error('airtight: no AI harness detected here or in your home directory.');
      console.error('  Pass one explicitly, for example: npx airtight install --providers=claude-code');
      return 1;
    }
  }

  console.log(`airtight ${pkg.version}`);
  console.log(`  ${update ? 'updating' : 'installing'} into ${scope === 'global' ? homedir() : projectRoot}`);
  for (const c of configs) console.log(`  - ${label(c)}`);
  if (configs.some((c) => c.verified === 'convention')) {
    console.log('  [untested] harnesses follow the common skill layout but have not been verified end to end.');
  }

  if (!opts.yes && !update && !(await confirm('Proceed?'))) {
    console.log('airtight: nothing written.');
    return 0;
  }

  const { dist, staged } = stage(configs);
  try {
    const placed = place(staged, projectRoot, { scope, withHooks: opts.hooks });
    console.log(`airtight: ${update ? 'updated' : 'installed'} for ${placed.length} harness(es).`);
    if (opts.hooks) {
      const hooked = placed.filter((c) => c.hooks);
      if (hooked.length) console.log(`  edit hook wired for: ${hooked.map((c) => c.display).join(', ')}`);
      const unhooked = placed.filter((c) => !c.hooks);
      if (unhooked.length) console.log(`  no hook surface on: ${unhooked.map((c) => c.display).join(', ')}`);
    }
    console.log('  reload your harness, then run: /airtight init');
    return 0;
  } finally {
    rmSync(dist, { recursive: true, force: true });
  }
}

function check() {
  const projectRoot = findProjectRoot(process.cwd());
  let any = false;
  console.log(`airtight ${pkg.version} — installed skills`);

  for (const scope of ['project', 'global']) {
    for (const config of providerList()) {
      const base = scope === 'global' ? globalRoot(config, process.env) : join(projectRoot, config.configDir);
      const skill = join(base, 'skills', SKILL);
      const versionFile = join(skill, 'scripts', 'VERSION');
      if (!existsSync(versionFile)) continue;
      any = true;
      const installed = readFileSync(versionFile, 'utf8').trim();
      const current = installed === pkg.version;
      const hookFile = config.hooks === 'claude-settings' ? join(base, 'settings.json') : null;
      const hooked = hookFile && existsSync(hookFile) && readFileSync(hookFile, 'utf8').includes(SKILL);
      console.log(`  ${current ? 'ok  ' : 'OLD '} ${scope.padEnd(8)} ${config.configDir.padEnd(10)} v${installed}${hooked ? '  hook' : ''}`);
    }
  }

  if (!any) { console.log('  nothing installed. Run: npx airtight install'); return 1; }
  return 0;
}

function uninstall() {
  const projectRoot = findProjectRoot(process.cwd());
  let removed = 0;
  for (const config of providerList()) {
    const skill = join(projectRoot, config.configDir, 'skills', SKILL);
    if (!existsSync(skill)) continue;
    rmSync(skill, { recursive: true, force: true });
    // Agent files are named, so they can be removed precisely rather than by
    // clearing a directory the user may also use.
    const agentDir = join(projectRoot, config.configDir, config.agentDir ?? 'agents');
    if (existsSync(agentDir)) {
      for (const f of readdirSync(agentDir)) {
        if (f.startsWith('airtight')) rmSync(join(agentDir, f), { recursive: true, force: true });
      }
      if (readdirSync(agentDir).length === 0) rmSync(agentDir, { recursive: true, force: true });
    }
    console.log(`airtight: removed from ${config.configDir}`);
    removed += 1;
  }
  if (!removed) { console.log('airtight: nothing to remove here.'); return 1; }
  console.log('airtight: hook manifests were left in place; remove them by hand if you had any.');
  return 0;
}

async function main() {
  const argv = process.argv.slice(2);
  const verb = argv[0];

  if (verb && ENGINE_VERBS.has(verb)) {
    return await runEngine(argv);
  }

  let opts;
  try { opts = parse(argv); } catch (err) {
    console.error(`airtight: ${err.message}`);
    return 1;
  }

  try {
    switch (opts.cmd) {
      case 'install': return await install(opts);
      case 'update': return await install({ ...opts, yes: true }, { update: true });
      case 'check': case 'doctor': return check();
      case 'uninstall': case 'remove': return uninstall();
      case 'help': case '--help': case '-h': console.log(USAGE); return 0;
      case 'version': case '--version': case '-v': console.log(pkg.version); return 0;
      default:
        console.error(`airtight: unknown command "${opts.cmd}"\n\n${USAGE}`);
        return 1;
    }
  } catch (err) {
    console.error(`airtight: ${err.message}`);
    return 1;
  }
}

/**
 * Only run when invoked directly. Without this guard, importing the module to
 * unit-test a helper executes the installer and exits the importing process --
 * which is how the test suite lost nine tests without failing.
 *
 * Compared via realpath, for the same reason the engine does: argv[1] keeps
 * the path as typed while import.meta.url is resolved, so the naive
 * `file://${process.argv[1]}` comparison is false behind any symlink.
 */
function isEntryPoint() {
  if (!process.argv[1]) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (isEntryPoint()) process.exit(await main());
