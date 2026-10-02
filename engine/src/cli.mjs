#!/usr/bin/env node
// airtight engine entry point.
//
// Exit codes are the contract, because CI and the edit hook both read them:
//   0  clean
//   1  the engine itself failed
//   2  findings present, or a control is failing
//
// Every verb returns a code; nothing here calls process.exit except main, so
// the engine stays testable in-process.

import { execFileSync } from 'node:child_process';
import { readFileSync, realpathSync, statSync, readdirSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compileAll, immediateTier } from './rules.mjs';
import { collectTargets, scanFiles } from './scan.mjs';
import { loadConfig, buildFilter, loadCustomRules, applySeverityOverrides } from './config.mjs';
import { renderJson, renderText } from './render.mjs';
import { renderSarif } from './render-sarif.mjs';
import { generateCycloneDx } from './sbom.mjs';
import { detectLockfiles, parseLockfile } from './lockfile.mjs';
import { queryOsv } from './osv.mjs';
import * as store from './store.mjs';
import { buildContext } from './context.mjs';
import { runHook, readStdin } from './hook.mjs';
import * as hooks from './hooks-admin.mjs';
import { loadControls, verifyControls, frameworkCoverage, frameworksIn } from './controls.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const VERSION = '0.4.1';

const USAGE = `airtight ${VERSION} — deterministic security rule engine

  airtight detect [paths...]        scan for security findings (default: .)
  airtight rules                    list loaded rules
  airtight findings <sub>           sync | list | accept | overdue
  airtight controls <sub>           verify | coverage
  airtight context                  project truth and session directives
  airtight sbom [paths...]          generate CycloneDX 1.5 SBOM from lockfiles
  airtight hook                     edit-hook entry point (reads stdin)
  airtight hooks <sub>              on | off | status | ignore-rule | ignore-file | ignore-value
  airtight engine-probe             launcher handshake

Options
  --format <type>        output format: text, json, sarif (default: text)
  --json                 machine-readable output (alias for --format json)
  --tier immediate       only the rules the edit hook may interrupt on
  --pack <name>          restrict to one rule pack (repeatable)
  --count-by-pack        display rule counts broken down by pack
  --baseline <path>      report only findings not present in baseline file
  --since <git-ref>      limit scan to files modified since git-ref
  --no-config            ignore .airtight/config.json suppressions
  --status <status>      filter findings by status
  --framework <name>     project controls onto one compliance framework
  --reason <text>        required when waiving a finding
  --file <glob>          scope a value waiver to paths (repeatable)
  --fingerprint <hex>    waive a redacted finding by its fingerprint
`;

function checkStaleRules(bundlePath) {
  try {
    const rulesDir = join(HERE, '..', 'rules');
    if (!existsSync(rulesDir)) return;
    const bundleStat = statSync(bundlePath);
    const yamlFiles = readdirSync(rulesDir).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'));
    for (const f of yamlFiles) {
      const yamlStat = statSync(join(rulesDir, f));
      if (yamlStat.mtimeMs > bundleStat.mtimeMs) {
        process.stderr.write(
          `[airtight warning] rule source 'engine/rules/${f}' is newer than compiled bundle '${bundlePath}'. Run: npm run build:rules\n`
        );
        break;
      }
    }
  } catch {
    // Fail open on stat errors
  }
}

function loadRules(env) {
  const candidates = [
    env.AIRTIGHT_RULES,
    join(HERE, '..', 'rules.json'),
    join(HERE, '..', 'build', 'rules.json'),
  ].filter(Boolean);

  for (const path of candidates) {
    try {
      const data = JSON.parse(readFileSync(path, 'utf8'));
      checkStaleRules(path);
      return compileAll(data);
    } catch (err) {
      if (err?.code !== 'ENOENT') throw err;
    }
  }
  throw new Error(`no compiled rule bundle found (looked in: ${candidates.join(', ')}). Run: npm run build:rules`);
}

const FLAGS_WITH_VALUES = new Set([
  '--tier', '--pack', '--status', '--framework', '--reason', '--approver',
  '--expires', '--fingerprint', '--baseline', '--since', '--format',
]);

function getChangedFilesSince(root, ref) {
  try {
    const diffOut = execFileSync('git', ['diff', '--name-only', '--diff-filter=ACMR', ref], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const untrackedOut = execFileSync('git', ['ls-files', '--others', '--exclude-standard'], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const set = new Set(
      `${diffOut}\n${untrackedOut}`
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)
        .map((p) => resolve(root, p))
        .filter((p) => {
          try { return statSync(p).isFile(); } catch { return false; }
        })
    );
    return [...set];
  } catch (err) {
    const msg = err.stderr ? err.stderr.toString().trim() : err.message;
    throw new Error(`git diff failed for --since "${ref}": ${msg}`);
  }
}

function parseArgs(argv) {
  const opts = { json: false, format: null, tier: null, packs: [], useConfig: true, paths: [], flags: {} };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--json') { opts.json = true; opts.format = 'json'; }
    else if (a === '--format') opts.format = argv[++i];
    else if (a === '--no-config') opts.useConfig = false;
    else if (a === '--pack') opts.packs.push(argv[++i]);
    else if (a === '--count-by-pack') opts.flags['count-by-pack'] = true;
    else if (a === '--file') (opts.files ??= []).push(argv[++i]);
    else if (a === '--tier') opts.tier = argv[++i];
    else if (FLAGS_WITH_VALUES.has(a)) opts.flags[a.slice(2)] = argv[++i];
    else if (a.startsWith('--')) throw new Error(`unknown option: ${a}`);
    else opts.paths.push(a);
  }
  return opts;
}

/** One scan, shared by detect, findings sync, and controls verify. */
function runScan(opts, env, { defaultPaths = ['.'] } = {}) {
  const root = process.cwd();
  let rules = loadRules(env);

  const config = opts.useConfig ? loadConfig(root) : { detector: {} };
  const isSuppressed = opts.useConfig ? buildFilter(config) : null;

  if (opts.useConfig && config.rulePaths?.length > 0) {
    try {
      const customRules = loadCustomRules(root, config);
      rules = [...rules, ...customRules];
    } catch (err) {
      process.stderr.write(`[airtight warning] loading custom rulePaths failed: ${err.message}\n`);
    }
  }

  const allRuleIds = new Set(rules.map((r) => r.id));

  if (opts.tier === 'immediate') rules = immediateTier(rules);
  if (opts.packs.length) rules = rules.filter((r) => opts.packs.includes(r.pack));

  let files;
  if (opts.flags.since) {
    const changed = getChangedFilesSince(root, opts.flags.since);
    if (opts.paths.length) {
      const targetPaths = opts.paths.map((p) => resolve(root, p));
      files = changed.filter((f) => targetPaths.some((t) => f === t || f.startsWith(t.endsWith('/') ? t : `${t}/`)));
    } else {
      files = changed;
    }
  } else {
    const paths = opts.paths.length ? opts.paths : defaultPaths;
    files = collectTargets(root, paths.map((p) => resolve(root, p)));
  }

  const scanned = scanFiles({ root, files, rules, config, isSuppressed });
  let findings = scanned.findings;

  if (opts.tier !== 'immediate' && (!opts.packs.length || opts.packs.includes('dep'))) {
    try {
      const lockfiles = detectLockfiles(root);
      const allDeps = [];
      for (const lf of lockfiles) {
        try {
          const content = readFileSync(lf, 'utf8');
          const parsed = parseLockfile(lf, content);
          if (parsed?.dependencies?.length) {
            allDeps.push(...parsed.dependencies);
          }
        } catch {}
      }
      if (allDeps.length > 0) {
        const advisories = queryOsv(allDeps, {
          cacheDir: join(root, '.airtight', 'cache', 'osv.json'),
          offline: false,
        });
        for (const adv of advisories) {
          if (!isSuppressed || !isSuppressed(adv)) {
            findings.push(adv);
          }
        }
      }
    } catch {
      // OSV fail-open guarantee
    }
  }

  if (opts.useConfig && config.severityOverrides && Object.keys(config.severityOverrides).length > 0) {
    findings = applySeverityOverrides(findings, config.severityOverrides);
  }

  let baselineIgnored = 0;

  if (opts.flags.baseline) {
    const baselineIds = store.loadBaseline(resolve(root, opts.flags.baseline));
    const totalBefore = findings.length;
    findings = store.filterBaseline(findings, baselineIds);
    baselineIgnored = totalBefore - findings.length;
  }

  return {
    ...scanned,
    findings,
    root,
    allRuleIds,
    rules,
    meta: {
      filesScanned: files.length - scanned.skipped.length,
      rulesApplied: rules.length,
      ...(baselineIgnored > 0 ? { baselineIgnored } : {}),
    },
  };
}

function cmdDetect(argv, io, env) {
  const opts = parseArgs(argv);
  const format = opts.format || (opts.json ? 'json' : 'text');
  if (format !== 'text' && format !== 'json' && format !== 'sarif') {
    throw new Error(`unknown output format: "${format}" (expected: text, json, sarif)`);
  }
  const { findings, vault, meta, rules } = runScan(opts, env);
  if (format === 'sarif') {
    io.out(renderSarif({ findings, vault, meta, rules, version: VERSION }));
  } else if (format === 'json') {
    io.out(renderJson({ findings, vault, meta }));
  } else {
    io.out(renderText({ findings, vault, meta }));
  }
  return findings.length > 0 ? 2 : 0;
}

function cmdRules(argv, io, env) {
  const opts = parseArgs(argv);
  let rules = loadRules(env);
  if (opts.packs.length) rules = rules.filter((r) => opts.packs.includes(r.pack));
  if (opts.flags['count-by-pack']) {
    const counts = {};
    for (const r of rules) counts[r.pack] = (counts[r.pack] ?? 0) + 1;
    if (opts.json) {
      io.out(JSON.stringify(counts, null, 2));
    } else {
      for (const [pack, count] of Object.entries(counts).sort()) {
        io.out(`${pack.padEnd(16)} ${count}`);
      }
      io.out(`\ntotal: ${rules.length}`);
    }
    return 0;
  }
  if (opts.json) { io.out(JSON.stringify(rules.map(stripCompiled), null, 2)); return 0; }
  for (const r of rules) {
    io.out(`${r.id.padEnd(40)} ${`${r.severity}/${r.confidence}`.padEnd(20)} ${r.tier.padEnd(9)} ${r.name}`);
  }
  io.out(`\n${rules.length} rule(s).`);
  return 0;
}

const stripCompiled = ({ re, notRe, requireRe, ...rest }) => rest;

// ----------------------------------------------------------------- findings

function cmdFindings(argv, io, env) {
  const [sub, ...rest] = argv;
  const opts = parseArgs(rest);
  const root = process.cwd();

  switch (sub) {
    case 'sync': {
      const { findings, vault } = runScan(opts, env);
      const { records, events } = store.reconcile(store.load(root), findings);
      const written = store.save(root, records);

      // Scrub even here. Records carry titles and locations rather than
      // values, but the vault is cheap and the guarantee should not depend on
      // remembering which fields are safe.
      if (opts.json) { io.out(vault.scrub(JSON.stringify({ events, total: written }, null, 2))); }
      else {
        io.out(`airtight: ${written} finding(s) tracked in ${store.STORE_PATH}`);
        io.out(`  new ${events.added} · regressed ${events.regressed} · fixed ${events.fixed}`
          + ` · unchanged ${events.unchanged} · waivers expired ${events.waiverExpired}`);
      }
      return events.added + events.regressed > 0 ? 2 : 0;
    }

    case 'list': {
      const records = [...store.load(root).values()]
        .filter((r) => !opts.flags.status || r.status === opts.flags.status)
        .sort((a, b) => a.severity.localeCompare(b.severity) || a.id.localeCompare(b.id));
      if (opts.json) { io.out(JSON.stringify(records, null, 2)); return 0; }
      for (const r of records) {
        io.out(`${r.id}  ${r.status.padEnd(9)} ${`${r.severity}/${r.confidence}`.padEnd(20)} ${r.location}`);
        io.out(`             ${r.rule} — ${r.title}`);
      }
      const s = store.summarize(store.load(root));
      io.out(`\n${s.total} tracked: ${Object.entries(s.byStatus).map(([k, v]) => `${v} ${k}`).join(', ') || 'none'}`);
      return 0;
    }

    case 'accept': {
      const [id] = opts.paths;
      if (!id) throw new Error('usage: airtight findings accept <id> --reason "..." --approver "..."');
      const config = opts.useConfig ? loadConfig(root) : {};
      const next = store.accept(store.load(root), id, {
        reason: opts.flags.reason,
        approver: opts.flags.approver,
        expires: opts.flags.expires,
        waiverPolicy: config.waiverPolicy,
      });
      store.save(root, next);
      io.out(`airtight: ${id} accepted by ${opts.flags.approver}`
        + (opts.flags.expires ? ` until ${opts.flags.expires}` : ' with no expiry'));
      if (!opts.flags.expires) {
        io.err('airtight: this acceptance has no expiry, so nothing will ever bring it back for review');
      }
      return 0;
    }

    case 'overdue': {
      const late = store.overdue(store.load(root));
      if (opts.json) { io.out(JSON.stringify(late, null, 2)); return late.length ? 2 : 0; }
      for (const r of late) io.out(`${r.id}  ${r.severity.padEnd(8)} due ${r.due.slice(0, 10)}  ${r.location}  ${r.rule}`);
      io.out(`\n${late.length} finding(s) past their remediation deadline.`);
      return late.length ? 2 : 0;
    }

    default:
      io.err('usage: airtight findings <sync|list|accept|overdue>');
      return 1;
  }
}

// ------------------------------------------------------------------ context

function cmdContext(argv, io, env) {
  const root = process.cwd();
  let ruleIds = new Set();
  try { ruleIds = new Set(loadRules(env).map((r) => r.id)); } catch { /* context still useful without rules */ }
  io.out(buildContext(root, { ruleIds }));
  return 0;
}

// -------------------------------------------------------------------- hooks

function cmdHooks(argv, io, env) {
  const [sub, ...rest] = argv;
  const opts = parseArgs(rest);
  const root = env.CLAUDE_PROJECT_DIR || process.cwd();

  switch (sub) {
    case 'on':
      io.out(`airtight: hook installed in ${hooks.install(root)}`);
      hooks.setEnabled(root, true);
      io.out('  PostToolUse runs the immediate tier after each edit; Stop runs every rule over the session.');
      return 0;

    case 'off':
      hooks.setEnabled(root, false);
      io.out('airtight: hook disabled in .airtight/config.json (the manifest is left in place; use `uninstall` to remove it)');
      return 0;

    case 'uninstall': {
      const path = hooks.uninstall(root);
      io.out(path ? `airtight: hook removed from ${path}` : 'airtight: no hook manifest found');
      return 0;
    }

    case 'status': {
      const s = hooks.status(root);
      if (opts.json) { io.out(JSON.stringify(s, null, 2)); return 0; }
      io.out(`installed: ${s.installed}${s.events.length ? ` (${s.events.join(', ')})` : ''}`);
      io.out(`enabled:   ${s.enabled}`);
      io.out(`limits:    ${JSON.stringify(s.limits)}`);
      io.out(`waivers:   ${s.suppressions.ignoreValues} value, ${s.suppressions.ignoreFiles.length} file, ${s.suppressions.ignoreRules.length} rule`);
      return 0;
    }

    case 'ignore-value': {
      const [rule, value] = opts.paths;
      io.out(`airtight: waiver added to ${hooks.ignoreValue(root, {
        rule, value, fingerprint: opts.flags.fingerprint, files: opts.files, reason: opts.flags.reason,
      })}`);
      return 0;
    }

    case 'ignore-file':
      io.out(`airtight: ${hooks.ignoreFile(root, opts.paths[0])} updated`);
      io.err(hooks.ESCALATION_NOTICE);
      return 0;

    case 'ignore-rule':
      io.out(`airtight: ${hooks.ignoreRule(root, opts.paths[0])} updated`);
      io.err(hooks.ESCALATION_NOTICE);
      return 0;

    default:
      io.err('usage: airtight hooks <on|off|uninstall|status|ignore-value|ignore-file|ignore-rule>');
      return 1;
  }
}

// ----------------------------------------------------------------- controls

function cmdControls(argv, io, env) {
  const [sub, ...rest] = argv;
  const opts = parseArgs(rest);
  const root = process.cwd();
  const { controls } = loadControls(root);

  if (controls.length === 0) {
    io.err(`airtight: no controls declared in ${'.airtight/controls.json'}`);
    return 1;
  }

  const { findings, allRuleIds } = runScan(opts, env);
  const results = verifyControls(controls, findings, allRuleIds);

  if (sub === 'coverage') {
    const framework = opts.flags.framework;
    if (!framework) {
      io.out(`frameworks declared: ${frameworksIn(controls).join(', ') || 'none'}`);
      return 0;
    }
    const coverage = frameworkCoverage(controls, framework, results);
    if (opts.json) { io.out(JSON.stringify(coverage, null, 2)); }
    else {
      for (const c of coverage) {
        io.out(`${c.satisfied ? 'ok  ' : 'GAP '} ${c.reference.padEnd(12)} ${c.controls.map((x) => `${x.control} (${x.status}/${x.verdict})`).join(', ')}`);
      }
      const gaps = coverage.filter((c) => !c.satisfied).length;
      io.out(`\n${coverage.length} ${framework} reference(s), ${gaps} with a gap.`);
    }
    return coverage.some((c) => !c.satisfied) ? 2 : 0;
  }

  if (sub !== 'verify') { io.err('usage: airtight controls <verify|coverage>'); return 1; }

  if (opts.json) { io.out(JSON.stringify(results, null, 2)); }
  else {
    for (const r of results) {
      const mark = { holding: 'ok  ', failing: 'FAIL', unverifiable: '??  ', broken: 'ERR ' }[r.verdict];
      io.out(`${mark} ${r.id.padEnd(28)} ${r.reason}`);
      for (const f of r.failures) io.out(`       ${f.at}  ${f.rule} (${f.severity})`);
    }
    const failing = results.filter((r) => r.verdict === 'failing').length;
    const broken = results.filter((r) => r.verdict === 'broken').length;
    const unverifiable = results.filter((r) => r.verdict === 'unverifiable').length;
    io.out(`\n${results.length} control(s): ${results.length - failing - broken - unverifiable} holding,`
      + ` ${failing} failing, ${unverifiable} unverifiable, ${broken} broken.`);
  }
  return results.some((r) => r.verdict === 'failing' || r.verdict === 'broken') ? 2 : 0;
}

function cmdSbom(argv, io, env) {
  const opts = parseArgs(argv);
  const root = process.cwd();
  const target = opts.paths.length ? resolve(root, opts.paths[0]) : root;
  const sbom = generateCycloneDx({ root: target });
  io.out(sbom);
  return 0;
}

export function run(argv, io = defaultIo(), env = process.env) {
  const [verb, ...rest] = argv;
  try {
    switch (verb) {
      case undefined:
      case '--help':
      case '-h':
      case 'help': io.out(USAGE); return 0;
      case '--version':
      case '-v': io.out(VERSION); return 0;
      case 'engine-probe': io.out(`airtight-engine ${VERSION}`); return 0;
      case 'detect': return cmdDetect(rest, io, env);
      case 'rules': return cmdRules(rest, io, env);
      case 'findings': return cmdFindings(rest, io, env);
      case 'context': return cmdContext(rest, io, env);
      case 'sbom': return cmdSbom(rest, io, env);
      case 'hook': return runHook(io, env, readStdin());
      case 'hooks': return cmdHooks(rest, io, env);
      case 'controls': return cmdControls(rest, io, env);
      default:
        io.err(`airtight: unknown command "${verb}"\n\n${USAGE}`);
        return 1;
    }
  } catch (err) {
    io.err(`airtight: ${err.message}`);
    return 1;
  }
}

function defaultIo() {
  return {
    out: (s) => process.stdout.write(`${s}\n`),
    err: (s) => process.stderr.write(`${s}\n`),
  };
}

/**
 * Entry-point detection, via realpath.
 *
 * The idiomatic `import.meta.url === \`file://${process.argv[1]}\`` is wrong
 * the moment the invocation path crosses a symlink: argv[1] keeps the path as
 * typed while import.meta.url is resolved. /tmp on macOS is a symlink to
 * /private/tmp, /home is often a symlink to /Users, and plenty of people keep
 * their projects behind one.
 *
 * The failure mode is the worst available: the module loads, nothing runs, and
 * the process exits 0. The launcher succeeds, the hook reports no findings,
 * and the user concludes the code is clean. Compare resolved paths.
 */
function isEntryPoint() {
  if (!process.argv[1]) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

if (isEntryPoint()) {
  process.exit(run(process.argv.slice(2)));
}
