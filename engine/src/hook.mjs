// The edit hook.
//
// One verb, two events, routed by the shape of stdin rather than by argv, so a
// single manifest entry covers both. Always exits 0 unless it is deliberately
// blocking, and any internal failure exits 0 silently: a broken detector must
// never stop someone from working.

import { readFileSync, writeFileSync, mkdirSync, statSync, realpathSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { compileAll, immediateTier } from './rules.mjs';
import { scanFiles } from './scan.mjs';
import { loadConfig, buildFilter } from './config.mjs';
import { matchesAny } from './glob.mjs';

export const ENVELOPE = '[airtight@1]';
const CACHE_PATH = '.airtight/hook.cache.json';
const MAX_SESSIONS = 8;
const MAX_EDITS_PER_FILE = 6;
const STOP_MAX_FILES = 20;

/**
 * Files worth scanning on an edit. Deliberately generous on config and
 * manifests, because that is where the highest-confidence findings live, and
 * deliberately not "everything", because a hook that fires on a changelog
 * teaches people to stop reading it.
 */
const SCANNABLE_EXT = new Set([
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.go', '.rb', '.java',
  '.php', '.cs', '.sh', '.bash', '.tf', '.tfvars', '.yaml', '.yml', '.json',
  '.toml', '.ini', '.conf', '.env', '.pem', '.key', '.properties', '.mk',
]);

const SCANNABLE_NAME = /^(Dockerfile|Containerfile|Makefile|justfile|go\.mod|go\.sum|\.npmrc|\.yarnrc|\.env|\.env\..*|pip\.conf|pip\.ini|requirements.*\.txt)$/;

const GENERATED = /(^|\/)(node_modules|dist|build|out|\.next|\.nuxt|coverage|vendor|target|__pycache__|\.terraform)\//;
const GENERATED_FILE = /\.(min\.(js|css)|d\.ts|map)$/;

// ------------------------------------------------------------------ harness

/** Identified by envelope shape, because each harness spells the same event differently. */
export function resolveHarness(input, env) {
  if (env.AIRTIGHT_HOOK_HARNESS) return env.AIRTIGHT_HOOK_HARNESS;
  if (input.conversation_id) return 'cursor';
  if (input.toolName || input.toolArgs) return 'github';
  if (input.turn_id) return 'codex';
  return 'claude';
}

export function isStopEvent(input) {
  const name = input.hook_event_name ?? input.hookEventName ?? input.event ?? '';
  return /stop/i.test(String(name));
}

/**
 * The only writer of stdout. Five harness contracts in twenty lines; everything
 * upstream produces plain text and never has to know which one it is talking to.
 */
export function payload(text, eventName, harness) {
  if (!text) return '';
  if (harness === 'cursor') return JSON.stringify({ additional_context: text });
  if (harness === 'github') return JSON.stringify({ additionalContext: text });
  if (harness === 'codex' && eventName === 'Stop') {
    return JSON.stringify({ decision: 'block', reason: text });
  }
  return JSON.stringify({ hookSpecificOutput: { hookEventName: eventName, additionalContext: text } });
}

// -------------------------------------------------------------------- cache

function loadCache(root) {
  try {
    return JSON.parse(readFileSync(join(root, CACHE_PATH), 'utf8'));
  } catch {
    return { sessions: {} };
  }
}

function saveCache(root, cache) {
  // Never create .airtight/ just to cache. A project that has not opted in
  // should not acquire state because a hook fired once.
  try {
    if (!statSync(join(root, '.airtight')).isDirectory()) return;
  } catch {
    return;
  }
  const ids = Object.keys(cache.sessions);
  if (ids.length > MAX_SESSIONS) {
    for (const id of ids.slice(0, ids.length - MAX_SESSIONS)) delete cache.sessions[id];
  }
  try {
    mkdirSync(dirname(join(root, CACHE_PATH)), { recursive: true });
    writeFileSync(join(root, CACHE_PATH), JSON.stringify(cache));
  } catch { /* caching is best effort */ }
}

const sessionOf = (cache, id) => (cache.sessions[id] ??= { files: {}, edits: {}, footerShown: false, cleanAcked: [] });

/** Identity within a session: the same finding must not be reported twice. */
const cacheKey = (f) => `${f.rule}:${f.line}:${f.valueFingerprint ?? f.snippet.slice(0, 60)}`;

// ------------------------------------------------------------------ targets

export function resolveTargets(input) {
  const ti = input.tool_input ?? input.toolInput ?? input.toolArgs ?? {};
  const paths = [ti.file_path, ti.path, ti.filePath, input.file_path].filter(Boolean);

  // Codex-style patch commands name their files inside the command text.
  const cmd = ti.command ?? '';
  for (const m of String(cmd).matchAll(/\*\*\* (?:Update|Add) File: (.+)/g)) paths.push(m[1].trim());

  return [...new Set(paths)];
}

function isScannable(rel) {
  const base = rel.slice(rel.lastIndexOf('/') + 1);
  if (SCANNABLE_NAME.test(base)) return true;
  const dot = base.lastIndexOf('.');
  return dot > 0 && SCANNABLE_EXT.has(base.slice(dot));
}

function insideProject(root, abs) {
  try {
    const realRoot = realpathSync(root);
    let probe = abs;
    for (;;) {
      try { return realpathSync(probe).startsWith(realRoot); } catch { /* walk up */ }
      const parent = dirname(probe);
      if (parent === probe) return false;
      probe = parent;
    }
  } catch {
    return false;
  }
}

// ----------------------------------------------------------------- findings

function renderFindings(findings, { multiFile, showFooter, total }) {
  const lines = [];
  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }

  const where = multiFile ? `${byFile.size} file(s)` : [...byFile.keys()][0];
  lines.push(`${ENVELOPE} Security findings in ${where} (${total} issue(s)):`);

  const seenRule = new Set();
  for (const [file, group] of byFile) {
    if (multiFile) lines.push(`${file}:`);
    for (const f of group) {
      const cwe = f.cwe ? ` · ${f.cwe}` : '';
      lines.push(`- L${f.line} [${f.rule}]${cwe} · ${f.severity}/${f.confidence}. ${f.message}`);
      // The taxonomy is explained once per message, not once per hit.
      if (!seenRule.has(f.rule)) {
        lines.push(`  Fix: ${f.fix}`);
        seenRule.add(f.rule);
      }
      // The escape hatch ships pre-filled so the agent never invents a broader one.
      const value = f.valueFingerprint ? `--fingerprint ${f.valueFingerprint}` : `"<value>"`;
      lines.push(`  If this is a false positive: airtight hooks ignore-value ${f.rule} ${value} --reason "<who decided: evidence>"`);
    }
  }

  if (total > findings.length) lines.push(`... and ${total - findings.length} more (run: airtight detect).`);
  lines.push(showFooter ? FOOTER : SHORT_FOOTER);
  return lines.join('\n');
}

const FOOTER = [
  '',
  'Triage each finding, then state in your reply what you fixed, what you suppressed, and what you left standing:',
  '- A real problem: fix it. Read the security-floor reference before editing.',
  '- A confident false positive: persist the narrowest waiver yourself with `ignore-value` and disclose it. Write "user confirmed" in a reason only when the user actually confirmed.',
  '- Unsure: leave it and ask the user in one line. Leaving a finding standing is a legitimate outcome; leaving it standing silently is not.',
  'Self-service ends at ignore-value. `ignore-file` and `ignore-rule` need the user, and a waiver must never be used to push a blocked write through.',
].join('\n');

const SHORT_FOOTER = '\nTriage each: fix, waive with `ignore-value` and disclose, or leave it and say so.';

/** Drop order: findings, then the long footer, then truncate. Never blow the window. */
function clampToBudget(text, maxChars) {
  if (text.length <= maxChars) return text;
  const withShort = text.replace(FOOTER, SHORT_FOOTER);
  if (withShort.length <= maxChars) return withShort;
  return `${withShort.slice(0, Math.max(0, maxChars - 1))}…`;
}

// --------------------------------------------------------------------- main

function loadRules(env, root) {
  const here = dirname(new URL(import.meta.url).pathname);
  for (const path of [env.AIRTIGHT_RULES, join(here, '..', 'rules.json'), join(here, '..', 'build', 'rules.json')]) {
    if (!path) continue;
    try { return compileAll(JSON.parse(readFileSync(path, 'utf8'))); } catch { /* next */ }
  }
  return null;
}

export function runHook(io, env, stdinText) {
  const root = env.CLAUDE_PROJECT_DIR || process.cwd();

  // Reentrancy: a hook that triggers an edit that triggers the hook.
  if (env.AIRTIGHT_HOOK_DEPTH || env.CLAUDE_HOOK_DEPTH) return 0;
  if (/^(1|true|yes|on)$/i.test(env.AIRTIGHT_HOOK_DISABLED ?? '')) return 0;

  let input;
  try { input = JSON.parse(stdinText); } catch { return 0; }
  if (!input || typeof input !== 'object') return 0;

  const config = loadConfig(root);
  if (config.hook?.enabled === false) return 0;

  const harness = resolveHarness(input, env);
  const stop = isStopEvent(input);
  const eventName = stop ? 'Stop' : 'PostToolUse';

  // Grok fires Stop twice, and a stop hook that re-enters itself never ends.
  if (stop && input.stop_hook_active) return 0;

  const rules = loadRules(env, root);
  if (!rules) return 0;

  const cache = loadCache(root);
  const sessionId = String(input.session_id ?? input.conversation_id ?? input.turn_id ?? 'default');
  const session = sessionOf(cache, sessionId);

  // Which files to look at.
  let rels;
  if (stop) {
    rels = Object.keys(session.files).slice(0, STOP_MAX_FILES);
  } else {
    rels = [];
    for (const p of resolveTargets(input)) {
      const abs = resolve(root, p);
      if (!insideProject(root, abs)) continue;
      const rel = relative(root, abs).split(sep).join('/');
      if (rel.startsWith('..')) continue;
      if (GENERATED.test(`/${rel}`) || GENERATED_FILE.test(rel)) continue;
      if (!isScannable(rel)) continue;
      if (matchesAny(rel, config.detector?.ignoreFiles ?? [])) continue;
      try { if (statSync(abs).size > (config.scan?.maxFileBytes ?? 1_048_576)) continue; } catch { continue; }

      session.edits[rel] = (session.edits[rel] ?? 0) + 1;
      // A file edited repeatedly is a file being worked on. Continuing to
      // interrupt is how a hook becomes something people disable.
      if (session.edits[rel] > MAX_EDITS_PER_FILE) continue;
      rels.push(rel);
    }
  }

  if (rels.length === 0) { saveCache(root, cache); return 0; }

  const active = stop ? rules : immediateTier(rules);
  const { findings, vault } = scanFiles({
    root,
    files: rels.map((r) => join(root, r)),
    rules: active,
    config,
    isSuppressed: buildFilter(config),
  });

  // Session dedup. Stop replaces the remembered set so a fixed-then-
  // reintroduced finding fires again rather than staying suppressed.
  const fresh = [];
  for (const f of findings) {
    const known = session.files[f.file] ?? [];
    const key = cacheKey(f);
    if (!stop && known.includes(key)) continue;
    fresh.push(f);
  }
  for (const rel of rels) {
    const keys = findings.filter((f) => f.file === rel).map(cacheKey);
    session.files[rel] = stop ? keys : [...new Set([...(session.files[rel] ?? []), ...keys])];
  }

  if (fresh.length === 0) {
    if (stop || config.hook?.quiet || rels.length !== 1) { saveCache(root, cache); return 0; }
    const rel = rels[0];

    // Nothing new is not the same as nothing. A file whose findings were
    // already reported this session still has them, and saying "no findings"
    // here would turn a deduplication into a false all-clear.
    if (findings.length > 0) {
      saveCache(root, cache);
      const sample = findings.slice(0, 3).map((f) => `${f.rule} L${f.line}`).join(', ');
      io.out(payload(`${ENVELOPE} Scanned ${rel}. Still has ${findings.length} finding(s) reported earlier this session`
        + ` (${sample}). The earlier triage still applies.`, eventName, harness));
      return 0;
    }

    if (!session.cleanAcked.includes(rel)) {
      session.cleanAcked.push(rel);
      saveCache(root, cache);
      // Deliberately anti-complacency: a clean deterministic scan is a narrow
      // claim and should not be allowed to read as a broad one.
      io.out(payload(`${ENVELOPE} Scanned ${rel}. No deterministic security findings. That is not the same as secure:`
        + ' the rules cover known shapes, not reachability, authorization logic, or business rules.', eventName, harness));
      return 0;
    }
    saveCache(root, cache);
    return 0;
  }

  const limits = config.hook?.limits ?? {};
  const maxFindings = limits.maxFindings ?? 5;
  const shown = fresh.slice(0, maxFindings);
  const text = vault.scrub(clampToBudget(
    renderFindings(shown, {
      multiFile: rels.length > 1,
      showFooter: !session.footerShown,
      total: fresh.length,
    }),
    limits.maxChars ?? 8000,
  ));
  session.footerShown = true;
  saveCache(root, cache);

  // A confirmed critical is the one case worth interrupting over. On Claude
  // Code, exit 2 puts stderr in front of the model and stops the turn.
  const blocking = shown.some((f) => f.severity === 'critical' && f.confidence === 'confirmed');
  if (blocking && (harness === 'claude' || harness === 'codex')) {
    io.err(`${text}\n\nThis write introduced a confirmed critical finding. Fix it before continuing.`);
    return 2;
  }

  io.out(payload(text, eventName, harness));
  return 0;
}

export function readStdin() {
  try { return readFileSync(0, 'utf8'); } catch { return ''; }
}
