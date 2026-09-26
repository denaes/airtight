// Filesystem walk and rule dispatch.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { matchesAny } from './glob.mjs';
import { buildWaiverIndex } from './waivers.mjs';
import { matchText } from './match/text.mjs';
import { matchStructured } from './match/structured.mjs';
import { matchCustom } from './match/custom.mjs';
import { createVault } from './redact.mjs';
import { sortFindings } from './findings.mjs';
import { isTestPath, applyTestMode } from './testpath.mjs';

/**
 * Directories with nothing authored in them. Note what is absent: we do not
 * skip .env, *.pem, or secrets.* the way impeccable's design hook does. Those
 * are the files we most need to read. Containment is the vault's job, not the
 * walker's.
 */
const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', 'out', '.next', '.nuxt', '.cache',
  'coverage', 'vendor', 'target', '.venv', 'venv', '__pycache__', '.tox',
  '.terraform', '.gradle', '.idea', '.airtight',
]);

const SKIP_FILE = /\.(min\.(js|css)|map|lock\.hcl)$|^\.DS_Store$/;

/**
 * Files whose entire contents are credentials. We still scan them — that is the
 * point — but every finding inside one is snippet-clamped to the match, so a
 * secret no rule recognizes cannot ride out on a neighbouring finding's line.
 */
const SENSITIVE_FILE = /(^|\/)(\.env(\..*)?|.*\.pem|.*\.key|.*\.p12|.*\.pfx|id_[rd]sa|.*credentials.*|.*secrets?\.(json|ya?ml|toml|ini))$/i;

function isBinary(buf) {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i += 1) if (buf[i] === 0) return true;
  return false;
}

export function* walk(root, dir = root) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walk(root, full);
    } else if (entry.isFile()) {
      if (SKIP_FILE.test(entry.name)) continue;
      yield full;
    }
  }
}

function toPosix(p) {
  return sep === '/' ? p : p.split(sep).join('/');
}

/**
 * Scan a set of files against a set of rules.
 *
 * Returns findings plus the vault, because the caller has to scrub its own
 * output with it. Handing back findings without the vault would be handing back
 * a loaded gun.
 */
export function scanFiles({ root, files, rules, config, isSuppressed, testMode = true }) {
  const vault = createVault();
  const maxBytes = config?.scan?.maxFileBytes ?? 1_048_576;
  const findings = [];
  const skipped = [];

  for (const absPath of files) {
    const relPath = toPosix(relative(root, absPath));

    let buf;
    try {
      const st = statSync(absPath);
      if (st.size > maxBytes) { skipped.push({ file: relPath, reason: 'too-large' }); continue; }
      buf = readFileSync(absPath);
    } catch {
      skipped.push({ file: relPath, reason: 'unreadable' });
      continue;
    }
    if (isBinary(buf)) { skipped.push({ file: relPath, reason: 'binary' }); continue; }

    // testMode off is for the rule corpus, which lives under fixtures/ and so
    // looks like test code to isTestPath. It is rule *input*, not test code:
    // a rule with `tests: ignore` must still fire on its own true positives.
    const inTest = testMode && isTestPath(relPath);
    const applicable = rules
      .filter((r) => matchesAny(relPath, r.files) && !matchesAny(relPath, r.exclude))
      .map((r) => applyTestMode(r, inTest))
      .filter(Boolean);
    if (applicable.length === 0) continue;

    const content = buf.toString('utf8');
    const lines = content.split(/\r?\n/);
    const isWaived = buildWaiverIndex(lines);
    // One parse per tier per file, shared across every rule that needs it.
    const parseCache = new Map();
    const ctx = {
      content, lines, relPath, vault, isWaived, parseCache,
      sensitiveFile: SENSITIVE_FILE.test(relPath),
    };

    for (const rule of applicable) {
      try {
        if (rule.parse === 'text') findings.push(...matchText(rule, ctx));
        else if (rule.parse === 'js') findings.push(...matchCustom(rule, ctx));
        else findings.push(...matchStructured(rule, ctx));
      } catch (err) {
        // One malformed file must not take down the scan. A rule that throws is
        // a bug we want reported, not a reason to stop looking at everything
        // else in the repository.
        skipped.push({ file: relPath, reason: `rule-error:${rule.id}:${err.message}` });
      }
    }
  }

  const kept = isSuppressed ? findings.filter((f) => !isSuppressed(f)) : findings;
  return { findings: sortFindings(kept), vault, skipped };
}

export function collectTargets(root, targets) {
  const out = [];
  for (const t of targets) {
    let st;
    try { st = statSync(t); } catch { continue; }
    if (st.isDirectory()) out.push(...walk(t));
    else out.push(t);
  }
  return out;
}
