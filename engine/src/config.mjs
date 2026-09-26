// Project configuration and the suppression ladder.
//
// .airtight/config.json is committed and shared; .airtight/config.local.json is
// per-developer and gitignored. Both are merged, later wins, and a malformed
// file is ignored rather than fatal — a broken config must never be the reason
// a security scan silently stops running.

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { matchesAny, matchesGlob } from './glob.mjs';

const DEFAULTS = {
  scan: { maxFileBytes: 1_048_576 },
  hook: { enabled: true, limits: { maxFindings: 5, maxChars: 8000 } },
  detector: { ignoreRules: [], ignoreFiles: [], ignoreValues: [] },
};

function readJson(path) {
  try {
    return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null;
  } catch {
    return null;
  }
}

function merge(base, extra) {
  if (!extra || typeof extra !== 'object') return base;
  const out = { ...base };
  for (const [k, v] of Object.entries(extra)) {
    out[k] = v && typeof v === 'object' && !Array.isArray(v) ? merge(base[k] ?? {}, v) : v;
  }
  return out;
}

export function loadConfig(projectRoot) {
  const dir = join(projectRoot, '.airtight');
  return merge(merge(DEFAULTS, readJson(join(dir, 'config.json'))),
    readJson(join(dir, 'config.local.json')));
}

/**
 * Three levels, deliberately unequal in who may create them:
 *
 *   ignoreValues  narrowest. The agent may add one itself, with named evidence
 *                 in --reason, because it is scoped to a single value.
 *   ignoreFiles   every rule, including rules written next year, for a path.
 *   ignoreRules   a rule, project-wide. The bluntest tool we ship.
 *
 * The last two require the user. That boundary is stated in the footer the hook
 * emits, so the policy travels attached to every finding rather than living in
 * documentation nobody opens.
 */
export function buildFilter(config) {
  const { ignoreRules = [], ignoreFiles = [], ignoreValues = [] } = config.detector ?? {};
  const rules = new Set(ignoreRules);

  return function isSuppressed(finding) {
    if (rules.has(finding.rule)) return true;
    if (matchesAny(finding.file, ignoreFiles)) return true;

    return ignoreValues.some((entry) => {
      if (entry.rule !== finding.rule) return false;

      const wildcard = entry.value === '*';
      // A bare "*" with no file scope is ignoreRule wearing a disguise.
      if (wildcard && !(entry.files?.length > 0)) return false;
      if (entry.files?.length > 0 && !entry.files.some((f) => matchesGlob(finding.file, f))) return false;
      if (wildcard) return true;

      // Redacted findings never carry the raw value, so value-scoped waivers on
      // secrets match by fingerprint instead.
      return finding.redacted
        ? entry.fingerprint === finding.valueFingerprint
        : finding.snippet.includes(entry.value);
    });
  };
}
