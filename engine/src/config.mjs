// Project configuration and the suppression ladder.
//
// .airtight/config.json is committed and shared; .airtight/config.local.json is
// per-developer and gitignored. Both are merged, later wins, and a malformed
// file is ignored rather than fatal — a broken config must never be the reason
// a security scan silently stops running.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, resolve, dirname, relative, isAbsolute, sep } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { compileRule } from './rules.mjs';
import { matchesAny, matchesGlob } from './glob.mjs';

const DEFAULTS = {
  scan: { maxFileBytes: 1_048_576 },
  hook: { enabled: true, limits: { maxFindings: 5, maxChars: 8000 } },
  detector: { ignoreRules: [], ignoreFiles: [], ignoreValues: [] },
  severityOverrides: {},
  rulePaths: [],
  waiverPolicy: {},
};

export function merge(base, extra) {
  if (!extra || typeof extra !== 'object') return base;
  const out = { ...base };
  for (const [k, v] of Object.entries(extra)) {
    out[k] = v && typeof v === 'object' && !Array.isArray(v) ? merge(base[k] ?? {}, v) : v;
  }
  return out;
}

export function resolveConfigExtends(config, baseDir, visited = new Set()) {
  if (!config || typeof config !== 'object' || Array.isArray(config) || !config.extends) return config;

  const extendList = Array.isArray(config.extends) ? config.extends : [config.extends];
  let base = {};

  for (const ext of extendList) {
    if (typeof ext !== 'string') continue;
    const targetPath = resolve(baseDir, ext);
    if (visited.has(targetPath)) {
      throw new Error(`circular extends detected: ${targetPath}`);
    }
    const nextVisited = new Set(visited);
    nextVisited.add(targetPath);

    if (!existsSync(targetPath)) continue;

    let parentRaw;
    try {
      parentRaw = JSON.parse(readFileSync(targetPath, 'utf8'));
    } catch {
      continue;
    }

    if (parentRaw && typeof parentRaw === 'object' && !Array.isArray(parentRaw)) {
      const resolvedParent = resolveConfigExtends(parentRaw, dirname(targetPath), nextVisited);
      base = merge(base, resolvedParent);
    }
  }

  const { extends: _, ...currentWithoutExtends } = config;
  return merge(base, currentWithoutExtends);
}

export function readConfigFile(filePath, visited = new Set()) {
  const resolved = resolve(filePath);
  if (!existsSync(resolved)) return null;

  if (visited.has(resolved)) {
    throw new Error(`circular extends detected: ${resolved}`);
  }
  const nextVisited = new Set(visited);
  nextVisited.add(resolved);

  let raw;
  try {
    raw = JSON.parse(readFileSync(resolved, 'utf8'));
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return raw;

  return resolveConfigExtends(raw, dirname(resolved), nextVisited);
}

export function loadConfig(projectRoot) {
  const dir = join(projectRoot, '.airtight');
  const baseConfig = readConfigFile(join(dir, 'config.json'));
  const localConfig = readConfigFile(join(dir, 'config.local.json'));
  return merge(merge(DEFAULTS, baseConfig), localConfig);
}

export function applySeverityOverrides(items, overrides = {}) {
  if (!items || !overrides || Object.keys(overrides).length === 0) return items;
  return items.map((item) => {
    const ruleId = item.rule ?? item.id;
    const override = overrides[ruleId];
    return override ? { ...item, severity: override } : item;
  });
}

export function getSeverityOverride(ruleId, overrides = {}) {
  return overrides?.[ruleId];
}

function walkFiles(dir, callback) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === '.git' || entry.name === 'node_modules' || entry.name === '.airtight') continue;
      walkFiles(full, callback);
    } else if (entry.isFile()) {
      callback(full);
    }
  }
}

export function resolveRuleFiles(projectRoot, config) {
  const patterns = config?.rulePaths ?? [];
  if (!Array.isArray(patterns) || patterns.length === 0) return [];

  const found = new Set();
  for (const entry of patterns) {
    if (!entry || typeof entry !== 'string') continue;

    const hasGlob = /[*?{}]/.test(entry);
    if (!hasGlob) {
      const full = isAbsolute(entry) ? entry : resolve(projectRoot, entry);
      if (!existsSync(full)) continue;
      const stat = statSync(full);
      if (stat.isDirectory()) {
        walkFiles(full, (file) => {
          if (file.endsWith('.yaml') || file.endsWith('.yml')) {
            found.add(file);
          }
        });
      } else if (stat.isFile()) {
        if (full.endsWith('.yaml') || full.endsWith('.yml')) {
          found.add(full);
        }
      }
      continue;
    }

    // Glob pattern
    const normalized = entry.replace(/\\/g, '/');
    const parts = normalized.split('/');
    const firstWildcardIdx = parts.findIndex((p) => /[*?{}]/.test(p));
    const baseParts = firstWildcardIdx > 0 ? parts.slice(0, firstWildcardIdx) : [];
    const baseDir = baseParts.length > 0
      ? (isAbsolute(entry) ? baseParts.join('/') : resolve(projectRoot, baseParts.join('/')))
      : projectRoot;

    if (!existsSync(baseDir)) continue;

    const globPattern = normalized.replace(/^\.\//, '');
    const globAfterBase = parts.slice(firstWildcardIdx).join('/');

    walkFiles(baseDir, (filePath) => {
      if (!filePath.endsWith('.yaml') && !filePath.endsWith('.yml')) return;
      const relToProject = relative(projectRoot, filePath).split(sep).join('/');
      const relNorm = relToProject.replace(/^\.\//, '');
      const relToBase = relative(baseDir, filePath).split(sep).join('/');
      if (matchesGlob(relNorm, globPattern) ||
          matchesGlob(relToProject, normalized) ||
          matchesGlob(relToBase, globAfterBase)) {
        found.add(filePath);
      }
    });
  }

  return [...found].sort();
}

export function loadCustomRules(projectRoot, config) {
  const files = resolveRuleFiles(projectRoot, config);
  const rules = [];
  for (const file of files) {
    const content = readFileSync(file, 'utf8');
    const parsed = parseYaml(content);
    if (!parsed) continue;
    const list = Array.isArray(parsed) ? parsed : [parsed];
    for (const raw of list) {
      if (!raw || typeof raw !== 'object') continue;
      rules.push(compileRule(raw));
    }
  }
  return rules;
}

export const resolveRulePaths = loadCustomRules;

export function validateWaiverPolicy({ waiverPolicy, reason, approver, expires, now } = {}) {
  if (!waiverPolicy || typeof waiverPolicy !== 'object') return true;

  if (waiverPolicy.maxExpiryDays !== undefined && waiverPolicy.maxExpiryDays !== null) {
    const maxDays = Number(waiverPolicy.maxExpiryDays);
    if (!expires) {
      throw new Error(`waiver policy requires an expiration date (max: ${maxDays} days)`);
    }
    const nowDate = now ? new Date(now) : new Date();
    const expiresDate = new Date(expires);
    if (Number.isNaN(expiresDate.getTime())) {
      throw new Error(`invalid waiver expiration date: ${expires}`);
    }
    const maxAllowedTime = nowDate.getTime() + maxDays * 86_400_000;
    if (expiresDate.getTime() > maxAllowedTime) {
      throw new Error(`waiver expiration (${expires}) exceeds maximum allowed duration of ${maxDays} days`);
    }
  }

  if (waiverPolicy.requiredApproverDomain) {
    const rawDomain = String(waiverPolicy.requiredApproverDomain);
    const domain = rawDomain.startsWith('@') ? rawDomain.slice(1) : rawDomain;
    const requiredSuffix = `@${domain}`;
    if (!approver || !approver.includes(requiredSuffix)) {
      throw new Error(`waiver approver must be from domain @${domain} (got: ${approver ?? '<none>'})`);
    }
  }

  return true;
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
