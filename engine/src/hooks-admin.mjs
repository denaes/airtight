// `airtight hooks <on|off|status|ignore-*>`
//
// The suppression ladder is enforced here as well as documented, because the
// boundary between what the agent may waive and what needs a human is the
// only thing that keeps a waiver meaningful.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { loadConfig } from './config.mjs';

const SETTINGS = '.claude/settings.json';
const CONFIG = '.airtight/config.json';
const LAUNCHER = '${CLAUDE_PROJECT_DIR}/.claude/skills/airtight/scripts/airtight';

/**
 * `[ ! -f X ] || X hook` rather than `X hook || true`: the guard makes a
 * missing launcher a silent no-op while preserving the launcher's own exit
 * code, so the exit-2 blocking signal still reaches the agent.
 */
const guarded = (verb) => `[ ! -f "${LAUNCHER}" ] || "${LAUNCHER}" ${verb}`;

const MANIFEST = {
  PostToolUse: [{
    matcher: 'Edit|Write',
    hooks: [{ type: 'command', command: guarded('hook'), timeout: 5, statusMessage: 'Checking security' }],
  }],
  Stop: [{
    hooks: [{ type: 'command', command: guarded('hook'), timeout: 30, statusMessage: 'Security deep pass' }],
  }],
};

function readJson(path, fallback) {
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return fallback; }
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

const isOurs = (entry) => JSON.stringify(entry).includes('airtight');

export function install(root) {
  const path = join(root, SETTINGS);
  const settings = readJson(path, {});
  settings.hooks ??= {};
  for (const [event, entries] of Object.entries(MANIFEST)) {
    // Replace our own entry, leave everyone else's alone.
    settings.hooks[event] = [...(settings.hooks[event] ?? []).filter((e) => !isOurs(e)), ...entries];
  }
  writeJson(path, settings);
  return path;
}

export function uninstall(root) {
  const path = join(root, SETTINGS);
  if (!existsSync(path)) return null;
  const settings = readJson(path, {});
  if (!settings.hooks) return null;
  for (const event of Object.keys(MANIFEST)) {
    const kept = (settings.hooks[event] ?? []).filter((e) => !isOurs(e));
    if (kept.length) settings.hooks[event] = kept;
    else delete settings.hooks[event];
  }
  writeJson(path, settings);
  return path;
}

export function status(root) {
  const settings = readJson(join(root, SETTINGS), {});
  const events = Object.keys(MANIFEST).filter((e) => (settings.hooks?.[e] ?? []).some(isOurs));
  const config = loadConfig(root);
  const d = config.detector ?? {};
  return {
    installed: events.length > 0,
    events,
    enabled: config.hook?.enabled !== false,
    limits: config.hook?.limits ?? {},
    suppressions: {
      ignoreRules: d.ignoreRules ?? [],
      ignoreFiles: d.ignoreFiles ?? [],
      ignoreValues: (d.ignoreValues ?? []).length,
    },
  };
}

function mutateConfig(root, fn) {
  const path = join(root, CONFIG);
  const config = readJson(path, { detector: { ignoreRules: [], ignoreFiles: [], ignoreValues: [] } });
  config.detector ??= {};
  config.detector.ignoreRules ??= [];
  config.detector.ignoreFiles ??= [];
  config.detector.ignoreValues ??= [];
  fn(config.detector);
  writeJson(path, config);
  return path;
}

export function setEnabled(root, enabled) {
  const path = join(root, CONFIG);
  const config = readJson(path, {});
  config.hook = { ...(config.hook ?? {}), enabled };
  writeJson(path, config);
  return path;
}

/**
 * The narrowest rung, and the only one the agent may use unattended. The
 * reason is mandatory: a waiver records a decision, and a decision with no
 * stated basis is indistinguishable from nobody having made one.
 */
export function ignoreValue(root, { rule, value, fingerprint, files, reason }) {
  if (!rule) throw new Error('ignore-value needs a rule id');
  if (!reason) throw new Error('ignore-value needs --reason naming who decided and on what evidence');
  if (!value && !fingerprint) throw new Error('ignore-value needs a value or a --fingerprint');
  if (value === '*' && !(files?.length)) {
    throw new Error('a bare "*" value with no --file scope is ignore-rule in disguise; use ignore-rule and get the user to approve it');
  }
  return mutateConfig(root, (d) => {
    d.ignoreValues.push({
      rule,
      value: value ?? '*',
      ...(fingerprint ? { fingerprint } : {}),
      ...(files?.length ? { files } : {}),
      reason,
      createdAt: new Date().toISOString(),
    });
  });
}

export function ignoreFile(root, glob) {
  if (!glob) throw new Error('ignore-file needs a glob');
  return mutateConfig(root, (d) => {
    if (!d.ignoreFiles.includes(glob)) d.ignoreFiles.push(glob);
  });
}

export function ignoreRule(root, rule) {
  if (!rule) throw new Error('ignore-rule needs a rule id');
  return mutateConfig(root, (d) => {
    if (!d.ignoreRules.includes(rule)) d.ignoreRules.push(rule);
  });
}

/** Printed whenever the agent reaches for a rung above its authority. */
export const ESCALATION_NOTICE =
  'ignore-file and ignore-rule suppress far more than one finding, including rules that do not exist yet. '
  + 'Confirm with the user before running this, and never run it to get past a blocked write.';
