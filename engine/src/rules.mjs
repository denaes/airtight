// Rule loading and validation.
//
// Rules are data. They are authored as YAML under engine/rules/, compiled to
// JSON at build time, and loaded here. The runtime never parses YAML for its
// own packs, which is what keeps the shipped engine dependency-free and lets a
// Rust runner consume the identical packs later without reauthoring anything.

import { SEVERITIES, CONFIDENCES, DISPOSITIONS } from './findings.mjs';
import { PREDICATE_NAMES } from './match/predicates.mjs';
import { TEST_MODES } from './testpath.mjs';
import { ANALYZER_NAMES } from './match/custom.mjs';

const PARSERS = ['text', 'dockerfile', 'yaml', 'json', 'hcl', 'js'];
const SNIPPET_MODES = ['line', 'capture'];
const ID_SHAPE = /^[a-z0-9-]+\/[a-z0-9-]+$/;

export class RuleError extends Error {}

function fail(id, msg) {
  throw new RuleError(`rule ${id ?? '<missing id>'}: ${msg}`);
}

/**
 * JS has no inline `(?i)`, but Go and Rust do and every rule author reaches for
 * it. Translate a leading one into the flag rather than making people remember
 * which flavour they are writing for.
 */
function compileRegex(id, field, source) {
  let body = source;
  let flags = 'g';
  // V8 12.8 / Node 23.6+ added regex modifier groups (?i:...), but Node 20 and
  // 22 reject them with SyntaxError: Invalid group. Normalize (?i:...) to (?:...)
  // and ensure the flags are set on the compiled RegExp.
  if (/\(\?[ims]+:/.test(body)) {
    for (const [, mod] of body.matchAll(/\(\?([ims]+):/g)) {
      for (const ch of mod) {
        if (!flags.includes(ch)) flags += ch;
      }
    }
    body = body.replace(/\(\?([ims]+):/g, '(?:');
  }
  const inline = /^\(\?([ims]+)\)/.exec(body);
  if (inline) {
    body = body.slice(inline[0].length);
    for (const ch of inline[1]) {
      if (!flags.includes(ch)) flags += ch;
    }
  }
  try {
    return new RegExp(body, flags);
  } catch (err) {
    fail(id, `${field} is not a valid regex: ${err.message}`);
  }
}

/**
 * Validate and compile one rule. Throws on anything malformed, because a rule
 * that silently never matches is worse than no rule: it reports a domain as
 * clean when nothing ever looked at it.
 */
export function compileRule(raw) {
  const id = raw?.id;
  if (!id || !ID_SHAPE.test(id)) fail(id, 'id must be "<pack>/<slug>", lowercase and hyphenated');

  for (const field of ['name', 'domain', 'message', 'why', 'fix']) {
    if (!raw[field] || typeof raw[field] !== 'string') fail(id, `missing required field "${field}"`);
  }
  if (!SEVERITIES.includes(raw.severity)) fail(id, `severity must be one of ${SEVERITIES.join(', ')}`);
  if (!CONFIDENCES.includes(raw.confidence)) fail(id, `confidence must be one of ${CONFIDENCES.join(', ')}`);
  if (raw.disposition && !DISPOSITIONS.includes(raw.disposition)) {
    fail(id, `disposition must be one of ${DISPOSITIONS.join(', ')}`);
  }

  const parse = raw.parse ?? 'text';
  if (!PARSERS.includes(parse)) fail(id, `parse must be one of ${PARSERS.join(', ')}`);
  if (parse === 'text' && !raw.match?.regex) fail(id, 'text rules need match.regex');
  if (raw.match?.in_string !== undefined && raw.match.in_string !== false) {
    fail(id, 'match.in_string only supports false (skip matches inside string literals)');
  }
  if (parse === 'js') {
    if (!ANALYZER_NAMES.includes(raw.script)) {
      fail(id, `js rules need script set to one of: ${ANALYZER_NAMES.join(', ')}`);
    }
  } else if (parse !== 'text') {
    const conditions = [...(raw.assert?.all ?? []), ...(raw.assert?.any ?? [])];
    if (conditions.length === 0) {
      fail(id, `${parse} rules need assert.all or assert.any with at least one condition`);
    }
    for (const c of conditions) {
      const ops = Object.keys(c).filter((k) => k !== 'path');
      if (ops.length === 0) fail(id, 'each assert.all condition needs at least one predicate');
      for (const op of ops) {
        if (!PREDICATE_NAMES.includes(op)) {
          fail(id, `unknown predicate "${op}" (expected one of ${PREDICATE_NAMES.join(', ')})`);
        }
      }
    }
  }
  if (!Array.isArray(raw.files) || raw.files.length === 0) fail(id, 'files must be a non-empty array of globs');
  if (raw.snippet && !SNIPPET_MODES.includes(raw.snippet)) {
    fail(id, `snippet must be one of ${SNIPPET_MODES.join(', ')}`);
  }
  if (raw.tests && !TEST_MODES.includes(raw.tests)) {
    fail(id, `tests must be one of ${TEST_MODES.join(', ')}`);
  }

  const rule = {
    ...raw,
    parse,
    pack: id.split('/')[0],
    disposition: raw.disposition ?? 'fix',
    redact: Boolean(raw.redact),
    snippet: raw.snippet ?? 'line',
    exclude: raw.exclude ?? [],
    tier: raw.tier ?? 'deep',
    tests: raw.tests ?? 'downgrade',
  };

  if (raw.match?.regex) rule.re = compileRegex(id, 'match.regex', raw.match.regex);
  if (raw.match?.not_regex) rule.notRe = compileRegex(id, 'match.not_regex', raw.match.not_regex);
  if (raw.match?.require_regex) rule.requireRe = compileRegex(id, 'match.require_regex', raw.match.require_regex);

  return rule;
}

export function compileAll(rawRules) {
  const seen = new Set();
  return rawRules.map((raw) => {
    if (seen.has(raw?.id)) fail(raw.id, 'duplicate rule id');
    seen.add(raw?.id);
    return compileRule(raw);
  });
}

/**
 * The immediate tier is what the edit hook is allowed to interrupt you with.
 * Selection follows impeccable's criterion, translated: mechanical,
 * unambiguous, and cheap to correct at the edit site. Everything architectural
 * waits for the deep pass.
 */
export function immediateTier(rules) {
  return rules.filter((r) => r.tier === 'immediate');
}
