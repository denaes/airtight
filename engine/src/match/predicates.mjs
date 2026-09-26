// Predicates evaluate against the *set* of values a path resolved to, which is
// what makes "no instruction is USER" expressible without a query language.
//
//   matches      any resolved value matches the regex
//   not_matches  no resolved value matches, including when nothing resolved
//   equals       any resolved value equals
//   not_equals   no resolved value equals
//   present      whether the path resolved to anything at all
//   gt / lt      any resolved value compares numerically
//
// `not_matches` holding vacuously on an empty set is the important choice: it
// is how a rule says "this file never sets X", which is most of container and
// Kubernetes hardening.

import { resolvePath } from './path.mjs';

const asString = (v) => (v === null || v === undefined ? '' : String(v));

const OPS = {
  matches: (hits, arg) => {
    const re = toRegex(arg);
    return hits.find((h) => { re.lastIndex = 0; return re.test(asString(h.value)); }) ?? null;
  },
  not_matches: (hits, arg) => {
    const re = toRegex(arg);
    return hits.some((h) => { re.lastIndex = 0; return re.test(asString(h.value)); }) ? null : NO_ANCHOR;
  },
  equals: (hits, arg) => hits.find((h) => h.value === arg || asString(h.value) === asString(arg)) ?? null,
  not_equals: (hits, arg) =>
    hits.some((h) => h.value === arg || asString(h.value) === asString(arg)) ? null : NO_ANCHOR,
  present: (hits, arg) => {
    const has = hits.length > 0;
    return has === Boolean(arg) ? (hits[0] ?? NO_ANCHOR) : null;
  },
  gt: (hits, arg) => hits.find((h) => Number(h.value) > Number(arg)) ?? null,
  lt: (hits, arg) => hits.find((h) => Number(h.value) < Number(arg)) ?? null,
};

/** A condition that held but has no location of its own to point at. */
export const NO_ANCHOR = { value: undefined, line: null, vacuous: true };

const regexCache = new Map();
function toRegex(source) {
  let re = regexCache.get(source);
  if (!re) {
    let body = source;
    let flags = '';
    const inline = /^\(\?([ims]+)\)/.exec(body);
    if (inline) { body = body.slice(inline[0].length); flags = inline[1]; }
    re = new RegExp(body, flags);
    regexCache.set(source, re);
  }
  return re;
}

export const PREDICATE_NAMES = Object.keys(OPS);

/**
 * Evaluate one condition. Returns the hit that anchors the finding, or null if
 * the condition did not hold.
 */
export function evaluate(condition, node, nodeLine, root = node, rootLine = nodeLine) {
  const { path, ...rest } = condition;

  // A leading `$.` escapes the iterated node and resolves from the document
  // root. Needed whenever a finding depends on two scopes at once: the classic
  // case is a checkout step that is only dangerous because the *workflow* is
  // triggered by pull_request_target.
  const absolute = typeof path === 'string' && path.startsWith('$.');
  const hits = path
    ? (absolute
      ? resolvePath(root, path.slice(2), rootLine)
      : resolvePath(node, path, nodeLine))
    : [{ value: node, line: nodeLine }];

  let anchor = NO_ANCHOR;
  for (const [op, arg] of Object.entries(rest)) {
    const fn = OPS[op];
    if (!fn) throw new Error(`unknown predicate "${op}"`);
    const result = fn(hits, arg);
    if (result === null) return null;
    if (result !== NO_ANCHOR && anchor === NO_ANCHOR) anchor = result;
  }
  return anchor;
}

/** At least one condition must hold. Returns its anchor, or null if none do. */
export function evaluateAny(conditions, node, nodeLine, root = node, rootLine = nodeLine) {
  for (const condition of conditions) {
    const result = evaluate(condition, node, nodeLine, root, rootLine);
    if (result !== null) return result;
  }
  return null;
}

/** Every condition must hold. Returns the best anchor, or null. */
export function evaluateAll(conditions, node, nodeLine, root = node, rootLine = nodeLine) {
  let anchor = NO_ANCHOR;
  for (const condition of conditions) {
    const result = evaluate(condition, node, nodeLine, root, rootLine);
    if (result === null) return null;
    if (result !== NO_ANCHOR && anchor === NO_ANCHOR) anchor = result;
  }
  return anchor;
}
