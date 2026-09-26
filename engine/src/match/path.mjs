// Path resolution for structured rules.
//
// Deliberately not a query language. A rule DSL that grows into JMESPath stops
// being reviewable, and a security rule nobody can review is a liability. Four
// segment forms cover every pack we plan:
//
//   a.b        map key
//   a[0]       array index
//   a[*]       every array element
//   a.*        every value of a map (or every array element)
//   **.a       `a` at any depth
//
// The deep wildcard exists for one recurring reason: the same pod spec lives at
// spec.containers in a Pod, spec.template.spec.containers in a Deployment, and
// spec.jobTemplate.spec.template.spec.containers in a CronJob. Without it every
// Kubernetes rule would have to be written three times and would still miss the
// fourth workload kind.

import { LINE, lineOf, hit } from '../parse/node.mjs';

const SEGMENT = /([^.[\]]+)|\[(\*|\d+)\]/g;

export function parsePath(path) {
  const segs = [];
  SEGMENT.lastIndex = 0;
  let m;
  while ((m = SEGMENT.exec(path)) !== null) {
    if (m[1] !== undefined) {
      if (m[1] === '**') segs.push({ deep: true });
      else if (m[1] === '*') segs.push({ wildcard: true });
      else segs.push({ key: m[1] });
    }
    else segs.push(m[2] === '*' ? { wildcard: true } : { index: Number(m[2]) });
  }
  return segs;
}

/**
 * Resolve a path to every matching value, each paired with the line of the
 * nearest enclosing node that carried one. Missing paths yield nothing rather
 * than throwing: a rule asking about a key that does not exist is the normal
 * case, not an error.
 */
export function resolvePath(root, path, rootLine = 1) {
  const segs = typeof path === 'string' ? parsePath(path) : path;
  let current = [hit(root, lineOf(root, rootLine))];

  for (const seg of segs) {
    const next = [];
    for (const { value, line } of current) {
      if (value === null || value === undefined) continue;

      if (seg.deep) {
        for (const d of descendants(value, line)) next.push(d);
        continue;
      }

      if (seg.key !== undefined) {
        if (typeof value !== 'object' || Array.isArray(value)) continue;
        if (!(seg.key in value)) continue;
        const child = value[seg.key];
        next.push(hit(child, lineOf(child, line)));
      } else if (seg.index !== undefined) {
        if (!Array.isArray(value)) continue;
        const child = value[seg.index];
        if (child === undefined) continue;
        next.push(hit(child, lineOf(child, line)));
      } else {
        const children = Array.isArray(value)
          ? value
          : (typeof value === 'object' ? Object.values(value) : []);
        for (const child of children) next.push(hit(child, lineOf(child, line)));
      }
    }
    current = next;
  }

  return current;
}

const MAX_DEPTH = 24;

/** The node itself plus every nested container, breadth-first and depth-capped. */
function descendants(root, rootLine) {
  const out = [];
  const queue = [{ value: root, line: rootLine, depth: 0 }];
  while (queue.length) {
    const cur = queue.shift();
    out.push({ value: cur.value, line: cur.line });
    if (cur.depth >= MAX_DEPTH) continue;
    const { value, line } = cur;
    if (value === null || typeof value !== 'object') continue;
    const children = Array.isArray(value) ? value : Object.values(value);
    for (const child of children) {
      if (child !== null && typeof child === 'object') {
        queue.push({ value: child, line: lineOf(child, line), depth: cur.depth + 1 });
      }
    }
  }
  return out;
}

export { LINE };
