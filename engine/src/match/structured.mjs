// The structured tiers: dockerfile, yaml, json, hcl.
//
// Shape of a structured rule:
//
//   parse: yaml
//   for_each: jobs.*.steps[*]     # optional; omit to assert on the document
//   assert:
//     all:
//       - { path: uses, matches: '...' }
//       - { path: uses, not_matches: '^(actions|github)/' }
//
// Every condition in `all` must hold for the rule to fire. The finding is
// anchored at the line of the first condition that had a location, falling back
// to the iterated node and then the document.

import { makeFinding } from '../findings.mjs';
import { parseFor } from '../parse/index.mjs';
import { resolvePath } from './path.mjs';
import { evaluateAll, evaluateAny } from './predicates.mjs';
import { lineOf } from '../parse/node.mjs';
import { NO_ANCHOR } from './predicates.mjs';

const MAX_SNIPPET = 160;
const TEMPLATE = /\{\{\s*([^}\s]+)\s*\}\}/g;

/**
 * Rule messages may interpolate `{{path}}` from the matched node, so a finding
 * can name the offending value rather than restating the rule. An unresolved
 * path renders as `?` instead of leaking the template at the user.
 */
function renderTemplate(text, node, nodeLine) {
  if (!text.includes('{{')) return text;
  return text.replace(TEMPLATE, (_, path) => {
    const hits = resolvePath(node, path, nodeLine);
    const value = hits.find((h) => h.value !== null && h.value !== undefined)?.value;
    return value === undefined ? '?' : String(value);
  });
}

function snippetAt(lines, line) {
  const text = (lines[line - 1] ?? '').trim();
  return text.length > MAX_SNIPPET ? `${text.slice(0, MAX_SNIPPET - 1)}…` : text;
}

export function matchStructured(rule, { content, lines, relPath, parseCache, isWaived }) {
  const conditions = rule.assert?.all ?? [];
  const alternatives = rule.assert?.any ?? [];
  if (conditions.length === 0 && alternatives.length === 0) return [];

  const { documents } = parseFor(rule.parse, content, parseCache);
  const findings = [];

  for (const doc of documents) {
    const docLine = lineOf(doc, 1);
    // for_each may be a list. initContainers are a real privilege-escalation
    // path, so a container rule that only covered `containers` would miss the
    // half an attacker actually reaches for.
    const paths = rule.for_each
      ? (Array.isArray(rule.for_each) ? rule.for_each : [rule.for_each])
      : null;
    const nodes = paths
      ? paths.flatMap((pth) => resolvePath(doc, pth, docLine))
      : [{ value: doc, line: docLine }];

    for (const { value: node, line: nodeLine } of nodes) {
      if (node === null || node === undefined) continue;

      const anchor = conditions.length
        ? evaluateAll(conditions, node, nodeLine, doc, docLine)
        : NO_ANCHOR;
      if (anchor === null) continue;

      // `any` narrows an `all` match: every condition in `all` must hold, and
      // then at least one alternative must too.
      let alt = NO_ANCHOR;
      if (alternatives.length) {
        alt = evaluateAny(alternatives, node, nodeLine, doc, docLine);
        if (alt === null) continue;
      }

      const line = anchor.line ?? alt?.line ?? nodeLine ?? docLine;
      if (isWaived(rule.id, line)) continue;

      findings.push(makeFinding(
        { ...rule, message: renderTemplate(rule.message, node, nodeLine) },
        { file: relPath, line, column: 1, snippet: snippetAt(lines, line) },
      ));
    }
  }

  return findings;
}
