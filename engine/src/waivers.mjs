// Inline waivers.
//
// The narrowest escape hatch in the suppression ladder, and the only one that
// lives in the code rather than in config. Works in any comment syntax because
// we only look for the marker, never for the comment delimiters around it.
//
//   airtight-disable <rule>            whole file
//   airtight-disable-line <rule>       this line
//   airtight-disable-next-line <rule>  the following line
//
// `<rule>` may be a comma-separated list, or `*` for every rule. An optional
// reason follows after `:` or `--`.

const MARKER = /airtight-disable(-next-line|-line)?\s+([^\n]*)/g;

function parseRules(tail) {
  const reason = tail.split(/\s+--\s+|:\s+/)[0];
  return reason
    .split(',')
    .map((r) => r.trim())
    .filter(Boolean);
}

function ruleListMatches(list, ruleId) {
  return list.some((r) => r === '*' || r === ruleId);
}

/**
 * Returns a predicate `(ruleId, lineNumber) => boolean`, true when the rule is
 * waived at that 1-indexed line.
 */
export function buildWaiverIndex(lines) {
  const fileWide = [];
  /** @type {Map<number, string[]>} 1-indexed line -> waived rules */
  const perLine = new Map();

  lines.forEach((text, i) => {
    MARKER.lastIndex = 0;
    let m;
    while ((m = MARKER.exec(text)) !== null) {
      const scope = m[1];
      const rules = parseRules(m[2]);
      if (rules.length === 0) continue;

      if (scope === '-line') {
        push(perLine, i + 1, rules);
      } else if (scope === '-next-line') {
        push(perLine, i + 2, rules);
      } else {
        fileWide.push(...rules);
      }
    }
  });

  return (ruleId, line) =>
    ruleListMatches(fileWide, ruleId) ||
    ruleListMatches(perLine.get(line) ?? [], ruleId);
}

function push(map, line, rules) {
  const existing = map.get(line);
  if (existing) existing.push(...rules);
  else map.set(line, [...rules]);
}
