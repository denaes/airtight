// The text tier: line-scoped regex with context gates.
//
// Three gates, in the order impeccable found necessary:
//   require_regex  file must contain this at all, else the rule stands down
//   regex          finds candidates on a line
//   not_regex      tested against the whole line, kills false positives
//
// Capture group 1, when present, is the value: the credential, the font name,
// the interpolated expression. It is what gets fingerprinted, redacted, and
// offered back in the pre-filled waiver command.

import { makeFinding } from '../findings.mjs';
import { fingerprint } from '../redact.mjs';

const MAX_SNIPPET = 160;

/**
 * Is this offset inside a quoted string?
 *
 * Added after express reported `eval(` as dynamic code execution four times,
 * every one of them inside an XSS test vector written as a string literal:
 *   var xss = 'javascript:eval(document.body.innerHTML=...)';
 * A dangerous construct quoted as data is data. Single-line scan, which is
 * what the text tier works on anyway.
 */
function insideString(line, index) {
  let quote = null;
  for (let i = 0; i < index; i += 1) {
    const c = line[i];
    if (c === '\\') { i += 1; continue; }
    if (quote) { if (c === quote) quote = null; continue; }
    if (c === '"' || c === "'" || c === '`') quote = c;
  }
  return quote !== null;
}

function truncate(text) {
  const t = text.trim();
  return t.length > MAX_SNIPPET ? `${t.slice(0, MAX_SNIPPET - 1)}…` : t;
}

export function matchText(rule, { content, lines, relPath, vault, isWaived, sensitiveFile }) {
  if (rule.requireRe) {
    rule.requireRe.lastIndex = 0;
    if (!rule.requireRe.test(content)) return [];
  }

  const findings = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const lineNo = i + 1;
    if (isWaived(rule.id, lineNo)) continue;

    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(line)) !== null) {
      // A zero-width match would spin forever.
      if (m[0] === '') { rule.re.lastIndex += 1; continue; }

      if (rule.notRe) {
        rule.notRe.lastIndex = 0;
        if (rule.notRe.test(line)) break;
      }

      if (rule.match?.in_string === false && insideString(line, m.index)) continue;

      const value = m[1] ?? m[0];
      let valueFingerprint;
      let display;

      if (rule.redact) {
        valueFingerprint = fingerprint(value);
        display = vault.register(value);
        // Register the full match too when it is wider than the capture, so a
        // surrounding quoted form cannot leak the value through the snippet.
        if (m[0] !== value) vault.register(m[0]);
      }

      // Showing the whole line is the useful default, but inside a file that is
      // credentials by definition the rest of the line is someone else's secret
      // that no rule happened to recognize. There, show only what matched.
      const showCaptureOnly = rule.snippet === 'capture' || sensitiveFile;
      const raw = showCaptureOnly ? m[0] : line;

      // Mask at construction, not at render. The vault scrubbing output is the
      // second layer; this is the first. A Finding must never hold the
      // credential, because the findings store and the hook both serialize
      // findings directly and neither should have to remember to scrub.
      const snippet = truncate(display ? raw.split(value).join(display) : raw);

      findings.push(makeFinding(rule, {
        file: relPath,
        line: lineNo,
        column: m.index + 1,
        snippet,
        valueFingerprint,
      }));

      // One finding per rule per line. Repeating the same taxonomy on one line
      // is noise, and the budget is better spent on the next file.
      break;
    }
  }

  return findings;
}
