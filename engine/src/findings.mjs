// The Finding shape, and the severity/confidence/priority model.
//
// Three orthogonal axes, because severity alone is what makes security tooling
// unusable:
//   severity    exploitability x impact      drives the remediation SLA
//   confidence  how sure the engine is       drives whether we interrupt you
//   disposition what should happen next      drives who acts

import { createHash } from 'node:crypto';

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const CONFIDENCES = ['confirmed', 'firm', 'tentative'];
export const DISPOSITIONS = ['fix', 'verify', 'accept', 'route'];

/**
 * Presentation priority is derived, never authored. The rule that matters: a
 * `tentative` finding can never present as P0. Reachability has to be proven by
 * the model layer or by `airtight exploit` before we tell someone to drop
 * everything.
 */
const PRIORITY = {
  critical: { confirmed: 'P0', firm: 'P0', tentative: 'P1' },
  high:     { confirmed: 'P1', firm: 'P1', tentative: 'P2' },
  medium:   { confirmed: 'P2', firm: 'P2', tentative: 'P3' },
  low:      { confirmed: 'P3', firm: 'P3', tentative: 'P3' },
};

/** Remediation SLA in days, by severity. Feeds the findings store `due` field. */
export const SLA_DAYS = { critical: 7, high: 30, medium: 90, low: 180 };

export function priorityOf(severity, confidence, { inTest = false } = {}) {
  const p = PRIORITY[severity]?.[confidence] ?? 'P3';
  // P0 means drop everything. A finding in a test path almost never does,
  // and a confidence downgrade alone does not help: critical + firm is still
  // P0. Measured against real repositories, committed test certificates were
  // reporting at P0 purely for sitting in tests/certs.
  return inTest && p === 'P0' ? 'P1' : p;
}

/**
 * A finding's identity must survive reformatting and line drift, or the store
 * reports every prettier run as a fresh vulnerability. Identity is therefore
 * rule + file + the matched value's fingerprint, and falls back to the line
 * number only when there is no value to fingerprint.
 */
export function findingId({ rule, file, valueFingerprint, line }) {
  const basis = valueFingerprint
    ? `${rule}\u0000${file}\u0000${valueFingerprint}`
    : `${rule}\u0000${file}\u0000L${line}`;
  return createHash('sha256').update(basis).digest('hex').slice(0, 12);
}

/**
 * Build a Finding. Metadata comes from the rule registry; a matcher only ever
 * supplies where it fired and what it saw. That is impeccable's registry/matcher
 * split: one place to audit the taxonomy, many places to implement detection.
 */
export function makeFinding(rule, { file, line, column = 0, snippet, valueFingerprint }) {
  const severity = rule.severity;
  const confidence = rule.confidence;
  return {
    id: findingId({ rule: rule.id, file, valueFingerprint, line }),
    rule: rule.id,
    title: rule.name,
    domain: rule.domain,
    severity,
    confidence,
    priority: priorityOf(severity, confidence, { inTest: Boolean(rule.inTest) }),
    disposition: rule.disposition ?? 'fix',
    cwe: rule.cwe ?? null,
    owasp: rule.owasp ?? null,
    file,
    line,
    column,
    snippet,
    message: rule.message,
    why: rule.why,
    fix: rule.fix,
    provenance: 'deterministic-rule',
    redacted: Boolean(rule.redact),
    ...(rule.inTest ? { inTest: true } : {}),
    ...(valueFingerprint ? { valueFingerprint } : {}),
  };
}

const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
const CONFIDENCE_RANK = Object.fromEntries(CONFIDENCES.map((c, i) => [c, i]));

/** Most severe first, then most confident, then stable by location. */
export function sortFindings(findings) {
  return [...findings].sort((a, b) =>
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence] ||
    a.file.localeCompare(b.file) ||
    a.line - b.line ||
    a.rule.localeCompare(b.rule));
}
