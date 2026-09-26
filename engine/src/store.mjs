// The findings store.
//
// A scan answers "what is wrong right now". The store answers the questions
// that actually run a security program: what is new since last time, what did
// we accept and why, what regressed after we fixed it, and what is past its
// remediation deadline.
//
// Format is newline-delimited JSON sorted by id, not a directory of files and
// not one big array. Sorted NDJSON means two branches that each add a finding
// produce edits on different lines, so git merges them without a conflict, and
// `grep` still works on it.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { SLA_DAYS } from './findings.mjs';

export const STORE_PATH = '.airtight/findings.ndjson';

/**
 * open      detected, not yet acted on
 * verified  an exploit or a reviewer confirmed it is real and reachable
 * accepted  a human accepted the risk; requires a waiver with an approver
 * fixed     no longer detected
 * regressed detected again after having been fixed
 */
export const STATUSES = ['open', 'verified', 'accepted', 'fixed', 'regressed'];

const ACTIVE = new Set(['open', 'verified', 'regressed']);

export function isActive(record) {
  return ACTIVE.has(record.status);
}

export function load(root) {
  const path = join(root, STORE_PATH);
  if (!existsSync(path)) return new Map();
  const out = new Map();
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const rec = JSON.parse(line);
      if (rec?.id) out.set(rec.id, rec);
    } catch {
      // A corrupt line is skipped rather than fatal. Losing one record is
      // recoverable; refusing to run the scan at all is not.
    }
  }
  return out;
}

export function save(root, records) {
  const path = join(root, STORE_PATH);
  mkdirSync(dirname(path), { recursive: true });
  const lines = [...records.values()]
    .sort((a, b) => a.id.localeCompare(b.id))
    .map((r) => JSON.stringify(r));
  writeFileSync(path, lines.length ? `${lines.join('\n')}\n` : '');
  return lines.length;
}

const day = 86_400_000;

export function dueDate(firstSeen, severity) {
  const days = SLA_DAYS[severity] ?? SLA_DAYS.low;
  return new Date(Date.parse(firstSeen) + days * day).toISOString();
}

/**
 * Reconcile a scan against the store.
 *
 * The important cases are the ones a plain scan cannot express:
 *
 *   fixed -> regressed   we closed this and it came back. That is a different
 *                        event from finding it the first time, and it usually
 *                        means the fix never reached the place it needed to.
 *   accepted stays       an accepted risk is not re-raised every run, but an
 *                        expired waiver is, because acceptance was time-boxed
 *                        on purpose.
 *   active -> fixed      no longer detected. Recorded rather than deleted, so
 *                        the trend survives and a regression is detectable.
 */
export function reconcile(store, findings, { now = new Date().toISOString() } = {}) {
  const seen = new Set();
  const events = { added: 0, regressed: 0, fixed: 0, unchanged: 0, waiverExpired: 0 };
  const next = new Map(store);

  for (const f of findings) {
    seen.add(f.id);
    const prior = next.get(f.id);

    if (!prior) {
      next.set(f.id, {
        id: f.id,
        rule: f.rule,
        title: f.title,
        domain: f.domain,
        severity: f.severity,
        confidence: f.confidence,
        disposition: f.disposition,
        cwe: f.cwe,
        owasp: f.owasp,
        location: `${f.file}:${f.line}`,
        status: 'open',
        provenance: f.provenance,
        evidence: [],
        owner: null,
        firstSeen: now,
        lastSeen: now,
        due: dueDate(now, f.severity),
        ...(f.valueFingerprint ? { valueFingerprint: f.valueFingerprint } : {}),
      });
      events.added += 1;
      continue;
    }

    const updated = { ...prior, lastSeen: now, location: `${f.file}:${f.line}` };

    if (prior.status === 'fixed') {
      updated.status = 'regressed';
      updated.regressedAt = now;
      events.regressed += 1;
    } else if (prior.status === 'accepted' && prior.waiver?.expires
      && Date.parse(prior.waiver.expires) < Date.parse(now)) {
      // Acceptance was time-boxed. When the box runs out the finding comes
      // back on its own, which is the whole point of putting an expiry on it.
      updated.status = 'open';
      updated.waiverExpiredAt = now;
      events.waiverExpired += 1;
    } else {
      events.unchanged += 1;
    }

    next.set(f.id, updated);
  }

  for (const [id, rec] of next) {
    if (seen.has(id) || !isActive(rec)) continue;
    next.set(id, { ...rec, status: 'fixed', fixedAt: now });
    events.fixed += 1;
  }

  return { records: next, events };
}

export function accept(store, id, { reason, approver, expires, now = new Date().toISOString() }) {
  const rec = store.get(id);
  if (!rec) throw new Error(`no finding with id ${id}`);
  if (!reason || !approver) {
    // An acceptance with no named approver is an anonymous decision, which is
    // indistinguishable from nobody having decided.
    throw new Error('accepting a finding requires both --reason and --approver');
  }
  const next = new Map(store);
  next.set(id, { ...rec, status: 'accepted', waiver: { reason, approver, expires: expires ?? null, acceptedAt: now } });
  return next;
}

export function overdue(store, now = new Date().toISOString()) {
  const t = Date.parse(now);
  return [...store.values()].filter((r) => isActive(r) && r.due && Date.parse(r.due) < t);
}

export function summarize(store) {
  const byStatus = {};
  const bySeverity = {};
  for (const r of store.values()) {
    byStatus[r.status] = (byStatus[r.status] ?? 0) + 1;
    if (isActive(r)) bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1;
  }
  return { total: store.size, byStatus, bySeverity };
}
