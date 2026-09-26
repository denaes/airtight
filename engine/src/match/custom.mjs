// The js tier: rules whose detection cannot be expressed as a pattern.
//
// Analyzers are registered statically rather than imported by path, so the
// shipped engine can be a single bundled file. An analyzer returns hits, never
// findings: metadata still comes from the registry, so the registry/matcher
// split holds here exactly as it does for regex rules.

import { makeFinding } from '../findings.mjs';
import { fingerprint } from '../redact.mjs';
import * as entropy from '../../custom/entropy.mjs';

const ANALYZERS = { entropy };

export const ANALYZER_NAMES = Object.keys(ANALYZERS);

const MAX_SNIPPET = 160;

export function matchCustom(rule, ctx) {
  const analyzer = ANALYZERS[rule.script];
  if (!analyzer) throw new Error(`unknown analyzer "${rule.script}"`);

  const { lines, relPath, vault, isWaived, sensitiveFile } = ctx;
  const findings = [];

  for (const hit of analyzer.check({ ...ctx, rule })) {
    if (isWaived(rule.id, hit.line)) continue;

    const value = hit.value ?? '';
    let valueFingerprint;
    let display;
    if (rule.redact && value) {
      valueFingerprint = fingerprint(value);
      display = vault.register(value);
    }

    const raw = hit.snippet ?? (rule.snippet === 'capture' || sensitiveFile
      ? value
      : (lines[hit.line - 1] ?? '').trim());
    const masked = display ? raw.split(value).join(display) : raw;

    findings.push(makeFinding(rule, {
      file: relPath,
      line: hit.line,
      column: hit.column ?? 1,
      snippet: masked.length > MAX_SNIPPET ? `${masked.slice(0, MAX_SNIPPET - 1)}…` : masked,
      valueFingerprint,
    }));
  }

  return findings;
}
