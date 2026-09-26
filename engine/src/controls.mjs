// The control register.
//
// CONTROLS.md is prose for humans; .airtight/controls.json is its machine
// form. One entry per control, carrying the statement, the rules that verify
// it, and its mapping into each compliance framework.
//
// The claim this structure exists to support: a control whose verification
// points at a deterministic rule is proven at every commit, with a failing
// file and line when it breaks. Compliance platforms check that a policy
// document exists and a console setting is toggled. This checks the code.

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { matchesGlob } from './glob.mjs';

export const CONTROLS_PATH = '.airtight/controls.json';

export const CONTROL_STATUSES = ['enforced', 'partial', 'planned', 'not-applicable'];

/**
 * holding       every rule verifier is clean
 * failing       at least one rule verifier produced findings
 * unverifiable  the control declares no rule verifier, so the engine cannot
 *               speak to it. Reported distinctly from holding, because
 *               "nothing checked this" and "this was checked and passed" are
 *               the two claims an auditor most needs told apart.
 * broken        a verifier names a rule that does not exist
 */
export const VERDICTS = ['holding', 'failing', 'unverifiable', 'broken'];

export function loadControls(root) {
  const path = join(root, CONTROLS_PATH);
  if (!existsSync(path)) return { schemaVersion: 1, controls: [] };
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return { schemaVersion: parsed.schemaVersion ?? 1, controls: parsed.controls ?? [] };
  } catch (err) {
    throw new Error(`${CONTROLS_PATH} is not valid JSON: ${err.message}`);
  }
}

const ruleRefs = (control) => (control.verification ?? [])
  .filter((v) => typeof v === 'string' && v.startsWith('rule:'))
  .map((v) => v.slice(5));

const otherRefs = (control) => (control.verification ?? [])
  .filter((v) => typeof v === 'string' && !v.startsWith('rule:'));

/**
 * Verify every control against a set of findings.
 *
 * `knownRuleIds` is not optional and not cosmetic. A verifier naming a rule
 * that does not exist matches nothing, produces no findings, and would
 * otherwise report the control as holding. That is the compliance version of
 * a rule that silently never fires, and it is worse, because the output is an
 * assurance someone signs their name to.
 */
export function verifyControls(controls, findings, knownRuleIds) {
  const known = knownRuleIds instanceof Set ? knownRuleIds : new Set(knownRuleIds);

  return controls.map((control) => {
    const refs = ruleRefs(control);
    const manual = otherRefs(control);

    const unknown = refs.filter((ref) => (ref.includes('*')
      ? ![...known].some((id) => matchesGlob(id, ref))
      : !known.has(ref)));

    if (unknown.length) {
      return {
        id: control.id,
        name: control.name,
        verdict: 'broken',
        reason: `verification names ${unknown.length === 1 ? 'a rule' : 'rules'} that do not exist: ${unknown.join(', ')}`,
        failures: [],
        manual,
      };
    }

    if (refs.length === 0) {
      return {
        id: control.id,
        name: control.name,
        verdict: 'unverifiable',
        reason: manual.length
          ? `no rule verifier; relies on ${manual.join(', ')}`
          : 'no verification declared',
        failures: [],
        manual,
      };
    }

    const failures = findings.filter((f) =>
      refs.some((ref) => (ref.includes('*') ? matchesGlob(f.rule, ref) : f.rule === ref)));

    return {
      id: control.id,
      name: control.name,
      verdict: failures.length ? 'failing' : 'holding',
      reason: failures.length
        ? `${failures.length} finding(s) from ${refs.join(', ')}`
        : `clean against ${refs.join(', ')}`,
      failures: failures.map((f) => ({ rule: f.rule, at: `${f.file}:${f.line}`, severity: f.severity })),
      manual,
    };
  });
}

/**
 * Project the register onto one framework. This is why the register exists in
 * this shape: SOC 2, ISO 27001 and PCI are largely the same controls under
 * different numbering, so the work is mapping once and rendering many times.
 */
export function frameworkCoverage(controls, framework, results) {
  const byId = new Map(results.map((r) => [r.id, r]));
  const coverage = new Map();

  for (const control of controls) {
    for (const ref of control.frameworks?.[framework] ?? []) {
      if (!coverage.has(ref)) coverage.set(ref, []);
      coverage.get(ref).push({
        control: control.id,
        status: control.status,
        verdict: byId.get(control.id)?.verdict ?? 'unverifiable',
      });
    }
  }

  return [...coverage.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([ref, entries]) => ({
      reference: ref,
      controls: entries,
      // A framework reference is only satisfied when every control mapped to
      // it is both declared enforced and verified holding. Either half alone
      // is a claim without evidence.
      satisfied: entries.every((e) => e.status === 'enforced' && e.verdict === 'holding'),
    }));
}

export function frameworksIn(controls) {
  const out = new Set();
  for (const c of controls) for (const f of Object.keys(c.frameworks ?? {})) out.add(f);
  return [...out].sort();
}
