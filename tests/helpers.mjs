import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compileAll } from '../engine/src/rules.mjs';
import { scanFiles } from '../engine/src/scan.mjs';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

let cached;
export function allRules() {
  cached ??= compileAll(JSON.parse(readFileSync(resolve(ROOT, 'engine/build/rules.json'), 'utf8')));
  return cached;
}

/**
 * Scan one file with the full rule set and no suppression config.
 *
 * testMode is off because the corpus lives under fixtures/, which isTestPath
 * matches by design. The corpus is rule input rather than test code, and a
 * rule with `tests: ignore` still has to fire on its own true positives.
 * Test-context behaviour is covered separately in tests/testpath.test.mjs.
 */
export function scanOne(absPath, rules = allRules()) {
  return scanFiles({ root: ROOT, files: [absPath], rules, config: {}, isSuppressed: null, testMode: false });
}
