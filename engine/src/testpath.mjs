// Test-context awareness.
//
// Added after measuring against real repositories: 24 of 32 false positives
// on clean, well-maintained code were test files. fastify disabling TLS
// verification against its own self-signed test server, requests round-
// tripping pickle, committed test certificates. Every one of those is the
// correct way to test the thing, and reporting them as P0 is how a security
// tool gets uninstalled in its first hour.
//
// The answer is not to skip tests. A real credential in a test file is a real
// leak, and test code often ships. The answer is that rules declare what test
// context means for them.

const TEST_PATH = [
  /(^|\/)(tests?|__tests__|spec|e2e|integration-tests?)\//i,
  /(^|\/)(testdata|fixtures|__fixtures__|__mocks__|mocks|testing)\//i,
  /(^|\/)[^/]*\.(test|spec)\.[a-z]+$/i,
  /(^|\/)(test_[^/]+|[^/]+_test)\.(py|go|rb)$/i,
  /(^|\/)conftest\.py$/i,
  /(^|\/)[^/]*\.stories\.[a-z]+$/i,
];

export function isTestPath(relPath) {
  return TEST_PATH.some((re) => re.test(relPath));
}

/**
 * How a rule behaves in a test path.
 *
 *   report     unchanged. For findings that are just as bad in a test: a real
 *              provider credential, a workflow that executes untrusted code.
 *   downgrade  fires with confidence reduced one step, and never in the
 *              immediate tier. The default, because most findings in tests are
 *              worth knowing about and not worth interrupting for.
 *   ignore     does not fire. Only where the construct is the standard,
 *              correct way to test the thing it describes.
 */
export const TEST_MODES = ['report', 'downgrade', 'ignore'];

const WEAKER = { confirmed: 'firm', firm: 'tentative', tentative: 'tentative' };

/** Returns the rule as it applies to this file, or null if it should not fire. */
export function applyTestMode(rule, inTest) {
  if (!inTest) return rule;
  const mode = rule.tests ?? 'downgrade';
  if (mode === 'ignore') return null;
  if (mode === 'report') return rule;
  return { ...rule, confidence: WEAKER[rule.confidence], tier: 'deep', inTest: true };
}
