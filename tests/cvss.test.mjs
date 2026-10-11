import test from 'node:test';
import assert from 'node:assert/strict';
import { calculateCvss31, parseCvssVector, roundup } from '../engine/src/cvss.mjs';

test('roundup correctly handles CVSS 3.1 rounding rule', () => {
  assert.strictEqual(roundup(0.0), 0.0);
  assert.strictEqual(roundup(4.0), 4.0);
  assert.strictEqual(roundup(4.00000), 4.0);
  assert.strictEqual(roundup(4.01), 4.1);
  assert.strictEqual(roundup(4.0001), 4.1);
  assert.strictEqual(roundup(4.09), 4.1);
  assert.strictEqual(roundup(9.7601), 9.8);
});

test('calculateCvss31 calculates standard critical vulnerability (e.g. SQLi / RCE)', () => {
  // Typical critical RCE: Network, Low complexity, No privileges, No UI, Scope unchanged, High C/I/A
  const result = calculateCvss31({
    av: 'N',
    ac: 'L',
    pr: 'N',
    ui: 'N',
    s: 'U',
    c: 'H',
    i: 'H',
    a: 'H',
  });

  assert.strictEqual(result.score, 9.8);
  assert.strictEqual(result.severity, 'critical');
  assert.strictEqual(result.priority, 'P0');
  assert.strictEqual(result.vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
});

test('calculateCvss31 calculates Scope Changed maximum (Log4Shell CVE-2021-44228)', () => {
  // Log4Shell: Network, Low complexity, No privileges, No UI, Scope Changed, High C/I/A -> 10.0
  const result = calculateCvss31({
    av: 'N',
    ac: 'L',
    pr: 'N',
    ui: 'N',
    s: 'C',
    c: 'H',
    i: 'H',
    a: 'H',
  });

  assert.strictEqual(result.score, 10.0);
  assert.strictEqual(result.severity, 'critical');
  assert.strictEqual(result.priority, 'P0');
  assert.strictEqual(result.vector, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
});

test('calculateCvss31 calculates medium / low severity vulnerabilities', () => {
  // Stored XSS requiring user interaction: Network, Low complexity, Low Privileges, Required UI, Scope Changed, Low C, Low I, None A
  const xss = calculateCvss31({
    av: 'N',
    ac: 'L',
    pr: 'L',
    ui: 'R',
    s: 'C',
    c: 'L',
    i: 'L',
    a: 'N',
  });

  assert.strictEqual(xss.score, 5.4);
  assert.strictEqual(xss.severity, 'medium');
  assert.strictEqual(xss.priority, 'P2');

  // Zero impact yields none
  const zero = calculateCvss31({
    av: 'N',
    ac: 'L',
    pr: 'N',
    ui: 'N',
    s: 'U',
    c: 'N',
    i: 'N',
    a: 'N',
  });
  assert.strictEqual(zero.score, 0.0);
  assert.strictEqual(zero.severity, 'none');
  assert.strictEqual(zero.priority, 'P3');
});

test('parseCvssVector correctly parses valid CVSS 3.1 vector strings', () => {
  const vectorStr = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  const parsed = parseCvssVector(vectorStr);

  assert.strictEqual(parsed.score, 9.8);
  assert.strictEqual(parsed.severity, 'critical');
  assert.strictEqual(parsed.priority, 'P0');
  assert.strictEqual(parsed.vector, vectorStr);
});

test('parseCvssVector throws on invalid or missing metrics', () => {
  assert.throws(() => parseCvssVector('INVALID/VECTOR'), /Unsupported or invalid CVSS vector prefix/);
  assert.throws(() => parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N'), /Missing required CVSS metric/);
  assert.throws(() => parseCvssVector(12345), /CVSS vector must be a string/);
});
