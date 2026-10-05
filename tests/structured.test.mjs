// Structured-tier behaviour that is not covered by any single rule's corpus.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDockerfile } from '../engine/src/parse/dockerfile.mjs';
import { parseStructured } from '../engine/src/parse/structured.mjs';
import { resolvePath } from '../engine/src/match/path.mjs';
import { evaluateAll } from '../engine/src/match/predicates.mjs';
import { lineOf } from '../engine/src/parse/node.mjs';

const DOCKERFILE = `FROM golang:1.23 AS builder
WORKDIR /src
RUN go build -o /out/app .

FROM gcr.io/distroless/static
COPY --from=builder /out/app /app
USER 10001
ENTRYPOINT ["/app"]
`;

test('stages carry the line of their own FROM', () => {
  // Regression: stage lines were read from a plain `.line` property while line
  // provenance lives on a symbol, so every stage reported line 1 and findings
  // about the final stage pointed at the first one.
  const doc = parseDockerfile(DOCKERFILE);
  assert.equal(doc.stages.length, 2);
  assert.equal(lineOf(doc.stages[0]), 1);
  assert.equal(lineOf(doc.stages[1]), 5);
  assert.equal(lineOf(doc.finalStage), 5);
});

test('finalStage is the stage that ships, not the flat instruction list', () => {
  const doc = parseDockerfile(DOCKERFILE);
  const flat = resolvePath(doc, 'instructions[*].name').map((h) => h.value);
  const final = resolvePath(doc, 'finalStage.instructions[*].name').map((h) => h.value);
  assert.ok(flat.includes('WORKDIR'), 'builder instructions appear in the flat list');
  assert.ok(!final.includes('WORKDIR'), 'and not in the final stage');
  assert.ok(final.includes('USER'));
});

test('line continuations join into one instruction', () => {
  const doc = parseDockerfile('FROM alpine\nRUN a \\\n && b \\\n && c\nUSER x\n');
  const run = doc.instructions.find((i) => i.name === 'RUN');
  assert.match(run.args, /a\s+&& b\s+&& c/);
  assert.equal(lineOf(run), 2, 'a joined instruction anchors at its first line');
});

test('not_matches holds vacuously on an empty set', () => {
  // This is how "this file never sets X" is expressed, which is most of
  // container and Kubernetes hardening. If it returned false on an empty set,
  // every one of those rules would silently stop firing.
  const doc = parseDockerfile('FROM alpine\nRUN true\n');
  const anchor = evaluateAll(
    [{ path: 'finalStage.instructions[*].name', not_matches: '^USER$' }], doc, 1);
  assert.notEqual(anchor, null);
});

test('multi-document YAML yields every document', () => {
  const { documents } = parseStructured(
    'kind: Deployment\nmetadata:\n  name: a\n---\nkind: Service\nmetadata:\n  name: b\n');
  assert.equal(documents.length, 2);
  assert.equal(documents[0].kind, 'Deployment');
  assert.equal(documents[1].kind, 'Service');
  assert.equal(lineOf(documents[1]), 5, 'the second document keeps its real line');
});

test('a malformed document is skipped rather than half-parsed', () => {
  // Guessing at a broken file is how a scanner reports a misconfiguration that
  // is not there, or misses one that is.
  const { documents } = parseStructured('a: [1, 2\nb: }{\n');
  assert.equal(documents.length, 0);
});

test('the $. prefix escapes the iterated node to the document root', () => {
  const { documents } = parseStructured(
    'on:\n  pull_request_target: {}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n');
  const doc = documents[0];
  const steps = resolvePath(doc, 'jobs.*.steps[*]');
  assert.equal(steps.length, 1);

  const withTrigger = evaluateAll(
    [{ path: 'uses', matches: '^actions/checkout@' }, { path: '$.on.pull_request_target', present: true }],
    steps[0].value, steps[0].line, doc, lineOf(doc));
  assert.notEqual(withTrigger, null);

  const withoutTrigger = evaluateAll(
    [{ path: '$.on.push', present: true }],
    steps[0].value, steps[0].line, doc, lineOf(doc));
  assert.equal(withoutTrigger, null);
});

test('"on" survives as a string key rather than a YAML 1.1 boolean', () => {
  const { documents } = parseStructured('on: [push]\njobs: {}\n');
  assert.deepEqual(Object.keys(documents[0]), ['on', 'jobs']);
});

test('path segments resolve maps, arrays, indices and wildcards', () => {
  const { documents } = parseStructured(
    'jobs:\n  a:\n    steps:\n      - uses: one\n      - uses: two\n  b:\n    steps:\n      - uses: three\n');
  const doc = documents[0];
  assert.deepEqual(resolvePath(doc, 'jobs.*.steps[*].uses').map((h) => h.value), ['one', 'two', 'three']);
  assert.deepEqual(resolvePath(doc, 'jobs.a.steps[1].uses').map((h) => h.value), ['two']);
  assert.deepEqual(resolvePath(doc, 'jobs.missing.steps[*]'), [], 'a missing path yields nothing, not an error');
});

test('YAML entity expansion bomb (billion laughs) is mitigated without memory exhaustion', () => {
  const bomb = `
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
`;
  const start = Date.now();
  const { documents } = parseStructured(bomb);
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 200, `YAML bomb handled in ${elapsed}ms`);
  assert.equal(documents.length, 1);
});
