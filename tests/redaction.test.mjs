// The redaction gate.
//
// This is the one test whose failure would make airtight actively dangerous.
// Impeccable's design hook skips .env, *.pem and secrets.* on purpose; we have
// to read exactly those files, so nothing but total containment is acceptable.
//
// The assertion is deliberately crude: plant known values, drive every output
// path the engine has, and grep the bytes. A clever test here would be a worse
// test.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { ROOT, allRules } from './helpers.mjs';
import { scanFiles } from '../engine/src/scan.mjs';
import { renderJson, renderText } from '../engine/src/render.mjs';

// Synthetic, but shaped exactly like the real thing — which means airtight
// finds them when it scans its own repository, correctly. This is the narrowest
// rung of the suppression ladder, used the way the ladder intends: scoped to one
// file, naming the rules, with the evidence in the reason.
//
// Every value is assembled from parts rather than written whole. A committed
// literal in a provider's format is indistinguishable from a live credential
// to a secret scanner, and asking people to allowlist secrets in order to
// clone a security tool is a poor first impression. Assembly changes nothing
// about what the engine sees at scan time.
//
// airtight-disable secret/high-entropy-assignment -- synthetic values owned by this file; it is the redaction gate and needs real-shaped input
const j = (...parts) => parts.join('');
const PLANTED = {
  aws: j('AKIA', 'QYLPM6R4T7XZVN3K'),
  awsSecret: j('kQ8vN2mR7pL4wX9c', 'B3zF6hT1yU5oA0sD8gJ2eI7n'),
  github: j('ghp', '_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'),
  anthropic: j('sk-ant-', 'api03-', '9xKmQ7wR2nL5vB8cT4hY6jP1zA3sD0fG7uE9iO2r'),
  stripe: j('sk', '_live_', '51H8xKvLmNoPqRsTuVwXyZaBc'),
  // No rule recognizes this one. It rides inside a .env line whose only
  // matching rule fires on the variable name, which is exactly the shape that
  // leaks a secret through a neighbouring finding's snippet.
  unrecognized: 'correct-horse-battery-staple-9471',
};

function plantedCorpus() {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-redaction-'));
  writeFileSync(join(dir, 'config.ts'), [
    `export const awsKey = "${PLANTED.aws}";`,
    `export const awsSecret = { aws_secret_access_key: "${PLANTED.awsSecret}" };`,
    `export const gh = "${PLANTED.github}";`,
    `export const claude = "${PLANTED.anthropic}";`,
    `export const stripe = "${PLANTED.stripe}";`,
  ].join('\n'));
  writeFileSync(join(dir, '.env'), [
    `AWS_ACCESS_KEY_ID=${PLANTED.aws}`,
    `MAIL_PASSWORD=${PLANTED.unrecognized}`,
  ].join('\n'));
  return dir;
}

function everyOutputPath(dir) {
  const files = ['config.ts', '.env'].map((f) => join(dir, f));
  const { findings, vault } = scanFiles({
    root: dir, files, rules: allRules(), config: {}, isSuppressed: null,
  });
  const meta = { filesScanned: files.length, rulesApplied: allRules().length };
  return {
    findings,
    outputs: {
      text: renderText({ findings, vault, meta }),
      json: renderJson({ findings, vault, meta }),
      // The store and the hook both serialize findings directly. If the vault
      // were the renderer's job rather than the engine's, this is the path that
      // would leak.
      rawFindingsJson: vault.scrub(JSON.stringify(findings)),
    },
  };
}

test('no planted secret survives any in-process output path', () => {
  const dir = plantedCorpus();
  try {
    const { findings, outputs } = everyOutputPath(dir);
    assert.ok(findings.length > 0, 'corpus produced no findings, so the test proves nothing');

    const leaks = [];
    for (const [path, text] of Object.entries(outputs)) {
      for (const [name, value] of Object.entries(PLANTED)) {
        if (text.includes(value)) leaks.push(`${name} leaked via ${path}`);
      }
    }
    assert.deepEqual(leaks, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('no planted secret survives the CLI, in text or json mode', () => {
  const dir = plantedCorpus();
  try {
    const cli = resolve(ROOT, 'engine/src/cli.mjs');
    const env = { ...process.env, AIRTIGHT_RULES: resolve(ROOT, 'engine/build/rules.json') };
    const run = (args) => {
      try {
        return execFileSync(process.execPath, [cli, ...args], { cwd: dir, env, encoding: 'utf8' });
      } catch (err) {
        // Exit 2 means findings, which is the expected outcome here.
        if (err.status === 2) return `${err.stdout ?? ''}${err.stderr ?? ''}`;
        throw err;
      }
    };

    const leaks = [];
    for (const args of [['detect', '.'], ['detect', '--json', '.']]) {
      const out = run(args);
      assert.ok(out.length > 0, `no output from: ${args.join(' ')}`);
      for (const [name, value] of Object.entries(PLANTED)) {
        if (out.includes(value)) leaks.push(`${name} leaked via cli ${args.join(' ')}`);
      }
    }
    assert.deepEqual(leaks, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a redacted finding still carries a usable fingerprint', () => {
  const dir = plantedCorpus();
  try {
    const { findings } = everyOutputPath(dir);
    const aws = findings.filter((f) => f.rule === 'secret/aws-access-key-id');
    assert.ok(aws.length >= 2, 'the same key appears in two files and should be found in both');

    // One credential, two locations. Deliberately two findings, because
    // removing it from source is two edits — but a shared fingerprint, because
    // rotating it is one action. The store groups on the fingerprint so it says
    // "rotate this key" once and "delete this line" twice.
    assert.equal(aws[0].valueFingerprint, aws[1].valueFingerprint,
      'the same credential must fingerprint identically wherever it appears');
    assert.notEqual(aws[0].id, aws[1].id,
      'findings are located, so two locations are two findings');
    assert.ok(aws.every((f) => !f.snippet.includes(PLANTED.aws)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
