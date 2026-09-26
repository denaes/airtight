#!/usr/bin/env node
// Compile engine/rules/*.yaml into a single validated JSON bundle.
//
// YAML is the authoring format because rules are read by humans far more often
// than by the engine. JSON is the runtime format because the shipped engine has
// to run from one bundled file with nothing installed. Validation happens here,
// at build time, so a malformed rule fails the build rather than silently
// matching nothing and reporting a domain as clean.

import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { compileAll } from '../engine/src/rules.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SRC = join(ROOT, 'engine', 'rules');
const OUT = join(ROOT, 'engine', 'build', 'rules.json');

function main() {
  const files = readdirSync(SRC).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml')).sort();
  if (files.length === 0) {
    console.error(`compile-rules: no rule files in ${SRC}`);
    return 1;
  }

  const all = [];
  for (const file of files) {
    let parsed;
    try {
      parsed = parse(readFileSync(join(SRC, file), 'utf8'));
    } catch (err) {
      console.error(`compile-rules: ${file} is not valid YAML: ${err.message}`);
      return 1;
    }
    if (!Array.isArray(parsed)) {
      console.error(`compile-rules: ${file} must be a top-level array of rules`);
      return 1;
    }
    all.push(...parsed);
  }

  // Compiling is the validation. Anything malformed throws with the rule id.
  let compiled;
  try {
    compiled = compileAll(all);
  } catch (err) {
    console.error(`compile-rules: ${err.message}`);
    return 1;
  }

  mkdirSync(dirname(OUT), { recursive: true });
  // Stable key order so the bundle diffs cleanly between runs.
  const sorted = [...all].sort((a, b) => a.id.localeCompare(b.id));
  writeFileSync(OUT, `${JSON.stringify(sorted, null, 2)}\n`);

  const packs = new Map();
  for (const r of compiled) packs.set(r.pack, (packs.get(r.pack) ?? 0) + 1);
  const summary = [...packs].map(([p, n]) => `${p}=${n}`).join(' ');
  const immediate = compiled.filter((r) => r.tier === 'immediate').length;
  console.log(`compile-rules: ${compiled.length} rules (${summary}), ${immediate} in the immediate tier -> ${OUT.replace(ROOT + '/', '')}`);
  return 0;
}

process.exit(main());
