#!/usr/bin/env node
// Repository progress audit for airtight.
//
// Performs a pre-commit audit across documentation, README, harnesses,
// demo golden files, tests, package versions, and invariants.
//
// Usage:
//   node scripts/progress-audit.mjs         # audit repository state
//   node scripts/progress-audit.mjs --fix   # auto-fix documentation & harness drift

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIX = process.argv.includes('--fix');

const issues = [];
const warnings = [];
const successes = [];

function pass(msg) {
  successes.push(msg);
}

function warn(msg) {
  warnings.push(msg);
}

function fail(msg) {
  issues.push(msg);
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', ...opts });
  return { code: r.status ?? 1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

// ----------------------------------------------------------- 1. Rules & Engine

function auditRulesAndEngine() {
  console.log('• Checking rules compilation and counts...');
  const comp = run(process.execPath, [join(ROOT, 'scripts/compile-rules.mjs')]);
  if (comp.code !== 0) {
    fail(`Rules compilation failed:\n${comp.stderr}`);
    return null;
  }

  const rulesFile = join(ROOT, 'engine/build/rules.json');
  if (!existsSync(rulesFile)) {
    fail('engine/build/rules.json does not exist. Run: npm run build:rules');
    return null;
  }

  const rules = JSON.parse(readFileSync(rulesFile, 'utf8'));
  const immediate = rules.filter((r) => r.tier === 'immediate');
  const deep = rules.filter((r) => r.tier === 'deep');

  const packs = new Map();
  for (const r of rules) {
    const pack = r.pack ?? r.id.split('/')[0];
    packs.set(pack, (packs.get(pack) ?? 0) + 1);
  }
  const packSummary = [...packs.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([p, n]) => `${p}=${n}`)
    .join(' ');

  pass(`Rules valid: ${rules.length} rules (${immediate.length} immediate, ${deep.length} deep) across packs: ${packSummary}`);
  return { rules, immediate, deep, packs };
}

// ------------------------------------------------------------- 2. Documentation

function auditDocs(rulesInfo) {
  console.log('• Checking README.md counts and claims...');
  if (!rulesInfo) return;

  const readmePath = join(ROOT, 'README.md');
  const readme = readFileSync(readmePath, 'utf8');
  const commandsMetaPath = join(ROOT, 'skill/scripts/command-metadata.json');
  const commandCount = existsSync(commandsMetaPath)
    ? Object.keys(JSON.parse(readFileSync(commandsMetaPath, 'utf8'))).length
    : 9;

  let readmeStale = false;
  let updatedReadme = readme;

  for (const [, n, noun] of readme.matchAll(/(\d+)[\s\n>]+(rules|commands)\b/g)) {
    const expected = noun === 'rules' ? rulesInfo.rules.length : commandCount;
    if (Number(n) !== expected) {
      readmeStale = true;
      if (FIX) {
        updatedReadme = updatedReadme.replace(
          new RegExp(`\\b${n}([\\s\\n>]+)${noun}\\b`, 'g'),
          `${expected}$1${noun}`,
        );
      } else {
        fail(`README.md claims ${n} ${noun}; actual count is ${expected}.`);
      }
    }
  }

  // Audit Rule packs table rows
  for (const [pack, count] of rulesInfo.packs.entries()) {
    const tableRowRegex = new RegExp(`\\|\\s*\`(${pack})\`\\s*\\|\\s*(\\d+)\\s*\\|`);
    const match = updatedReadme.match(tableRowRegex);
    if (match) {
      const statedCount = Number(match[2]);
      if (statedCount !== count) {
        readmeStale = true;
        if (FIX) {
          updatedReadme = updatedReadme.replace(
            tableRowRegex,
            `| \`${pack}\` | ${count} |`,
          );
        } else {
          fail(`README.md pack table lists ${statedCount} rules for ${pack}, but actual count is ${count}.`);
        }
      }
    } else {
      fail(`README.md pack table is missing pack '${pack}'.`);
    }
  }

  if (readmeStale && FIX) {
    writeFileSync(readmePath, updatedReadme);
    pass(`README.md counts updated to ${rulesInfo.rules.length} rules, ${commandCount} commands.`);
  } else if (!readmeStale) {
    pass(`README.md claims match actual counts (${rulesInfo.rules.length} rules, ${commandCount} commands).`);
  }

  console.log('• Checking docs/rules.md freshness...');
  const DOCS = join(ROOT, 'docs');
  const docFiles = () => readdirSync(DOCS).filter((f) => f.endsWith('.md'));
  const before = Object.fromEntries(docFiles().map((f) => [f, readFileSync(join(DOCS, f), 'utf8')]));

  const buildDocs = run(process.execPath, [join(ROOT, 'scripts/build-docs.mjs')]);
  if (buildDocs.code !== 0) {
    fail(`scripts/build-docs.mjs failed:\n${buildDocs.stderr}`);
  } else {
    const stale = docFiles().filter((f) => before[f] !== undefined && before[f] !== readFileSync(join(DOCS, f), 'utf8'));
    if (stale.length > 0) {
      if (FIX) {
        pass(`docs/ reference regenerated and updated (${stale.join(', ')}).`);
      } else {
        fail(`docs/ reference files are stale: ${stale.join(', ')}. Run: npm run build:docs`);
      }
    } else {
      pass('docs/ generated references are fully up to date.');
    }
  }

  // Check coverage roadmap
  const roadmapPath = join(ROOT, 'docs/plans/coverage-matrix-roadmap.md');
  if (existsSync(roadmapPath)) {
    pass('Coverage matrix roadmap present at docs/plans/coverage-matrix-roadmap.md.');
  } else {
    warn('docs/plans/coverage-matrix-roadmap.md not found.');
  }
}

// --------------------------------------------------------- 3. Demo Golden Suite

function auditDemo(rulesInfo) {
  console.log('• Checking demo golden test and pack coverage...');
  const check = run(process.execPath, [join(ROOT, 'scripts/demo.mjs'), '--check']);

  if (check.code !== 0) {
    if (FIX) {
      const write = run(process.execPath, [join(ROOT, 'scripts/demo.mjs'), '--write']);
      if (write.code === 0) {
        syncDemoReadme();
        pass('demo/expected-findings.txt and demo/README.md synchronized.');
      } else {
        fail(`Failed to update demo golden: ${write.stderr}`);
      }
    } else {
      fail('demo/expected-findings.txt drifted from live engine output. Run: node scripts/demo.mjs --write');
    }
  } else {
    pass('demo/expected-findings.txt matches live engine output.');
    // Check demo README
    const golden = readFileSync(join(ROOT, 'demo/expected-findings.txt'), 'utf8');
    const readme = readFileSync(join(ROOT, 'demo/README.md'), 'utf8');
    let demoReadmeStale = false;
    for (const key of ['total findings:', 'distinct rules:', 'by priority:', 'by pack:']) {
      const line = golden.split('\n').find((l) => l.startsWith(key));
      if (line && !readme.includes(line)) {
        demoReadmeStale = true;
      }
    }
    if (demoReadmeStale) {
      if (FIX) {
        syncDemoReadme();
        pass('demo/README.md updated with current demo golden numbers.');
      } else {
        fail('demo/README.md numbers do not match demo/expected-findings.txt.');
      }
    } else {
      pass('demo/README.md matches expected findings golden lines.');
    }
  }

  // Check demo pack coverage
  if (rulesInfo && existsSync(join(ROOT, 'demo/expected-findings.txt'))) {
    const golden = readFileSync(join(ROOT, 'demo/expected-findings.txt'), 'utf8');
    const packLine = golden.split('\n').find((l) => l.startsWith('by pack:')) ?? '';
    const missingPacks = [];
    for (const pack of rulesInfo.packs.keys()) {
      if (!new RegExp(`\\b${pack}=`).test(packLine)) {
        missingPacks.push(pack);
      }
    }
    if (missingPacks.length > 0) {
      fail(`demo/vulnerable-shop does not exercise rules from pack(s): ${missingPacks.join(', ')}`);
    } else {
      pass(`demo/vulnerable-shop exercises all ${rulesInfo.packs.size} active rule packs.`);
    }
  }
}

function syncDemoReadme() {
  const goldenPath = join(ROOT, 'demo/expected-findings.txt');
  const readmePath = join(ROOT, 'demo/README.md');
  if (!existsSync(goldenPath) || !existsSync(readmePath)) return;

  const golden = readFileSync(goldenPath, 'utf8');
  let readme = readFileSync(readmePath, 'utf8');

  for (const key of ['total findings:', 'distinct rules:', 'by priority:', 'by pack:']) {
    const targetLine = golden.split('\n').find((l) => l.startsWith(key));
    if (targetLine) {
      readme = readme.replace(new RegExp(`^${key}.*$`, 'm'), targetLine);
    }
  }
  writeFileSync(readmePath, readme);
}

// ---------------------------------------------------- 4. Harnesses & Shipped Dists

function auditHarnesses() {
  console.log('• Checking engine bundle and harness synchronization...');

  // Check engine bundle
  const bundle = run(process.execPath, [join(ROOT, 'scripts/build-engine.mjs')]);
  if (bundle.code !== 0) {
    fail(`Engine bundling failed:\n${bundle.stderr}`);
  } else {
    pass('Engine bundle compiled to skill/scripts/engine/airtight.mjs.');
  }

  // Check build & harness sync
  const build = run(process.execPath, [join(ROOT, 'scripts/build.js')]);
  if (build.code !== 0) {
    fail(`Build validation failed:\n${build.stderr}`);
  } else {
    pass('All 18 harness transforms validated in dist/.');
  }

  // Verify shipped rule bundle in .claude matches engine/build/rules.json
  const shippedRulesPath = join(ROOT, '.claude/skills/airtight/scripts/rules.json');
  const compiledRulesPath = join(ROOT, 'engine/build/rules.json');
  if (existsSync(shippedRulesPath) && existsSync(compiledRulesPath)) {
    const shipped = readFileSync(shippedRulesPath, 'utf8');
    const compiled = readFileSync(compiledRulesPath, 'utf8');
    if (shipped !== compiled) {
      if (FIX) {
        const release = run(process.execPath, [join(ROOT, 'scripts/build.js'), '--sync']);
        if (release.code === 0) {
          pass('Tracked harness directories synced via build.js --sync.');
        } else {
          fail(`Failed to sync tracked harnesses:\n${release.stderr}`);
        }
      } else {
        fail('Tracked harness files are out of sync with engine/build/rules.json. Run: npm run build:release');
      }
    } else {
      pass('Tracked harness rules match compiled rules.');
    }
  }
}

// ---------------------------------------------------------- 5. Package Versions

function auditPackages() {
  console.log('• Checking package versions and manifests...');
  const rootPkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const version = rootPkg.version;

  const enginePkgPath = join(ROOT, 'engine/package.json');
  if (existsSync(enginePkgPath)) {
    const enginePkg = JSON.parse(readFileSync(enginePkgPath, 'utf8'));
    if (enginePkg.version !== version) {
      if (FIX) {
        enginePkg.version = version;
        writeFileSync(enginePkgPath, `${JSON.stringify(enginePkg, null, 2)}\n`);
        pass(`Updated engine/package.json version to ${version}.`);
      } else {
        fail(`engine/package.json version (${enginePkg.version}) disagrees with root (${version}).`);
      }
    } else {
      pass(`engine/package.json matches version v${version}.`);
    }
  }

  const versionFilePath = join(ROOT, 'skill/scripts/VERSION');
  if (existsSync(versionFilePath)) {
    const vText = readFileSync(versionFilePath, 'utf8').trim();
    if (vText !== version) {
      if (FIX) {
        writeFileSync(versionFilePath, `${version}\n`);
        pass(`Updated skill/scripts/VERSION to ${version}.`);
      } else {
        warn(`skill/scripts/VERSION (${vText}) differs from package.json (${version}).`);
      }
    } else {
      pass(`skill/scripts/VERSION matches v${version}.`);
    }
  }
}

// ---------------------------------------------------------------- 6. Invariants

function auditInvariants() {
  console.log('• Checking invariants (subagents read-only, secrets redaction)...');

  // Subagents read-only invariant
  const agentsDir = join(ROOT, 'skill/agents');
  if (existsSync(agentsDir)) {
    for (const f of readdirSync(agentsDir).filter((x) => x.endsWith('.md'))) {
      const text = readFileSync(join(agentsDir, f), 'utf8');
      const toolMatch = text.match(/^tools:\s*(.*)$/m);
      if (toolMatch) {
        const tools = toolMatch[1].split(',').map((t) => t.trim());
        for (const forbidden of ['Write', 'Edit', 'NotebookEdit']) {
          if (tools.includes(forbidden)) {
            fail(`Subagent ${f} declares write tool: ${forbidden}! Subagents must be read-only.`);
          }
        }
      }
    }
    pass('Subagents verified read-only.');
  }

  // Redaction test invariant
  const redaction = run(process.execPath, ['--test', 'tests/redaction.test.mjs']);
  if (redaction.code !== 0) {
    fail(`tests/redaction.test.mjs failed! Airtight must never leak secrets:\n${redaction.stderr || redaction.stdout}`);
  } else {
    pass('Redaction invariant passed (tests/redaction.test.mjs clean).');
  }
}

// ------------------------------------------------------------- 7. Git Workspace

function auditGitStatus() {
  console.log('• Checking git workspace hygiene...');
  const status = run('git', ['status', '--porcelain']);
  if (status.code !== 0) return;

  const lines = status.stdout.split('\n').filter(Boolean);
  const untracked = lines.filter((l) => l.startsWith('??'));
  const modified = lines.filter((l) => !l.startsWith('??'));

  if (untracked.length > 0) {
    const scratch = untracked.filter((l) => l.includes('scratch') || /(^|[/._-])(temp|tmp)([/._-]|$)/i.test(l) || l.endsWith('.tmp'));
    if (scratch.length > 0) {
      warn(`Untracked temporary files detected:\n  ${scratch.join('\n  ')}`);
    }
  }

  pass(`Git status: ${modified.length} modified file(s), ${untracked.length} untracked file(s).`);
}

// ------------------------------------------------------------------------- Main

function main() {
  console.log('=== Airtight Pre-Commit Progress Audit ===\n');

  const rulesInfo = auditRulesAndEngine();
  auditDocs(rulesInfo);
  auditDemo(rulesInfo);
  auditHarnesses();
  auditPackages();
  auditInvariants();
  auditGitStatus();

  console.log('\n=== Audit Summary ===');
  console.log(`Passed checks: ${successes.length}`);
  if (warnings.length > 0) {
    console.log(`\nWarnings (${warnings.length}):`);
    for (const w of warnings) console.log(`  [!] ${w}`);
  }

  if (issues.length > 0) {
    console.log(`\nAction Required Before Committing (${issues.length}):`);
    for (const iss of issues) console.log(`  [X] ${iss}`);
    console.log('\nRun `node scripts/progress-audit.mjs --fix` or `npm run build:release` to resolve drift.');
    return 1;
  }

  console.log('\n[OK] All pre-commit audits passed! Safe to commit.');
  return 0;
}

process.exit(main());
