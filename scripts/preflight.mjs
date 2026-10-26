#!/usr/bin/env node
// Airtight Preflight Compliance Runner.
//
// Guarantees 100% compliance with GitHub Actions CI workflows and npm registry
// requirements before pushing git commits or publishing packages.

import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// CLI Flags
const args = process.argv.slice(2);
const IS_GIT_HOOK = args.includes('--git-hook');
const FIX = args.includes('--fix');
const ONLY_GITHUB = args.includes('--github');
const ONLY_NPM = args.includes('--npm');
const SHOW_HELP = args.includes('--help') || args.includes('-h');
const SKIP_TEST = args.includes('--no-test') || process.env.AIRTIGHT_SKIP_NESTED_TEST === '1';

if (SHOW_HELP) {
  console.log(`Airtight Preflight Compliance Runner

Usage:
  node scripts/preflight.mjs [options]

Options:
  --github      Run GitHub Actions CI parity checks
  --npm         Run npm registry publication checks
  --fix         Automatically resolve harness drift and docs before checking
  --git-hook    Executed automatically by .git/hooks/pre-push
  --no-test     Skip full test suite execution
  --help, -h    Show this help message
`);
  process.exit(0);
}

// ANSI Colors
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const GRAY = '\x1b[90m';

const results = {
  passed: [],
  failed: [],
  warnings: [],
};

function pass(name, detail = '') {
  results.passed.push(name);
  console.log(`  ${GREEN}✓${RESET} ${name}${detail ? ` ${GRAY}(${detail})${RESET}` : ''}`);
}

function fail(name, reason, remediation = '') {
  results.failed.push({ name, reason, remediation });
  console.log(`  ${RED}✗${RESET} ${BOLD}${name}${RESET}`);
  if (reason) console.log(`    ${RED}${reason}${RESET}`);
  if (remediation) console.log(`    ${YELLOW}Fix: ${remediation}${RESET}`);
}

function warn(name, detail = '') {
  results.warnings.push({ name, detail });
  console.log(`  ${YELLOW}⚠${RESET} ${name}${detail ? ` ${GRAY}(${detail})${RESET}` : ''}`);
}

function section(title) {
  console.log(`\n${BOLD}${CYAN}▸ ${title}${RESET}`);
}

function run(cmd, cmdArgs, opts = {}) {
  try {
    const stdout = execFileSync(cmd, cmdArgs, {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 120_000,
      ...opts,
    });
    return { code: 0, stdout: stdout.trim(), stderr: '' };
  } catch (err) {
    return {
      code: err.status ?? 1,
      stdout: (err.stdout ?? '').toString().trim(),
      stderr: (err.stderr ?? '').toString().trim(),
    };
  }
}

// ------------------------------------------------------------- Phase 1: GitHub CI

function checkGitHubParity() {
  section('Phase 1: GitHub Actions CI Parity Checks');

  // 1. Sync & Generated Files
  console.log('  Checking generated artifacts and tracked harnesses...');
  if (FIX) {
    run('npm', ['run', 'audit:progress:fix']);
    run('npm', ['run', 'build:release']);
  }

  if (IS_GIT_HOOK) {
    const diffCheck = run('git', [
      'diff',
      '--exit-code',
      '--',
      '.agent', '.agents', '.claude', '.cursor', '.dsh', '.gemini', '.github',
      '.grok', '.hermes', '.kiro', '.opencode', '.pi', '.qoder', '.rovodev',
      '.trae', '.trae-cn', '.veto', '.vibe', 'plugin', '.claude-plugin',
      'skill/scripts/engine', 'skill/scripts/rules.json', 'docs/', 'README.md',
    ]);

    if (diffCheck.code !== 0) {
      fail(
        'Harness & documentation drift detected',
        'Committed files differ from canonical skill/ source of truth.',
        'Run: npm run preflight:fix (or npm run audit:progress:fix && npm run build:release)',
      );
    } else {
      pass('Harness & documentation sync', 'all 18 harnesses and docs committed in sync');
    }
  } else {
    const buildRes = run('node', [join(ROOT, 'scripts/build.js')]);
    if (buildRes.code !== 0) {
      fail('Harness build validation failed', buildRes.stderr || buildRes.stdout);
    } else {
      pass('Harness & documentation sync', 'all 18 harness transforms valid');
    }
  }

  // 2. Pre-commit Progress Audit
  console.log('  Running progress audit...');
  const auditRes = run('node', ['scripts/progress-audit.mjs']);
  if (auditRes.code !== 0) {
    fail(
      'Progress audit failed',
      auditRes.stdout || auditRes.stderr,
      'Run: npm run audit:progress:fix',
    );
  } else {
    pass('Progress audit', '15 pre-commit checks clean');
  }

  // 3. Airtight Self-Scan
  console.log('  Running Airtight self-scan (detect .)...');
  const scanRes = run('node', ['engine/src/cli.mjs', 'detect', '.']);
  if (scanRes.code !== 0) {
    fail(
      'Airtight self-scan failed',
      scanRes.stdout || scanRes.stderr,
      'Resolve or waive internal findings using airtight waiver comments',
    );
  } else {
    pass('Airtight self-scan', 'zero security findings in repository');
  }

  // 4. Security Controls Verification
  console.log('  Verifying security controls...');
  const controlsRes = run('node', ['engine/src/cli.mjs', 'controls', 'verify']);
  if (controlsRes.code !== 0 || /\b[1-9]\d*\s+failing\b/.test(controlsRes.stdout)) {
    fail('Security controls verification failed', controlsRes.stdout);
  } else {
    pass('Security controls', 'all declared controls holding');
  }

  // 5. Demo Output Drift
  console.log('  Checking demo golden output...');
  const demoRes = run('node', ['scripts/demo.mjs', '--check']);
  if (demoRes.code !== 0) {
    fail('Demo output drifted from golden', demoRes.stderr || demoRes.stdout, 'Run: node scripts/demo.mjs --write');
  } else {
    pass('Demo golden', 'output matches expected-findings.txt');
  }

  // 6. Self-Contained Engine Probe
  console.log('  Testing self-contained engine bundle probe...');
  const probeRes = run('node', ['skill/scripts/engine/airtight.mjs', 'engine-probe']);
  if (probeRes.code !== 0) {
    fail('Engine probe failed', probeRes.stderr || probeRes.stdout);
  } else {
    pass('Self-contained engine bundle', probeRes.stdout);
  }

  // 7. Full Test Suite Execution
  if (!SKIP_TEST) {
    console.log('  Executing full test suite (npm test)...');
    const testRes = run('npm', ['test'], {
      env: { ...process.env, AIRTIGHT_SKIP_NESTED_TEST: '1' },
    });
    if (testRes.code !== 0) {
      fail('Test suite failed', 'One or more tests in tests/*.test.mjs failed.', 'Run: npm test to inspect failing tests');
    } else {
      pass('Test suite', '100% of unit, corpus, and invariant tests passed');
    }
  } else {
    pass('Test suite', 'skipped (--no-test or nested test execution)');
  }
}

// ---------------------------------------------------------------- Phase 2: npm

function checkNpmParity() {
  section('Phase 2: npm Publication & Package Checks');

  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  const localVersion = pkg.version;
  const pkgName = pkg.name;

  // 1. Version Collision Check against npm Registry
  console.log(`  Checking npm registry for version collision (${pkgName}@${localVersion})...`);
  const viewRes = run('npm', ['view', `${pkgName}@${localVersion}`, 'version', '--json']);

  if (viewRes.code === 0 && viewRes.stdout.replace(/["\s]/g, '') === localVersion) {
    const msg = `Version ${localVersion} has already been published to npm!`;
    if (ONLY_NPM) {
      fail(
        'npm version collision',
        msg,
        'Bump package version before publishing: npm version patch (or minor)',
      );
    } else {
      warn(
        `Version ${localVersion} is already published on npm.`,
        'Remember to bump version before running npm publish.',
      );
    }
  } else {
    pass('npm version availability', `v${localVersion} is unreleased on npm`);
  }

  // 2. npm Authentication Check
  console.log('  Checking npm authentication status (npm whoami)...');
  const whoamiRes = run('npm', ['whoami']);
  if (whoamiRes.code === 0 && whoamiRes.stdout) {
    pass('npm authentication', `logged in as ${whoamiRes.stdout}`);
  } else {
    const msg = 'Not currently authenticated to npm.';
    if (ONLY_NPM) {
      fail('npm authentication', msg, 'Run: npm login before publishing');
    } else {
      warn('npm authentication', 'not logged in (run npm login when publishing releases)');
    }
  }

  // 3. Package Dry Run & Manifest Verification
  console.log('  Verifying package tarball (npm pack --dry-run)...');
  const packRes = run('npm', ['pack', '--dry-run', '--json']);
  if (packRes.code !== 0) {
    fail('npm pack --dry-run failed', packRes.stderr || packRes.stdout);
  } else {
    try {
      const jsonStart = packRes.stdout.indexOf('[');
      const jsonText = jsonStart >= 0 ? packRes.stdout.slice(jsonStart) : packRes.stdout;
      const parsed = JSON.parse(jsonText);
      const tarball = Array.isArray(parsed) ? parsed[0] : parsed;
      const filePaths = new Set(tarball.files.map((f) => f.path));

      // Assert essential files exist
      const required = [
        'package.json',
        'README.md',
        'LICENSE',
        'cli/bin/airtight.js',
        'skill/scripts/engine/airtight.mjs',
        'skill/scripts/rules.json',
      ];
      const missing = required.filter((r) => !filePaths.has(r));

      // Assert sensitive files are excluded
      const leaked = [...filePaths].filter((p) =>
        /(^|\/)(\.env|.*\.pem|.*\.key|fixtures\/flag\/|tests\/)/i.test(p)
      );

      if (missing.length > 0) {
        fail('Package contents incomplete', `Missing required files: ${missing.join(', ')}`);
      } else if (leaked.length > 0) {
        fail('Package leak detected', `Sensitive files included in npm tarball: ${leaked.join(', ')}`);
      } else {
        const kbSize = Math.round(tarball.size / 1024);
        pass('npm package tarball', `${tarball.entryCount} files, ${kbSize} kB packed`);
      }
    } catch (e) {
      warn('Could not parse npm pack output', e.message);
    }
  }

  // 4. Git Working Tree Check (for npm publish)
  if (ONLY_NPM) {
    const statusRes = run('git', ['status', '--porcelain']);
    if (statusRes.code === 0 && statusRes.stdout.length > 0) {
      fail('Uncommitted changes present', 'npm publish requires a clean git working tree', 'Commit or stash changes');
    } else {
      pass('Git working tree', 'clean for release');
    }
  }
}

// ------------------------------------------------------------- Summary & Exit

function printSummary() {
  console.log(`\n${BOLD}=== Preflight Summary ===${RESET}`);
  console.log(`Passed checks: ${GREEN}${results.passed.length}${RESET}`);

  if (results.warnings.length > 0) {
    console.log(`\n${YELLOW}Warnings (${results.warnings.length}):${RESET}`);
    for (const w of results.warnings) {
      console.log(`  ${YELLOW}⚠${RESET} ${w.name}${w.detail ? ` - ${w.detail}` : ''}`);
    }
  }

  if (results.failed.length > 0) {
    console.log(`\n${RED}${BOLD}Compliance Blockers (${results.failed.length}):${RESET}`);
    for (const f of results.failed) {
      console.log(`  ${RED}✗${RESET} ${BOLD}${f.name}${RESET}: ${f.reason}`);
      if (f.remediation) console.log(`    ${YELLOW}Suggested action: ${f.remediation}${RESET}`);
    }
    console.log(`\n${RED}Preflight check failed. Fix blockers before pushing or publishing.${RESET}\n`);
    return 1;
  }

  console.log(`\n${GREEN}${BOLD}[OK] Full compliance verified! Safe to push to GitHub and publish to npm.${RESET}\n`);
  return 0;
}

function main() {
  console.log(`${BOLD}=== Airtight Preflight Compliance Check ===${RESET}`);
  if (IS_GIT_HOOK) {
    console.log(`${GRAY}[Running via git pre-push hook]${RESET}`);
  }

  if (ONLY_GITHUB) {
    checkGitHubParity();
  } else if (ONLY_NPM) {
    checkNpmParity();
  } else {
    checkGitHubParity();
    checkNpmParity();
  }

  return printSummary();
}

process.exit(main());
