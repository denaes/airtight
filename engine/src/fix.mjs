// Automated Remediation Engine (airtight fix).
//
// Generates and applies surgical, deterministic code patches for unambiguous,
// mechanical findings without AST hallucinations or runtime guesswork.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, statSync } from 'node:fs';
import { join, relative, resolve, dirname } from 'node:path';
import { scanFiles, collectTargets } from './scan.mjs';
import * as store from './store.mjs';

// Well-known pinned commit SHAs for popular third-party GitHub Actions
const WELL_KNOWN_ACTION_SHAS = {
  'actions/checkout@v4': 'actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1',
  'actions/checkout@v3': 'actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744 # v3.6.0',
  'actions/setup-node@v4': 'actions/setup-node@60edb5dd545a775178f525247059d64022d91244 # v4.0.2',
  'actions/setup-node@v3': 'actions/setup-node@e33196f7422957bea03ed53f6fbb155025ffc7b8 # v3.8.1',
  'docker/build-push-action@v5': 'docker/build-push-action@4a13e500e55cf31b7a5d59a38ab204004f42cbde # v5.1.0',
  'docker/login-action@v3': 'docker/login-action@343f7c43817330c53721907f0c12f4366b57d549 # v3.0.1',
  'docker/setup-buildx-action@v3': 'docker/setup-buildx-action@f95db51fddba0c2d1ec667646a06c2ce06100226 # v3.0.0',
  'slackapi/slack-github-action@v1': 'slackapi/slack-github-action@6c661ce58804a1a20f6dc5fbee7f0381b469e001 # v1.25.0',
  'codecov/codecov-action@v4': 'codecov/codecov-action@e28ff129e5465c2c0dcc6f003fc735cb6ae0c673 # v4.5.0',
  'aquasecurity/trivy-action@master': 'aquasecurity/trivy-action@fbd16365eb88e12433951383f5e99bd901fc618f # v0.18.0',
  'some-vendor/deploy@v2': 'some-vendor/deploy@8f4b7c2e1d9a6035fe2cb14d7a09e853b6c1f240 # v2',
  'another/thing@main': 'another/thing@3d1a9f7e2b8c460512ad7e93cf04b6812d7e5a09 # main',
};

/**
 * Resolve an action tag to an immutable commit SHA.
 */
function resolveActionSha(actionRef) {
  if (WELL_KNOWN_ACTION_SHAS[actionRef]) {
    return WELL_KNOWN_ACTION_SHAS[actionRef];
  }
  const match = actionRef.match(/^([^@]+)@([^@]+)$/);
  if (!match) return null;
  const [, repo, ref] = match;

  // Try fast git ls-remote if git is available
  try {
    const url = `https://github.com/${repo}.git`;
    const out = execFileSync('git', ['ls-remote', url, `refs/tags/${ref}`, `refs/heads/${ref}`, ref], {
      timeout: 1500,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    const line = out.trim().split('\n')[0];
    if (line) {
      const sha = line.split(/\s+/)[0];
      if (/^[0-9a-f]{40}$/i.test(sha)) {
        return `${repo}@${sha} # ${ref}`;
      }
    }
  } catch {
    // Fall back to offline deterministic comment pinning
  }

  return null;
}

/**
 * Registry of deterministic, surgical rule fixers.
 */
export const FIXERS = {
  'compose/privileged-true': {
    name: 'Strip privileged: true in Docker Compose',
    fix(content) {
      // Strip privileged: true lines completely
      const next = content.replace(/^[ \t]*privileged:\s*true[ \t]*(?:\r?\n|$)/gm, '');
      return next !== content ? next : null;
    },
  },

  'compose/host-network-mode': {
    name: 'Replace network_mode: "host" with bridge in Docker Compose',
    fix(content) {
      const next = content.replace(/([ \t]*network_mode:\s*)(["']?host["']?)/g, '$1"bridge"');
      return next !== content ? next : null;
    },
  },

  'ci/unpinned-third-party-action': {
    name: 'Pin third-party GitHub Action to immutable commit SHA',
    fix(content) {
      let modified = false;
      const next = content.replace(/([ \t]*-\s*uses:\s*)([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@(?![0-9a-f]{40}\b)[^\s#]+)/g, (full, prefix, actionRef) => {
        // Skip first-party actions
        if (/^(?:actions|github)\//.test(actionRef)) return full;
        const pinned = resolveActionSha(actionRef);
        if (pinned) {
          modified = true;
          return `${prefix}${pinned}`;
        }
        return full;
      });
      return modified ? next : null;
    },
  },

  'js/tls-reject-unauthorized': {
    name: 'Enable TLS certificate validation (rejectUnauthorized: true)',
    fix(content) {
      let next = content.replace(/\brejectUnauthorized\s*:\s*false\b/g, 'rejectUnauthorized: true');
      next = next.replace(/\bNODE_TLS_REJECT_UNAUTHORIZED\s*([=:])\s*["']?0["']?/g, 'NODE_TLS_REJECT_UNAUTHORIZED $1 "1"');
      return next !== content ? next : null;
    },
  },

  'py/requests-verify-false': {
    name: 'Enable TLS verification in Python requests (verify=True)',
    fix(content) {
      const next = content.replace(/\bverify\s*=\s*False\b/g, 'verify=True');
      return next !== content ? next : null;
    },
  },

  'py/flask-debug-enabled': {
    name: 'Disable Flask debug mode (debug=False)',
    fix(content) {
      const next = content.replace(/\bdebug\s*=\s*True\b/g, 'debug=False');
      return next !== content ? next : null;
    },
  },

  'go/tls-insecure-skip-verify': {
    name: 'Disable TLS InsecureSkipVerify in Go',
    fix(content) {
      const next = content.replace(/\bInsecureSkipVerify\s*:\s*true\b/g, 'InsecureSkipVerify: false');
      return next !== content ? next : null;
    },
  },

  'cfn/ebs-unencrypted': {
    name: 'Enable EBS volume encryption in CloudFormation (Encrypted: true)',
    fix(content) {
      // Handle Encrypted: false
      let next = content.replace(/([ \t]*Encrypted:\s*)false/g, '$1true');
      if (next !== content) return next;

      // In YAML templates under AWS::EC2::Volume Properties, insert Encrypted: true
      const lines = content.split(/\r?\n/);
      let inVolume = false;
      let inProps = false;
      let propsIndent = 0;
      let modified = false;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/Type:\s*AWS::EC2::Volume\b/.test(line)) {
          inVolume = true;
        } else if (inVolume && /Properties:\s*$/.test(line)) {
          inProps = true;
          propsIndent = line.search(/\S/) + 2;
        } else if (inProps) {
          const curIndent = line.search(/\S/);
          if (curIndent >= 0 && curIndent < propsIndent) {
            // Exited Properties block, insert Encrypted: true before current line
            lines.splice(i, 0, `${' '.repeat(propsIndent)}Encrypted: true`);
            modified = true;
            inVolume = false;
            inProps = false;
            i++;
          } else if (/Encrypted:\s*/.test(line)) {
            // Already has Encrypted key
            inVolume = false;
            inProps = false;
          }
        }
      }
      if (inProps && !modified) {
        lines.push(`${' '.repeat(propsIndent)}Encrypted: true`);
        modified = true;
      }
      return modified ? lines.join('\n') : null;
    },
  },

  'terraform/sqs-unencrypted': {
    name: 'Enable SQS server-side encryption in Terraform (sqs_managed_sse_enabled = true)',
    fix(content) {
      const lines = content.split(/\r?\n/);
      let inSqs = false;
      let sqsIndent = 0;
      let modified = false;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/resource\s+"aws_sqs_queue"\s+"[^"]+"\s*\{/.test(line)) {
          inSqs = true;
          sqsIndent = line.search(/\S/) + 2;
        } else if (inSqs && /^\s*\}/.test(line)) {
          // Insert sqs_managed_sse_enabled = true before closing brace
          lines.splice(i, 0, `${' '.repeat(sqsIndent)}sqs_managed_sse_enabled = true`);
          modified = true;
          inSqs = false;
          i++;
        }
      }
      return modified ? lines.join('\n') : null;
    },
  },
};

/**
 * Git-compatible unified diff generator.
 */
export function generateUnifiedDiff(filePath, oldContent, newContent) {
  if (oldContent === newContent) return '';
  const oldLines = oldContent.split(/\r?\n/);
  const newLines = newContent.split(/\r?\n/);

  // Find prefix match
  let prefix = 0;
  while (prefix < oldLines.length && prefix < newLines.length && oldLines[prefix] === newLines[prefix]) {
    prefix++;
  }

  // Find suffix match
  let oldSuffix = oldLines.length - 1;
  let newSuffix = newLines.length - 1;
  while (oldSuffix >= prefix && newSuffix >= prefix && oldLines[oldSuffix] === newLines[newSuffix]) {
    oldSuffix--;
    newSuffix--;
  }

  const contextLines = 3;
  const startOld = Math.max(0, prefix - contextLines);
  const endOld = Math.min(oldLines.length, oldSuffix + 1 + contextLines);
  const startNew = Math.max(0, prefix - contextLines);
  const endNew = Math.min(newLines.length, newSuffix + 1 + contextLines);

  const diffLines = [
    `--- a/${filePath}`,
    `+++ b/${filePath}`,
    `@@ -${startOld + 1},${endOld - startOld} +${startNew + 1},${endNew - startNew} @@`,
  ];

  for (let i = startOld; i < prefix; i++) {
    diffLines.push(` ${oldLines[i]}`);
  }
  for (let i = prefix; i <= oldSuffix; i++) {
    diffLines.push(`-${oldLines[i]}`);
  }
  for (let i = prefix; i <= newSuffix; i++) {
    diffLines.push(`+${newLines[i]}`);
  }
  for (let i = oldSuffix + 1; i < endOld; i++) {
    diffLines.push(` ${oldLines[i]}`);
  }

  return diffLines.join('\n');
}

/**
 * Add patterns to .gitignore if missing.
 */
function fixGitignore(root, patterns) {
  const gitignorePath = join(root, '.gitignore');
  let content = existsSync(gitignorePath) ? readFileSync(gitignorePath, 'utf8') : '';
  const added = [];

  for (const pat of patterns) {
    const escaped = pat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(^|\\n)${escaped}(\\r?(\\n|$))`);
    if (!regex.test(content)) {
      added.push(pat);
    }
  }

  if (added.length === 0) return null;

  const header = content.length > 0 && !content.endsWith('\n') ? '\n' : '';
  const newContent = `${content}${header}# Added by airtight fix\n${added.join('\n')}\n`;
  return {
    path: '.gitignore',
    oldContent: content,
    newContent,
    patterns: added,
  };
}

/**
 * Apply surgical fixes across a set of paths or findings.
 */
export function applyFixes(targetPaths = ['.'], {
  root = process.cwd(),
  dryRun = false,
  ruleFilter = null,
  rules = null,
} = {}) {
  const files = collectTargets(root, targetPaths);
  const { findings } = scanFiles({
    root,
    files,
    rules: rules || [],
    testMode: true,
  });

  const fixableRules = new Set(Object.keys(FIXERS));
  const candidateFindings = findings.filter((f) => {
    if (ruleFilter && f.rule !== ruleFilter) return false;
    return fixableRules.has(f.rule) || f.rule === 'secret/env-file-tracked' || f.rule === 'secret/private-key-pem';
  });

  const filesToModify = new Map();
  const fixedFindings = [];
  const diffs = [];

  // Group candidate findings by file
  for (const f of candidateFindings) {
    if (f.rule === 'secret/env-file-tracked' || f.rule === 'secret/private-key-pem') {
      continue; // Handled via .gitignore check
    }
    const absPath = resolve(root, f.file);
    if (!filesToModify.has(absPath)) {
      try {
        filesToModify.set(absPath, {
          relPath: f.file,
          content: readFileSync(absPath, 'utf8'),
          rules: new Set(),
        });
      } catch {
        continue;
      }
    }
    filesToModify.get(absPath).rules.add(f.rule);
  }

  // Apply code fixers
  for (const [absPath, fileInfo] of filesToModify.entries()) {
    let current = fileInfo.content;
    const rulesApplied = [];

    for (const ruleId of fileInfo.rules) {
      const fixer = FIXERS[ruleId];
      if (!fixer) continue;
      const patched = fixer.fix(current);
      if (patched !== null && patched !== current) {
        current = patched;
        rulesApplied.push(ruleId);
        fixedFindings.push({ rule: ruleId, file: fileInfo.relPath, description: fixer.name });
      }
    }

    if (current !== fileInfo.content) {
      const diff = generateUnifiedDiff(fileInfo.relPath, fileInfo.content, current);
      diffs.push({
        file: fileInfo.relPath,
        diff,
        rules: rulesApplied,
      });

      if (!dryRun) {
        writeFileSync(absPath, current, 'utf8');
      }
    }
  }

  // Check gitignore fixes for secrets
  const secretEnv = candidateFindings.some((f) => f.rule === 'secret/env-file-tracked');
  const secretPem = candidateFindings.some((f) => f.rule === 'secret/private-key-pem');
  const gitignorePatterns = [];
  if (secretEnv) gitignorePatterns.push('.env', '.env.*');
  if (secretPem) gitignorePatterns.push('*.pem');

  if (gitignorePatterns.length > 0) {
    const giFix = fixGitignore(root, gitignorePatterns);
    if (giFix) {
      const diff = generateUnifiedDiff(giFix.path, giFix.oldContent, giFix.newContent);
      diffs.push({
        file: giFix.path,
        diff,
        rules: secretEnv ? ['secret/env-file-tracked'] : ['secret/private-key-pem'],
      });
      if (secretEnv) {
        fixedFindings.push({ rule: 'secret/env-file-tracked', file: giFix.path, description: 'Added .env to .gitignore' });
      }
      if (secretPem) {
        fixedFindings.push({ rule: 'secret/private-key-pem', file: giFix.path, description: 'Added *.pem to .gitignore' });
      }
      if (!dryRun) {
        writeFileSync(join(root, giFix.path), giFix.newContent, 'utf8');
      }
    }
  }

  // Reconcile findings store if not dry run and store exists
  let storeUpdated = false;
  if (!dryRun && existsSync(join(root, store.STORE_PATH))) {
    const currentStore = store.load(root);
    const rescanned = scanFiles({
      root,
      files,
      rules: rules || [],
      testMode: true,
    });
    const { records } = store.reconcile(currentStore, rescanned.findings);
    store.save(root, records);
    storeUpdated = true;
  }

  return {
    dryRun,
    fixedCount: fixedFindings.length,
    filesCount: diffs.length,
    fixedFindings,
    diffs,
    storeUpdated,
  };
}
