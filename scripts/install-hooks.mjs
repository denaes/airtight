#!/usr/bin/env node
// Install git pre-push hook for Airtight.
//
// Automatically prevents broken pushes to GitHub and invalid npm states by
// running preflight validation before any git push succeeds.

import { existsSync, writeFileSync, chmodSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const GIT_DIR = join(ROOT, '.git');
const HOOKS_DIR = join(GIT_DIR, 'hooks');
const PRE_PUSH_PATH = join(HOOKS_DIR, 'pre-push');

export function installHooks({ silent = false } = {}) {
  if (!existsSync(GIT_DIR)) {
    if (!silent) console.log('[preflight] Not a git repository, skipping hook installation.');
    return false;
  }

  if (!existsSync(HOOKS_DIR)) {
    mkdirSync(HOOKS_DIR, { recursive: true });
  }

  const hookContent = `#!/usr/bin/env bash
# Airtight Pre-Push Verification Hook
# Generated automatically by scripts/install-hooks.mjs.
# Guarantees full compliance with GitHub Actions CI and npm before pushing.

set -e

# Allow bypassing with --no-verify if explicitly intended
if [ "$GIT_PARAMS" = "--no-verify" ] || [ "$AIRTIGHT_SKIP_PREFLIGHT" = "1" ]; then
  exit 0
fi

node scripts/preflight.mjs --git-hook
`;

  writeFileSync(PRE_PUSH_PATH, hookContent, 'utf8');
  try {
    chmodSync(PRE_PUSH_PATH, 0o755);
  } catch {
    // Windows or restrictive filesystems may not support chmod
  }

  const isNpmPrepare = process.env.npm_lifecycle_event === 'prepare';
  if (!silent && !isNpmPrepare) {
    console.log('[OK] Airtight git pre-push hook active at .git/hooks/pre-push');
  }
  return true;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  installHooks();
}
