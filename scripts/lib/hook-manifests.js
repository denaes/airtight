// Hook manifests, per harness.
//
// Shared by the build (which writes standalone manifests where a harness reads
// one) and the CLI installer (which merges into a settings file where a harness
// uses one). Two producers of the same shape would drift.

const SKILL = 'airtight';

/** Where the launcher lives, expressed the way each harness resolves paths. */
export function launcherPath(configDir, style) {
  const rel = `${configDir}/skills/${SKILL}/scripts/airtight`;
  if (style === 'claude') return `\${CLAUDE_PROJECT_DIR}/${rel}`;
  if (style === 'git-root') return `$(git rev-parse --show-toplevel)/${rel}`;
  return rel;
}

/**
 * `[ ! -f X ] || X hook` rather than `X hook || true`.
 *
 * The guard makes a missing launcher a silent no-op while preserving the
 * launcher's own exit code, so the exit-2 blocking signal still reaches the
 * agent. `|| true` would swallow it and the blocking path would silently stop
 * blocking, which is the worst possible failure for this file: it looks
 * installed and protects nothing.
 */
export const guarded = (path, verb = 'hook') => `[ ! -f "${path}" ] || "${path}" ${verb}`;

/** Claude Code: merged into .claude/settings.json by the installer. */
export function claudeSettings(configDir = '.claude') {
  const p = launcherPath(configDir, 'claude');
  return {
    PostToolUse: [{
      matcher: 'Edit|Write',
      hooks: [{ type: 'command', command: guarded(p), timeout: 5, statusMessage: 'Checking security' }],
    }],
    Stop: [{
      hooks: [{ type: 'command', command: guarded(p), timeout: 30, statusMessage: 'Security deep pass' }],
    }],
  };
}

/** Codex: a standalone .codex/hooks.json, with a Windows sibling command. */
export function codexHooks(configDir = '.agents') {
  const p = launcherPath(configDir);
  return {
    hooks: {
      // apply_patch is Codex's own edit tool and has to be matched explicitly.
      PostToolUse: [{
        matcher: 'Edit|Write|apply_patch',
        hooks: [{
          type: 'command',
          command: guarded(p),
          commandWindows: `if exist "${configDir}\\skills\\${SKILL}\\scripts\\airtight.cmd" "${configDir}\\skills\\${SKILL}\\scripts\\airtight.cmd" hook`,
          timeout: 5,
        }],
      }],
      Stop: [{
        hooks: [{ type: 'command', command: guarded(p), timeout: 30 }],
      }],
    },
  };
}

/**
 * Cursor: preToolUse only. Cursor's stop hook is not dispatched reliably, and
 * its preToolUse gate can deny a write before it lands, so this is the one
 * harness where the block happens before the edit rather than after.
 */
export function cursorHooks(configDir = '.cursor') {
  return {
    version: 1,
    hooks: {
      preToolUse: [{ command: guarded(launcherPath(configDir), 'hook-before-edit') }],
    },
  };
}

/** Copilot: committed to the repo, so the path is resolved from the git root. */
export function githubHooks(configDir = '.github') {
  const p = launcherPath(configDir, 'git-root');
  return {
    version: 1,
    hooks: {
      postToolUse: [{ matcher: 'Edit|Write', command: guarded(p), timeoutSec: 5 }],
      stop: [{ command: guarded(p), timeoutSec: 30 }],
    },
  };
}

/** Grok: PostToolUse stdout never reaches the model, so it warms Stop. */
export function grokHooks(configDir = '.grok') {
  const p = launcherPath(configDir);
  return {
    version: 1,
    hooks: {
      PostToolUse: [{ matcher: 'Edit|Write', command: guarded(p), timeout: 5 }],
      Stop: [{ command: guarded(p), timeout: 30 }],
    },
  };
}

/** Manifests that are written as their own file, and where. */
export const STANDALONE = {
  'codex-hooks': { file: 'hooks.json', build: codexHooks },
  'cursor-hooks': { file: 'hooks.json', build: cursorHooks },
  'github-hooks': { file: 'hooks/airtight.json', build: githubHooks },
  'grok-hooks': { file: 'airtight.json', build: grokHooks },
};
