// The provider table.
//
// One row per harness. Adding a harness is a row here plus its placeholder
// values; the build does not change. That is why the generator existed while
// only one provider was registered.
//
// CONFIDENCE. Three tiers, recorded per row in `verified`:
//   'yes'         the conventions are confirmed against the real harness
//   'documented'  taken from the harness's published docs or from impeccable's
//                 provider table, not run end to end here
//   'convention'  the harness follows the emerging <dir>/skills/<name>/
//                 layout and nothing harness-specific is known
// A row marked 'convention' ships plain skill markdown and no hooks. That is
// deliberately conservative: emitting a frontmatter key a loader rejects breaks
// the whole skill, while omitting one it would have read only loses a feature.

export const PROVIDERS = {
  'claude-code': {
    provider: 'claude-code',
    display: 'Claude Code',
    configDir: '.claude',
    providerTags: ['claude-code', 'claude'],
    // `allowed-tools` is deliberately absent: on Claude Code its presence
    // blocks skill activation in non-interactive sessions.
    frontmatterFields: ['user-invocable', 'argument-hint', 'license'],
    agentFormat: 'claude-md',
    agentDir: 'agents',
    hooks: 'claude-settings',
    verified: 'yes',
  },

  cursor: {
    provider: 'cursor',
    display: 'Cursor',
    configDir: '.cursor',
    providerTags: ['cursor'],
    // Cursor's loader does not read user-invocable or argument-hint.
    frontmatterFields: ['license'],
    agentFormat: 'cursor-md',
    agentDir: 'agents',
    hooks: 'cursor-hooks',
    verified: 'documented',
  },

  codex: {
    provider: 'codex',
    display: 'Codex CLI',
    configDir: '.agents',
    providerTags: ['codex', 'agents'],
    // Codex's validator rejects unknown top-level frontmatter keys, so the
    // version moves into metadata and nothing else is emitted.
    frontmatterFields: [],
    versionInMetadata: true,
    writeOpenAIMetadata: true,
    agentFormat: 'codex-toml',
    // Codex discovers agents nested inside an installed skill, so the TOML
    // lives in the skill rather than in a sibling agents directory.
    agentDir: 'skills/airtight/agents',
    hooks: 'codex-hooks',
    hooksDir: '.codex',
    verified: 'documented',
  },

  copilot: {
    provider: 'copilot',
    display: 'GitHub Copilot',
    configDir: '.github',
    providerTags: ['github', 'copilot'],
    frontmatterFields: ['license'],
    // `tools` is omitted on purpose: omitting it grants all tools, and
    // Copilot's tool vocabulary does not match ours.
    agentFormat: 'copilot-agent-md',
    agentDir: 'agents',
    hooks: 'github-hooks',
    verified: 'documented',
  },

  gemini: {
    provider: 'gemini',
    display: 'Gemini CLI',
    configDir: '.gemini',
    providerTags: ['gemini'],
    frontmatterFields: [],
    agentFormat: 'none',
    verified: 'documented',
  },

  opencode: {
    provider: 'opencode',
    display: 'OpenCode',
    configDir: '.opencode',
    providerTags: ['opencode'],
    frontmatterFields: ['license'],
    agentFormat: 'none',
    // OpenCode registers skill commands but its autocomplete hides them, so a
    // thin command file is emitted as a bridge.
    commandBridge: true,
    verified: 'documented',
  },

  grok: {
    provider: 'grok',
    display: 'Grok Build',
    configDir: '.grok',
    providerTags: ['grok'],
    frontmatterFields: ['user-invocable', 'argument-hint', 'license'],
    agentFormat: 'claude-md',
    agentDir: 'agents',
    hooks: 'grok-hooks',
    hooksDir: '.grok/hooks',
    verified: 'documented',
  },

  hermes: {
    provider: 'hermes',
    display: 'Hermes Agent',
    configDir: '.hermes',
    providerTags: ['hermes'],
    // Spec-only fields; harness extensions are silently ignored here.
    frontmatterFields: ['license'],
    agentFormat: 'none',
    verified: 'documented',
  },

  antigravity: {
    provider: 'antigravity',
    display: 'Google Antigravity',
    configDir: '.agent',
    providerTags: ['antigravity'],
    frontmatterFields: [],
    agentFormat: 'none',
    verified: 'convention',
  },

  // The rows below follow the emerging <dir>/skills/<name>/ layout and nothing
  // harness-specific is known. Plain markdown, no agents, no hooks.
  ...Object.fromEntries([
    ['deepseek', 'DeepSeek Harness', '.dsh'],
    ['pi', 'Pi', '.pi'],
    ['qoder', 'Qoder', '.qoder'],
    ['rovo-dev', 'Rovo Dev', '.rovodev'],
    ['trae', 'Trae', '.trae'],
    ['trae-cn', 'Trae China', '.trae-cn'],
    ['veto', 'Veto', '.veto'],
    ['vibe', 'Mistral Vibe', '.vibe'],
    ['kiro', 'Kiro', '.kiro'],
  ].map(([provider, display, configDir]) => [provider, {
    provider, display, configDir,
    providerTags: [provider],
    frontmatterFields: [],
    agentFormat: 'none',
    verified: 'convention',
  }])),
};

/**
 * Per-harness wording. `ask_instruction` matters most: the skill's interview
 * steps have to name a tool the harness actually has, and telling a model to
 * call a tool that does not exist is worse than telling it to ask in chat.
 */
export const PLACEHOLDERS = {
  'claude-code': {
    model: 'Claude',
    config_file: 'CLAUDE.md',
    command_prefix: '/',
    ask_instruction: 'STOP and call the AskUserQuestion tool to ask.',
  },
  cursor: {
    model: 'the model',
    config_file: '.cursorrules',
    command_prefix: '/',
    ask_instruction: 'Ask the user directly in chat.',
  },
  codex: {
    model: 'GPT',
    config_file: 'AGENTS.md',
    command_prefix: '$',
    ask_instruction: "STOP and use Codex's structured question tool when available; otherwise ask directly in chat.",
  },
  copilot: {
    model: 'Copilot',
    config_file: '.github/copilot-instructions.md',
    command_prefix: '/',
    ask_instruction: 'Ask the user directly in chat.',
  },
  gemini: {
    model: 'Gemini',
    config_file: 'GEMINI.md',
    command_prefix: '/',
    ask_instruction: 'Ask the user directly in chat.',
  },
  opencode: {
    model: 'the model',
    config_file: 'AGENTS.md',
    command_prefix: '/',
    ask_instruction: 'STOP and call the `question` tool to ask.',
  },
  grok: {
    model: 'Grok',
    config_file: 'AGENTS.md',
    command_prefix: '/',
    ask_instruction: 'Ask the user directly in chat.',
  },
  hermes: {
    model: 'the model',
    config_file: 'AGENTS.md',
    command_prefix: '/',
    ask_instruction: 'Ask the user directly in chat.',
  },
};

const DEFAULT_PLACEHOLDERS = {
  model: 'the model',
  config_file: 'AGENTS.md',
  command_prefix: '/',
  ask_instruction: 'Ask the user directly in chat.',
};

export const placeholdersFor = (provider) => ({
  ...DEFAULT_PLACEHOLDERS,
  ...(PLACEHOLDERS[provider] ?? {}),
});

/** Frontmatter keys renamed on the way out, per agent format. */
export const FIELD_RENAMES = {
  'claude-md': { 'max-turns': 'maxTurns' },
  'cursor-md': {},
  'copilot-agent-md': {},
};

export const providerList = () => Object.values(PROVIDERS);
export const byVerification = (tier) => providerList().filter((p) => p.verified === tier);
