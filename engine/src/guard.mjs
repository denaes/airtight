// Active Agent Execution Guardrail & Tool Firewall.
//
// Evaluates AI agent tool calls in real time before execution (bash, write, sql, fetch),
// preventing destructive actions, workspace breakout, credential exfiltration,
// and prompt injection payload execution.

export const GUARD_RULES = [
  // ----------------------------------------------------------------- Bash / Shell
  {
    id: 'guard/bash-root-rm',
    tool: 'bash',
    action: 'block',
    cwe: 'CWE-78',
    match: (input) => /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:\/|~|\$HOME|\.\/|\*|\/\*|\$ROOT)(?:\s|$)/i.test(input.command || ''),
    reason: 'Destructive recursive filesystem deletion target (root, home, or wildcard).',
    suggestion: 'Scope deletion to an explicit subpath inside the workspace.',
  },
  {
    id: 'guard/bash-pipe-to-shell',
    tool: 'bash',
    action: 'block',
    cwe: 'CWE-494',
    match: (input) => /(?:curl|wget)\s+[^\n|;&]+\|\s*(?:bash|sh|zsh|python|perl|ruby)\b/i.test(input.command || ''),
    reason: 'Piping untrusted remote network downloads directly into shell interpreter.',
    suggestion: 'Download script to disk, inspect or checksum verify, then execute.',
  },
  {
    id: 'guard/bash-disk-wipe',
    tool: 'bash',
    action: 'block',
    cwe: 'CWE-78',
    match: (input) => /\b(?:mkfs(?:\.[a-z0-9]+)?|dd\s+if=[^\s]+\s+of=\/dev\/(?:sd[a-z]|nvme[0-9]+[a-z0-9]*|hd[a-z]|vd[a-z]))(?:\s|$)/i.test(input.command || ''),
    reason: 'Raw block device wipe or filesystem format command detected.',
    suggestion: 'Do not format physical block storage devices via agent commands.',
  },
  {
    id: 'guard/bash-credential-exfil',
    tool: 'bash',
    action: 'block',
    cwe: 'CWE-200',
    match: (input) => /(?:curl|wget|nc|netcat)\s+[^\n|;&]+(?:@|\/|\$)(?:\.env|id_[rd]sa|\.aws\/credentials|\/etc\/shadow)/i.test(input.command || ''),
    reason: 'Outbound network transfer referencing sensitive credential or key files.',
    suggestion: 'Do not pipe or send private keys and environment files to remote hosts.',
  },
  {
    id: 'guard/bash-force-push',
    tool: 'bash',
    action: 'warn',
    cwe: 'CWE-284',
    match: (input) => /\bgit\s+push\s+(?:--force|-f)\s+(?:origin|upstream)\s+(?:main|master|release)\b/i.test(input.command || ''),
    reason: 'Force-pushing to default production branches can rewrite shared commit history.',
    suggestion: 'Use normal git push or push to a feature branch.',
  },
  {
    id: 'guard/bash-disable-security',
    tool: 'bash',
    action: 'block',
    cwe: 'CWE-276',
    match: (input) => /\b(?:setenforce\s+0|ufw\s+disable|iptables\s+-F|systemctl\s+stop\s+(?:firewalld|apparmor))\b/i.test(input.command || ''),
    reason: 'Disabling host firewall, SELinux, or kernel security enforcement.',
    suggestion: 'Configure explicit granular firewall rules rather than disabling subsystem.',
  },

  // ------------------------------------------------------------- File Write / Edit
  {
    id: 'guard/write-vcs-tamper',
    tool: 'write',
    action: 'block',
    cwe: 'CWE-276',
    match: (input) => /(?:^|[/\\])\.git[/\\](?:config|hooks[/\\][a-zA-Z0-9_-]+)$/i.test(input.path || ''),
    reason: 'Attempting to overwrite VCS configuration or hook scripts directly.',
    suggestion: 'Modify repository files inside the working tree, not internal .git metadata.',
  },
  {
    id: 'guard/write-ssh-key',
    tool: 'write',
    action: 'block',
    cwe: 'CWE-276',
    match: (input) => /(?:^|[/\\])\.ssh[/\\](?:authorized_keys|id_[rd]sa|known_hosts)$/i.test(input.path || ''),
    reason: 'Attempting to tamper with SSH keys or authorized_keys identity files.',
    suggestion: 'Do not write directly to SSH identity files via automated tools.',
  },
  {
    id: 'guard/write-system-file',
    tool: 'write',
    action: 'block',
    cwe: 'CWE-276',
    match: (input) => /^\/(?:etc\/(?:passwd|shadow|sudoers|hosts|crontab)|boot\/|sys\/)/i.test(input.path || ''),
    reason: 'Target path is an immutable host system configuration file.',
    suggestion: 'Limit file modifications to project repository directories.',
  },

  // ----------------------------------------------------------- SQL / Database
  {
    id: 'guard/sql-drop-table',
    tool: 'sql',
    action: 'block',
    cwe: 'CWE-89',
    match: (input) => /\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\s+/i.test(input.query || ''),
    reason: 'Destructive DDL drop table or database statement.',
    suggestion: 'Use non-destructive schema migrations or soft deletes.',
  },
  {
    id: 'guard/sql-unbounded-delete',
    tool: 'sql',
    action: 'block',
    cwe: 'CWE-89',
    match: (input) => {
      const q = (input.query || '').trim();
      return /^\s*DELETE\s+FROM\s+[`"']?[a-zA-Z0-9_]+[`"']?\s*(?:;)?$/i.test(q);
    },
    reason: 'DELETE statement executed without a WHERE constraint clause (mass truncation).',
    suggestion: 'Specify an explicit WHERE clause or condition to scope deletion.',
  },
  {
    id: 'guard/sql-unbounded-update',
    tool: 'sql',
    action: 'block',
    cwe: 'CWE-89',
    match: (input) => {
      const q = (input.query || '').trim();
      return /^\s*UPDATE\s+[`"']?[a-zA-Z0-9_]+[`"']?\s+SET\s+[^;]+$/i.test(q) && !/\bWHERE\b/i.test(q);
    },
    reason: 'UPDATE statement executed without a WHERE constraint clause (mass overwrite).',
    suggestion: 'Specify an explicit WHERE clause to restrict rows updated.',
  },

  // ------------------------------------------------------------- Network / Fetch
  {
    id: 'guard/fetch-cloud-metadata',
    tool: 'fetch',
    action: 'block',
    cwe: 'CWE-918',
    match: (input) => /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b/i.test(input.url || ''),
    reason: 'Target URL addresses cloud provider instance metadata service (SSRF vector).',
    suggestion: 'Filter out private/link-local IP addresses before making HTTP requests.',
  },
  {
    id: 'guard/fetch-internal-daemon',
    tool: 'fetch',
    action: 'warn',
    cwe: 'CWE-918',
    match: (input) => /(?:127\.0\.0\.1|localhost):(2375|6379|9200|27017)\b/i.test(input.url || ''),
    reason: 'Target URL targets sensitive internal service ports (Docker, Redis, Elastic, Mongo).',
    suggestion: 'Verify authorization and authenticate before connecting to internal daemons.',
  },
];

/**
 * Evaluates an agent tool invocation against the active guardrail rules.
 *
 * @param {Object} input - { tool: 'bash'|'write'|'sql'|'fetch', command?, path?, content?, query?, url? }
 * @returns {Object} - { verdict: 'allow'|'block'|'warn', rule?, reason?, cwe?, suggestion?, tool }
 */
export function evaluateGuard(input = {}) {
  const tool = (input.tool || 'bash').toLowerCase();

  for (const rule of GUARD_RULES) {
    if (rule.tool !== tool) continue;

    if (rule.match(input)) {
      return {
        verdict: rule.action,
        rule: rule.id,
        reason: rule.reason,
        cwe: rule.cwe,
        suggestion: rule.suggestion,
        tool,
      };
    }
  }

  return {
    verdict: 'allow',
    tool,
    reason: 'Command satisfies agent safety invariants.',
  };
}
