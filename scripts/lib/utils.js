// Text transforms shared by every provider.

import { placeholdersFor } from './providers.js';

/** Every tag the build knows about, so an unknown tag is left alone rather than eaten. */
const KNOWN_TAGS = new Set(['claude-code', 'claude', 'cursor', 'codex', 'agents', 'github', 'gemini']);

/**
 * Harness-conditional blocks. A standalone <codex>...</codex> block is kept for
 * matching providers and removed for everyone else. Unknown tags pass through
 * untouched, so a genuine HTML example in prose is not destroyed.
 */
export function compileProviderBlocks(text, providerTags) {
  const keep = new Set(providerTags);
  return text.replace(
    /^<([a-z-]+)>\n([\s\S]*?)\n<\/\1>\n?/gm,
    (whole, tag, body) => {
      if (!KNOWN_TAGS.has(tag)) return whole;
      return keep.has(tag) ? `${body}\n` : '';
    },
  );
}

export function replacePlaceholders(text, providerKey, scriptsPath) {
  // placeholdersFor supplies defaults, so a provider row that declares no
  // wording of its own still renders. Reading the map raw left every
  // convention-tier harness shipping literal {{command_prefix}} text.
  const values = { ...placeholdersFor(providerKey), scripts_path: scriptsPath };
  return text.replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (whole, name) =>
    (name in values ? values[name] : whole));
}

const YAML_SCALAR = /^[A-Za-z0-9._/@:+ -]*$/;

function emitScalar(value) {
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  const s = String(value);
  return YAML_SCALAR.test(s) && s.trim() === s && s !== '' ? s : JSON.stringify(s);
}

/** Codex rejects unknown top-level keys, so the version nests under metadata. */
function emitNested(key, obj) {
  return [`${key}:`, ...Object.entries(obj).map(([k, v]) => `  ${k}: ${emitScalar(v)}`)].join('\n');
}

export function splitFrontmatter(text) {
  const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
  if (!m) return { raw: null, body: text };
  return { raw: m[1], body: text.slice(m[0].length) };
}

/** Parse the flat key/value frontmatter this project uses. No nesting needed. */
export function parseFrontmatter(raw) {
  const out = {};
  if (!raw) return out;
  for (const line of raw.split('\n')) {
    const m = /^([a-z-]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2].trim();
    if (/^".*"$/.test(value)) value = JSON.parse(value);
    else if (value === 'true') value = true;
    else if (value === 'false') value = false;
    else if (/^\d+$/.test(value)) value = Number(value);
    out[m[1]] = value;
  }
  return out;
}

export function renderFrontmatter(entries) {
  const lines = entries
    .filter(([, v]) => v !== undefined && v !== null)
    .map(([k, v]) => (v && typeof v === 'object' && !Array.isArray(v)
      ? emitNested(k, v)
      : `${k}: ${emitScalar(v)}`));
  return `---\n${lines.join('\n')}\n---\n`;
}
