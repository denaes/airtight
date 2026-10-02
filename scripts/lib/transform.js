// Per-provider transform: skill/ in, dist/<provider>/<configDir>/ out.

import { cpSync, mkdirSync, readdirSync, readFileSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { FIELD_RENAMES, placeholdersFor } from './providers.js';
import { STANDALONE } from './hook-manifests.js';
import {
  compileProviderBlocks, replacePlaceholders, splitFrontmatter,
  parseFrontmatter, renderFrontmatter,
} from './utils.js';

const SKILL_NAME = 'airtight';

const DEGRADED_PREAMBLE = `<!-- Generated from skill/agents/ at build time. Do not edit; edit the agent definition. -->
This harness has no sub-agent capability, so you are running this role inline. Step fully out of the work you just finished, adopt only this file's instructions for the pass, and disclose the substitution in one line when you report. Where the text below addresses a parent agent, you are both parties: produce the full output contract first, then act on it yourself.

Note what you lose by running inline. This role exists in a separate context because judgment anchors: having just read the detector's output, or having just written the code, changes what you notice. Say so rather than implying an isolated pass.

`;

const render = (text, config, scriptsPath) =>
  replacePlaceholders(compileProviderBlocks(text, config.providerTags), config.provider, scriptsPath);

const write = (path, body) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, body);
};

// ------------------------------------------------------------------- agents

/**
 * TOML multiline literal. Prefers ''' and escapes into """ only when the body
 * itself contains '''.
 */
function tomlMultiline(body) {
  if (!body.includes("'''")) return `'''\n${body}\n'''`;
  return `"""\n${body.replace(/\\/g, '\\\\').replace(/"""/g, '\\"\\"\\"')}\n"""`;
}

const tomlString = (s) => JSON.stringify(String(s));

function emitAgent(config, scriptsPath, outRoot, file, data, body) {
  const rendered = render(body, config, scriptsPath).trimStart();
  const renames = FIELD_RENAMES[config.agentFormat] ?? {};
  const dir = join(outRoot, config.agentDir ?? 'agents');
  const tools = String(data.tools ?? '').split(',').map((t) => t.trim()).filter(Boolean);

  if (config.agentFormat === 'codex-toml') {
    const name = String(data.name).replace(/-/g, '_');
    const lines = [
      `name = ${tomlString(name)}`,
      `description = ${tomlString(data.description)}`,
    ];
    if (data.effort) lines.push(`model_reasoning_effort = ${tomlString(data.effort)}`);
    // tools, model and max-turns have no Codex equivalent and are dropped
    // rather than emitted as keys its validator would reject.
    lines.push(`developer_instructions = ${tomlMultiline(rendered)}`);
    write(join(dir, `${name}.toml`), `${lines.join('\n')}\n`);
    return;
  }

  const entries = [['name', data.name], ['description', data.description]];

  if (config.agentFormat === 'cursor-md') {
    entries.push(['model', data.model ?? 'inherit']);
    // Cursor expresses capability as a flag rather than a tool list. Both our
    // agents are read-only, so both get it; deriving rather than hardcoding
    // means an agent that later gains Write loses the flag automatically.
    if (tools.length && !tools.includes('Write') && !tools.includes('Edit')) entries.push(['readonly', true]);
    entries.push(['is_background', false]);
    // `effort` is skipped: Cursor's effort option requires an explicit model id.
  } else if (config.agentFormat === 'copilot-agent-md') {
    // tools omitted deliberately: omitting grants all tools, and Copilot's
    // tool vocabulary does not match ours.
  } else {
    for (const key of ['tools', 'model', 'effort', 'max-turns']) {
      if (data[key] !== undefined) entries.push([renames[key] ?? key, data[key]]);
    }
  }

  const suffix = config.agentFormat === 'copilot-agent-md' ? '.agent.md' : '.md';
  write(join(dir, file.replace(/\.md$/, suffix)), renderFrontmatter(entries) + rendered);
}

/** Codex reads an interface descriptor alongside the skill. */
function emitOpenAIMetadata(skillOut, data) {
  const short = data.description.length <= 88
    ? data.description
    : `${data.description.slice(0, 88).replace(/\s+\S*$/, '')}...`;
  write(join(skillOut, 'agents', 'openai.yaml'), [
    'interface:',
    '  display_name: Airtight',
    `  short_description: ${JSON.stringify(short)}`,
    '  default_prompt: "Use airtight to review, audit, or harden the security of this project."',
    '',
  ].join('\n'));
}

export function syncDegradedAgents(skillDir) {
  const agentFiles = readdirSync(join(skillDir, 'agents')).filter((f) => f.endsWith('.md'));
  const degradedDir = join(skillDir, 'reference', 'degraded');
  mkdirSync(degradedDir, { recursive: true });
  for (const file of agentFiles) {
    const { raw: aRaw, body: aBody } = splitFrontmatter(readFileSync(join(skillDir, 'agents', file), 'utf8'));
    writeFileSync(join(degradedDir, file.replace(/^airtight-/, '')),
      DEGRADED_PREAMBLE + aBody.trimStart());
  }
}

// -------------------------------------------------------------------- main

export function transform(skillDir, distDir, config, { version, symlinks = false }) {
  const outRoot = join(distDir, config.provider, config.configDir);
  const skillOut = join(outRoot, 'skills', SKILL_NAME);
  const scriptsPath = `${config.configDir}/skills/${SKILL_NAME}/scripts`;

  rmSync(join(distDir, config.provider), { recursive: true, force: true });
  mkdirSync(skillOut, { recursive: true });

  // SKILL.src.md is named that way on purpose: a loader discovers a skill by
  // finding a literal SKILL.md, so the source must not be one.
  const src = readFileSync(join(skillDir, 'SKILL.src.md'), 'utf8');
  const { raw, body } = splitFrontmatter(src);
  const data = parseFrontmatter(raw);

  const fm = [['name', data.name], ['description', data.description]];
  if (config.versionInMetadata) fm.push(['metadata', { version }]);
  else fm.push(['version', version]);
  for (const key of config.frontmatterFields) {
    if (data[key] !== undefined) fm.push([key, data[key]]);
  }
  write(join(skillOut, 'SKILL.md'), renderFrontmatter(fm) + render(body, config, scriptsPath).trimStart());

  if (symlinks) {
    const refTarget = relative(skillOut, join(skillDir, 'reference'));
    symlinkSync(refTarget, join(skillOut, 'reference'));
    const scriptsTarget = relative(skillOut, join(skillDir, 'scripts'));
    symlinkSync(scriptsTarget, join(skillOut, 'scripts'));
  } else {
    cpSync(join(skillDir, 'reference'), join(skillOut, 'reference'), { recursive: true });
    cpSync(join(skillDir, 'scripts'), join(skillOut, 'scripts'), { recursive: true });
  }

  // Agents in this provider's format
  const agentFiles = readdirSync(join(skillDir, 'agents')).filter((f) => f.endsWith('.md'));
  for (const file of agentFiles) {
    const { raw: aRaw, body: aBody } = splitFrontmatter(readFileSync(join(skillDir, 'agents', file), 'utf8'));
    const aData = parseFrontmatter(aRaw);
    if (config.agentFormat !== 'none') emitAgent(config, scriptsPath, outRoot, file, aData, aBody);
  }

  if (config.writeOpenAIMetadata) emitOpenAIMetadata(skillOut, data);

  // OpenCode registers skill commands natively but its autocomplete hides
  // them, so a thin command file is emitted as a discoverability bridge.
  if (config.commandBridge) {
    write(join(outRoot, 'commands', `${SKILL_NAME}.md`),
      `Call skill({ name: "${SKILL_NAME}" }) and follow its Setup and Commands sections to handle $ARGUMENTS.\n`);
  }

  // Harnesses that read a standalone hook manifest get one written here.
  // Claude Code uses a settings file the user also owns, so that one is merged
  // by the installer rather than written whole.
  let hookManifest = null;
  const standalone = STANDALONE[config.hooks];
  if (standalone) {
    hookManifest = join(config.hooksDir ?? config.configDir, standalone.file);
    write(join(distDir, config.provider, hookManifest),
      `${JSON.stringify(standalone.build(config.configDir), null, 2)}\n`);
  }

  return {
    skillOut, outRoot, scriptsPath, hookManifest,
    agents: config.agentFormat === 'none' ? 0 : agentFiles.length,
    placeholders: placeholdersFor(config.provider),
  };
}
