// Dockerfile parsing.
//
// Exposes both a flat instruction list and a `finalStage` view, because those
// answer different questions. "Does this image ever run as root" is a question
// about the final stage only: a builder stage without USER is correct and
// normal, and a rule that checks the flat list would flag every multi-stage
// build in existence.

import { annotate, lineOf } from './node.mjs';

const INSTRUCTION = /^\s*([A-Za-z][A-Za-z0-9_]*)\s+([\s\S]*)$/;

export function parseDockerfile(source) {
  const rawLines = source.split(/\r?\n/);
  const instructions = [];

  for (let i = 0; i < rawLines.length; i += 1) {
    let line = rawLines[i];
    const startLine = i + 1;

    const stripped = line.replace(/^\s+/, '');
    if (stripped === '' || stripped.startsWith('#')) continue;

    // Join continuations so `RUN a \` + `  && b` is one instruction.
    while (/\\\s*$/.test(line) && i + 1 < rawLines.length) {
      i += 1;
      line = `${line.replace(/\\\s*$/, '')} ${rawLines[i].replace(/^\s+/, '')}`;
    }

    const m = INSTRUCTION.exec(line);
    if (!m) continue;

    const name = m[1].toUpperCase();
    const args = m[2].trim();
    // Flags like `--from=builder` or `--chown=node:node` are not arguments.
    const flags = [...args.matchAll(/(?:^|\s)(--[a-zA-Z-]+)(?:=(\S+))?/g)]
      .map((f) => ({ name: f[1], value: f[2] ?? true }));
    const bare = args.replace(/(?:^|\s)--[a-zA-Z-]+(?:=\S+)?/g, '').trim();

    instructions.push(annotate({ name, args, bare, flags }, startLine));
  }

  // Split into stages at each FROM.
  const stages = [];
  for (const instr of instructions) {
    if (instr.name === 'FROM') {
      const [image, as, alias] = instr.bare.split(/\s+/);
      stages.push(annotate({
        image: image ?? '',
        alias: /^as$/i.test(as ?? '') ? alias : null,
        instructions: [instr],
      }, lineOf(instr)));
    } else if (stages.length) {
      stages[stages.length - 1].instructions.push(instr);
    }
  }

  const doc = { instructions, stages };
  // The stage that actually ships. Rules about the running container point here.
  doc.finalStage = stages.length ? stages[stages.length - 1] : { image: '', alias: null, instructions: [] };
  return annotate(doc, 1);
}
