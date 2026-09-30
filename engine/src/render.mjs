// Output rendering. Every path out of the engine funnels through here, and
// every path scrubs through the vault before returning a string.

const PRIORITY_ORDER = ['P0', 'P1', 'P2', 'P3'];

export function renderJson({ findings, vault, meta }) {
  const payload = vault.scrubDeep({ version: 1, ...meta, findings });
  return JSON.stringify(payload, null, 2);
}

export function renderText({ findings, vault, meta }) {
  const baselineNote = meta?.baselineIgnored ? ` (${meta.baselineIgnored} baseline finding(s) ignored)` : '';
  if (findings.length === 0) {
    return vault.scrub(`airtight: no findings in ${meta.filesScanned} file(s)${baselineNote}.`);
  }

  const byFile = new Map();
  for (const f of findings) {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  }

  const out = [];
  const counts = tally(findings);
  out.push(`airtight: ${findings.length} finding(s) in ${byFile.size} file(s) (${counts})${baselineNote}.`);
  out.push('');

  for (const [file, group] of byFile) {
    out.push(file);
    for (const f of group) {
      const cwe = f.cwe ? ` · ${f.cwe}` : '';
      out.push(`  L${f.line} [${f.priority}] ${f.rule}${cwe} · ${f.severity}/${f.confidence}`);
      out.push(`       ${f.message}`);
      out.push(`       ${f.snippet}`);
      out.push(`       fix: ${f.fix}`);
    }
    out.push('');
  }

  return vault.scrub(out.join('\n').trimEnd());
}

function tally(findings) {
  const counts = {};
  for (const f of findings) counts[f.priority] = (counts[f.priority] ?? 0) + 1;
  return PRIORITY_ORDER.filter((p) => counts[p]).map((p) => `${counts[p]} ${p}`).join(', ');
}
