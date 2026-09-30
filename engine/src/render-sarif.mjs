// SARIF 2.1.0 output renderer.
//
// Formats findings for GitHub Code Scanning, GitLab SAST, and DefectDojo.
// Every string scrubs through the vault before returning.

import { VERSION } from './cli.mjs';

function priorityToLevel(priority, severity) {
  if (priority === 'P0' || priority === 'P1') return 'error';
  if (priority === 'P2') return 'warning';
  if (priority === 'P3') return 'note';
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

function confidenceToPrecision(confidence) {
  if (confidence === 'confirmed') return 'very-high';
  if (confidence === 'firm') return 'high';
  return 'medium';
}

export function renderSarif({ findings = [], vault, meta, rules = [], version = VERSION } = {}) {
  const ruleMap = new Map();
  for (const r of rules) {
    if (r?.id) ruleMap.set(r.id, r);
  }

  // Collect rules actually cited in findings, plus any passed in
  const citedRuleIds = new Set(findings.map((f) => f.rule));
  const sarifRules = [];

  for (const ruleId of citedRuleIds) {
    const r = ruleMap.get(ruleId) ?? { id: ruleId };
    const tags = [
      'security',
      r.domain,
      r.cwe,
      r.owasp,
    ].filter(Boolean);

    const ruleName = (r.id || 'rule').replace(/[^a-zA-Z0-9_-]/g, '-');

    sarifRules.push({
      id: r.id,
      name: ruleName,
      shortDescription: { text: r.name || r.id },
      fullDescription: { text: r.why ? r.why.trim() : (r.name || r.id) },
      help: {
        text: `Why: ${r.why || ''}\n\nFix: ${r.fix || ''}`.trim(),
        markdown: `### Why\n\n${r.why || ''}\n\n### Fix\n\n${r.fix || ''}`.trim(),
      },
      properties: {
        tags,
        precision: confidenceToPrecision(r.confidence),
        'problem.severity': r.severity === 'critical' || r.severity === 'high' ? 'error' : 'warning',
      },
      defaultConfiguration: {
        level: priorityToLevel(r.priority, r.severity),
      },
    });
  }

  const results = findings.map((f) => ({
    ruleId: f.rule,
    level: priorityToLevel(f.priority, f.severity),
    message: {
      text: `${f.message}${f.fix ? `\n\nFix: ${f.fix}` : ''}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: f.file,
            uriBaseId: '%SRCROOT%',
          },
          region: {
            startLine: f.line > 0 ? f.line : 1,
            startColumn: f.column > 0 ? f.column : 1,
            snippet: {
              text: f.snippet || '',
            },
          },
        },
      },
    ],
    partialFingerprints: {
      primaryLocationLineHash: f.valueFingerprint || f.id,
    },
    properties: {
      priority: f.priority,
      severity: f.severity,
      confidence: f.confidence,
      ...(f.cwe ? { cwe: f.cwe } : {}),
      ...(f.owasp ? { owasp: f.owasp } : {}),
    },
  }));

  const payload = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'airtight',
            semanticVersion: version,
            informationUri: 'https://github.com/denaes/airtight',
            rules: sarifRules,
          },
        },
        results,
      },
    ],
  };

  const scrubbed = vault?.scrubDeep ? vault.scrubDeep(payload) : payload;
  return JSON.stringify(scrubbed, null, 2);
}
