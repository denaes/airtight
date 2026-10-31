// Agent Context & Memory Poisoning Shield (airtight shield).
//
// Protects AI coding agents from indirect prompt injection, memory hijacking,
// and invisible Unicode instruction smuggling in documentation, instructions,
// and prompt templates.

import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { resolve, relative, basename } from 'node:path';
import { collectTargets } from './scan.mjs';

export const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\u200E\u200F\u2060\uFEFF]/g;
export const ZERO_WIDTH_SEQUENCE_REGEX = /[\u200B\u200C\u200D\u2060\uFEFF]{2,}/;

export const INJECTION_PATTERNS = [
  {
    type: 'instruction-override',
    regex: /(?:\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|directives|prompts|system\s+messages?)\b|\[(?:SYSTEM|INSTRUCTION|OVERRIDE)\]\s*(?:new\s+instructions|disregard|ignore)|\bSYSTEM\s+PROMPT\s+OVERRIDE\s*[:\-]|\bNEW\s+DIRECTIVE:\s*DISREGARD\b|\byou\s+are\s+now\s+in\s+developer\s+mode\b)/i,
    notRegex: /(?:how\s+to\s+prevent|mitigate|defense\s+against|airtight|detection|vulnerability|example|e\.g\.|evidence|attack|finding)/i,
    severity: 'critical',
    cwe: 'CWE-74',
    description: 'System instruction override / jailbreak directive detected',
  },
  {
    type: 'exfiltration-lure',
    regex: /(?:(?:\b(?:send|exfiltrate|transmit|upload|post)\s+(?:all\s+)?(?:the\s+contents\s+of\s+)?(?:\.env|id_[rd]sa|api[_-]?keys?|secrets?|credentials?)\b\s+(?:to|at)\s+https?:\/\/|(?:curl|wget)\s+[^\n|;&]+(?:@|\/|\$)(?:\.env|id_[rd]sa|\.aws\/credentials)))/i,
    severity: 'critical',
    cwe: 'CWE-200',
    description: 'Credential exfiltration lure targeting model file access',
  },
  {
    type: 'delimiter-hijacking',
    regex: /(?:<\/context>[\s\S]*<context>|<\/system>[\s\S]*<system>|<\/instruction>[\s\S]*<instruction>)/i,
    severity: 'high',
    cwe: 'CWE-74',
    description: 'Fake prompt boundary delimiter injection',
  },
];

/**
 * Scan a single string or file content for prompt poisoning threats.
 */
export function inspectContentForShield(content, filePath = 'inline') {
  const threats = [];
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;

    // 1. Check for invisible unicode smuggling
    if (ZERO_WIDTH_SEQUENCE_REGEX.test(line)) {
      const match = line.match(ZERO_WIDTH_REGEX);
      threats.push({
        file: filePath,
        line: lineNo,
        type: 'invisible-unicode',
        severity: 'high',
        cwe: 'CWE-74',
        snippet: line.trim().slice(0, 100),
        description: `Embedded ${match?.length || 2}+ hidden zero-width Unicode characters`,
        remediation: 'Strip invisible zero-width unicode characters using: airtight shield --sanitize',
      });
    }

    // 2. Check for prompt injection / instruction override patterns
    for (const pat of INJECTION_PATTERNS) {
      if (pat.regex.test(line)) {
        if (pat.notRegex && pat.notRegex.test(line)) continue;
        threats.push({
          file: filePath,
          line: lineNo,
          type: pat.type,
          severity: pat.severity,
          cwe: pat.cwe,
          snippet: line.trim().slice(0, 120),
          description: pat.description,
          remediation: 'Enclose untrusted external input within strict data delimiters or remove malicious directive.',
        });
      }
    }
  }

  return threats;
}

/**
 * Strips zero-width and invisible unicode characters from content.
 */
export function sanitizeContent(content) {
  return content.replace(ZERO_WIDTH_REGEX, '');
}

/**
 * Run context shield sweep across repository files or markdown/prompts.
 */
export function scanWorkspaceShield(targetPaths = ['.'], { root = process.cwd(), sanitize = false } = {}) {
  const absPaths = targetPaths.map((p) => resolve(root, p));
  const files = collectTargets(root, absPaths);
  const relevantFiles = files.filter((f) => {
    const b = basename(f);
    return /\.(md|txt|prompt|json|yaml|yml|js|ts|py)$/i.test(b)
      && !/(node_modules|dist|\.git|\.airtight|fixtures|engine\/rules)[/\\]/.test(f)
      && !f.endsWith('rules.json')
      && !f.endsWith('docs/rules.md');
  });

  const threats = [];
  let sanitizedCount = 0;

  for (const absFile of relevantFiles) {
    const relFile = relative(root, absFile);
    let content;
    try {
      content = readFileSync(absFile, 'utf8');
    } catch {
      continue;
    }

    const fileThreats = inspectContentForShield(content, relFile);
    if (fileThreats.length > 0) {
      threats.push(...fileThreats);

      if (sanitize) {
        const cleaned = sanitizeContent(content);
        if (cleaned !== content) {
          writeFileSync(absFile, cleaned, 'utf8');
          sanitizedCount++;
        }
      }
    }
  }

  return {
    scannedFiles: relevantFiles.length,
    threats,
    threatsCount: threats.length,
    sanitizedCount,
  };
}
