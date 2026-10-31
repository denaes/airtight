// Native Language Server Protocol (LSP 3.17) server for Airtight.
//
// Exposes instantaneous (<15ms) security diagnostics and 1-click QuickFix
// code actions to IDEs (VS Code, Neovim, Zed, Cursor, Sublime) over stdio.
//
// Pure Node.js ESM implementation with zero external dependencies.

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

import { compileAll, immediateTier } from './rules.mjs';
import { matchText } from './match/text.mjs';
import { matchStructured } from './match/structured.mjs';
import { matchCustom } from './match/custom.mjs';
import { createVault } from './redact.mjs';
import { buildWaiverIndex } from './waivers.mjs';
import { matchesAny } from './glob.mjs';
import { FIXERS } from './fix.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const LSP_SERVER_NAME = 'airtight-lsp';
export const LSP_SERVER_VERSION = '0.10.0';

function loadRulesBundle(env = process.env) {
  if (env.AIRTIGHT_RULES && existsSync(env.AIRTIGHT_RULES)) {
    return compileAll(JSON.parse(readFileSync(env.AIRTIGHT_RULES, 'utf8')));
  }
  const candidates = [
    join(HERE, '..', 'build', 'rules.json'),
    join(HERE, '..', '..', 'skill', 'scripts', 'rules.json'),
    join(HERE, '..', '..', 'rules.json'),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      return compileAll(JSON.parse(readFileSync(p, 'utf8')));
    }
  }
  return [];
}

/**
 * Scan a single document's text against immediate-tier rules and return LSP Diagnostics.
 */
export function scanDocumentForLsp(uri, text, rules) {
  let relPath = uri;
  try {
    if (uri.startsWith('file://')) {
      relPath = basename(fileURLToPath(uri));
    }
  } catch {
    relPath = uri.split('/').pop() || 'document.js';
  }

  const lines = text.split(/\r?\n/);
  const isWaived = buildWaiverIndex(lines);
  const vault = createVault();
  const parseCache = new Map();
  const ctx = {
    content: text,
    lines,
    relPath,
    vault,
    isWaived,
    parseCache,
    sensitiveFile: false,
  };

  const applicable = rules.filter((r) => matchesAny(relPath, r.files) && !matchesAny(relPath, r.exclude));
  const findings = [];

  for (const rule of applicable) {
    try {
      if (rule.parse === 'text') findings.push(...matchText(rule, ctx));
      else if (rule.parse === 'js') findings.push(...matchCustom(rule, ctx));
      else findings.push(...matchStructured(rule, ctx));
    } catch {
      // Fail open on rule errors
    }
  }

  // Convert Airtight findings to LSP Diagnostic items
  return findings.map((f) => {
    const lineIndex = Math.max(0, (f.line || 1) - 1);
    const lineLen = lines[lineIndex]?.length || 80;
    const severity = (f.priority === 'P0' || f.priority === 'P1' || f.severity === 'critical') ? 1 : 2;

    return {
      range: {
        start: { line: lineIndex, character: 0 },
        end: { line: lineIndex, character: lineLen },
      },
      severity,
      code: f.rule,
      source: 'airtight',
      message: `${f.title || f.rule}${f.cwe ? ` [${f.cwe}]` : ''}: ${f.why || 'Security policy violation.'}${f.fix ? `\nFix: ${f.fix}` : ''}`,
      data: {
        rule: f.rule,
        fixable: Boolean(FIXERS[f.rule]),
      },
    };
  });
}

/**
 * Creates an in-process or stdio LSP server instance.
 */
export function createLspServer({ input = process.stdin, output = process.stdout, env = process.env } = {}) {
  const documents = new Map(); // uri -> { text, version }
  const docDiagnostics = new Map(); // uri -> Diagnostic[]
  let rules = immediateTier(loadRulesBundle(env));
  let isShutdown = false;

  let buffer = Buffer.alloc(0);

  function send(msg) {
    const json = JSON.stringify(msg);
    const len = Buffer.byteLength(json, 'utf8');
    output.write(`Content-Length: ${len}\r\n\r\n${json}`);
  }

  function sendResult(id, result) {
    send({ jsonrpc: '2.0', id, result });
  }

  function sendNotification(method, params) {
    send({ jsonrpc: '2.0', method, params });
  }

  function sendError(id, code, message) {
    send({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
  }

  function publishDiagnostics(uri, text) {
    const diagnostics = scanDocumentForLsp(uri, text, rules);
    docDiagnostics.set(uri, diagnostics);
    sendNotification('textDocument/publishDiagnostics', {
      uri,
      diagnostics,
    });
  }

  async function handleMessage(msg) {
    const { id, method, params } = msg;

    if (id === undefined || id === null) {
      // Notifications
      switch (method) {
        case 'initialized':
          break;

        case 'textDocument/didOpen': {
          if (params?.textDocument) {
            const { uri, text, version } = params.textDocument;
            documents.set(uri, { text, version });
            publishDiagnostics(uri, text);
          }
          break;
        }

        case 'textDocument/didChange': {
          if (params?.textDocument && params.contentChanges?.length) {
            const { uri, version } = params.textDocument;
            // Full content sync (capability textDocumentSync: 1)
            const text = params.contentChanges[params.contentChanges.length - 1].text;
            documents.set(uri, { text, version });
            publishDiagnostics(uri, text);
          }
          break;
        }

        case 'textDocument/didClose': {
          if (params?.textDocument?.uri) {
            const { uri } = params.textDocument;
            documents.delete(uri);
            docDiagnostics.delete(uri);
            sendNotification('textDocument/publishDiagnostics', { uri, diagnostics: [] });
          }
          break;
        }

        case 'exit': {
          process.exit(isShutdown ? 0 : 1);
          break;
        }
      }
      return;
    }

    // Requests
    try {
      switch (method) {
        case 'initialize': {
          sendResult(id, {
            capabilities: {
              textDocumentSync: 1, // Full document sync
              codeActionProvider: true,
            },
            serverInfo: {
              name: LSP_SERVER_NAME,
              version: LSP_SERVER_VERSION,
            },
          });
          break;
        }

        case 'shutdown': {
          isShutdown = true;
          sendResult(id, null);
          break;
        }

        case 'textDocument/codeAction': {
          const uri = params?.textDocument?.uri;
          const range = params?.range;
          const actions = [];

          if (uri && range && documents.has(uri)) {
            const doc = documents.get(uri);
            const diagnostics = docDiagnostics.get(uri) || [];

            // Find matching diagnostics on or near current line
            for (const diag of diagnostics) {
              const lineMatch = Math.abs(diag.range.start.line - range.start.line) <= 2;
              if (lineMatch && diag.data?.fixable) {
                const fixer = FIXERS[diag.data.rule];
                if (fixer) {
                  const fixedText = fixer.fix(doc.text);
                  if (fixedText && fixedText !== doc.text) {
                    const lineCount = doc.text.split(/\r?\n/).length;
                    actions.push({
                      title: `Airtight: ${fixer.name}`,
                      kind: 'quickfix',
                      isPreferred: true,
                      diagnostics: [diag],
                      edit: {
                        changes: {
                          [uri]: [
                            {
                              range: {
                                start: { line: 0, character: 0 },
                                end: { line: lineCount + 1, character: 0 },
                              },
                              newText: fixedText,
                            },
                          ],
                        },
                      },
                    });
                  }
                }
              }
            }
          }

          sendResult(id, actions);
          break;
        }

        default: {
          sendError(id, -32601, `Method not found: ${method}`);
          break;
        }
      }
    } catch (err) {
      sendError(id, -32603, `Internal error: ${err.message}`);
    }
  }

  const onData = (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (true) {
      const headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) break;

      const header = buffer.subarray(0, headerEnd).toString('utf8');
      const match = /Content-Length:\s*(\d+)/i.exec(header);
      if (!match) {
        buffer = buffer.subarray(headerEnd + 4);
        continue;
      }

      const contentLength = parseInt(match[1], 10);
      const bodyStart = headerEnd + 4;
      if (buffer.length < bodyStart + contentLength) {
        // Incomplete message body; wait for next chunk
        break;
      }

      const body = buffer.subarray(bodyStart, bodyStart + contentLength).toString('utf8');
      buffer = buffer.subarray(bodyStart + contentLength);

      try {
        const msg = JSON.parse(body);
        handleMessage(msg);
      } catch {}
    }
  };

  input.on('data', onData);

  return {
    close: () => {
      input.removeListener('data', onData);
    },
    send,
  };
}

export function runLspServer(io = { out: (s) => process.stdout.write(s) }, env = process.env) {
  return new Promise((resolve) => {
    const server = createLspServer({
      input: process.stdin,
      output: process.stdout,
      env,
    });
    const finish = () => {
      server.close();
      resolve(0);
    };
    process.stdin.on('close', finish);
    process.stdin.on('end', finish);
  });
}
