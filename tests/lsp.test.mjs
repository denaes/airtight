import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { createLspServer, LSP_SERVER_NAME, LSP_SERVER_VERSION } from '../engine/src/lsp.mjs';

function createMockLspClient() {
  const input = new PassThrough();
  const output = new PassThrough();

  const server = createLspServer({
    input,
    output,
  });

  const messages = [];
  let buffer = Buffer.alloc(0);

  output.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (true) {
      const headerEnd = buffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) break;
      const header = buffer.subarray(0, headerEnd).toString('utf8');
      const match = /Content-Length:\s*(\d+)/i.exec(header);
      if (!match) break;
      const contentLength = parseInt(match[1], 10);
      const bodyStart = headerEnd + 4;
      if (buffer.length < bodyStart + contentLength) break;
      const body = buffer.subarray(bodyStart, bodyStart + contentLength).toString('utf8');
      buffer = buffer.subarray(bodyStart + contentLength);
      try {
        messages.push(JSON.parse(body));
      } catch {}
    }
  });

  async function send(msg) {
    const json = JSON.stringify(msg);
    const len = Buffer.byteLength(json, 'utf8');
    input.write(`Content-Length: ${len}\r\n\r\n${json}`);
    await new Promise((r) => setImmediate(r));
  }

  return {
    send,
    messages,
    close: () => {
      server.close();
      input.end();
      output.end();
    },
  };
}

test('LSP server handles initialize handshake', async () => {
  const client = createMockLspClient();
  try {
    await client.send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { rootUri: 'file:///workspace' },
    });

    assert.strictEqual(client.messages.length, 1);
    const res = client.messages[0];
    assert.strictEqual(res.id, 1);
    assert.strictEqual(res.result.capabilities.textDocumentSync, 1);
    assert.strictEqual(res.result.capabilities.codeActionProvider, true);
    assert.strictEqual(res.result.serverInfo.name, LSP_SERVER_NAME);
  } finally {
    client.close();
  }
});

test('LSP server publishes diagnostics on textDocument/didOpen', async () => {
  const client = createMockLspClient();
  try {
    const vulnCode = `
      const https = require('https');
      const agent = new https.Agent({ rejectUnauthorized: false });
    `;

    await client.send({
      jsonrpc: '2.0',
      method: 'textDocument/didOpen',
      params: {
        textDocument: {
          uri: 'file:///workspace/client.js',
          languageId: 'javascript',
          version: 1,
          text: vulnCode,
        },
      },
    });

    assert.strictEqual(client.messages.length, 1);
    const diagMsg = client.messages[0];
    assert.strictEqual(diagMsg.method, 'textDocument/publishDiagnostics');
    assert.strictEqual(diagMsg.params.uri, 'file:///workspace/client.js');
    assert.ok(diagMsg.params.diagnostics.length > 0, 'Expected diagnostics to be emitted');
    const diag = diagMsg.params.diagnostics[0];
    assert.strictEqual(diag.code, 'js/tls-verification-disabled');
    assert.strictEqual(diag.source, 'airtight');
  } finally {
    client.close();
  }
});

test('LSP server provides QuickFix CodeActions on textDocument/codeAction', async () => {
  const client = createMockLspClient();
  try {
    const vulnCompose = `
services:
  web:
    image: nginx
    privileged: true
`;

    // 1. Open document
    await client.send({
      jsonrpc: '2.0',
      method: 'textDocument/didOpen',
      params: {
        textDocument: {
          uri: 'file:///workspace/docker-compose.yml',
          languageId: 'yaml',
          version: 1,
          text: vulnCompose,
        },
      },
    });

    // 2. Request code actions for line 4 (privileged: true)
    await client.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'textDocument/codeAction',
      params: {
        textDocument: { uri: 'file:///workspace/docker-compose.yml' },
        range: {
          start: { line: 4, character: 0 },
          end: { line: 4, character: 20 },
        },
      },
    });

    assert.strictEqual(client.messages.length, 2);
    const actionRes = client.messages[1];
    assert.strictEqual(actionRes.id, 2);
    const actions = actionRes.result;
    assert.ok(actions.length > 0, 'Expected QuickFix code action');
    assert.strictEqual(actions[0].kind, 'quickfix');
    assert.match(actions[0].title, /Airtight/);
    const edit = actions[0].edit.changes['file:///workspace/docker-compose.yml'];
    assert.ok(edit, 'Expected workspace edit');
    assert.ok(!edit[0].newText.includes('privileged: true'), 'Expected fix to strip privileged: true');
  } finally {
    client.close();
  }
});
