import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { createMcpServer, TOOLS, SERVER_NAME, SERVER_VERSION, PROTOCOL_VERSION } from '../engine/src/mcp.mjs';

function createMockMcpClient() {
  const input = new PassThrough();
  const output = new PassThrough();
  output.setEncoding('utf8');

  const server = createMcpServer({
    root: process.cwd(),
    input,
    output,
  });

  const responses = [];
  let buffer = '';

  output.on('data', (chunk) => {
    buffer += chunk;
    const lines = buffer.split('\n');
    buffer = lines.pop(); // keep partial line
    for (const line of lines) {
      if (line.trim()) {
        try {
          responses.push(JSON.parse(line));
        } catch {}
      }
    }
  });

  async function send(msg) {
    input.write(JSON.stringify(msg) + '\n');
    // wait next event loop tick
    await new Promise((r) => setImmediate(r));
  }

  return {
    send,
    responses,
    close: () => {
      server.close();
      input.end();
      output.end();
    },
  };
}

test('MCP server handles initialize handshake', async () => {
  const client = createMockMcpClient();
  try {
    await client.send({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { clientInfo: { name: 'test-client', version: '1.0.0' } },
    });

    assert.strictEqual(client.responses.length, 1);
    const res = client.responses[0];
    assert.strictEqual(res.jsonrpc, '2.0');
    assert.strictEqual(res.id, 1);
    assert.strictEqual(res.result.protocolVersion, PROTOCOL_VERSION);
    assert.strictEqual(res.result.serverInfo.name, SERVER_NAME);
    assert.strictEqual(res.result.serverInfo.version, SERVER_VERSION);
    assert.ok(res.result.capabilities.tools);
  } finally {
    client.close();
  }
});

test('MCP server handles ping and notifications/initialized', async () => {
  const client = createMockMcpClient();
  try {
    // 1. Notification (no id)
    await client.send({
      jsonrpc: '2.0',
      method: 'notifications/initialized',
    });
    assert.strictEqual(client.responses.length, 0);

    // 2. Ping
    await client.send({
      jsonrpc: '2.0',
      id: 2,
      method: 'ping',
    });
    assert.strictEqual(client.responses.length, 1);
    assert.strictEqual(client.responses[0].id, 2);
    assert.deepStrictEqual(client.responses[0].result, {});
  } finally {
    client.close();
  }
});

test('MCP server lists all Airtight tools with inputSchema', async () => {
  const client = createMockMcpClient();
  try {
    await client.send({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/list',
    });

    assert.strictEqual(client.responses.length, 1);
    const { tools } = client.responses[0].result;
    assert.strictEqual(tools.length, 9);

    const names = tools.map((t) => t.name);
    assert.ok(names.includes('airtight_detect'));
    assert.ok(names.includes('airtight_map'));
    assert.ok(names.includes('airtight_correlate'));
    assert.ok(names.includes('airtight_rules'));
    assert.ok(names.includes('airtight_findings'));
    assert.ok(names.includes('airtight_controls'));
    assert.ok(names.includes('airtight_sbom'));
    assert.ok(names.includes('airtight_cvss'));
    assert.ok(names.includes('airtight_fix'));

    for (const tool of tools) {
      assert.ok(tool.description);
      assert.strictEqual(tool.inputSchema.type, 'object');
    }
  } finally {
    client.close();
  }
});

test('MCP server executes airtight_rules, airtight_sbom, and airtight_cvss tools', async () => {
  const client = createMockMcpClient();
  try {
    // 1. airtight_rules
    await client.send({
      jsonrpc: '2.0',
      id: 10,
      method: 'tools/call',
      params: {
        name: 'airtight_rules',
        arguments: { packs: ['secret'] },
      },
    });

    assert.strictEqual(client.responses.length, 1);
    const rulesRes = client.responses[0].result;
    assert.strictEqual(rulesRes.content[0].type, 'text');
    const rules = JSON.parse(rulesRes.content[0].text);
    assert.ok(Array.isArray(rules));
    assert.ok(rules.some((r) => r.id === 'secret/anthropic-key'));

    // 2. airtight_sbom
    await client.send({
      jsonrpc: '2.0',
      id: 11,
      method: 'tools/call',
      params: {
        name: 'airtight_sbom',
        arguments: {},
      },
    });

    assert.strictEqual(client.responses.length, 2);
    const sbomRes = client.responses[1].result;
    assert.strictEqual(sbomRes.content[0].type, 'text');
    const sbom = JSON.parse(sbomRes.content[0].text);
    assert.strictEqual(sbom.bomFormat, 'CycloneDX');
    assert.strictEqual(sbom.specVersion, '1.5');

    // 3. airtight_cvss
    await client.send({
      jsonrpc: '2.0',
      id: 12,
      method: 'tools/call',
      params: {
        name: 'airtight_cvss',
        arguments: {
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        },
      },
    });

    assert.strictEqual(client.responses.length, 3);
    const cvssRes = client.responses[2].result;
    assert.strictEqual(cvssRes.content[0].type, 'text');
    const cvssData = JSON.parse(cvssRes.content[0].text);
    assert.strictEqual(cvssData.score, 9.8);
    assert.strictEqual(cvssData.severity, 'critical');
    assert.strictEqual(cvssData.priority, 'P0');
  } finally {
    client.close();
  }
});

test('MCP server returns standard JSON-RPC 2.0 error codes', async () => {
  const client = createMockMcpClient();
  try {
    // 1. Method not found (-32601)
    await client.send({
      jsonrpc: '2.0',
      id: 99,
      method: 'non_existent_method',
    });
    assert.strictEqual(client.responses.length, 1);
    assert.strictEqual(client.responses[0].error.code, -32601);

    // 2. Missing tool name (-32602)
    await client.send({
      jsonrpc: '2.0',
      id: 100,
      method: 'tools/call',
      params: {},
    });
    assert.strictEqual(client.responses.length, 2);
    assert.strictEqual(client.responses[1].error.code, -32602);
  } finally {
    client.close();
  }
});
