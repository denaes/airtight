import test from 'node:test';
import assert from 'node:assert/strict';
import { traceFileTaint, findTaintPathForSink, enrichFindingsWithTaint } from '../engine/src/taint.mjs';

test('JS/TS: traces req.query destructuring through concat to db.query sink', () => {
  const code = `
    const express = require('express');
    const app = express();

    app.get('/users', (req, res) => {
      const { id } = req.query;
      const sqlQuery = "SELECT * FROM users WHERE id = " + id; // airtight-disable-line js/sql-string-concat
      db.query(sqlQuery);
      res.send('ok');
    });
  `;
  const lines = code.split('\n');
  const tracker = traceFileTaint(code, lines, '.js');

  assert.ok(tracker.taintedVars.has('id'), 'Expected id to be marked tainted');
  assert.ok(tracker.taintedVars.has('sqlQuery'), 'Expected sqlQuery to be marked tainted via propagation');

  const taint = findTaintPathForSink(tracker, 8, 'db.query(sqlQuery);');
  assert.ok(taint, 'Expected taint path to be found for db.query sink');
  assert.equal(taint.hasTaint, true);
  assert.equal(taint.sinkType, 'sql');
  assert.ok(taint.pathSummary.includes('id -> sqlQuery -> sql'));
});

test('Python: traces request.args through f-string to os.system sink', () => {
  const code = `
    from flask import Flask, request
    import os

    app = Flask(__name__)

    @app.route('/ping')
    def ping():
        target = request.args.get('target')
        cmd = f"ping -c 1 {target}"
        os.system(cmd)
        return "done"
  `;
  const lines = code.split('\n');
  const tracker = traceFileTaint(code, lines, '.py');

  assert.ok(tracker.taintedVars.has('target'));
  assert.ok(tracker.taintedVars.has('cmd'));

  const taint = findTaintPathForSink(tracker, 11, 'os.system(cmd)');
  assert.ok(taint);
  assert.equal(taint.sinkType, 'exec');
  assert.ok(taint.pathSummary.includes('target -> cmd -> exec'));
});

test('Go: traces c.Query through fmt.Sprintf to db.Exec sink', () => {
  const code = `
    func GetUser(c *gin.Context) {
        q := c.Query("q")
        sql := fmt.Sprintf("SELECT * FROM items WHERE name = '%s'", q)
        db.Exec(sql)
    }
  `;
  const lines = code.split('\n');
  const tracker = traceFileTaint(code, lines, '.go');

  assert.ok(tracker.taintedVars.has('q'));
  assert.ok(tracker.taintedVars.has('sql'));

  const taint = findTaintPathForSink(tracker, 5, 'db.Exec(sql)');
  assert.ok(taint);
  assert.equal(taint.sinkType, 'sql');
  assert.ok(taint.pathSummary.includes('q -> sql -> sql'));
});

test('Java: traces request.getParameter to fetch / HTTP sink', () => {
  const code = `
    public void handle(HttpServletRequest request) {
        String targetUrl = request.getParameter("url");
        HttpClient.newHttpClient().send(targetUrl);
    }
  `;
  const lines = code.split('\n');
  const tracker = traceFileTaint(code, lines, '.java');

  assert.ok(tracker.taintedVars.has('targetUrl'));

  const taint = findTaintPathForSink(tracker, 4, 'HttpClient.newHttpClient().send(targetUrl);');
  assert.ok(taint);
  assert.equal(taint.sinkType, 'ssrf');
});

test('PHP: traces $_GET to raw SQL query sink', () => {
  const code = `
    $userId = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id = " . $userId;
    $db->query($sql);
  `;
  const lines = code.split('\n');
  const tracker = traceFileTaint(code, lines, '.php');

  assert.ok(tracker.taintedVars.has('$userId'));
  assert.ok(tracker.taintedVars.has('$sql'));

  const taint = findTaintPathForSink(tracker, 4, '$db->query($sql);');
  assert.ok(taint);
  assert.equal(taint.sinkType, 'sql');
});

test('C#: traces Request.Query to Process.Start sink', () => {
  const code = `
    string userInput = Request.Query["cmd"];
    string fullCmd = "sh -c " + userInput;
    Process.Start(fullCmd);
  `;
  const lines = code.split('\n');
  const tracker = traceFileTaint(code, lines, '.cs');

  assert.ok(tracker.taintedVars.has('userInput'));
  assert.ok(tracker.taintedVars.has('fullCmd'));

  const taint = findTaintPathForSink(tracker, 4, 'Process.Start(fullCmd);');
  assert.ok(taint);
  assert.equal(taint.sinkType, 'exec');
});

test('Benign / Static query has no taint detected', () => {
  const code = `
    const sql = "SELECT * FROM users WHERE active = 1";
    db.query(sql);
  `;
  const lines = code.split('\n');
  const tracker = traceFileTaint(code, lines, '.js');

  assert.equal(tracker.taintedVars.size, 0);
  const taint = findTaintPathForSink(tracker, 3, 'db.query(sql);');
  assert.equal(taint, null);
});

test('enrichFindingsWithTaint: elevates confidence and attaches taintPath', () => {
  const file = 'app.js';
  const code = `
    app.get('/search', (req, res) => {
      const q = req.query.q;
      const sql = "SELECT * FROM articles WHERE title LIKE '%" + q + "%'"; // airtight-disable-line js/sql-string-concat
      db.query(sql);
    });
  `;
  const fileContentMap = new Map([[file, code]]);

  const findings = [
    {
      file,
      line: 5,
      snippet: 'db.query(sql);',
      rule: 'js/sql-string-concat',
      severity: 'high',
      confidence: 'firm',
      priority: 'P2',
    },
  ];

  const enriched = enrichFindingsWithTaint(findings, fileContentMap);
  assert.equal(enriched[0].reachable, true);
  assert.equal(enriched[0].confidence, 'confirmed');
  assert.equal(enriched[0].priority, 'P1');
  assert.ok(enriched[0].taintPath.includes('q -> sql -> sql'));
});
