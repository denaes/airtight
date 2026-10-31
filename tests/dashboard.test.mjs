import test from 'node:test';
import assert from 'node:assert/strict';
import { compileDashboardData, renderTerminalDashboard } from '../engine/src/dashboard.mjs';

test('Dashboard: compiles telemetry data from controls, attack surface, and guardrails', () => {
  const root = process.cwd();
  const data = compileDashboardData(root);

  assert.equal(data.version, '0.9.0');
  assert.ok(data.timestamp);
  assert.ok(data.controls.summary.total > 0);
  assert.ok(data.guard.totalRules > 0);
  assert.equal(typeof data.guard.byTool.bash, 'number');
  assert.equal(typeof data.attackSurface.totalRoutes, 'number');
});

test('Dashboard: renders formatted terminal dashboard text', () => {
  const root = process.cwd();
  const data = compileDashboardData(root);
  const rendered = renderTerminalDashboard(data);

  assert.match(rendered, /AIRTIGHT SECURITY DASHBOARD/);
  assert.match(rendered, /COMPLIANCE & CONTROL READINESS/);
  assert.match(rendered, /ATTACK SURFACE & INGRESS EXPOSURE/);
  assert.match(rendered, /AGENT TOOL FIREWALL & GUARDRAIL TELEMETRY/);
});
