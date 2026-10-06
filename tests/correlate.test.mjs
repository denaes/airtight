import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  extractIngressRules,
  extractServicePorts,
  correlateAttackSurface,
} from '../engine/src/correlate.mjs';
import { run } from '../engine/src/cli.mjs';

function createTempProject(files) {
  const dir = mkdtempSync(join(tmpdir(), 'airtight-correlate-test-'));
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = join(dir, relPath);
    mkdirSync(join(fullPath, '..'), { recursive: true });
    writeFileSync(fullPath, content, 'utf8');
  }
  return {
    dir,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

test('extractIngressRules identifies public and internal Terraform ingress', () => {
  const proj = createTempProject({
    'infra/main.tf': `
resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = "sg-123"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "google_compute_firewall" "allow_web" {
  name          = "allow-web"
  source_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}

resource "azurerm_network_security_rule" "allow_ssh" {
  name                       = "allow-ssh"
  access                     = "Allow"
  direction                  = "Inbound"
  source_address_prefix      = "*"
  destination_port_range     = "22"
  protocol                   = "Tcp"
}
`,
  });

  try {
    const rules = extractIngressRules(['.'], { root: proj.dir });
    assert.strictEqual(rules.length >= 5, true);

    const publicRules = rules.filter((r) => r.isPublic);
    const internalRules = rules.filter((r) => !r.isPublic);

    // Port 80 is public
    assert.ok(publicRules.some((r) => r.fromPort === 80 && r.isPublic));
    // Port 443 is public
    assert.ok(publicRules.some((r) => r.fromPort === 443 && r.isPublic));
    // Port 8080 GCP firewall is public
    assert.ok(publicRules.some((r) => r.fromPort === 8080 && r.isPublic));
    // Port 22 Azure NSG is public
    assert.ok(publicRules.some((r) => r.fromPort === 22 && r.isPublic));
    // Port 5432 is internal (10.0.0.0/16)
    assert.ok(internalRules.some((r) => r.fromPort === 5432 && !r.isPublic));
  } finally {
    proj.cleanup();
  }
});

test('extractIngressRules identifies CloudFormation ingress rules', () => {
  const proj = createTempProject({
    'template.yaml': `
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  PublicSG:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Public web access
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 3306
          ToPort: 3306
          CidrIp: 192.168.1.0/24
  IngressRule:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: sg-999
      IpProtocol: tcp
      FromPort: 443
      ToPort: 443
      CidrIp: 0.0.0.0/0
`,
  });

  try {
    const rules = extractIngressRules(['.'], { root: proj.dir });
    const publicRules = rules.filter((r) => r.isPublic);
    const internalRules = rules.filter((r) => !r.isPublic);

    assert.ok(publicRules.some((r) => r.fromPort === 80 && r.source === 'cfn'));
    assert.ok(publicRules.some((r) => r.fromPort === 443 && r.source === 'cfn'));
    assert.ok(internalRules.some((r) => r.fromPort === 3306 && !r.isPublic));
  } finally {
    proj.cleanup();
  }
});

test('extractIngressRules identifies Kubernetes Service and Ingress exposure', () => {
  const proj = createTempProject({
    'k8s/service.yaml': `
apiVersion: v1
kind: Service
metadata:
  name: frontend-svc
spec:
  type: LoadBalancer
  ports:
    - port: 80
      targetPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: internal-db-svc
spec:
  type: ClusterIP
  ports:
    - port: 5432
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
spec:
  rules:
    - http:
        paths:
          - path: /api
            backend:
              service:
                name: api-svc
                port:
                  number: 8080
`,
  });

  try {
    const rules = extractIngressRules(['.'], { root: proj.dir });
    const publicRules = rules.filter((r) => r.isPublic);
    const internalRules = rules.filter((r) => !r.isPublic);

    assert.ok(publicRules.some((r) => r.resource.includes('frontend-svc') && r.isPublic));
    assert.ok(publicRules.some((r) => r.resource.includes('app-ingress') && r.fromPort === 8080));
    assert.ok(internalRules.some((r) => r.resource.includes('internal-db-svc') && !r.isPublic));
  } finally {
    proj.cleanup();
  }
});

test('extractIngressRules identifies Docker Compose port mappings and host networking', () => {
  const proj = createTempProject({
    'docker-compose.yml': `
version: '3.8'
services:
  web:
    image: node:alpine
    ports:
      - "80:3000"
      - "127.0.0.1:9090:9090"
  worker:
    image: worker:latest
    network_mode: host
`,
  });

  try {
    const rules = extractIngressRules(['.'], { root: proj.dir });
    const publicRules = rules.filter((r) => r.isPublic);
    const localhostRules = rules.filter((r) => !r.isPublic);

    // "80:3000" maps public port 80 to container port 3000
    assert.ok(publicRules.some((r) => r.fromPort === 80 && r.targetPort === 3000 && r.isPublic));
    // "127.0.0.1:9090:9090" bound only to localhost
    assert.ok(localhostRules.some((r) => r.fromPort === 9090 && !r.isPublic));
    // host network mode exposes all ports
    assert.ok(publicRules.some((r) => r.resource.includes('worker') && r.isPublic));
  } finally {
    proj.cleanup();
  }
});

test('extractServicePorts discovers explicit listen ports across languages', () => {
  const proj = createTempProject({
    'src/server.js': `
const express = require('express');
const app = express();
app.listen(3000, () => console.log('Listening'));
`,
    'src/main/resources/application.properties': `
server.port = 8080
`,
    'main.go': `
package main
import "github.com/gin-gonic/gin"
func main() {
    r := gin.Default()
    r.Run(":8081")
}
`,
  });

  try {
    const ports = extractServicePorts(['.'], { root: proj.dir });
    const portNumbers = ports.map((p) => p.port);
    assert.ok(portNumbers.includes(3000));
    assert.ok(portNumbers.includes(8080));
    assert.ok(portNumbers.includes(8081));
  } finally {
    proj.cleanup();
  }
});

function makeAppWithSql(route, table, column, inputExpr) {
  const sqlStatement = ['SELECT *', 'FROM ' + table, 'WHERE ' + column + ' = '].join(' ');
  return [
    "const express = require('express');",
    "const db = require('./db');",
    "const app = express();",
    `app.post('${route}', (req, res) => {`,
    `  db.query(${JSON.stringify(sqlStatement)} + ${inputExpr});`,
    "  res.send('ok');",
    "});",
    "app.listen(3000);",
  ].join('\n');
}

test('correlateAttackSurface connects public ingress to exposed route and dangerous sink', () => {
  const proj = createTempProject({
    'infra/main.tf': `
resource "aws_security_group" "web_sg" {
  name = "web"
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`,
    'src/app.js': makeAppWithSql('/api/users/search', 'users', 'name', 'req.body.name'),
  });

  try {
    const correlation = correlateAttackSurface(['.'], { root: proj.dir });
    assert.strictEqual(correlation.summary.totalPublicIngressRules, 1);
    assert.strictEqual(correlation.summary.totalExposedRoutes, 1);
    assert.strictEqual(correlation.summary.totalAttackPaths, 1);

    const ap = correlation.attackPaths[0];
    assert.strictEqual(ap.framework, 'express');
    assert.strictEqual(ap.method, 'POST');
    assert.strictEqual(ap.path, '/api/users/search');
    assert.strictEqual(ap.sinkType, 'sql');
    assert.strictEqual(ap.riskLevel, 'critical');
    assert.strictEqual(ap.publicIngress.cidr, '0.0.0.0/0');
    assert.ok(ap.pathString.includes('Internet (0.0.0.0/0)'));
    assert.ok(ap.pathString.includes('POST /api/users/search'));
  } finally {
    proj.cleanup();
  }
});

test('correlateAttackSurface leaves internal-only routes unexposed', () => {
  const proj = createTempProject({
    'infra/main.tf': `
resource "aws_security_group" "internal_sg" {
  name = "internal"
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
`,
    'src/app.js': makeAppWithSql('/admin/query', 'secrets', 'id', 'req.body.id'),
  });

  try {
    const correlation = correlateAttackSurface(['.'], { root: proj.dir });
    assert.strictEqual(correlation.summary.totalPublicIngressRules, 0);
    assert.strictEqual(correlation.summary.totalExposedRoutes, 0);
    assert.strictEqual(correlation.summary.totalAttackPaths, 0);
    assert.strictEqual(correlation.internalRoutes.length, 1);
    assert.strictEqual(correlation.internalRoutes[0].exposure, 'internal');
  } finally {
    proj.cleanup();
  }
});

test('CLI correlate command reports attack paths and returns code 2 on exposure', () => {
  const proj = createTempProject({
    'infra/main.tf': `
resource "aws_security_group" "web_sg" {
  name = "web"
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`,
    'src/app.js': makeAppWithSql('/api/lookup', 'items', 'id', 'req.query.id'),
  });

  try {
    let stdout = '';
    const io = {
      out: (s) => { stdout += s + '\n'; },
      err: (s) => {},
    };

    const prevCwd = process.cwd();
    process.chdir(proj.dir);
    try {
      // 1. Text format
      const code = run(['correlate', '.'], io);
      assert.strictEqual(code, 2);
      assert.ok(stdout.includes('airtight: cross-layer exposure correlation'));
      assert.ok(stdout.includes('[CRITICAL] SQL Sink reachable from Internet'));
      assert.ok(stdout.includes('Internet [0.0.0.0/0]'));

      // 2. JSON format
      let jsonOut = '';
      const jsonIo = {
        out: (s) => { jsonOut += s; },
        err: () => {},
      };
      const jsonCode = run(['correlate', '.', '--json'], jsonIo);
      assert.strictEqual(jsonCode, 2);
      const parsed = JSON.parse(jsonOut);
      assert.strictEqual(parsed.attackPaths.length, 1);
      assert.strictEqual(parsed.summary.totalAttackPaths, 1);

      // 3. Map with exposure
      let mapOut = '';
      const mapIo = {
        out: (s) => { mapOut += s; },
        err: () => {},
      };
      const mapCode = run(['map', '--with-exposure', '.'], mapIo);
      assert.strictEqual(mapCode, 0);
      const mapParsed = JSON.parse(mapOut);
      assert.strictEqual(mapParsed.exposedRoutes.length, 1);
      assert.strictEqual(mapParsed.exposedRoutes[0].exposure, 'internet-facing');

      // 4. Detect with --correlate
      let detectOut = '';
      const detectIo = {
        out: (s) => { detectOut += s; },
        err: () => {},
      };
      const detectCode = run(['detect', '.', '--correlate', '--json'], detectIo);
      assert.strictEqual(detectCode, 2);
      const detectParsed = JSON.parse(detectOut);
      const criticalFindings = detectParsed.findings.filter((f) => f.severity === 'critical');
      assert.ok(criticalFindings.length >= 1);
    } finally {
      process.chdir(prevCwd);
    }
  } finally {
    proj.cleanup();
  }
});

