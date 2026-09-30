// CycloneDX 1.5 SBOM generation tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateCycloneDx, toPurl } from '../engine/src/sbom.mjs';

test('toPurl formats package URLs across ecosystems accurately', () => {
  assert.equal(toPurl('npm', 'lodash', '4.17.21'), 'pkg:npm/lodash@4.17.21');
  assert.equal(toPurl('npm', '@babel/core', '7.22.5'), 'pkg:npm/%40babel/core@7.22.5');
  assert.equal(toPurl('PyPI', 'requests', '2.31.0'), 'pkg:pypi/requests@2.31.0');
  assert.equal(toPurl('crates.io', 'serde', '1.0.197'), 'pkg:cargo/serde@1.0.197');
  assert.equal(toPurl('Go', 'github.com/gin-gonic/gin', '1.9.1'), 'pkg:golang/github.com/gin-gonic/gin@1.9.1');
});

test('generateCycloneDx emits valid CycloneDX 1.5 JSON structure', () => {
  const dependencies = [
    { name: 'lodash', version: '4.17.21', ecosystem: 'npm' },
    { name: 'requests', version: '2.31.0', ecosystem: 'PyPI' },
    { name: 'serde', version: '1.0.197', ecosystem: 'crates.io' },
    { name: 'github.com/gin-gonic/gin', version: '1.9.1', ecosystem: 'Go' },
  ];

  const rawJson = generateCycloneDx({
    dependencies,
    projectName: 'my-service',
    version: '2.4.0',
  });

  assert.equal(typeof rawJson, 'string');
  const bom = JSON.parse(rawJson);

  // Core CycloneDX 1.5 schema requirements
  assert.equal(bom.$schema, 'http://cyclonedx.org/schema/bom-1.5.json');
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.specVersion, '1.5');
  assert.equal(bom.version, 1);
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);

  // Metadata
  assert.equal(bom.metadata.component.type, 'application');
  assert.equal(bom.metadata.component.name, 'my-service');
  assert.equal(bom.metadata.component.version, '2.4.0');
  assert.equal(bom.metadata.tools[0].name, 'airtight');
  assert.ok(Date.parse(bom.metadata.timestamp));

  // Components
  assert.equal(bom.components.length, 4);

  const lodashComp = bom.components.find((c) => c.name === 'lodash');
  assert.deepEqual(lodashComp, {
    type: 'library',
    name: 'lodash',
    version: '4.17.21',
    purl: 'pkg:npm/lodash@4.17.21',
    'bom-ref': 'pkg:npm/lodash@4.17.21',
  });

  const pypiComp = bom.components.find((c) => c.name === 'requests');
  assert.equal(pypiComp.purl, 'pkg:pypi/requests@2.31.0');

  const cargoComp = bom.components.find((c) => c.name === 'serde');
  assert.equal(cargoComp.purl, 'pkg:cargo/serde@1.0.197');

  const goComp = bom.components.find((c) => c.name === 'github.com/gin-gonic/gin');
  assert.equal(goComp.purl, 'pkg:golang/github.com/gin-gonic/gin@1.9.1');
});

test('generateCycloneDx deduplicates and sorts components stably', () => {
  const dependencies = [
    { name: 'zeta', version: '1.0.0', ecosystem: 'npm' },
    { name: 'alpha', version: '2.0.0', ecosystem: 'npm' },
    { name: 'alpha', version: '2.0.0', ecosystem: 'npm' }, // duplicate
    { name: 'alpha', version: '1.0.0', ecosystem: 'npm' },
  ];

  const bom = generateCycloneDx({ dependencies, asObject: true });
  assert.equal(bom.components.length, 3);
  assert.equal(bom.components[0].name, 'alpha');
  assert.equal(bom.components[0].version, '1.0.0');
  assert.equal(bom.components[1].name, 'alpha');
  assert.equal(bom.components[1].version, '2.0.0');
  assert.equal(bom.components[2].name, 'zeta');
});

test('generateCycloneDx discovers lockfiles from root when dependencies omitted', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'airtight-sbom-root-'));
  try {
    const pkgLock = JSON.stringify({
      name: 'root-project',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': { name: 'root-project', version: '1.0.0' },
        'node_modules/debug': { version: '4.3.4' },
      },
    });
    writeFileSync(join(tmp, 'package-lock.json'), pkgLock);

    const cargoLock = `[[package]]\nname = "rand"\nversion = "0.8.5"\n`;
    writeFileSync(join(tmp, 'Cargo.lock'), cargoLock);

    const bom = generateCycloneDx({ root: tmp, asObject: true, projectName: 'auto-discovered' });
    assert.equal(bom.metadata.component.name, 'auto-discovered');
    assert.equal(bom.components.length, 2);
    assert.equal(bom.components[0].name, 'debug');
    assert.equal(bom.components[0].purl, 'pkg:npm/debug@4.3.4');
    assert.equal(bom.components[1].name, 'rand');
    assert.equal(bom.components[1].purl, 'pkg:cargo/rand@0.8.5');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
