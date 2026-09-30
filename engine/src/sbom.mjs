// CycloneDX 1.5 SBOM generation.
//
// Emits valid CycloneDX 1.5 JSON documents with purl component references
// across npm, PyPI, crates.io, and Go ecosystems.

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { detectLockfiles, parseLockfile } from './lockfile.mjs';

/**
 * Formats a package ecosystem, name, and version into a canonical Package URL (purl).
 */
export function toPurl(ecosystem, name, version) {
  const eco = String(ecosystem || '').toLowerCase();
  let type = 'generic';
  if (eco === 'npm') type = 'npm';
  else if (eco === 'pypi') type = 'pypi';
  else if (eco === 'crates.io' || eco === 'cargo') type = 'cargo';
  else if (eco === 'go' || eco === 'golang') type = 'golang';

  let formattedName = name;
  if (type === 'npm' && name.startsWith('@')) {
    formattedName = name.replace(/^@/, '%40');
  }
  return `pkg:${type}/${formattedName}@${version}`;
}

/**
 * Generates a CycloneDX 1.5 JSON SBOM.
 *
 * @param {object} opts
 * @param {string} [opts.root] Root directory to discover lockfiles if dependencies not passed
 * @param {Array} [opts.dependencies] Explicit dependencies list [{ name, version, ecosystem }]
 * @param {string} [opts.projectName='project'] Project name for root component
 * @param {string} [opts.version='1.0.0'] Project version for root component
 * @param {boolean} [opts.asObject=false] If true, returns raw object instead of JSON string
 * @returns {string|object}
 */
export function generateCycloneDx({
  root,
  dependencies,
  projectName = 'project',
  version = '1.0.0',
  asObject = false,
} = {}) {
  let deps = dependencies;
  if (!deps && root) {
    const lockfiles = detectLockfiles(root);
    deps = [];
    for (const lf of lockfiles) {
      try {
        const content = readFileSync(lf, 'utf8');
        const parsed = parseLockfile(lf, content);
        if (parsed?.dependencies) {
          deps.push(...parsed.dependencies);
        }
      } catch {
        // fail open
      }
    }
  }
  deps ??= [];

  const seenPurls = new Set();
  const components = [];

  for (const dep of deps) {
    if (!dep?.name || !dep?.version) continue;
    const purl = toPurl(dep.ecosystem, dep.name, dep.version);
    if (seenPurls.has(purl)) continue;
    seenPurls.add(purl);

    components.push({
      type: 'library',
      name: dep.name,
      version: dep.version,
      purl,
      'bom-ref': purl,
    });
  }

  components.sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

  const bom = {
    $schema: 'http://cyclonedx.org/schema/bom-1.5.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'airtight',
          name: 'airtight',
          version: '0.3.1',
        },
      ],
      component: {
        type: 'application',
        name: projectName,
        version: version,
      },
    },
    components,
  };

  return asObject ? bom : JSON.stringify(bom, null, 2);
}
