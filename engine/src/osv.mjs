// OSV vulnerability advisory queries and caching.
//
// Queries https://api.osv.dev/v1/querybatch in batches of up to 100.
// Fails open on timeout, offline mode, or network failure, returning cached
// results or empty findings.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { findingId, priorityOf, sortFindings } from './findings.mjs';

function resolveCacheFile(cacheDir) {
  if (!cacheDir) {
    return join(process.cwd(), '.airtight', 'cache', 'osv.json');
  }
  if (cacheDir.endsWith('.json')) {
    return resolve(cacheDir);
  }
  return join(resolve(cacheDir), 'osv.json');
}

function readCache(filePath) {
  try {
    if (existsSync(filePath)) {
      const data = JSON.parse(readFileSync(filePath, 'utf8'));
      if (data && typeof data === 'object') return data;
    }
  } catch {
    // Fail open on corrupt cache
  }
  return {};
}

function writeCache(filePath, data) {
  try {
    mkdirSync(dirname(filePath), { recursive: true });
    writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
  } catch {
    // Fail open on write errors
  }
}

function mapSeverity(vuln) {
  const dbSev = vuln.database_specific?.severity || vuln.ecosystem_specific?.severity;
  if (typeof dbSev === 'string') {
    const s = dbSev.toLowerCase().trim();
    if (s === 'critical') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'moderate' || s === 'medium') return 'medium';
    if (s === 'low') return 'low';
  }

  let cvssScore = null;
  if (typeof vuln.database_specific?.cvss_score === 'number') {
    cvssScore = vuln.database_specific.cvss_score;
  } else if (Array.isArray(vuln.severity)) {
    for (const item of vuln.severity) {
      if (typeof item?.score === 'number') {
        cvssScore = item.score;
        break;
      }
      if (typeof item?.score === 'string' && /^\d+(\.\d+)?$/.test(item.score.trim())) {
        cvssScore = parseFloat(item.score.trim());
        break;
      }
    }
  }

  if (cvssScore !== null) {
    if (cvssScore >= 9.0) return 'critical';
    if (cvssScore >= 7.0) return 'high';
    if (cvssScore >= 4.0) return 'medium';
    return 'low';
  }

  return 'medium';
}

function extractCwe(vuln) {
  const db = vuln.database_specific;
  if (db) {
    if (Array.isArray(db.cwe_ids) && db.cwe_ids.length > 0) {
      const match = String(db.cwe_ids[0]).match(/CWE-\d+/i);
      if (match) return match[0].toUpperCase();
    }
    if (typeof db.cwe === 'string') {
      const match = db.cwe.match(/CWE-\d+/i);
      if (match) return match[0].toUpperCase();
    }
    if (Array.isArray(db.cwes) && db.cwes.length > 0) {
      const match = String(db.cwes[0]).match(/CWE-\d+/i);
      if (match) return match[0].toUpperCase();
    }
  }
  if (Array.isArray(vuln.references)) {
    for (const ref of vuln.references) {
      if (ref?.url) {
        const match = ref.url.match(/CWE-(\d+)/i);
        if (match) return `CWE-${match[1]}`;
        const matchDef = ref.url.match(/definitions\/(\d+)\.html/i);
        if (matchDef) return `CWE-${matchDef[1]}`;
      }
    }
  }
  return null;
}

function extractFix(vuln, pkg) {
  if (!Array.isArray(vuln.affected)) return null;
  for (const aff of vuln.affected) {
    if (aff?.package?.name && aff.package.name !== pkg.name) continue;
    if (Array.isArray(aff.ranges)) {
      for (const range of aff.ranges) {
        if (Array.isArray(range.events)) {
          for (const ev of range.events) {
            if (ev?.fixed) {
              return String(ev.fixed);
            }
          }
        }
      }
    }
    if (Array.isArray(aff.versions) && aff.versions.length > 0) {
      return aff.versions.join(', ');
    }
  }
  return null;
}

/**
 * Queries OSV API for known vulnerabilities for the given dependencies.
 *
 * Batches queries up to 100 items per request, caches results to disk, and
 * fails open gracefully on network error, timeout, or offline mode.
 */
export async function queryOsv(dependencies, { cacheDir, offline = false, timeoutMs = 3000 } = {}) {
  if (!Array.isArray(dependencies) || dependencies.length === 0) {
    return [];
  }

  const cacheFile = resolveCacheFile(cacheDir);
  const cache = readCache(cacheFile);
  let cacheUpdated = false;

  const uncachedMap = new Map();
  for (const dep of dependencies) {
    if (!dep?.name || !dep?.version || !dep?.ecosystem) continue;
    const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    if (!(key in cache) && !uncachedMap.has(key)) {
      uncachedMap.set(key, dep);
    }
  }

  const uncached = Array.from(uncachedMap.values());

  if (!offline && uncached.length > 0) {
    const BATCH_SIZE = 100;
    for (let i = 0; i < uncached.length; i += BATCH_SIZE) {
      const batch = uncached.slice(i, i + BATCH_SIZE);
      const payload = {
        queries: batch.map((dep) => ({
          package: {
            name: dep.name,
            ecosystem: dep.ecosystem,
          },
          version: dep.version,
        })),
      };

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const res = await fetch('https://api.osv.dev/v1/querybatch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });

        if (res.ok) {
          const data = await res.json();
          if (data?.results && Array.isArray(data.results)) {
            for (let j = 0; j < batch.length; j++) {
              const dep = batch[j];
              const cacheKey = `${dep.ecosystem}:${dep.name}@${dep.version}`;
              const vulns = data.results[j]?.vulns || [];
              cache[cacheKey] = vulns;
            }
            cacheUpdated = true;
          }
        }
      } catch {
        // Fail open: network unreachable, DNS error, timeout, or abort
      } finally {
        clearTimeout(timeoutId);
      }
    }

    if (cacheUpdated) {
      writeCache(cacheFile, cache);
    }
  }

  const findings = [];
  const seenFindingIds = new Set();

  for (const dep of dependencies) {
    if (!dep?.name || !dep?.version || !dep?.ecosystem) continue;
    const cacheKey = `${dep.ecosystem}:${dep.name}@${dep.version}`;
    const vulns = cache[cacheKey];
    if (!Array.isArray(vulns) || vulns.length === 0) continue;

    let relFile = dep.lockfile ? relative(process.cwd(), resolve(dep.lockfile)) : 'lockfile';
    relFile = relFile.replace(/\\/g, '/');

    for (const vuln of vulns) {
      if (!vuln || !vuln.id) continue;
      const rule = 'dep/' + dep.ecosystem.toLowerCase() + '-advisory';
      const severity = mapSeverity(vuln);
      const confidence = 'confirmed';
      const cwe = extractCwe(vuln);
      const message = vuln.summary || `Vulnerability ${vuln.id} in ${dep.name}@${dep.version}`;
      const fix = extractFix(vuln, dep);
      const valueFingerprint = `${dep.name}@${dep.version}:${vuln.id}`;
      const id = findingId({ rule, file: relFile, valueFingerprint });

      if (seenFindingIds.has(id)) continue;
      seenFindingIds.add(id);

      findings.push({
        id,
        rule,
        title: `${vuln.id} in ${dep.name}`,
        domain: 'supply-chain',
        severity,
        confidence,
        priority: priorityOf(severity, confidence),
        disposition: 'fix',
        cwe,
        owasp: null,
        file: relFile,
        line: 1,
        column: 0,
        snippet: `${dep.name}@${dep.version}`,
        message,
        why: vuln.details || vuln.summary || message,
        fix,
        provenance: 'osv-advisory',
        redacted: false,
        valueFingerprint,
        package: {
          name: dep.name,
          version: dep.version,
          ecosystem: dep.ecosystem,
        },
        advisory: vuln.id,
      });
    }
  }

  return sortFindings(findings);
}
