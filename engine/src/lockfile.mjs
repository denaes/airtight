// Lockfile detection and parsing across ecosystems.
//
// Supports:
//   npm:       package-lock.json (v1, v2, v3)
//   yarn:      yarn.lock (v1 classic, v2 Berry)
//   pnpm:      pnpm-lock.yaml (v5, v6, v9)
//   Rust:      Cargo.lock (TOML)
//   Go:        go.sum
//   Python:    requirements.txt, poetry.lock (TOML)

import { readdirSync, readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', 'out', '.next', '.nuxt', '.cache',
  'coverage', 'vendor', 'target', '.venv', 'venv', '__pycache__', '.tox',
  '.terraform', '.gradle', '.idea', '.airtight',
]);

const LOCKFILE_FILENAMES = new Set([
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'Cargo.lock',
  'go.sum',
  'requirements.txt',
  'poetry.lock',
]);

/**
 * Recursively scans root for supported lockfiles, skipping build and cache directories.
 * Returns an array of absolute paths to found lockfiles.
 */
export function detectLockfiles(root) {
  const found = [];
  function walk(dir) {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(join(dir, entry.name));
      } else if (entry.isFile()) {
        if (LOCKFILE_FILENAMES.has(entry.name)) {
          found.push(join(dir, entry.name));
        }
      }
    }
  }
  walk(resolve(root));
  return found;
}

function parsePackageLock(content, filePath) {
  try {
    const data = JSON.parse(content);
    const dependencies = [];
    const seen = new Set();

    function add(name, version) {
      if (!name || !version || typeof name !== 'string' || typeof version !== 'string') return;
      const key = `${name}@${version}`;
      if (seen.has(key)) return;
      seen.add(key);
      dependencies.push({
        name,
        version,
        ecosystem: 'npm',
        lockfile: filePath,
      });
    }

    // npm v2 and v3 format: packages map
    if (data.packages && typeof data.packages === 'object') {
      for (const [pkgPath, info] of Object.entries(data.packages)) {
        if (!pkgPath || pkgPath === '') continue; // Skip root project
        if (!info || typeof info !== 'object' || !info.version) continue;
        let pkgName = info.name;
        if (!pkgName) {
          const lastIdx = pkgPath.lastIndexOf('node_modules/');
          if (lastIdx !== -1) {
            pkgName = pkgPath.slice(lastIdx + 'node_modules/'.length);
          } else {
            pkgName = pkgPath;
          }
        }
        add(pkgName, info.version);
      }
    }

    // npm v1 fallback or v2 legacy tree
    if (dependencies.length === 0 && data.dependencies && typeof data.dependencies === 'object') {
      function walkV1(deps) {
        if (!deps || typeof deps !== 'object') return;
        for (const [depName, info] of Object.entries(deps)) {
          if (!info || typeof info !== 'object') continue;
          if (info.version && typeof info.version === 'string') {
            add(depName, info.version);
          }
          if (info.dependencies) {
            walkV1(info.dependencies);
          }
        }
      }
      walkV1(data.dependencies);
    }

    return { dependencies };
  } catch {
    return { dependencies: [] };
  }
}

function parseYarnLock(content, filePath) {
  try {
    const dependencies = [];
    const seen = new Set();
    const lines = content.split('\n');
    let currentNames = [];

    for (const rawLine of lines) {
      const line = rawLine.replace(/\r$/, '');
      if (/^[^\s#].*:$/.test(line)) {
        currentNames = [];
        const header = line.trim().replace(/:$/, '');
        const entries = header.split(',').map((s) => s.trim().replace(/^["']|["']$/g, ''));
        for (const entry of entries) {
          if (!entry || entry.startsWith('__metadata')) continue;
          const atIndex = entry.startsWith('@') ? entry.indexOf('@', 1) : entry.indexOf('@');
          if (atIndex > 0) {
            const name = entry.slice(0, atIndex);
            if (!currentNames.includes(name)) {
              currentNames.push(name);
            }
          }
        }
        continue;
      }

      if (currentNames.length > 0 && /^\s+version[:\s]/.test(line)) {
        const match = line.match(/^\s+version[:\s]\s*"?([^"\s\r\n]+)"?/);
        if (match) {
          const version = match[1];
          for (const name of currentNames) {
            const key = `${name}@${version}`;
            if (!seen.has(key)) {
              seen.add(key);
              dependencies.push({
                name,
                version,
                ecosystem: 'npm',
                lockfile: filePath,
              });
            }
          }
          currentNames = [];
        }
      }
    }
    return { dependencies };
  } catch {
    return { dependencies: [] };
  }
}

function parsePnpmLock(content, filePath) {
  try {
    const data = parseYaml(content);
    if (!data || typeof data !== 'object') return { dependencies: [] };

    const dependencies = [];
    const seen = new Set();

    function add(pkgName, version) {
      if (!pkgName || !version || typeof pkgName !== 'string' || typeof version !== 'string') return;
      const cleanVer = version.split(/[_()]/)[0].trim();
      if (!cleanVer) return;
      const key = `${pkgName}@${cleanVer}`;
      if (seen.has(key)) return;
      seen.add(key);
      dependencies.push({
        name: pkgName,
        version: cleanVer,
        ecosystem: 'npm',
        lockfile: filePath,
      });
    }

    if (data.packages && typeof data.packages === 'object') {
      for (const [key, val] of Object.entries(data.packages)) {
        if (val && typeof val === 'object' && val.name && val.version) {
          add(val.name, String(val.version));
          continue;
        }

        const cleanKey = key.startsWith('/') ? key.slice(1) : key;
        const atIndex = cleanKey.startsWith('@') ? cleanKey.indexOf('@', 1) : cleanKey.indexOf('@');
        if (atIndex > 0) {
          const name = cleanKey.slice(0, atIndex);
          const verPart = cleanKey.slice(atIndex + 1);
          add(name, verPart);
        } else {
          const lastSlash = cleanKey.lastIndexOf('/');
          if (lastSlash > 0) {
            const name = cleanKey.slice(0, lastSlash);
            const verPart = cleanKey.slice(lastSlash + 1);
            add(name, verPart);
          }
        }
      }
    }

    if (dependencies.length === 0) {
      const topDeps = data.dependencies || data.importers?.['.']?.dependencies;
      if (topDeps && typeof topDeps === 'object') {
        for (const [name, val] of Object.entries(topDeps)) {
          const ver = typeof val === 'string' ? val : (val?.version ? String(val.version) : null);
          if (ver) add(name, ver);
        }
      }
    }

    return { dependencies };
  } catch {
    return { dependencies: [] };
  }
}

function parseCargoLock(content, filePath) {
  try {
    const dependencies = [];
    const seen = new Set();
    const blocks = content.split('[[package]]');
    for (let i = 1; i < blocks.length; i++) {
      const block = blocks[i];
      const nameMatch = block.match(/name\s*=\s*["']([^"']+)["']/);
      const verMatch = block.match(/version\s*=\s*["']([^"']+)["']/);
      if (nameMatch && verMatch) {
        const name = nameMatch[1];
        const version = verMatch[1];
        const key = `${name}@${version}`;
        if (!seen.has(key)) {
          seen.add(key);
          dependencies.push({
            name,
            version,
            ecosystem: 'crates.io',
            lockfile: filePath,
          });
        }
      }
    }
    return { dependencies };
  } catch {
    return { dependencies: [] };
  }
}

function parseGoSum(content, filePath) {
  try {
    const dependencies = [];
    const seen = new Set();
    const lines = content.split('\n');
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('//') || line.startsWith('#')) continue;
      const parts = line.split(/\s+/);
      if (parts.length < 2) continue;
      const [mod, ver] = parts;
      if (ver.includes('/go.mod') || mod.includes('/go.mod')) continue;
      const version = ver.startsWith('v') ? ver.slice(1) : ver;
      const key = `${mod}@${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        dependencies.push({
          name: mod,
          version,
          ecosystem: 'Go',
          lockfile: filePath,
        });
      }
    }
    return { dependencies };
  } catch {
    return { dependencies: [] };
  }
}

function parseRequirementsTxt(content, filePath) {
  try {
    const dependencies = [];
    const seen = new Set();
    const lines = content.split('\n');
    for (const rawLine of lines) {
      let line = rawLine.split('#')[0].trim();
      if (!line || line.startsWith('-') || line.startsWith('--')) continue;
      line = line.split(';')[0].trim();
      const match = line.match(/^([A-Za-z0-9_.-]+)\s*={2,3}\s*([A-Za-z0-9_.-]+)/);
      if (match) {
        const name = match[1];
        const version = match[2];
        const key = `${name.toLowerCase()}@${version}`;
        if (!seen.has(key)) {
          seen.add(key);
          dependencies.push({
            name,
            version,
            ecosystem: 'PyPI',
            lockfile: filePath,
          });
        }
      }
    }
    return { dependencies };
  } catch {
    return { dependencies: [] };
  }
}

function parsePoetryLock(content, filePath) {
  try {
    const dependencies = [];
    const seen = new Set();
    const blocks = content.split('[[package]]');
    for (let i = 1; i < blocks.length; i++) {
      const block = blocks[i];
      const nameMatch = block.match(/name\s*=\s*["']([^"']+)["']/);
      const verMatch = block.match(/version\s*=\s*["']([^"']+)["']/);
      if (nameMatch && verMatch) {
        const name = nameMatch[1];
        const version = verMatch[1];
        const key = `${name.toLowerCase()}@${version}`;
        if (!seen.has(key)) {
          seen.add(key);
          dependencies.push({
            name,
            version,
            ecosystem: 'PyPI',
            lockfile: filePath,
          });
        }
      }
    }
    return { dependencies };
  } catch {
    return { dependencies: [] };
  }
}

/**
 * Parses a lockfile content string or file at filePath and extracts dependencies.
 * Fails open on corrupt syntax, returning { dependencies: [] }.
 */
export function parseLockfile(filePath, content) {
  if (content === undefined || content === null) {
    try {
      content = readFileSync(filePath, 'utf8');
    } catch {
      return { dependencies: [] };
    }
  }

  const name = basename(filePath);
  if (name === 'package-lock.json') return parsePackageLock(content, filePath);
  if (name === 'yarn.lock') return parseYarnLock(content, filePath);
  if (name === 'pnpm-lock.yaml') return parsePnpmLock(content, filePath);
  if (name === 'Cargo.lock') return parseCargoLock(content, filePath);
  if (name === 'go.sum') return parseGoSum(content, filePath);
  if (name === 'requirements.txt' || (name.startsWith('requirements-') && name.endsWith('.txt'))) {
    return parseRequirementsTxt(content, filePath);
  }
  if (name === 'poetry.lock') return parsePoetryLock(content, filePath);

  return { dependencies: [] };
}
