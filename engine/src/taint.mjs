// Source-to-sink intra-procedural taint analysis and reachability tracing.
//
// Identifies untrusted request input sources across web frameworks, tracks local
// variable propagations and string interpolations, and verifies whether untrusted
// data reaches dangerous sinks (SQL, command execution, SSRF, eval, file I/O).

/** Common source patterns by ecosystem/framework */
export const SOURCE_PATTERNS = [
  // JavaScript / TypeScript (Express, Fastify, Next.js, Nuxt, SvelteKit, NestJS, Koa, Hono)
  {
    lang: 'js',
    type: 'request-param',
    regex: /(?:\b(?:req|request)\.(?:body|query|params|headers|cookies)(?:\.[\w$]+|\[[^\]]+\])?|\b(?:c\.req)\.(?:param|query|header)\s*\([^)]*\)|\burl\.searchParams\.get\s*\([^)]*\))/i,
    extractVars: (line) => {
      // Destructuring: const { a, b } = req.body / req.query
      const destrMatch = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:req|request)\.(?:body|query|params|headers|cookies)/i.exec(line);
      if (destrMatch) {
        return destrMatch[1].split(',').map((s) => s.trim().split(':')[0].trim()).filter(Boolean);
      }
      // Assignment: const x = req.query.id / req.body['id']
      const assignMatch = /(?:const|let|var)\s+([\w$]+)\s*=\s*(?:req|request)\.(?:body|query|params|headers|cookies|c\.req|url\.searchParams)/i.exec(line);
      if (assignMatch) return [assignMatch[1]];
      return [];
    },
  },

  // Python (Flask, FastAPI, Django, Tornado)
  {
    lang: 'py',
    type: 'request-param',
    regex: /(?:\brequest\.(?:args|form|values|GET|POST|headers)(?:\.get\s*\([^)]*\)|\[[^\]]+\])|\brequest\.(?:json|body|data)\b|\bparams\.get\s*\([^)]*\))/i,
    extractVars: (line) => {
      const match = /^\s*([a-zA-Z_]\w*)\s*=\s*(?:request\.(?:args|form|values|GET|POST|json|body|headers)|params\.get)/i.exec(line);
      return match ? [match[1]] : [];
    },
  },

  // Go (Gin, Echo, Chi, net/http)
  {
    lang: 'go',
    type: 'request-param',
    regex: /(?:\bc\.(?:Query|Param|PostForm|GetString|DefaultQuery)\s*\([^)]*\)|\br\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue)\s*\([^)]*\)|\bio\.ReadAll\s*\(\s*r\.Body\s*\))/i,
    extractVars: (line) => {
      const match = /^\s*([a-zA-Z_]\w*)\s*(?::=|=)\s*(?:c\.(?:Query|Param|PostForm|GetString|DefaultQuery)|r\.(?:URL\.Query|FormValue|PostFormValue)|io\.ReadAll)/i.exec(line);
      return match ? [match[1]] : [];
    },
  },

  // Java (Spring, JAX-RS, Servlet)
  {
    lang: 'java',
    type: 'request-param',
    regex: /(?:\brequest\.getParameter\s*\([^)]*\)|\brequest\.getHeader\s*\([^)]*\)|@RequestParam\b|@PathVariable\b|@RequestBody\b)/i,
    extractVars: (line) => {
      const match = /(?:String|var|Object|[A-Z]\w*)\s+([a-zA-Z_]\w*)\s*=\s*request\.getParameter/i.exec(line);
      if (match) return [match[1]];
      const annotMatch = /@(?:RequestParam|PathVariable|RequestBody)[^)]*\)?\s*(?:(?:final\s+)?(?:String|var|[A-Z]\w*)\s+)?([a-zA-Z_]\w*)/i.exec(line);
      return annotMatch ? [annotMatch[1]] : [];
    },
  },

  // PHP (Vanilla, Laravel, Symfony)
  {
    lang: 'php',
    type: 'request-param',
    regex: /(?:\$_(?:GET|POST|REQUEST)\[[^\]]+\]|\$request->(?:input|get|query|all)\s*\([^)]*\)|\$request->[\w$]+|file_get_contents\s*\(\s*['"]php:\/\/input['"]\s*\))/i,
    extractVars: (line) => {
      const match = /^\s*(\$[a-zA-Z_]\w*)\s*=\s*(?:\$_(?:GET|POST|REQUEST)|\$request->|file_get_contents\s*\(\s*['"]php:\/\/input)/i.exec(line);
      return match ? [match[1]] : [];
    },
  },

  // C# / .NET (ASP.NET Core / MVC)
  {
    lang: 'dotnet',
    type: 'request-param',
    regex: /(?:\bRequest\.(?:Query|Form|Headers)\[[^\]]+\]|\bRequest\.Query\.TryGetValue\s*\(|\[FromQuery\]|\[FromRoute\]|\[FromBody\])/i,
    extractVars: (line) => {
      const match = /(?:string|var|object|[A-Z]\w*)\s+([a-zA-Z_]\w*)\s*=\s*Request\.(?:Query|Form|Headers)/i.exec(line);
      return match ? [match[1]] : [];
    },
  },
];

/** Dangerous sink patterns for taint verification */
export const SINK_PATTERNS = [
  {
    type: 'sql',
    regex: /(?:\$?(?:db|conn|connection|client|pool|session|cursor|jdbcTemplate|em|dataSource|entityManager|DB)(?:\.|->)(?:query|execute|rawQuery|queryRaw|executeRaw|executeUpdate|executeQuery|Query|QueryRow|Exec|createNativeQuery|raw|select|selectRaw)\s*\(|\b(?:knex|prisma|sequelize)\.raw\s*\(|`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*`|["'](?:SELECT|INSERT|UPDATE|DELETE)\s+[^"']*["'])/i,
  },
  {
    type: 'exec',
    regex: /(?:\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(|\bos\.(?:system|popen|spawn[a-z]*)\s*\(|\bexec\.Command(?:Context)?\s*\(|\bRuntime\.getRuntime\(\)\.exec\s*\(|\bnew\s+ProcessBuilder\s*\(|\bProcess\.Start\s*\(|\b(?:shell_exec|system|passthru|exec)\s*\()/,
  },
  {
    type: 'eval',
    regex: /(?:(?<![\w$])(?:eval|Function)\s*\(|\bvm\.(?:runInContext|runInNewContext|runInThisContext)\s*\(|(?<![\w$.])exec\s*\([^)]*\))/,
  },
  {
    type: 'ssrf',
    regex: /(?:(?<![\w$])(?:fetch|superagent|got)\s*\(|\baxios(?:\.(?:get|post|put|delete|patch|request))?\s*\(|\b(?:http|https)\.(?:get|request)\s*\(|\brequests\.(?:get|post|put|delete|patch|request)\s*\(|\burllib\.request\.urlopen\s*\(|\bhttpx\.(?:get|post|put|delete|patch|request)\s*\(|\bhttp\.(?:Get|Post|Head|PostForm|NewRequest(?:WithContext)?)\s*\(|\bHttpClient\.newHttpClient\s*\(|\brestTemplate\.(?:getForObject|getForEntity|postForObject|postForEntity|exchange)\s*\(|\bcurl_init\s*\(|\bfile_get_contents\s*\()/i,
  },
  {
    type: 'file',
    regex: /(?:\bfs(?:\.promises)?\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|appendFile|appendFileSync)\s*\(|(?<![\w$])open\s*\([^)]*['"][rwa]|(?<![\w$])aiofiles\.open\s*\(|\bos\.(?:ReadFile|WriteFile|Open|OpenFile|Create)\s*\(|\bio(?:util)?\.(?:ReadFile|WriteFile)\s*\(|\bFiles\.(?:readAllBytes|readAllLines|readString|write|writeString|newInputStream|newOutputStream)\s*\(|\bnew\s+(?:FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(|\bFile\.(?:Open|ReadAllText|ReadAllBytes|WriteAllText)\s*\()/i,
  },
  {
    type: 'decompression',
    regex: /(?:\bzlib\.(?:gunzip|gunzipSync|brotliDecompress|brotliDecompressSync|inflate|inflateSync|unzip|unzipSync)\s*\(|\bbrotli\.decompress\s*\(|\bzlib\.decompress\s*\(|\bgzdecode\s*\(|\bgzinflate\s*\(|\bgzuncompress\s*\()/i,
  },
];

/**
 * Perform intra-procedural taint analysis across the lines of a file.
 *
 * Tracks:
 * 1. Entry point sources (request parameters, route arguments)
 * 2. Taint propagation through variable assignments, string concat, and template literals
 * 3. Hops and provenance for every tainted variable
 */
export function traceFileTaint(content, lines, ext = '') {
  // Map of tainted variable name -> { name, line, sourceExpr, hops: string[] }
  const taintedVars = new Map();
  // Array of all detected taint hops/records
  const taintHistory = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const lineNo = i + 1;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('/*')) {
      continue;
    }

    // Step 1: Detect new input sources on this line
    for (const pat of SOURCE_PATTERNS) {
      if (pat.regex.test(line)) {
        const extracted = pat.extractVars ? pat.extractVars(line) : [];
        const sourceMatch = pat.regex.exec(line);
        const sourceExpr = sourceMatch ? sourceMatch[0] : 'user-input';

        if (extracted.length > 0) {
          for (const v of extracted) {
            const entry = {
              name: v,
              line: lineNo,
              sourceExpr,
              hops: [sourceExpr, v],
            };
            taintedVars.set(v, entry);
            taintHistory.push(entry);
          }
        } else {
          // Check for generic assignment: varName = ...source...
          const genericAssign = /^\s*(?:(?:const|let|var|string|var|val|\$)\s+)?([$a-zA-Z_]\w*)\s*(?::=|=)\s*(.+)$/.exec(line);
          if (genericAssign) {
            const varName = genericAssign[1];
            const entry = {
              name: varName,
              line: lineNo,
              sourceExpr,
              hops: [sourceExpr, varName],
            };
            taintedVars.set(varName, entry);
            taintHistory.push(entry);
          }
        }
      }
    }

    // Step 2: Track taint propagation across assignments:
    // e.g. newVar = ... existingTaintedVar ...
    if (taintedVars.size > 0) {
      const assignMatch = /^\s*(?:(?:const|let|var|string|var|val|\$)\s+)?([$a-zA-Z_]\w*)\s*(?::=|=)\s*(.+)$/.exec(line);
      if (assignMatch) {
        const destVar = assignMatch[1];
        const rhs = assignMatch[2];

        // Check if any existing tainted variable appears in the RHS
        for (const [taintedName, prev] of taintedVars.entries()) {
          const varRegex = createVarRegex(taintedName);
          if (varRegex.test(rhs) && destVar !== taintedName) {
            // Propagate taint to destVar
            const newHops = [...prev.hops, destVar];
            const entry = {
              name: destVar,
              line: lineNo,
              sourceExpr: prev.sourceExpr,
              hops: newHops,
            };
            taintedVars.set(destVar, entry);
            taintHistory.push(entry);
            break;
          }
        }
      }
    }
  }

  return {
    taintedVars,
    taintHistory,
  };
}

function createVarRegex(varName) {
  if (varName.startsWith('$')) {
    return new RegExp(`(?:^|[^a-zA-Z0-9_])${escapeRegex(varName)}\\b`);
  }
  return new RegExp(`\\b${escapeRegex(varName)}\\b`);
}

/**
 * Check if a sink expression at a given line consumes any tainted variable.
 * Returns taint trace info if matched, or null if untainted.
 */
export function findTaintPathForSink(taintTracker, sinkLineNo, snippet, windowLines = 3) {
  if (!taintTracker || taintTracker.taintedVars.size === 0) {
    return null;
  }

  // Check if snippet contains any of the tainted variables
  for (const [varName, info] of taintTracker.taintedVars.entries()) {
    // Only consider variables tainted at or before the sink line
    if (info.line > sinkLineNo) continue;

    // Check if the variable is within reasonable line distance (intra-procedural scope window)
    if (sinkLineNo - info.line > 100) continue;

    const varRegex = createVarRegex(varName);
    if (varRegex.test(snippet)) {
      // Find sink type
      let sinkType = 'sink';
      for (const s of SINK_PATTERNS) {
        if (s.regex.test(snippet)) {
          sinkType = s.type;
          break;
        }
      }

      const fullHops = [...info.hops, sinkType];
      const pathSummary = fullHops.join(' -> ');

      return {
        hasTaint: true,
        source: { expr: info.sourceExpr, line: info.line },
        variable: varName,
        hops: fullHops,
        pathSummary,
        sinkType,
        sinkLine: sinkLineNo,
      };
    }
  }

  return null;
}

/**
 * Resolves a module import specifier from a source file relative to the repository files in fileContentMap.
 */
export function resolveImportPath(fromFile, specifier, fileContentMap) {
  if (!specifier || typeof specifier !== 'string') return null;
  if (specifier.startsWith('.')) {
    const fromDir = fromFile.includes('/') ? fromFile.replace(/\/[^/]+$/, '') : '';
    const parts = (fromDir ? `${fromDir}/${specifier}` : specifier).split('/');
    const normalized = [];
    for (const part of parts) {
      if (part === '.' || part === '') continue;
      if (part === '..') normalized.pop();
      else normalized.push(part);
    }
    const basePath = normalized.join('/');
    const candidates = [
      basePath,
      `${basePath}.js`,
      `${basePath}.mjs`,
      `${basePath}.ts`,
      `${basePath}.py`,
      `${basePath}.php`,
      `${basePath}/index.js`,
      `${basePath}/index.ts`,
    ];
    for (const cand of candidates) {
      if (fileContentMap.has(cand)) return cand;
    }
    return null;
  }

  for (const [filePath] of fileContentMap.entries()) {
    const baseName = filePath.replace(/\.[^.]+$/, '').split('/').pop();
    if (baseName === specifier) return filePath;
  }
  return null;
}

/**
 * Extracts function declarations and formal parameter lists from file content.
 */
export function extractFileFunctions(content, ext = '') {
  const fns = new Map();
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;

    // JS/TS: export function fn(a, b) / function fn(a, b) / const fn = (a, b) =>
    const jsFnMatch = /(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z_$][\w$]*)\s*\(([^)]*)\)|(?:export\s+)?(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/.exec(line);
    if (jsFnMatch) {
      const name = jsFnMatch[1] || jsFnMatch[3];
      const rawParams = jsFnMatch[2] !== undefined ? jsFnMatch[2] : jsFnMatch[4];
      const params = rawParams
        .split(',')
        .map((p) => p.trim().split(/[:=]/)[0].trim().replace(/^\{([^}]+)\}$/, '$1'))
        .filter(Boolean);
      fns.set(name, { name, params, line: lineNo });
      continue;
    }

    // Python: def fn(a, b):
    const pyFnMatch = /(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)/.exec(line);
    if (pyFnMatch) {
      const name = pyFnMatch[1];
      const params = pyFnMatch[2]
        .split(',')
        .map((p) => p.trim().split(/[:=]/)[0].trim())
        .filter((p) => p && p !== 'self' && p !== 'cls');
      fns.set(name, { name, params, line: lineNo });
      continue;
    }

    // Go: func Fn(a string, b int)
    const goFnMatch = /func\s+([A-Z][\w$]*)\s*\(([^)]*)\)/.exec(line);
    if (goFnMatch) {
      const name = goFnMatch[1];
      const params = goFnMatch[2]
        .split(',')
        .map((p) => p.trim().split(/\s+/)[0].trim())
        .filter(Boolean);
      fns.set(name, { name, params, line: lineNo });
      continue;
    }

    // PHP: function fn($a, $b)
    const phpFnMatch = /function\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)/.exec(line);
    if (phpFnMatch) {
      const name = phpFnMatch[1];
      const params = phpFnMatch[2]
        .split(',')
        .map((p) => p.trim().split(/[:=]/)[0].trim())
        .filter(Boolean);
      fns.set(name, { name, params, line: lineNo });
    }
  }

  return fns;
}

/**
 * Extracts import statements and maps imported symbols to target module specifiers.
 */
export function extractFileImports(content, ext = '') {
  const imports = new Map();
  const lines = content.split(/\r?\n/);

  for (const line of lines) {
    // JS/TS: import { a, b as c } from './module'
    const esImport = /import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/.exec(line);
    if (esImport) {
      const symbols = esImport[1].split(',').map((s) => s.trim().split(/\s+as\s+/)[0].trim());
      const spec = esImport[2];
      for (const sym of symbols) imports.set(sym, spec);
      continue;
    }

    // JS/TS: import foo from './module'
    const defaultImport = /import\s+([a-zA-Z_$][\w$]*)\s+from\s+['"]([^'"]+)['"]/.exec(line);
    if (defaultImport) {
      imports.set(defaultImport[1], defaultImport[2]);
      continue;
    }

    // JS/TS: const { a, b } = require('./module')
    const reqImport = /(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/.exec(line);
    if (reqImport) {
      const symbols = reqImport[1].split(',').map((s) => s.trim().split(':')[0].trim());
      const spec = reqImport[2];
      for (const sym of symbols) imports.set(sym, spec);
      continue;
    }

    // Python: from .module import a, b OR from module import a, b
    const pyFromImport = /from\s+([.\w]+)\s+import\s+([\w,\s]+)/.exec(line);
    if (pyFromImport) {
      const spec = pyFromImport[1];
      const symbols = pyFromImport[2].split(',').map((s) => s.trim());
      for (const sym of symbols) imports.set(sym, spec);
      continue;
    }
  }

  return imports;
}

const CODE_EXTS = new Set(['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx', '.py', '.go', '.java', '.php', '.cs']);
const CALL_IGNORE = new Set([
  'if', 'for', 'while', 'catch', 'switch', 'return', 'function', 'class',
  'const', 'let', 'var', 'import', 'export', 'print', 'println', 'console',
  'require', 'assert', 'describe', 'test', 'it', 'expect', 'sizeof', 'typeof',
]);

/**
 * Traces taint propagation across all files in a project, resolving inter-module
 * calls where tainted variables in caller files are passed into callee function parameters.
 */
export function traceProjectTaint(fileContentMap) {
  const fileTrackers = new Map();
  const fileFunctions = new Map();
  const fileImports = new Map();
  const fileLinesMap = new Map();
  const globalFnIndex = new Map();
  const taintedCallerFiles = new Set();

  for (const [filePath, content] of fileContentMap.entries()) {
    const extMatch = /\.[^.]+$/.exec(filePath);
    const ext = extMatch ? extMatch[0].toLowerCase() : '';
    if (!CODE_EXTS.has(ext)) continue;

    const lines = content.split(/\r?\n/);
    fileLinesMap.set(filePath, lines);
    const tracker = traceFileTaint(content, lines, ext);
    fileTrackers.set(filePath, tracker);
    if (tracker.taintedVars.size > 0) {
      taintedCallerFiles.add(filePath);
    }

    const fns = extractFileFunctions(content, ext);
    fileFunctions.set(filePath, fns);
    for (const [fnName, fnDef] of fns.entries()) {
      if (!globalFnIndex.has(fnName)) globalFnIndex.set(fnName, []);
      globalFnIndex.get(fnName).push({ file: filePath, fnDef });
    }

    fileImports.set(filePath, extractFileImports(content, ext));
  }

  let propagated = true;
  let iterations = 0;
  const MAX_ITERATIONS = 5;

  while (propagated && iterations < MAX_ITERATIONS && taintedCallerFiles.size > 0) {
    propagated = false;
    iterations++;
    const callersToCheck = Array.from(taintedCallerFiles);

    for (const callerPath of callersToCheck) {
      const tracker = fileTrackers.get(callerPath);
      if (!tracker || tracker.taintedVars.size === 0) continue;

      const lines = fileLinesMap.get(callerPath);
      if (!lines) continue;
      const imports = fileImports.get(callerPath) || new Map();

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNo = i + 1;
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('//') || trimmed.startsWith('#')) continue;

        // Check for function calls: callee(arg1, arg2) or obj.callee(arg1, arg2)
        const callRegex = /(?:([a-zA-Z_$][\w$]*)\.)?([a-zA-Z_$][\w$]*)\s*\(([^)]*)\)/g;
        let callMatch;

        while ((callMatch = callRegex.exec(line)) !== null) {
          const calleeName = callMatch[2];
          if (CALL_IGNORE.has(calleeName)) continue;

          const rawArgs = callMatch[3];
          if (!rawArgs.trim()) continue;

          const args = rawArgs.split(',').map((a) => a.trim());

          for (let argIdx = 0; argIdx < args.length; argIdx++) {
            const argExpr = args[argIdx];
            for (const [taintedName, prev] of tracker.taintedVars.entries()) {
              if (!argExpr.includes(taintedName)) continue;
              const varRegex = createVarRegex(taintedName);
              if (varRegex.test(argExpr) && prev.line <= lineNo) {
                let targetFile = null;
                let targetFnDef = null;

                const specifier = imports.get(calleeName);
                if (specifier) {
                  targetFile = resolveImportPath(callerPath, specifier, fileContentMap);
                  if (targetFile) {
                    targetFnDef = fileFunctions.get(targetFile)?.get(calleeName);
                  }
                }

                if (!targetFile) {
                  const candidates = globalFnIndex.get(calleeName);
                  if (candidates) {
                    for (const c of candidates) {
                      if (c.file !== callerPath) {
                        targetFile = c.file;
                        targetFnDef = c.fnDef;
                        break;
                      }
                    }
                  }
                }

                if (targetFile && targetFnDef && fileTrackers.has(targetFile)) {
                  if (targetFnDef.params[argIdx]) {
                    const paramName = targetFnDef.params[argIdx];
                    const targetTracker = fileTrackers.get(targetFile);

                    if (!targetTracker.taintedVars.has(paramName)) {
                      const crossHop = `${callerPath}:${lineNo}:${calleeName}(${argExpr})`;
                      const paramHop = `${targetFile}:${targetFnDef.line}:${paramName}`;
                      const newHops = [...prev.hops, crossHop, paramHop];

                      const paramEntry = {
                        name: paramName,
                        line: targetFnDef.line,
                        sourceExpr: prev.sourceExpr,
                        hops: newHops,
                        isCrossFile: true,
                        callerFile: callerPath,
                      };

                      targetTracker.taintedVars.set(paramName, paramEntry);
                      targetTracker.taintHistory.push(paramEntry);
                      taintedCallerFiles.add(targetFile);
                      propagated = true;

                      const targetLines = fileLinesMap.get(targetFile);
                      if (targetLines) {
                        for (let j = targetFnDef.line - 1; j < targetLines.length; j++) {
                          const tLine = targetLines[j];
                          const tLineNo = j + 1;
                          const assignMatch = /^\s*(?:(?:const|let|var|string|var|val|\$)\s+)?([$a-zA-Z_]\w*)\s*(?::=|=)\s*(.+)$/.exec(tLine);
                          if (assignMatch) {
                            const destVar = assignMatch[1];
                            const rhs = assignMatch[2];
                            for (const [tName, tPrev] of targetTracker.taintedVars.entries()) {
                              if (!rhs.includes(tName)) continue;
                              const vReg = createVarRegex(tName);
                              if (vReg.test(rhs) && destVar !== tName && !targetTracker.taintedVars.has(destVar)) {
                                const destHops = [...tPrev.hops, `${targetFile}:${tLineNo}:${destVar}`];
                                const destEntry = {
                                  name: destVar,
                                  line: tLineNo,
                                  sourceExpr: tPrev.sourceExpr,
                                  hops: destHops,
                                  isCrossFile: true,
                                };
                                targetTracker.taintedVars.set(destVar, destEntry);
                                targetTracker.taintHistory.push(destEntry);
                                propagated = true;
                                break;
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
                break;
              }
            }
          }
        }
      }
    }
  }

  return fileTrackers;
}

/**
 * Enrich detected findings with taint analysis and reachability metadata.
 *
 * If a finding matches an injection or dangerous sink rule and has a verified
 * source-to-sink taint path:
 * 1. Attaches `finding.taintPath` (e.g. `req.query.id -> id -> query -> sql`)
 * 2. Attaches `finding.reachable = true`
 * 3. Elevates confidence to `confirmed` and recalculates presentation priority.
 */
export function enrichFindingsWithTaint(findings, fileContentMap) {
  if (!findings || findings.length === 0) return findings;

  const projectTrackers = traceProjectTaint(fileContentMap);

  for (const f of findings) {
    if (!f.file || !f.line) continue;

    const taintData = projectTrackers.get(f.file);
    if (taintData) {
      const taint = findTaintPathForSink(taintData, f.line, f.snippet ?? '');
      if (taint) {
        f.taintPath = taint.pathSummary;
        f.reachable = true;
        // Elevate confidence to confirmed if previously firm or tentative
        if (f.confidence !== 'confirmed') {
          f.confidence = 'confirmed';
          // Re-evaluate priority
          if (f.priority === 'P2' && f.severity === 'high') f.priority = 'P1';
          if (f.priority === 'P1' && f.severity === 'critical') f.priority = 'P0';
        }
      }
    }
  }

  return findings;
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
