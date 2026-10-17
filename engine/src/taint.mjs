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
    regex: /(?:\$_(?:GET|POST|REQUEST)\[[^\]]+\]|\$request->(?:input|get|query|all)\s*\([^)]*\)|\$request->[\w$]+)/i,
    extractVars: (line) => {
      const match = /^\s*(\$[a-zA-Z_]\w*)\s*=\s*(?:\$_(?:GET|POST|REQUEST)|\$request->)/i.exec(line);
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

  // Cache traceFileTaint results per file
  const fileTaintCache = new Map();

  for (const f of findings) {
    if (!f.file || !f.line) continue;

    let taintData = fileTaintCache.get(f.file);
    if (!taintData && fileContentMap.has(f.file)) {
      const content = fileContentMap.get(f.file);
      const lines = content.split(/\r?\n/);
      const extMatch = /\.[^.]+$/.exec(f.file);
      const ext = extMatch ? extMatch[0].toLowerCase() : '';
      taintData = traceFileTaint(content, lines, ext);
      fileTaintCache.set(f.file, taintData);
    }

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
