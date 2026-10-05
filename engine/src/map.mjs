// Attack surface mapping and dangerous sink detection across web frameworks.
//
// Extracts HTTP routes and discovers dangerous sinks (SQL, exec, eval, SSRF, file I/O)
// located within the handler or file scope.

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', 'out', '.next', '.nuxt', '.cache',
  'coverage', 'vendor', 'target', '.venv', 'venv', '__pycache__', '.tox',
  '.terraform', '.gradle', '.idea', '.airtight',
]);

const SKIP_FILE = /\.(min\.(js|css)|map|lock\.hcl)$|^\.DS_Store$/;

const CODE_EXTS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.py',
  '.go',
  '.java', '.kt',
]);

function toPosix(p) {
  return sep === '/' ? p : p.split(sep).join('/');
}

function isBinary(buf) {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i += 1) if (buf[i] === 0) return true;
  return false;
}

function* walk(root, dir = root) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* walk(root, full);
    } else if (entry.isFile()) {
      if (SKIP_FILE.test(entry.name)) continue;
      yield full;
    }
  }
}

// ------------------------------------------------ Dangerous Sinks Detection

const SINK_PATTERNS = [
  {
    type: 'sql',
    regex: /(?:\b(?:db|conn|connection|client|pool|session|cursor|jdbcTemplate|em|dataSource|entityManager)\.(?:query|execute|rawQuery|queryRaw|executeRaw|executeUpdate|executeQuery|Query|QueryRow|Exec|createNativeQuery)\s*\(|\b(?:knex|prisma|sequelize)\.raw\s*\(|`[^`]*(?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM)[^`]*`|["'](?:SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+.+\s+SET|DELETE\s+FROM)[^"']*["'])/i,
  },
  {
    type: 'exec',
    regex: /(?:\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(|\bos\.(?:system|popen|spawn[a-z]*)\s*\(|\bexec\.Command(?:Context)?\s*\(|\bRuntime\.getRuntime\(\)\.exec\s*\(|\bnew\s+ProcessBuilder\s*\()/,
  },
  {
    type: 'eval',
    regex: /(?:(?<![\w$])(?:eval|Function)\s*\(|\bvm\.(?:runInContext|runInNewContext|runInThisContext)\s*\(|(?<![\w$.])exec\s*\([^)]*\))/,
  },
  {
    type: 'ssrf',
    regex: /(?:(?<![\w$])(?:fetch|superagent|got)\s*\(|\baxios(?:\.(?:get|post|put|delete|patch|request))?\s*\(|\b(?:http|https)\.(?:get|request)\s*\(|\brequests\.(?:get|post|put|delete|patch|request)\s*\(|\burllib\.request\.urlopen\s*\(|\bhttpx\.(?:get|post|put|delete|patch|request)\s*\(|\bhttp\.(?:Get|Post|Head|PostForm|NewRequest(?:WithContext)?)\s*\(|\bHttpClient\.newHttpClient\s*\(|\brestTemplate\.(?:getForObject|getForEntity|postForObject|postForEntity|exchange)\s*\()/,
  },
  {
    type: 'file',
    regex: /(?:\bfs(?:\.promises)?\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|appendFile|appendFileSync)\s*\(|(?<![\w$])open\s*\([^)]*['"][rwa]|(?<![\w$])aiofiles\.open\s*\(|\bos\.(?:ReadFile|WriteFile|Open|OpenFile|Create)\s*\(|\bio(?:util)?\.(?:ReadFile|WriteFile)\s*\(|\bFiles\.(?:readAllBytes|readAllLines|readString|write|writeString|newInputStream|newOutputStream)\s*\(|\bnew\s+(?:FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\()/,
  },
];

function detectSinksInLines(lines) {
  const sinks = [];
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const lineNo = i + 1;
    for (const { type, regex } of SINK_PATTERNS) {
      if (regex.test(line)) {
        sinks.push({
          type,
          line: lineNo,
          snippet: line.trim(),
        });
      }
    }
  }
  return sinks;
}

// ------------------------------------------------ Framework Route Parsers

/** Express: app.(get|post|...), router.(get|post|...) */
function parseExpressRoutes(content, lines, relPath) {
  if (content.includes('fastify') && !content.includes('express')) return [];
  const routes = [];
  const routeRe = /\b(app|router|[a-zA-Z0-9_$]*(?:Router|App|Server))\.(get|post|put|delete|patch|use|all)\s*\(\s*(['"`])([^'"`]+)\3(?:\s*,\s*([a-zA-Z0-9_$]+))?/g;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    routeRe.lastIndex = 0;
    let m;
    while ((m = routeRe.exec(line)) !== null) {
      const method = m[2].toUpperCase();
      const path = m[4];
      const handlerName = m[5] || 'anonymous';
      routes.push({
        framework: 'express',
        method,
        path,
        file: relPath,
        line: i + 1,
        handlerName,
      });
    }
  }
  return routes;
}

/** Fastify: fastify.(get|post|...|route) */
function parseFastifyRoutes(content, lines, relPath) {
  const routes = [];
  let varName = 'fastify';
  if (content.includes('fastify')) {
    const mInst = /(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:await\s+)?(?:fastify\s*\(|require\(['"]fastify['"]\)\()/i.exec(content);
    if (mInst) varName = mInst[1];
  }
  const prefixPattern = varName === 'fastify' ? 'fastify' : `(?:fastify|${varName})`;
  const simpleRe = new RegExp(`\\b${prefixPattern}\\.(get|post|put|delete|patch|all)\\s*\\(\\s*(['"\`])([^'"\`]+)\\2(?:\\s*,\\s*([a-zA-Z0-9_$]+))?`, 'g');
  const routeMethodRe = new RegExp(`\\b${prefixPattern}\\.route\\s*\\(\\s*\\{`);

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    simpleRe.lastIndex = 0;
    let m;
    while ((m = simpleRe.exec(line)) !== null) {
      routes.push({
        framework: 'fastify',
        method: m[1].toUpperCase(),
        path: m[3],
        file: relPath,
        line: i + 1,
        handlerName: m[4] || 'anonymous',
      });
    }

    if (routeMethodRe.test(line)) {
      // Look forward up to 10 lines for method, url, handler
      let method = 'GET';
      let path = '/';
      let handler = 'anonymous';
      const maxJ = Math.min(lines.length, i + 10);
      for (let j = i; j < maxJ; j += 1) {
        const sub = lines[j];
        const mMethod = /method\s*:\s*['"`]([A-Za-z]+)['"`]/.exec(sub)
          || /method\s*:\s*\[\s*['"`]([A-Za-z]+)['"`]/.exec(sub);
        if (mMethod) method = mMethod[1].toUpperCase();

        const mUrl = /(?:url|path)\s*:\s*['"`]([^'"`]+)['"`]/.exec(sub);
        if (mUrl) path = mUrl[1];

        const mHandler = /handler\s*:\s*([a-zA-Z0-9_$]+)/.exec(sub);
        if (mHandler) handler = mHandler[1];
        if (sub.includes('}')) break;
      }
      routes.push({
        framework: 'fastify',
        method,
        path,
        file: relPath,
        line: i + 1,
        handlerName: handler,
      });
    }
  }
  return routes;
}

/** Next.js App Router, Pages Router, and Server Actions */
function parseNextJsRoutes(content, lines, relPath) {
  const routes = [];

  // 1. App Router: app/**/route.(ts|js|tsx|jsx)
  const appMatch = /(?:^|\/)(?:src\/)?app(\/.*)?\/route\.(?:ts|js|tsx|jsx)$/.exec(relPath);
  if (appMatch) {
    let routePath = appMatch[1] || '/';
    if (!routePath.startsWith('/')) routePath = '/' + routePath;

    const exportFuncRe = /export\s+(?:async\s+)?function\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/;
    const exportConstRe = /export\s+const\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/;

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      const m = exportFuncRe.exec(line) || exportConstRe.exec(line);
      if (m) {
        routes.push({
          framework: 'nextjs',
          method: m[1].toUpperCase(),
          path: routePath,
          file: relPath,
          line: i + 1,
          handlerName: m[1],
        });
      }
    }
  }

  // 2. Pages Router: pages/api/**
  const pagesMatch = /(?:^|\/)(?:src\/)?pages\/api\/(.+)\.(?:ts|js|tsx|jsx)$/.exec(relPath);
  if (pagesMatch) {
    let sub = pagesMatch[1];
    if (sub === 'index') {
      sub = '';
    } else if (sub.endsWith('/index')) {
      sub = sub.slice(0, -6);
    }
    sub = sub.replace(/\[\.\.\.([a-zA-Z0-9_$]+)\]/g, ':$1*');
    sub = sub.replace(/\[([a-zA-Z0-9_$]+)\]/g, ':$1');

    let routePath = '/api' + (sub ? (sub.startsWith('/') ? sub : '/' + sub) : '');
    if (!routePath.startsWith('/')) routePath = '/' + routePath;

    let handlerName = 'handler';
    let handlerLine = 1;
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      const mFunc = /export\s+default\s+(?:async\s+)?function\s*([a-zA-Z0-9_$]+)?/.exec(line);
      if (mFunc) {
        handlerName = mFunc[1] || 'handler';
        handlerLine = i + 1;
        break;
      }
      const mIdent = /export\s+default\s+([a-zA-Z0-9_$]+)\s*;?$/.exec(line);
      if (mIdent) {
        handlerName = mIdent[1];
        handlerLine = i + 1;
        break;
      }
    }

    routes.push({
      framework: 'nextjs',
      method: 'ALL',
      path: routePath,
      file: relPath,
      line: handlerLine,
      handlerName,
    });
  }

  // 3. Server Actions: files with 'use server' at top or functions with 'use server' directive
  const topUseServer = /^\s*['"]use server['"]\s*;?/.test(
    lines.slice(0, 10).map((l) => l.trim()).filter((l) => l && !l.startsWith('//') && !l.startsWith('/*')).join('\n')
  );

  if (topUseServer) {
    const exportActionRe = /export\s+(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\b|export\s+const\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\(/;
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      const m = exportActionRe.exec(line);
      if (m) {
        const actionName = m[1] || m[2];
        routes.push({
          framework: 'nextjs',
          method: 'POST',
          path: `/${actionName}`,
          file: relPath,
          line: i + 1,
          handlerName: actionName,
        });
      }
    }
  } else if (content.includes("'use server'") || content.includes('"use server"')) {
    const funcHeaderRe = /(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(/;
    const constActionRe = /(?:export\s+)?const\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\(/;

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      if (/export\s+default\b/.test(line)) continue;

      const mFunc = funcHeaderRe.exec(line) || constActionRe.exec(line);
      if (mFunc) {
        const actionName = mFunc[1];
        let hasUseServer = false;
        // The first non-empty statement inside the function must be 'use server'
        for (let j = i + 1; j < Math.min(lines.length, i + 5); j += 1) {
          const trimmed = lines[j].trim();
          if (!trimmed || trimmed === '{') continue;
          if (/^['"]use server['"]\s*;?$/.test(trimmed)) {
            hasUseServer = true;
          }
          break;
        }
        if (hasUseServer) {
          routes.push({
            framework: 'nextjs',
            method: 'POST',
            path: `/${actionName}`,
            file: relPath,
            line: i + 1,
            handlerName: actionName,
          });
        }
      }
    }
  }

  return routes;
}

/** NestJS: @Controller(...) classes and HTTP method decorators */
function parseNestJsRoutes(content, lines, relPath) {
  if (!content.includes('@Controller')) return [];

  const routes = [];
  const controllerRe = /@Controller\s*(?:\(\s*(?:['"`]([^'"`]*)['"`])?\s*\))?/;
  const methodRe = /@(Get|Post|Put|Delete|Patch|All)\s*(?:\(\s*(?:['"`]([^'"`]*)['"`])?\s*\))?/;

  let currentPrefix = '';
  let inController = false;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];

    const cMatch = controllerRe.exec(line);
    if (cMatch) {
      currentPrefix = cMatch[1] ?? '';
      inController = true;
      continue;
    }

    if (!inController) continue;

    const mMatch = methodRe.exec(line);
    if (mMatch) {
      const verb = mMatch[1].toUpperCase();
      const subPath = mMatch[2] ?? '';

      // Combine controller prefix and method path
      let p = currentPrefix.trim();
      let s = subPath.trim();
      if (p && !p.startsWith('/')) p = '/' + p;
      if (p.endsWith('/')) p = p.slice(0, -1);
      if (s && !s.startsWith('/')) s = '/' + s;
      let fullPath = p + s;
      if (!fullPath || fullPath === '') fullPath = '/';
      fullPath = fullPath.replace(/\/+/g, '/');

      // Look forward for handler method name and parameters
      let handlerName = 'anonymous';
      let paramText = '';
      const maxJ = Math.min(lines.length, i + 10);
      for (let j = i + 1; j < maxJ; j += 1) {
        const subLine = lines[j];
        if (subLine.includes('@Controller')) break;

        const mHandler = /(?:public\s+|private\s+|protected\s+)?(?:async\s+)?([a-zA-Z0-9_$]+)\s*\(([\s\S]*)/.exec(subLine);
        if (mHandler && !subLine.trim().startsWith('@')) {
          handlerName = mHandler[1];
          let collected = mHandler[2];
          if (!collected.includes(')')) {
            for (let k = j + 1; k < Math.min(lines.length, j + 10); k += 1) {
              collected += ' ' + lines[k];
              if (lines[k].includes(')')) break;
            }
          }
          paramText = collected;
          break;
        }
      }

      // Extract parameter annotations (@Body(), @Query(), @Param())
      const paramMatches = [...paramText.matchAll(/@(Body|Query|Param)\b/g)];
      const params = [...new Set(paramMatches.map((m) => `@${m[1]}()`))];

      routes.push({
        framework: 'nestjs',
        method: verb,
        path: fullPath,
        file: relPath,
        line: i + 1,
        handlerName,
        params,
        parameters: params,
      });
    }
  }

  return routes;
}

/** Cloudflare Pages Functions: functions/api/** or functions/** */
function parseCloudflareRoutes(content, lines, relPath) {
  const match = /(?:^|\/)functions\/(.+)\.(?:ts|js|mjs|cjs)$/.exec(relPath);
  if (!match) return [];

  let sub = match[1];
  if (sub === 'index') {
    sub = '';
  } else if (sub.endsWith('/index')) {
    sub = sub.slice(0, -6);
  }
  sub = sub.replace(/\[\.\.\.([a-zA-Z0-9_$]+)\]/g, ':$1*');
  sub = sub.replace(/\[([a-zA-Z0-9_$]+)\]/g, ':$1');

  let routePath = sub ? (sub.startsWith('/') ? sub : '/' + sub) : '/';
  routePath = routePath.replace(/\/+/g, '/');

  const routes = [];
  const exportFuncRe = /export\s+(?:async\s+)?function\s+(onRequest(?:Get|Post|Put|Delete|Patch|Head|Options)?)\b/;
  const exportConstRe = /export\s+const\s+(onRequest(?:Get|Post|Put|Delete|Patch|Head|Options)?)\b/;

  const methodMap = {
    onRequestGet: 'GET',
    onRequestPost: 'POST',
    onRequestPut: 'PUT',
    onRequestDelete: 'DELETE',
    onRequestPatch: 'PATCH',
    onRequestHead: 'HEAD',
    onRequestOptions: 'OPTIONS',
    onRequest: 'ALL',
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const m = exportFuncRe.exec(line) || exportConstRe.exec(line);
    if (m) {
      const handlerName = m[1];
      const method = methodMap[handlerName] || 'ALL';
      routes.push({
        framework: 'cloudflare',
        method,
        path: routePath,
        file: relPath,
        line: i + 1,
        handlerName,
      });
    }
  }

  return routes;
}

/** Flask: @app.route(...), @(bp|api).route(...) */
function parseFlaskRoutes(lines, relPath) {
  const routes = [];
  const routeRe = /@([a-zA-Z0-9_]+)\.route\s*\(\s*(['"])([^'"]+)\2(?:\s*,\s*methods\s*=\s*\[([^\]]+)\])?\s*\)/;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const m = routeRe.exec(line);
    if (m) {
      const path = m[3];
      const rawMethods = m[4];
      let handlerName = 'anonymous';

      // Find next function definition
      for (let j = i + 1; j < Math.min(lines.length, i + 6); j += 1) {
        const defMatch = /(?:async\s+)?def\s+([a-zA-Z0-9_]+)\s*\(/.exec(lines[j]);
        if (defMatch) {
          handlerName = defMatch[1];
          break;
        }
      }

      const methods = rawMethods
        ? [...rawMethods.matchAll(/['"]([A-Za-z]+)['"]/g)].map((x) => x[1].toUpperCase())
        : ['GET'];

      for (const method of methods) {
        routes.push({
          framework: 'flask',
          method,
          path,
          file: relPath,
          line: i + 1,
          handlerName,
        });
      }
    }
  }
  return routes;
}

/** FastAPI: @app.(get|post|...), @router.(get|post|...) */
function parseFastApiRoutes(lines, relPath) {
  const routes = [];
  const routeRe = /@([a-zA-Z0-9_]+)\.(get|post|put|delete|patch|options|head)\s*\(\s*(['"])([^'"]+)\3\s*\)/;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const m = routeRe.exec(line);
    if (m) {
      const method = m[2].toUpperCase();
      const path = m[4];
      let handlerName = 'anonymous';

      for (let j = i + 1; j < Math.min(lines.length, i + 6); j += 1) {
        const defMatch = /(?:async\s+)?def\s+([a-zA-Z0-9_]+)\s*\(/.exec(lines[j]);
        if (defMatch) {
          handlerName = defMatch[1];
          break;
        }
      }

      routes.push({
        framework: 'fastapi',
        method,
        path,
        file: relPath,
        line: i + 1,
        handlerName,
      });
    }
  }
  return routes;
}

/** Django: path('...', views.xxx) and re_path('...', views.xxx) in urls.py */
function parseDjangoRoutes(lines, relPath) {
  if (!/(?:^|\/)[a-zA-Z0-9_]*urls.*\.py$/.test(relPath)) return [];

  const routes = [];
  const djangoRe = /\b(?:path|re_path)\s*\(\s*r?(['"])([^'"]*)\1\s*,\s*([a-zA-Z0-9_.]+(?:\.as_view\(\))?)/g;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    djangoRe.lastIndex = 0;
    let m;
    while ((m = djangoRe.exec(line)) !== null) {
      routes.push({
        framework: 'django',
        method: 'ALL',
        path: m[2],
        file: relPath,
        line: i + 1,
        handlerName: m[3],
      });
    }
  }
  return routes;
}

/** Gin (Go): r.(GET|POST|...|Group), router.(GET|POST|...) */
function parseGinRoutes(lines, relPath) {
  const routes = [];
  const ginRe = /\b([a-zA-Z0-9_]+)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Group)\s*\(\s*(["'])([^"']+)\3(?:\s*,\s*([a-zA-Z0-9_.]+))?/g;

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    ginRe.lastIndex = 0;
    let m;
    while ((m = ginRe.exec(line)) !== null) {
      const verb = m[2];
      const method = verb === 'Group' ? 'GROUP' : verb.toUpperCase();
      const path = m[4];
      const handlerName = m[5] || 'anonymous';
      routes.push({
        framework: 'gin',
        method,
        path,
        file: relPath,
        line: i + 1,
        handlerName,
      });
    }
  }
  return routes;
}

/** Spring: @(Get|Post|Put|Delete|Patch|Request)Mapping(...) */
function parseSpringRoutes(lines, relPath) {
  const routes = [];
  const mappingRe = /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(\s*(?:(?:value|path)\s*=\s*)?(?:\{?\s*)?(["'])([^"']*)\2)?/;

  let classLine = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (/\b(?:public\s+|private\s+|protected\s+)?class\s+[A-Za-z0-9_]+/.test(lines[i])) {
      classLine = i + 1;
      break;
    }
  }

  let classPrefix = '';
  // Check if class-level @RequestMapping exists before class declaration
  const searchLimit = classLine > 0 ? classLine : Math.min(lines.length, 50);
  for (let i = 0; i < searchLimit; i += 1) {
    const line = lines[i];
    const m = /@RequestMapping\s*\(\s*(?:(?:value|path)\s*=\s*)?(["'])([^"']*)\1/.exec(line);
    if (m) {
      classPrefix = m[2];
      break;
    }
  }

  const startIdx = classLine > 0 ? classLine : 0;
  for (let i = startIdx; i < lines.length; i += 1) {
    const line = lines[i];
    const m = mappingRe.exec(line);
    if (m) {
      const annotation = m[1];
      let subPath = m[3] ?? '';
      let method = 'GET';

      if (annotation === 'PostMapping') method = 'POST';
      else if (annotation === 'PutMapping') method = 'PUT';
      else if (annotation === 'DeleteMapping') method = 'DELETE';
      else if (annotation === 'PatchMapping') method = 'PATCH';
      else if (annotation === 'RequestMapping') {
        const mMethod = /method\s*=\s*RequestMethod\.([A-Za-z]+)/.exec(line);
        method = mMethod ? mMethod[1].toUpperCase() : 'ALL';
      }

      let fullPath = subPath;
      if (classPrefix) {
        fullPath = (classPrefix.endsWith('/') ? classPrefix.slice(0, -1) : classPrefix)
          + (subPath.startsWith('/') ? subPath : '/' + subPath);
      }
      if (!fullPath) fullPath = '/';

      let handlerName = 'anonymous';
      for (let j = i + 1; j < Math.min(lines.length, i + 6); j += 1) {
        const mMethodDef = /(?:public|protected|private)?\s*(?:[\w<>\[\],\s]+\s+)+([a-zA-Z0-9_]+)\s*\(/.exec(lines[j]);
        if (mMethodDef && !lines[j].includes('class ')) {
          handlerName = mMethodDef[1];
          break;
        }
      }

      routes.push({
        framework: 'spring',
        method,
        path: fullPath,
        file: relPath,
        line: i + 1,
        handlerName,
      });
    }
  }
  return routes;
}

// ------------------------------------------------ Main Entry Point

export function generateAttackSurfaceMap(paths, { root = process.cwd() } = {}) {
  const targetPaths = paths
    ? (Array.isArray(paths) ? paths : [paths])
    : ['.'];

  const filesToScan = new Set();

  for (const p of targetPaths) {
    const absPath = resolve(root, p);
    let st;
    try {
      st = statSync(absPath);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      for (const f of walk(absPath)) {
        filesToScan.add(f);
      }
    } else if (st.isFile()) {
      filesToScan.add(absPath);
    }
  }

  const allRoutes = [];

  for (const absPath of filesToScan) {
    const relPath = toPosix(relative(root, absPath));
    const extMatch = /\.[^.]+$/.exec(relPath);
    const ext = extMatch ? extMatch[0].toLowerCase() : '';

    if (!CODE_EXTS.has(ext)) continue;

    let buf;
    try {
      const st = statSync(absPath);
      if (st.size > 2_097_152) continue; // Skip files > 2MB
      buf = readFileSync(absPath);
    } catch {
      continue;
    }
    if (isBinary(buf)) continue;

    const content = buf.toString('utf8');
    const lines = content.split('\n');

    let fileRoutes = [];

    // Dispatch framework route parsers
    if (['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'].includes(ext)) {
      fileRoutes.push(...parseNextJsRoutes(content, lines, relPath));
      fileRoutes.push(...parseNestJsRoutes(content, lines, relPath));
      fileRoutes.push(...parseCloudflareRoutes(content, lines, relPath));
      fileRoutes.push(...parseExpressRoutes(content, lines, relPath));
      fileRoutes.push(...parseFastifyRoutes(content, lines, relPath));
    }

    if (ext === '.py') {
      fileRoutes.push(...parseFlaskRoutes(lines, relPath));
      fileRoutes.push(...parseFastApiRoutes(lines, relPath));
      fileRoutes.push(...parseDjangoRoutes(lines, relPath));
    }

    if (ext === '.go') {
      fileRoutes.push(...parseGinRoutes(lines, relPath));
    }

    if (['.java', '.kt'].includes(ext)) {
      fileRoutes.push(...parseSpringRoutes(lines, relPath));
    }

    if (fileRoutes.length === 0) continue;

    // Detect sinks in the file
    const fileSinks = detectSinksInLines(lines);

    // Associate sinks with routes by line proximity / handler scope
    // Sort routes by line
    fileRoutes.sort((a, b) => a.line - b.line);

    for (let rIdx = 0; rIdx < fileRoutes.length; rIdx += 1) {
      const currentRoute = fileRoutes[rIdx];

      // Find next route on a DIFFERENT line
      let nextRoute;
      for (let k = rIdx + 1; k < fileRoutes.length; k += 1) {
        if (fileRoutes[k].line !== currentRoute.line) {
          nextRoute = fileRoutes[k];
          break;
        }
      }

      // Find previous route on a DIFFERENT line
      let prevRoute;
      for (let k = rIdx - 1; k >= 0; k -= 1) {
        if (fileRoutes[k].line !== currentRoute.line) {
          prevRoute = fileRoutes[k];
          break;
        }
      }

      const startLine = prevRoute ? currentRoute.line : 1;
      const endLine = nextRoute ? nextRoute.line - 1 : lines.length;

      currentRoute.sinks = fileSinks.filter((s) => s.line >= startLine && s.line <= endLine);
    }

    allRoutes.push(...fileRoutes);
  }

  // Sort overall routes by file, then line
  allRoutes.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);

  const frameworks = [...new Set(allRoutes.map((r) => r.framework))].sort();
  const uniqueSinks = new Set();
  for (const r of allRoutes) {
    for (const s of r.sinks) {
      uniqueSinks.add(`${r.file}:${s.line}:${s.type}`);
    }
  }
  const totalSinksNearRoutes = uniqueSinks.size;

  return {
    routes: allRoutes,
    summary: {
      totalRoutes: allRoutes.length,
      frameworks,
      totalSinksNearRoutes,
    },
  };
}
