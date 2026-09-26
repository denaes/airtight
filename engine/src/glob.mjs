// Minimal glob matcher. Supports **, *, ?, {a,b} and [abc] against POSIX-style
// relative paths. No dependency, because the shipped engine must run from a
// single bundled file with nothing installed.

const cache = new Map();

function toRegexSource(glob) {
  let out = '';
  let i = 0;
  const depth = [];

  while (i < glob.length) {
    const c = glob[i];

    if (c === '*') {
      // `**/` spans any number of directories, including none.
      if (glob[i + 1] === '*') {
        if (glob[i + 2] === '/') {
          out += '(?:.*/)?';
          i += 3;
          continue;
        }
        out += '.*';
        i += 2;
        continue;
      }
      // A single star never crosses a directory separator.
      out += '[^/]*';
      i += 1;
      continue;
    }

    if (c === '?') { out += '[^/]'; i += 1; continue; }

    if (c === '[') {
      const end = glob.indexOf(']', i + 1);
      if (end === -1) { out += '\\['; i += 1; continue; }
      let body = glob.slice(i + 1, end);
      if (body[0] === '!') body = '^' + body.slice(1);
      out += '[' + body + ']';
      i = end + 1;
      continue;
    }

    if (c === '{') { depth.push(true); out += '(?:'; i += 1; continue; }
    if (c === '}' && depth.length) { depth.pop(); out += ')'; i += 1; continue; }
    if (c === ',' && depth.length) { out += '|'; i += 1; continue; }

    out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    i += 1;
  }

  return out;
}

export function globToRegex(glob) {
  let re = cache.get(glob);
  if (!re) {
    re = new RegExp('^' + toRegexSource(glob) + '$');
    cache.set(glob, re);
  }
  return re;
}

/**
 * A bare `*.yaml` should match at any depth, the way .gitignore and every
 * scanner users have met already behave. An anchored pattern (one containing a
 * slash) is matched only against the full relative path.
 */
export function matchesGlob(relPath, glob) {
  if (globToRegex(glob).test(relPath)) return true;
  if (!glob.includes('/')) {
    const base = relPath.slice(relPath.lastIndexOf('/') + 1);
    return globToRegex(glob).test(base);
  }
  return false;
}

export function matchesAny(relPath, globs) {
  if (!globs || globs.length === 0) return false;
  return globs.some((g) => matchesGlob(relPath, g));
}
