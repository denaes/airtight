// Generic high-entropy credential detection.
//
// The escape hatch exists for rules that cannot be a regex, and this is the
// canonical one: "looks like a secret" is a property of the *distribution* of
// characters, not of a pattern. Everything a provider-specific rule can catch
// should be caught there instead, because this rule is necessarily the least
// precise one we ship. It is tentative for that reason.

const ASSIGNMENT = /(?:^|[\s,{(])([A-Za-z_][A-Za-z0-9_]{2,40})\s*[:=]\s*["'`]([^"'`\n]{16,120})["'`]/g;

const SECRETISH = /(?:secret|token|passwd|password|api[_-]?key|apikey|auth|credential|private[_-]?key|access[_-]?key|client[_-]?secret|encryption[_-]?key|signing[_-]?key)/i;

// Shapes that are long and mixed but are not credentials.
const NOT_A_SECRET = [
  /^https?:\/\//i,
  /^[a-f0-9-]{36}$/i,                         // a plain UUID
  /^\$\{|\{\{|^<%|^%\(/,                       // template or interpolation
  /^(sha256|sha512|md5)[-:]/i,
  /^[A-Za-z0-9+/]+={1,2}$/,                    // padded base64 of something inert
  /\s/,                                        // prose
  /^(true|false|null|undefined)$/i,
  /^[0-9.]+$/,                                 // versions and numbers
  /^[a-z]+([-_][a-z]+){2,}$/i,                 // kebab or snake identifiers
  /^\/|^\.\/|^\.\.\//,                         // paths
];

function shannonEntropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/** Character-class breadth. A long lowercase word has decent entropy but is not a key. */
function classes(s) {
  return (/[a-z]/.test(s) ? 1 : 0) + (/[A-Z]/.test(s) ? 1 : 0)
    + (/[0-9]/.test(s) ? 1 : 0) + (/[^A-Za-z0-9]/.test(s) ? 1 : 0);
}

export function check({ lines }) {
  const hits = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    ASSIGNMENT.lastIndex = 0;
    let m;
    while ((m = ASSIGNMENT.exec(line)) !== null) {
      const [, name, value] = m;
      if (!SECRETISH.test(name)) continue;
      if (NOT_A_SECRET.some((re) => re.test(value))) continue;
      if (classes(value) < 3) continue;
      if (shannonEntropy(value) < 3.6) continue;

      hits.push({ line: i + 1, column: m.index + 1, value });
    }
  }

  return hits;
}
