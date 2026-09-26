// HCL2 (Terraform) parsing.
//
// Deliberately not a complete HCL implementation. Assertion rules need three
// things: what kind of block this is, what its labels are, and what its
// attributes are set to. Expressions we cannot evaluate are kept as their raw
// source text, which is what rules actually want — a rule asking whether
// cidr_blocks contains "0.0.0.0/0" is happy with the literal, and a rule
// looking at `var.allowed` should see `var.allowed` rather than a guess.
//
// The plan flagged this parser as the one with real schedule risk. The scope
// above is how that risk is contained: no expression evaluation, no type
// system, no module resolution.

import { annotate, lineOf } from './node.mjs';

const ID_START = /[A-Za-z_]/;
const ID_CHAR = /[A-Za-z0-9_.\-*]/;

class Scanner {
  constructor(source) {
    this.s = source;
    this.i = 0;
    this.line = 1;
  }

  eof() { return this.i >= this.s.length; }
  peek(n = 0) { return this.s[this.i + n]; }

  advance(n = 1) {
    for (let k = 0; k < n && this.i < this.s.length; k += 1) {
      if (this.s[this.i] === '\n') this.line += 1;
      this.i += 1;
    }
  }

  /** Whitespace and comments. `stopAtNewline` keeps attribute parsing honest. */
  skipTrivia(stopAtNewline = false) {
    for (;;) {
      const c = this.peek();
      if (c === undefined) return;
      if (c === '\n' && stopAtNewline) return;
      if (c === ' ' || c === '\t' || c === '\r' || c === '\n') { this.advance(); continue; }
      if (c === '#' || (c === '/' && this.peek(1) === '/')) {
        while (!this.eof() && this.peek() !== '\n') this.advance();
        continue;
      }
      if (c === '/' && this.peek(1) === '*') {
        this.advance(2);
        while (!this.eof() && !(this.peek() === '*' && this.peek(1) === '/')) this.advance();
        this.advance(2);
        continue;
      }
      return;
    }
  }

  ident() {
    if (!ID_START.test(this.peek() ?? '')) return null;
    const start = this.i;
    while (!this.eof() && ID_CHAR.test(this.peek())) this.advance();
    return this.s.slice(start, this.i);
  }

  /** Quoted string. Interpolation is preserved verbatim inside the value. */
  string() {
    if (this.peek() !== '"') return null;
    this.advance();
    let out = '';
    while (!this.eof() && this.peek() !== '"') {
      if (this.peek() === '\\') {
        const next = this.peek(1);
        out += next === 'n' ? '\n' : next === 't' ? '\t' : next;
        this.advance(2);
        continue;
      }
      out += this.peek();
      this.advance();
    }
    this.advance();
    return out;
  }

  heredoc() {
    if (this.peek() !== '<' || this.peek(1) !== '<') return null;
    this.advance(2);
    if (this.peek() === '-') this.advance();
    const tag = this.ident();
    if (!tag) return '';
    while (!this.eof() && this.peek() !== '\n') this.advance();
    this.advance();
    const start = this.i;
    for (;;) {
      if (this.eof()) break;
      const lineStart = this.i;
      let j = this.i;
      while (j < this.s.length && (this.s[j] === ' ' || this.s[j] === '\t')) j += 1;
      if (this.s.startsWith(tag, j)) {
        const body = this.s.slice(start, lineStart);
        this.advance(j + tag.length - this.i);
        return body;
      }
      while (!this.eof() && this.peek() !== '\n') this.advance();
      this.advance();
    }
    return this.s.slice(start);
  }

  /**
   * Anything we do not model: a reference, a function call, a ternary. Read to
   * the end of the expression, tracking bracket depth so a call spanning lines
   * is captured whole, and hand back the source text.
   */
  rawExpression() {
    const start = this.i;
    let depth = 0;
    while (!this.eof()) {
      const c = this.peek();
      if (c === '"') { this.string(); continue; }
      if (c === '(' || c === '[' || c === '{') depth += 1;
      if (c === ')' || c === ']' || c === '}') {
        if (depth === 0) break;
        depth -= 1;
      }
      if (depth === 0 && (c === '\n' || c === ',')) break;
      this.advance();
    }
    return this.s.slice(start, this.i).trim();
  }

  value() {
    this.skipTrivia(true);
    const c = this.peek();
    if (c === '"') return this.string();
    if (c === '<' && this.peek(1) === '<') return this.heredoc();

    if (c === '[') {
      const line = this.line;
      this.advance();
      const out = [];
      for (;;) {
        this.skipTrivia();
        if (this.eof() || this.peek() === ']') { this.advance(); break; }
        out.push(this.value());
        this.skipTrivia();
        if (this.peek() === ',') this.advance();
      }
      return annotate(out, line);
    }

    if (c === '{') {
      const line = this.line;
      this.advance();
      const out = {};
      for (;;) {
        this.skipTrivia();
        if (this.eof() || this.peek() === '}') { this.advance(); break; }
        const key = this.string() ?? this.ident();
        if (key === null) { this.advance(); continue; }
        this.skipTrivia(true);
        if (this.peek() === '=' || this.peek() === ':') this.advance();
        out[key] = this.value();
        this.skipTrivia();
        if (this.peek() === ',') this.advance();
      }
      return annotate(out, line);
    }

    const raw = this.rawExpression();
    if (raw === 'true') return true;
    if (raw === 'false') return false;
    if (raw === 'null') return null;
    if (/^-?\d+(\.\d+)?$/.test(raw)) return Number(raw);
    return raw;
  }
}

function parseBody(sc, depth) {
  const attrs = {};
  const blocks = [];

  for (;;) {
    sc.skipTrivia();
    if (sc.eof()) break;
    if (sc.peek() === '}') { sc.advance(); break; }

    const line = sc.line;
    const name = sc.string() ?? sc.ident();
    if (name === null) { sc.advance(); continue; }

    sc.skipTrivia(true);

    if (sc.peek() === '=' && sc.peek(1) !== '=') {
      sc.advance();
      attrs[name] = sc.value();
      continue;
    }

    // Otherwise it is a block: read labels up to the opening brace.
    const labels = [];
    for (;;) {
      sc.skipTrivia(true);
      const c = sc.peek();
      if (c === '{' || c === '\n' || c === undefined) break;
      const label = sc.string() ?? sc.ident();
      if (label === null) { sc.advance(); continue; }
      labels.push(label);
    }

    sc.skipTrivia();
    if (sc.peek() !== '{') continue;
    sc.advance();

    // A pathological nesting depth is malformed input, not a deep config.
    const body = depth > 64 ? { attrs: {}, blocks: [] } : parseBody(sc, depth + 1);
    blocks.push(annotate({ type: name, labels: annotate(labels, line), ...body }, line));
  }

  return { attrs: annotate(attrs, 1), blocks: annotate(blocks, 1) };
}

/** Depth-first flattening, so a rule can match a nested block without knowing how deep it is. */
function flatten(blocks, prefix, out) {
  for (const b of blocks) {
    const address = [...prefix, b.type, ...b.labels].join('.');
    out.push(annotate({ ...b, address }, lineOf(b)));
    flatten(b.blocks, [...prefix, b.type, ...b.labels], out);
  }
  return out;
}

/**
 * Every attribute anywhere, denormalized with its enclosing block's context.
 *
 * The path language can resolve a value or a key but cannot correlate the two,
 * and "an attribute *named* like a password holding a literal" needs exactly
 * that correlation. Flattening it into one node per attribute is cheaper and
 * far more reviewable than growing the query language to do it.
 */
function flattenAttrs(blocks, out) {
  for (const b of blocks) {
    const address = b.address ?? [b.type, ...b.labels].join('.');
    for (const [name, value] of Object.entries(b.attrs ?? {})) {
      emitAttr(out, b, address, name, name, value, 0);
    }
  }
  return out;
}

function emitAttr(out, block, address, name, fullName, value, depth) {
  out.push(annotate({
    name,
    fullName,
    value,
    blockType: block.type,
    labels: block.labels,
    address,
  }, lineOf(value, lineOf(block))));

  // Map-valued attributes hide their keys one level down. `environment {
  // variables = { API_KEY = "..." } }` is the common shape, and the key is the
  // half that says whether the value is a credential.
  if (depth < 3 && value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value)) {
      emitAttr(out, block, address, k, `${fullName}.${k}`, v, depth + 1);
    }
  }
}

export function parseHcl(source) {
  const sc = new Scanner(source);
  let body;
  try {
    body = parseBody(sc, 0);
  } catch {
    return { documents: [] };
  }
  const allBlocks = flatten(body.blocks, [], []);
  const doc = annotate({
    attrs: body.attrs,
    blocks: body.blocks,
    allBlocks: annotate(allBlocks, 1),
    allAttrs: annotate(flattenAttrs(allBlocks, []), 1),
  }, 1);
  return { documents: [doc] };
}
