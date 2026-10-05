// YAML and JSON parsing.
//
// One parser serves both, because YAML is a superset of JSON and the `yaml`
// package's document AST carries byte ranges. Walking that AST ourselves rather
// than calling toJS() is what buys exact line numbers, which is the difference
// between "this workflow is unsafe" and "this workflow is unsafe at line 34".

import { parseAllDocuments, isMap, isSeq, isScalar, isAlias } from 'yaml';
import { annotate, lineIndexer } from './node.mjs';

function toPlain(node, toLine, doc, seen, state = { aliasCount: 0 }) {
  if (node === null || node === undefined) return null;

  if (isAlias(node)) {
    // Anchors are rare in the config we scan, and a cyclic or exponential bomb would hang us.
    state.aliasCount += 1;
    if (state.aliasCount > 100) return null;
    if (seen.has(node)) return null;
    seen.add(node);
    try {
      return toPlain(node.resolve(doc), toLine, doc, seen, state);
    } catch {
      return null;
    } finally {
      seen.delete(node);
    }
  }

  const line = node.range ? toLine(node.range[0]) : 1;

  if (isMap(node)) {
    const out = {};
    for (const item of node.items) {
      const key = isScalar(item.key) ? String(item.key.value) : String(item.key);
      out[key] = toPlain(item.value, toLine, doc, seen, state);
    }
    return annotate(out, line);
  }

  if (isSeq(node)) {
    return annotate(node.items.map((item) => toPlain(item, toLine, doc, seen, state)), line);
  }

  if (isScalar(node)) return node.value;
  return null;
}

/**
 * Returns `{ documents: [...] }`. Multi-document is the normal case for
 * Kubernetes manifests, so every caller handles a list and no caller has to
 * remember which formats can contain more than one.
 */
export function parseStructured(source) {
  const toLine = lineIndexer(source);
  let docs;
  try {
    docs = parseAllDocuments(source, { logLevel: 'silent', maxAliasCount: 100 });
  } catch {
    return { documents: [], parseError: true };
  }

  const documents = [];
  for (const doc of docs) {
    // A document with syntax errors is skipped rather than guessed at. Half a
    // parse is how a scanner reports a misconfiguration that is not there.
    if (doc.errors?.length) continue;
    const plain = toPlain(doc.contents, toLine, doc, new Set(), { aliasCount: 0 });
    if (plain !== null) documents.push(plain);
  }
  return { documents, parseError: false };
}
