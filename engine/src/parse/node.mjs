// Every structured parser produces plain JS values so rules stay readable, but
// a finding needs a line number. Line provenance therefore rides on a symbol
// property: invisible to JSON.stringify, invisible to rule authors, and
// available to the path resolver when it needs to say where something was.

export const LINE = Symbol('airtight.line');

export function annotate(value, line) {
  if (value !== null && typeof value === 'object') {
    Object.defineProperty(value, LINE, { value: line, enumerable: false, configurable: true });
  }
  return value;
}

export function lineOf(node, fallback = 1) {
  return (node !== null && typeof node === 'object' && node[LINE]) || fallback;
}

/** Build an offset -> 1-indexed line lookup for a source string. */
export function lineIndexer(source) {
  const starts = [0];
  for (let i = 0; i < source.length; i += 1) if (source[i] === '\n') starts.push(i + 1);
  return (offset) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}

/**
 * Scalars cannot carry a symbol, so the resolver returns hits rather than bare
 * values: the value, and the line of the nearest container that knew one.
 */
export function hit(value, line) {
  return { value, line };
}
