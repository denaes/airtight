import { parseDockerfile } from './dockerfile.mjs';
import { parseStructured } from './structured.mjs';
import { parseHcl } from './hcl.mjs';

const PARSERS = {
  dockerfile: (source) => ({ documents: [parseDockerfile(source)] }),
  yaml: parseStructured,
  json: parseStructured,
  hcl: parseHcl,
};

/**
 * Parse once per (file, tier) and reuse. A Kubernetes manifest can attract
 * twenty rules; parsing it twenty times would make the edit hook miss its
 * five-second budget on a large repo.
 */
export function parseFor(tier, source, cache) {
  if (cache.has(tier)) return cache.get(tier);
  const parser = PARSERS[tier];
  const result = parser ? parser(source) : { documents: [] };
  cache.set(tier, result);
  return result;
}

export const STRUCTURED_TIERS = Object.keys(PARSERS);
