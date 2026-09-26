// Secret redaction.
//
// Redaction is enforced here, in the engine, and never at the renderer. A rule
// marked `redact: true` registers its matched value with the scan's vault; the
// vault then scrubs every byte of output on the way out, so a secret cannot
// reach stdout through a path someone forgot to cover. This inverts impeccable,
// whose hook deliberately skips .env and *.pem — we have to read exactly those
// files, so the containment has to be unconditional.

import { createHash } from 'node:crypto';

export function fingerprint(value) {
  return createHash('sha256').update(value).digest('hex').slice(0, 6);
}

/**
 * A redacted value keeps its leading provider marker (so `AKIA` still tells you
 * it is an AWS key), its length, and a short non-reversible fingerprint. The
 * fingerprint is what lets the findings store correlate the same credential
 * across files and runs without ever holding the credential.
 */
export function redactValue(value) {
  const fp = fingerprint(value);
  const prefix = value.length >= 12 ? value.slice(0, 4) : '';
  return prefix
    ? `${prefix}…[redacted len=${value.length} fp=${fp}]`
    : `[redacted len=${value.length} fp=${fp}]`;
}

export function createVault() {
  /** @type {Map<string, string>} raw value -> redacted display */
  const entries = new Map();

  return {
    /** Register a secret and get its display form. Idempotent. */
    register(value) {
      if (!value) return '';
      let display = entries.get(value);
      if (!display) {
        display = redactValue(value);
        entries.set(value, display);
      }
      return display;
    },

    /**
     * Replace every registered secret anywhere in `text`. Longest first, so a
     * value that contains a shorter registered value is not partially masked
     * into something unrecognizable.
     */
    scrub(text) {
      if (typeof text !== 'string' || entries.size === 0) return text;
      let out = text;
      const values = [...entries.keys()].sort((a, b) => b.length - a.length);
      for (const value of values) out = out.split(value).join(entries.get(value));
      return out;
    },

    /** Recursively scrub an object destined for JSON output. */
    scrubDeep(node) {
      if (typeof node === 'string') return this.scrub(node);
      if (Array.isArray(node)) return node.map((n) => this.scrubDeep(n));
      if (node && typeof node === 'object') {
        const out = {};
        for (const [k, v] of Object.entries(node)) out[k] = this.scrubDeep(v);
        return out;
      }
      return node;
    },

    get size() { return entries.size; },
  };
}
