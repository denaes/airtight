// CVSS 3.1 Base Score Calculator and Vector Parser.
//
// Zero external dependencies: pure Node.js ESM implementation of the
// FIRST.org Common Vulnerability Scoring System v3.1 specification.

// Metric score constants per CVSS 3.1 specification
export const CVSS_METRICS = {
  av: {
    N: 0.85, // Network
    A: 0.62, // Adjacent
    L: 0.55, // Local
    P: 0.20, // Physical
  },
  ac: {
    L: 0.77, // Low
    H: 0.44, // High
  },
  pr: {
    // Unchanged scope
    U: {
      N: 0.85, // None
      L: 0.62, // Low
      H: 0.27, // High
    },
    // Changed scope
    C: {
      N: 0.85, // None
      L: 0.68, // Low
      H: 0.50, // High
    },
  },
  ui: {
    N: 0.85, // None
    R: 0.62, // Required
  },
  s: {
    U: 'U', // Unchanged
    C: 'C', // Changed
  },
  cia: {
    N: 0.0,  // None
    L: 0.22, // Low
    H: 0.56, // High
  },
};

/**
 * CVSS v3.1 Roundup function.
 * Defined as the smallest number, specified to one decimal place, that is
 * greater than or equal to the input.
 *
 * @param {number} input
 * @returns {number}
 */
export function roundup(input) {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/**
 * Calculate CVSS 3.1 base score and qualitative severity rating.
 *
 * @param {Object} metrics
 * @param {'N'|'A'|'L'|'P'} [metrics.av='N'] Attack Vector
 * @param {'L'|'H'} [metrics.ac='L'] Attack Complexity
 * @param {'N'|'L'|'H'} [metrics.pr='N'] Privileges Required
 * @param {'N'|'R'} [metrics.ui='N'] User Interaction
 * @param {'U'|'C'} [metrics.s='U'] Scope
 * @param {'N'|'L'|'H'} [metrics.c='H'] Confidentiality Impact
 * @param {'N'|'L'|'H'} [metrics.i='H'] Integrity Impact
 * @param {'N'|'L'|'H'} [metrics.a='N'] Availability Impact
 * @returns {{
 *   score: number,
 *   severity: 'none'|'low'|'medium'|'high'|'critical',
 *   vector: string,
 *   priority: 'P0'|'P1'|'P2'|'P3',
 *   iss: number,
 *   impact: number,
 *   exploitability: number
 * }}
 */
export function calculateCvss31(metrics = {}) {
  const av = (metrics.av || 'N').toUpperCase();
  const ac = (metrics.ac || 'L').toUpperCase();
  const pr = (metrics.pr || 'N').toUpperCase();
  const ui = (metrics.ui || 'N').toUpperCase();
  const s = (metrics.s || 'U').toUpperCase();
  const c = (metrics.c || 'N').toUpperCase();
  const i = (metrics.i || 'N').toUpperCase();
  const a = (metrics.a || 'N').toUpperCase();

  const avScore = CVSS_METRICS.av[av] ?? 0.85;
  const acScore = CVSS_METRICS.ac[ac] ?? 0.77;
  const prScore = s === 'C' ? (CVSS_METRICS.pr.C[pr] ?? 0.85) : (CVSS_METRICS.pr.U[pr] ?? 0.85);
  const uiScore = CVSS_METRICS.ui[ui] ?? 0.85;

  const cScore = CVSS_METRICS.cia[c] ?? 0.0;
  const iScore = CVSS_METRICS.cia[i] ?? 0.0;
  const aScore = CVSS_METRICS.cia[a] ?? 0.0;

  // Impact Sub-Score (ISS)
  const iss = 1 - (1 - cScore) * (1 - iScore) * (1 - aScore);

  // Impact
  let impact;
  if (s === 'U') {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  // Exploitability
  const exploitability = 8.22 * avScore * acScore * prScore * uiScore;

  // Base Score
  let score = 0;
  if (impact <= 0) {
    score = 0.0;
  } else if (s === 'U') {
    score = roundup(Math.min(impact + exploitability, 10.0));
  } else {
    score = roundup(Math.min(1.08 * (impact + exploitability), 10.0));
  }

  let severity = 'none';
  if (score === 0.0) {
    severity = 'none';
  } else if (score < 4.0) {
    severity = 'low';
  } else if (score < 7.0) {
    severity = 'medium';
  } else if (score < 9.0) {
    severity = 'high';
  } else {
    severity = 'critical';
  }

  const priority = score >= 9.0 ? 'P0' : score >= 7.0 ? 'P1' : score >= 4.0 ? 'P2' : 'P3';
  const vector = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;

  return {
    score,
    severity,
    vector,
    priority,
    iss: Number(iss.toFixed(4)),
    impact: Number(impact.toFixed(4)),
    exploitability: Number(exploitability.toFixed(4)),
  };
}

/**
 * Parse a standard CVSS 3.1 vector string into metrics and calculate score.
 * Example input: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
 *
 * @param {string} vectorStr
 * @returns {ReturnType<typeof calculateCvss31>}
 */
export function parseCvssVector(vectorStr) {
  if (typeof vectorStr !== 'string') {
    throw new TypeError('CVSS vector must be a string');
  }

  const cleaned = vectorStr.trim();
  const parts = cleaned.split('/');

  if (!parts[0].startsWith('CVSS:3.1') && !parts[0].startsWith('CVSS:3.0')) {
    throw new Error(`Unsupported or invalid CVSS vector prefix: '${parts[0]}'. Expected 'CVSS:3.1'`);
  }

  const metrics = {};
  for (let idx = 1; idx < parts.length; idx++) {
    const pair = parts[idx].split(':');
    if (pair.length === 2) {
      const key = pair[0].toLowerCase();
      const val = pair[1].toUpperCase();
      metrics[key] = val;
    }
  }

  const required = ['av', 'ac', 'pr', 'ui', 's', 'c', 'i', 'a'];
  for (const req of required) {
    if (!metrics[req]) {
      throw new Error(`Missing required CVSS metric in vector: '${req.toUpperCase()}'`);
    }
  }

  return calculateCvss31(metrics);
}
