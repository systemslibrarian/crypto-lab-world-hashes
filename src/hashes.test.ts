import { describe, expect, it } from 'vitest';

import {
  ALGORITHM_BITS,
  ALGORITHM_LABELS,
  TEST_VECTORS,
  computeHex,
  runSelfTest
} from './hashes';

const utf8 = new TextEncoder();

describe('known-answer test vectors', () => {
  it('has coverage for every algorithm', () => {
    const covered = new Set(TEST_VECTORS.map((v) => v.algorithm));
    expect([...covered].sort()).toEqual(Object.keys(ALGORITHM_LABELS).sort());
  });

  it('holds the 19 vectors the badge counts, algorithm by algorithm', () => {
    // The README's table and the hero badge both describe this list, so the
    // per-algorithm split is pinned here: a vector added to one algorithm has
    // to be added to that table row too, and the badge follows the length.
    const perAlgorithm: Record<string, number> = {};
    for (const vector of TEST_VECTORS) {
      perAlgorithm[vector.algorithm] = (perAlgorithm[vector.algorithm] ?? 0) + 1;
    }
    expect(perAlgorithm).toEqual({
      sm3: 2,
      sha256: 3,
      sha512: 2,
      'sha3-256': 2,
      'sha3-512': 1,
      streebog256: 2,
      streebog512: 2,
      kupyna256: 2,
      kupyna512: 1,
      bash256: 1,
      lsh256: 1
    });
    expect(TEST_VECTORS).toHaveLength(19);
  });

  for (const vector of TEST_VECTORS) {
    it(`${ALGORITHM_LABELS[vector.algorithm]} (${vector.inputLabel}) matches ${vector.source}`, () => {
      const actual = computeHex(vector.algorithm, utf8.encode(vector.input));
      expect(actual).toBe(vector.expected);
    });
  }
});

describe('digest geometry', () => {
  for (const vector of TEST_VECTORS) {
    it(`${ALGORITHM_LABELS[vector.algorithm]} emits ${ALGORITHM_BITS[vector.algorithm]} bits`, () => {
      const digest = computeHex(vector.algorithm, utf8.encode(vector.input));
      expect(digest).toMatch(/^[0-9a-f]+$/);
      expect(digest.length * 4).toBe(ALGORITHM_BITS[vector.algorithm]);
    });
  }
});

describe('runSelfTest', () => {
  it('reports every vector as passing', () => {
    const report = runSelfTest();
    expect(report.total).toBe(TEST_VECTORS.length);
    expect(report.failed).toBe(0);
    expect(report.passed).toBe(report.total);
  });
});

describe('avalanche behaviour', () => {
  it('a one-character edit changes close to half the digest bits', () => {
    // Sanity check that these are real cryptographic hashes: a single-bit-ish
    // input change should diffuse to roughly 50% of output bits.
    const a = computeHex('sha256', utf8.encode('avalanche test message a'));
    const b = computeHex('sha256', utf8.encode('avalanche test message b'));
    let changed = 0;
    for (let i = 0; i < a.length; i += 1) {
      changed += (Number.parseInt(a[i], 16) ^ Number.parseInt(b[i], 16))
        .toString(2)
        .split('')
        .filter((bit) => bit === '1').length;
    }
    const ratio = changed / 256;
    expect(ratio).toBeGreaterThan(0.3);
    expect(ratio).toBeLessThan(0.7);
  });
});

describe('provenance labels say what the standard actually prints', () => {
  it('claims no Streebog vector as a GOST R 34.11-2012 example', () => {
    // GOST R 34.11-2012 / RFC 6986 §10 "Examples (Informative)" gives exactly
    // two: M1 (a 63-byte digit string) and M2 (a Russian sentence). The empty
    // message is not among them, so the two empty-string rows were mislabelled
    // "GOST R 34.11-2012" while the fox rows already disclaimed it.
    const streebog = TEST_VECTORS.filter((v) => v.algorithm.startsWith('streebog'));
    expect(streebog).toHaveLength(4);
    for (const vector of streebog) {
      expect(vector.source, `${vector.algorithm} (${vector.inputLabel})`).toMatch(
        /not in GOST R 34\.11-2012 \/ RFC 6986/,
      );
      expect(vector.source).not.toBe('GOST R 34.11-2012');
    }
  });

  it('keeps the standard-sourced labels for the vectors that really are in a standard', () => {
    const byAlgorithm = (algorithm: string) =>
      TEST_VECTORS.filter((v) => v.algorithm === algorithm).map((v) => v.source);
    expect(byAlgorithm('sha256')).toContain('FIPS 180-4');
    expect(byAlgorithm('sha3-256')).toContain('FIPS 202');
    expect(byAlgorithm('sm3')).toContain('GM/T 0004-2012');
  });
});
