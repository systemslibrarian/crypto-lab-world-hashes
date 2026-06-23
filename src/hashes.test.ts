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
