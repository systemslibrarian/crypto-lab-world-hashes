/**
 * Guards on the truncated-collision search.
 *
 * Statistical margin: the number of hashes before a birthday collision has a
 * coefficient of variation near 0.42, so a single run's ratio to the expectation
 * swings widely (0.16 … 1.65 observed). The aggregate is what is asserted. Over
 * eight independent batches of 20 searches at 20 bits, the batch mean ratio ran
 * 0.810 … 1.081, so the [0.5, 1.7] band asserted below carries roughly three
 * times the observed deviation while still failing loudly if the search stopped
 * being a birthday search at all.
 */
import { describe, expect, it } from 'vitest';

import { computeHex } from './hashes';
import type { AlgorithmId } from './hashes';
import {
  MAX_TRUNCATION_BITS,
  MIN_TRUNCATION_BITS,
  collisionVerdict,
  expectedHashes,
  findTruncatedCollision,
  truncateDigest,
} from './collision-search';

const utf8 = new TextEncoder();

describe('truncation', () => {
  it('takes the leading bits, not a whole number of hex characters', () => {
    // 0xff... → first 4 bits = 0xf, first 5 bits = 0b11111 = 31.
    expect(truncateDigest('ff' + '0'.repeat(62), 4)).toBe(0xf);
    expect(truncateDigest('ff' + '0'.repeat(62), 5)).toBe(31);
    expect(truncateDigest('80' + '0'.repeat(62), 1)).toBe(1);
    expect(truncateDigest('00' + '0'.repeat(62), 8)).toBe(0);
    expect(truncateDigest('a5' + '0'.repeat(62), 8)).toBe(0xa5);
  });

  it('rejects widths it cannot represent exactly', () => {
    expect(() => truncateDigest('0'.repeat(64), 0)).toThrow();
    expect(() => truncateDigest('0'.repeat(64), 33)).toThrow();
  });
});

describe('the search', () => {
  const algorithms: AlgorithmId[] = ['sha256', 'sm3', 'sha3-256', 'streebog256', 'kupyna256'];

  it('finds and re-verifies a real collision for every algorithm', () => {
    for (const algorithm of algorithms) {
      const result = findTruncatedCollision(algorithm, 20, 200_000);
      expect(result.found, algorithm).toBe(true);
      expect(result.verified, algorithm).toBe(true);
      // Independently re-verify the reported pair, outside the search.
      const a = computeHex(algorithm, utf8.encode(result.inputA!));
      const b = computeHex(algorithm, utf8.encode(result.inputB!));
      expect(result.inputA).not.toBe(result.inputB);
      expect(a).toBe(result.digestA);
      expect(b).toBe(result.digestB);
      expect(truncateDigest(a, 20)).toBe(truncateDigest(b, 20));
      // The collision is in the truncation only — the real digests differ.
      expect(a).not.toBe(b);
      expect(collisionVerdict(result).kind).toBe('collision');
    }
  });

  it('tracks the birthday expectation in aggregate (25 searches per batch)', () => {
    for (const bits of [16, 20]) {
      const runs = 25;
      let total = 0;
      for (let i = 0; i < runs; i += 1) {
        const result = findTruncatedCollision('sha256', bits, 200_000);
        expect(result.found).toBe(true);
        total += result.ratio!;
      }
      const mean = total / runs;
      expect(mean, `mean ratio at ${bits} bits`).toBeGreaterThan(0.5);
      expect(mean, `mean ratio at ${bits} bits`).toBeLessThan(1.7);
    }
  });

  it('reports an honest failure when the budget is too small', () => {
    const result = findTruncatedCollision('sha256', 32, 50);
    expect(result.found).toBe(false);
    expect(result.hashes).toBe(50);
    expect(result.inputA).toBeNull();
    expect(result.verified).toBe(false);
    const verdict = collisionVerdict(result);
    expect(verdict.kind).toBe('exhausted');
    expect(verdict.detail).toMatch(/proves nothing either way/);
  });

  it('is a fresh search each time, not a replay', () => {
    const a = findTruncatedCollision('sha256', 20, 200_000);
    const b = findTruncatedCollision('sha256', 20, 200_000);
    expect(a.inputA).not.toBe(b.inputA);
  });

  it('rejects widths and budgets outside what it can honestly do', () => {
    expect(() => findTruncatedCollision('sha256', MIN_TRUNCATION_BITS - 1)).toThrow();
    expect(() => findTruncatedCollision('sha256', MAX_TRUNCATION_BITS + 1)).toThrow();
    expect(() => findTruncatedCollision('sha256', 20, 0)).toThrow();
  });
});

describe('the expectation', () => {
  it('is sqrt(pi/2 · 2^n), and doubles for every two bits', () => {
    expect(expectedHashes(16)).toBeCloseTo(Math.sqrt((Math.PI / 2) * 65536), 6);
    expect(expectedHashes(18) / expectedHashes(16)).toBeCloseTo(2, 6);
  });
});
