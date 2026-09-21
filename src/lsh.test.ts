/**
 * Guards on the LSH (KS X 3262) implementation.
 *
 * LSH is the second hand-rolled primitive in this lab, and the more exposed of
 * the two: Bash at least had a library shipping a correct `bash-f` permutation
 * to borrow, whereas there is no LSH on npm at all. Every constant and every
 * step here was transcribed, so these tests are the only thing standing between
 * the page and a plausible-looking wrong digest.
 *
 * The two independent directions matter more than the count. The `"abc"`
 * vectors are published references that do not come from Crypto++; the rest
 * come from Crypto++'s LSH test data, which derives from KISA's own
 * specification and source. A transcription error would have to be reproduced
 * identically by both to survive.
 */
import { describe, expect, it } from 'vitest';

import {
  LSH256_BLOCK_BYTES,
  LSH256_CV_BITS,
  LSH_VECTORS,
  crossCheckLsh,
  lsh256,
  lshHash,
} from './lsh';

const utf8 = new TextEncoder();
const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

describe('published LSH vectors', () => {
  const checks = crossCheckLsh();

  it('ships a vector table that is fully populated', () => {
    // A vector carrying an empty `expected` would pass nothing while looking
    // like coverage. This caught a real placeholder left in during authoring.
    expect(LSH_VECTORS.length).toBeGreaterThanOrEqual(12);
    for (const vector of LSH_VECTORS) {
      expect(vector.expected, vector.label).toMatch(/^[0-9a-f]{56}$|^[0-9a-f]{64}$/);
      expect(vector.expected.length / 2, vector.label).toBe(vector.digestBytes);
    }
  });

  it('draws on two independent sources, not one', () => {
    const sources = new Set(LSH_VECTORS.map((v) => v.source));
    expect(sources.size).toBeGreaterThanOrEqual(2);
    // The published "abc" digests are the ones not derived from Crypto++.
    expect(LSH_VECTORS.filter((v) => v.source === 'published LSH reference value')).toHaveLength(2);
  });

  for (const check of crossCheckLsh()) {
    it(`${check.label} — ${check.source}`, () => {
      expect(check.computed).toBe(check.published);
      expect(check.agrees).toBe(true);
    });
  }

  it('reports every vector as agreeing', () => {
    expect(checks.every((c) => c.agrees)).toBe(true);
  });
});

describe('block-boundary coverage', () => {
  it('spans the 128-byte block in both directions, for both widths', () => {
    for (const digestBytes of [28, 32] as const) {
      const lengths = LSH_VECTORS.filter((v) => v.digestBytes === digestBytes).map((v) =>
        v.message.kind === 'zeros'
          ? v.message.length
          : v.message.kind === 'hex'
            ? v.message.value.length / 2
            : utf8.encode(v.message.value).length,
      );
      expect(lengths.some((n) => n < LSH256_BLOCK_BYTES), `${digestBytes} below`).toBe(true);
      expect(lengths.some((n) => n >= LSH256_BLOCK_BYTES), `${digestBytes} at or above`).toBe(true);
      // An exact multiple forces a whole extra padding block — the case an
      // implementation is most likely to get wrong, and the one that broke the
      // bundled Bash library this lab had to replace.
      expect(
        lengths.some((n) => n > 0 && n % LSH256_BLOCK_BYTES === 0),
        `${digestBytes} exact multiple`,
      ).toBe(true);
    }
  });

  it('gives a message that exactly fills a block a different digest from one byte less', () => {
    const full = toHex(lsh256(new Uint8Array(LSH256_BLOCK_BYTES)));
    const short = toHex(lsh256(new Uint8Array(LSH256_BLOCK_BYTES - 1)));
    expect(full).not.toBe(short);
  });

  it('keeps every length across two blocks distinct', () => {
    const seen = new Map<string, number>();
    for (let length = 0; length <= 2 * LSH256_BLOCK_BYTES + 4; length += 1) {
      const digest = toHex(lsh256(new Uint8Array(length).fill(0x61)));
      expect(seen.has(digest), `length ${length} collided with ${seen.get(digest)}`).toBe(false);
      seen.set(digest, length);
    }
  });
});

describe('wide-pipe geometry', () => {
  it('folds a 512-bit chaining variable down to a 256-bit digest', () => {
    expect(LSH256_CV_BITS).toBe(512);
    expect(lsh256(utf8.encode('x'))).toHaveLength(32);
    // Half the state never reaches the digest. That gap is what the
    // length-extension exhibit reports for LSH.
    expect(LSH256_CV_BITS - 32 * 8).toBe(256);
  });

  it('emits the requested width for both variants', () => {
    expect(lshHash(28, utf8.encode('abc'))).toHaveLength(28);
    expect(lshHash(32, utf8.encode('abc'))).toHaveLength(32);
  });

  it('truncates rather than recomputing: LSH-224 is not a prefix of LSH-256', () => {
    // Different IVs, so the 224 digest must NOT be the 256 digest cut short.
    const a = toHex(lshHash(28, utf8.encode('abc')));
    const b = toHex(lshHash(32, utf8.encode('abc'))).slice(0, 56);
    expect(a).not.toBe(b);
  });
});

describe('digest shape', () => {
  it('is deterministic and input-sensitive', () => {
    const a = toHex(lsh256(utf8.encode('world hashes')));
    expect(toHex(lsh256(utf8.encode('world hashes')))).toBe(a);
    expect(toHex(lsh256(utf8.encode('world hashes.')))).not.toBe(a);
  });

  it('diffuses about half the output bits on a one-character change', () => {
    const a = toHex(lsh256(utf8.encode('avalanche test message a')));
    const b = toHex(lsh256(utf8.encode('avalanche test message b')));
    let changed = 0;
    for (let i = 0; i < a.length; i += 1) {
      const diff = Number.parseInt(a[i], 16) ^ Number.parseInt(b[i], 16);
      changed += ((diff & 1) ? 1 : 0) + ((diff & 2) ? 1 : 0) + ((diff & 4) ? 1 : 0) + ((diff & 8) ? 1 : 0);
    }
    const ratio = changed / 256;
    expect(ratio).toBeGreaterThan(0.3);
    expect(ratio).toBeLessThan(0.7);
  });
});
