/**
 * Guards on the Bash (STB 34.101.77) implementation.
 *
 * This is the one algorithm in the lab whose sponge is written out here rather
 * than imported, because `@li0ard/bash`'s own wrapper computes the rate wrong
 * and fails 7 of the 11 published vectors (see the header of `bash.ts`). That
 * makes these tests load-bearing in a way the other algorithms' are not: they
 * are the only thing standing between the page and a plausible-looking wrong
 * digest.
 *
 * The rate-boundary cases are the whole point. A sponge with the wrong rate
 * still agrees with the standard on every message shorter than one block —
 * which is why the library's own suite (0, 54 and 127-byte messages) is green.
 */
import { describe, expect, it } from 'vitest';

import {
  BASH_STATE_BYTES,
  BASH_VECTORS,
  bashCapacityBytes,
  bashHash,
  bashRateBytes,
  crossCheckBash,
} from './bash';
import type { BashDigestBytes } from './bash';

const utf8 = new TextEncoder();
const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const SIZES: BashDigestBytes[] = [32, 48, 64];

describe('published vectors from STB 34.101.77 Annex A', () => {
  const checks = crossCheckBash();

  it('covers the permutation and all eleven hash vectors', () => {
    // A.2 plus A.3.1 … A.3.11. Asserted so that a silently shortened vector
    // table cannot make this suite pass by checking less.
    expect(checks).toHaveLength(12);
    expect(BASH_VECTORS).toHaveLength(11);
    expect(checks[0].section).toBe('A.2');
  });

  for (const check of crossCheckBash()) {
    it(`§${check.section} — ${check.label}`, () => {
      expect(check.computed).toBe(check.published);
      expect(check.agrees).toBe(true);
    });
  }

  it('spans the rate boundary in both directions for every digest size', () => {
    // The defect this file exists to avoid only shows at or above the rate, so
    // the vector set has to straddle it rather than merely being long.
    for (const digestBytes of SIZES) {
      const rate = bashRateBytes(digestBytes);
      const lengths = BASH_VECTORS.filter((v) => v.digestBytes === digestBytes).map(
        (v) => v.messageBytes,
      );
      expect(lengths.some((n) => n < rate), `Bash-${digestBytes * 8} below rate`).toBe(true);
      expect(lengths.some((n) => n >= rate), `Bash-${digestBytes * 8} at or above rate`).toBe(true);
      expect(lengths.some((n) => n % rate === 0 && n > 0), `Bash-${digestBytes * 8} exact multiple`)
        .toBe(true);
    }
  });
});

describe('sponge geometry', () => {
  it('splits a fixed 1536-bit state into rate + capacity', () => {
    for (const digestBytes of SIZES) {
      expect(bashRateBytes(digestBytes) + bashCapacityBytes(digestBytes)).toBe(BASH_STATE_BYTES);
    }
  });

  it('gives every variant a capacity of exactly twice its digest', () => {
    for (const digestBytes of SIZES) {
      expect(bashCapacityBytes(digestBytes)).toBe(2 * digestBytes);
    }
  });

  it('withholds most of the state from the digest — the sponge property', () => {
    // 1280 of 1536 bits for Bash-256. This is the number the length-extension
    // exhibit reports, so it is pinned where the construction is defined.
    expect(BASH_STATE_BYTES * 8 - 32 * 8).toBe(1280);
    for (const digestBytes of SIZES) {
      expect(BASH_STATE_BYTES).toBeGreaterThan(digestBytes);
    }
  });

  it('uses the rates the standard defines, not the bundled library’s', () => {
    // 192 − 2 × digest. The library computes 192 − digest/2 and gets 176/168/160.
    expect(bashRateBytes(32)).toBe(128);
    expect(bashRateBytes(48)).toBe(96);
    expect(bashRateBytes(64)).toBe(64);
  });
});

describe('digest shape', () => {
  it('emits the requested width for every variant', () => {
    for (const digestBytes of SIZES) {
      expect(bashHash(digestBytes, utf8.encode('abc'))).toHaveLength(digestBytes);
    }
  });

  it('is deterministic and input-sensitive', () => {
    const a = toHex(bashHash(32, utf8.encode('world hashes')));
    expect(toHex(bashHash(32, utf8.encode('world hashes')))).toBe(a);
    expect(toHex(bashHash(32, utf8.encode('world hashes.')))).not.toBe(a);
  });

  it('keeps every message length around each rate boundary distinct', () => {
    // A wrong rate collapses or shifts blocks; distinct lengths of the same
    // byte would then start colliding. Checked across two full blocks.
    const seen = new Map<string, number>();
    for (let length = 0; length <= 2 * bashRateBytes(32) + 8; length += 1) {
      const digest = toHex(bashHash(32, new Uint8Array(length).fill(0x61)));
      expect(seen.has(digest), `length ${length} collided with ${seen.get(digest)}`).toBe(false);
      seen.set(digest, length);
    }
  });

  it('agrees with an independently published non-Annex-A vector', () => {
    // From the Belarusian OAC conformance-methodology document for
    // STB 34.101.77-2020, via the @li0ard/bash test suite — a second source
    // that is not bee2, so the two do not share a transcription error.
    expect(toHex(bashHash(32, utf8.encode('Fifty four byte or four hundred thirty two bit message')))).toBe(
      '8f866380a7714b539dbc9f3d18020bcaedbd428aecc69f1405699be12c19ed02',
    );
  });
});
