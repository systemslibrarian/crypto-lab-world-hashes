/**
 * collision-search.ts — a REAL birthday collision search, run in the browser.
 *
 * "Collision-resistant" is the fourth property the intro panel lists, and it is
 * the one a reader has no way to feel: nobody can find a full SHA-256 collision
 * to show you. What they CAN do is truncate the digest to a width small enough
 * to attack, and watch the birthday bound hold — the work scales as 2^(n/2),
 * not 2^n, which is why 128-bit digests were retired and 256-bit ones were not.
 *
 * Everything here is measured. The search hashes real inputs with the same
 * implementations the rest of the lab uses, stops at the first genuine
 * collision, and re-verifies it: the two inputs must differ, their truncated
 * digests must match, and their FULL digests must not. Nothing is asserted.
 */

import { computeHex } from './hashes';
import type { AlgorithmId } from './hashes';

const utf8 = new TextEncoder();

/** Narrowest and widest truncation the exhibit will attempt. */
export const MIN_TRUNCATION_BITS = 8;
/**
 * 32 bits needs about 82,000 hashes on average — a second or two even for the
 * slower pure-JS implementations here. Beyond that the page would hang, so the
 * control stops rather than pretending to offer a search it cannot finish.
 */
export const MAX_TRUNCATION_BITS = 32;

/** Expected number of hashes before a collision: sqrt(pi/2 · 2^n). */
export function expectedHashes(bits: number): number {
  return Math.sqrt((Math.PI / 2) * 2 ** bits);
}

/** The first `bits` bits of a hex digest, as a number (bits <= 32). */
export function truncateDigest(digestHex: string, bits: number): number {
  if (!Number.isInteger(bits) || bits < 1 || bits > 32) {
    throw new Error('truncation width must be an integer in [1, 32]');
  }
  const hexChars = Math.ceil(bits / 4);
  const value = parseInt(digestHex.slice(0, hexChars), 16);
  const excess = hexChars * 4 - bits;
  return value >>> excess;
}

export interface CollisionResult {
  algorithm: AlgorithmId;
  bits: number;
  /** True only if two distinct inputs were found and re-verified. */
  found: boolean;
  /** Hashes actually computed. This is the measurement. */
  hashes: number;
  budget: number;
  elapsedMs: number;
  expected: number;
  /** Measured hashes ÷ the birthday expectation. */
  ratio: number | null;
  inputA: string | null;
  inputB: string | null;
  digestA: string | null;
  digestB: string | null;
  /** The shared truncated prefix, as hex. */
  truncatedHex: string | null;
  /** Re-verified: inputs differ, truncations match, full digests differ. */
  verified: boolean;
}

/**
 * Search for two distinct inputs whose digests agree in their first `bits` bits.
 *
 * Inputs are `<label>-<counter>` strings, so every candidate is distinct by
 * construction and the search cannot fool itself by hashing the same input
 * twice. The label is randomised per run, so repeated runs are independent
 * searches rather than a replay.
 *
 * Returns `found: false` when the budget is exhausted — a real outcome of a
 * real search, which the caller must report as "no collision found" rather than
 * dressing up as anything else.
 */
export function findTruncatedCollision(
  algorithm: AlgorithmId,
  bits: number,
  budget = 400_000,
  label = `wh-${Math.floor(Math.random() * 2 ** 32).toString(36)}`,
): CollisionResult {
  if (!Number.isInteger(bits) || bits < MIN_TRUNCATION_BITS || bits > MAX_TRUNCATION_BITS) {
    throw new Error(`truncation width must be an integer in [${MIN_TRUNCATION_BITS}, ${MAX_TRUNCATION_BITS}]`);
  }
  if (!Number.isInteger(budget) || budget < 1) throw new Error('budget must be a positive integer');

  const started = Date.now();
  const seen = new Map<number, string>();
  const hexChars = Math.ceil(bits / 4);
  let hashes = 0;

  for (let counter = 0; counter < budget; counter += 1) {
    const input = `${label}-${counter}`;
    const digest = computeHex(algorithm, utf8.encode(input));
    hashes += 1;
    const key = truncateDigest(digest, bits);
    const previous = seen.get(key);
    if (previous === undefined) {
      seen.set(key, input);
      continue;
    }
    // Re-verify from scratch before reporting anything as a collision.
    const digestPrev = computeHex(algorithm, utf8.encode(previous));
    const verified =
      previous !== input &&
      truncateDigest(digestPrev, bits) === truncateDigest(digest, bits) &&
      digestPrev !== digest;
    return {
      algorithm,
      bits,
      found: true,
      hashes,
      budget,
      elapsedMs: Date.now() - started,
      expected: expectedHashes(bits),
      ratio: hashes / expectedHashes(bits),
      inputA: previous,
      inputB: input,
      digestA: digestPrev,
      digestB: digest,
      truncatedHex: digest.slice(0, hexChars),
      verified,
    };
  }

  return {
    algorithm,
    bits,
    found: false,
    hashes,
    budget,
    elapsedMs: Date.now() - started,
    expected: expectedHashes(bits),
    ratio: null,
    inputA: null,
    inputB: null,
    digestA: null,
    digestB: null,
    truncatedHex: null,
    verified: false,
  };
}

export interface CollisionVerdict {
  kind: 'collision' | 'unverified' | 'exhausted';
  headline: string;
  detail: string;
}

/** A verdict that states only what this search established. */
export function collisionVerdict(result: CollisionResult): CollisionVerdict {
  if (!result.found) {
    return {
      kind: 'exhausted',
      headline: `No collision in ${result.hashes.toLocaleString()} hashes`,
      detail:
        `The budget of ${result.budget.toLocaleString()} ran out first. The birthday expectation at ` +
        `${result.bits} bits is about ${Math.round(result.expected).toLocaleString()} hashes, so this ` +
        `run proves nothing either way — raise the budget or narrow the truncation.`,
    };
  }
  if (!result.verified) {
    return {
      kind: 'unverified',
      headline: 'A candidate failed re-verification',
      detail:
        'Two inputs matched on the truncated prefix but did not survive the recheck. No collision ' +
        'is claimed from this run.',
    };
  }
  return {
    kind: 'collision',
    headline: `Collision found in ${result.hashes.toLocaleString()} hashes`,
    detail:
      `Two different inputs share the first ${result.bits} bits of their ${result.algorithm} digest, ` +
      `and their full digests differ — both rechecked. The birthday bound predicts about ` +
      `${Math.round(result.expected).toLocaleString()} hashes (√(π/2·2^${result.bits})); this run took ` +
      `${(result.ratio ?? 0).toFixed(2)}× that. Doubling the truncation width squares the search ` +
      `space but only doubles the exponent of the work — which is exactly why a 256-bit digest ` +
      `costs 2^128, not 2^256, to collide.`,
  };
}
