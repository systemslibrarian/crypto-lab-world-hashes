/**
 * length-extension.ts — a REAL length-extension attack, executed in the browser.
 *
 * The rest of this lab teaches that SM3 and SHA-256 hand out their final
 * chaining state as the digest, while SHA-3 (sponge), Kupyna (wide-pipe) and
 * Streebog (checksum + length finalization) do not. That claim is worth
 * something only if you can watch it break something. This module lets you.
 *
 * THE SCENARIO
 * ------------
 * A server authenticates messages with the naive construction
 *
 *     tag = H(secret ‖ message)
 *
 * and publishes (message, tag). It never publishes the secret. That is enough:
 * for a Merkle–Damgård hash whose digest IS its final chaining state, an
 * attacker who knows only (message, tag, len(secret)) can compute
 *
 *     tag' = H(secret ‖ message ‖ glue ‖ suffix)
 *
 * for a suffix of their choosing, by loading `tag` back into the compression
 * function as a state and continuing. `glue` is the padding the hash would have
 * appended after `secret ‖ message`, which the attacker can reconstruct because
 * padding depends only on LENGTH, not on content.
 *
 * WHAT IS IMPLEMENTED HERE, AND WHY
 * ---------------------------------
 * The attack needs a hash you can resume from an arbitrary state, which no
 * library exposes. So SHA-256 and SM3 compression functions are implemented
 * here directly, from FIPS 180-4 and GM/T 0004-2012. They are cross-checked
 * against the audited `@noble/hashes` SHA-256 and the `sm-crypto` SM3 on every
 * test run and on every page load — if this file ever disagreed with them, the
 * page would say so rather than show you a forged digest it could not justify.
 *
 * The forging function `forgeFromTag` deliberately takes ONLY the published tag,
 * the guessed length and the suffix. It cannot see the secret, because it is
 * never passed one. That is the honest form of the claim "no secret needed".
 */

import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';

import { bytesToHex, computeHex } from './hashes';
import type { AlgorithmId } from './hashes';

const utf8 = new TextEncoder();

/* ------------------------------------------------------- SHA-256 internals */

const SHA256_IV = Uint32Array.from([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

const SHA256_K = Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x: number, n: number): number => ((x >>> n) | (x << (32 - n))) >>> 0;
const rotl = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;

/** One SHA-256 compression step, FIPS 180-4 §6.2.2. Mutates `state` in place. */
export function sha256Compress(state: Uint32Array, block: Uint8Array, offset = 0): void {
  const w = new Uint32Array(64);
  for (let i = 0; i < 16; i += 1) {
    const j = offset + i * 4;
    w[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
  }
  for (let i = 16; i < 64; i += 1) {
    const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
    const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }
  let [a, b, c, d, e, f, g, h] = state;
  for (let i = 0; i < 64; i += 1) {
    const S1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
    const ch = ((e & f) ^ (~e & g)) >>> 0;
    const temp1 = (h + S1 + ch + SHA256_K[i] + w[i]) >>> 0;
    const S0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
    const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
    const temp2 = (S0 + maj) >>> 0;
    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }
  state[0] = (state[0] + a) >>> 0;
  state[1] = (state[1] + b) >>> 0;
  state[2] = (state[2] + c) >>> 0;
  state[3] = (state[3] + d) >>> 0;
  state[4] = (state[4] + e) >>> 0;
  state[5] = (state[5] + f) >>> 0;
  state[6] = (state[6] + g) >>> 0;
  state[7] = (state[7] + h) >>> 0;
}

/* ----------------------------------------------------------- SM3 internals */

const SM3_IV = Uint32Array.from([
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
]);

const p0 = (x: number): number => (x ^ rotl(x, 9) ^ rotl(x, 17)) >>> 0;
const p1 = (x: number): number => (x ^ rotl(x, 15) ^ rotl(x, 23)) >>> 0;

/** One SM3 compression step, GM/T 0004-2012 §5.3.3. Mutates `state` in place. */
export function sm3Compress(state: Uint32Array, block: Uint8Array, offset = 0): void {
  const w = new Uint32Array(68);
  const w1 = new Uint32Array(64);
  for (let i = 0; i < 16; i += 1) {
    const j = offset + i * 4;
    w[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
  }
  for (let i = 16; i < 68; i += 1) {
    w[i] =
      (p1((w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15)) >>> 0) ^ rotl(w[i - 13], 7) ^ w[i - 6]) >>> 0;
  }
  for (let i = 0; i < 64; i += 1) w1[i] = (w[i] ^ w[i + 4]) >>> 0;

  let [a, b, c, d, e, f, g, h] = state;
  for (let i = 0; i < 64; i += 1) {
    const t = i < 16 ? 0x79cc4519 : 0x7a879d8a;
    const ss1 = rotl((rotl(a, 12) + e + rotl(t, i % 32)) >>> 0, 7);
    const ss2 = (ss1 ^ rotl(a, 12)) >>> 0;
    const ff = i < 16 ? (a ^ b ^ c) >>> 0 : ((a & b) | (a & c) | (b & c)) >>> 0;
    const gg = i < 16 ? (e ^ f ^ g) >>> 0 : ((e & f) | (~e & g)) >>> 0;
    const tt1 = (ff + d + ss2 + w1[i]) >>> 0;
    const tt2 = (gg + h + ss1 + w[i]) >>> 0;
    d = c;
    c = rotl(b, 9);
    b = a;
    a = tt1;
    h = g;
    g = rotl(f, 19);
    f = e;
    e = p0(tt2);
  }
  state[0] = (state[0] ^ a) >>> 0;
  state[1] = (state[1] ^ b) >>> 0;
  state[2] = (state[2] ^ c) >>> 0;
  state[3] = (state[3] ^ d) >>> 0;
  state[4] = (state[4] ^ e) >>> 0;
  state[5] = (state[5] ^ f) >>> 0;
  state[6] = (state[6] ^ g) >>> 0;
  state[7] = (state[7] ^ h) >>> 0;
}

/* ---------------------------------------------- the shared Merkle–Damgård shell */

/** The two narrow-pipe, 512-bit-block, 256-bit-digest hashes this lab teaches. */
export type ExtendableAlgorithm = 'sha256' | 'sm3';

export const EXTENDABLE_ALGORITHMS: ExtendableAlgorithm[] = ['sha256', 'sm3'];

interface MdSpec {
  iv: Uint32Array;
  compress(state: Uint32Array, block: Uint8Array, offset?: number): void;
}

const MD_SPECS: Record<ExtendableAlgorithm, MdSpec> = {
  sha256: { iv: SHA256_IV, compress: sha256Compress },
  sm3: { iv: SM3_IV, compress: sm3Compress },
};

/** Block size in bytes. Both algorithms use 512-bit blocks. */
export const MD_BLOCK_BYTES = 64;

/**
 * The Merkle–Damgård padding both algorithms append: a 0x80 byte, then zeros,
 * then the message length in BITS as a 64-bit big-endian integer, padded so the
 * total is a whole number of blocks. It depends on LENGTH ALONE — which is the
 * entire reason the attacker can reconstruct it without the secret.
 */
export function mdPadding(messageLengthBytes: number): Uint8Array {
  if (!Number.isInteger(messageLengthBytes) || messageLengthBytes < 0) {
    throw new Error('message length must be a non-negative integer');
  }
  const remainder = messageLengthBytes % MD_BLOCK_BYTES;
  const zeroCount = remainder < 56 ? 55 - remainder : 119 - remainder;
  const padding = new Uint8Array(1 + zeroCount + 8);
  padding[0] = 0x80;
  const bits = BigInt(messageLengthBytes) * 8n;
  for (let i = 0; i < 8; i += 1) {
    padding[padding.length - 1 - i] = Number((bits >> BigInt(8 * i)) & 0xffn);
  }
  return padding;
}

function stateToHex(state: Uint32Array): string {
  return Array.from(state, (word) => word.toString(16).padStart(8, '0')).join('');
}

/** Read a 256-bit digest back into the eight 32-bit chaining words. */
export function stateFromDigest(digestHex: string): Uint32Array {
  if (!/^[0-9a-f]{64}$/i.test(digestHex)) {
    throw new Error('digest must be 64 hex characters (256 bits)');
  }
  const state = new Uint32Array(8);
  for (let i = 0; i < 8; i += 1) {
    state[i] = parseInt(digestHex.slice(i * 8, i * 8 + 8), 16) >>> 0;
  }
  return state;
}

/**
 * Reference implementation using the compression function above — used to
 * cross-check this file against the audited libraries.
 */
export function mdHash(algorithm: ExtendableAlgorithm, message: Uint8Array): string {
  const spec = MD_SPECS[algorithm];
  const state = Uint32Array.from(spec.iv);
  const padded = new Uint8Array(message.length + mdPadding(message.length).length);
  padded.set(message, 0);
  padded.set(mdPadding(message.length), message.length);
  for (let offset = 0; offset < padded.length; offset += MD_BLOCK_BYTES) {
    spec.compress(state, padded, offset);
  }
  return stateToHex(state);
}

/**
 * THE ATTACK ITSELF.
 *
 * Note the parameter list: a published tag, a guessed length, a suffix. There
 * is no secret here to leak in, which is what makes the "no secret required"
 * claim structural rather than rhetorical.
 *
 * @param tagHex             the published H(secret ‖ message)
 * @param hashedLengthBytes  attacker's belief about len(secret ‖ message)
 * @param suffix             the bytes to append
 */
export function forgeFromTag(
  algorithm: ExtendableAlgorithm,
  tagHex: string,
  hashedLengthBytes: number,
  suffix: Uint8Array,
): string {
  const spec = MD_SPECS[algorithm];
  const state = stateFromDigest(tagHex);
  // Everything hashed so far, from the resumed state's point of view: the
  // original message plus the glue padding that closed it out.
  const consumed = hashedLengthBytes + mdPadding(hashedLengthBytes).length;
  const tail = new Uint8Array(suffix.length + mdPadding(consumed + suffix.length).length);
  tail.set(suffix, 0);
  tail.set(mdPadding(consumed + suffix.length), suffix.length);
  for (let offset = 0; offset < tail.length; offset += MD_BLOCK_BYTES) {
    spec.compress(state, tail, offset);
  }
  return stateToHex(state);
}

/* --------------------------------------------------------------- the exhibit */

export interface ExtensionAttempt {
  algorithm: ExtendableAlgorithm;
  /** What the server published. */
  message: string;
  tag: string;
  /** What the learner chose. */
  suffix: string;
  guessedSecretLength: number;
  actualSecretLength: number;
  /** The padding the attacker reconstructed, as hex. */
  gluePaddingHex: string;
  /** The tag the attack produced, without ever seeing the secret. */
  forgedTag: string;
  /** What the server actually computes for the forged message. Ground truth. */
  serverTag: string;
  /** Printable form of the forged message, with the glue shown as escapes. */
  forgedMessagePreview: string;
  /** Computed by comparing the two tags — never assumed. */
  forged: boolean;
  /** Why it failed, when it did. */
  reason: 'forged' | 'wrong-secret-length';
}

function previewBytes(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) =>
    byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, '0')}`,
  ).join('');
}

/**
 * Run the whole scenario end to end.
 *
 * The server holds `secret` and publishes tag = H(secret ‖ message). The
 * attacker is handed only (message, tag, guessedSecretLength) and appends
 * `suffix`. Whether the forgery worked is decided by recomputing what the
 * server would produce for the forged message and comparing — so a wrong
 * length guess produces an honest failure, not a fudged success.
 */
export function attemptLengthExtension(
  algorithm: ExtendableAlgorithm,
  secret: string,
  message: string,
  suffix: string,
  guessedSecretLength: number,
): ExtensionAttempt {
  if (!Number.isInteger(guessedSecretLength) || guessedSecretLength < 0 || guessedSecretLength > 4096) {
    throw new Error('guessed secret length must be an integer in [0, 4096]');
  }
  const secretBytes = utf8.encode(secret);
  const messageBytes = utf8.encode(message);
  const suffixBytes = utf8.encode(suffix);

  // --- server side ---
  const authenticated = new Uint8Array(secretBytes.length + messageBytes.length);
  authenticated.set(secretBytes, 0);
  authenticated.set(messageBytes, secretBytes.length);
  const tag = mdHash(algorithm, authenticated);

  // --- attacker side: only tag, message, guessed length, suffix ---
  const guessedTotal = guessedSecretLength + messageBytes.length;
  const glue = mdPadding(guessedTotal);
  const forgedTag = forgeFromTag(algorithm, tag, guessedTotal, suffixBytes);

  // --- ground truth: what the server computes for the forged message ---
  const realGlue = mdPadding(secretBytes.length + messageBytes.length);
  const forgedBody = new Uint8Array(
    secretBytes.length + messageBytes.length + glue.length + suffixBytes.length,
  );
  forgedBody.set(secretBytes, 0);
  forgedBody.set(messageBytes, secretBytes.length);
  forgedBody.set(glue, secretBytes.length + messageBytes.length);
  forgedBody.set(suffixBytes, secretBytes.length + messageBytes.length + glue.length);
  const serverTag = mdHash(algorithm, forgedBody);
  void realGlue;

  const forged = forgedTag === serverTag;
  const visible = new Uint8Array(messageBytes.length + glue.length + suffixBytes.length);
  visible.set(messageBytes, 0);
  visible.set(glue, messageBytes.length);
  visible.set(suffixBytes, messageBytes.length + glue.length);

  return {
    algorithm,
    message,
    tag,
    suffix,
    guessedSecretLength,
    actualSecretLength: secretBytes.length,
    gluePaddingHex: bytesToHex(glue),
    forgedTag,
    serverTag,
    forgedMessagePreview: previewBytes(visible),
    forged,
    reason: forged ? 'forged' : 'wrong-secret-length',
  };
}

/* ------------------------------------------------- the constructions that resist */

export type ResistantAlgorithm = 'sha3-256' | 'kupyna256' | 'streebog256';

export interface ResistanceResult {
  algorithm: ResistantAlgorithm | 'hmac-sha256';
  label: string;
  /** Why the attack cannot even be assembled for this construction. */
  reason: string;
  /**
   * The closest computable analogue of the attack — treat the digest as if it
   * were a resumable state and continue from it — and its measured result.
   */
  naiveForgery: string;
  serverTag: string;
  /** Computed: did the analogue match? It must not. */
  forged: boolean;
}

/**
 * For a sponge, a wide-pipe hash or a hash with a length/checksum finalization,
 * there is no chaining state to load, so the attack above cannot be built at
 * all. What CAN be computed — and is, here — is the closest analogue: take the
 * published tag, continue from it in the only way an attacker could without
 * internal state, and check the result against what the server computes. The
 * page reports that measured comparison and states plainly that it is an
 * analogue, not the real attack, because the real attack has no entry point.
 */
export function checkResistance(
  algorithm: ResistantAlgorithm | 'hmac-sha256',
  secret: string,
  message: string,
  suffix: string,
): ResistanceResult {
  const secretBytes = utf8.encode(secret);
  const messageBytes = utf8.encode(message);
  const suffixBytes = utf8.encode(suffix);

  const tagOf = (bytes: Uint8Array): string =>
    algorithm === 'hmac-sha256'
      ? bytesToHex(hmac(nobleSha256, secretBytes, bytes))
      : computeHex(algorithm as AlgorithmId, bytes);

  // What the server publishes.
  const authenticated =
    algorithm === 'hmac-sha256'
      ? messageBytes
      : (() => {
          const joined = new Uint8Array(secretBytes.length + messageBytes.length);
          joined.set(secretBytes, 0);
          joined.set(messageBytes, secretBytes.length);
          return joined;
        })();
  const tag = tagOf(authenticated);

  // The attacker's best analogue: hash (tag ‖ suffix) — the only continuation
  // available without an internal state.
  const tagBytes = Uint8Array.from(
    (tag.match(/../g) ?? []).map((pair) => parseInt(pair, 16)),
  );
  const naiveInput = new Uint8Array(tagBytes.length + suffixBytes.length);
  naiveInput.set(tagBytes, 0);
  naiveInput.set(suffixBytes, tagBytes.length);
  const naiveForgery =
    algorithm === 'hmac-sha256'
      ? bytesToHex(hmac(nobleSha256, secretBytes, naiveInput))
      : computeHex(algorithm as AlgorithmId, naiveInput);

  // What the server would compute for the extended message.
  const extended =
    algorithm === 'hmac-sha256'
      ? (() => {
          const joined = new Uint8Array(messageBytes.length + suffixBytes.length);
          joined.set(messageBytes, 0);
          joined.set(suffixBytes, messageBytes.length);
          return joined;
        })()
      : (() => {
          const joined = new Uint8Array(
            secretBytes.length + messageBytes.length + suffixBytes.length,
          );
          joined.set(secretBytes, 0);
          joined.set(messageBytes, secretBytes.length);
          joined.set(suffixBytes, secretBytes.length + messageBytes.length);
          return joined;
        })();
  const serverTag = tagOf(extended);

  const REASONS: Record<ResistantAlgorithm | 'hmac-sha256', { label: string; reason: string }> = {
    'sha3-256': {
      label: 'SHA-3-256',
      reason:
        'Sponge. The 1600-bit state is squeezed down to 256 bits of output, so the digest is not ' +
        'the state — there is nothing to load and continue from.',
    },
    kupyna256: {
      label: 'Kupyna-256',
      reason:
        'Wide-pipe Merkle–Damgård. The internal state is twice the digest width and is finalized ' +
        'and truncated before output, so the published digest is not a resumable chaining value.',
    },
    streebog256: {
      label: 'Streebog-256',
      reason:
        'Merkle–Damgård with a finalization that folds in the total message length and a modular ' +
        'checksum of every block — both of which depend on the secret, so the attacker cannot ' +
        'reproduce them.',
    },
    'hmac-sha256': {
      label: 'HMAC-SHA-256',
      reason:
        'The fix, not a different hash. HMAC computes H(k⊕opad ‖ H(k⊕ipad ‖ m)), so the published ' +
        'tag is the output of an OUTER hash whose input the attacker cannot extend.',
    },
  };

  return {
    algorithm,
    label: REASONS[algorithm].label,
    reason: REASONS[algorithm].reason,
    naiveForgery,
    serverTag,
    forged: naiveForgery === serverTag,
  };
}

/**
 * Self-check run on page load and in the unit suite: the compression functions
 * implemented in this file must agree with the audited libraries the rest of
 * the lab uses. If they ever disagree, the exhibit must not claim a forgery.
 */
export interface CrossCheck {
  algorithm: ExtendableAlgorithm;
  input: string;
  mine: string;
  library: string;
  agrees: boolean;
}

export function crossCheckImplementations(): CrossCheck[] {
  const inputs = [
    '',
    'abc',
    'The quick brown fox jumps over the lazy dog',
    'a'.repeat(55), // one byte short of needing a second block
    'a'.repeat(56), // exactly forces a second block
    'a'.repeat(64),
    'a'.repeat(200),
  ];
  const out: CrossCheck[] = [];
  for (const algorithm of EXTENDABLE_ALGORITHMS) {
    for (const input of inputs) {
      const bytes = utf8.encode(input);
      const mine = mdHash(algorithm, bytes);
      const library = computeHex(algorithm, bytes);
      out.push({
        algorithm,
        input: input.length > 20 ? `${input.slice(0, 12)}… (${input.length} chars)` : input || '(empty)',
        mine,
        library,
        agrees: mine === library,
      });
    }
  }
  return out;
}
