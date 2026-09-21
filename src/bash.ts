/**
 * bash.ts — Bash (STB 34.101.77), Belarus's national hash standard.
 *
 * WHY THIS FILE EXISTS RATHER THAN A ONE-LINE IMPORT
 * --------------------------------------------------
 * Every other algorithm in this lab is one import from an audited library.
 * Bash is not, and the reason is worth stating plainly because it is the whole
 * justification for the code below.
 *
 * `@li0ard/bash` ships two things: the `bash-f` permutation, and a `Bash` class
 * that wraps it in a sponge. The permutation is correct — it reproduces the
 * 1536-bit test vector in STB 34.101.77 §A.2 exactly, and `crossCheckBash()`
 * re-checks that on every page load and every test run. The sponge wrapper is
 * not: it computes the rate as `192 - outputLen / 2` bytes, which is the
 * standard's `192 - l / 2` with the security level `l` (in BITS) confused for
 * the digest length (in BYTES). The true rate is therefore 128 / 96 / 64 bytes
 * for the 256 / 384 / 512-bit variants, not 176 / 168 / 160. It also XORs each
 * block into the state where the standard overwrites, and copies whole 192-byte
 * buffers where it should copy one rate's worth.
 *
 * None of that is visible on a short message: for a single block the rate never
 * comes into play and XOR-into-zero is the same as overwrite. So the library
 * agrees with the standard on the empty string and on anything shorter than
 * one rate, and disagrees on everything else — it fails 7 of the 11 hash
 * vectors in STB 34.101.77 Annex A. Its own test suite only exercises messages
 * of 0, 54 and 127 bytes, all below the true rate, which is why the defect is
 * still shipping in 0.1.3.
 *
 * A demo whose stated purpose is "real digests only" cannot show a digest that
 * is wrong for any input past 127 bytes, and a "N/N vectors verified" badge
 * must not vouch for one. So the sponge is implemented here, from the standard,
 * over the library's permutation — the same arrangement `length-extension.ts`
 * already uses for SHA-256 and SM3, and for the same reason: the part that has
 * to be inspectable is written out, and the part that is borrowed is pinned
 * against a published vector.
 *
 * THE CONSTRUCTION
 * ----------------
 * Bash is a SPONGE, like SHA-3 and unlike every other hash in this lab. A
 * 1536-bit state is split into a `rate` that the message is written into and a
 * `capacity` that the message never touches and the digest never shows:
 *
 *     state    = 192 bytes (1536 bits), always
 *     capacity = 2 × digest length          (64 / 96 / 128 bytes)
 *     rate     = 192 − capacity             (128 /  96 /  64 bytes)
 *
 * That is the fact the length-extension exhibit turns on. For SHA-256 and SM3
 * the digest IS the entire chaining state, so an attacker can load it back and
 * keep hashing. For Bash, 1280 of the 1536 state bits never appear in a 256-bit
 * digest, so there is nothing to load — see `unexposedStateBits` in
 * `length-extension.ts`, which computes that gap rather than asserting it.
 */

import { BASHF } from '@li0ard/bash';

/** The bash-f state: 1536 bits, for every digest size. */
export const BASH_STATE_BYTES = 192;

/** Digest sizes the standard defines, in bytes (BASH.HASH128/192/256). */
export type BashDigestBytes = 32 | 48 | 64;

/**
 * Sponge rate in bytes — how much message each permutation call absorbs.
 *
 * STB 34.101.77 sets the buffer length to `192 − l / 2` octets for security
 * level `l` bits, and the digest to `l / 4` octets. Written in terms of the
 * digest size that is `192 − 2 × digestBytes`, leaving a capacity of exactly
 * twice the digest — the standard sponge choice.
 */
export function bashRateBytes(digestBytes: BashDigestBytes): number {
  return BASH_STATE_BYTES - 2 * digestBytes;
}

/** Capacity in bytes: the part of the state the message and the digest never touch. */
export function bashCapacityBytes(digestBytes: BashDigestBytes): number {
  return 2 * digestBytes;
}

/**
 * One bash-f application, in place, over the 192-byte state.
 *
 * The library's permutation works on 24 big-endian 64-bit words; this is the
 * byte view the sponge needs. The `bigend` flag is what the library's own
 * `Bash` class passes, and the pairing is pinned by the §A.2 vector in
 * `crossCheckBash()` — if either side of that convention ever changed, the
 * cross-check would fail rather than the page quietly showing wrong digests.
 */
function permute(state: Uint8Array): void {
  const words = new BigUint64Array(BASH_STATE_BYTES / 8);
  const view = new DataView(state.buffer, state.byteOffset, BASH_STATE_BYTES);
  for (let i = 0; i < words.length; i += 1) {
    words[i] = view.getBigUint64(i * 8, false);
  }
  BASHF(words, true);
  for (let i = 0; i < words.length; i += 1) {
    view.setBigUint64(i * 8, words[i], false);
  }
}

/**
 * Bash, per STB 34.101.77 §6.
 *
 * Absorb: the message OVERWRITES the first `rate` bytes of the state (a sponge
 * in overwrite mode — not XOR), permuting each time the rate fills.
 *
 * Pad and squeeze: the remaining rate bytes are zeroed, a single `0x40` byte is
 * written at the position the message stopped at, and the state is permuted one
 * last time. A message whose length is an exact multiple of the rate therefore
 * gets a whole extra padding block, which is the case the bundled library's
 * wrapper also gets wrong.
 *
 * The digest is the first `digestBytes` of the state. The capacity is never
 * read out, and that is the entire reason Bash has nothing to extend from.
 */
export function bashHash(digestBytes: BashDigestBytes, message: Uint8Array): Uint8Array {
  const rate = bashRateBytes(digestBytes);
  const state = new Uint8Array(BASH_STATE_BYTES);
  // s ← 0^{1536−64} ‖ ⟨l / 4⟩_64, little-endian, so one byte carries it.
  state[BASH_STATE_BYTES - 8] = digestBytes;

  let position = 0;
  for (let i = 0; i < message.length; i += 1) {
    state[position] = message[i];
    position += 1;
    if (position === rate) {
      permute(state);
      position = 0;
    }
  }

  state.fill(0, position, rate);
  state[position] = 0x40;
  permute(state);

  return state.slice(0, digestBytes);
}

/** Bash-256 (BASH.HASH128) — the 256-bit variant this lab compares. */
export function bash256(message: Uint8Array): Uint8Array {
  return bashHash(32, message);
}

/* ------------------------------------------------ the published-vector check */

/**
 * The 192-byte test string every Bash vector in STB 34.101.77 Annex A is a
 * prefix of. It is the standard Belarusian test data from STB 34.101.31 (belt),
 * reproduced in the bee2 reference implementation as `beltH()`.
 */
const BELT_H_192 =
  'b194bac80a08f53b366d008e584a5de48504fa9d1bb6c7ac252e72c202fdce0d' +
  '5be3d61217b96181fe6786ad716b890b5cb0c0ff33c356b835c405aed8e07f99' +
  'e12bdc1ae28257ec703fccf095ee8df1c1ab76389fe678caf7c6f860d5bb9c4f' +
  'f33c657b637c306add4ea7799eb23d313e98b56e27d3bccf591e181f4c5ab793' +
  'e9dee72c8f0c0fa62ddb49f46f73964706075316ed247a3739cba38303a98bf6' +
  '92bd9b1ce5d141015445fbc95e4d0ef2682080aa227d642f2687f93490405511';

export interface BashVector {
  /** The clause of STB 34.101.77 Annex A the vector is stated in. */
  section: string;
  digestBytes: BashDigestBytes;
  /** Message length in bytes — the message is that prefix of the belt test data. */
  messageBytes: number;
  expected: string;
}

/**
 * Every hash vector in STB 34.101.77 Annex A (A.3.1 … A.3.11), transcribed from
 * the bee2 reference implementation's `bashTest()` (`test/crypto/bash_test.c`,
 * "Тесты из приложения А к СТБ 34.101.77").
 *
 * The lab's KAT badge pins the empty-message one, A.3.1, because that is the
 * vector whose input is expressible as the UTF-8 text the badge table shows.
 * The other ten have binary inputs and are checked here instead — which matters
 * more than it looks: A.3.1 is a single-block message, and it is exactly the
 * kind of vector that passes against a sponge with the wrong rate.
 */
export const BASH_VECTORS: BashVector[] = [
  { section: 'A.3.1', digestBytes: 32, messageBytes: 0, expected: '114c3dfae373d9bcbc3602d6386f2d6a2059ba1bf9048dbaa5146a6cb775709d' },
  { section: 'A.3.2', digestBytes: 32, messageBytes: 127, expected: '3d7f4efa00e9ba33feed259986567dcf5c6d12d51057a968f14f06cc0f905961' },
  { section: 'A.3.3', digestBytes: 32, messageBytes: 128, expected: 'd7f428311254b8b2d00f7f9eefbd8f3025fa87c4babd1bddbe87e35b7ac80dd6' },
  { section: 'A.3.4', digestBytes: 32, messageBytes: 135, expected: '1393fa1b65172f2d18946aeae576fa1cf54fdd354a0cb2974a997dc4865d3100' },
  { section: 'A.3.5', digestBytes: 48, messageBytes: 95, expected: '64334af830d33f63e9acdfa184e32522103fff5c6860110a2cd369edbc04387c501d8f92f749ae4de15a8305c353d64d' },
  { section: 'A.3.6', digestBytes: 48, messageBytes: 96, expected: 'd06efbc16fd6c0880cbfc6a4e3d65ab101fa82826934190faabebfbffede93b22b85ea72a7fb3147a133a5a8febd8320' },
  { section: 'A.3.7', digestBytes: 48, messageBytes: 108, expected: 'ff763296571e2377e71a1538070cc0de88888606f32eee6b082788d246686b00fc05a17405c5517699da44b7ef5f55ab' },
  { section: 'A.3.8', digestBytes: 64, messageBytes: 63, expected: '2a66c87c189c12e255239406123bdedbf19955eaf0808b2ad705e249220845e20f4786fb6765d0b5c48984b1b16556ef19ea8192b985e4233d9c09508d6339e7' },
  { section: 'A.3.9', digestBytes: 64, messageBytes: 64, expected: '07abbf8580e7e5a321e9b940f667ae209e2952cef557978ae743db086bab4885b708233c3f5541df8aafc3611482fde498e58b3379a6622dac2664c9c118a162' },
  { section: 'A.3.10', digestBytes: 64, messageBytes: 127, expected: '526073918f97928e9d15508385f42f03ade3211a23900a30131f8a1e3e1ee21cc09d13cff6981101235d895746a4643f0aa62b0a7bc98a269e4507a257f0d4ee' },
  { section: 'A.3.11', digestBytes: 64, messageBytes: 192, expected: '8724c7ff8a2a83f22e38cb9763777b96a70aba3444f214c763d93cd6d19fcfde6c3d3931857c4ff6cccd49bd99852fe9eaa7495eccdd96b571e0edcf47f89768' },
];

/**
 * The bash-f permutation applied to the belt test data, STB 34.101.77 §A.2.
 * This pins the borrowed permutation itself, separately from the sponge built
 * on it, so a failure says which half moved.
 */
const BASH_F_A2 =
  '8fe727775ea7f140b95bb6a200cbb28c7f0809c0c0bc68b7dc5aedc841bd94e4' +
  '03630c301fc255df5b67db53ef65e376e8a4d797a6172f2271ba48093173d329' +
  'c3502ac946767326a2891971392d3f7089959f5d61621238655975e00e2132a0' +
  'd5018ceedb17731ccd88fc50151d37c0d4a3359506aedc2e6109511e7703afbb' +
  '014642348d8568aa1a5d9868c4c7e6dfa756b1690c7c2608a2dc136f5997ab8f' +
  'bb3f4d9f033c87ca6070e117f099c4094972acd9d976214b7ced8e3f8b6e058e';

function hexToBytes(hex: string): Uint8Array {
  const pairs = hex.match(/../g) ?? [];
  return Uint8Array.from(pairs, (pair) => Number.parseInt(pair, 16));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export interface BashCheck {
  /** Which clause of the standard this row is. */
  section: string;
  label: string;
  computed: string;
  published: string;
  agrees: boolean;
}

/**
 * Recompute every published Bash vector — the §A.2 permutation and all eleven
 * §A.3 hash vectors — against this module.
 *
 * Runs in the unit suite and on every page load, for the same reason
 * `crossCheckImplementations()` does: this lab hand-rolls a primitive, so it
 * owes the reader a live check rather than a promise. The eleven §A.3 vectors
 * are the ones that matter, because they span the rate boundary in both
 * directions for all three digest sizes — the exact place the bundled library's
 * own sponge goes wrong.
 */
export function crossCheckBash(): BashCheck[] {
  const data = hexToBytes(BELT_H_192);
  const out: BashCheck[] = [];

  const permuted = data.slice(0, BASH_STATE_BYTES);
  permute(permuted);
  out.push({
    section: 'A.2',
    label: 'bash-f permutation (1536-bit state)',
    computed: toHex(permuted),
    published: BASH_F_A2,
    agrees: toHex(permuted) === BASH_F_A2,
  });

  for (const vector of BASH_VECTORS) {
    const computed = toHex(bashHash(vector.digestBytes, data.slice(0, vector.messageBytes)));
    out.push({
      section: vector.section,
      label: `Bash-${vector.digestBytes * 8}, ${vector.messageBytes}-byte message`,
      computed,
      published: vector.expected,
      agrees: computed === vector.expected,
    });
  }

  return out;
}
