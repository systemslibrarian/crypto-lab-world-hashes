/**
 * lsh.ts — LSH (KS X 3262), South Korea's national hash standard.
 *
 * LSH-256 is a WIDE-PIPE design, and the third construction family this lab
 * teaches. It keeps a 512-bit chaining variable in two halves, absorbs a
 * 1024-bit message block, runs 26 steps, and then folds the two halves
 * together — `cv_l[i] ^ cv_r[i]` — to produce a 256-bit digest. That fold is an
 * output transformation in the Kupyna sense: half the state never leaves the
 * function, so there is nothing for a length-extension attack to resume from.
 *
 * Two details are worth knowing because they are unusual:
 *
 *   - **No length padding.** LSH appends a single `0x80` byte and zero-fills to
 *     the block; it encodes no message length at all. SHA-256, SM3 and Streebog
 *     all bind the length in. LSH relies entirely on the wide pipe instead.
 *   - **A message that is an exact multiple of the 128-byte block still gets a
 *     whole extra padding block.** That is the case an implementation is most
 *     likely to get wrong, so the vector table below covers it at 128, 256,
 *     384 and 512 bytes rather than stopping below one block.
 *
 * WHERE THIS COMES FROM, AND HOW IT IS CHECKED
 * --------------------------------------------
 * There is no LSH implementation on npm — the packages named "lsh" are all
 * locality-sensitive hashing, a different thing entirely — so this is written
 * from the algorithm as published by KISA. The constants and the step structure
 * are transcribed from Crypto++'s `lsh256.cpp`, which states it is "Based on
 * the specification and source code provided by Korea Internet & Security
 * Agency (KISA)".
 *
 * Transcription is exactly where a hand-rolled primitive goes wrong, so it is
 * checked two independent ways, both re-run on every page load and every test
 * run by `crossCheckLsh()`:
 *
 *   1. Against the published `"abc"` reference digests for LSH-256-256 and
 *      LSH-256-224 — values published independently of Crypto++.
 *   2. Against vectors from Crypto++'s own LSH test data, chosen to straddle
 *      the 128-byte block boundary in both directions for both digest widths.
 *
 * During development the full Crypto++ set — 294 vectors across LSH-224 and
 * LSH-256, messages from 0 to 65,536 bytes — was run against this file and all
 * 294 matched. The subset embedded here is what ships, so the page can re-check
 * its own arithmetic in the browser without carrying a 300-vector table.
 */

/** LSH-256 message block: 1024 bits. */
export const LSH256_BLOCK_BYTES = 128;

/** The chaining variable: 16 words of 32 bits, held as two halves of 8. */
export const LSH256_CV_BITS = 512;

/** Steps per compression. */
const NUM_STEPS = 26;

/** Rotation amounts: alpha/beta for even and odd steps. */
const ROT_EVEN_ALPHA = 29;
const ROT_EVEN_BETA = 1;
const ROT_ODD_ALPHA = 5;
const ROT_ODD_BETA = 17;

/** Per-word rotation applied to the right half after each mix. */
const GAMMA = [0, 8, 16, 24, 24, 16, 8, 0];

const IV256 = Uint32Array.from([
  0x46a10f1f, 0xfddce486, 0xb41443a8, 0x198e6b9d, 0x3304388d, 0xb0f5a3c7, 0xb36061c4, 0x7adbd553,
  0x105d5378, 0x2f74de54, 0x5c2f2d95, 0xf2553fbe, 0x8051357a, 0x138668c8, 0x47aa4484, 0xe01afb41,
]);

const IV224 = Uint32Array.from([
  0x068608d3, 0x62d8f7a7, 0xd76652ab, 0x4c600a43, 0xbdc40aa8, 0x1eca0b68, 0xda1a89be, 0x3147d354,
  0x707eb4f9, 0xf65b3862, 0x6b0b2abe, 0x56b8ec0a, 0xcf237286, 0xee0d1727, 0x33636595, 0x8bb8d05f,
]);

/** 8 constants per step, 26 steps. */
const STEP_CONSTANTS = Uint32Array.from([
  0x917caf90, 0x6c1b10a2, 0x6f352943, 0xcf778243, 0x2ceb7472, 0x29e96ff2, 0x8a9ba428, 0x2eeb2642,
  0x0e2c4021, 0x872bb30e, 0xa45e6cb2, 0x46f9c612, 0x185fe69e, 0x1359621b, 0x263fccb2, 0x1a116870,
  0x3a6c612f, 0xb2dec195, 0x02cb1f56, 0x40bfd858, 0x784684b6, 0x6cbb7d2e, 0x660c7ed8, 0x2b79d88a,
  0xa6cd9069, 0x91a05747, 0xcdea7558, 0x00983098, 0xbecb3b2e, 0x2838ab9a, 0x728b573e, 0xa55262b5,
  0x745dfa0f, 0x31f79ed8, 0xb85fce25, 0x98c8c898, 0x8a0669ec, 0x60e445c2, 0xfde295b0, 0xf7b5185a,
  0xd2580983, 0x29967709, 0x182df3dd, 0x61916130, 0x90705676, 0x452a0822, 0xe07846ad, 0xaccd7351,
  0x2a618d55, 0xc00d8032, 0x4621d0f5, 0xf2f29191, 0x00c6cd06, 0x6f322a67, 0x58bef48d, 0x7a40c4fd,
  0x8beee27f, 0xcd8db2f2, 0x67f2c63b, 0xe5842383, 0xc793d306, 0xa15c91d6, 0x17b381e5, 0xbb05c277,
  0x7ad1620a, 0x5b40a5bf, 0x5ab901a2, 0x69a7a768, 0x5b66d9cd, 0xfdee6877, 0xcb3566fc, 0xc0c83a32,
  0x4c336c84, 0x9be6651a, 0x13baa3fc, 0x114f0fd1, 0xc240a728, 0xec56e074, 0x009c63c7, 0x89026cf2,
  0x7f9ff0d0, 0x824b7fb5, 0xce5ea00f, 0x605ee0e2, 0x02e7cfea, 0x43375560, 0x9d002ac7, 0x8b6f5f7b,
  0x1f90c14f, 0xcdcb3537, 0x2cfeafdd, 0xbf3fc342, 0xeab7b9ec, 0x7a8cb5a3, 0x9d2af264, 0xfacedb06,
  0xb052106e, 0x99006d04, 0x2bae8d09, 0xff030601, 0xa271a6d6, 0x0742591d, 0xc81d5701, 0xc9a9e200,
  0x02627f1e, 0x996d719d, 0xda3b9634, 0x02090800, 0x14187d78, 0x499b7624, 0xe57458c9, 0x738be2c9,
  0x64e19d20, 0x06df0f36, 0x15d1cb0e, 0x0b110802, 0x2c95f58c, 0xe5119a6d, 0x59cd22ae, 0xff6eac3c,
  0x467ebd84, 0xe5ee453c, 0xe79cd923, 0x1c190a0d, 0xc28b81b8, 0xf6ac0852, 0x26efd107, 0x6e1ae93b,
  0xc53c41ca, 0xd4338221, 0x8475fd0a, 0x35231729, 0x4e0d3a7a, 0xa2b45b48, 0x16c0d82d, 0x890424a9,
  0x017e0c8f, 0x07b5a3f5, 0xfa73078e, 0x583a405e, 0x5b47b4c8, 0x570fa3ea, 0xd7990543, 0x8d28ce32,
  0x7f8a9b90, 0xbd5998fc, 0x6d7a9688, 0x927a9eb6, 0xa2fc7d23, 0x66b38e41, 0x709e491a, 0xb5f700bf,
  0x0a262c0f, 0x16f295b9, 0xe8111ef5, 0x0d195548, 0x9f79a0c5, 0x1a41cfa7, 0x0ee7638a, 0xacf7c074,
  0x30523b19, 0x09884ecf, 0xf93014dd, 0x266e9d55, 0x191a6664, 0x5c1176c1, 0xf64aed98, 0xa4b83520,
  0x828d5449, 0x91d71dd8, 0x2944f2d6, 0x950bf27b, 0x3380ca7d, 0x6d88381d, 0x4138868e, 0x5ced55c4,
  0x0fe19dcb, 0x68f4f669, 0x6e37c8ff, 0xa0fe6e10, 0xb44b47b0, 0xf5c0558a, 0x79bf14cf, 0x4a431a20,
  0xf17f68da, 0x5deb5fd1, 0xa600c86d, 0x9f6c7eb0, 0xff92f864, 0xb615e07f, 0x38d3e448, 0x8d5d3a6a,
  0x70e843cb, 0x494b312e, 0xa6c93613, 0x0beb2f4f, 0x928b5d63, 0xcbf66035, 0x0cb82c80, 0xea97a4f7,
  0x592c0f3b, 0x947c5f77, 0x6fff49b9, 0xf71a7e5a, 0x1de8c0f5, 0xc2569600, 0xc4e4ac8c, 0x823c9ce1,
]);

/** Digest widths the 256-bit family defines, in bytes. */
export type LshDigestBytes = 28 | 32;

const rotl = (x: number, n: number): number =>
  n === 0 ? x >>> 0 : (((x << n) | (x >>> (32 - n))) >>> 0);

/**
 * One compression: absorb a 128-byte block into the 512-bit chaining variable.
 *
 * The block is read as 32 little-endian 32-bit words and split into four
 * sub-messages — even/odd × left/right. Even and odd steps alternate, each
 * XOR-ing its sub-message into the state, mixing, and permuting the words.
 * From step 2 onward the sub-messages are re-derived by the expansion below
 * rather than re-read, which is what lets 26 steps run off one block.
 */
function compress(cvL: Uint32Array, cvR: Uint32Array, block: Uint8Array, offset: number): void {
  const eL = new Uint32Array(8);
  const eR = new Uint32Array(8);
  const oL = new Uint32Array(8);
  const oR = new Uint32Array(8);
  const view = new DataView(block.buffer, block.byteOffset + offset, LSH256_BLOCK_BYTES);
  for (let i = 0; i < 8; i += 1) {
    eL[i] = view.getUint32(i * 4, true);
    eR[i] = view.getUint32(32 + i * 4, true);
    oL[i] = view.getUint32(64 + i * 4, true);
    oR[i] = view.getUint32(96 + i * 4, true);
  }

  // Message expansion: each half is rebuilt from itself and its counterpart.
  const expand = (target: Uint32Array, other: Uint32Array): void => {
    let t = target[0];
    target[0] = (other[0] + target[3]) >>> 0;
    target[3] = (other[3] + target[1]) >>> 0;
    target[1] = (other[1] + target[2]) >>> 0;
    target[2] = (other[2] + t) >>> 0;
    t = target[4];
    target[4] = (other[4] + target[7]) >>> 0;
    target[7] = (other[7] + target[6]) >>> 0;
    target[6] = (other[6] + target[5]) >>> 0;
    target[5] = (other[5] + t) >>> 0;
  };

  const addMsg = (left: Uint32Array, right: Uint32Array): void => {
    for (let i = 0; i < 8; i += 1) {
      cvL[i] = (cvL[i] ^ left[i]) >>> 0;
      cvR[i] = (cvR[i] ^ right[i]) >>> 0;
    }
  };

  const mix = (alpha: number, beta: number, sc: number): void => {
    for (let i = 0; i < 8; i += 1) cvL[i] = (cvL[i] + cvR[i]) >>> 0;
    for (let i = 0; i < 8; i += 1) cvL[i] = rotl(cvL[i], alpha);
    for (let i = 0; i < 8; i += 1) cvL[i] = (cvL[i] ^ STEP_CONSTANTS[sc + i]) >>> 0;
    for (let i = 0; i < 8; i += 1) cvR[i] = (cvR[i] + cvL[i]) >>> 0;
    for (let i = 0; i < 8; i += 1) cvR[i] = rotl(cvR[i], beta);
    for (let i = 0; i < 8; i += 1) cvL[i] = (cvL[i] + cvR[i]) >>> 0;
    for (let i = 1; i < 7; i += 1) cvR[i] = rotl(cvR[i], GAMMA[i]);
  };

  const wordPerm = (): void => {
    let t = cvL[0];
    cvL[0] = cvL[6];
    cvL[6] = cvR[6];
    cvR[6] = cvR[2];
    cvR[2] = cvL[1];
    cvL[1] = cvL[4];
    cvL[4] = cvR[4];
    cvR[4] = cvR[0];
    cvR[0] = cvL[2];
    cvL[2] = cvL[5];
    cvL[5] = cvR[7];
    cvR[7] = cvR[1];
    cvR[1] = t;
    t = cvL[3];
    cvL[3] = cvL[7];
    cvL[7] = cvR[5];
    cvR[5] = cvR[3];
    cvR[3] = t;
  };

  addMsg(eL, eR);
  mix(ROT_EVEN_ALPHA, ROT_EVEN_BETA, 0);
  wordPerm();
  addMsg(oL, oR);
  mix(ROT_ODD_ALPHA, ROT_ODD_BETA, 8);
  wordPerm();

  for (let i = 1; i < NUM_STEPS / 2; i += 1) {
    expand(eL, oL);
    expand(eR, oR);
    addMsg(eL, eR);
    mix(ROT_EVEN_ALPHA, ROT_EVEN_BETA, 16 * i);
    wordPerm();

    expand(oL, eL);
    expand(oR, eR);
    addMsg(oL, oR);
    mix(ROT_ODD_ALPHA, ROT_ODD_BETA, 16 * i + 8);
    wordPerm();
  }

  // The final half-step adds the message but neither mixes nor permutes.
  expand(eL, oL);
  expand(eR, oR);
  addMsg(eL, eR);
}

/**
 * LSH-256, per KS X 3262.
 *
 * Padding is a single `0x80` byte then zeros to the end of the block, with NO
 * length encoded — so a message that exactly fills a block gets an entire extra
 * block of padding. The digest is the XOR-fold of the two 256-bit halves of the
 * chaining variable, serialized little-endian and truncated to `digestBytes`.
 */
export function lshHash(digestBytes: LshDigestBytes, message: Uint8Array): Uint8Array {
  const iv = digestBytes === 28 ? IV224 : IV256;
  const cvL = Uint32Array.from(iv.subarray(0, 8));
  const cvR = Uint32Array.from(iv.subarray(8, 16));

  let offset = 0;
  while (message.length - offset >= LSH256_BLOCK_BYTES) {
    compress(cvL, cvR, message, offset);
    offset += LSH256_BLOCK_BYTES;
  }

  const last = new Uint8Array(LSH256_BLOCK_BYTES);
  last.set(message.subarray(offset), 0);
  last[message.length - offset] = 0x80;
  compress(cvL, cvR, last, 0);

  // The fold: 512 bits of state down to 256 bits of output. Half the state
  // never appears in the digest, which is why LSH resists length extension.
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  for (let i = 0; i < 8; i += 1) {
    outView.setUint32(i * 4, (cvL[i] ^ cvR[i]) >>> 0, true);
  }
  return out.slice(0, digestBytes);
}

/** LSH-256-256 — the variant this lab compares. */
export function lsh256(message: Uint8Array): Uint8Array {
  return lshHash(32, message);
}

/* ------------------------------------------------ the published-vector check */

/**
 * How a vector's message is expressed. `zeros` matters: the block-boundary
 * cases are long runs of 0x00, and spelling them out as hex would put several
 * kilobytes of constant into the bundle for no gain.
 */
export type LshMessage =
  | { kind: 'text'; value: string }
  | { kind: 'hex'; value: string }
  | { kind: 'zeros'; length: number };

export interface LshVector {
  label: string;
  digestBytes: LshDigestBytes;
  message: LshMessage;
  expected: string;
  source: string;
}

const CRYPTOPP = "Crypto++ LSH test data (from KISA's specification and source)";
const PUBLISHED = 'published LSH reference value';

/**
 * The shipped vector set.
 *
 * Two published `"abc"` digests, then block-boundary coverage for both widths:
 * empty, 127 bytes (one short of a block), and 128 / 256 / 384 / 512 bytes —
 * every one of the last three an exact multiple, which is the case that forces
 * the extra padding block.
 */
export const LSH_VECTORS: LshVector[] = [
  { label: 'LSH-256-256, "abc"', digestBytes: 32, message: { kind: 'text', value: 'abc' }, expected: '5fbf365daea5446a7053c52b57404d77a07a5f48a1f7c1963a0898ba1b714741', source: PUBLISHED },
  { label: 'LSH-256-224, "abc"', digestBytes: 28, message: { kind: 'text', value: 'abc' }, expected: 'f7c53ba4034e708e74fba42e55997ca5126bb7623688f85342f73732', source: PUBLISHED },
  { label: 'LSH-256-256, empty message', digestBytes: 32, message: { kind: 'zeros', length: 0 }, expected: 'f3cd416a03818217726cb47f4e4d2881c9c29fd445c18b66fb19dea1a81007c1', source: CRYPTOPP },
  { label: 'LSH-256-224, empty message', digestBytes: 28, message: { kind: 'zeros', length: 0 }, expected: '48a0d55b2b3d91f26e06f7110fe9ce8ea0e2656bbe344cb1c5930653', source: CRYPTOPP },
  { label: 'LSH-256-256, 127-byte message (one short of a block)', digestBytes: 32, message: { kind: 'hex', value: '4736cec0425fa500d737100811587619e431b753f3886333d65d2be10b1643b30b0156fc7257df9933c35d48af2fa7ea4337ac3ba6605f450aadea9e5369631a835aa2a59260563a2788e1459faf3f12e92b683f0d714b158e2e63a58d6c842da058ff23cfd6e8787572cd1147c55859fbeaabcf592641df5d3167321e8f70' }, expected: '82c7c18f22f752725ce8c29364e5f87c4be0294c484dc363474885ba8aab38dd', source: CRYPTOPP },
  { label: 'LSH-256-224, 127-byte message (one short of a block)', digestBytes: 28, message: { kind: 'hex', value: 'e2e756062d770e300ff1dfe3a92d16c4f4be063f10f2e949cd0590dfc7cb2127630826b6e1b2d40be40c3b8157edb39879e26205f119836ae820f48317b23c38681a04ed2e2f7fc2551c6d503f3822a4ca58b821eeff46a860458e7a8279fabb5e7154bf74840af8352646b9560fa433f0fc4d91842372dceeb79528549626' }, expected: '3395f4d28a08a9d830d83241cb53ad71f218b8bd3bec2b7b0c234381', source: CRYPTOPP },
  { label: 'LSH-256-256, 128 zero bytes (exactly one block)', digestBytes: 32, message: { kind: 'zeros', length: 128 }, expected: 'd44fdd8a41c88053f3409a7c298fb6f51ab8e3add1f3412440313cdef54005a4', source: CRYPTOPP },
  { label: 'LSH-256-256, 256 zero bytes', digestBytes: 32, message: { kind: 'zeros', length: 256 }, expected: '2e8608025f4f89b9393173933d232b4c2ee8300a6442c7f653c601df01f62f81', source: CRYPTOPP },
  { label: 'LSH-256-256, 384 zero bytes', digestBytes: 32, message: { kind: 'zeros', length: 384 }, expected: '242c96d54d672959339a977fe543cb07a856a50d9f3bce264746a03dda7021e7', source: CRYPTOPP },
  { label: 'LSH-256-256, 512 zero bytes', digestBytes: 32, message: { kind: 'zeros', length: 512 }, expected: '10d3cc85aee4fe6bf90abdce4945776902f857e34c1d1ea3a043ca5fa16eb1d1', source: CRYPTOPP },
  { label: 'LSH-256-224, 128 zero bytes (exactly one block)', digestBytes: 28, message: { kind: 'zeros', length: 128 }, expected: 'ba4793d003dc5d4de44ebfbecb1430a13a69f41664d04436984e4cf3', source: CRYPTOPP },
  { label: 'LSH-256-224, 256 zero bytes', digestBytes: 28, message: { kind: 'zeros', length: 256 }, expected: '779b665fa8c905836c92821802ad9b83170d978d3e4245321963631a', source: CRYPTOPP },
  { label: 'LSH-256-224, 384 zero bytes', digestBytes: 28, message: { kind: 'zeros', length: 384 }, expected: 'ea79cca2aa02223d91d965fd275e07a13bf0aeb9a9c4790335fd4b50', source: CRYPTOPP },
  { label: 'LSH-256-224, 512 zero bytes', digestBytes: 28, message: { kind: 'zeros', length: 512 }, expected: '80ff3f526f5a5b273abdbb6b14b296b63563b488834c58b802cff38b', source: CRYPTOPP },
];

const utf8 = new TextEncoder();

function materialize(message: LshMessage): Uint8Array {
  if (message.kind === 'text') return utf8.encode(message.value);
  if (message.kind === 'zeros') return new Uint8Array(message.length);
  const pairs = message.value.match(/../g) ?? [];
  return Uint8Array.from(pairs, (pair) => Number.parseInt(pair, 16));
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export interface LshCheck {
  label: string;
  source: string;
  computed: string;
  published: string;
  agrees: boolean;
}

/**
 * Recompute every shipped LSH vector against this module.
 *
 * Runs in the unit suite and on every page load, for the same reason
 * `crossCheckBash()` does: this lab hand-rolls the primitive, so it owes the
 * reader a live check rather than a promise.
 */
export function crossCheckLsh(): LshCheck[] {
  return LSH_VECTORS.map((vector) => {
    const computed = toHex(lshHash(vector.digestBytes, materialize(vector.message)));
    return {
      label: vector.label,
      source: vector.source,
      computed,
      published: vector.expected,
      agrees: computed === vector.expected,
    };
  });
}
