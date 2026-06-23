import { kupyna256, kupyna512 } from '@li0ard/kupyna';
import { streebog256, streebog512 } from '@li0ard/streebog';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { sm3 as sm3Hash } from 'sm-crypto';

/**
 * Single source of truth for every hash function in the demo.
 *
 * The UI and the test suite both import from here, so the digests a visitor
 * sees in the browser are produced by exactly the same code path that is
 * checked against published known-answer test vectors (see `TEST_VECTORS`).
 */
export type AlgorithmId =
  | 'sm3'
  | 'sha256'
  | 'sha512'
  | 'sha3-256'
  | 'sha3-512'
  | 'streebog256'
  | 'streebog512'
  | 'kupyna256'
  | 'kupyna512';

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

const IMPLEMENTATIONS: Record<AlgorithmId, (bytes: Uint8Array) => string> = {
  sm3: (bytes) => sm3Hash(Array.from(bytes)),
  sha256: (bytes) => bytesToHex(sha256(bytes)),
  sha512: (bytes) => bytesToHex(sha512(bytes)),
  'sha3-256': (bytes) => bytesToHex(sha3_256(bytes)),
  'sha3-512': (bytes) => bytesToHex(sha3_512(bytes)),
  streebog256: (bytes) => bytesToHex(streebog256(bytes)),
  streebog512: (bytes) => bytesToHex(streebog512(bytes)),
  kupyna256: (bytes) => bytesToHex(kupyna256(bytes)),
  kupyna512: (bytes) => bytesToHex(kupyna512(bytes))
};

/** Human-readable labels, used in headings and result cards. */
export const ALGORITHM_LABELS: Record<AlgorithmId, string> = {
  sm3: 'SM3',
  sha256: 'SHA-256',
  sha512: 'SHA-512',
  'sha3-256': 'SHA-3-256',
  'sha3-512': 'SHA-3-512',
  streebog256: 'Streebog-256',
  streebog512: 'Streebog-512',
  kupyna256: 'Kupyna-256',
  kupyna512: 'Kupyna-512'
};

/** Digest length in bits, used to report avalanche statistics. */
export const ALGORITHM_BITS: Record<AlgorithmId, number> = {
  sm3: 256,
  sha256: 256,
  sha512: 512,
  'sha3-256': 256,
  'sha3-512': 512,
  streebog256: 256,
  streebog512: 512,
  kupyna256: 256,
  kupyna512: 512
};

export function computeHex(algorithm: AlgorithmId, bytes: Uint8Array): string {
  return IMPLEMENTATIONS[algorithm](bytes);
}

export interface TestVector {
  algorithm: AlgorithmId;
  /** UTF-8 text input. An empty string means the zero-length message. */
  input: string;
  /** Short, human-readable description of the input for display. */
  inputLabel: string;
  expected: string;
  /** Authoritative standard or reference the vector is drawn from. */
  source: string;
}

/**
 * Known-answer test vectors taken from the algorithms' defining standards and
 * widely published reference values. Every entry has been confirmed to match
 * the bundled implementations; the live self-test (`runSelfTest`) re-checks
 * them in the browser on every load.
 */
export const TEST_VECTORS: TestVector[] = [
  // SM3 — GM/T 0004-2012 / GB/T 32905-2016
  { algorithm: 'sm3', input: '', inputLabel: 'empty string', expected: '1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b', source: 'GM/T 0004-2012' },
  { algorithm: 'sm3', input: 'abc', inputLabel: '"abc"', expected: '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0', source: 'GM/T 0004-2012 §A.1' },
  // SHA-256 — FIPS 180-4
  { algorithm: 'sha256', input: '', inputLabel: 'empty string', expected: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', source: 'FIPS 180-4 / NIST CAVP' },
  { algorithm: 'sha256', input: 'abc', inputLabel: '"abc"', expected: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', source: 'FIPS 180-4' },
  { algorithm: 'sha256', input: 'The quick brown fox jumps over the lazy dog', inputLabel: '"…lazy dog"', expected: 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592', source: 'NIST CAVP' },
  // SHA-512 — FIPS 180-4
  { algorithm: 'sha512', input: '', inputLabel: 'empty string', expected: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', source: 'FIPS 180-4' },
  { algorithm: 'sha512', input: 'abc', inputLabel: '"abc"', expected: 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f', source: 'FIPS 180-4' },
  // SHA-3 — FIPS 202
  { algorithm: 'sha3-256', input: '', inputLabel: 'empty string', expected: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a', source: 'FIPS 202' },
  { algorithm: 'sha3-256', input: 'abc', inputLabel: '"abc"', expected: '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532', source: 'FIPS 202' },
  { algorithm: 'sha3-512', input: '', inputLabel: 'empty string', expected: 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26', source: 'FIPS 202' },
  // Streebog — GOST R 34.11-2012
  { algorithm: 'streebog256', input: '', inputLabel: 'empty string', expected: '3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb', source: 'GOST R 34.11-2012' },
  { algorithm: 'streebog256', input: 'The quick brown fox jumps over the lazy dog', inputLabel: '"…lazy dog"', expected: '3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4', source: 'GOST R 34.11-2012 reference' },
  { algorithm: 'streebog512', input: '', inputLabel: 'empty string', expected: '8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a', source: 'GOST R 34.11-2012' },
  { algorithm: 'streebog512', input: 'The quick brown fox jumps over the lazy dog', inputLabel: '"…lazy dog"', expected: 'd2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe', source: 'GOST R 34.11-2012 reference' },
  // Kupyna — DSTU 7564:2014
  { algorithm: 'kupyna256', input: '', inputLabel: 'empty string', expected: 'cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6', source: 'DSTU 7564:2014' },
  { algorithm: 'kupyna256', input: 'The quick brown fox jumps over the lazy dog', inputLabel: '"…lazy dog"', expected: '996899f2d7422ceaf552475036b2dc120607eff538abf2b8dff471a98a4740c6', source: 'DSTU 7564:2014 reference' },
  { algorithm: 'kupyna512', input: '', inputLabel: 'empty string', expected: '656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538', source: 'DSTU 7564:2014' }
];

export interface SelfTestResult {
  vector: TestVector;
  actual: string;
  pass: boolean;
}

export interface SelfTestReport {
  total: number;
  passed: number;
  failed: number;
  results: SelfTestResult[];
}

const utf8 = new TextEncoder();

/** Runs every known-answer test vector against the bundled implementations. */
export function runSelfTest(): SelfTestReport {
  const results = TEST_VECTORS.map((vector) => {
    const actual = computeHex(vector.algorithm, utf8.encode(vector.input));
    return { vector, actual, pass: actual === vector.expected };
  });
  const passed = results.filter((r) => r.pass).length;
  return {
    total: results.length,
    passed,
    failed: results.length - passed,
    results
  };
}
