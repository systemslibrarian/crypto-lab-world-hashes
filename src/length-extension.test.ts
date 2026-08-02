/**
 * Guards on the length-extension lab.
 *
 * The load-bearing check is the cross-check: this repo reimplements the SHA-256
 * and SM3 compression functions (no library exposes a resumable state), so those
 * reimplementations are pinned against the audited libraries the rest of the lab
 * uses. If they ever drift, the forgery the page shows would be meaningless.
 */
import { describe, expect, it } from 'vitest';

import { computeHex } from './hashes';
import {
  EXTENDABLE_ALGORITHMS,
  MD_BLOCK_BYTES,
  attemptLengthExtension,
  checkResistance,
  crossCheckImplementations,
  forgeFromTag,
  mdHash,
  mdPadding,
  stateFromDigest,
} from './length-extension';

const utf8 = new TextEncoder();

describe('the reimplemented compression functions', () => {
  it('agree with the audited libraries on every cross-check input', () => {
    const checks = crossCheckImplementations();
    expect(checks.length).toBeGreaterThan(10);
    for (const check of checks) {
      expect(check.mine, `${check.algorithm} on ${check.input}`).toBe(check.library);
      expect(check.agrees).toBe(true);
    }
  });

  it('agree on 200 random inputs spanning every block boundary', () => {
    for (let length = 0; length <= 200; length += 1) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + length * 11) & 0xff);
      for (const algorithm of EXTENDABLE_ALGORITHMS) {
        expect(mdHash(algorithm, bytes), `${algorithm} @ ${length} bytes`).toBe(
          computeHex(algorithm, bytes),
        );
      }
    }
  });
});

describe('Merkle–Damgård padding', () => {
  it('always lands the padded message on a block boundary', () => {
    for (let length = 0; length < 200; length += 1) {
      expect((length + mdPadding(length).length) % MD_BLOCK_BYTES).toBe(0);
    }
  });

  it('starts with 0x80 and ends with the bit length, big-endian', () => {
    const padding = mdPadding(1);
    expect(padding[0]).toBe(0x80);
    expect(padding[padding.length - 1]).toBe(8); // 1 byte = 8 bits
    const wide = mdPadding(64);
    expect(wide.length).toBe(64); // a full extra block
    expect(wide[wide.length - 1]).toBe(512 & 0xff);
    expect(wide[wide.length - 2]).toBe((512 >> 8) & 0xff);
  });

  it('rejects a negative or fractional length', () => {
    expect(() => mdPadding(-1)).toThrow();
    expect(() => mdPadding(1.5)).toThrow();
  });
});

describe('reading a digest back as a chaining state', () => {
  it('round-trips through the hash of the empty string', () => {
    const state = stateFromDigest(computeHex('sha256', new Uint8Array()));
    expect(state).toHaveLength(8);
    for (const word of state) expect(word).toBeGreaterThanOrEqual(0);
  });

  it('rejects anything that is not a 256-bit hex digest', () => {
    expect(() => stateFromDigest('abc')).toThrow();
    expect(() => stateFromDigest('z'.repeat(64))).toThrow();
  });
});

describe('the attack itself', () => {
  const secrets = ['k', 'sup3rs3cr3t', 'a'.repeat(40), 'a'.repeat(63), 'a'.repeat(64), 'a'.repeat(100)];
  const messages = ['', 'user=guest', 'amount=10&to=bob', 'x'.repeat(70)];
  const suffixes = ['&admin=true', '!', 'y'.repeat(80)];

  it('forges for every algorithm across every secret/message/suffix combination', () => {
    let forgeries = 0;
    for (const algorithm of EXTENDABLE_ALGORITHMS) {
      for (const secret of secrets) {
        for (const message of messages) {
          for (const suffix of suffixes) {
            const attempt = attemptLengthExtension(
              algorithm,
              secret,
              message,
              suffix,
              utf8.encode(secret).length,
            );
            expect(attempt.forged, `${algorithm}/${secret.length}/${message.length}/${suffix.length}`).toBe(true);
            expect(attempt.forgedTag).toBe(attempt.serverTag);
            expect(attempt.reason).toBe('forged');
            forgeries += 1;
          }
        }
      }
    }
    // 2 algorithms × 6 secrets × 4 messages × 3 suffixes.
    expect(forgeries).toBe(144);
  });

  it('fails honestly when the guessed secret length is wrong', () => {
    for (const algorithm of EXTENDABLE_ALGORITHMS) {
      for (const delta of [-2, -1, 1, 2, 8]) {
        const attempt = attemptLengthExtension(
          algorithm,
          'sup3rs3cr3t',
          'user=guest',
          '&admin=true',
          11 + delta,
        );
        expect(attempt.forged, `${algorithm} delta ${delta}`).toBe(false);
        expect(attempt.forgedTag).not.toBe(attempt.serverTag);
        expect(attempt.reason).toBe('wrong-secret-length');
      }
    }
  });

  it('never needs the secret: forgeFromTag takes only the tag, length and suffix', () => {
    const secret = 'sup3rs3cr3t';
    const message = 'user=guest';
    const suffix = '&admin=true';
    const joined = utf8.encode(secret + message);
    const tag = mdHash('sha256', joined);
    // Everything below is computable by someone who has only `tag` and lengths.
    const forged = forgeFromTag('sha256', tag, joined.length, utf8.encode(suffix));
    // And it matches what the server, holding the secret, would produce.
    const glue = mdPadding(joined.length);
    const full = new Uint8Array(joined.length + glue.length + suffix.length);
    full.set(joined, 0);
    full.set(glue, joined.length);
    full.set(utf8.encode(suffix), joined.length + glue.length);
    expect(forged).toBe(mdHash('sha256', full));
  });

  it('rejects a nonsense length guess rather than inventing a forgery', () => {
    expect(() => attemptLengthExtension('sha256', 'k', 'm', 's', -1)).toThrow();
    expect(() => attemptLengthExtension('sha256', 'k', 'm', 's', 1.5)).toThrow();
    expect(() => attemptLengthExtension('sha256', 'k', 'm', 's', 99_999)).toThrow();
  });
});

describe('the constructions that resist it', () => {
  const lineup = ['sha3-256', 'kupyna256', 'streebog256', 'hmac-sha256'] as const;

  it('holds for every one of them, across several inputs', () => {
    for (const algorithm of lineup) {
      for (const secret of ['k', 'sup3rs3cr3t', 'a'.repeat(64)]) {
        for (const suffix of ['&admin=true', 'z'.repeat(70)]) {
          const result = checkResistance(algorithm, secret, 'user=guest', suffix);
          expect(result.forged, `${algorithm}/${secret.length}/${suffix.length}`).toBe(false);
          expect(result.naiveForgery).not.toBe(result.serverTag);
          expect(result.reason.length).toBeGreaterThan(20);
        }
      }
    }
  });

  it("names Kupyna's wide pipe and SHA-3's sponge as the reason, not hand-waving", () => {
    expect(checkResistance('kupyna256', 'k', 'm', 's').reason).toMatch(/wide-pipe/i);
    expect(checkResistance('kupyna256', 'k', 'm', 's').reason).toMatch(/Merkle–Damgård/);
    expect(checkResistance('sha3-256', 'k', 'm', 's').reason).toMatch(/sponge/i);
    expect(checkResistance('streebog256', 'k', 'm', 's').reason).toMatch(/checksum/i);
    expect(checkResistance('hmac-sha256', 'k', 'm', 's').reason).toMatch(/opad/);
  });
});
