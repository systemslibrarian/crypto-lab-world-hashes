# crypto-lab-world-hashes

## What It Is

World Hashes demonstrates three national cryptographic hash standards — SM3 (China, OSCCA, 2010), Streebog (Russia, FSB, 2012), and Kupyna (Ukraine, 2014) — alongside SHA-256 and SHA-3 as reference anchors. Each national hash was developed for cryptographic sovereignty: to reduce dependence on U.S.-designed primitives for government and regulated-industry use. The security model is collision-resistant one-way function: given a hash output, finding the input or a second input with the same hash must be computationally infeasible.

The page opens with a **ground-floor "what is a cryptographic hash?" panel** that defines the four properties — deterministic, fixed-length, one-way, collision-resistant — and demonstrates them live (type anything and watch the digest stay 256 bits while a single extra character scrambles it). Every construction term (Merkle–Damgård, sponge, wide-pipe, S-box, Miyaguchi–Preneel, Keccak-f[1600], length-extension) is glossed inline on hover/focus, and a "Constructions 101" note contrasts block-chaining against absorb-and-squeeze so a newcomer can follow the rest.

## When to Use It

- SM3: Required for Chinese PKI, Chinese TLS (TLCP), and products under Chinese Cryptography Law — pairs with SM2 signatures.
- Streebog-256/512: Required for Russian GOST R 34.11-2012 compliance — pairs with GOST elliptic curve signatures.
- Kupyna-256/512: Required for Ukrainian DSTU 7564:2014 compliance.
- SHA-256: General-purpose default for all other use cases.
- SHA-3: Preferred for new protocol designs or when sponge security matters.
- Do not use Streebog outside Russian compliance requirements — shared S-box transparency concerns with Kuznyechik apply.
- Do not use any of these as a MAC without HMAC wrapping.
- Do NOT treat this as a production crypto library — it is a teaching demo for comparing national hash standards, not a hardened deployment.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-world-hashes](https://systemslibrarian.github.io/crypto-lab-world-hashes/)**

A ground-floor intro panel plus five exhibits:

0. **What is a cryptographic hash?** — the four properties in plain language, demonstrated live: type anything and watch the SHA-256 digest stay a fixed 256 bits while one extra character scrambles it; a collapsible explains one-wayness and collisions.
1. **SM3 (China)** with SHA-256 side-by-side, a labelled **Merkle–Damgård mechanism diagram** (message blocks chaining through a compression function to an exposed final state → length-extension), and a **user-driven avalanche** — click any character to flip it yourself and watch the digest re-scramble.
2. **Streebog (Russia)** with S-box controversy documentation and its wide-pipe MD construction glossed.
3. **Kupyna (Ukraine)** with geopolitical context and a **sponge mechanism diagram** (absorb into a wide rate/capacity state, squeeze out the digest, capacity never exposed → no length-extension).
4. **SHA-256 and SHA-3 as reference anchors** with five-way simultaneous hashing.
5. **Five-way comparison table + decision tree**, with the **Trust-level column explicitly labelled editorial opinion** and each grade sourced in an expandable note (e.g. Streebog's caution cites Perrin et al. 2019 on the shared S-box).

All hash outputs are real — no simulation. Every digest is produced in your browser by [`src/hashes.ts`](src/hashes.ts), the same module the test suite checks. Each exhibit shows a **visual avalanche diff** (changed hex nibbles highlighted, with bit-diffusion percentage against the ideal ~50%) and a live **input byte-length** readout. Nothing is sent to a server — all hashing is local.

## What Can Go Wrong

- Using a raw Merkle–Damgård hash (SM3, SHA-256, Streebog) directly as a MAC is vulnerable to length-extension; wrap it in HMAC instead.
- Streebog and Kuznyechik share S-box transparency concerns, so deploying Streebog outside its compliance mandate inherits an unresolved design-trust question.
- Reaching for a national hash outside its regulatory requirement trades SHA-2/SHA-3 scrutiny and tooling for weaker ecosystem support with no security gain.
- Collision and second-preimage resistance are assumptions, not guarantees; truncating a digest or misusing it for password storage (no salt/KDF) undermines the intended security.
- Mismatched variants (e.g. confusing the 256-bit and 512-bit outputs, or differing byte/endianness conventions between standards) break interoperability between implementations.

## Real-World Usage

- SM3 underpins Chinese PKI, Chinese TLS (TLCP), and products under Chinese Cryptography Law, paired with SM2 signatures.
- Streebog-256/512 is mandated for Russian GOST R 34.11-2012 compliance, paired with GOST elliptic-curve signatures.
- Kupyna-256/512 is required for Ukrainian DSTU 7564:2014 compliance.
- SHA-256 (FIPS 180-4) remains the general-purpose default across the internet, with SHA-3 (FIPS 202) preferred for new sponge-based designs.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-world-hashes
cd crypto-lab-world-hashes
npm install
npm run dev
```

## Related Demos
- [crypto-lab-world-ciphers](https://systemslibrarian.github.io/crypto-lab-world-ciphers/) — the encryption counterpart: Camellia, ARIA, SM4, and Kuznyechik national block ciphers.
- [crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/) — SHA-256, SHA3-256, BLAKE3, and the Merkle–Damgård construction explained.
- [crypto-lab-babel-hash](https://systemslibrarian.github.io/crypto-lab-babel-hash/) — interactive SHA-256, SHA3-256, BLAKE3, and HMAC.
- [crypto-lab-mac-race](https://systemslibrarian.github.io/crypto-lab-mac-race/) — HMAC, CMAC, Poly1305, and GHASH: turning hashes into authenticators.
- [crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — Merkle trees and inclusion proofs built on a hash function.

## Verified Correctness

The hero shows a live self-test badge (e.g. `✓ 17/17 test vectors verified`). On every page load the app recomputes published **known-answer test vectors** and compares them byte-for-byte against the values in each algorithm's defining standard:

| Algorithm | Standard | Vectors |
| --- | --- | --- |
| SM3 | GM/T 0004-2012 | empty, `"abc"` |
| SHA-256 / SHA-512 | FIPS 180-4 | empty, `"abc"`, fox |
| SHA-3-256 / SHA-3-512 | FIPS 202 | empty, `"abc"` |
| Streebog-256 / -512 | GOST R 34.11-2012 | empty, fox |
| Kupyna-256 / -512 | DSTU 7564:2014 | empty, fox |

The same vectors run in CI via [Vitest](https://vitest.dev/) on every push, alongside a happy-dom render test that asserts the UI mounts and reports all vectors passing, and an [axe-core](https://github.com/dequelabs/axe-core) accessibility scan.

```bash
npm test         # known-answer + render + accessibility tests
npm run test:watch
npm run typecheck
```

## Accessibility

The lab is built to WCAG 2.1 AA: semantic landmarks and a skip link, the full ARIA tab pattern with arrow/Home/End keyboard navigation, visible focus rings, focus and caret preserved across re-renders, `scope`-annotated data tables, `prefers-reduced-motion` support, and a `<noscript>` fallback. Avalanche highlights carry three independent cues (colour, background, underline) so they never rely on colour alone, and colour contrast meets AA in both themes.

`npm test` runs an automated axe-core scan (WCAG 2 A/AA) against the rendered app in both themes on every push. Layout-dependent colour-contrast is verified separately, since a headless DOM has no rendering engine.

## GitHub Pages Setup

This project is configured for automatic Pages deploy from GitHub Actions.

1. Push this repo to GitHub on the `main` branch.
2. In GitHub: `Settings -> Pages -> Build and deployment`.
3. Set `Source` to `GitHub Actions`.
4. Push to `main` (or run the `Deploy to GitHub Pages` workflow manually).

Manual deploy is also available:

```bash
npm run deploy
```

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
