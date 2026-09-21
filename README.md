# crypto-lab-world-hashes

## What It Is

World Hashes demonstrates four national cryptographic hash standards — SM3 (China, OSCCA, 2010), Streebog (Russia, FSB, 2012), Kupyna (Ukraine, 2014), and Bash (Belarus, STB 34.101.77, 2016) — alongside SHA-256 and SHA-3 as reference anchors. Each national hash was developed for cryptographic sovereignty: to reduce dependence on U.S.-designed primitives for government and regulated-industry use. The security model is collision-resistant one-way function: given a hash output, finding the input or a second input with the same hash must be computationally infeasible.

The page opens with a **ground-floor "what is a cryptographic hash?" panel** that defines the four properties — deterministic, fixed-length, one-way, collision-resistant — and demonstrates them live (type anything and watch the digest stay 256 bits while a single extra character scrambles it). Every construction term (Merkle–Damgård, sponge, wide-pipe, S-box, Miyaguchi–Preneel, Keccak-f[1600], length-extension) is glossed inline on hover/focus, and a "Constructions 101" note contrasts block-chaining (SM3, SHA-256, and the wide-pipe variants Streebog and Kupyna) against absorb-and-squeeze (SHA-3 and Bash) so a newcomer can follow the rest.

## When to Use It

- SM3: Required for Chinese PKI, Chinese TLS (TLCP), and products under Chinese Cryptography Law — pairs with SM2 signatures.
- Streebog-256/512: Required for Russian GOST R 34.11-2012 compliance — pairs with GOST elliptic curve signatures.
- Kupyna-256/512: Required for Ukrainian DSTU 7564:2014 compliance.
- Bash-256/384/512: Required for Belarusian STB 34.101.77 compliance.
- SHA-256: General-purpose default for all other use cases.
- SHA-3: Preferred for new protocol designs or when sponge security matters.
- Do not use Streebog outside Russian compliance requirements — shared S-box transparency concerns with Kuznyechik apply.
- Do NOT reach for Bash from npm without checking it against STB 34.101.77 Annex A yourself. The package this lab depends on, `@li0ard/bash`, ships a correct `bash-f` permutation wrapped in a sponge that miscomputes the rate; it fails 7 of the standard's 11 hash vectors, and agrees on every message shorter than one block — which is why its own suite is green. This lab therefore implements the sponge in [`src/bash.ts`](src/bash.ts) and pins all eleven vectors.
- Do not use any of these as a MAC without HMAC wrapping — Exhibit 5 forges a `H(secret ‖ message)` tag for SM3 and SHA-256 in front of you, and shows HMAC holding against the same attempt.
- Do NOT treat this as a production crypto library — it is a teaching demo for comparing national hash standards, not a hardened deployment.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-world-hashes](https://systemslibrarian.github.io/crypto-lab-world-hashes/)**

A ground-floor intro panel plus six exhibits:

0. **What is a cryptographic hash?** — the four properties in plain language, demonstrated live: type anything and watch the SHA-256 digest stay a fixed 256 bits while one extra character scrambles it; a collapsible explains one-wayness and collisions.
1. **SM3 (China)** with SHA-256 side-by-side, a labelled **Merkle–Damgård mechanism diagram** (message blocks chaining through a compression function to an exposed final state → length-extension), and a **user-driven avalanche** — click any character to flip it yourself and watch the digest re-scramble.
2. **Streebog (Russia)** with S-box controversy documentation and its wide-pipe MD construction glossed.
3. **Kupyna (Ukraine)** with geopolitical context and a **wide-pipe mechanism diagram** (blocks chained through a double-width state, truncated by a final output transformation → no length-extension). Kupyna is a Grøstl-style wide-pipe Merkle–Damgård hash, *not* a sponge.
4. **SHA-256 and SHA-3 as reference anchors** with six-way simultaneous hashing (SHA-256, SHA-3-256, SM3, Streebog-256, Kupyna-256, Bash-256) and the **sponge mechanism diagram** (absorb into a wide rate/capacity state, squeeze out the digest, capacity never exposed → no length-extension). SHA-3 and **Bash (Belarus)** are the two sponges in the lab; everything else chains blocks.
5. **Break it** — the exhibits above *tell* you that narrow-pipe Merkle–Damgård hashes hand out their final chaining state, and that this exposes length-extension. This one lets you do it, and lets you fail at it:
   - **A real length-extension forgery.** A server authenticates with the naive `tag = H(secret ‖ message)` and publishes only the message and the tag. Given those plus a guess at the secret's *length*, the page appends a suffix of your choosing and produces a tag that matches, byte for byte, what the server computes for the extended message. It works against both SM3 and SHA-256. Guess the length wrong and the forgery visibly fails, and the verdict names why.
   - **Kept honest by a cross-check.** The attack needs a hash it can resume from an arbitrary state, which no library exposes, so [`src/length-extension.ts`](src/length-extension.ts) reimplements the SHA-256 and SM3 compression functions from FIPS 180-4 and GM/T 0004-2012. Those are cross-checked against the audited libraries the rest of the lab uses on every page load and on every test run — the forging routine is handed only the tag, the guessed length and the suffix, so "no secret required" is a fact about its signature rather than a claim in prose.
   - **The same attempt against the constructions that resist it.** SHA-3 and Bash (sponges), Kupyna (wide-pipe), Streebog (length + checksum finalization) and HMAC-SHA-256 all hold, and the table states for each *why the attack has no entry point at all*, alongside the measured result of the closest analogue an attacker without internal state could compute.
   - **A negative claim, backed by a fixture.** Bash carries **no** length-extension countermeasure — no length encoding, no checksum, no output transformation. Neither does SHA-256, which this same page forges. The table prints `none` in both places and puts the actual difference beside it as a measurement: how many state bits the published digest withholds (SHA-256: **0 of 256** — the digest *is* the chaining state; Bash: **1280 of 1536**). The page states plainly that a green row for Bash means the attack has no entry point, *not* that `H(secret ‖ message)` is a sound MAC. `e2e/claims.spec.ts` drives the page into that all-green state and asserts the limitation is visible in it.
   - **A real birthday collision search.** Truncate any of the ten digests to 8–32 bits and watch a genuine search find two distinct inputs that agree on that prefix — rechecked, with the full digests shown differing. The measured hash count is compared against √(π/2·2ⁿ). Starve the budget and the verdict refuses to claim anything.
6. **Six-way comparison table + decision tree**, with the **Trust-level column explicitly labelled editorial opinion** and each grade sourced in an expandable note (e.g. Streebog's caution cites Perrin, IACR ToSC 2019, on the shared S-box).

All hash outputs are real — no simulation. Every digest is produced in your browser by [`src/hashes.ts`](src/hashes.ts), the same module the test suite checks. Each exhibit shows a **visual avalanche diff** (changed hex nibbles highlighted, with bit-diffusion percentage against the ideal ~50%) and a live **input byte-length** readout. Nothing is sent to a server — all hashing is local.

## What Can Go Wrong

- Using a narrow-pipe Merkle–Damgård hash (SM3, SHA-256) directly as a MAC is vulnerable to length-extension; wrap it in HMAC instead. Exhibit 5 runs that forgery live rather than describing it. The others avoid it for different reasons — Streebog through its length/checksum finalization, Kupyna through its wide state and output transformation, SHA-3 and Bash because a sponge never hands out its state at all — but HMAC remains the portable choice, and length-extension immunity is not on its own MAC security.
- Streebog and Kuznyechik share S-box transparency concerns, so deploying Streebog outside its compliance mandate inherits an unresolved design-trust question.
- Bash's risk today is ecosystem, not design: the npm implementation this lab started from fails 7 of the 11 vectors in the standard's own Annex A, and does so *silently* — it agrees with the standard on anything shorter than one sponge block. A conformance suite that only tests short messages will not catch it. Test against Annex A across a rate boundary before trusting any Bash implementation.
- Reaching for a national hash outside its regulatory requirement trades SHA-2/SHA-3 scrutiny and tooling for weaker ecosystem support with no security gain.
- Collision and second-preimage resistance are assumptions, not guarantees; truncating a digest or misusing it for password storage (no salt/KDF) undermines the intended security.
- Mismatched variants (e.g. confusing the 256-bit and 512-bit outputs, or differing byte/endianness conventions between standards) break interoperability between implementations.

## Real-World Usage

- SM3 underpins Chinese PKI, Chinese TLS (TLCP), and products under Chinese Cryptography Law, paired with SM2 signatures.
- Streebog-256/512 is mandated for Russian GOST R 34.11-2012 compliance, paired with GOST elliptic-curve signatures.
- Kupyna-256/512 is required for Ukrainian DSTU 7564:2014 compliance.
- Bash-256/384/512 (STB 34.101.77) is Belarus's national hash, designed at the Research Institute for Applied Problems of Mathematics and Informatics, BSU, and used alongside the belt block cipher (STB 34.101.31) and bign signatures (STB 34.101.45).
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

The hero shows a live self-test badge (e.g. `✓ 18/18 test vectors verified`). On every page load the app recomputes published **known-answer test vectors** and compares them byte-for-byte against published values. Where a vector appears in the algorithm's defining standard the table says so; the `"…lazy dog"` vectors are widely published reference values rather than standard vectors, and each entry carries its own provenance label in [`src/hashes.ts`](src/hashes.ts):

| Algorithm | Standard | Vectors |
| --- | --- | --- |
| SM3 | GM/T 0004-2012 | empty, `"abc"` |
| SHA-256 / SHA-512 | FIPS 180-4 | empty, `"abc"`, fox |
| SHA-3-256 / SHA-3-512 | FIPS 202 | empty, `"abc"` |
| Streebog-256 / -512 | GOST R 34.11-2012 | empty, fox |
| Kupyna-256 / -512 | DSTU 7564:2014 | empty, fox |
| Bash-256 | STB 34.101.77 §A.3.1 | empty |

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

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
