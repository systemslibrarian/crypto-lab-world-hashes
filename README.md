# crypto-lab-world-hashes

## 1. What It Is

World Hashes demonstrates three national cryptographic hash standards — SM3 (China, OSCCA, 2010), Streebog (Russia, FSB, 2012), and Kupyna (Ukraine, 2014) — alongside SHA-256 and SHA-3 as reference anchors. Each national hash was developed for cryptographic sovereignty: to reduce dependence on U.S.-designed primitives for government and regulated-industry use. The security model is collision-resistant one-way function: given a hash output, finding the input or a second input with the same hash must be computationally infeasible.

## 2. When to Use It

- ✅ SM3: Required for Chinese PKI, Chinese TLS (TLCP), and products under Chinese Cryptography Law — pairs with SM2 signatures
- ✅ Streebog-256/512: Required for Russian GOST R 34.11-2012 compliance — pairs with GOST elliptic curve signatures
- ✅ Kupyna-256/512: Required for Ukrainian DSTU 7564:2014 compliance
- ✅ SHA-256: General-purpose default for all other use cases
- ✅ SHA-3: Preferred for new protocol designs or when sponge security matters
- ❌ Do not use Streebog outside Russian compliance requirements — shared S-box transparency concerns with Kuznyechik apply
- ❌ Do not use any of these as a MAC without HMAC wrapping

## 3. Live Demo

Link: https://systemslibrarian.github.io/crypto-lab-world-hashes/
Five exhibits: SM3 with SHA-256 side-by-side and construction comparison, Streebog with S-box controversy documentation, Kupyna with geopolitical context and sponge construction comparison, SHA-256 and SHA-3 as reference anchors with five-way simultaneous hashing, and a full five-way comparison table with decision tree. All hash outputs are real — no simulation.

## 4. How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-world-hashes
cd crypto-lab-world-hashes
npm install
npm run dev
```

## 5. GitHub Pages Setup

This project is configured for automatic Pages deploy from GitHub Actions.

1. Push this repo to GitHub on the `main` branch.
2. In GitHub: `Settings -> Pages -> Build and deployment`.
3. Set `Source` to `GitHub Actions`.
4. Push to `main` (or run the `Deploy to GitHub Pages` workflow manually).

Manual deploy is also available:

```bash
npm run deploy
```

## 6. Part of the Crypto-Lab Suite

Part of [crypto-lab](https://systemslibrarian.github.io/crypto-lab/) — browser-based cryptography demos spanning 2,500 years of cryptographic history to NIST FIPS 2024 post-quantum standards.

---

*So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*