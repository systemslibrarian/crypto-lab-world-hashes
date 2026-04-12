import './styles.css';

import { kupyna256, kupyna512 } from '@li0ard/kupyna';
import { streebog256, streebog512 } from '@li0ard/streebog';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { sha3_256, sha3_512 } from '@noble/hashes/sha3.js';
import { sm3 as sm3Hash } from 'sm-crypto';

type TabId = 'sm3' | 'streebog' | 'kupyna' | 'anchors' | 'decision';
type InputMode = 'text' | 'hex';
type DigestSize = 256 | 512;

type CopyState = {
  key: string;
  status: 'idle' | 'copied' | 'error';
};

const state: {
  activeTab: TabId;
  sm3: { input: string; mode: InputMode };
  streebog: { input: string; mode: InputMode; size: DigestSize };
  kupyna: { input: string; mode: InputMode; size: DigestSize };
  anchors: { input: string; mode: InputMode };
  copyState: CopyState;
} = {
  activeTab: 'sm3',
  sm3: {
    input: 'Sovereign standards still need strong engineering discipline.',
    mode: 'text'
  },
  streebog: {
    input: 'Compliance can force algorithm choice even when trust is debated.',
    mode: 'text',
    size: 256
  },
  kupyna: {
    input: 'Cryptographic independence can be a national policy objective.',
    mode: 'text',
    size: 256
  },
  anchors: {
    input: 'One message, five standards, five distinct digests.',
    mode: 'text'
  },
  copyState: {
    key: '',
    status: 'idle'
  }
};

const encoder = new TextEncoder();

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
}

function normalizeHex(input: string): string {
  return input.replace(/\s+/g, '').toLowerCase();
}

function parseInput(input: string, mode: InputMode): { ok: true; bytes: Uint8Array } | { ok: false; error: string } {
  if (mode === 'text') {
    return { ok: true, bytes: encoder.encode(input) };
  }

  const normalized = normalizeHex(input);
  if (normalized.length === 0) {
    return { ok: true, bytes: new Uint8Array(0) };
  }
  if (normalized.length % 2 !== 0) {
    return { ok: false, error: 'Hex input must contain an even number of characters.' };
  }
  if (!/^[0-9a-f]+$/i.test(normalized)) {
    return { ok: false, error: 'Hex input may only contain 0-9 and a-f.' };
  }

  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
  }
  return { ok: true, bytes };
}

function mutateInput(input: string, mode: InputMode): string {
  if (mode === 'text') {
    if (input.length === 0) {
      return 'a';
    }
    const last = input[input.length - 1];
    const next = last === 'a' ? 'b' : 'a';
    return `${input.slice(0, -1)}${next}`;
  }

  const normalized = normalizeHex(input);
  if (normalized.length === 0) {
    return '00';
  }
  const firstNibble = normalized[0];
  const replacement = firstNibble === '0' ? '1' : '0';
  return `${replacement}${normalized.slice(1)}`;
}

function sm3DigestHex(bytes: Uint8Array): string {
  return sm3Hash(bytes);
}

function sha256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

function sha512Hex(bytes: Uint8Array): string {
  return bytesToHex(sha512(bytes));
}

function sha3_256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha3_256(bytes));
}

function sha3_512Hex(bytes: Uint8Array): string {
  return bytesToHex(sha3_512(bytes));
}

function streebogHex(bytes: Uint8Array, size: DigestSize): string {
  return size === 256 ? bytesToHex(streebog256(bytes)) : bytesToHex(streebog512(bytes));
}

function kupynaHex(bytes: Uint8Array, size: DigestSize): string {
  return size === 256 ? bytesToHex(kupyna256(bytes)) : bytesToHex(kupyna512(bytes));
}

function changedHexBits(a: string, b: string): number {
  const maxLength = Math.max(a.length, b.length);
  let changed = 0;
  for (let i = 0; i < maxLength; i += 1) {
    const x = Number.parseInt(a[i] ?? '0', 16);
    const y = Number.parseInt(b[i] ?? '0', 16);
    const diff = x ^ y;
    changed += ((diff & 1) !== 0 ? 1 : 0)
      + ((diff & 2) !== 0 ? 1 : 0)
      + ((diff & 4) !== 0 ? 1 : 0)
      + ((diff & 8) !== 0 ? 1 : 0);
  }
  return changed;
}

function copyButton(resultKey: string, value: string): string {
  const copied = state.copyState.key === resultKey && state.copyState.status === 'copied';
  const errored = state.copyState.key === resultKey && state.copyState.status === 'error';
  const label = copied ? 'Copied' : errored ? 'Copy failed' : 'Copy';
  return `<button class="copy-btn" data-copy-key="${resultKey}" data-copy-value="${value}">${label}</button>`;
}

function hashRow(title: string, digest: string, key: string): string {
  return `
    <div class="card">
      <div class="result-header">
        <strong>${title}</strong>
        ${copyButton(key, digest)}
      </div>
      <div class="digest-block">${digest}</div>
    </div>
  `;
}

function renderSm3Exhibit(): string {
  const parsed = parseInput(state.sm3.input, state.sm3.mode);
  if (!parsed.ok) {
    return `<div class="panel"><h2>Exhibit 1 — SM3 (China)</h2><p class="callout warn">${parsed.error}</p></div>`;
  }

  const original = parsed.bytes;
  const mutatedInput = mutateInput(state.sm3.input, state.sm3.mode);
  const mutatedParsed = parseInput(mutatedInput, state.sm3.mode);
  if (!mutatedParsed.ok) {
    return `<div class="panel"><h2>Exhibit 1 — SM3 (China)</h2><p class="callout warn">${mutatedParsed.error}</p></div>`;
  }

  const sm3Digest = sm3DigestHex(original);
  const shaDigest = sha256Hex(original);
  const sm3Mutated = sm3DigestHex(mutatedParsed.bytes);
  const shaMutated = sha256Hex(mutatedParsed.bytes);

  return `
    <div class="grid-2">
      <div class="panel">
        <h2>Exhibit 1 — SM3 (China)</h2>
        <p class="muted small">
          <strong>SM3</strong> is standardized in <strong>GM/T 0004-2012</strong>, <strong>GB/T 32905-2016</strong>, and ISO/IEC 10118-3.
          It is a 256-bit Merkle-Damgard hash with a 512-bit message block and 64 rounds.
        </p>
        <label for="sm3-mode">Input mode</label>
        <select id="sm3-mode">
          <option value="text" ${state.sm3.mode === 'text' ? 'selected' : ''}>Text</option>
          <option value="hex" ${state.sm3.mode === 'hex' ? 'selected' : ''}>Hex</option>
        </select>
        <label for="sm3-input">Input</label>
        <textarea id="sm3-input">${escapeHtml(state.sm3.input)}</textarea>
        <div class="button-row">
          <button class="primary" data-focus-result="sm3-result">Hash with SM3</button>
          <button data-focus-result="sm3-sha-result">Hash with SHA-256</button>
        </div>
        <div id="sm3-result">${hashRow('SM3 (256-bit)', sm3Digest, 'sm3')}</div>
        <div id="sm3-sha-result">${hashRow('SHA-256 (256-bit)', shaDigest, 'sha256')}</div>
      </div>
      <div class="panel">
        <h3>Construction comparison: SM3 vs SHA-256</h3>
        <div class="diagram">
          <div class="diagram-row">
            <div class="diagram-node">SM3: 512-bit block</div>
            <div class="diagram-arrow">→</div>
            <div class="diagram-node">SM3 compression (64 rounds, distinct expansion)</div>
          </div>
          <div class="diagram-row">
            <div class="diagram-node">SHA-256: 512-bit block</div>
            <div class="diagram-arrow">→</div>
            <div class="diagram-node">SHA-256 compression (64 rounds, SSIG schedule)</div>
          </div>
        </div>
        <div class="callout" style="margin-top: 0.8rem;">
          <strong>Design transparency note:</strong> SM3 design rationale is partially published. Wang Xiaoyun's team has strong cryptanalytic credibility,
          but full design criteria are not as openly documented as the AES process.
        </div>
        <div class="callout good" style="margin-top: 0.8rem;">
          <strong>Why this matters:</strong> SM3 is required in Chinese regulated environments with SM2 signatures and TLCP deployments.
          Engineers shipping into China need practical SM3 interoperability.
        </div>
      </div>
    </div>
    <div class="panel" style="margin-top: 1rem;">
      <h3>Avalanche demo (single-character change)</h3>
      <p class="small muted">Original input: <code>${escapeHtml(state.sm3.input)}</code></p>
      <p class="small muted">Modified input: <code>${escapeHtml(mutatedInput)}</code></p>
      <div class="grid-2">
        <div class="card">
          <strong>SM3</strong>
          <div class="digest-block">${sm3Digest}</div>
          <div class="digest-block">${sm3Mutated}</div>
          <p class="small">Changed bits: <strong>${changedHexBits(sm3Digest, sm3Mutated)}</strong> / 256</p>
        </div>
        <div class="card">
          <strong>SHA-256</strong>
          <div class="digest-block">${shaDigest}</div>
          <div class="digest-block">${shaMutated}</div>
          <p class="small">Changed bits: <strong>${changedHexBits(shaDigest, shaMutated)}</strong> / 256</p>
        </div>
      </div>
    </div>
  `;
}

function renderStreebogExhibit(): string {
  const parsed = parseInput(state.streebog.input, state.streebog.mode);
  if (!parsed.ok) {
    return `<div class="panel"><h2>Exhibit 2 — Streebog (Russia)</h2><p class="callout warn">${parsed.error}</p></div>`;
  }

  const currentSize = state.streebog.size;
  const streebogDigest = streebogHex(parsed.bytes, currentSize);
  const referenceDigest = currentSize === 256 ? sha256Hex(parsed.bytes) : sha512Hex(parsed.bytes);
  const changedInput = mutateInput(state.streebog.input, state.streebog.mode);
  const changedParsed = parseInput(changedInput, state.streebog.mode);
  if (!changedParsed.ok) {
    return `<div class="panel"><h2>Exhibit 2 — Streebog (Russia)</h2><p class="callout warn">${changedParsed.error}</p></div>`;
  }

  const streebogChanged = streebogHex(changedParsed.bytes, currentSize);
  const referenceChanged = currentSize === 256 ? sha256Hex(changedParsed.bytes) : sha512Hex(changedParsed.bytes);

  return `
    <div class="grid-2">
      <div class="panel">
        <h2>Exhibit 2 — Streebog (Russia)</h2>
        <p class="muted small">
          <strong>GOST R 34.11-2012</strong> (Streebog) replaced GOST R 34.11-94 and defines 256-bit and 512-bit digests.
          It uses a wide-pipe Merkle-Damgard structure with Miyaguchi-Preneel style compression.
        </p>
        <label for="streebog-mode">Input mode</label>
        <select id="streebog-mode">
          <option value="text" ${state.streebog.mode === 'text' ? 'selected' : ''}>Text</option>
          <option value="hex" ${state.streebog.mode === 'hex' ? 'selected' : ''}>Hex</option>
        </select>
        <label for="streebog-input">Input</label>
        <textarea id="streebog-input">${escapeHtml(state.streebog.input)}</textarea>
        <label for="streebog-size">Output size</label>
        <select id="streebog-size">
          <option value="256" ${currentSize === 256 ? 'selected' : ''}>256-bit</option>
          <option value="512" ${currentSize === 512 ? 'selected' : ''}>512-bit</option>
        </select>
        ${hashRow(`Streebog-${currentSize}`, streebogDigest, `streebog-${currentSize}`)}
        ${hashRow(currentSize === 256 ? 'SHA-256' : 'SHA-512', referenceDigest, `streebog-ref-${currentSize}`)}
      </div>
      <div class="panel">
        <h3>Mandatory S-box connection note</h3>
        <div class="callout warn">
          Streebog uses the same S-box as Kuznyechik. In 2019, L\'eo Perrin and co-authors documented hidden structure in that S-box inconsistent
          with random generation. The same S-box controversy from Kuznyechik applies here. Use Streebog only when Russian compliance requires it.
        </div>
        <p class="small">
          See the related Kuznyechik discussion in World Ciphers Exhibit 4:
          <a href="https://systemslibrarian.github.io/crypto-lab-world-ciphers/" target="_blank" rel="noreferrer">crypto-lab-world-ciphers</a>
        </p>
        <div class="callout good">
          <strong>Why this matters:</strong> Russian regulated systems and digital signature workflows may mandate Streebog-256 or Streebog-512
          with GOST R 34.10-2012 signature profiles.
        </div>
      </div>
    </div>
    <div class="panel" style="margin-top: 1rem;">
      <h3>Avalanche demo</h3>
      <div class="grid-2">
        <div class="card">
          <strong>Streebog-${currentSize}</strong>
          <div class="digest-block">${streebogDigest}</div>
          <div class="digest-block">${streebogChanged}</div>
          <p class="small">Changed bits: <strong>${changedHexBits(streebogDigest, streebogChanged)}</strong> / ${currentSize}</p>
        </div>
        <div class="card">
          <strong>${currentSize === 256 ? 'SHA-256' : 'SHA-512'}</strong>
          <div class="digest-block">${referenceDigest}</div>
          <div class="digest-block">${referenceChanged}</div>
          <p class="small">Changed bits: <strong>${changedHexBits(referenceDigest, referenceChanged)}</strong> / ${currentSize}</p>
        </div>
      </div>
    </div>
  `;
}

function renderKupynaExhibit(): string {
  const parsed = parseInput(state.kupyna.input, state.kupyna.mode);
  if (!parsed.ok) {
    return `<div class="panel"><h2>Exhibit 3 — Kupyna (Ukraine)</h2><p class="callout warn">${parsed.error}</p></div>`;
  }

  const currentSize = state.kupyna.size;
  const kupynaDigest = kupynaHex(parsed.bytes, currentSize);
  const sha3Digest = currentSize === 256 ? sha3_256Hex(parsed.bytes) : sha3_512Hex(parsed.bytes);

  const changedInput = mutateInput(state.kupyna.input, state.kupyna.mode);
  const changedParsed = parseInput(changedInput, state.kupyna.mode);
  if (!changedParsed.ok) {
    return `<div class="panel"><h2>Exhibit 3 — Kupyna (Ukraine)</h2><p class="callout warn">${changedParsed.error}</p></div>`;
  }
  const kupynaChanged = kupynaHex(changedParsed.bytes, currentSize);
  const sha3Changed = currentSize === 256 ? sha3_256Hex(changedParsed.bytes) : sha3_512Hex(changedParsed.bytes);

  return `
    <div class="grid-2">
      <div class="panel">
        <h2>Exhibit 3 — Kupyna (Ukraine)</h2>
        <p class="muted small">
          <strong>DSTU 7564:2014</strong> defines Kupyna as Ukraine\'s national hash standard with 256-bit and 512-bit variants.
          It uses a permutation-driven sponge-like wide-pipe design instead of Merkle-Damgard chaining.
        </p>
        <label for="kupyna-mode">Input mode</label>
        <select id="kupyna-mode">
          <option value="text" ${state.kupyna.mode === 'text' ? 'selected' : ''}>Text</option>
          <option value="hex" ${state.kupyna.mode === 'hex' ? 'selected' : ''}>Hex</option>
        </select>
        <label for="kupyna-input">Input</label>
        <textarea id="kupyna-input">${escapeHtml(state.kupyna.input)}</textarea>
        <label for="kupyna-size">Output size</label>
        <select id="kupyna-size">
          <option value="256" ${currentSize === 256 ? 'selected' : ''}>256-bit</option>
          <option value="512" ${currentSize === 512 ? 'selected' : ''}>512-bit</option>
        </select>
        ${hashRow(`Kupyna-${currentSize}`, kupynaDigest, `kupyna-${currentSize}`)}
        ${hashRow(currentSize === 256 ? 'SHA-3-256' : 'SHA-3-512', sha3Digest, `kupyna-ref-${currentSize}`)}
      </div>
      <div class="panel">
        <h3>Construction distinction panel</h3>
        <ul>
          <li>Kupyna and SHA-3 both use permutation-based sponge families.</li>
          <li>Kupyna uses a dedicated permutation (10 rounds in its base round structure).</li>
          <li>SHA-3 uses Keccak-f[1600] with 24 rounds of theta, rho, pi, chi, and iota.</li>
          <li>Kupyna emphasizes efficient hardware and 64-bit software implementation without lookup tables.</li>
        </ul>
        <div class="callout">
          <strong>Geopolitical context:</strong> DSTU 7564:2014 was standardized in the same year Russia annexed Crimea.
          Ukraine\'s migration away from Russian GOST profiles is a concrete example of cryptographic sovereignty.
        </div>
        <div class="callout good" style="margin-top: 0.8rem;">
          <strong>Why this matters:</strong> Kupyna is both a technical primitive and a policy statement about standards independence.
        </div>
      </div>
    </div>
    <div class="panel" style="margin-top: 1rem;">
      <h3>Avalanche demo</h3>
      <div class="grid-2">
        <div class="card">
          <strong>Kupyna-${currentSize}</strong>
          <div class="digest-block">${kupynaDigest}</div>
          <div class="digest-block">${kupynaChanged}</div>
          <p class="small">Changed bits: <strong>${changedHexBits(kupynaDigest, kupynaChanged)}</strong> / ${currentSize}</p>
        </div>
        <div class="card">
          <strong>${currentSize === 256 ? 'SHA-3-256' : 'SHA-3-512'}</strong>
          <div class="digest-block">${sha3Digest}</div>
          <div class="digest-block">${sha3Changed}</div>
          <p class="small">Changed bits: <strong>${changedHexBits(sha3Digest, sha3Changed)}</strong> / ${currentSize}</p>
        </div>
      </div>
    </div>
  `;
}

function renderAnchorsExhibit(): string {
  const parsed = parseInput(state.anchors.input, state.anchors.mode);
  if (!parsed.ok) {
    return `<div class="panel"><h2>Exhibit 4 — SHA-256 and SHA-3 Anchors</h2><p class="callout warn">${parsed.error}</p></div>`;
  }

  const digests = {
    'SHA-256': sha256Hex(parsed.bytes),
    'SHA-3-256': sha3_256Hex(parsed.bytes),
    SM3: sm3DigestHex(parsed.bytes),
    'Streebog-256': streebogHex(parsed.bytes, 256),
    'Kupyna-256': kupynaHex(parsed.bytes, 256)
  };

  const changedInput = mutateInput(state.anchors.input, state.anchors.mode);
  const changedParsed = parseInput(changedInput, state.anchors.mode);
  if (!changedParsed.ok) {
    return `<div class="panel"><h2>Exhibit 4 — SHA-256 and SHA-3 Anchors</h2><p class="callout warn">${changedParsed.error}</p></div>`;
  }

  const changedDigests = {
    'SHA-256': sha256Hex(changedParsed.bytes),
    'SHA-3-256': sha3_256Hex(changedParsed.bytes),
    SM3: sm3DigestHex(changedParsed.bytes),
    'Streebog-256': streebogHex(changedParsed.bytes, 256),
    'Kupyna-256': kupynaHex(changedParsed.bytes, 256)
  };

  const outputCards = Object.entries(digests)
    .map(([name, digest]) => hashRow(name, digest, `anchors-${name}`))
    .join('');

  const avalancheRows = Object.entries(digests)
    .map(([name, digest]) => {
      const changed = changedDigests[name as keyof typeof changedDigests];
      return `<tr><td>${name}</td><td>${changedHexBits(digest, changed)} / 256</td></tr>`;
    })
    .join('');

  return `
    <div class="grid-2">
      <div class="panel">
        <h2>Exhibit 4 — SHA-256 and SHA-3 as Reference Anchors</h2>
        <label for="anchors-mode">Input mode</label>
        <select id="anchors-mode">
          <option value="text" ${state.anchors.mode === 'text' ? 'selected' : ''}>Text</option>
          <option value="hex" ${state.anchors.mode === 'hex' ? 'selected' : ''}>Hex</option>
        </select>
        <label for="anchors-input">Input</label>
        <textarea id="anchors-input">${escapeHtml(state.anchors.input)}</textarea>
        <p class="small muted">One input, five real digests: SHA-256, SHA-3-256, SM3, Streebog-256, Kupyna-256.</p>
      </div>
      <div class="panel">
        <h3>Reference summary</h3>
        <ul>
          <li><strong>SHA-256</strong> — FIPS 180-4, Merkle-Damgard, 64 rounds, widely deployed in TLS and software signing.</li>
          <li><strong>SHA-3</strong> — FIPS 202, sponge construction over Keccak-f[1600], 24 rounds, open competition lineage.</li>
        </ul>
      </div>
    </div>
    <div class="grid-2" style="margin-top: 1rem;">${outputCards}</div>
    <div class="panel" style="margin-top: 1rem;">
      <h3>Five-way avalanche snapshot</h3>
      <p class="small muted">Modified input used for comparison: <code>${escapeHtml(changedInput)}</code></p>
      <table class="comparison-table">
        <thead><tr><th>Algorithm</th><th>Changed bits after one edit</th></tr></thead>
        <tbody>${avalancheRows}</tbody>
      </table>
    </div>
  `;
}

function renderDecisionExhibit(): string {
  return `
    <div class="panel">
      <h2>Exhibit 5 — Five-Way Comparison and Decision Tree</h2>
      <div class="compare-table-wrap">
        <table class="comparison-table">
          <thead>
            <tr>
              <th>Property</th>
              <th>SM3</th>
              <th>Streebog-256/512</th>
              <th>Kupyna-256/512</th>
              <th>SHA-256</th>
              <th>SHA-3-256</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>Country</td><td>China</td><td>Russia</td><td>Ukraine</td><td>USA (NIST)</td><td>USA (NIST)</td></tr>
            <tr><td>Year</td><td>2010</td><td>2012</td><td>2014</td><td>2001</td><td>2015</td></tr>
            <tr><td>Output sizes</td><td>256-bit</td><td>256 / 512-bit</td><td>256 / 512-bit</td><td>256-bit</td><td>224/256/384/512</td></tr>
            <tr><td>Construction</td><td>Merkle-Damgard</td><td>Wide-pipe MD</td><td>Sponge-like</td><td>Merkle-Damgard</td><td>Sponge</td></tr>
            <tr><td>ISO standardized</td><td>Yes</td><td>Yes</td><td>No (DSTU)</td><td>Yes</td><td>Yes</td></tr>
            <tr><td>Design transparency</td><td>Partial</td><td>S-box opaque concern</td><td>Published</td><td>Published</td><td>Published</td></tr>
            <tr><td>Known practical breaks</td><td>None publicly known</td><td>None publicly known</td><td>None publicly known</td><td>None publicly known</td><td>None publicly known</td></tr>
            <tr><td>Use when</td><td>China compliance</td><td>Russian GOST compliance</td><td>Ukrainian DSTU compliance</td><td>General use</td><td>New designs</td></tr>
            <tr><td>Trust level</td><td>Medium-High</td><td>Use with caution</td><td>High</td><td>High</td><td>High</td></tr>
          </tbody>
        </table>
      </div>
    </div>
    <div class="grid-2" style="margin-top: 1rem;">
      <div class="panel">
        <h3>Decision tree</h3>
        <ol class="decision-list">
          <li>I need a hash for general-purpose use → SHA-256 or SHA-3-256.</li>
          <li>I am operating under Chinese Cryptography Law or Chinese PKI → SM3.</li>
          <li>I need Russian GOST R 34.11-2012 compliance → Streebog (with S-box caveat).</li>
          <li>I need Ukrainian DSTU 7564:2014 compliance → Kupyna.</li>
          <li>I am building a new protocol without compliance constraints → SHA-3 or BLAKE3.</li>
        </ol>
      </div>
      <div class="panel">
        <h3>Cross-demo links</h3>
        <ul>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-world-ciphers/" target="_blank" rel="noreferrer">World Ciphers</a></li>
          <li><a href="https://systemslibrarian.github.io/crypto-compare/" target="_blank" rel="noreferrer">Crypto Compare</a></li>
          <li><a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" target="_blank" rel="noreferrer">Babel Hash</a></li>
        </ul>
      </div>
    </div>
  `;
}

function render(): void {
  const app = document.querySelector<HTMLDivElement>('#app');
  if (!app) {
    throw new Error('Missing #app mount node');
  }

  const theme = document.documentElement.getAttribute('data-theme') ?? 'dark';
  const toggleEmoji = theme === 'dark' ? '☀️' : '🌙';
  const toggleLabel = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';

  app.innerHTML = `
    <main class="app-shell" id="main-content">
      <header class="hero">
        <button class="theme-toggle" id="theme-toggle" aria-label="${toggleLabel}" title="${toggleLabel}">${toggleEmoji}</button>
        <div class="hero-badges">
          <span class="badge">National Hash Standards</span>
          <span class="badge">SM3 · Streebog · Kupyna</span>
          <span class="badge">SHA-256 · SHA-3 Reference</span>
        </div>
        <h1>crypto-lab-world-hashes</h1>
        <p>
          SHA-256 and SHA-3 are global defaults, but nations also standardize domestic hashes for sovereignty and regulation.
          This lab compares SM3, Streebog, and Kupyna side by side with real digest output.
        </p>
      </header>

      <nav class="tabs" aria-label="Exhibit tabs">
        <button class="tab-button ${state.activeTab === 'sm3' ? 'active' : ''}" data-tab-target="sm3">1. SM3</button>
        <button class="tab-button ${state.activeTab === 'streebog' ? 'active' : ''}" data-tab-target="streebog">2. Streebog</button>
        <button class="tab-button ${state.activeTab === 'kupyna' ? 'active' : ''}" data-tab-target="kupyna">3. Kupyna</button>
        <button class="tab-button ${state.activeTab === 'anchors' ? 'active' : ''}" data-tab-target="anchors">4. Anchors</button>
        <button class="tab-button ${state.activeTab === 'decision' ? 'active' : ''}" data-tab-target="decision">5. Comparison</button>
      </nav>

      <section class="tab-panel ${state.activeTab === 'sm3' ? 'active' : ''}">${renderSm3Exhibit()}</section>
      <section class="tab-panel ${state.activeTab === 'streebog' ? 'active' : ''}">${renderStreebogExhibit()}</section>
      <section class="tab-panel ${state.activeTab === 'kupyna' ? 'active' : ''}">${renderKupynaExhibit()}</section>
      <section class="tab-panel ${state.activeTab === 'anchors' ? 'active' : ''}">${renderAnchorsExhibit()}</section>
      <section class="tab-panel ${state.activeTab === 'decision' ? 'active' : ''}">${renderDecisionExhibit()}</section>
    </main>
  `;
}

async function copyDigest(copyKey: string, value: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(value);
    state.copyState = { key: copyKey, status: 'copied' };
  } catch {
    state.copyState = { key: copyKey, status: 'error' };
  }
  render();
  window.setTimeout(() => {
    if (state.copyState.key === copyKey) {
      state.copyState = { key: '', status: 'idle' };
      render();
    }
  }, 1200);
}

function wireEvents(): void {
  document.addEventListener('click', (event) => {
    const target = event.target as HTMLElement | null;
    if (!target) {
      return;
    }

    if (target instanceof HTMLButtonElement && target.id === 'theme-toggle') {
      const currentTheme = document.documentElement.getAttribute('data-theme') ?? 'dark';
      const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', nextTheme);
      localStorage.setItem('theme', nextTheme);
      const nextEmoji = nextTheme === 'dark' ? '☀️' : '🌙';
      const nextLabel = nextTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
      target.textContent = nextEmoji;
      target.setAttribute('aria-label', nextLabel);
      target.setAttribute('title', nextLabel);
      render();
      return;
    }

    const tab = target.closest<HTMLButtonElement>('[data-tab-target]');
    if (tab?.dataset.tabTarget) {
      state.activeTab = tab.dataset.tabTarget as TabId;
      render();
      return;
    }

    const copy = target.closest<HTMLButtonElement>('[data-copy-key]');
    if (copy) {
      const key = copy.dataset.copyKey ?? '';
      const value = copy.dataset.copyValue ?? '';
      void copyDigest(key, value);
      return;
    }
  });

  document.addEventListener('input', (event) => {
    const target = event.target as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null;
    if (!target) {
      return;
    }

    if (target.id === 'sm3-input') {
      state.sm3.input = target.value;
      render();
      return;
    }
    if (target.id === 'sm3-mode') {
      state.sm3.mode = target.value as InputMode;
      render();
      return;
    }

    if (target.id === 'streebog-input') {
      state.streebog.input = target.value;
      render();
      return;
    }
    if (target.id === 'streebog-mode') {
      state.streebog.mode = target.value as InputMode;
      render();
      return;
    }
    if (target.id === 'streebog-size') {
      state.streebog.size = Number.parseInt(target.value, 10) as DigestSize;
      render();
      return;
    }

    if (target.id === 'kupyna-input') {
      state.kupyna.input = target.value;
      render();
      return;
    }
    if (target.id === 'kupyna-mode') {
      state.kupyna.mode = target.value as InputMode;
      render();
      return;
    }
    if (target.id === 'kupyna-size') {
      state.kupyna.size = Number.parseInt(target.value, 10) as DigestSize;
      render();
      return;
    }

    if (target.id === 'anchors-input') {
      state.anchors.input = target.value;
      render();
      return;
    }
    if (target.id === 'anchors-mode') {
      state.anchors.mode = target.value as InputMode;
      render();
    }
  });
}

function boot(): void {
  render();
  wireEvents();
}

boot();
