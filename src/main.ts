import './styles.css';

import { ALGORITHM_LABELS, computeHex, runSelfTest } from './hashes';
import type { SelfTestReport } from './hashes';

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

// Persisting the theme must never throw: localStorage access raises a
// SecurityError in sandboxed iframes and some private-browsing modes.
function saveTheme(theme: string): void {
  try {
    localStorage.setItem('theme', theme);
  } catch {
    /* storage unavailable — theme still applies for this session */
  }
}

// Run every known-answer test vector once, at load, against the same hashing
// code the UI uses. The result is surfaced as a trust badge in the hero so a
// visitor can see the live build matches the published standards.
const selfTest: SelfTestReport = runSelfTest();

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\"/g, '&quot;')
    .replace(/'/g, '&#39;');
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

// Thin wrappers over the single hashing source of truth in ./hashes, so the
// digests rendered here are produced by the exact code the test suite checks.
const sm3DigestHex = (bytes: Uint8Array): string => computeHex('sm3', bytes);
const sha256Hex = (bytes: Uint8Array): string => computeHex('sha256', bytes);
const sha512Hex = (bytes: Uint8Array): string => computeHex('sha512', bytes);
const sha3_256Hex = (bytes: Uint8Array): string => computeHex('sha3-256', bytes);
const sha3_512Hex = (bytes: Uint8Array): string => computeHex('sha3-512', bytes);
const streebogHex = (bytes: Uint8Array, size: DigestSize): string =>
  computeHex(size === 256 ? 'streebog256' : 'streebog512', bytes);
const kupynaHex = (bytes: Uint8Array, size: DigestSize): string =>
  computeHex(size === 256 ? 'kupyna256' : 'kupyna512', bytes);

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
  const label = copied ? 'Copied' : errored ? 'Copy failed' : 'Copy digest';
  const text = copied ? 'Copied' : errored ? 'Copy failed' : 'Copy';
  return `<button class="copy-btn" aria-label="${label}" data-copy-key="${escapeHtml(resultKey)}" data-copy-value="${escapeHtml(value)}">${text}</button>`;
}

function hashRow(title: string, digest: string, key: string): string {
  return `
    <div class="card" role="status" aria-live="polite">
      <div class="result-header">
        <strong>${title}</strong>
        ${copyButton(key, digest)}
      </div>
      <div class="digest-block">${digest}</div>
    </div>
  `;
}

/** Renders `compared`, highlighting every hex nibble that differs from `reference`. */
function diffDigestHtml(reference: string, compared: string): string {
  let out = '';
  for (let i = 0; i < compared.length; i += 1) {
    const char = compared[i];
    if (reference[i] === char) {
      out += char;
    } else {
      out += `<span class="nibble-changed">${char}</span>`;
    }
  }
  return out;
}

/**
 * Avalanche comparison card: original digest, the digest after a one-character
 * input change with changed nibbles highlighted, and the bit-diffusion stat.
 * A strong hash should flip close to 50% of output bits from a tiny input edit.
 */
function avalancheCard(label: string, original: string, mutated: string, bits: number): string {
  const changed = changedHexBits(original, mutated);
  const pct = (changed / bits) * 100;
  const pctText = pct.toFixed(1);
  return `
    <div class="card">
      <div class="result-header"><strong>${label}</strong></div>
      <div class="digest-block">${original}</div>
      <div class="digest-block">${diffDigestHtml(original, mutated)}</div>
      <div class="avalanche-meter" role="img"
        aria-label="${changed} of ${bits} bits changed, ${pctText} percent">
        <span class="avalanche-fill" style="width: ${Math.min(pct, 100)}%"></span>
        <span class="avalanche-ideal" aria-hidden="true"></span>
      </div>
      <p class="small muted">Changed bits: <strong>${changed}</strong> / ${bits}
        (<strong>${pctText}%</strong> · ideal ≈ 50%)</p>
    </div>
  `;
}

function byteCount(bytes: Uint8Array): string {
  const n = bytes.length;
  return `<p class="small muted byte-count">Input length: <strong>${n}</strong> ${n === 1 ? 'byte' : 'bytes'} · ${n * 8} bits</p>`;
}

/** Hero trust chip reporting the live known-answer self-test outcome. */
function verificationBadge(): string {
  const ok = selfTest.failed === 0;
  const cls = ok ? 'badge badge-verified' : 'badge badge-failed';
  const icon = ok ? '✓' : '✕';
  const text = ok
    ? `${selfTest.passed}/${selfTest.total} test vectors verified`
    : `${selfTest.failed}/${selfTest.total} vectors FAILED`;
  return `<span class="${cls}" title="Live known-answer self-test against the algorithms' defining standards">${icon} ${text}</span>`;
}

/** Full known-answer table: input → authoritative source → live pass/fail. */
function verificationPanel(): string {
  const rows = selfTest.results
    .map((r) => {
      const status = r.pass
        ? '<span class="kat-pass">✓ pass</span>'
        : '<span class="kat-fail">✕ fail</span>';
      return `<tr>
        <td><strong>${ALGORITHM_LABELS[r.vector.algorithm]}</strong></td>
        <td>${escapeHtml(r.vector.inputLabel)}</td>
        <td class="kat-source">${escapeHtml(r.vector.source)}</td>
        <td>${status}</td>
      </tr>`;
    })
    .join('');

  return `
    <div class="panel" style="margin-top: 1rem;">
      <h3>Known-answer verification</h3>
      <p class="small muted">
        Every digest in this lab is produced by the same module checked here. On load, the page recomputes
        ${selfTest.total} published test vectors and compares them byte-for-byte against the values in each
        algorithm's defining standard — <strong>${selfTest.passed}/${selfTest.total} passing</strong>.
      </p>
      <div class="compare-table-wrap">
        <table class="comparison-table kat-table">
          <thead><tr><th scope="col">Algorithm</th><th scope="col">Input</th><th scope="col">Source</th><th scope="col">Self-test</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
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
        ${byteCount(original)}
        <p class="live-note"><span class="live-dot" aria-hidden="true"></span>Digests recompute live as you type — both algorithms hash the same bytes.</p>
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
      <p class="small muted">Modified input: <code>${escapeHtml(mutatedInput)}</code> — <span class="nibble-changed">highlighted</span> nibbles differ from the original digest.</p>
      <div class="grid-2">
        ${avalancheCard('SM3', sm3Digest, sm3Mutated, 256)}
        ${avalancheCard('SHA-256', shaDigest, shaMutated, 256)}
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
        ${byteCount(parsed.bytes)}
        <p class="live-note"><span class="live-dot" aria-hidden="true"></span>Digests recompute live as you type.</p>
        ${hashRow(`Streebog-${currentSize}`, streebogDigest, `streebog-${currentSize}`)}
        ${hashRow(currentSize === 256 ? 'SHA-256' : 'SHA-512', referenceDigest, `streebog-ref-${currentSize}`)}
      </div>
      <div class="panel">
        <h3>Mandatory S-box connection note</h3>
        <div class="callout warn">
          Streebog uses the same S-box as Kuznyechik. In 2019, Léo Perrin and co-authors documented hidden structure in that S-box inconsistent
          with random generation. The same S-box controversy from Kuznyechik applies here. Use Streebog only when Russian GOST R 34.11-2012 compliance requires it.
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
      <p class="small muted"><span class="nibble-changed">Highlighted</span> nibbles differ after a one-character input change.</p>
      <div class="grid-2">
        ${avalancheCard(`Streebog-${currentSize}`, streebogDigest, streebogChanged, currentSize)}
        ${avalancheCard(currentSize === 256 ? 'SHA-256' : 'SHA-512', referenceDigest, referenceChanged, currentSize)}
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
          <strong>DSTU 7564:2014</strong> defines Kupyna as Ukraine's national hash standard with 256-bit and 512-bit variants.
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
        ${byteCount(parsed.bytes)}
        <p class="live-note"><span class="live-dot" aria-hidden="true"></span>Digests recompute live as you type.</p>
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
          Ukraine's migration away from Russian GOST profiles is a concrete example of cryptographic sovereignty.
        </div>
        <div class="callout good" style="margin-top: 0.8rem;">
          <strong>Why this matters:</strong> Kupyna is both a technical primitive and a policy statement about standards independence.
        </div>
      </div>
    </div>
    <div class="panel" style="margin-top: 1rem;">
      <h3>Avalanche demo</h3>
      <p class="small muted"><span class="nibble-changed">Highlighted</span> nibbles differ after a one-character input change.</p>
      <div class="grid-2">
        ${avalancheCard(`Kupyna-${currentSize}`, kupynaDigest, kupynaChanged, currentSize)}
        ${avalancheCard(currentSize === 256 ? 'SHA-3-256' : 'SHA-3-512', sha3Digest, sha3Changed, currentSize)}
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
      const bitsChanged = changedHexBits(digest, changed);
      const pct = ((bitsChanged / 256) * 100).toFixed(1);
      return `<tr><td>${name}</td><td>${bitsChanged} / 256</td><td>${pct}%</td></tr>`;
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
        ${byteCount(parsed.bytes)}
        <p class="live-note"><span class="live-dot" aria-hidden="true"></span>One input, five real digests, recomputed live: SHA-256, SHA-3-256, SM3, Streebog-256, Kupyna-256.</p>
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
      <p class="small muted">Modified input used for comparison: <code>${escapeHtml(changedInput)}</code> — a strong hash flips close to 50% of output bits.</p>
      <div class="compare-table-wrap">
        <table class="comparison-table">
          <thead><tr><th scope="col">Algorithm</th><th scope="col">Changed bits after one edit</th><th scope="col">Diffusion</th></tr></thead>
          <tbody>${avalancheRows}</tbody>
        </table>
      </div>
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
              <th scope="col">Property</th>
              <th scope="col">SM3</th>
              <th scope="col">Streebog-256/512</th>
              <th scope="col">Kupyna-256/512</th>
              <th scope="col">SHA-256</th>
              <th scope="col">SHA-3-256</th>
            </tr>
          </thead>
          <tbody>
            <tr><th scope="row">Country</th><td>China</td><td>Russia</td><td>Ukraine</td><td>USA (NIST)</td><td>USA (NIST)</td></tr>
            <tr><th scope="row">Year</th><td>2010</td><td>2012</td><td>2014</td><td>2001</td><td>2015</td></tr>
            <tr><th scope="row">Output sizes</th><td>256-bit</td><td>256 / 512-bit</td><td>256 / 512-bit</td><td>256-bit</td><td>224/256/384/512</td></tr>
            <tr><th scope="row">Construction</th><td>Merkle-Damgard</td><td>Wide-pipe MD</td><td>Sponge-like</td><td>Merkle-Damgard</td><td>Sponge</td></tr>
            <tr><th scope="row">ISO standardized</th><td>Yes</td><td>Yes</td><td>No (DSTU)</td><td>Yes</td><td>Yes</td></tr>
            <tr><th scope="row">Design transparency</th><td>Partial</td><td>S-box opaque concern</td><td>Published</td><td>Published</td><td>Published</td></tr>
            <tr><th scope="row">Known practical breaks</th><td>None publicly known</td><td>None publicly known</td><td>None publicly known</td><td>None publicly known</td><td>None publicly known</td></tr>
            <tr><th scope="row">Use when</th><td>China compliance</td><td>Russian GOST compliance</td><td>Ukrainian DSTU compliance</td><td>General use</td><td>New designs</td></tr>
            <tr><th scope="row">Trust level</th><td>Medium-High</td><td>Use with caution</td><td>High</td><td>High</td><td>High</td></tr>
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
    ${verificationPanel()}
  `;
}

function render(): void {
  const app = document.querySelector<HTMLDivElement>('#app');
  if (!app) {
    throw new Error('Missing #app mount node');
  }

  const activeEl = document.activeElement as HTMLElement | null;
  const focusId = activeEl?.id ?? '';
  let cursorStart = 0;
  let cursorEnd = 0;
  if (activeEl instanceof HTMLTextAreaElement || activeEl instanceof HTMLInputElement) {
    cursorStart = activeEl.selectionStart ?? 0;
    cursorEnd = activeEl.selectionEnd ?? 0;
  }

  const theme = document.documentElement.getAttribute('data-theme') ?? 'dark';
  const toggleEmoji = theme === 'dark' ? '☀️' : '🌙';
  const toggleLabel = theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';

  const tabs: Array<{ id: TabId; label: string }> = [
    { id: 'sm3', label: '1. SM3' },
    { id: 'streebog', label: '2. Streebog' },
    { id: 'kupyna', label: '3. Kupyna' },
    { id: 'anchors', label: '4. Anchors' },
    { id: 'decision', label: '5. Comparison' }
  ];

  const tabButtons = tabs.map((t) => {
    const active = state.activeTab === t.id;
    return `<button class="tab-button ${active ? 'active' : ''}"
      id="tab-${t.id}"
      role="tab"
      aria-selected="${active}"
      aria-controls="panel-${t.id}"
      tabindex="${active ? '0' : '-1'}"
      data-tab-target="${t.id}">${t.label}</button>`;
  }).join('');

  const panels: Record<TabId, string> = {
    sm3: renderSm3Exhibit(),
    streebog: renderStreebogExhibit(),
    kupyna: renderKupynaExhibit(),
    anchors: renderAnchorsExhibit(),
    decision: renderDecisionExhibit()
  };

  const panelSections = tabs.map((t) => {
    const active = state.activeTab === t.id;
    // Inactive panels use the native `hidden` attribute, which removes them from
    // both the accessibility tree and the tab order — avoiding the aria-hidden
    // anti-pattern of hiding a subtree that still contains focusable controls.
    return `<section id="panel-${t.id}" class="tab-panel ${active ? 'active' : ''}"
      role="tabpanel" aria-labelledby="tab-${t.id}" ${active ? '' : 'hidden'}>${panels[t.id]}</section>`;
  }).join('');

  app.innerHTML = `
    <main class="app-shell" id="main-content">
      <header class="cl-hero">
        <button class="theme-toggle" id="theme-toggle" aria-label="${toggleLabel}" title="${toggleLabel}">${toggleEmoji}</button>
        <div class="cl-hero-main">
          <h1 class="cl-hero-title">World Hashes</h1>
          <p class="cl-hero-sub">SM3 · Streebog · Kupyna · SHA-256 · SHA-3</p>
          <p class="cl-hero-desc">
            Hash the same input with three national standards and the SHA anchors side by side, and watch the avalanche effect flip half the output bits from a one-bit change.
          </p>
          <div class="hero-badges">
            <span class="badge">National Hash Standards</span>
            <span class="badge">SM3 · Streebog · Kupyna</span>
            <span class="badge">SHA-256 · SHA-3 Reference</span>
            ${verificationBadge()}
          </div>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label">WHY IT MATTERS</span>
          <p class="cl-hero-why-text">
            SHA-256 and SHA-3 dominate globally, yet China, Russia, and Ukraine mandate their own hashes for regulated systems. Knowing them is what lets you build, audit, or interoperate across sovereign compliance regimes.
          </p>
        </aside>
      </header>

      <nav class="tabs" role="tablist" aria-label="Exhibit tabs">
        ${tabButtons}
      </nav>

      ${panelSections}
    </main>
  `;

  if (focusId) {
    const restored = document.getElementById(focusId);
    if (restored) {
      restored.focus({ preventScroll: true });
      if (restored instanceof HTMLTextAreaElement || restored instanceof HTMLInputElement) {
        restored.setSelectionRange(cursorStart, cursorEnd);
      }
    }
  }
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
      saveTheme(nextTheme);
      // render() rebuilds the toggle button from the new theme (icon + label),
      // and restores focus to it by id.
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

  const inputHandlers: Record<string, (value: string) => void> = {
    'sm3-input': (v) => { state.sm3.input = v; },
    'sm3-mode': (v) => { state.sm3.mode = v as InputMode; },
    'streebog-input': (v) => { state.streebog.input = v; },
    'streebog-mode': (v) => { state.streebog.mode = v as InputMode; },
    'streebog-size': (v) => { state.streebog.size = Number.parseInt(v, 10) as DigestSize; },
    'kupyna-input': (v) => { state.kupyna.input = v; },
    'kupyna-mode': (v) => { state.kupyna.mode = v as InputMode; },
    'kupyna-size': (v) => { state.kupyna.size = Number.parseInt(v, 10) as DigestSize; },
    'anchors-input': (v) => { state.anchors.input = v; },
    'anchors-mode': (v) => { state.anchors.mode = v as InputMode; }
  };

  document.addEventListener('input', (event) => {
    const target = event.target as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null;
    const handler = target ? inputHandlers[target.id] : undefined;
    if (!target || !handler) {
      return;
    }
    handler(target.value);
    // Don't rebuild the DOM mid-IME-composition: recreating the textarea cancels
    // composition (e.g. typing Chinese for SM3). `isComposing` is read per-event,
    // so — unlike a persistent flag — it can never get stuck if a composition is
    // abandoned by blurring or switching tabs before it commits.
    if (!(event as InputEvent).isComposing) {
      render();
    }
  });

  // Composition committed — render once to reflect the final character.
  document.addEventListener('compositionend', () => {
    render();
  });

  document.addEventListener('keydown', (event) => {
    const target = event.target as HTMLElement | null;
    if (!target || target.getAttribute('role') !== 'tab') {
      return;
    }

    const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
    const currentIndex = tabs.indexOf(target as HTMLButtonElement);
    if (currentIndex === -1) {
      return;
    }

    let nextIndex: number | null = null;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      nextIndex = (currentIndex + 1) % tabs.length;
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    } else if (event.key === 'Home') {
      nextIndex = 0;
    } else if (event.key === 'End') {
      nextIndex = tabs.length - 1;
    }

    if (nextIndex !== null) {
      event.preventDefault();
      const tabId = tabs[nextIndex].dataset.tabTarget as TabId | undefined;
      if (tabId) {
        state.activeTab = tabId;
        render();
        // render() rebuilds the DOM, so the old tab nodes are detached. Focus the
        // freshly rendered tab by id (selection follows focus, per the ARIA tabs
        // automatic-activation pattern). preventScroll matches render()'s own
        // focus restore so keyboard navigation doesn't jerk the viewport.
        document.getElementById(`tab-${tabId}`)?.focus({ preventScroll: true });
      }
    }
  });
}

function boot(): void {
  render();
  wireEvents();
}

boot();
