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
  intro: { input: string };
  sm3: { input: string; mode: InputMode; flip: number | null };
  streebog: { input: string; mode: InputMode; size: DigestSize };
  kupyna: { input: string; mode: InputMode; size: DigestSize };
  anchors: { input: string; mode: InputMode };
  copyState: CopyState;
} = {
  activeTab: 'sm3',
  intro: {
    input: 'hash me'
  },
  sm3: {
    input: 'Sovereign standards still need strong engineering discipline.',
    mode: 'text',
    // Index of the character the learner has chosen to flip in the avalanche
    // demo. null = flip the last character (the default, one-character edit).
    flip: null
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

/**
 * Flip exactly one character of `input` at `index` (default: the last character),
 * returning the mutated string. Used by the interactive avalanche demo so the
 * learner picks which single character changes and watches the digest re-scramble.
 * The replacement is deterministic and always differs from the original char.
 */
function flipCharAt(input: string, index: number | null): { mutated: string; index: number } {
  if (input.length === 0) {
    return { mutated: 'a', index: 0 };
  }
  const i = index === null || index < 0 || index >= input.length ? input.length - 1 : index;
  const c = input[i];
  // Nudge to a visibly different, still-printable character. Letters toggle
  // case-ish (a<->b, others +1); everything else flips to '#'/'~'.
  const replacement = c === 'a' ? 'b' : c === 'A' ? 'B' : c === ' ' ? '_' : c === '#' ? '~' : '#';
  return { mutated: `${input.slice(0, i)}${replacement}${input.slice(i + 1)}`, index: i };
}

/**
 * A clickable strip of the input characters. Clicking a character selects it as
 * the single byte to flip; the currently-flipped one is marked. Keyboard users
 * get real <button>s. This turns the avalanche from a pre-baked readout into
 * something the learner causes themselves.
 */
function flipStrip(input: string, flipIndex: number): string {
  const chars = Array.from(input);
  const cells = chars
    .map((c, i) => {
      const display = c === ' ' ? '␣' : escapeHtml(c);
      const selected = i === flipIndex;
      return `<button type="button" class="flip-cell${selected ? ' flip-cell-active' : ''}"
        data-flip-index="${i}" aria-pressed="${selected}"
        aria-label="Flip character ${i + 1}${c === ' ' ? ' (space)' : `: ${c}`}">${display}</button>`;
    })
    .join('');
  return `<div class="flip-strip" role="group" aria-label="Click a character to flip it">${cells}</div>`;
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

/**
 * Inline jargon gloss. Wraps a term in a native <abbr> with a title tooltip and
 * a dotted underline cue, so the definition is one hover/long-press away and is
 * also read by screen readers via the expanded title. Definitions are kept to
 * one plain-English line — the full contrast lives in "Constructions 101".
 */
const GLOSSARY: Record<string, string> = {
  'Merkle-Damgard':
    'Merkle–Damgård: build a hash by splitting the message into fixed blocks and chaining each block through a compression function, carrying a running state forward.',
  'Merkle–Damgård':
    'Merkle–Damgård: build a hash by splitting the message into fixed blocks and chaining each block through a compression function, carrying a running state forward.',
  sponge:
    'Sponge: absorb the message into one big internal state a few bytes at a time, then squeeze the digest back out of that state. The state is larger than the output, so the final chaining value is never exposed.',
  'wide-pipe':
    'Wide-pipe: keep an internal state that is wider (more bits) than the final digest, then truncate at the end. The extra width makes internal collisions harder to reach.',
  'S-box':
    'S-box (substitution box): a small fixed lookup table that non-linearly scrambles bytes. Its internal structure is a classic place to hide — or accidentally leak — weaknesses.',
  'Miyaguchi-Preneel':
    'Miyaguchi–Preneel: a standard recipe for turning a block cipher into a compression function by XOR-mixing the input block, the cipher output, and the previous state.',
  'Keccak-f[1600]':
    'Keccak-f[1600]: the 1600-bit permutation at the heart of SHA-3 — 24 rounds of five steps (θ, ρ, π, χ, ι) that stir the whole sponge state.',
  'length-extension':
    'Length-extension: given only H(secret‖message) and the length, an attacker can compute H(secret‖message‖padding‖extra) without knowing the secret — a Merkle–Damgård hazard sponges avoid.'
};

function gloss(term: string, display?: string): string {
  const def = GLOSSARY[term];
  const shown = display ?? term;
  if (!def) return escapeHtml(shown);
  return `<abbr class="gloss" tabindex="0" title="${escapeHtml(def)}">${escapeHtml(shown)}</abbr>`;
}

/**
 * Exhibit 0 — the ground floor. Defines what a hash IS in plain language and
 * demonstrates all four properties live: the learner types anything and watches
 * the digest stay a fixed length while looking random and one-way. Every later
 * exhibit is anchored to this baseline.
 */
function renderIntroExhibit(): string {
  const bytes = encoder.encode(state.intro.input);
  const digest = sha256Hex(bytes);
  // Second live digest of a near-identical input, to show determinism +
  // unpredictability at once: same input → identical digest; tiny change → total scramble.
  const nudged = state.intro.input + '!';
  const nudgedDigest = sha256Hex(encoder.encode(nudged));
  const nudgedDiff = changedHexBits(digest, nudgedDigest);
  const nudgedPct = ((nudgedDiff / 256) * 100).toFixed(0);
  const n = bytes.length;

  return `
    <section class="panel intro-panel" aria-labelledby="intro-heading">
      <h2 id="intro-heading">Start here — what is a cryptographic hash?</h2>
      <p class="small muted" style="max-width:70ch;">
        Everything below compares national <em>hash functions</em>. A cryptographic hash is a
        function that takes any input — a word, a file, a whole disk image — and returns a short
        fixed-size fingerprint called a <strong>digest</strong>. Four properties make it useful:
      </p>
      <div class="grid-2 prop-grid">
        <div class="prop-card"><span class="prop-tag">1 · Deterministic</span>
          <p class="small">The same input always gives the same digest. Hash it twice, get the same fingerprint — that is how you verify a download.</p></div>
        <div class="prop-card"><span class="prop-tag">2 · Fixed length</span>
          <p class="small">One byte or one gigabyte in, the digest is always the same size (256 bits here). The output length never grows with the input.</p></div>
        <div class="prop-card"><span class="prop-tag">3 · One-way</span>
          <p class="small">Easy to go input → digest, infeasible to go back. Given a digest, you cannot recover the input — the fingerprint reveals nothing about it.</p></div>
        <div class="prop-card"><span class="prop-tag">4 · Collision-resistant</span>
          <p class="small">No one can find two different inputs with the same digest. That is what lets a digest stand in for the data it fingerprints.</p></div>
      </div>

      <div class="intro-live">
        <label for="intro-input">Try it — type anything and watch the four properties hold</label>
        <textarea id="intro-input" rows="2" aria-describedby="intro-live-note">${escapeHtml(state.intro.input)}</textarea>
        <p id="intro-live-note" class="live-note"><span class="live-dot" aria-hidden="true"></span>Hashed live with SHA-256 in your browser.</p>
        <div class="card" role="status" aria-live="polite">
          <div class="result-header"><strong>SHA-256 digest</strong>
            <span class="badge fixed-len-badge">always 256 bits · 64 hex chars</span></div>
          <div class="digest-block">${digest}</div>
          <p class="small muted" style="margin:.4rem 0 0;">
            Your input is <strong>${n}</strong> ${n === 1 ? 'byte' : 'bytes'} (${n * 8} bits), yet the digest is
            <strong>always 256 bits</strong> — property 2. Type more and it will not get longer.
          </p>
        </div>
        <div class="card" style="margin-top:.7rem;">
          <div class="result-header"><strong>Now add one character:</strong> <code>${escapeHtml(nudged)}</code></div>
          <div class="digest-block">${diffDigestHtml(digest, nudgedDigest)}</div>
          <p class="small muted" style="margin:.4rem 0 0;">
            One extra <code>!</code> scrambled <strong>${nudgedDiff}/256</strong> bits (${nudgedPct}%) — the digest looks
            unrelated (one-wayness in action, property 3), yet re-typing the exact same text always returns the exact
            same fingerprint (property 1).
          </p>
        </div>
      </div>

      <details class="explainer">
        <summary>Why can't I just reverse it? (one-wayness &amp; collisions)</summary>
        <p class="small">
          A 256-bit digest has 2<sup>256</sup> possible values — more than there are atoms in the observable universe.
          Because the output is far smaller than the space of possible inputs, <em>collisions must exist</em> in theory,
          but the security goal is that no one can <strong>find</strong> one, nor find any input that maps to a chosen
          digest. Searching for a matching input by brute force would take longer than the age of the universe, which is
          exactly why a digest can safely stand in for the data. That is the property every algorithm below is judged on.
        </p>
      </details>
    </section>
  `;
}

/**
 * Merkle–Damgård mechanism diagram: message blocks M1..M3 flow into a
 * compression function f, each chaining the previous state forward (IV → h1 →
 * h2 → digest). The final state IS the digest — highlighted to motivate why
 * length-extension is possible. This is a labelled SVG, not decoration: it
 * shows the actual data flow the prose describes.
 */
function mdDiagram(): string {
  return `
    <figure class="mech" role="group" aria-label="Merkle–Damgård construction: message blocks chained through a compression function">
      <svg viewBox="0 0 640 150" class="mech-svg" role="img"
        aria-label="Three message blocks M1, M2, M3 each feed a compression function f. Each f also takes the previous chaining state, starting from the initialization vector, and outputs the next state. The final state after the last block is the digest and is exposed.">
        <defs>
          <marker id="md-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0 0L10 5L0 10z" fill="currentColor"/>
          </marker>
        </defs>
        <g class="mech-flow" font-size="13" text-anchor="middle">
          <!-- IV -->
          <rect class="mech-state" x="6" y="58" width="56" height="34" rx="6"/>
          <text x="34" y="80">IV</text>
          <!-- three f stages -->
          <g>
            <rect class="mech-msg" x="86" y="10" width="70" height="30" rx="6"/><text x="121" y="30">M1</text>
            <rect class="mech-f" x="86" y="56" width="70" height="38" rx="8"/><text x="121" y="80">f</text>
            <line class="mech-line" x1="62" y1="75" x2="86" y2="75" marker-end="url(#md-arrow)"/>
            <line class="mech-line" x1="121" y1="40" x2="121" y2="56" marker-end="url(#md-arrow)"/>
          </g>
          <g>
            <rect class="mech-msg" x="216" y="10" width="70" height="30" rx="6"/><text x="251" y="30">M2</text>
            <rect class="mech-f" x="216" y="56" width="70" height="38" rx="8"/><text x="251" y="80">f</text>
            <line class="mech-line" x1="156" y1="75" x2="216" y2="75" marker-end="url(#md-arrow)"/>
            <text x="186" y="70" class="mech-tag">h1</text>
            <line class="mech-line" x1="251" y1="40" x2="251" y2="56" marker-end="url(#md-arrow)"/>
          </g>
          <g>
            <rect class="mech-msg" x="346" y="10" width="70" height="30" rx="6"/><text x="381" y="30">M3</text>
            <rect class="mech-f" x="346" y="56" width="70" height="38" rx="8"/><text x="381" y="80">f</text>
            <line class="mech-line" x1="286" y1="75" x2="346" y2="75" marker-end="url(#md-arrow)"/>
            <text x="316" y="70" class="mech-tag">h2</text>
          </g>
          <!-- exposed digest -->
          <line class="mech-line" x1="416" y1="75" x2="470" y2="75" marker-end="url(#md-arrow)"/>
          <rect class="mech-digest" x="472" y="56" width="120" height="38" rx="8"/>
          <text x="532" y="80">digest = state</text>
        </g>
      </svg>
      <figcaption class="small muted">
        Blocks chain left-to-right; each compression <code>f</code> mixes a message block into the running state.
        The <strong>final state is handed out as the digest</strong> — so an attacker who knows it can keep chaining,
        which is the ${gloss('length-extension')} weakness.
      </figcaption>
    </figure>
  `;
}

/**
 * Sponge mechanism diagram: bytes are absorbed into a large state split into an
 * outer "rate" and a hidden "capacity", stirred by a permutation, then squeezed
 * out as the digest. The capacity is never output — visually the reason sponges
 * resist length-extension.
 */
function spongeDiagram(): string {
  return `
    <figure class="mech" role="group" aria-label="Sponge construction: absorb bytes into a wide state, then squeeze out the digest">
      <svg viewBox="0 0 640 170" class="mech-svg" role="img"
        aria-label="Message bytes are absorbed into the outer rate part of a wide state and stirred by a permutation P across several rounds. The inner capacity part is never exposed. The digest is then squeezed out of the rate. Because the capacity stays hidden, the final state is not revealed.">
        <defs>
          <marker id="sp-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0 0L10 5L0 10z" fill="currentColor"/>
          </marker>
        </defs>
        <g font-size="13" text-anchor="middle">
          <!-- absorb inputs -->
          <rect class="mech-msg" x="8" y="20" width="60" height="26" rx="6"/><text x="38" y="38">bytes</text>
          <line class="mech-line" x1="68" y1="33" x2="110" y2="33" marker-end="url(#sp-arrow)"/>
          <text x="120" y="14" class="mech-tag">absorb</text>
          <!-- state: rate + capacity, two permutation stages -->
          <g>
            <rect class="mech-rate" x="110" y="20" width="80" height="30" rx="5"/><text x="150" y="40">rate</text>
            <rect class="mech-cap" x="110" y="52" width="80" height="46" rx="5"/><text x="150" y="80" class="mech-cap-t">capacity</text>
            <rect class="mech-perm" x="200" y="20" width="46" height="78" rx="8"/><text x="223" y="63">P</text>
            <line class="mech-line" x1="190" y1="59" x2="200" y2="59" marker-end="url(#sp-arrow)"/>
          </g>
          <g>
            <rect class="mech-rate" x="256" y="20" width="80" height="30" rx="5"/><text x="296" y="40">rate</text>
            <rect class="mech-cap" x="256" y="52" width="80" height="46" rx="5"/><text x="296" y="80" class="mech-cap-t">capacity</text>
            <rect class="mech-perm" x="346" y="20" width="46" height="78" rx="8"/><text x="369" y="63">P</text>
            <line class="mech-line" x1="336" y1="59" x2="346" y2="59" marker-end="url(#sp-arrow)"/>
          </g>
          <!-- squeeze -->
          <text x="440" y="14" class="mech-tag">squeeze</text>
          <line class="mech-line" x1="392" y1="35" x2="430" y2="35" marker-end="url(#sp-arrow)"/>
          <rect class="mech-digest" x="432" y="20" width="120" height="30" rx="6"/><text x="492" y="40">digest</text>
          <line class="mech-line" x1="392" y1="75" x2="430" y2="75"/>
          <text x="500" y="79" class="mech-cap-t">capacity stays hidden</text>
        </g>
      </svg>
      <figcaption class="small muted">
        Bytes are absorbed into the <strong>rate</strong> and stirred by permutation <code>P</code>; the
        <strong>capacity</strong> half is never output. Because the full state is never revealed, there is nothing to
        extend — sponges resist ${gloss('length-extension')} by construction.
      </figcaption>
    </figure>
  `;
}

/**
 * Wide-pipe Merkle–Damgård mechanism diagram (Kupyna, Grøstl-style): message
 * blocks are still chained through a compression function, but the chaining
 * state is twice the digest width and is never output directly — a final
 * output transformation Ω truncates it. That truncation, not absorb/squeeze,
 * is why a wide-pipe hash resists length-extension.
 */
function widePipeDiagram(): string {
  return `
    <figure class="mech" role="group" aria-label="Wide-pipe Merkle–Damgård construction: blocks chained through a double-width state, then truncated by an output transformation">
      <svg viewBox="0 0 640 150" class="mech-svg" role="img"
        aria-label="Message blocks M1 and M2 each feed a compression function f together with the previous chaining state, starting from the initialization vector. The chaining state is twice the digest width. After the last block an output transformation truncates the wide state down to the digest, so the full internal state is never exposed.">
        <defs>
          <marker id="wp-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0 0L10 5L0 10z" fill="currentColor"/>
          </marker>
        </defs>
        <g class="mech-flow" font-size="13" text-anchor="middle">
          <rect class="mech-state" x="6" y="50" width="56" height="50" rx="6"/>
          <text x="34" y="80">IV</text>
          <g>
            <rect class="mech-msg" x="86" y="10" width="70" height="30" rx="6"/><text x="121" y="30">M1</text>
            <rect class="mech-f" x="86" y="50" width="70" height="50" rx="8"/><text x="121" y="80">f</text>
            <line class="mech-line" x1="62" y1="75" x2="86" y2="75" marker-end="url(#wp-arrow)"/>
            <line class="mech-line" x1="121" y1="40" x2="121" y2="50" marker-end="url(#wp-arrow)"/>
          </g>
          <g>
            <rect class="mech-msg" x="216" y="10" width="70" height="30" rx="6"/><text x="251" y="30">M2</text>
            <rect class="mech-f" x="216" y="50" width="70" height="50" rx="8"/><text x="251" y="80">f</text>
            <line class="mech-line" x1="156" y1="75" x2="216" y2="75" marker-end="url(#wp-arrow)"/>
            <text x="186" y="66" class="mech-tag">2n bits</text>
            <line class="mech-line" x1="251" y1="40" x2="251" y2="50" marker-end="url(#wp-arrow)"/>
          </g>
          <!-- wide state carried into the output transformation, never exposed -->
          <line class="mech-line" x1="286" y1="75" x2="346" y2="75" marker-end="url(#wp-arrow)"/>
          <text x="316" y="66" class="mech-tag">2n bits</text>
          <rect class="mech-cap" x="346" y="50" width="110" height="50" rx="8"/>
          <text x="401" y="72" class="mech-cap-t">output</text>
          <text x="401" y="90" class="mech-cap-t">transform &#937;</text>
          <line class="mech-line" x1="456" y1="75" x2="500" y2="75" marker-end="url(#wp-arrow)"/>
          <rect class="mech-digest" x="502" y="56" width="120" height="38" rx="8"/>
          <text x="562" y="80">digest = n bits</text>
        </g>
      </svg>
      <figcaption class="small muted">
        Blocks still chain left-to-right, but the running state is <strong>twice the digest width</strong> and the
        output transformation <code>&#937;</code> truncates it. Because the full internal state is never handed out,
        there is nothing for an attacker to keep chaining from — no ${gloss('length-extension')}.
      </figcaption>
    </figure>
  `;
}

function renderSm3Exhibit(): string {
  const parsed = parseInput(state.sm3.input, state.sm3.mode);
  if (!parsed.ok) {
    return `<div class="panel"><h2>Exhibit 1 — SM3 (China)</h2><p class="callout warn">${parsed.error}</p></div>`;
  }

  const original = parsed.bytes;
  // Interactive avalanche: the learner picks which single character to flip (or
  // the last one by default). In hex mode we fall back to the automatic
  // one-nibble flip since there is no clean per-character strip for raw hex.
  const interactive = state.sm3.mode === 'text';
  let mutatedInput: string;
  let flipIndex = 0;
  if (interactive) {
    const flip = flipCharAt(state.sm3.input, state.sm3.flip);
    mutatedInput = flip.mutated;
    flipIndex = flip.index;
  } else {
    mutatedInput = mutateInput(state.sm3.input, state.sm3.mode);
  }
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
          It is a 256-bit ${gloss('Merkle-Damgard', 'Merkle–Damgård')} hash with a 512-bit message block and 64 rounds —
          the same block-chaining family as SHA-256.
        </p>
        <details class="explainer">
          <summary>Constructions 101 — block-chaining vs sponge (the distinction this whole demo turns on)</summary>
          <div class="constr-101">
            <div>
              <strong>Merkle–Damgård</strong> (SM3, SHA-256, and — in ${gloss('wide-pipe')} form —
              Streebog and Kupyna): chop the message into fixed blocks and chain each one through a
              <em>compression function</em>, carrying a running state forward. Simple and fast — and
              when the final state <em>is</em> handed out as the digest (SM3, SHA-256) that exposes it
              to ${gloss('length-extension')}. Wide-pipe designs keep an internal state wider than the
              digest and finalize before output, so there is no full state to extend from.
            </div>
            <div>
              <strong>Sponge</strong> (SHA-3): ${gloss('sponge', 'absorb')} the message into one
              big internal state a few bytes at a time, then <em>squeeze</em> the digest out of it.
              The state is wider than the output, so the final chaining value is never revealed —
              which is why sponges are immune to length-extension by construction.
            </div>
          </div>
        </details>
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
        <h3>How Merkle–Damgård actually works (SM3 &amp; SHA-256)</h3>
        <p class="small muted">Both hash the same way: split the message into 512-bit blocks and chain them through a compression function over 64 rounds. SM3 uses a distinct message expansion; SHA-256 uses its SSIG schedule — but the data flow is identical:</p>
        ${mdDiagram()}
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
      <h3>Avalanche demo — flip one character yourself</h3>
      <p class="small muted" style="max-width:72ch;">
        A good hash makes a 1-bit input change and a completely different digest indistinguishable from random.
        ${interactive
          ? 'Click any character below to flip it, then watch which output nibbles re-scramble and how far the diffusion meter moves.'
          : 'In hex mode the first nibble is flipped automatically; switch to Text mode to pick the character yourself.'}
      </p>
      ${interactive ? flipStrip(state.sm3.input, flipIndex) : ''}
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
          It uses a ${gloss('wide-pipe')} ${gloss('Merkle-Damgard', 'Merkle–Damgård')} structure with
          ${gloss('Miyaguchi-Preneel', 'Miyaguchi–Preneel')}-style compression built from an
          ${gloss('S-box')}-based block cipher — so like SM3 it chains blocks forward, but keeps a wider internal state.
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
        <h3>Mandatory ${gloss('S-box')} connection note</h3>
        <div class="callout warn">
          Streebog uses the same ${gloss('S-box')} as Kuznyechik. In 2019, Léo Perrin documented hidden structure in that S-box inconsistent
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
          It is a ${gloss('wide-pipe')} ${gloss('Merkle-Damgard', 'Merkle–Damgård')} design in the style of the SHA-3 finalist
          Grøstl: blocks <em>are</em> chained, but through a compression function built from two permutations
          (T<sup>⊕</sup> and T<sup>+</sup>, borrowed from the Kalyna block cipher) over a state twice the digest width,
          with a final output transformation that truncates it. It is not a ${gloss('sponge')} — the resistance to
          length-extension comes from the wide state and the output transformation, not from absorb-and-squeeze.
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
        <h3>How Kupyna actually works — wide-pipe chaining, not a sponge</h3>
        <p class="small muted">Kupyna does chain blocks, like SM3 and SHA-256 — but over a state twice the digest width, and it never hands that state out directly. A final output transformation truncates it:</p>
        ${widePipeDiagram()}
        <ul class="small">
          <li>Kupyna is a ${gloss('wide-pipe')} ${gloss('Merkle-Damgard', 'Merkle–Damgård')} hash, structurally close to the SHA-3 finalist Grøstl — <strong>not</strong> a ${gloss('sponge')}. SHA-3 is the sponge in this comparison; Kupyna is the wide-pipe alternative.</li>
          <li>Its compression step is <code>h<sub>i</sub> = T<sup>⊕</sup>(h<sub>i−1</sub> ⊕ m<sub>i</sub>) ⊕ T<sup>+</sup>(m<sub>i</sub>) ⊕ h<sub>i−1</sub></code>, built from two permutations taken from the Kalyna block cipher (DSTU 7624:2014).</li>
          <li>Kupyna-256 uses a 512-bit state with 10 rounds per permutation; Kupyna-512 uses a 1024-bit state with 14 rounds.</li>
          <li>SHA-3 uses ${gloss('Keccak-f[1600]')} with 24 rounds of θ (theta), ρ (rho), π (pi), χ (chi), and ι (iota).</li>
          <li>Both avoid ${gloss('length-extension')}, but for different reasons: SHA-3 never exposes the sponge capacity, while Kupyna truncates a doubled-width state in its output transformation.</li>
          <li>Kupyna targets efficient hardware and 64-bit software without large lookup tables.</li>
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
          <li><strong>SHA-256</strong> — FIPS 180-4, ${gloss('Merkle-Damgard', 'Merkle–Damgård')}, 64 rounds, widely deployed in TLS and software signing.</li>
          <li><strong>SHA-3</strong> — FIPS 202, ${gloss('sponge')} construction over ${gloss('Keccak-f[1600]')}, 24 rounds, open competition lineage.</li>
        </ul>
        <p class="small muted">SHA-3 is the only ${gloss('sponge')} in this lab — every other algorithm here chains blocks:</p>
        ${spongeDiagram()}
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
            <tr><th scope="row">Construction</th><td>Merkle-Damgard</td><td>Wide-pipe MD</td><td>Wide-pipe MD (Grostl-like)</td><td>Merkle-Damgard</td><td>Sponge</td></tr>
            <tr><th scope="row">ISO standardized</th><td>Yes</td><td>Yes</td><td>No (DSTU)</td><td>Yes</td><td>Yes</td></tr>
            <tr><th scope="row">Design transparency</th><td>Partial</td><td>S-box opaque concern</td><td>Published</td><td>Published</td><td>Published</td></tr>
            <tr><th scope="row">Known practical breaks</th><td>None publicly known</td><td>None publicly known</td><td>None publicly known</td><td>None publicly known</td><td>None publicly known</td></tr>
            <tr><th scope="row">Use when</th><td>China compliance</td><td>Russian GOST compliance</td><td>Ukrainian DSTU compliance</td><td>General use</td><td>New designs</td></tr>
            <tr><th scope="row">Trust level <span class="editorial-tag" title="Author's editorial judgment, not a measurement">opinion<sup>†</sup></span></th>
              <td>Medium-High<sup>a</sup></td><td>Use with caution<sup>b</sup></td><td>High<sup>c</sup></td><td>High<sup>d</sup></td><td>High<sup>d</sup></td></tr>
          </tbody>
        </table>
      </div>
      <p class="small muted" style="margin:.6rem 0 0;">
        <sup>†</sup> <strong>Trust level is editorial opinion, not a measured quantity.</strong> Every column above it
        (construction, output size, standardization) is a fact; these grades are one engineer's read of the published
        cryptanalysis and design transparency. Reasonable experts differ. The reasoning behind each:
      </p>
      <details class="explainer" style="margin-top:.5rem;">
        <summary>How each trust grade was derived</summary>
        <ul class="small trust-notes">
          <li><sup>a</sup> <strong>SM3 — Medium-High.</strong> No practical break; strong cryptanalytic pedigree (Wang Xiaoyun's team). Marked down only because the full design rationale is less openly documented than the AES/SHA-3 competition processes.</li>
          <li><sup>b</sup> <strong>Streebog — Use with caution.</strong> Perrin (2019) showed the shared Kuznyechik ${gloss('S-box')} has hidden structure inconsistent with random generation. No break follows from it, but unexplained structure in an opaque component is a design-trust red flag outside a compliance mandate.</li>
          <li><sup>c</sup> <strong>Kupyna — High.</strong> Public design, wide-pipe construction with an output transformation (no length-extension), no known practical weakness. Lower ecosystem/tooling maturity than SHA-2/3 is a practical, not a trust, caveat.</li>
          <li><sup>d</sup> <strong>SHA-256 / SHA-3 — High.</strong> Decades (SHA-256) or an open public competition (SHA-3) of scrutiny, fully published design, ubiquitous tooling.</li>
        </ul>
        <p class="small muted">Sources: L. Perrin, "Partitions in the S-Box of Streebog and Kuznyechik" (ToSC 2019); FIPS 180-4; FIPS 202; GM/T 0004-2012; DSTU 7564:2014.</p>
      </details>
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

      ${renderIntroExhibit()}

      <p class="section-lead small muted">Now compare how five real standards do it. Each exhibit hashes the same bytes and shows the avalanche effect — a good hash turns a tiny input change into a totally different digest.</p>

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

    const flip = target.closest<HTMLButtonElement>('[data-flip-index]');
    if (flip?.dataset.flipIndex) {
      state.sm3.flip = Number.parseInt(flip.dataset.flipIndex, 10);
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
    'intro-input': (v) => { state.intro.input = v; },
    'sm3-input': (v) => { state.sm3.input = v; state.sm3.flip = null; },
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
