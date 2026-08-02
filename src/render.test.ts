// @vitest-environment happy-dom
import { beforeAll, describe, expect, it } from 'vitest';

import { TEST_VECTORS } from './hashes';

// Importing main.ts boots the app against the DOM, so the mount node must
// exist first.
beforeAll(async () => {
  document.documentElement.setAttribute('data-theme', 'dark');
  document.body.innerHTML = '<div id="app"></div>';
  await import('./main');
});

describe('initial render', () => {
  // Six since the "Break it" attack lab landed (was five).
  it('mounts the six exhibit tabs', () => {
    const tabs = document.querySelectorAll('[role="tab"]');
    expect(tabs).toHaveLength(6);
    expect(document.querySelector('#tab-break')?.textContent).toContain('Break it');
  });

  it('shows the live self-test trust badge with all vectors passing', () => {
    const badge = document.querySelector('.badge-verified');
    expect(badge).not.toBeNull();
    expect(badge?.textContent).toContain(`${TEST_VECTORS.length}/${TEST_VECTORS.length}`);
    expect(document.querySelector('.badge-failed')).toBeNull();
  });

  it('renders a real SM3 digest in the default panel', () => {
    const digest = document.querySelector('#sm3-result .digest-block');
    expect(digest?.textContent).toMatch(/^[0-9a-f]{64}$/);
  });

  it('highlights changed nibbles in the avalanche comparison', () => {
    const highlighted = document.querySelectorAll('.nibble-changed');
    expect(highlighted.length).toBeGreaterThan(0);
  });

  it('reports input byte length', () => {
    expect(document.querySelector('.byte-count')?.textContent).toMatch(/Input length/);
  });
});

describe('known-answer verification panel', () => {
  it('lists every test vector with a passing status', () => {
    // The decision/comparison panel is rendered for all tabs; switch to it.
    const comparisonTab = document.querySelector<HTMLButtonElement>('[data-tab-target="decision"]');
    comparisonTab?.click();
    const passes = document.querySelectorAll('.kat-table .kat-pass');
    expect(passes).toHaveLength(TEST_VECTORS.length);
    expect(document.querySelectorAll('.kat-table .kat-fail')).toHaveLength(0);
  });
});

describe('Kupyna construction accuracy', () => {
  it('identifies Kupyna as wide-pipe Merkle–Damgård rather than a sponge', () => {
    const kupynaTab = document.querySelector<HTMLButtonElement>('[data-tab-target="kupyna"]');
    kupynaTab?.click();

    const panel = document.getElementById('panel-kupyna');
    expect(panel?.textContent).toContain('wide-pipe');
    expect(panel?.textContent).toContain('Merkle–Damgård');
    expect(panel?.textContent).toContain('not a sponge');
    expect(
      panel?.querySelector('[aria-label^="Wide-pipe Merkle–Damgård construction"]'),
    ).not.toBeNull();
  });
});

describe('the Break-it attack lab renders only computed verdicts', () => {
  it('claims nothing before an attack is run', () => {
    document.querySelector<HTMLButtonElement>('[data-tab-target="break"]')?.click();
    const panel = document.getElementById('panel-break');
    expect(panel?.textContent).toContain('no forgery is claimed');
    expect(panel?.textContent).toContain('no collision is claimed');
    expect(panel?.querySelector('[data-attack-result]')).toBeNull();
    expect(panel?.querySelector('[data-collision-verdict]')).toBeNull();
  });

  it('states the cross-check against the audited libraries on the page', () => {
    const panel = document.getElementById('panel-break');
    // The reimplemented compression functions must be reported as agreeing.
    expect(panel?.querySelector('.kat-pass')?.textContent).toMatch(/\d+\/\d+ agree/);
    expect(panel?.textContent).toContain('never passed the secret');
  });

  it('forges when the attack is run, and says which tag matched', () => {
    document.querySelector<HTMLButtonElement>('#break-run')?.click();
    const result = document.querySelector('[data-attack-result]');
    expect(result?.getAttribute('data-attack-result')).toBe('forged');
    const forged = document.querySelector('#attack-forged-tag')?.textContent ?? '';
    const server = document.querySelector('#attack-server-tag')?.textContent ?? '';
    expect(forged).toMatch(/^[0-9a-f]{64}$/);
    expect(server).toBe(forged);
  });

  it('fails visibly when the learner guesses the wrong secret length', () => {
    document.querySelector<HTMLButtonElement>('#break-run-wrong')?.click();
    const result = document.querySelector('[data-attack-result]');
    expect(result?.getAttribute('data-attack-result')).toBe('not-forged');
    expect(result?.textContent).toContain('NOT FORGED');
    const forged = document.querySelector('#attack-forged-tag')?.textContent ?? '';
    const server = document.querySelector('#attack-server-tag')?.textContent ?? '';
    expect(forged).not.toBe(server);
  });

  it('shows the resistant constructions holding, each from a real attempt', () => {
    document.querySelector<HTMLButtonElement>('#break-run-resistant')?.click();
    const rows = document.querySelectorAll('[data-resist-row]');
    expect(rows).toHaveLength(4);
    for (const row of rows) {
      expect(row.querySelector('[data-resist-outcome]')?.getAttribute('data-resist-outcome')).toBe('held');
    }
    const body = document.getElementById('break-resist-body');
    expect(body?.querySelector('[data-resist-row="kupyna256"]')?.textContent).toContain('Wide-pipe');
    expect(body?.querySelector('[data-resist-row="sha3-256"]')?.textContent).toContain('Sponge');
  });

  it('finds a verified truncated collision and refuses to claim one on a starved budget', () => {
    document.querySelector<HTMLButtonElement>('#collision-run')?.click();
    expect(
      document.querySelector('[data-collision-verdict]')?.getAttribute('data-collision-verdict'),
    ).toBe('collision');
    expect(document.getElementById('collision-hashes')?.textContent).toMatch(/[\d,]+/);

    document.querySelector<HTMLButtonElement>('#collision-run-starved')?.click();
    const verdict = document.querySelector('[data-collision-verdict]');
    expect(verdict?.getAttribute('data-collision-verdict')).toBe('exhausted');
    expect(verdict?.textContent).toContain('No collision in 50 hashes');
  });
});
