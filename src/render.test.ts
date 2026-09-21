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

describe('LSH is presented as wide-pipe, and hashed live', () => {
  it('appears in the anchors exhibit with a real digest', () => {
    document.querySelector<HTMLButtonElement>('[data-tab-target="anchors"]')?.click();
    const panel = document.getElementById('panel-anchors');
    expect(panel?.textContent).toContain('LSH-256');
    const card = Array.from(panel?.querySelectorAll('.card') ?? []).find((c) =>
      c.textContent?.includes('LSH-256'),
    );
    expect(card?.querySelector('.digest-block')?.textContent).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('Bash is presented as a sponge, alongside SHA-3 rather than instead of it', () => {
  it('names both sponges in the anchors exhibit and hashes Bash live', () => {
    document.querySelector<HTMLButtonElement>('[data-tab-target="anchors"]')?.click();
    const panel = document.getElementById('panel-anchors');
    expect(panel?.textContent).toContain('Bash-256');
    // The claim this replaced ("SHA-3 is the only sponge in this lab") stopped
    // being true the moment Bash landed.
    expect(panel?.textContent).toContain('SHA-3 and Bash are the two');
    expect(panel?.textContent).not.toContain('only sponge');
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
    // Six since LSH joined SHA-3, Bash, Kupyna, Streebog and HMAC (was five).
    expect(rows).toHaveLength(6);
    for (const row of rows) {
      expect(row.querySelector('[data-resist-outcome]')?.getAttribute('data-resist-outcome')).toBe('held');
    }
    const body = document.getElementById('break-resist-body');
    expect(body?.querySelector('[data-resist-row="kupyna256"]')?.textContent).toContain('Wide-pipe');
    expect(body?.querySelector('[data-resist-row="sha3-256"]')?.textContent).toContain('Sponge');
    expect(body?.querySelector('[data-resist-row="bash256"]')?.textContent).toContain('Sponge');
    expect(body?.querySelector('[data-resist-row="lsh256"]')?.textContent).toContain('Wide-pipe');
  });

  it('presents Bash as needing no countermeasure, not as defending itself', () => {
    const bash = document.querySelector('[data-resist-row="bash256"]');
    // The honesty rule this guards: Bash must never be shown carrying an
    // MD-style defence it does not have.
    expect(bash?.querySelector('[data-countermeasure]')?.getAttribute('data-countermeasure')).toBe(
      'none',
    );
    // …while the constructions that DO add a mechanism are marked as such, so
    // "none" is a distinction the table can actually draw. LSH is one of them:
    // it folds its 512-bit chaining variable in half before output.
    for (const id of ['kupyna256', 'streebog256', 'lsh256']) {
      expect(
        document
          .querySelector(`[data-resist-row="${id}"] [data-countermeasure]`)
          ?.getAttribute('data-countermeasure'),
      ).toBe('added');
    }
  });

  it('backs the negative claim with computed bit counts, not prose', () => {
    const claim = document.querySelector('[data-negative-claim]');
    expect(claim?.getAttribute('data-negative-claim')).toBe('no-countermeasure');

    // Re-derive the withheld-bits figures from the geometry the page prints,
    // rather than trusting the sentence around them.
    const read = (id: string): number =>
      Number.parseInt(document.getElementById(id)?.textContent?.trim() ?? '', 10);
    expect(read('claim-immune-withheld')).toBe(read('claim-immune-state') - 256);
    expect(read('claim-forgeable-withheld')).toBe(read('claim-forgeable-state') - 256);
    // Bash withholds most of its state; SHA-256 withholds none, which is the
    // whole reason one is forged above and the other cannot be entered.
    expect(read('claim-immune-withheld')).toBe(1280);
    expect(read('claim-forgeable-withheld')).toBe(0);
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
