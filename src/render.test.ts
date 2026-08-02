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
  it('mounts the five exhibit tabs', () => {
    const tabs = document.querySelectorAll('[role="tab"]');
    expect(tabs).toHaveLength(5);
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
