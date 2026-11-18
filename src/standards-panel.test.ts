// @vitest-environment happy-dom
import { beforeAll, describe, expect, it } from 'vitest';

// Importing main.ts boots the app against the DOM, so the mount node must
// exist first.
beforeAll(async () => {
  document.documentElement.setAttribute('data-theme', 'dark');
  document.body.innerHTML = '<div id="app"></div>';
  await import('./main');
});

const squash = (text: string | null | undefined): string => (text ?? '').replace(/\s+/g, ' ').trim();

// render() rebuilds #app on every state change, so always look the panel up again.
const panel = (): HTMLElement => {
  const node = document.querySelector<HTMLElement>('#national-standards');
  if (!node) throw new Error('the national-standards panel did not render');
  return node;
};

const open = (target: string): void => {
  document.querySelector<HTMLButtonElement>(`[data-tab-target="${target}"]`)?.click();
};

describe('national-standards panel', () => {
  it('is the seventh tab, hidden until selected', () => {
    const tabs = Array.from(document.querySelectorAll('[role="tab"]')).map((t) => t.id);
    expect(tabs).toEqual(['tab-sm3', 'tab-streebog', 'tab-kupyna', 'tab-anchors', 'tab-break', 'tab-decision', 'tab-standards']);

    open('sm3');
    const section = document.querySelector<HTMLElement>('#panel-standards');
    expect(section?.getAttribute('role')).toBe('tabpanel');
    expect(section?.getAttribute('aria-labelledby')).toBe('tab-standards');
    expect(section?.hasAttribute('hidden')).toBe(true);

    open('standards');
    expect(document.querySelector('#panel-standards')?.hasAttribute('hidden')).toBe(false);
    expect(document.querySelector('#tab-standards')?.getAttribute('aria-selected')).toBe('true');
    expect(panel().closest('#panel-standards')).not.toBeNull();
    // Exactly one panel is visible, as for every other tab.
    expect(document.querySelectorAll('.tab-panel:not([hidden])')).toHaveLength(1);
  });

  it('carries a dated status line', () => {
    open('standards');
    const status = squash(panel().querySelector('#standards-status')?.textContent);
    expect(status).toContain('As of November 2026');
    expect(status).toContain('first round');
    expect(status).toContain('Nothing in round one is standardized or deployed');
  });

  it('has one table row for each of hash, block cipher and signature', () => {
    open('standards');
    const rows = Array.from(panel().querySelectorAll('tbody tr th[scope="row"]')).map((th) => th.textContent);
    expect(rows).toEqual(['Hash', 'Block cipher', 'Signature']);
    // The signature row is text only, and says so.
    expect(squash(panel().querySelector('tbody tr:last-child')?.textContent)).toContain('Neither is implemented in this lab');
  });

  it('prints counts that add up to the totals it prints', () => {
    open('standards');
    const text = squash(panel().textContent);
    const candidates = /119 first-round candidates are published: (\d+) hash functions, (\d+) signature schemes, (\d+) key-encapsulation mechanisms and (\d+) key-exchange schemes/.exec(text);
    expect(candidates, 'the candidate breakdown is on the page').not.toBeNull();
    const [hash, sign, kem, kex] = candidates!.slice(1).map(Number);
    expect(hash + sign + kem + kex).toBe(119);

    const families = /The (\d+) public-key candidates come from the families other post-quantum efforts use: (\d+) lattice-based, (\d+) code-based, (\d+) multivariate, (\d+) isogeny-based, (\d+) hash-based signatures, (\d+) symmetric \(VOLE-in-the-head\) and (\d+) other group action/.exec(text);
    expect(families, 'the family breakdown is on the page').not.toBeNull();
    const [publicKey, ...byFamily] = families!.slice(1).map(Number);
    expect(publicKey).toBe(sign + kem + kex);
    expect(byFamily.reduce((a, b) => a + b, 0)).toBe(publicKey);
  });

  it('labels commentary as commentary and links the sources it names', () => {
    open('standards');
    expect(squash(panel().textContent)).toContain('Those two points are commentary, not ICCS statements.');
    const links = Array.from(panel().querySelectorAll<HTMLAnchorElement>('a[href^="http"]')).map((a) => a.href);
    expect(links).toContain('https://niccs.org.cn/niccs/Notice/pc/content/content_1975896137741635584.html');
    expect(links).toContain('https://pqc-security.org/countries/china');
    expect(links.some((href) => href.includes('crypto-lab-sm2-forge'))).toBe(true);
    expect(links.some((href) => href.includes('eprint.iacr.org'))).toBe(false);
  });

  it('leaves the other exhibits working after it has been opened', () => {
    open('standards');
    open('sm3');
    expect(document.querySelector('#panel-standards')?.hasAttribute('hidden')).toBe(true);
    expect(document.querySelector('#sm3-result .digest-block')?.textContent).toMatch(/^[0-9a-f]{64}$/);
  });
});
