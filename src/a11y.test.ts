// @vitest-environment happy-dom
import axe from 'axe-core';
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * Automated accessibility scan of the rendered app against WCAG 2.1 A/AA.
 *
 * Runs in happy-dom, so layout-dependent checks (notably `color-contrast`,
 * which needs a real rendering engine) report as "incomplete" rather than
 * "violation" — those are verified separately by hand/by contrast math. This
 * suite catches the structural failures: missing names, bad ARIA, unlabelled
 * controls, broken table semantics, duplicate ids, landmark problems, etc.
 */
async function scan(): Promise<axe.AxeResults> {
  return axe.run(document.documentElement, {
    runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'] }
  });
}

function summarize(violations: axe.Result[]): string {
  return violations
    .map((v) => `${v.id} (${v.impact}): ${v.nodes.length} node(s) — ${v.help}`)
    .join('\n');
}

beforeAll(async () => {
  // Mirror the real index.html document shell (lang + title) that the SPA mounts
  // into, since these tests replace document.body for the app root.
  document.documentElement.setAttribute('data-theme', 'dark');
  document.documentElement.lang = 'en';
  document.title = 'crypto-lab-world-hashes';
  document.body.innerHTML = '<div id="app"></div>';
  await import('./main');
});

describe('axe-core accessibility scan', () => {
  it('default exhibit (SM3) has no WCAG A/AA violations', async () => {
    const results = await scan();
    expect(summarize(results.violations)).toBe('');
  });

  it('comparison exhibit (tables + verification panel) has no violations', async () => {
    document.querySelector<HTMLButtonElement>('[data-tab-target="decision"]')?.click();
    const results = await scan();
    expect(summarize(results.violations)).toBe('');
  });

  it('light theme has no violations', async () => {
    document.documentElement.setAttribute('data-theme', 'light');
    document.querySelector<HTMLButtonElement>('[data-tab-target="anchors"]')?.click();
    const results = await scan();
    expect(summarize(results.violations)).toBe('');
    document.documentElement.setAttribute('data-theme', 'dark');
  });
});
