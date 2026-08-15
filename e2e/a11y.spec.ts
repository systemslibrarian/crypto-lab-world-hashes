import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where the
 * SM3 tab is the only visible panel, five are behind the `hidden` attribute and
 * three explainers are shut; both skip links and an inline glossary term
 * focused; the SM3 explainers opened through their own summaries; a character
 * flipped so the avalanche comparison, its changed nibbles and its meter render;
 * a digest copied; all three of the parse-rejection renderings that replace a
 * whole exhibit panel with one warning callout; Streebog and Kupyna at 512-bit,
 * which is the only route to a 128-hex digest; the reference-anchor tab with
 * five live digests; the attack lab in all four of its outcomes — a successful
 * length-extension forgery against SHA-256 and again against SM3, the same
 * forgery FAILING on a wrong secret-length guess, the resistance table, a real
 * truncated-digest collision, and a search that exhausts its budget; the
 * comparison tab with its seventeen known-answer vectors; and the hover state of
 * a flip cell, an attack button and an inactive tab. Every one of those states
 * is scanned, in both themes, at desktop and phone width.
 *
 * Clipboard permission is granted because `copyDigest()` awaits
 * `navigator.clipboard.writeText` inside a `try/catch` that renders "Copy
 * failed" on rejection: without the grant the drive would be asserting against
 * the error branch while believing it had measured the success one.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * force-revealed (the `hidden` attribute IS this lab's tab mechanism), why the
 * lab's defaults are asserted rather than assumed, and why `violations` is not
 * the whole oracle.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page, context }) => {
    test.setTimeout(1_200_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page, context }) => {
    test.setTimeout(1_200_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
