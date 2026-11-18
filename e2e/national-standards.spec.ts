import { expect, test } from '@playwright/test';

/**
 * The national-standards panel is the seventh tab. src/standards-panel.test.ts
 * checks its content in happy-dom. What needs a real browser is layout: the
 * tab must open from the keyboard as well as by click, its table must scroll
 * inside its own region at phone width, and opening it must not make the page
 * taller than the tallest exhibit already is.
 *
 * That last check is the reason this panel is a tab. The page background is two
 * radial washes sized by the document, so a panel that lengthened every state
 * moved the wash behind the tab bar and cost the tab borders their 3:1.
 */

for (const width of [1280, 380]) {
  test(`national-standards tab opens, fits and does not lengthen the page at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');

    const height = () => page.evaluate(() => document.documentElement.scrollHeight);

    // The tallest state the lab had before this tab: the Comparison exhibit.
    await page.locator('#tab-decision').click();
    await expect(page.locator('#panel-decision')).toBeVisible();
    const comparisonHeight = await height();

    // Reach the new tab from the keyboard: it is the next tab after Comparison.
    await page.locator('#tab-decision').press('ArrowRight');
    const panel = page.locator('#panel-standards #national-standards');
    await expect(panel).toBeVisible();
    await expect(page.locator('#tab-standards')).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#tab-standards')).toBeFocused();
    await expect(page.locator('.tab-panel:not([hidden])')).toHaveCount(1);
    await expect(panel.getByRole('heading', { level: 2 })).toContainText('National standards');
    await expect(page.locator('#standards-status')).toContainText('As of November 2026');

    expect(await height(), 'the new tab must not be the tallest state on the page').toBeLessThanOrEqual(comparisonHeight);

    // The table scrolls inside its own region; the page itself does not.
    const region = panel.getByRole('region', { name: /compared by family/ });
    await region.focus();
    await expect(region).toBeFocused();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);

    // And it is still there by click, from another exhibit.
    await page.locator('#tab-sm3').click();
    await expect(panel).toBeHidden();
    await page.locator('#tab-standards').click();
    await expect(panel).toBeVisible();
  });
}
