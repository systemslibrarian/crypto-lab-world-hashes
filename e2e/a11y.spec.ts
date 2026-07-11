import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the published KAT
 * vectors; this gates them on accessibility the same way. Scans every tab
 * panel with all live demos driven, in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

const TAB_IDS = ['sm3', 'streebog', 'kupyna', 'anchors', 'decision'];

// Neutralize animations/transitions/opacity so nothing is mid-flight while axe
// samples colours, and reveal any collapsed regions.
async function prep(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation:none !important;
      transition:none !important;
    }`,
  });
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal any class-hidden panels so their content is scanned.
    document
      .querySelectorAll('[hidden]')
      .forEach((el) => el.removeAttribute('hidden'));
  });
}

// Drive every tab so each dynamically-rendered exhibit (with its live digest
// output regions, tables, and avalanche cards) is present in the DOM.
async function driveAllTabs(page: Page): Promise<void> {
  for (const id of TAB_IDS) {
    await page.locator(`#tab-${id}`).click();
    await expect(page.locator(`#panel-${id}`)).toBeVisible();
    // Exercise the input so the live-recompute output regions populate.
    const input = page.locator(`#${id}-input`);
    if (await input.count()) {
      await input.fill('accessibility scan probe');
    }
  }
}

async function scan(page: Page): Promise<void> {
  await prep(page);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#app .app-shell')).toBeVisible();
  await driveAllTabs(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#app .app-shell')).toBeVisible();
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveAllTabs(page);
  await scan(page);
});
