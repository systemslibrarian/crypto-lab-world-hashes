import { expect, test } from '@playwright/test';

test('Kupyna is presented as wide-pipe chaining and contrasted with SHA-3 sponge', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-kupyna').click();

  const panel = page.locator('#panel-kupyna');
  await expect(panel).toContainText('wide-pipe Merkle–Damgård');
  await expect(panel).toContainText('It is not a sponge');
  await expect(panel).toContainText('SHA-3 is the sponge in this comparison');
  await expect(
    panel.locator('[aria-label^="Wide-pipe Merkle–Damgård construction"]'),
  ).toBeVisible();

  await page.locator('#tab-anchors').click();
  await expect(page.locator('#panel-anchors')).toContainText(
    'SHA-3 is the only sponge in this lab',
  );
});
