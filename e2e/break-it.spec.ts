import { expect, test } from '@playwright/test';

/**
 * Blocking browser regressions for the Break-it attack lab.
 *
 * Every assertion is on a computed outcome: the forged tag is read out of the
 * page and compared against the server's tag rendered beside it, and the
 * collision search's verdict attribute is set from the search's own result.
 * Both the success and the learner-caused failure paths are covered.
 *
 * Statistical margin for the collision search: over eight independent batches
 * of 20 searches at 20 bits the batch mean ratio to the birthday expectation
 * ran 0.810 … 1.081. The browser spec asserts only that a verified collision is
 * found inside a 400,000-hash budget, which at 24 bits (expectation ≈ 5,100) is
 * an enormous margin; this spec was repeated 6x clean.
 */

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-break').click();
  await expect(page.locator('#panel-break')).toBeVisible();
});

test('the length-extension attack forges a tag without the secret', async ({ page }) => {
  // Nothing is claimed until something is run.
  await expect(page.locator('#break-output')).toContainText('no forgery is claimed');
  await expect(page.locator('[data-attack-result]')).toHaveCount(0);

  await page.locator('#break-run').click();

  const result = page.locator('[data-attack-result]');
  await expect(result).toHaveAttribute('data-attack-result', 'forged', { timeout: 30_000 });
  await expect(result).toContainText('FORGED');

  // The forged tag and the server's tag are the same 256-bit value.
  const forged = (await page.locator('#attack-forged-tag').textContent())?.trim() ?? '';
  const server = (await page.locator('#attack-server-tag').textContent())?.trim() ?? '';
  expect(forged).toMatch(/^[0-9a-f]{64}$/);
  expect(server).toBe(forged);
  // …and it is not simply the published tag echoed back.
  const known = (await page.locator('#attack-known-tag').textContent())?.trim() ?? '';
  expect(forged).not.toBe(known);

  // The suffix really is in the forged message, after reconstructed glue padding.
  await expect(page.locator('#break-output')).toContainText('&role=admin');
  await expect(page.locator('#break-output')).toContainText('\\x80');
});

test('the same attack works against SM3, not just SHA-256', async ({ page }) => {
  await page.locator('#break-algorithm').selectOption('sm3');
  await page.locator('#break-run').click();
  const result = page.locator('[data-attack-result]');
  await expect(result).toHaveAttribute('data-attack-result', 'forged', { timeout: 30_000 });
  const forged = (await page.locator('#attack-forged-tag').textContent())?.trim() ?? '';
  const server = (await page.locator('#attack-server-tag').textContent())?.trim() ?? '';
  expect(server).toBe(forged);
});

test('a wrong secret-length guess makes the forgery fail, and the page says why', async ({
  page,
}) => {
  await page.locator('#break-run-wrong').click();

  const result = page.locator('[data-attack-result]');
  await expect(result).toHaveAttribute('data-attack-result', 'not-forged', { timeout: 30_000 });
  await expect(result).toContainText('NOT FORGED');
  await expect(result).toContainText('guessed secret length was wrong');

  const forged = (await page.locator('#attack-forged-tag').textContent())?.trim() ?? '';
  const server = (await page.locator('#attack-server-tag').textContent())?.trim() ?? '';
  expect(forged).toMatch(/^[0-9a-f]{64}$/);
  expect(server).not.toBe(forged);

  // Correcting the guess restores the forgery.
  await page.locator('#break-length').fill('11');
  await page.locator('#break-run').click();
  await expect(result).toHaveAttribute('data-attack-result', 'forged', { timeout: 30_000 });
});

test('SHA-3, Kupyna, Streebog and HMAC all hold against the same attempt', async ({ page }) => {
  await page.locator('#break-run-resistant').click();

  const rows = page.locator('[data-resist-row]');
  await expect(rows).toHaveCount(4);
  for (const id of ['sha3-256', 'kupyna256', 'streebog256', 'hmac-sha256']) {
    const row = page.locator(`[data-resist-row="${id}"]`);
    await expect(row.locator('[data-resist-outcome]')).toHaveAttribute(
      'data-resist-outcome',
      'held',
    );
  }
  // The reasons name the actual constructions, and must not regress the
  // wide-pipe distinction this repo already guards (commit c5e7f01).
  await expect(page.locator('[data-resist-row="kupyna256"]')).toContainText(
    'Wide-pipe Merkle–Damgård',
  );
  await expect(page.locator('[data-resist-row="sha3-256"]')).toContainText('Sponge');
  await expect(page.locator('[data-resist-row="streebog256"]')).toContainText('checksum');
});

test('the truncated-collision search finds a verified collision', async ({ page }) => {
  await expect(page.locator('#collision-output')).toContainText('no collision is claimed');

  await page.locator('#collision-run').click();
  const verdict = page.locator('[data-collision-verdict]');
  await expect(verdict).toHaveAttribute('data-collision-verdict', 'collision', { timeout: 60_000 });
  await expect(verdict).toContainText('Collision found in');

  // The full digests differ — only the truncated prefix collides.
  const digestA = ((await page.locator('#collision-digest-a').textContent()) ?? '').trim();
  const digestB = ((await page.locator('#collision-digest-b').textContent()) ?? '').trim();
  expect(digestA).toMatch(/^[0-9a-f]{64}$/);
  expect(digestB).toMatch(/^[0-9a-f]{64}$/);
  expect(digestB).not.toBe(digestA);
  const bits = Number((await page.locator('#collision-bits').inputValue()) || '24');
  const sharedHexChars = Math.floor(bits / 4);
  expect(digestB.slice(0, sharedHexChars)).toBe(digestA.slice(0, sharedHexChars));
  await expect(page.locator('#collision-output')).toContainText('are different');

  const hashes = Number(
    ((await page.locator('#collision-hashes').textContent()) ?? '').replace(/[^\d]/g, ''),
  );
  expect(hashes).toBeGreaterThan(0);
  expect(hashes).toBeLessThanOrEqual(400_000);
});

test('a starved budget makes the search refuse to claim a collision', async ({ page }) => {
  await page.locator('#collision-bits').fill('32');
  await page.locator('#collision-run-starved').click();
  const verdict = page.locator('[data-collision-verdict]');
  await expect(verdict).toHaveAttribute('data-collision-verdict', 'exhausted', { timeout: 30_000 });
  await expect(verdict).toContainText('No collision in 50 hashes');
  await expect(verdict).toContainText('proves nothing either way');
});

test('changing an input clears the previous verdict rather than leaving it stale', async ({
  page,
}) => {
  await page.locator('#break-run').click();
  await expect(page.locator('[data-attack-result]')).toHaveAttribute(
    'data-attack-result',
    'forged',
    { timeout: 30_000 },
  );
  await page.locator('#break-suffix').fill('&role=root');
  await expect(page.locator('[data-attack-result]')).toHaveCount(0);
  await expect(page.locator('#break-output')).toContainText('no forgery is claimed');
});
