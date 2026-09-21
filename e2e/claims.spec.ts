import { expect, test } from '@playwright/test';

/**
 * The claims suite (template §4.1b): does the page tell the truth?
 *
 * Where possible these compare two values the page itself printed, or
 * re-derive a claim from the page's own raw inputs by a different route than
 * the source takes — a test that merely restates the source's expression will
 * agree with a bug.
 */

test('Kupyna is presented as wide-pipe chaining and contrasted with the sponges', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#tab-kupyna').click();

  const panel = page.locator('#panel-kupyna');
  await expect(panel).toContainText('wide-pipe Merkle–Damgård');
  await expect(panel).toContainText('It is not a sponge');
  await expect(panel).toContainText('SHA-3 and Bash are the sponges in this comparison');
  await expect(
    panel.locator('[aria-label^="Wide-pipe Merkle–Damgård construction"]'),
  ).toBeVisible();

  await page.locator('#tab-anchors').click();
  const anchors = page.locator('#panel-anchors');
  await expect(anchors).toContainText('SHA-3 and Bash are the two');
  // The claim that stood here before Bash landed — "SHA-3 is the only sponge in
  // this lab" — became false the moment a second sponge joined the lineup. This
  // asserts it did not survive the edit.
  await expect(anchors).not.toContainText('only sponge');
});

test('Bash is hashed live, and its KAT row is sourced to the clause it comes from', async ({
  page,
}) => {
  await page.goto('.');

  // The badge count and the table it summarises must agree — a cross-check
  // between two surfaces, not an assertion against a number this test invents.
  const badge = (await page.locator('.badge-verified').textContent()) ?? '';
  const [, passed, total] = badge.match(/(\d+)\/(\d+) test vectors verified/) ?? [];
  expect(Number(passed)).toBe(Number(total));

  await page.locator('#tab-decision').click();
  const table = page.locator('#panel-decision .kat-table');
  await expect(table.locator('tbody tr')).toHaveCount(Number(total));
  await expect(table.locator('.kat-pass')).toHaveCount(Number(passed));
  await expect(table.locator('.kat-fail')).toHaveCount(0);

  // Bash's row exists, is passing, and names the clause of STB 34.101.77 the
  // expected digest is published in — not a vague "the standard".
  const bashRow = table.locator('tbody tr', { hasText: 'Bash-256' });
  await expect(bashRow).toHaveCount(1);
  await expect(bashRow).toContainText('STB 34.101.77 §A.3.1');
  await expect(bashRow.locator('.kat-pass')).toBeVisible();

  // That single pinned vector is the empty message, which any sponge with the
  // wrong rate would also pass. So the page reports the rest of Annex A too,
  // and that report must be green for the row above to mean anything.
  await expect(page.locator('#bash-crosscheck .kat-pass')).toBeVisible();
  await expect(page.locator('#bash-crosscheck .kat-fail')).toHaveCount(0);
  const crossCheck = (await page.locator('#bash-crosscheck').textContent()) ?? '';
  const [, reproduced, vectors] = crossCheck.match(/(\d+)\/(\d+) published Bash vectors/) ?? [];
  expect(Number(reproduced)).toBe(Number(vectors));
  // A.2 plus A.3.1 … A.3.11.
  expect(Number(vectors)).toBe(12);

  // And the digest really is computed in the browser, in the six-way panel.
  await page.locator('#tab-anchors').click();
  const bashCard = page.locator('#panel-anchors .card', { hasText: 'Bash-256' }).first();
  await expect(bashCard.locator('.digest-block')).toHaveText(/^[0-9a-f]{64}$/);
});

test('LSH is hashed live, and its hand-rolled maths is pinned to two sources', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#tab-decision').click();

  // LSH's KAT row names what it is pinned to — and, unusually, names what it is
  // NOT pinned to. The standard itself was not consulted, and the page says so
  // rather than implying an authority the lab does not have.
  const table = page.locator('#panel-decision .kat-table');
  const lshRow = table.locator('tbody tr', { hasText: 'LSH-256' });
  await expect(lshRow).toHaveCount(1);
  await expect(lshRow).toContainText('published LSH reference value');
  await expect(lshRow).toContainText('KS X 3262 not consulted directly');
  await expect(lshRow.locator('.kat-pass')).toBeVisible();

  // One pinned digest cannot vouch for a transcribed primitive, so the page
  // recomputes the whole shipped vector set on load and reports the result.
  await expect(page.locator('#lsh-crosscheck .kat-pass')).toBeVisible();
  await expect(page.locator('#lsh-crosscheck .kat-fail')).toHaveCount(0);
  const note = (await page.locator('#lsh-crosscheck').textContent()) ?? '';
  const [, reproduced, vectors] = note.match(/(\d+)\/(\d+) published LSH vectors/) ?? [];
  expect(Number(reproduced)).toBe(Number(vectors));
  expect(Number(vectors)).toBeGreaterThanOrEqual(12);

  // The surrounding prose states the two-source claim the vector table embodies.
  const panel = page.locator('#panel-decision');
  await expect(panel).toContainText('no npm implementation at all');
  await expect(panel).toContainText('corroborate rather than repeat each other');

  // And the digest really is computed in the browser.
  await page.locator('#tab-anchors').click();
  const card = page.locator('#panel-anchors .card', { hasText: 'LSH-256' }).first();
  await expect(card.locator('.digest-block')).toHaveText(/^[0-9a-f]{64}$/);
});

test('the Bash trust grade is for the algorithm, with the tooling defect kept on record', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#tab-decision').click();

  // The visible grade. Read off the cell's own text node so the footnote
  // marker in the <sup> does not get folded into it.
  const gradeCell = page.locator('[data-trust-grade="bash256"]');
  await expect(gradeCell).toBeVisible();
  const cellGrade = (
    await gradeCell.evaluate((el) => el.childNodes[0]?.textContent ?? '')
  ).trim();
  expect(cellGrade).toBe('High');

  // The derivation note behind the disclosure must state the SAME grade — two
  // surfaces rendering one claim, so a regrade that updates only one is caught.
  const notes = page.locator('#panel-decision details.explainer');
  await notes.locator('summary').click();
  const bashNote = notes.locator('li', { hasText: 'Bash —' });
  await expect(bashNote).toHaveCount(1);
  const noteGrade = ((await bashNote.textContent()) ?? '').match(/Bash\s+—\s+([^.]+)\./)?.[1] ?? '';
  expect(noteGrade.trim()).toBe(cellGrade);

  // The grade is scoped to the algorithm, not to what you can install.
  await expect(bashNote).toContainText('This grade is for the algorithm');
  await expect(bashNote).toContainText('Tooling caveat, counted separately');

  // And the concrete defect that caveat exists for stays on the record: the
  // count, the root cause, and what this lab does about it. Softening any of
  // these to a vague "immature tooling" note fails here.
  await expect(bashNote).toContainText('@li0ard/bash');
  await expect(bashNote).toContainText('7 of the 11');
  await expect(bashNote).toContainText('Annex A');
  await expect(bashNote).toContainText('security level in bits with the digest length in bytes');
  await expect(bashNote).toContainText('wrong rate');
  await expect(bashNote).toContainText('XORs each block into the state where the standard overwrites');
  await expect(bashNote).toContainText('src/bash.ts');

  // The claim the caveat rests on is the one the page can actually back: this
  // lab's own sponge reproduces every published vector.
  await expect(page.locator('#bash-crosscheck .kat-pass')).toBeVisible();
  await expect(page.locator('#bash-crosscheck .kat-fail')).toHaveCount(0);
});

/**
 * The negative claim (template §4.1d).
 *
 * The claim: Bash carries NO length-extension countermeasure — no length
 * encoding, no checksum, no output transformation. Neither does SHA-256, which
 * this same page forges. So the page must not present the sponge as defending
 * itself, and must not let a green row read as "this tag is authenticated".
 *
 * The three assertions §4.1d requires:
 *   1. Reach the fixture through the UI.
 *   2. Every verdict rendered in that state reports success.
 *   3. The limitation is on screen in that same state — visible, not in the
 *      README and not behind a disclosure.
 */
test('negative claim: Bash has no length-extension defence, and needs none', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-break').click();

  // Nothing is claimed before anything is run.
  await expect(page.locator('[data-negative-claim]')).toHaveCount(0);

  // ── 1. Reach the fixture ────────────────────────────────────────────────
  await page.locator('#break-run').click();
  await expect(page.locator('[data-attack-result]')).toHaveAttribute(
    'data-attack-result',
    'forged',
    { timeout: 30_000 },
  );
  await page.locator('#break-run-resistant').click();
  await expect(page.locator('[data-resist-row="bash256"]')).toBeVisible();

  // ── 2. Everything on screen reports success ─────────────────────────────
  // Asserted against the rendered verdicts, not a flag this test sets.
  const outcomes = page.locator('[data-resist-outcome]');
  await expect(outcomes).toHaveCount(6);
  expect(await outcomes.evaluateAll((nodes) =>
    nodes.map((n) => n.getAttribute('data-resist-outcome')),
  )).toEqual(['held', 'held', 'held', 'held', 'held', 'held']);
  await expect(page.locator('#break-resist-body .kat-fail')).toHaveCount(0);
  await expect(page.locator('.badge-failed')).toHaveCount(0);
  // The forgery against SHA-256 succeeded, which is what makes the contrast in
  // the claim a measured fact rather than a rhetorical one.
  await expect(page.locator('[data-attack-result]')).toHaveAttribute(
    'data-attack-result',
    'forged',
  );

  // ── 3. The limitation is on screen in that state ────────────────────────
  const claim = page.locator('[data-negative-claim]');
  await expect(claim).toBeVisible();
  await expect(claim).toHaveAttribute('data-negative-claim', 'no-countermeasure');
  await expect(claim).toContainText('no length-extension countermeasure at all');
  await expect(claim).toContainText('what that absence does not buy is authentication', {
    ignoreCase: true,
  });
  await expect(claim).toContainText('no entry point');

  // The numbers behind it are re-derived here from the geometry the page
  // printed, rather than compared against a constant this test carries.
  const num = async (id: string): Promise<number> =>
    Number(((await page.locator(`#${id}`).textContent()) ?? '').trim());
  const immuneWithheld = await num('claim-immune-withheld');
  const immuneState = await num('claim-immune-state');
  const forgeableWithheld = await num('claim-forgeable-withheld');
  const forgeableState = await num('claim-forgeable-state');
  // Both digests on this page are 256 bits, so withheld = state − 256.
  expect(immuneWithheld).toBe(immuneState - 256);
  expect(forgeableWithheld).toBe(forgeableState - 256);
  // SHA-256 withholds nothing: the digest IS the chaining state, which is the
  // precondition the forgery above needs. Bash withholds most of its state.
  expect(forgeableWithheld).toBe(0);
  expect(immuneWithheld).toBeGreaterThan(1000);

  // The claim's own number and the resistance table's must agree — two
  // surfaces rendering the same measurement.
  const rowWithheld = Number(
    (await page
      .locator('[data-resist-row="bash256"] [data-withheld-bits]')
      .getAttribute('data-withheld-bits')) ?? '0',
  );
  expect(rowWithheld).toBe(immuneWithheld);

  // And the absence is marked as an absence on both sponges, not dressed up.
  for (const id of ['bash256', 'sha3-256']) {
    await expect(page.locator(`[data-resist-row="${id}"] [data-countermeasure]`)).toHaveAttribute(
      'data-countermeasure',
      'none',
    );
  }
});

test('the negative claim is retired when the inputs that produced it change', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-break').click();
  await page.locator('#break-run-resistant').click();
  await expect(page.locator('[data-negative-claim]')).toBeVisible();

  // A verdict must never outlive the inputs it was computed from.
  await page.locator('#break-secret').fill('a-different-secret');
  await expect(page.locator('[data-negative-claim]')).toHaveCount(0);
  await expect(page.locator('[data-resist-row]')).toHaveCount(0);

  // Re-running restores it rather than leaving the panel permanently empty.
  await page.locator('#break-run-resistant').click();
  await expect(page.locator('[data-negative-claim]')).toBeVisible();
});
