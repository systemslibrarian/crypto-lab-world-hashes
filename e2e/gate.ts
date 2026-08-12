import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/** The six exhibit tabs, in the order the tablist renders them. */
export const TAB_IDS = ['sm3', 'streebog', 'kupyna', 'anchors', 'break', 'decision'] as const;

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects a specific thing the
 * gate this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old `prep()` pushed
 *     `animation:none !important; transition:none !important` through
 *     `addStyleTag`, which BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it.
 *     The block clamps every duration to 0.01ms and pins
 *     `animation-iteration-count: 1`, which is what actually stops
 *     `.live-dot`'s infinite `live-pulse`. The injection produced a similar
 *     rendering by a different route, so it proved nothing about the block —
 *     and it was checked, here, for the failure where cancelling an animation
 *     strands an element at its start value: it cannot happen, because the
 *     block contains no declaration other than the three timing ones, and
 *     `live-pulse` only animates `box-shadow` while the dot's own
 *     `background: var(--green)` is static. `expectNotBlank` measures that in
 *     every state rather than trusting the reading.
 *
 *  2. IT FORCE-REVEALED EVERY PANEL AND EVERY DISCLOSURE. The old `prep()` set
 *     `details.open = true` on all three explainers and then stripped the
 *     `hidden` attribute from every element carrying one. On this page the
 *     `hidden` attribute is exactly how the five INACTIVE TAB PANELS are hidden
 *     — `render()` writes it, with a comment explaining that it is used in
 *     preference to `aria-hidden` because it also removes the panels from the
 *     tab order. Stripping it produced a document with all six exhibit panels
 *     open at once: six `role="tabpanel"` sections visible against one
 *     `aria-selected` tab, every textarea and every attack control reachable
 *     simultaneously. No visitor can load that document, and no assertion about
 *     it describes the product. This gate never touches `hidden`, `display` or
 *     `open`; every panel is reached by clicking its tab and every disclosure by
 *     clicking its own `<summary>`.
 *
 *  3. IT SCANNED ONCE, AFTER A DRIVE THAT OVERWROTE EVERYTHING IT BUILT. The old
 *     `driveAllTabs()` visited all six tabs, typed into each input, then ran five
 *     attack-lab operations in a row — and only then called `scan()`. Every state
 *     but the last was gone. It also drove at one viewport, so the whole 380px
 *     column — where `.comparison-table` picks up `min-width: 700px` and its
 *     wrapper starts scrolling — had never been opened. This drive scans after
 *     every step, in {dark, light} x {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The defect this repo
 *     actually had is the clearest possible case: `<div id="app"
 *     aria-label="World Hashes demo">` in `index.html` puts an `aria-label` on a
 *     role-less element, where it is PROHIBITED and silently discarded. axe knows
 *     — and files it under `incomplete`, never under `violations`, so a
 *     violations-only gate reports green for a label that does not exist.
 *
 *  5. IT HAD NO REFLOW, KEYBOARD-SCROLLER OR NON-TEXT-CONTRAST ORACLE. The repo
 *     did ship a separate `e2e/border.spec.ts` for 1.4.11, and it was worse than
 *     nothing twice over: it queried `textarea, input[type='text'], select`,
 *     which is EXACTLY and only the rule `--control-border` was applied to, so it
 *     asserted 3:1 over the three selectors where the correct token was already
 *     kept; and it compared each element's `borderTopColor` against its OWN
 *     `backgroundColor`, never against the surface outside it, so it never asked
 *     the question 1.4.11 asks. Every button on this page — `.tab-button`,
 *     `.button-row button`, `.copy-btn`, `.flip-cell` — drew its edge from
 *     `--border` and was invisible against its panel, and that spec was
 *     structurally incapable of noticing. It is deleted; `nontext.ts` replaces it
 *     with a composite-aware audit of every control, run at every driven state.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * `styles.css` cannot currently be in that shape, and the assertion is what makes
 * that a measurement rather than a reading. Its reduced-motion block was read
 * declaration by declaration: it contains `transition-duration`,
 * `animation-duration` and `animation-iteration-count` and nothing else, so it
 * cannot strand anything. The file's only `@keyframes` is `live-pulse`, which
 * animates `box-shadow` alone. The check runs in every state anyway, because both
 * of those are properties of the current stylesheet rather than of the page.
 *
 * `aria-hidden` subtrees are excluded; see the note on `ariaHidden` in
 * `contrast.ts` for what this lab hides and why each one was checked by hand.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page is
 * created. This whole lab is one `app.innerHTML = ...` render function: a throw
 * anywhere inside it leaves the PREVIOUS render on screen, which looks entirely
 * plausible and which a gate would then scan and report green. Attach before
 * `boot`, assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * This lab's hero is a `<header class="cl-hero">` INSIDE `<main id="main-content">`,
 * which scopes it out of the banner role on its own — and `index.html`'s
 * `dedupeBanner()` skips it for that reason (its `el.closest('main, …')` test
 * returns early). So nothing here demotes anything and the single banner is a
 * property of the markup. Asserting the OUTCOME rather than either mechanism
 * means a change to the nesting is caught too, which matters here because the
 * hero is emitted from a template literal that could be moved in one edit.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which pins down a real failure mode as a side effect: `index.html`'s
 * anti-flash script reads `localStorage.getItem('theme')` and both toggles —
 * the shared bar's and this lab's own `#theme-toggle`, via `saveTheme()` — write
 * the same key. If those drift apart the theme silently stops persisting, and
 * this boot fails on `data-theme` rather than quietly scanning dark twice.
 *
 * The defaults are asserted at length because everything on this page is
 * rendered by JavaScript into an empty `<div id="app">`. A navigation that
 * resolves proves nothing at all here: the whole document, hero to footer, comes
 * out of one `innerHTML` assignment, and every digest on it is computed at
 * render time. The KAT self-test in particular is asserted at 17/17 rather than
 * merely present, because a page that says "3/17 vectors FAILED" is still a
 * page a gate can scan and call green.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  // The SPA has actually mounted, rather than the navigation merely resolving.
  await expect(page.locator('main#main-content')).toBeVisible();
  await assertSingleBanner(page);

  // Both skip links point at ids that exist. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run says
  // nothing about. `#app` is in index.html; `#main-content` only exists once the
  // SPA has rendered.
  await expect(page.locator('#app')).toHaveCount(1);
  await expect(page.locator('#main-content')).toHaveCount(1);

  // The `hidden` attribute really removes an element. `[hidden]` has specificity
  // (0,1,0) — identical to a class — so any later `.foo { display: … }` beats it
  // and the attribute silently does nothing. This lab hides its five inactive tab
  // panels with `hidden` and nothing else, so if that ever stopped applying the
  // page would show all six exhibits at once and no assertion here would notice.
  // Measured from a live element rather than inferred from the CSS.
  expect(
    await page.evaluate(() => {
      const probe = document.createElement('div');
      probe.hidden = true;
      document.body.appendChild(probe);
      const display = getComputedStyle(probe).display;
      probe.remove();
      return display;
    }),
    'the hidden attribute must actually hide (it is how five tab panels are hidden)'
  ).toBe('none');

  // The lab's own theme toggle is suppressed by the shared header's stylesheet
  // (`display:none !important`) while staying in the DOM so its JS keeps working.
  await expect(page.locator('#theme-toggle')).toBeHidden();

  // ── Tabs: six, exactly one selected, five panels hidden ──────────────────
  await expect(page.locator('.tabs[role="tablist"] .tab-button')).toHaveCount(6);
  await expect(page.locator('#tab-sm3')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#panel-sm3')).toBeVisible();
  for (const id of TAB_IDS.filter((t) => t !== 'sm3')) {
    await expect(page.locator(`#panel-${id}`)).toBeHidden();
  }

  // ── Three explainer disclosures, all shut on arrival ─────────────────────
  // The gate this replaces opened all of them from script before its only scan.
  await expect(page.locator('details.explainer')).toHaveCount(3);
  await expect(page.locator('details[open]')).toHaveCount(0);

  // ── The live self-test, and the digests it vouches for ───────────────────
  await expect(page.locator('.badge-verified')).toHaveText('✓ 17/17 test vectors verified');
  await expect(page.locator('.badge-failed')).toHaveCount(0);

  // ── Every shipped control default ────────────────────────────────────────
  await expect(page.locator('#intro-input')).toHaveValue('hash me');
  await expect(page.locator('#sm3-mode')).toHaveValue('text');
  await expect(page.locator('#sm3-input')).toHaveValue(
    'Sovereign standards still need strong engineering discipline.'
  );
  // 61 characters of input, 61 clickable flip cells — the avalanche strip is
  // built from the live input rather than a fixture.
  await expect(page.locator('.flip-cell')).toHaveCount(61);
  await expect(page.locator('.flip-cell[aria-pressed="true"]')).toHaveCount(1);

  // Both digests on the arrival tab are real 64-hex output, not placeholders.
  await expect(page.locator('#sm3-result .digest-block').first()).toHaveText(/^[0-9a-f]{64}$/);
  await expect(page.locator('#sm3-sha-result .digest-block').first()).toHaveText(/^[0-9a-f]{64}$/);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. The shapes at risk
 * here are the four `.comparison-table`s, which take `min-width: 700px` below
 * 860px and are meant to scroll inside their own `.compare-table-wrap`; the
 * 64-hex `.digest-block`s, which rely on `word-break: break-all`; and the
 * `.attack-row` grid, whose `minmax(0, …)` tracks are what stop a monospace
 * hex value from setting the page's width.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. Every
    // `.comparison-table` on this page is such a decoy at phone width.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * The four `.compare-table-wrap` scrollers on this page are the case: the
 * known-answer table, the length-extension resistance table, and the two
 * reference tables on the Anchors and Comparison tabs. None holds a focusable
 * control, and below 860px each wraps a table pinned to `min-width: 700px`. At
 * 1280px none of them overflows, so the failure does not exist in the only
 * viewport the old gate ever opened.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function expectScrollersReachableSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectScrollersReachable(page, label);
  try {
    await expectScrollersReachable(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * The 1.4.11 ratchet, soft-wrapped the same way as every other oracle here.
 *
 * The wrapper is written out longhand rather than folded into a neighbour
 * because of how this oracle died elsewhere in this fleet:
 * `expectNoNewNonTextFailures` had been called from inside
 * `expectScrollersReachableSoft`, AFTER that function's `if (!COLLECTING) return`
 * guard, so in a strict run — which is every run in CI and every run anyone reads
 * as a pass — the guard returned first and `nontext.ts` never executed at all.
 * It is called from `scan()` here, at every driven state, and this repo's
 * baseline was captured by that live path.
 */
async function expectNoNewNonTextFailuresSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoNewNonTextFailures(page, label);
  try {
    await expectNoNewNonTextFailures(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

async function expectNoHorizontalOverflowSoft(page: Page, label: string): Promise<void> {
  if (!COLLECTING) return expectNoHorizontalOverflow(page, label);
  try {
    await expectNoHorizontalOverflow(page, label);
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast, and
 * the arithmetic text walk cannot reach a control's boundary or a `::before`
 * glyph, because a pseudo-element is not an element and owns no text node. The
 * check this repo shipped instead — `e2e/border.spec.ts` — is deleted, for the
 * two reasons given at the top of this file.
 *
 * The remaining backlog here is the shared Crypto Lab top bar, byte-identical in
 * every repo in the fleet and not this one's to change, so this does not block on
 * it. A check that merely logs is not a gate, though, so it ratchets: anything
 * NOT in the baseline fails, anything in the baseline that got WORSE fails, and
 * anything in the baseline that has been FIXED fails until its entry is deleted.
 * That last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array, and which is where this repo's most concrete defect lived:
 *    `aria-prohibited-attr` on `<div id="app" aria-label="World Hashes demo">`.
 *    The one rule id allowed to remain incomplete is `color-contrast`, and only
 *    because the next assertion computes those ratios arithmetically — which
 *    matters more here than in most labs, since `.panel` and `.card` are painted
 *    with a `linear-gradient` between two translucent `rgba()` surfaces, `<body>`
 *    carries two radial-gradient washes, and `--accent-soft`, `--amber-soft`,
 *    `--chip` and `--hash-block` are all translucent. axe declines to resolve the
 *    surface under most of this page.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it, which is the question
 *    `border.spec.ts` never asked.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads exactly
  // like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of axe-core
  // 4.12's 105 rule definitions; the chained form executes 4.
  //
  // Confirmed here by experiment rather than by reading: `<html lang="en">` was
  // changed to `<html>` and the full drive re-run against the identical page. The
  // merged form below failed on `html-has-lang` (SC 3.1.1, tagged `wcag2a`) at
  // the very first state. See the commit message for the measured before/after.
  //
  // The landmark four are still wanted because they are best-practice rather than
  // WCAG-tagged, so `withTags` alone does not reach them — and this page has the
  // shape they catch: a sticky `<header role="banner">` above a `<main>` that
  // itself contains a `<header class="cl-hero">` with an
  // `<aside role="complementary">` inside it.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  await expectNoNewNonTextFailuresSoft(page, label);
  await expectScrollersReachableSoft(page, label);
  await expectNoHorizontalOverflowSoft(page, label);
}

// ── The drive ───────────────────────────────────────────────────────────────

/** Click a tab by id and wait for its panel to actually be the visible one. */
async function openTab(page: Page, id: (typeof TAB_IDS)[number]): Promise<void> {
  await page.click(`#tab-${id}`);
  await expect(page.locator(`#panel-${id}`)).toBeVisible();
  await expect(page.locator(`#tab-${id}`)).toHaveAttribute('aria-selected', 'true');
  // Exactly one panel visible at a time is the property the old gate destroyed
  // by stripping every `hidden` attribute before its only scan.
  await expect(page.locator('.tab-panel:not([hidden])')).toHaveCount(1);
}

/**
 * Open every shut disclosure on the CURRENT panel by clicking its summary.
 *
 * `render()` rebuilds `#app` from scratch on every state change and emits each
 * `<details>` without an `open` attribute, so any disclosure re-closes the moment
 * anything else is touched. That is why they are opened and scanned as their own
 * step rather than once at the start — and it is the precise reason the old
 * gate's `details.open = true` sweep could not have produced a state a reader
 * ever sees.
 */
async function openDisclosures(page: Page, expected: number): Promise<void> {
  const shut = page.locator('details:not([open]) > summary:visible');
  await expect(shut).toHaveCount(expected);
  for (let i = 0; i < expected; i++) {
    await shut.first().click();
  }
  await expect(page.locator('details:not([open]) > summary:visible')).toHaveCount(0);
  await expect(page.locator('details[open]')).toHaveCount(expected);
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - ONE TAB AT A TIME, REACHED BY ITS TAB. Five of the six panels ship behind
 *    the `hidden` attribute; each is opened by clicking its `role="tab"` button
 *    and `openTab` asserts that exactly one panel is visible afterwards. The gate
 *    this replaces stripped `hidden` from all five before its only scan, which
 *    measured a document with six exhibit panels open simultaneously.
 *
 *  - THE ERROR STATES ARE DRIVEN, AND DRIVING THEM FOUND A DEAD END. Each of the
 *    four hashing exhibits calls `parseInput()` and, on failure, re-renders the
 *    exhibit as a heading, its controls, and a `.callout.warn`. It did NOT
 *    render the controls until this drive tried to type its way back out: the
 *    error branch replaced the whole panel, taking the mode selector and the
 *    textarea with it, so a reader who switched to Hex mode with prose in the box
 *    was told the input was invalid and left with nothing to fix it with. The
 *    drive failing on a missing `#sm3-input` is what surfaced it — a single scan
 *    of that state would have reported it perfectly accessible. Both rejection
 *    messages are now driven, in the order `parseInput()` produces them.
 *
 *  - THE ATTACK LAB'S FOUR OUTCOMES, NOT JUST ITS SUCCESSES. A forged tag, a
 *    forgery that FAILS because the secret-length guess was wrong, a found
 *    collision, and a search that exhausts a 50-hash budget. Those are four
 *    different verdict palettes, and the failure ones are the states a learner
 *    reaches by getting something wrong.
 *
 *  - THE EXTREMES OF EVERY SIZE CONTROL. Streebog and Kupyna both offer 512-bit
 *    output, which doubles the digest to 128 hex characters — the longest
 *    unbroken token on the page, and the thing `word-break: break-all` has to
 *    handle at 380px. The 256-bit default never produces it.
 *
 *  - HOVER IS A STATE. `.flip-cell:hover` swaps its border to `--accent` and its
 *    fill to `--accent-soft`, `.attack-button:hover` applies a
 *    `filter: brightness(1.08)`, and `.theme-toggle:hover` swaps to
 *    `--panel-strong`. A visitor is in one of those states immediately after
 *    pointing at anything, and none had ever been measured.
 *
 *  - NO FIXED TIMEOUTS. Every operation here has a real DOM completion signal —
 *    a `data-attack-result` attribute, a `data-collision-verdict`, a row
 *    appearing, a digest changing — and the drive waits on those. The attack and
 *    collision searches are genuinely slow (hundreds of thousands of hashes on
 *    the main thread), so they get explicit long timeouts rather than a sleep.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('first paint, SM3 tab, five panels hidden and three disclosures shut');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('shared skip link focused, slid into view');

  // This lab ships a SECOND skip link of its own, parked at `left:-9999px` and
  // revealed at `left:0` on focus. Its focused rendering is the only one in
  // which it paints any pixels at all — the contrast walk deliberately skips the
  // parked copy.
  await page.locator('a.skip-link').focus();
  await expect(page.locator('a.skip-link')).toBeFocused();
  await scanAt('the lab own skip link focused');

  // The inline glossary `<abbr class="gloss" tabindex="0">`. It is focusable, so
  // it needs a visible focus indicator (2.4.7) — which is a `box-shadow` ring,
  // not an outline, and therefore not something axe checks.
  await page.locator('abbr.gloss').first().focus();
  await expect(page.locator('abbr.gloss').first()).toBeFocused();
  await scanAt('an inline glossary term focused');

  // ── Exhibit 1: SM3 ───────────────────────────────────────────────────────
  // Two of the three `details.explainer` are reachable from here: the intro
  // exhibit's, which is rendered ABOVE the tablist and so appears on every tab,
  // and the SM3 panel's "Constructions 101". The third lives in the Comparison
  // panel and is behind the `hidden` attribute until that tab is opened — which
  // is exactly the distinction `:visible` enforces and the old gate erased when
  // it set `.open = true` on all three at once.
  await openDisclosures(page, 2);
  await scanAt('SM3 tab, both reachable explainer disclosures open');

  // Flipping a character re-renders the exhibit with the avalanche comparison:
  // the changed nibbles get `--nibble-ink` on `--amber-soft`, and the meter
  // renders its fill and the 50% ideal marker.
  await page.locator('[data-flip-index="7"]').click();
  await expect(page.locator('[data-flip-index="7"]')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('.nibble-changed').first()).toBeVisible();
  await expect(page.locator('.avalanche-meter').first()).toBeVisible();
  await scanAt('SM3 avalanche, one character flipped');

  await page.locator('.flip-cell').nth(20).hover();
  await scanAt('a flip cell hovered');

  // The copy control's confirmation. `copyDigest()` re-renders with the button
  // relabelled and reverts after 1200ms; the assertion proves the clipboard
  // promise RESOLVED (it has a `catch` that renders "Copy failed" instead, so a
  // missing permission would silently drive the wrong branch).
  await page.locator('.copy-btn').first().click();
  await expect(page.locator('.copy-btn').first()).toHaveText('Copied');
  await scanAt('a digest copied, the control showing its confirmation');
  await expect(page.locator('.copy-btn').first()).toHaveText('Copy', { timeout: 5_000 });

  // Hex mode with English prose still in the box is the one-click route to the
  // parse-error rendering, which replaces the exhibit's output with a warning
  // while keeping the controls needed to correct it — a property this drive is
  // what established, by needing them.
  await page.selectOption('#sm3-mode', 'hex');
  // `parseInput()` checks LENGTH before charset, and the default input is 61
  // characters, so the odd-length message is the one this reaches first. Both
  // messages are driven, in the order the function actually produces them.
  await expect(page.locator('#panel-sm3 .callout.warn')).toHaveText(
    'Hex input must contain an even number of characters.'
  );
  await scanAt('SM3 rejected an odd-length hex string');

  await page.fill('#sm3-input', 'zzzz');
  await expect(page.locator('#panel-sm3 .callout.warn')).toHaveText(
    'Hex input may only contain 0-9 and a-f.'
  );
  await scanAt('SM3 rejected non-hex characters in hex mode');

  await page.fill('#sm3-input', 'deadbeef');
  await expect(page.locator('#sm3-result .digest-block').first()).toHaveText(/^[0-9a-f]{64}$/);
  await scanAt('SM3 hashing raw hex bytes');

  // ── Exhibit 2: Streebog, at both output sizes ────────────────────────────
  await openTab(page, 'streebog');
  await expect(page.locator('#streebog-size')).toHaveValue('256');
  await scanAt('Streebog tab at 256-bit');

  await page.selectOption('#streebog-size', '512');
  await expect(page.locator('#panel-streebog .digest-block').first()).toHaveText(/^[0-9a-f]{128}$/);
  await scanAt('Streebog at 512-bit, a 128-hex digest');

  await page.selectOption('#streebog-mode', 'hex');
  await expect(page.locator('#panel-streebog .callout.warn')).toBeVisible();
  await scanAt('Streebog rejected non-hex input');

  // ── Exhibit 3: Kupyna ────────────────────────────────────────────────────
  await openTab(page, 'kupyna');
  await scanAt('Kupyna tab at 256-bit');

  await page.selectOption('#kupyna-size', '512');
  await expect(page.locator('#panel-kupyna .digest-block').first()).toHaveText(/^[0-9a-f]{128}$/);
  await scanAt('Kupyna at 512-bit, beside SHA-3-512');

  // Only the intro exhibit's disclosure is reachable here; `render()` rebuilt it
  // shut when the size selector changed, which is why it is opened again rather
  // than assumed to still be open from the SM3 step.
  await openDisclosures(page, 1);
  await scanAt('Kupyna tab with the intro disclosure open');

  // ── Exhibit 4: the reference anchors, five digests at once ───────────────
  await openTab(page, 'anchors');
  await expect(page.locator('#panel-anchors .digest-block').first()).toHaveText(/^[0-9a-f]{64}$/);
  await expect(page.locator('#panel-anchors .comparison-table')).toBeVisible();
  await scanAt('Anchors tab, five digests and the five-way avalanche table');

  // ── Exhibit 5: the attack lab, all four outcomes ─────────────────────────
  await openTab(page, 'break');
  // Nothing is claimed until something is run — a real state, and the first one
  // a reader meets.
  await expect(page.locator('#break-output')).toContainText('no forgery is claimed');
  await expect(page.locator('[data-attack-result]')).toHaveCount(0);
  await scanAt('attack lab before anything is run');

  await page.locator('.attack-button').first().hover();
  await scanAt('a primary attack button hovered');

  await page.click('#break-run');
  await expect(page.locator('[data-attack-result]')).toHaveAttribute(
    'data-attack-result',
    'forged',
    { timeout: 60_000 }
  );
  await expect(page.locator('#attack-forged-tag')).toHaveText(/^[0-9a-f]{64}$/);
  await scanAt('length-extension forgery succeeded against SHA-256');

  // The learner-caused failure: a wrong secret-length guess. Different verdict
  // palette, and the state a reader reaches by getting it wrong.
  await page.click('#break-run-wrong');
  await expect(page.locator('[data-attack-result]')).toHaveAttribute(
    'data-attack-result',
    'not-forged',
    { timeout: 60_000 }
  );
  // The wrong-length button WRITES its guess back into state, so `#break-length`
  // now shows 10 rather than the real 11 — the field says exactly what produced
  // the failure. That is deliberate and visible, and it is asserted here rather
  // than worked around, because it also means the next run inherits it: a drive
  // that did not restore the field would silently be re-running the failing
  // attack while claiming to measure the successful one.
  await expect(page.locator('#break-length')).toHaveValue('10');
  await scanAt('the same forgery FAILING on a wrong secret-length guess');

  await page.fill('#break-length', '11');
  await expect(page.locator('#break-length')).toHaveValue('11');
  await page.selectOption('#break-algorithm', 'sm3');
  await page.click('#break-run');
  await expect(page.locator('[data-attack-result]')).toHaveAttribute(
    'data-attack-result',
    'forged',
    { timeout: 60_000 }
  );
  await scanAt('the same forgery against SM3');

  await page.click('#break-run-resistant');
  await expect(page.locator('[data-resist-row="kupyna256"]')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#break-resist-body tr').first()).toBeVisible();
  await scanAt('the resistance table, sponge and wide-pipe holding');

  await page.click('#collision-run');
  await expect(page.locator('[data-collision-verdict]')).toHaveAttribute(
    'data-collision-verdict',
    'collision',
    { timeout: 120_000 }
  );
  await expect(page.locator('#collision-digest-a')).toHaveText(/^[0-9a-f]+$/);
  await scanAt('a real truncated-digest collision found');

  // The starved search: a budget too small to succeed, which is the other
  // verdict palette and the honest negative result.
  await page.click('#collision-run-starved');
  await expect(page.locator('[data-collision-verdict]')).toHaveAttribute(
    'data-collision-verdict',
    'exhausted',
    { timeout: 60_000 }
  );
  await scanAt('the collision search exhausting a 50-hash budget');

  // ── Exhibit 6: the comparison tab, which carries the KAT table ───────────
  await openTab(page, 'decision');
  await expect(page.locator('#panel-decision .kat-table tbody tr')).toHaveCount(17);
  await expect(page.locator('#panel-decision .kat-table .kat-pass')).toHaveCount(17);
  await expect(page.locator('#panel-decision .kat-table .kat-fail')).toHaveCount(0);
  await scanAt('Comparison tab, seventeen known-answer vectors listed as passing');

  await page.locator('#tab-sm3').hover();
  await scanAt('the finished page with an inactive tab hovered');
}
