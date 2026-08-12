/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 *
 * What survives here is the SHARED Crypto Lab top bar, and nothing else. Every
 * control inside `#app` is audited with no exemption and comes back clean —
 * including `.tab-button`, `.button-row button`, `.copy-btn` and `.flip-cell`,
 * which were the real findings this oracle turned up in this repo and which are
 * now fixed in `src/styles.css` rather than baselined.
 *
 * `.cl-btn` draws its edge as
 * `1px solid color-mix(in srgb, var(--accent, #35d6bb) 38%, transparent)` over
 * the bar's fixed `#0b1512`. This lab defines `--accent`, and defines it
 * differently per theme, so the composited edge — and therefore the finding —
 * moves with the theme. The ratchet stores the WORST of the two, because a single
 * key covers both themes and storing the better figure would let the other
 * regress unnoticed. Measured through this gate's own path:
 *
 *   dark   --accent #6ecfff -> edge rgb(49,92,108) = 2.55:1 against #0b1512
 *   light  --accent #0066cc -> edge rgb(7,52,89)   = 1.46:1 against #0b1512
 *
 * Every repo in this fleet carries a byte-identical copy of that markup and CSS,
 * and `CLAUDE.md` is explicit that a change every lab should get is a deliberate
 * reviewed fleet-wide pass and never an overwrite driven from one repo. So it is
 * measured here, ratcheted here, and reported upward.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  'control-boundary|a.cl-btn': { ratio: 1.46, required: 3, unverified: false },
  'control-boundary|button#cl-theme-toggle.cl-btn.cl-icon': {
    ratio: 1.46,
    required: 3,
    unverified: false,
  },
};
