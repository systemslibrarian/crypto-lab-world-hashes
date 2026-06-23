// @vitest-environment happy-dom
import { beforeAll, describe, expect, it } from 'vitest';

beforeAll(async () => {
  // happy-dom does not expose a bare `localStorage` global; provide a minimal
  // one so the theme-persistence path can be exercised (browsers always have it).
  if (typeof globalThis.localStorage === 'undefined') {
    const store = new Map<string, string>();
    globalThis.localStorage = {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, String(v)),
      removeItem: (k: string) => void store.delete(k),
      clear: () => store.clear(),
      key: (i: number) => [...store.keys()][i] ?? null,
      get length() {
        return store.size;
      }
    } as Storage;
  }

  document.documentElement.setAttribute('data-theme', 'dark');
  document.body.innerHTML = '<div id="app"></div>';
  await import('./main');
});

function tab(id: string): HTMLButtonElement {
  const el = document.getElementById(`tab-${id}`);
  if (!el) throw new Error(`missing tab ${id}`);
  return el as HTMLButtonElement;
}

function pressKey(el: HTMLElement, key: string): void {
  el.focus();
  el.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }));
}

describe('keyboard tab navigation (ARIA tabs)', () => {
  it('ArrowRight moves selection AND focus to the next tab', () => {
    tab('sm3').click();
    pressKey(tab('sm3'), 'ArrowRight');

    expect(tab('streebog').getAttribute('aria-selected')).toBe('true');
    expect(tab('sm3').getAttribute('aria-selected')).toBe('false');
    // The bug this guards against: focus was left on the old tab after render().
    expect(document.activeElement?.id).toBe('tab-streebog');
    expect(document.getElementById('panel-streebog')?.hasAttribute('hidden')).toBe(false);
    expect(document.getElementById('panel-sm3')?.hasAttribute('hidden')).toBe(true);
  });

  it('ArrowLeft wraps from the first tab to the last', () => {
    tab('sm3').click();
    pressKey(tab('sm3'), 'ArrowLeft');
    expect(document.activeElement?.id).toBe('tab-decision');
    expect(tab('decision').getAttribute('aria-selected')).toBe('true');
  });

  it('Home and End jump to the first and last tab', () => {
    tab('streebog').click();
    pressKey(tab('streebog'), 'End');
    expect(document.activeElement?.id).toBe('tab-decision');

    pressKey(tab('decision'), 'Home');
    expect(document.activeElement?.id).toBe('tab-sm3');
  });

  it('only the active tab is in the tab order (roving tabindex)', () => {
    tab('kupyna').click();
    expect(tab('kupyna').getAttribute('tabindex')).toBe('0');
    expect(tab('sm3').getAttribute('tabindex')).toBe('-1');
  });
});

describe('IME composition safety', () => {
  it('does not rebuild the focused textarea mid-composition', () => {
    tab('sm3').click();
    const input = document.getElementById('sm3-input') as HTMLTextAreaElement;
    input.focus();

    input.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }));
    input.value = '中';
    // A real browser sets isComposing on input events fired during composition.
    input.dispatchEvent(new InputEvent('input', { bubbles: true, isComposing: true }));

    // Still the very same DOM node — composition was not interrupted by a re-render.
    expect(document.getElementById('sm3-input')).toBe(input);
    expect(document.activeElement).toBe(input);

    // Committing the character re-renders and the digest reflects the new input.
    input.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true }));
    expect(document.querySelector('#sm3-result .digest-block')?.textContent).toMatch(/^[0-9a-f]{64}$/);
  });

  it('keeps re-rendering after a composition is abandoned without compositionend', () => {
    // Regression guard: a stuck "composing" flag used to freeze all live updates
    // if compositionend never fired (e.g. blurring mid-composition in Firefox).
    tab('sm3').click();
    const input = document.getElementById('sm3-input') as HTMLTextAreaElement;
    input.focus();
    input.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }));
    input.value = '中';
    input.dispatchEvent(new InputEvent('input', { bubbles: true, isComposing: true }));
    // No compositionend — the user blurred. A subsequent ordinary edit must render.
    input.value = 'abc';
    input.dispatchEvent(new InputEvent('input', { bubbles: true, isComposing: false }));

    expect((document.getElementById('sm3-input') as HTMLTextAreaElement).value).toBe('abc');
    // SM3("abc") known-answer digest — proves the live re-render produced fresh output.
    expect(document.querySelector('#sm3-result .digest-block')?.textContent).toBe(
      '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'
    );
  });
});

describe('theme toggle', () => {
  it('flips the document theme and persists it', () => {
    document.documentElement.setAttribute('data-theme', 'dark');
    const toggle = () => document.getElementById('theme-toggle') as HTMLButtonElement;

    toggle().click();
    expect(document.documentElement.getAttribute('data-theme')).toBe('light');
    expect(localStorage.getItem('theme')).toBe('light');

    toggle().click();
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark');
    expect(localStorage.getItem('theme')).toBe('dark');
  });

  it('updates the toggle button label for the new theme', () => {
    document.documentElement.setAttribute('data-theme', 'dark');
    const toggle = () => document.getElementById('theme-toggle') as HTMLButtonElement;
    toggle().click(); // -> light
    expect(toggle().getAttribute('aria-label')).toBe('Switch to dark mode');
  });
});
