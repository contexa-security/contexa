/**
 * The demo's own font and the regular Pretendard pieces that back up a character it lacks (approval Q-36). They load
 * after the first screen has been painted, so that the 160 KB font never shares the network with the code that paints
 * it (C-13); until then the text shows in the system font (font-display: swap). Once the font has loaded in this
 * browser it is in the cache, so later visits read it at once and never show the system font.
 */
const FONT_LOADED = 'showcase.fontLoaded';
let started = false;

export function loadFonts(): void {
  if (started) {
    return;
  }
  started = true;
  void import('./styles/demoFont.css')
    .then(() => document.fonts.load('1em "Pretendard Demo"'))
    .then((faces) => {
      if (faces.length > 0) {
        try {
          window.localStorage.setItem(FONT_LOADED, '1');
        } catch {
          // Remembering it only saves the system font on the next visit.
        }
      }
    })
    .catch(() => {
      // A font that cannot load leaves the text in the system font; nothing else depends on it.
    });
  void import('pretendard/dist/web/variable/pretendardvariable-dynamic-subset.css');
}

/** True when this browser loaded the font before, so it is read from the cache at once. */
export function fontInCache(): boolean {
  try {
    return window.localStorage.getItem(FONT_LOADED) === '1';
  } catch {
    // Storage can be unavailable (private mode); the font then loads after the first screen.
    return false;
  }
}

/** How long a first visit waits at most for its first screen before the font loads anyway. */
const FIRST_SCREEN_LIMIT_MS = 3000;

/**
 * Loads the font once the browser reports that the application's first content is on the glass: the first largest
 * contentful paint outside the bar index.html paints before the application loads. A frame callback alone runs before
 * its frame is shown, which is too early. Browsers without that report load it two frames after the start.
 */
export function loadFontsAfterFirstScreen(): void {
  if (PerformanceObserver.supportedEntryTypes.includes('largest-contentful-paint')) {
    const observer = new PerformanceObserver((list) => {
      const shown = list.getEntries().some((entry) => {
        const element = (entry as PerformanceEntry & { readonly element?: Element | null }).element ?? null;
        return element !== null && element.closest('.app-shell') === null;
      });
      if (shown) {
        observer.disconnect();
        setTimeout(loadFonts, 0);
      }
    });
    observer.observe({ type: 'largest-contentful-paint', buffered: true });
    setTimeout(loadFonts, FIRST_SCREEN_LIMIT_MS);
    return;
  }
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      setTimeout(loadFonts, 0);
    });
  });
}
