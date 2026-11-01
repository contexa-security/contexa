import { useEffect, useRef } from 'react';
import { useLocation, useNavigationType } from 'react-router-dom';

/**
 * A new screen starts at its top with the focus on its heading (WCAG 2.4.3): otherwise the address keeps the scroll of
 * the screen before. Back and forward keep the browser's own place, a window that is open keeps its focus, the first
 * load keeps the browser's start (the skip link first), and a change of tab or step inside one screen (the same path)
 * moves nothing.
 */
export function RouteFocus() {
  const { pathname } = useLocation();
  const navigation = useNavigationType();
  const first = useRef(true);
  const settled = useRef<string | null>(null);
  useEffect(() => {
    const move = !first.current && navigation !== 'POP';
    first.current = false;
    if (move) {
      window.scrollTo({ top: 0 });
    }
    // The next screen's code may still be loading with the screen before on view: wait for its own heading.
    let tries = 0;
    const timer = window.setInterval(() => {
      tries += 1;
      const heading = document.querySelector<HTMLElement>('main h1');
      if (!heading || (heading.textContent === settled.current && move && tries < 20)) {
        if (tries >= 40) {
          window.clearInterval(timer);
        }
        return;
      }
      window.clearInterval(timer);
      settled.current = heading.textContent;
      if (move && !document.querySelector('dialog[open]')) {
        heading.focus({ preventScroll: true });
      }
    }, 50);
    return () => window.clearInterval(timer);
  }, [pathname, navigation]);
  return null;
}
