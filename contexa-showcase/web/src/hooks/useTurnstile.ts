import { useEffect, useRef, useState } from 'react';

interface TurnstileApi {
  render: (element: HTMLElement, options: Record<string, unknown>) => string;
  reset: (widgetId: string) => void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

const SCRIPT = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';

/**
 * Cloudflare Turnstile before a new live run (deck p.28): most visitors pass without a click. Without a site key the
 * check is off (a development stack) and no script is loaded.
 */
export function useTurnstile(siteKey: string | null) {
  const container = useRef<HTMLDivElement>(null);
  const widget = useRef<string | null>(null);
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    const element = container.current;
    if (!siteKey || !element) {
      return;
    }
    const render = () => {
      if (window.turnstile && widget.current === null) {
        widget.current = window.turnstile.render(element, {
          sitekey: siteKey,
          action: 'live_run',
          callback: (value: string) => setToken(value),
          'expired-callback': () => setToken(null),
          'error-callback': () => setToken(null),
        });
      }
    };
    if (window.turnstile) {
      render();
      return;
    }
    let script = document.querySelector<HTMLScriptElement>(`script[src="${SCRIPT}"]`);
    if (!script) {
      script = document.createElement('script');
      script.src = SCRIPT;
      script.async = true;
      document.head.appendChild(script);
    }
    script.addEventListener('load', render);
    return () => script?.removeEventListener('load', render);
  }, [siteKey]);

  function reset() {
    if (widget.current && window.turnstile) {
      window.turnstile.reset(widget.current);
    }
    setToken(null);
  }

  return { container, token, required: Boolean(siteKey), reset };
}
