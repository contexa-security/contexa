import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './styles/tokens.css';
import './styles/base.css';
import { i18nReady } from './i18n';
import App from './App';
import { preloadFirstScreen } from './screens';
import { fontInCache, loadFonts, loadFontsAfterFirstScreen } from './fonts';

const queryClient = new QueryClient();

const root = document.getElementById('root');

function render(container: HTMLElement) {
  createRoot(container).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </StrictMode>,
  );
}

if (root) {
  // A step opened straight from its address waits for its code and head records, and every screen for the visitor's
  // dictionary (index.html preloaded it), so the first paint is the screen itself instead of a loading fallback (C-13);
  // if something cannot be read now, the screen loads it when it renders, as before.
  void Promise.allSettled([preloadFirstScreen(window.location, queryClient), i18nReady]).then(() =>
    render(root),
  );
}

// A returning visitor's browser has the font in its cache, so it is read at once; a first visit reads it after the
// first screen is shown (C-13).
if (fontInCache()) {
  loadFonts();
} else {
  loadFontsAfterFirstScreen();
}
