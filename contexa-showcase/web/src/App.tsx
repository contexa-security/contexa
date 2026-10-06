import { lazy, Suspense } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { SiteFooter } from './components/SiteFooter';
import { AppHeader } from './components/AppHeader';
import ExperiencePage from './pages/ExperiencePage';
import ReplayPage from './pages/ReplayPage';

// The experience (docs/showcase/체험우선-설계.md) and the recorded replay, opened straight from shared links, ship in the
// main bundle (P2-FE-03); every other screen is loaded when it is opened (P5-FE-01).
const StatsPage = lazy(() => import('./pages/StatsPage'));
const EndPage = lazy(() => import('./pages/EndPage'));
const LibraryPage = lazy(() => import('./pages/LibraryPage'));
const AdoptPage = lazy(() => import('./pages/AdoptPage'));
const PolicyPage = lazy(() => import('./pages/PolicyPage'));

// The design mock and its sample data exist only in development builds; Vite removes this branch
// from the production bundle, so no sample data can reach visitors.
const DesignPage = import.meta.env.DEV ? lazy(() => import('./pages/design/DesignPage')) : null;
const DesignStatesPage = import.meta.env.DEV ? lazy(() => import('./pages/design/DesignStatesPage')) : null;

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<LoadingScreen />}>
        <Routes>
          <Route path="/" element={<ExperiencePage />} />
          <Route path="/replay/:pairKey" element={<ReplayPage />} />
          {/* Trying it and changing the conditions are part of the experience now. */}
          <Route path="/try" element={<Navigate to="/" replace />} />
          <Route path="/explore" element={<Navigate to="/" replace />} />
          <Route path="/stats" element={<StatsPage />} />
          <Route path="/end/:pairKey" element={<EndPage />} />
          <Route path="/library" element={<LibraryPage />} />
          <Route path="/adopt" element={<AdoptPage />} />
          <Route path="/privacy" element={<PolicyPage />} />
          {DesignPage ? <Route path="/design" element={<DesignPage />} /> : null}
          {DesignStatesPage ? <Route path="/design/states" element={<DesignStatesPage />} /> : null}
          <Route path="*" element={<ExperiencePage />} />
        </Routes>
      </Suspense>
      <VisitorChrome />
    </BrowserRouter>
  );
}

/** The footer links on every visitor screen; the development-only design mocks are left out. */
function VisitorChrome() {
  const { pathname } = useLocation();
  return pathname.startsWith('/design') ? null : <SiteFooter />;
}

/** While a screen's code loads: the same header and an empty main area, so nothing moves when it arrives. */
function LoadingScreen() {
  return (
    <>
      <AppHeader />
      <main id="main" />
    </>
  );
}
