import { lazy, Suspense } from 'react';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import HomePage from './pages/HomePage';
import ExplorePage from './pages/ExplorePage';
import ReplayPage from './pages/ReplayPage';
import StatsPage from './pages/StatsPage';
import TryPage from './pages/TryPage';

// The design mock and its sample data exist only in development builds; Vite removes this branch
// from the production bundle, so no sample data can reach visitors.
const DesignPage = import.meta.env.DEV ? lazy(() => import('./pages/design/DesignPage')) : null;
const DesignStatesPage = import.meta.env.DEV ? lazy(() => import('./pages/design/DesignStatesPage')) : null;

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={null}>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/replay/:pairKey" element={<ReplayPage />} />
          <Route path="/try" element={<TryPage />} />
          <Route path="/explore" element={<ExplorePage />} />
          <Route path="/stats" element={<StatsPage />} />
          {DesignPage ? <Route path="/design" element={<DesignPage />} /> : null}
          {DesignStatesPage ? <Route path="/design/states" element={<DesignStatesPage />} /> : null}
          <Route path="*" element={<HomePage />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
