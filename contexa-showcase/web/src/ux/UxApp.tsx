import { lazy } from 'react';
import { Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import {
  homeScreen,
  introScreen,
  liveScreen,
  pickScreen,
  resultScreen,
  reviewScreen,
  withDictionary,
} from '../screens';
import { OLD_ADDRESSES, fillTarget, oldBenchmarkTarget, oldDetailTarget, oldGlossaryTarget } from './routes';
import { Shell } from './shell/Shell';

// The screens built so far (구현계획서 4절) are the first screens of src/screens.tsx; a menu without one opens its
// pending screen (DEC-15).

// Development-only page (Vite removes this branch from the production bundle): the new parts and states.
const PartsPage = import.meta.env.DEV ? lazy(withDictionary(() => import('./pages/design/PartsPage'))) : null;

// The screens built after the first screens (UX-R1 I-4~): their code and the rest of the dictionary load when opened.
const AgentPickPage = lazy(withDictionary(() => import('./pages/simulate/agent/PickPage')));
const AgentReviewPage = lazy(withDictionary(() => import('./pages/simulate/agent/ReviewPage')));
const AgentLivePage = lazy(withDictionary(() => import('./pages/simulate/agent/LivePage')));
const AgentResultPage = lazy(withDictionary(() => import('./pages/simulate/agent/ResultPage')));
const SurgePage = lazy(withDictionary(() => import('./pages/simulate/surge/SurgePage')));
const PolicyPage = lazy(withDictionary(() => import('./pages/simulate/policy/PolicyPage')));
const RunsPage = lazy(withDictionary(() => import('./pages/runs/RunsPage')));
const RunDetailPage = lazy(withDictionary(() => import('./pages/runs/RunDetailPage')));
const EnginePage = lazy(withDictionary(() => import('./pages/engine/EnginePage')));
const ComparePage = lazy(withDictionary(() => import('./pages/compare/ComparePage')));
const BenchmarksPage = lazy(withDictionary(() => import('./pages/benchmarks/BenchmarksPage')));
const ValidationPage = lazy(withDictionary(() => import('./pages/validation/ValidationPage')));
const MetricsPage = lazy(withDictionary(() => import('./pages/metrics/MetricsPage')));
const AdoptPage = lazy(withDictionary(() => import('./pages/adopt/AdoptPage')));
const GlossaryPage = lazy(withDictionary(() => import('./pages/glossary/GlossaryPage')));
const PrivacyPage = lazy(withDictionary(() => import('./pages/privacy/PrivacyPage')));
const TourPage = lazy(withDictionary(() => import('./pages/tour/TourPage')));

/** An old address: the new place that shows the same thing, with the old address's parameters carried over. */
function OldAddress({ to }: { readonly to: string }) {
  const params = useParams();
  const { search } = useLocation();
  const filled = fillTarget(to, params);
  const target = to.startsWith('/validation') ? oldBenchmarkTarget(filled, search) : filled;
  return <Navigate replace to={oldDetailTarget(search) ?? target} />;
}

/**
 * The application's addresses (구현계획서 3절): every menu inside the frame, the old addresses leading to their new
 * place, and anything else to the start of the demo. An old shared decision-details window (`?modal=detail`) opens the
 * run's decision details from any address.
 */
export function UxApp() {
  const { search } = useLocation();
  const detail = oldDetailTarget(search) ?? oldGlossaryTarget(search);
  if (detail) {
    return <Navigate replace to={detail} />;
  }
  return (
    <Routes>
      {/* The introduction stands alone, without the menu (DEC-76); the demo starts at /start (DEC-78). */}
      <Route path="/" element={<introScreen.Screen />} />
      <Route element={<Shell />}>
        <Route path="/start" element={<homeScreen.Screen />} />
        <Route path="/simulate/person" element={<pickScreen.Screen />} />
        <Route path="/simulate/person/:caseKey/review" element={<reviewScreen.Screen />} />
        <Route path="/simulate/person/:caseKey/live" element={<liveScreen.Screen />} />
        <Route path="/simulate/person/:caseKey/result" element={<resultScreen.Screen />} />
        <Route path="/simulate/agent" element={<AgentPickPage />} />
        <Route path="/simulate/agent/:caseKey/review" element={<AgentReviewPage />} />
        <Route path="/simulate/agent/:caseKey/live" element={<AgentLivePage />} />
        <Route path="/simulate/agent/:caseKey/result" element={<AgentResultPage />} />
        <Route path="/simulate/surge" element={<SurgePage />} />
        <Route path="/simulate/policy" element={<PolicyPage />} />
        <Route path="/runs" element={<RunsPage />} />
        <Route path="/runs/:runId" element={<RunDetailPage />} />
        <Route path="/engine" element={<EnginePage />} />
        <Route path="/compare" element={<ComparePage />} />
        <Route path="/benchmarks" element={<BenchmarksPage />} />
        <Route path="/benchmarks/:bench" element={<BenchmarksPage />} />
        <Route path="/validation" element={<ValidationPage />} />
        <Route path="/metrics" element={<MetricsPage />} />
        <Route path="/adopt" element={<AdoptPage />} />
        <Route path="/glossary" element={<GlossaryPage />} />
        <Route path="/privacy" element={<PrivacyPage />} />
        <Route path="/tour" element={<TourPage />} />
        {Object.entries(OLD_ADDRESSES).map(([from, to]) => (
          <Route key={from} path={from} element={<OldAddress to={to} />} />
        ))}
        <Route path="*" element={<Navigate replace to="/start" />} />
      </Route>
      {PartsPage ? <Route path="/design/ux" element={<PartsPage />} /> : null}
    </Routes>
  );
}
