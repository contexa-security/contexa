import { lazy, Suspense, useEffect, useRef, useState } from 'react';
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigationType,
  useParams,
  useSearchParams,
} from 'react-router-dom';
import { GlossaryModal } from './components/common/Glossary';
import { DetailAddress } from './components/detail/DetailAddress';
import { DETAIL_MODAL } from './components/detail/useDetail';
import { SiteFooter } from './components/SiteFooter';
import { AppHeader } from './components/AppHeader';
import ReplayPage from './pages/ReplayPage';
import HookPage from './pages/try/HookPage';
import {
  adoptChangeScreen,
  approachesScreen,
  compareScreen,
  conceptScreen,
  dilemmaScreen,
  experienceScreen,
  followScreen,
  howScreen,
  introScreen,
  labBeforeScreen,
  labCaseScreen,
  labChangeScreen,
  labEntranceScreen,
  labResultScreen,
  labRulesScreen,
  labSendScreen,
  learnWhyScreen,
  learnedScreen,
  promptScreen,
  learnAfterScreen,
  orderScreen,
  quizScreen,
  recapScreen,
  rulesScreen,
  stackScreen,
  timingScreen,
  valueScreen,
  whereScreen,
} from './screens';

// The first screen (hook) and the recorded replay, opened straight from shared links, ship in the main bundle
// (P2-FE-03); every other screen is loaded when it is opened (P5-FE-01).
const AdoptPage = lazy(() => import('./pages/AdoptPage'));
const PolicyPage = lazy(() => import('./pages/PolicyPage'));
// The decision details' window is loaded the first time a screen opens it.
const DecisionDetailModal = lazy(() =>
  import('./components/detail/DecisionDetail').then((module) => ({ default: module.DecisionDetailModal })),
);
const BenchSummaryPage = lazy(() => import('./pages/benchmark/BenchSummaryPage'));
const BenchCasesPage = lazy(() => import('./pages/benchmark/BenchCasesPage'));
const BenchJudgmentPage = lazy(() => import('./pages/benchmark/BenchJudgmentPage'));
const BenchLimitsPage = lazy(() => import('./pages/benchmark/BenchLimitsPage'));

// The design mock and its sample data exist only in development builds; Vite removes this branch
// from the production bundle, so no sample data can reach visitors.
const DesignStatesPage = import.meta.env.DEV ? lazy(() => import('./pages/design/DesignStatesPage')) : null;
const DesignPartsPage = import.meta.env.DEV ? lazy(() => import('./pages/design/DesignPartsPage')) : null;

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<LoadingScreen />}>
        <Routes>
          <Route path="/" element={<HookPage />} />
          <Route path="/replay/:pairKey" element={<ReplayPage />} />
          {/* Try 1 of act 1 in its seven steps (7.1). */}
          <Route path="/try/attacker/:step" element={<experienceScreen.Screen role="attacker" />} />
          {/* Act 2 (7.2): try 2 in its seven steps, the published rules, the follow-up map and the act's end. */}
          <Route path="/try/owner/:step" element={<experienceScreen.Screen role="owner" />} />
          <Route path="/intro/how/rules" element={<rulesScreen.Screen />} />
          <Route path="/intro/learning" element={<learnWhyScreen.Screen />} />
          <Route path="/intro/learning/learned" element={<learnedScreen.Screen />} />
          <Route path="/intro/how" element={<howScreen.Screen />} />
          <Route path="/try/prompt" element={<promptScreen.Screen />} />
          <Route path="/try/timing/:step" element={<timingScreen.Screen />} />
          <Route path="/try/stack" element={<stackScreen.Screen />} />
          <Route path="/try/summary/learning" element={<learnAfterScreen.Screen ending={false} />} />
          <Route path="/try/summary/learning/end" element={<learnAfterScreen.Screen ending />} />
          <Route path="/try/follow" element={<followScreen.Screen ending={false} />} />
          <Route path="/try/follow/end" element={<followScreen.Screen ending />} />
          <Route path="/intro" element={<introScreen.Screen />} />
          <Route path="/intro/concept" element={<conceptScreen.Screen />} />
          <Route path="/intro/compare" element={<compareScreen.Screen />} />
          <Route path="/intro/order" element={<orderScreen.Screen />} />
          <Route path="/intro/approaches" element={<approachesScreen.Screen />} />
          <Route path="/intro/approaches/where" element={<whereScreen.Screen />} />
          <Route path="/try/summary/dilemma" element={<dilemmaScreen.Screen />} />
          <Route path="/try/summary/recap" element={<recapScreen.Screen />} />
          <Route path="/try/summary/quiz" element={<quizScreen.Screen />} />
          <Route path="/try/summary/value" element={<valueScreen.Screen />} />
          <Route path="/try/summary/adopt" element={<adoptChangeScreen.Screen />} />
          {/* Trying it and changing the conditions are part of the experience now. */}
          <Route path="/try" element={<Navigate to="/" replace />} />
          <Route path="/explore" element={<Navigate to="/" replace />} />
          {/* W4-5: the old "other scenes" and "statistics" screens gave way to the lab and the benchmark. */}
          <Route path="/stats" element={<Navigate to="/benchmark" replace />} />
          {/* The old end screen counted on the screen (T-42); its address leads to what the visitor did. */}
          <Route path="/end/:pairKey" element={<Navigate to="/try/summary/recap" replace />} />
          <Route path="/library" element={<Navigate to="/lab" replace />} />
          <Route path="/adopt" element={<AdoptPage />} />
          <Route path="/privacy" element={<PolicyPage />} />
          <Route path="/run/:runId/detail" element={<DetailAddress />} />
          <Route path="/runs/:runId/steps/:stepNo" element={<DetailAddress />} />
          <Route path="/lab" element={<labEntranceScreen.Screen />} />
          <Route path="/lab/case" element={<labCaseScreen.Screen />} />
          <Route path="/lab/change" element={<labChangeScreen.Screen />} />
          <Route path="/lab/before" element={<labBeforeScreen.Screen />} />
          <Route path="/lab/send" element={<labSendScreen.Screen />} />
          <Route path="/lab/result" element={<labResultScreen.Screen />} />
          <Route path="/lab/rules" element={<labRulesScreen.Screen />} />
          <Route path="/benchmark" element={<BenchSummaryPage />} />
          <Route path="/benchmark/cases" element={<BenchCasesPage />} />
          <Route path="/benchmark/cases/:caseKey" element={<CaseAddress />} />
          <Route path="/benchmark/judgment" element={<BenchJudgmentPage />} />
          <Route path="/benchmark/limits" element={<BenchLimitsPage />} />
          {DesignStatesPage ? <Route path="/design/states" element={<DesignStatesPage />} /> : null}
          {DesignPartsPage ? <Route path="/design/parts" element={<DesignPartsPage />} /> : null}
          <Route path="*" element={<HookPage />} />
        </Routes>
      </Suspense>
      <VisitorChrome />
      <RouteFocus />
    </BrowserRouter>
  );
}

/**
 * The footer links and the windows every visitor screen can open (the glossary, the decision details); the
 * development-only design mocks are left out. Once opened, the details stay mounted, so closing them returns the focus
 * to the button that opened them.
 */
/**
 * A new screen starts at its top with the focus on its heading (WCAG 2.4.3, S12): the address keeps the scroll of the
 * screen before otherwise, so the next screen opened partway down. Back and forward keep the browser's own place, a
 * window that is open keeps its focus, and the first load keeps the browser's start (the skip link first).
 */
function RouteFocus() {
  const { pathname } = useLocation();
  const navigation = useNavigationType();
  const first = useRef(true);
  // The heading of the screen last settled on; a heading with other words is the next screen's.
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
        heading.tabIndex = -1;
        heading.focus({ preventScroll: true });
        window.scrollTo({ top: 0 });
      }
    }, 50);
    return () => window.clearInterval(timer);
  }, [pathname, navigation]);
  return null;
}

function VisitorChrome() {
  const { pathname } = useLocation();
  const [params] = useSearchParams();
  const [detailWanted, setDetailWanted] = useState(false);
  if (!detailWanted && params.get('modal') === DETAIL_MODAL) {
    setDetailWanted(true);
  }
  return pathname.startsWith('/design') ? null : (
    <>
      <SiteFooter />
      <GlossaryModal />
      {detailWanted ? (
        <Suspense fallback={null}>
          <DecisionDetailModal />
        </Suspense>
      ) : null}
    </>
  );
}

/** A case's own address (7.8, `/benchmark/cases/:caseKey`): the case window over the case list. */
function CaseAddress() {
  const { caseKey = '' } = useParams();
  const [params] = useSearchParams();
  const next = new URLSearchParams(params);
  next.set('modal', 'case');
  next.set('case', caseKey);
  return <Navigate replace to={{ pathname: '/benchmark/cases', search: `?${next.toString()}` }} />;
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
