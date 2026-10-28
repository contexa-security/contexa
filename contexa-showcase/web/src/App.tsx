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
import { AppHeader } from './components/AppHeader';
import { COVER_REDIRECTS } from './journey/journey';
import ReplayPage from './pages/ReplayPage';
import GuidesPage from './pages/GuidesPage';
import OpeningPage from './pages/main/OpeningPage';
import {
  agentConfirmScreen,
  agentEndScreen,
  agentBurstScreen,
  agentResultScreen,
  agentChooseScreen,
  attackReasonScreen,
  agentNextScreen,
  agentConsoleScreen,
  agentReasonScreen,
  agentRequestScreen,
  approachesScreen,
  changeScreen,
  consoleScreen,
  deeperScreen,
  diffScreen,
  checkScreen,
  evidenceMapScreen,
  evidencePromptScreen,
  evidenceVerdictScreen,
  experienceScreen,
  followScreen,
  howScreen,
  insideScreen,
  introMapScreen,
  labBeforeScreen,
  labCaseScreen,
  labChangeScreen,
  labEntranceScreen,
  labResultScreen,
  labRulesScreen,
  labAgentScreen,
  labSendScreen,
  learnWhyScreen,
  learnedScreen,
  learnAfterScreen,
  moreScreen,
  nextScreen,
  personChooseScreen,
  personNextScreen,
  requestScreen,
  trackChooseScreen,
  resultScreen,
  ruleSwitchScreen,
  runsScreen,
  stackScreen,
  summaryScreen,
  timingScreen,
  withDictionary,
} from './screens';

// The first screen (hook) and the recorded replay, opened straight from shared links, ship in the main bundle
// (P2-FE-03); every other screen is loaded when it is opened (P5-FE-01), and, outside the main flow, drawn once the rest
// of the dictionary is in (FC-4, withDictionary).
const AdoptPage = lazy(withDictionary(() => import('./pages/AdoptPage')));
const PolicyPage = lazy(withDictionary(() => import('./pages/PolicyPage')));
// The decision details' window is loaded the first time a screen opens it.
const DecisionDetailModal = lazy(
  withDictionary(() =>
    import('./components/detail/DecisionDetail').then((module) => ({ default: module.DecisionDetailModal })),
  ),
);
const BenchSummaryPage = lazy(withDictionary(() => import('./pages/benchmark/BenchSummaryPage')));
const BenchApproachesPage = lazy(withDictionary(() => import('./pages/benchmark/BenchApproachesPage')));
const BenchCasesPage = lazy(withDictionary(() => import('./pages/benchmark/BenchCasesPage')));
const BenchJudgmentPage = lazy(withDictionary(() => import('./pages/benchmark/BenchJudgmentPage')));
const BenchReasoningPage = lazy(withDictionary(() => import('./pages/benchmark/BenchReasoningPage')));
const BenchLimitsPage = lazy(withDictionary(() => import('./pages/benchmark/BenchLimitsPage')));
const BenchAgentPage = lazy(withDictionary(() => import('./pages/benchmark/BenchAgentPage')));

// The design mock and its sample data exist only in development builds; Vite removes this branch
// from the production bundle, so no sample data can reach visitors.
const DesignStatesPage = import.meta.env.DEV
  ? lazy(withDictionary(() => import('./pages/design/DesignStatesPage')))
  : null;
const DesignPartsPage = import.meta.env.DEV
  ? lazy(withDictionary(() => import('./pages/design/DesignPartsPage')))
  : null;

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<LoadingScreen />}>
        <Routes>
          {/* The main flow (첫화면-선택형-체험-구현계획 3절): the start chooses a track; the person's track and the agent's
              each open with a chooser, walk the lanes of their cases and end in a next-chooser; the deeper screens sit
              behind a hub. The old covers' addresses lead to the first screen of what they opened. */}
          <Route path="/" element={<OpeningPage />} />
          <Route path="/choose" element={<trackChooseScreen.Screen />} />
          <Route path="/person" element={<personChooseScreen.Screen />} />
          <Route path="/person/next" element={<personNextScreen.Screen />} />
          <Route path="/deeper" element={<deeperScreen.Screen />} />
          {Object.entries(COVER_REDIRECTS).map(([cover, target]) => (
            <Route key={cover} path={cover} element={<Navigate to={target} replace />} />
          ))}
          <Route path="/intro/map" element={<introMapScreen.Screen />} />
          <Route path="/attack/request" element={<requestScreen.Screen role="attacker" />} />
          <Route path="/attack/console" element={<consoleScreen.Screen role="attacker" />} />
          <Route path="/attack/result" element={<resultScreen.Screen />} />
          <Route path="/attack/reason" element={<attackReasonScreen.Screen />} />
          <Route path="/evidence/map" element={<evidenceMapScreen.Screen />} />
          <Route path="/evidence/prompt" element={<evidencePromptScreen.Screen />} />
          <Route path="/evidence/verdict" element={<evidenceVerdictScreen.Screen />} />
          <Route path="/normal/request" element={<requestScreen.Screen role="owner" />} />
          <Route path="/normal/console" element={<consoleScreen.Screen role="owner" />} />
          <Route path="/normal/diff" element={<diffScreen.Screen />} />
          <Route path="/normal/check" element={<checkScreen.Screen />} />
          <Route path="/insider/request" element={<requestScreen.Screen role="insider" />} />
          <Route path="/insider/console" element={<consoleScreen.Screen role="insider" />} />
          <Route path="/insider/reason" element={<insideScreen.Screen />} />
          {/* docs/agent A7-3: the business agent group (화면설계 4절 AD-0 to AD-4). */}
          <Route path="/agent" element={<agentChooseScreen.Screen />} />
          <Route path="/agent/next" element={<agentNextScreen.Screen />} />
          <Route path="/agent/request" element={<agentRequestScreen.Screen />} />
          <Route path="/agent/console" element={<agentConsoleScreen.Screen />} />
          <Route path="/agent/reason" element={<agentReasonScreen.Screen />} />
          <Route path="/agent/confirm" element={<agentConfirmScreen.Screen />} />
          <Route path="/agent/end" element={<agentEndScreen.Screen />} />
          <Route path="/agent/burst" element={<agentBurstScreen.Screen />} />
          <Route path="/agent/result" element={<agentResultScreen.Screen />} />
          <Route path="/compare/rule" element={<ruleSwitchScreen.Screen />} />
          <Route path="/compare/change" element={<changeScreen.Screen />} />
          {/* The attack inside the rules became group 2's stolen account (IN-6); its address leads to the insider. */}
          <Route path="/compare/inside" element={<Navigate to="/insider/reason" replace />} />
          <Route path="/compare/runs" element={<runsScreen.Screen />} />
          <Route path="/summary" element={<summaryScreen.Screen />} />
          <Route path="/summary/next" element={<nextScreen.Screen />} />
          {/* "Learn more": the screens of the flow before, walked by topic and ending back at the hub. */}
          <Route path="/more" element={<moreScreen.Screen />} />
          <Route path="/intro/learning" element={<learnWhyScreen.Screen />} />
          <Route path="/intro/learning/learned" element={<learnedScreen.Screen />} />
          <Route path="/intro/how" element={<howScreen.Screen />} />
          <Route path="/try/stack" element={<stackScreen.Screen />} />
          <Route path="/try/summary/learning" element={<learnAfterScreen.Screen ending={false} />} />
          <Route path="/try/timing/:step" element={<timingScreen.Screen />} />
          <Route path="/try/follow" element={<followScreen.Screen ending={false} />} />
          <Route path="/intro/approaches" element={<approachesScreen.Screen />} />
          <Route path="/replay/:pairKey" element={<ReplayPage />} />
          {/* The flow before: its addresses lead to the screen of the new flow that took their place. */}
          <Route path="/part/:part" element={<PartAddress />} />
          <Route path="/try/attacker/:step" element={<TryAddress role="attacker" />} />
          <Route path="/try/owner/:step" element={<TryAddress role="owner" />} />
          <Route path="/try/prompt" element={<Navigate to="/evidence/prompt" replace />} />
          <Route path="/try/timing/end" element={<Navigate to="/more" replace />} />
          <Route path="/try/follow/end" element={<Navigate to="/more" replace />} />
          <Route path="/try/summary/learning/end" element={<Navigate to="/more" replace />} />
          <Route path="/try/summary/dilemma" element={<Navigate to="/compare/rule" replace />} />
          <Route path="/try/summary/recap" element={<Navigate to="/summary" replace />} />
          <Route path="/try/summary/quiz" element={<Navigate to="/summary" replace />} />
          <Route path="/try/summary/value" element={<Navigate to="/summary" replace />} />
          <Route path="/try/summary/adopt" element={<Navigate to="/summary/next" replace />} />
          <Route path="/try/summary/end" element={<Navigate to="/summary/next" replace />} />
          <Route path="/intro/how/rules" element={<Navigate to="/evidence/verdict" replace />} />
          <Route path="/intro" element={<Navigate to="/" replace />} />
          <Route path="/intro/concept" element={<Navigate to="/" replace />} />
          <Route path="/intro/compare" element={<Navigate to="/" replace />} />
          <Route path="/intro/order" element={<Navigate to="/" replace />} />
          <Route path="/intro/approaches/where" element={<Navigate to="/intro/approaches" replace />} />
          <Route path="/try" element={<Navigate to="/" replace />} />
          <Route path="/explore" element={<Navigate to="/" replace />} />
          {/* W4-5: the old "other scenes" and "statistics" screens gave way to the lab and the benchmark. */}
          <Route path="/stats" element={<Navigate to="/benchmark" replace />} />
          <Route path="/end/:pairKey" element={<Navigate to="/summary" replace />} />
          <Route path="/library" element={<Navigate to="/lab" replace />} />
          <Route path="/adopt" element={<AdoptPage />} />
          <Route path="/videos" element={<GuidesPage />} />
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
          <Route path="/lab/agent" element={<labAgentScreen.Screen />} />
          <Route path="/benchmark" element={<BenchSummaryPage />} />
          <Route path="/benchmark/approaches" element={<BenchApproachesPage />} />
          <Route path="/benchmark/cases" element={<BenchCasesPage />} />
          <Route path="/benchmark/cases/:caseKey" element={<CaseAddress />} />
          <Route path="/benchmark/judgment" element={<BenchJudgmentPage />} />
          <Route path="/benchmark/reasoning" element={<BenchReasoningPage />} />
          <Route path="/benchmark/prompt" element={<Navigate to="/benchmark/reasoning" replace />} />
          <Route path="/benchmark/limits" element={<BenchLimitsPage />} />
          <Route path="/benchmark/agent" element={<BenchAgentPage />} />
          {DesignStatesPage ? <Route path="/design/states" element={<DesignStatesPage />} /> : null}
          {DesignPartsPage ? <Route path="/design/parts" element={<DesignPartsPage />} /> : null}
          <Route path="*" element={<OpeningPage />} />
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
      <GlossaryModal />
      {detailWanted ? (
        <Suspense fallback={null}>
          <DecisionDetailModal />
        </Suspense>
      ) : null}
    </>
  );
}

/** Where an old part's briefing leads (최종화면-구현계획 2절): the cover of the group that took its place. */
const PART_COVERS: Readonly<Record<string, string>> = {
  '1': '/attack',
  '2': '/normal',
  '3': '/more',
  '4': '/more',
  '5': '/compare',
};

function PartAddress() {
  const { part = '' } = useParams();
  return <Navigate replace to={PART_COVERS[part] ?? '/'} />;
}

/** Where an old try step leads: the screen of the new flow that shows the same moment. */
const TRY_STEPS: Readonly<Record<'attacker' | 'owner', Readonly<Record<string, string>>>> = {
  attacker: {
    scene: '/attack/request',
    compare: '/attack/request',
    predict: '/attack/request',
    run: '/attack/console',
    result: '/attack/result',
    reason: '/attack/result',
    after: '/attack/result',
    end: '/evidence',
  },
  owner: {
    scene: '/normal/request',
    compare: '/normal/request',
    predict: '/normal/request',
    run: '/normal/console',
    result: '/normal/diff',
    reason: '/normal/diff',
    after: '/normal/console',
  },
};

/**
 * An old try step's address. The run step the timing topic sends its asynchronous resend on stays the try's run page
 * (a request sent "from=timing" belongs to that topic); every other step leads to the new flow.
 */
function TryAddress({ role }: { readonly role: 'attacker' | 'owner' }) {
  const { step = '' } = useParams();
  const [params] = useSearchParams();
  if (step === 'run' && params.get('from')?.startsWith('timing')) {
    return <experienceScreen.Screen role={role} />;
  }
  return <Navigate replace to={TRY_STEPS[role][step] ?? (role === 'attacker' ? '/attack' : '/normal')} />;
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
