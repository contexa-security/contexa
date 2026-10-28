import type { QueryClient } from '@tanstack/react-query';
import { lazy, type ComponentType } from 'react';
import { beforeSendQuery } from './api/anatomy';
import { labOptionsQuery } from './api/lab';
import { firstScreenOf, type FirstScreenModule } from './firstScreens';
import { dictionaryComplete } from './i18n';
import { CASES, modeOf } from './pages/try/experience';

/**
 * A screen outside the main flow is drawn once the rest of the dictionary is in (FC-4, dictionarySplit.ts): its words
 * are not in the part the first screen reads. If the rest cannot be read, the screen is drawn anyway.
 */
export function withDictionary<T>(load: () => Promise<T>): () => Promise<T> {
  return () => Promise.all([load(), dictionaryComplete().catch(() => undefined)]).then(([module]) => module);
}

/**
 * A screen whose code loads when it is first opened (P5-FE-01), which a visitor can also open straight from a shared
 * step link. On such a first load its code is read before the first render, so the screen never waits behind the
 * loading fallback, which React keeps for at least 300 ms once shown (C-13).
 */
function preloadable<P extends object>(load: () => Promise<{ default: ComponentType<P> }>) {
  let loaded: ComponentType<P> | null = null;
  const Lazy = lazy(load);
  function Screen(props: P) {
    const Loaded = loaded;
    return Loaded ? <Loaded {...props} /> : <Lazy {...props} />;
  }
  return {
    Screen,
    preload: () =>
      load().then((module) => {
        loaded = module.default;
      }),
  };
}

export const experienceScreen = preloadable(withDictionary(() => import('./pages/try/ExperiencePage')));
export const followScreen = preloadable(withDictionary(() => import('./pages/try/FollowPage')));
export const learnWhyScreen = preloadable(withDictionary(() => import('./pages/intro/LearnWhyPage')));
export const learnedScreen = preloadable(withDictionary(() => import('./pages/intro/LearnedPage')));
export const howScreen = preloadable(withDictionary(() => import('./pages/intro/HowPage')));
export const timingScreen = preloadable(withDictionary(() => import('./pages/try/TimingPage')));
export const stackScreen = preloadable(withDictionary(() => import('./pages/try/StackPage')));
export const learnAfterScreen = preloadable(withDictionary(() => import('./pages/try/LearnAfterPage')));
export const approachesScreen = preloadable(withDictionary(() => import('./pages/intro/ApproachesPage')));
export const trackChooseScreen = preloadable(() => import('./pages/main/TrackChoosePage'));
export const personChooseScreen = preloadable(() => import('./pages/main/PersonChoosePage'));
export const personNextScreen = preloadable(() => import('./pages/main/PersonNextPage'));
export const agentChooseScreen = preloadable(() => import('./pages/main/AgentChoosePage'));
export const agentNextScreen = preloadable(() => import('./pages/main/AgentNextPage'));
export const deeperScreen = preloadable(() => import('./pages/main/DeeperPage'));
export const introMapScreen = preloadable(() => import('./pages/main/IntroMapPage'));
export const requestScreen = preloadable(() => import('./pages/main/RequestPage'));
export const consoleScreen = preloadable(() => import('./pages/main/ConsolePage'));
export const resultScreen = preloadable(() => import('./pages/main/ResultPage'));
export const attackReasonScreen = preloadable(() => import('./pages/main/AttackReasonPage'));
export const evidenceMapScreen = preloadable(() => import('./pages/main/EvidenceMapPage'));
export const evidencePromptScreen = preloadable(() => import('./pages/main/EvidencePromptPage'));
export const evidenceVerdictScreen = preloadable(() => import('./pages/main/EvidenceVerdictPage'));
export const diffScreen = preloadable(() => import('./pages/main/DiffPage'));
export const checkScreen = preloadable(() => import('./pages/main/CheckPage'));
export const ruleSwitchScreen = preloadable(() => import('./pages/main/RuleSwitchPage'));
export const changeScreen = preloadable(() => import('./pages/main/ChangePage'));
export const insideScreen = preloadable(() => import('./pages/main/InsidePage'));
export const agentRequestScreen = preloadable(() => import('./pages/main/AgentRequestPage'));
export const agentConsoleScreen = preloadable(() => import('./pages/main/AgentConsolePage'));
export const agentReasonScreen = preloadable(() => import('./pages/main/AgentReasonPage'));
export const agentConfirmScreen = preloadable(() => import('./pages/main/AgentConfirmPage'));
export const agentEndScreen = preloadable(() => import('./pages/main/AgentEndPage'));
export const agentBurstScreen = preloadable(() => import('./pages/main/AgentBurstPage'));
export const agentResultScreen = preloadable(() => import('./pages/main/AgentResultPage'));
export const runsScreen = preloadable(() => import('./pages/main/RunsPage'));
export const summaryScreen = preloadable(() => import('./pages/main/SummaryPage'));
export const nextScreen = preloadable(() => import('./pages/main/NextPage'));
export const moreScreen = preloadable(() => import('./pages/more/MorePage'));
export const labEntranceScreen = preloadable(withDictionary(() => import('./pages/lab/LabEntrancePage')));
export const labCaseScreen = preloadable(withDictionary(() => import('./pages/lab/LabCasePage')));
export const labChangeScreen = preloadable(withDictionary(() => import('./pages/lab/LabChangePage')));
export const labBeforeScreen = preloadable(withDictionary(() => import('./pages/lab/LabBeforePage')));
export const labSendScreen = preloadable(withDictionary(() => import('./pages/lab/LabSendPage')));
export const labResultScreen = preloadable(withDictionary(() => import('./pages/lab/LabResultPage')));
export const labRulesScreen = preloadable(withDictionary(() => import('./pages/lab/LabRulesPage')));
export const labAgentScreen = preloadable(withDictionary(() => import('./pages/lab/LabAgentPage')));

/** Each first screen's code, by the module the shared rule (src/firstScreens.ts) names. */
const BY_MODULE: Readonly<Record<FirstScreenModule, { readonly preload: () => Promise<void> }>> = {
  'pages/try/ExperiencePage': experienceScreen,
  'pages/try/TimingPage': timingScreen,
  'pages/try/FollowPage': followScreen,
  'pages/intro/LearnWhyPage': learnWhyScreen,
  'pages/intro/LearnedPage': learnedScreen,
  'pages/intro/HowPage': howScreen,
  'pages/try/StackPage': stackScreen,
  'pages/try/LearnAfterPage': learnAfterScreen,
  'pages/intro/ApproachesPage': approachesScreen,
  'pages/main/TrackChoosePage': trackChooseScreen,
  'pages/main/PersonChoosePage': personChooseScreen,
  'pages/main/PersonNextPage': personNextScreen,
  'pages/main/AgentChoosePage': agentChooseScreen,
  'pages/main/AgentNextPage': agentNextScreen,
  'pages/main/DeeperPage': deeperScreen,
  'pages/main/IntroMapPage': introMapScreen,
  'pages/main/RequestPage': requestScreen,
  'pages/main/ConsolePage': consoleScreen,
  'pages/main/ResultPage': resultScreen,
  'pages/main/AttackReasonPage': attackReasonScreen,
  'pages/main/EvidenceMapPage': evidenceMapScreen,
  'pages/main/EvidencePromptPage': evidencePromptScreen,
  'pages/main/EvidenceVerdictPage': evidenceVerdictScreen,
  'pages/main/DiffPage': diffScreen,
  'pages/main/CheckPage': checkScreen,
  'pages/main/RuleSwitchPage': ruleSwitchScreen,
  'pages/main/ChangePage': changeScreen,
  'pages/main/InsidePage': insideScreen,
  'pages/main/AgentRequestPage': agentRequestScreen,
  'pages/main/AgentConsolePage': agentConsoleScreen,
  'pages/main/AgentReasonPage': agentReasonScreen,
  'pages/main/AgentConfirmPage': agentConfirmScreen,
  'pages/main/AgentEndPage': agentEndScreen,
  'pages/main/AgentBurstPage': agentBurstScreen,
  'pages/main/AgentResultPage': agentResultScreen,
  'pages/main/RunsPage': runsScreen,
  'pages/main/SummaryPage': summaryScreen,
  'pages/main/NextPage': nextScreen,
  'pages/more/MorePage': moreScreen,
  'pages/lab/LabEntrancePage': labEntranceScreen,
  'pages/lab/LabCasePage': labCaseScreen,
  'pages/lab/LabChangePage': labChangeScreen,
  'pages/lab/LabBeforePage': labBeforeScreen,
  'pages/lab/LabSendPage': labSendScreen,
  'pages/lab/LabResultPage': labResultScreen,
  'pages/lab/LabRulesPage': labRulesScreen,
  'pages/lab/LabAgentPage': labAgentScreen,
};

/** How long the first render waits at most for the records of a step opened straight from its address. */
const FIRST_RECORDS_LIMIT_MS = 1500;

/**
 * Reads the code of the screen at the first address before the first render, and the records its head shows (the case
 * list, and the latest run's comparison for the situation and the comparison) at the same time, so the first paint
 * already carries the step's headline. A slow answer holds the first render no longer than the limit; the screen then
 * shows its loading state as before. The other screens need nothing.
 */
export function preloadFirstScreen(location: Location, queryClient: QueryClient): Promise<void> {
  const module = firstScreenOf(location.pathname);
  if (module === null) {
    return Promise.resolve();
  }
  if (module !== 'pages/try/ExperiencePage') {
    return BY_MODULE[module].preload();
  }
  const match = /^\/try\/(attacker|owner)\/([a-z]+)$/.exec(location.pathname);
  const role = match?.[1] === 'owner' ? 'owner' : 'attacker';
  const step = match?.[2] ?? '';
  const records = [queryClient.prefetchQuery(labOptionsQuery)];
  if (step === 'scene' || step === 'compare') {
    const mode = modeOf(new URLSearchParams(location.search));
    records.push(queryClient.prefetchQuery(beforeSendQuery(CASES[role][mode], 1)));
  }
  const limit = new Promise<void>((done) => {
    setTimeout(done, FIRST_RECORDS_LIMIT_MS);
  });
  return Promise.all([experienceScreen.preload(), Promise.race([Promise.all(records), limit])]).then(
    () => undefined,
  );
}
