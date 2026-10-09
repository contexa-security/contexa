import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useParams, useSearchParams } from 'react-router-dom';
import { useBeforeSend } from '../../api/anatomy';
import { useActEnd } from '../../api/journey';
import { useLabOptions } from '../../api/lab';
import { useVisitor } from '../../api/queries';
import { useTeasers } from '../../api/teasers';
import { AppHeader } from '../../components/AppHeader';
import { TermScope } from '../../components/common/Glossary';
import { ActEndCard, TeaserBand } from '../../components/journey/Cards';
import { stepName } from '../../components/journey/flow';
import { JourneyBar } from '../../components/journey/JourneyParts';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { actEndSentence, teaserCopy } from '../../journey/copy';
import { EXPERIENCE_STEPS } from '../../journey/journey';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import { CASES, modeOf, stepPath, type Role, type StepFlow } from './experience';
import styles from './Experience.module.css';
import { AfterStep } from './steps/AfterStep';
import { CheckStep } from './steps/CheckStep';
import { CompareStep } from './steps/CompareStep';
import { PredictStep } from './steps/PredictStep';
import { ReasonStep } from './steps/ReasonStep';
import { ResultStep } from './steps/ResultStep';
import { RunStep } from './steps/RunStep';
import { SceneStep } from './steps/SceneStep';

/** The "next" button of a step whose route device is a button, naming the step it leads to, by try. */
const NEXT_LABELS: Readonly<Record<Role, Readonly<Partial<Record<string, string>>>>> = {
  attacker: {
    scene: 'e1.next.compare',
    compare: 'e1.next.predict',
    run: 'e1.next.result',
    after: 'e1.next.end',
  },
  owner: {
    scene: 'e1.next.compare',
    compare: 'e1.next.predict',
    run: 'e1.next.result',
    reason: 'e2.next.rules',
    after: 'e2.next.follow',
  },
};

/**
 * A try of the default route in its seven steps (7.1, 7.2): each step has its own address (/try/attacker/scene …,
 * /try/owner/scene …), the place band on top, and one action area at its end with the way back, skip and the main
 * button, the teaser band over it where the route puts one. Try 1's act-end card is a screen of its own after its
 * follow-up (D-41); try 2's seventh step is the identity check.
 */
export default function ExperiencePage({ role }: { readonly role: Role }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const { step = 'scene' } = useParams();
  const [params] = useSearchParams();
  const mode = modeOf(params);
  useVisitor();
  const position = useJourneyPosition();
  const options = useLabOptions();
  const teasers = useTeasers();
  const ending = role === 'attacker' && step === 'end';
  const index = (EXPERIENCE_STEPS as readonly string[]).indexOf(step);
  const actEnd = useActEnd(1, ending);
  // The situation and the comparison read what the engine received in the latest run of the case; the case follows
  // from the address, so that record is asked for together with the case list instead of after it (C-13).
  useBeforeSend(step === 'scene' || step === 'compare' ? CASES[role][mode] : null, 1);

  if (index < 0 && !ending) {
    return <Navigate to={`/try/${role}/scene`} replace />;
  }
  const labCase = options.data?.cases.find((candidate) => candidate.key === CASES[role][mode]) ?? null;
  const employee =
    options.data?.employees.find((candidate) => candidate.key === labCase?.conditions.employee) ?? null;
  const screen = position.screen;
  const next = position.next;
  const nextTo = next
    ? `${next.path}${mode === 'async' && next.path.startsWith(`/try/${role}/`) ? '?mode=async' : ''}`
    : null;
  const see = (difference: Parameters<typeof position.see>[0]) => {
    if (!position.differences.includes(difference)) {
      void position.see(difference);
    }
  };

  if (ending) {
    return (
      <>
        <AppHeader />
        <main id="main" className={styles.page}>
          <JourneyBar />
          <ActEndCard
            act={1}
            differences={position.differences}
            sentence={
              actEnd.data && actEnd.data.source !== 'NONE' ? actEndSentence(t, language, actEnd.data) : null
            }
            measured={actEnd.data?.source === 'MEASUREMENT'}
            runId={actEnd.data?.runId ?? null}
            next={teaserCopy(t, language, 'E1_AFTER_RULES', teasers.data, position.differences.length)}
            continueTo={nextTo ?? '/try/owner/scene'}
            back={{
              to: stepPath('attacker', 'after', mode),
              label: t('step.back', { step: t('place.step.e1-after') }),
            }}
            resendAsyncTo={mode === 'sync' ? '/try/timing/try?from=attacker' : null}
            benchmarkTo="/benchmark"
            shareUrl={window.location.href}
          />
        </main>
      </>
    );
  }

  const previous = position.previous;
  const teaser =
    screen?.teaser && !screen.actEnd && nextTo ? (
      <TeaserBand copy={teaserCopy(t, language, screen.teaser, teasers.data, position.differences.length)} />
    ) : null;
  let nextDevice: ReactNode = null;
  // An attack sent again asynchronously from the "send it again" screen (sync-try, D-34) goes back there when it ends.
  const from = params.get('from');
  if (step === 'run' && from?.startsWith('timing')) {
    nextDevice = (
      <NextLink
        to={`/try/timing/try${from === 'timing-attacker' ? '?from=attacker' : ''}`}
        label={t('timing.try.backToResend')}
      />
    );
  } else if (teaser && nextTo) {
    nextDevice = <NextLink to={nextTo} label={t('teaser.see')} />;
  } else if (nextTo && NEXT_LABELS[role][step]) {
    nextDevice = <NextLink to={nextTo} label={t(NEXT_LABELS[role][step] ?? '')} />;
  }
  const flow: StepFlow = {
    // The run is not left backwards while it goes; its way on is the result.
    back:
      previous && step !== 'run'
        ? {
            to: `${previous.path}${mode === 'async' && previous.path.startsWith(`/try/${role}/`) ? '?mode=async' : ''}`,
            label: t('step.back', { step: stepName(t, previous, screen) }),
          }
        : null,
    next: nextDevice,
    teaser,
  };

  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page}>
        <JourneyBar />
        <TermScope>
          {options.isPending ? <StateScreen kind="loading" /> : null}
          {options.isError || (options.data && (!labCase || !employee)) ? (
            <StateScreen kind="notReady" />
          ) : null}
          {labCase && employee && options.data ? (
            <div className={styles.step}>
              {step === 'scene' ? (
                <SceneStep
                  role={role}
                  mode={mode}
                  labCase={labCase}
                  employee={employee}
                  options={options.data}
                  flow={flow}
                />
              ) : null}
              {step === 'compare' ? (
                <CompareStep role={role} labCase={labCase} see={see} flow={flow} />
              ) : null}
              {step === 'predict' ? (
                <PredictStep role={role} mode={mode} labCase={labCase} flow={flow} />
              ) : null}
              {step === 'run' ? (
                <RunStep role={role} mode={mode} labCase={labCase} see={see} flow={flow} />
              ) : null}
              {step === 'result' ? (
                <ResultStep role={role} mode={mode} labCase={labCase} see={see} flow={flow} />
              ) : null}
              {step === 'reason' ? (
                <ReasonStep role={role} mode={mode} labCase={labCase} see={see} flow={flow} />
              ) : null}
              {step === 'after' && role === 'owner' ? (
                <CheckStep mode={mode} labCase={labCase} see={see} flow={flow} />
              ) : null}
              {step === 'after' && role === 'attacker' ? (
                <AfterStep
                  role={role}
                  mode={mode}
                  labCase={labCase}
                  employee={employee}
                  see={see}
                  flow={flow}
                />
              ) : null}
            </div>
          ) : null}
        </TermScope>
      </main>
    </>
  );
}
