import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Navigate, useParams, useSearchParams } from 'react-router-dom';
import { useBeforeSend } from '../../api/anatomy';
import { useActEnd } from '../../api/journey';
import { useLabOptions } from '../../api/lab';
import { useVisitor } from '../../api/queries';
import { AppHeader } from '../../components/AppHeader';
import { TermScope } from '../../components/common/Glossary';
import { PartWrap } from '../../components/journey/Cards';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { actEndSentence } from '../../journey/copy';
import { EXPERIENCE_STEPS } from '../../journey/journey';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import { CASES, modeOf, type Role, type StepFlow } from './experience';
import styles from './Experience.module.css';
import { AfterStep } from './steps/AfterStep';
import { CheckStep } from './steps/CheckStep';
import { CompareStep } from './steps/CompareStep';
import { PredictStep } from './steps/PredictStep';
import { ReasonStep } from './steps/ReasonStep';
import { ResultStep } from './steps/ResultStep';
import { RunStep } from './steps/RunStep';
import { SceneStep } from './steps/SceneStep';

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
      <PartWrap
        sentence={actEnd.data && actEnd.data.source !== 'NONE' ? actEndSentence(t, language, actEnd.data) : null}
        measured={actEnd.data?.source === 'MEASUREMENT'}
        differences={position.differences}
      />
    );
  }

  const previous = position.previous;
  // The main button's words are the next screen's question from the copy source (R-6); a step with its own action
  // (Send on the predict step) has none and draws that action itself.
  const nextWords = screen ? t(`screen.${screen.number}.next`, { defaultValue: '' }) : '';
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
  } else if (nextTo && nextWords) {
    nextDevice = <NextLink to={nextTo} label={nextWords} />;
  }
  const flow: StepFlow = {
    // The run is not left backwards while it goes; its way on is the result.
    back:
      previous && step !== 'run'
        ? {
            to: `${previous.path}${mode === 'async' && previous.path.startsWith(`/try/${role}/`) ? '?mode=async' : ''}`,
            label: t('frame.back'),
          }
        : null,
    next: nextDevice,
    teaser: null,
  };

  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page} data-type={position.screen?.type}>
        <TermScope>
          {options.isPending ? <StateScreen kind="loading" /> : null}
          {options.isError || (options.data && (!labCase || !employee)) ? (
            <StateScreen kind="notReady" />
          ) : null}
          {labCase && employee && options.data ? (
            <>
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
            </>
          ) : null}
        </TermScope>
      </main>
    </>
  );
}
