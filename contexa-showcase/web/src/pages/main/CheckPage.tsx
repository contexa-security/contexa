import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useBeforeSend } from '../../api/anatomy';
import { useBenchmark } from '../../api/benchmark';
import { postJson } from '../../api/http';
import { useJourney } from '../../api/journey';
import { useLabOptions } from '../../api/lab';
import { useTeasers } from '../../api/teasers';
import type { LiveRunView } from '../../api/types';
import { ChallengePanel } from '../../components/ChallengePanel';
import { MainButton, MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { useLiveSend } from '../../hooks/useLiveSend';
import { count } from '../../journey/format';
import { useTryRun } from '../try/steps/tryRun';
import { blindNote, caseOf, companyClock, personName, readsAgain } from './mainCases';
import { LearnLine } from './ProofPanel';
import { CheckRecord, StepRow } from './RequestSteps';
import styles from './CheckPage.module.css';

/**
 * The real user's case whose work Contexa checks on the way (최종화면-구현계획 FU-3): an engineer on a registered
 * business trip, on a laptop never seen before, at the company's dawn, opens two assigned drawings and exports twelve
 * items. It is the one designed legitimate case whose extra check meets the visitor in a live run (measured 5 of 5).
 */
export const CHECK_CASE = 'S14';

/** The run states during which the screen still follows the run. */
const GOING = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED']);

/** The check stages in which the visitor still has something to do. */
const CHECK_OPEN = new Set(['WAITING', 'CODE_SHOWN', 'VERIFYING', 'CANCELLED']);

/**
 * Moves the keyboard to a card's heading and brings it into view only when needed, clear of the sticky header by the
 * heading's scroll margin (B-06: a heading scrolled to the very top hid under the header).
 */
function bringTo(heading: HTMLElement | null) {
  heading?.focus({ preventScroll: true });
  heading?.scrollIntoView?.({ block: 'nearest' });
}

/**
 * 4-4, the real user checked on the way (FU-3): the visitor sends the case and watches its three requests go out with
 * the usual gap between them. When Contexa asks for an extra check the code comes to the demo inbox, the visitor
 * confirms it and the request goes again. Each request shows what the four existing approaches and Contexa did; at the
 * end the headline, the comparison, the extra check as recorded and the learning come from the run's own records
 * (L-36).
 */
export default function CheckPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const queryClient = useQueryClient();
  const options = useLabOptions();
  const found = caseOf(options.data, CHECK_CASE);
  const steps = found?.labCase.steps ?? 3;
  const run = useTryRun(CHECK_CASE, steps);
  const view: LiveRunView | null = run.view;
  const before = useBeforeSend(CHECK_CASE, 1);
  const journey = useJourney(true);
  const teasers = useTeasers();
  const requestsTitle = useRef<HTMLHeadingElement>(null);
  const wayTitle = useRef<HTMLHeadingElement>(null);
  const { send, sending, ready, refusal, waiting, turnstileContainer, turnstileRequired } = useLiveSend(
    CHECK_CASE,
    () => bringTo(requestsTitle.current),
  );
  const benchmark = useBenchmark(null);
  // The approval-record rule's footnote adds that the case is not in its conditions only for a rule-blind case (V-12).
  const note = blindNote(benchmark.data?.suites.find((suite) => suite.suite === 'RULE_BLIND')?.cases ?? [], [
    CHECK_CASE,
  ]);
  const going = view !== null && !run.stored && GOING.has(view.status);
  const finished = view !== null && (run.stored || view.status === 'COMPLETED');
  const runId = finished ? run.runId : null;
  const line =
    runId === null
      ? null
      : ([...(journey.data?.runs ?? [])].reverse().find((candidate) => candidate.runId === runId) ?? null);
  const challenge = going ? (view?.challenge ?? null) : null;
  const checking = challenge !== null && CHECK_OPEN.has(challenge.stage);

  // A pressed button that goes away (a check's buttons, Send once the run ends) leaves the keyboard on the screen, not
  // on the page; only on such a change, so a screen just opened keeps its focus on its heading.
  const seen = useRef({ checking, going });
  useEffect(() => {
    const changed = seen.current.checking !== checking || seen.current.going !== going;
    const wasGoing = seen.current.going;
    seen.current = { checking, going };
    if (
      wasGoing &&
      changed &&
      (document.activeElement === null || document.activeElement === document.body)
    ) {
      bringTo(wayTitle.current);
    }
  }, [checking, going]);
  const resumed = teasers.data?.teasers.find((teaser) => teaser.key === 'CHALLENGE_OUTCOMES')?.values[
    'resumed'
  ];

  async function act(path: string, body: Record<string, string> = {}) {
    const response = await postJson<LiveRunView>(path, body);
    if (response.body && response.status < 300) {
      queryClient.setQueryData(['live-run'], response.body);
    }
  }

  if (options.isPending || run.pending) {
    return (
      <MainScreen title={t('main.4-4.title')} main={null}>
        <StateScreen kind="loading" />
      </MainScreen>
    );
  }
  if (!found) {
    return (
      <MainScreen title={t('main.4-4.title')} main={null}>
        <StateScreen kind="notReady" />
      </MainScreen>
    );
  }
  const { labCase, employee } = found;
  const trip = labCase.facts.find((fact) => fact.kind === 'TRAVEL') ?? null;
  const city = trip?.city ? t(`main.city.${trip.city}`, { defaultValue: trip.city }) : '-';
  const clock = companyClock(t, before.data?.comparison?.companyTime) ?? '…';
  const contexa = line?.business['D'];
  const title = !finished
    ? t('main.4-4.title')
    : contexa === 'PASSED_AFTER_CHECK'
      ? t('main.4-4.title.afterCheck')
      : contexa === 'PASSED'
        ? t('main.4-4.title.through')
        : t('main.4-4.title.other');
  const conclusion =
    contexa === 'PASSED_AFTER_CHECK'
      ? line?.business['C1'] === 'HALTED'
        ? t('main.4-4.split')
        : t('main.4-4.afterCheckOnly')
      : null;
  const sendButton = (
    <MainButton onClick={() => void send()} disabled={!ready}>
      {t(sending ? 'main.request.sending' : view ? 'main.4-4.sendAgain' : 'main.request.send')}
    </MainButton>
  );

  return (
    <MainScreen
      title={title}
      intro={t('main.4-4.intro', { name: personName(t, employee), city, clock })}
      live={going && view?.runId ? view.runId : null}
      main={finished ? undefined : going ? null : sendButton}
      waiting={going ? { label: t('main.4-4.going'), hint: t('main.4-4.goingHint') } : null}
      nextNote={finished ? undefined : null}
    >
      {view?.status === 'QUEUED' ? (
        <StateScreen
          kind="queued"
          queuePosition={view.queuePosition}
          remainingSeconds={view.queueWaitSeconds}
        />
      ) : null}
      <div className={styles.layout}>
        <section className={styles.card} aria-labelledby="check-requests">
          <h2 id="check-requests" ref={requestsTitle} tabIndex={-1} className={styles.cardTitle}>
            {t('main.4-4.requests')}
          </h2>
          <p className={styles.situation}>
            {t('main.4-4.situation', {
              place: t('main.place.TRAVEL'),
              network: trip?.network ?? '-',
              device: t(`main.device.${labCase.conditions.device}`),
            })}
          </p>
          <ol className={styles.steps}>
            {labCase.requests.map((request, index) => (
              <StepRow
                key={index}
                stepNo={index + 1}
                request={request}
                facts={labCase.facts}
                view={view}
                stored={run.stored}
                runId={runId}
                threat={labCase.classification === 'THREAT'}
                language={language}
                again={readsAgain(labCase.requests, index)}
              />
            ))}
          </ol>
        </section>
        <section className={styles.card} aria-labelledby="check-way">
          <h2 id="check-way" ref={wayTitle} tabIndex={-1} className={styles.cardTitle}>
            {t('main.4-4.way')}
          </h2>
          {challenge && checking ? (
            <ChallengePanel
              challenge={challenge}
              onRequestCode={() => void act('/api/live/runs/current/code')}
              onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
              onCancel={() => void act('/api/live/runs/current/cancel')}
            />
          ) : finished ? null : (
            // Once the run ends the requests card holds each request's result; no sentence points at it (P-11).
            <p className={styles.wayNote}>{t(going ? 'main.4-4.wayWatching' : 'main.4-4.wayBefore')}</p>
          )}
          {finished && runId ? (
            <>
              {conclusion ? <p className={styles.conclusion}>{conclusion}</p> : null}
              {labCase.requests.map((_, index) => (
                <CheckRecord key={index} runId={runId} stepNo={index + 1} />
              ))}
              <div className={styles.learning}>
                <h3 className={styles.learningTitle}>{t('main.proof.learn.title')}</h3>
                <ul className={styles.learningRows}>
                  <LearnLine runId={runId} name={t('main.4-4.thisRun')} />
                </ul>
              </div>
              <p className={styles.footnote}>
                {note ? `${t('main.4-3.c2Note')} ${t(note)}` : t('main.4-3.c2Note')}
              </p>
              <div className={styles.badges}>
                <SourceBadge kind="run" label={t('main.4-4.thisRun')} runId={runId} />
                {typeof resumed === 'number' ? (
                  <SourceBadge
                    kind="repeated"
                    label={t('main.recovery.measured', { n: count(resumed, language), count: resumed })}
                  />
                ) : null}
              </div>
            </>
          ) : null}
        </section>
      </div>
      {turnstileRequired ? <div ref={turnstileContainer} /> : null}
      {waiting ? <p className={styles.wayNote}>{t('p1.predict.waitEarlier')}</p> : null}
      {refusal ? (
        <StateScreen
          kind={refusal === 'dailyLimit' ? 'dailyLimit' : refusal === 'paused' ? 'paused' : 'outage'}
          recordTo="/benchmark"
          {...(refusal === 'error' || refusal === 'turnstile' ? { onRetry: () => void send() } : {})}
        />
      ) : null}
    </MainScreen>
  );
}
