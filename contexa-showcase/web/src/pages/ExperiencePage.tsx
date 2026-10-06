import { useQueryClient } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useEffect, useRef, useState, type ReactNode, type Ref, type RefObject } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { HttpError, postJson } from '../api/http';
import { useEndedRun, useLiveConfig, useLiveResult, useLiveRun, useVisitor } from '../api/queries';
import type { CombinationView, LiveRunView, StepResult } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import { EvidenceDrawer } from '../components/EvidenceDrawer';
import { LaneBoard, type BoardStatus } from '../components/LaneBoard';
import { LiveChallenge } from '../components/LiveChallenge';
import { StateScreen } from '../components/StateScreen';
import { WorkConsole } from '../components/WorkConsole';
import { evidenceChain } from '../domain/evidence';
import {
  ATTACK_SCENE,
  bothRight,
  changedFacts,
  changedFrom,
  isRight,
  liveLanes,
  outcomesOf,
  OWNER_SCENE,
  recordedLanes,
  type Expectation,
  type Fact,
  type Lane,
  type SceneOutcome,
} from '../domain/experience';
import { keyOf, type Selection } from '../domain/explore';
import { refusalOf, type GateRefusal } from '../domain/live';
import { tally } from '../domain/summary';
import type { BusinessOutcome, ControlId } from '../domain/verdict';
import { CONTROL_ORDER, OUTCOME_KEYS } from '../domain/verdict';
import { useTurnstile } from '../hooks/useTurnstile';
import styles from './ExperiencePage.module.css';

type SectionId = 'attack' | 'owner' | 'free';

/** One press of the button: the conditions sent, the live run it started, or why it could not start. */
interface Attempt {
  readonly selection: Selection;
  readonly sending: boolean;
  readonly liveRunId: string | null;
  readonly refusal: GateRefusal | null;
  /** A stored real run of the same conditions, shown as a record when the live run could not start. */
  readonly fallback: CombinationView | null;
}

type Attempts = Readonly<Record<SectionId, Attempt | null>>;

/** What a free send is compared with: the conditions and outcomes of the send before it. */
interface FreeBase {
  readonly selection: Selection;
  readonly outcomes: Readonly<Record<ControlId, BusinessOutcome>> | null;
}

const ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE']);

/**
 * The first screen is the experience itself (docs/showcase/체험우선-설계.md): the visitor presses the button and the
 * same export really goes to the five security approaches, as the attacker, then as the real owner, then under
 * conditions of their own choosing. Every answer on this screen comes from the run the visitor just started; a stored
 * real run is shown only when a live run cannot start, and it says so.
 */
export default function ExperiencePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const queryClient = useQueryClient();
  const visitor = useVisitor();
  const config = useLiveConfig();
  const live = useLiveRun(config.isSuccess);
  const {
    container: turnstileContainer,
    token: turnstileToken,
    required: turnstileRequired,
    reset: resetTurnstile,
  } = useTurnstile(config.data?.turnstileSiteKey ?? null);
  const [attempts, setAttempts] = useState<Attempts>({ attack: null, owner: null, free: null });
  const [unlocked, setUnlocked] = useState<1 | 2 | 3>(1);
  const [freeSelection, setFreeSelection] = useState<Selection>(OWNER_SCENE);
  const [freeBase, setFreeBase] = useState<FreeBase | null>(null);
  const [evidenceOf, setEvidenceOf] = useState<{ section: SectionId; control: ControlId } | null>(null);
  const ownerRef = useRef<HTMLElement>(null);
  const compareRef = useRef<HTMLElement>(null);
  const attackResultRef = useRef<HTMLDivElement>(null);
  const ownerResultRef = useRef<HTMLDivElement>(null);
  const freeResultRef = useRef<HTMLDivElement>(null);

  const current = live.data ?? null;
  const running = current !== null && ACTIVE.has(current.status);
  // A run that ended stays with its scene, so the next run does not replace what the visitor saw.
  const ended = {
    attack: useEndedRun(attempts.attack?.liveRunId ?? null).data ?? null,
    owner: useEndedRun(attempts.owner?.liveRunId ?? null).data ?? null,
    free: useEndedRun(attempts.free?.liveRunId ?? null).data ?? null,
  };

  useEffect(() => {
    const target = unlocked === 2 ? ownerRef.current : unlocked === 3 ? compareRef.current : null;
    target?.scrollIntoView({ behavior: motion(), block: 'start' });
  }, [unlocked]);

  const views: Record<SectionId, LiveRunView | null> = {
    attack: viewOf(attempts.attack, ended.attack, current),
    owner: viewOf(attempts.owner, ended.owner, current),
    free: viewOf(attempts.free, ended.free, current),
  };
  const completed = (section: SectionId) =>
    views[section]?.status === 'COMPLETED' ? (attempts[section]?.liveRunId ?? null) : null;
  const liveResults = {
    attack: useLiveResult(completed('attack'), current?.liveRunId === completed('attack')),
    owner: useLiveResult(completed('owner'), current?.liveRunId === completed('owner')),
    free: useLiveResult(completed('free'), current?.liveRunId === completed('free')),
  };

  function resultOf(section: SectionId): StepResult | null {
    const fallback = attempts[section]?.fallback?.result;
    return fallback ?? liveResults[section].data ?? null;
  }

  function lanesOf(section: SectionId): Readonly<Record<ControlId, Lane>> {
    const fallback = attempts[section]?.fallback?.result;
    return fallback ? recordedLanes(fallback) : liveLanes(views[section]);
  }

  function statusOf(section: SectionId): BoardStatus | null {
    const attempt = attempts[section];
    if (!attempt) {
      return 'idle';
    }
    if (attempt.fallback?.result) {
      return 'record';
    }
    const view = views[section];
    if (!view) {
      return attempt.sending ? 'starting' : null;
    }
    switch (view.status) {
      case 'QUEUED':
        return 'queued';
      case 'STARTING':
        return 'starting';
      case 'RUNNING':
      case 'CHALLENGE':
        return 'running';
      case 'COMPLETED':
        return 'done';
      default:
        return 'failed';
    }
  }

  function outcomeOf(section: SectionId): SceneOutcome | null {
    const status = statusOf(section);
    if (status !== 'done' && status !== 'record') {
      return null;
    }
    const outcomes = outcomesOf(lanesOf(section));
    const challenge = views[section]?.challenge;
    return outcomes
      ? {
          outcomes,
          servedAfterCheck: challenge?.stage === 'DONE' && challenge.reissueOutcome === 'DELIVERED',
        }
      : null;
  }

  async function send(section: SectionId, selection: Selection) {
    if (section === 'free') {
      const last = attempts.free;
      setFreeBase(
        last
          ? { selection: last.selection, outcomes: outcomeOf('free')?.outcomes ?? null }
          : { selection: OWNER_SCENE, outcomes: outcomeOf('owner')?.outcomes ?? null },
      );
    }
    const pending: Attempt = { selection, sending: true, liveRunId: null, refusal: null, fallback: null };
    setAttempts((all) => ({ ...all, [section]: pending }));
    const result = await postJson<LiveRunView & { reason?: string; fallback?: CombinationView }>(
      '/api/live/combinations',
      { key: keyOf(selection), turnstileToken },
    );
    resetTurnstile();
    const body = result.body;
    if (result.status === 202 && body) {
      queryClient.setQueryData(['live-run'], body);
      setAttempts((all) => ({ ...all, [section]: { ...pending, sending: false, liveRunId: body.liveRunId } }));
    } else {
      setAttempts((all) => ({
        ...all,
        [section]: {
          ...pending,
          sending: false,
          refusal: refusalOf(result.status, body?.reason ?? null),
          fallback: body?.fallback ?? null,
        },
      }));
    }
    const target = { attack: attackResultRef, owner: ownerResultRef, free: freeResultRef }[section];
    window.setTimeout(() => target.current?.scrollIntoView({ behavior: motion(), block: 'nearest' }), 80);
  }

  async function act(path: string, body: unknown = {}) {
    const result = await postJson<LiveRunView>(path, body);
    if (result.body && result.status < 300) {
      queryClient.setQueryData(['live-run'], result.body);
    }
  }

  const ready = visitor.isSuccess && !(turnstileRequired && !turnstileToken);
  const note = config.data
    ? t('exp.console.note', { remaining: config.data.remainingToday })
    : undefined;
  const attack = outcomeOf('attack');
  const owner = outcomeOf('owner');

  function scene(
    section: SectionId,
    resultRef: Ref<HTMLDivElement>,
    expectation: Expectation | null,
    children: ReactNode,
    after: ReactNode,
  ) {
    const attempt = attempts[section];
    const status = statusOf(section);
    const view = views[section];
    const outcome = outcomeOf(section);
    const result = resultOf(section);
    const challenge = view?.challenge ?? null;
    return (
      <>
        {children}
        <div ref={resultRef} className={styles.result}>
          {section === 'free' && attempt && freeBase ? (
            <FactChange before={freeBase.selection} after={attempt.selection} />
          ) : null}
          {attempt?.refusal && attempt.fallback ? (
            <p className={styles.fallback} role="status">
              {t(attempt.refusal === 'dailyLimit' ? 'exp.fallback.dailyLimit' : 'exp.fallback.paused')}
            </p>
          ) : null}
          {attempt?.refusal && !attempt.fallback ? <Refusal refusal={attempt.refusal} /> : null}
          {status ? (
            <LaneBoard
              lanes={lanesOf(section)}
              status={status}
              queuePosition={view?.queuePosition}
              recordedAt={recordedDate(attempt?.fallback ?? null, language)}
              expectation={expectation}
              servedAfterCheck={outcome?.servedAfterCheck ?? false}
              previous={section === 'free' ? (freeBase?.outcomes ?? null) : null}
              result={result}
              onOpenEvidence={result ? (control) => setEvidenceOf({ section, control }) : undefined}
            />
          ) : null}
          {challenge && section === 'attack' && view?.status === 'CHALLENGE' ? (
            <div className={styles.held}>
              <p>{t('exp.attack.held')}</p>
              <button type="button" className={styles.secondary} onClick={() => void act('/api/live/runs/current/abandon')}>
                {t('exp.attack.giveUp')}
              </button>
            </div>
          ) : null}
          {challenge && section !== 'attack' ? (
            <LiveChallenge
              challenge={challenge}
              onRequestCode={() => void act('/api/live/runs/current/code')}
              onAnswer={(code) => void act('/api/live/runs/current/answer', { code })}
              onCancel={() => void act('/api/live/runs/current/cancel')}
              onRestart={() => attempt && void send(section, attempt.selection)}
            />
          ) : null}
          {status === 'failed' && attempt ? (
            <StateScreen kind="outage" onRetry={() => void send(section, attempt.selection)} />
          ) : null}
          {outcome ? (
            <Summary
              outcome={outcome}
              expectation={expectation}
              changed={
                section === 'free' && freeBase?.outcomes ? changedFrom(outcome.outcomes, freeBase.outcomes).size : null
              }
            />
          ) : null}
          {outcome ? after : null}
        </div>
      </>
    );
  }

  const evidenceLayer = evidenceOf
    ? (resultOf(evidenceOf.section)?.layers.find((layer) => layer.control === evidenceOf.control) ?? null)
    : null;
  const liveClosed = config.isError && config.error instanceof HttpError && config.error.status === 404;

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        <header className={styles.intro}>
          <p className={styles.eyebrow}>{t('exp.eyebrow')}</p>
          <h1 className={styles.title}>{t('exp.title')}</h1>
          <p className={styles.body}>{t('exp.body')}</p>
          <ol className={styles.steps} aria-label={t('exp.steps.label')}>
            {([1, 2, 3] as const).map((step) => (
              <li key={step} className={styles.step} data-state={stepState(step, unlocked)}>
                <span className={styles.stepNumber}>{step}</span>
                {t(`exp.steps.${step}`)}
              </li>
            ))}
          </ol>
        </header>

        {config.isPending ? <StateScreen kind="loading" /> : null}
        {liveClosed ? <StateScreen kind="liveClosed" recordTo="/library" /> : null}
        {config.isError && !liveClosed ? <StateScreen kind="error" onRetry={() => void config.refetch()} /> : null}

        {config.data ? (
          <>
            {turnstileRequired ? <div ref={turnstileContainer} className={styles.turnstile} /> : null}
            <section className={styles.scene} aria-labelledby="scene-attack">
              <div className={styles.sceneHead}>
                <p className={styles.label}>{t('exp.attack.label')}</p>
                <h2 id="scene-attack" className={styles.sceneTitle}>
                  {t('exp.attack.title')}
                </h2>
                <p className={styles.sceneBody}>{t('exp.attack.body')}</p>
              </div>
              {scene(
                'attack',
                attackResultRef,
                'STOP',
                <WorkConsole
                  selection={ATTACK_SCENE}
                  editable={false}
                  sending={attempts.attack?.sending ?? false}
                  disabled={!ready || running || attack !== null}
                  onSend={() => void send('attack', ATTACK_SCENE)}
                  note={note}
                />,
                unlocked === 1 ? (
                  <button type="button" className={styles.next} onClick={() => setUnlocked(2)}>
                    {t('exp.attack.next')}
                  </button>
                ) : null,
              )}
            </section>

            {unlocked >= 2 ? (
              <section ref={ownerRef} className={styles.scene} aria-labelledby="scene-owner">
                <div className={styles.sceneHead}>
                  <p className={styles.label}>{t('exp.owner.label')}</p>
                  <h2 id="scene-owner" className={styles.sceneTitle}>
                    {t('exp.owner.title')}
                  </h2>
                  <p className={styles.sceneBody}>{t('exp.owner.body')}</p>
                </div>
                {scene(
                  'owner',
                  ownerResultRef,
                  'PASS',
                  <WorkConsole
                    selection={OWNER_SCENE}
                    editable={false}
                    changed={['ticket']}
                    sending={attempts.owner?.sending ?? false}
                    disabled={!ready || running || owner !== null}
                    onSend={() => void send('owner', OWNER_SCENE)}
                    note={note}
                  />,
                  unlocked === 2 ? (
                    <button type="button" className={styles.next} onClick={() => setUnlocked(3)}>
                      {t('exp.owner.next')}
                    </button>
                  ) : null,
                )}
              </section>
            ) : null}

            {unlocked >= 3 && attack && owner ? (
              <Comparison ref={compareRef} attack={attack} owner={owner} />
            ) : null}

            {unlocked >= 3 ? (
              <section className={styles.scene} aria-labelledby="scene-free">
                <div className={styles.sceneHead}>
                  <p className={styles.label}>{t('exp.free.label')}</p>
                  <h2 id="scene-free" className={styles.sceneTitle}>
                    {t('exp.free.title')}
                  </h2>
                  <p className={styles.sceneBody}>{t('exp.free.body')}</p>
                </div>
                {scene(
                  'free',
                  freeResultRef,
                  null,
                  <WorkConsole
                    selection={freeSelection}
                    editable
                    onChange={setFreeSelection}
                    sending={attempts.free?.sending ?? false}
                    disabled={!ready || running}
                    onSend={() => void send('free', freeSelection)}
                    note={note}
                  />,
                  null,
                )}
              </section>
            ) : null}
          </>
        ) : null}

        <nav className={styles.more} aria-labelledby="more-title">
          <h2 id="more-title" className={styles.moreTitle}>
            {t('exp.more.title')}
          </h2>
          <ul className={styles.moreList}>
            <li>
              <Link to="/library">{t('nav.library')}</Link>
              <span>{t('exp.more.library')}</span>
            </li>
            <li>
              <Link to="/stats">{t('nav.stats')}</Link>
              <span>{t('exp.more.stats')}</span>
            </li>
            <li>
              <Link to="/adopt">{t('nav.adopt')}</Link>
              <span>{t('exp.more.adopt')}</span>
            </li>
          </ul>
        </nav>
      </main>
      <EvidenceDrawer
        title={evidenceLayer ? t(`control.${evidenceLayer.control}.name`) : ''}
        evidence={evidenceLayer ? evidenceChain(evidenceLayer, t) : null}
        onClose={() => setEvidenceOf(null)}
      />
    </>
  );
}

/** The run of a scene: as it ended, or the visitor's current run while it is this scene's. */
function viewOf(attempt: Attempt | null, ended: LiveRunView | null, current: LiveRunView | null): LiveRunView | null {
  if (!attempt?.liveRunId) {
    return null;
  }
  if (ended) {
    return ended;
  }
  return current?.liveRunId === attempt.liveRunId ? current : null;
}

function stepState(step: number, unlocked: number): 'done' | 'current' | 'next' {
  if (step < unlocked) {
    return 'done';
  }
  return step === unlocked ? 'current' : 'next';
}

function recordedDate(fallback: CombinationView | null, language: 'ko' | 'en'): string | undefined {
  if (!fallback?.recordedAt) {
    return undefined;
  }
  return new Intl.DateTimeFormat(language, { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(
    new Date(fallback.recordedAt),
  );
}

function motion(): ScrollBehavior {
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
}

/** Why a live run could not start, when no stored run of the same conditions exists to show instead. */
function Refusal({ refusal }: { readonly refusal: GateRefusal }) {
  const { t } = useTranslation();
  if (refusal === 'turnstile') {
    return (
      <p className={styles.alert} role="alert">
        {t('explore.refused.turnstile')}
      </p>
    );
  }
  return <StateScreen kind={refusal === 'dailyLimit' ? 'dailyLimit' : refusal === 'paused' ? 'paused' : 'outage'} />;
}

/** The conditions this free send changed from the send before it, each as before and after. */
function FactChange({ before, after }: { readonly before: Selection; readonly after: Selection }) {
  const { t, i18n } = useTranslation();
  const count = new Intl.NumberFormat(i18n.language === 'ko' ? 'ko-KR' : 'en-US');
  const facts = changedFacts(before, after);
  const word = (fact: Fact, selection: Selection) => {
    switch (fact) {
      case 'employee':
        return t(`explore.employee.${selection.employee}`);
      case 'slot':
        return t(`exp.slot.${selection.slot}`);
      case 'device':
        return t(`exp.device.${selection.device}`);
      case 'ticket':
        return t(`exp.ticket.${selection.ticket}`);
      default:
        return t('exp.items', { items: count.format(selection.items) });
    }
  };
  const label: Record<Fact, string> = {
    employee: t('exp.console.signedIn'),
    slot: t('exp.console.time'),
    device: t('exp.console.device'),
    ticket: t('exp.console.ticket'),
    items: t('exp.console.items'),
  };
  return (
    <p className={styles.factChange}>
      {facts.length === 0
        ? t('exp.free.sameFacts')
        : t('exp.free.changedFacts', {
            list: facts.map((fact) => `${label[fact]} ${word(fact, before)} → ${word(fact, after)}`).join(' · '),
          })}
    </p>
  );
}

/**
 * The scene's conclusion: the right answer, how many got it right, how many stopped it, what Contexa did, and in free
 * play how many results changed from the send before.
 */
function Summary({
  outcome,
  expectation,
  changed,
}: {
  readonly outcome: SceneOutcome;
  readonly expectation: Expectation | null;
  readonly changed: number | null;
}) {
  const { t } = useTranslation();
  const layers = CONTROL_ORDER.map((control) => ({ outcome: outcome.outcomes[control] }));
  const counts = tally(layers);
  const contexa = outcome.outcomes.D;
  const right = expectation
    ? CONTROL_ORDER.filter(
        (control) =>
          isRight(outcome.outcomes[control], expectation, control === 'D' && outcome.servedAfterCheck) === true,
      ).length
    : null;
  return (
    <div className={styles.summary}>
      {expectation ? (
        <p className={styles.expect}>
          {t(expectation === 'STOP' ? 'exp.attack.expect' : 'exp.owner.expect')}
          {right !== null ? <span className={styles.score}>{t('exp.scoreLine', { right })}</span> : null}
        </p>
      ) : null}
      <p className={styles.summaryLine}>
        {t('replay.summary', { stopped: counts.stopped, passed: counts.passed })}
        {counts.other > 0 ? ` ${t('replay.summaryOther', { count: counts.other })}` : ''}
      </p>
      <p className={styles.summaryContexa} data-outcome={contexa}>
        {outcome.servedAfterCheck ? t('exp.contexaServed') : t(`replay.contexa.${contexa}`)}
      </p>
      {changed !== null ? (
        <p className={styles.changedCount}>
          {changed > 0 ? t('exp.free.changedCount', { count: changed }) : t('exp.free.unchanged')}
        </p>
      ) : null}
    </div>
  );
}

/** Both scenes side by side: who stopped the attacker and let the real owner through. */
function Comparison({
  ref,
  attack,
  owner,
}: {
  readonly ref: RefObject<HTMLElement | null>;
  readonly attack: SceneOutcome;
  readonly owner: SceneOutcome;
}) {
  const { t } = useTranslation();
  const winners = bothRight(attack, owner);
  return (
    <section ref={ref} className={styles.compare} aria-labelledby="compare-title">
      <h2 id="compare-title" className={styles.sceneTitle}>
        {t('exp.compare.title')}
      </h2>
      <p className={styles.sceneBody}>{t('exp.compare.body')}</p>
      <p className={styles.winners}>
        {winners.length > 0
          ? t('exp.compare.winners', { list: winners.map((control) => t(`control.${control}.name`)).join(', ') })
          : t('exp.compare.none')}
      </p>
      <table className={styles.table}>
        <thead>
          <tr>
            <th scope="col">{t('exp.compare.approach')}</th>
            <th scope="col">{t('exp.compare.attack')}</th>
            <th scope="col">{t('exp.compare.owner')}</th>
            <th scope="col">{t('exp.compare.both')}</th>
          </tr>
        </thead>
        <tbody>
          {CONTROL_ORDER.map((control) => {
            const both = winners.includes(control);
            return (
              <tr key={control} data-control={control} data-both={both}>
                <th scope="row">{t(`control.${control}.name`)}</th>
                <td>{cell(attack, control, 'STOP', t)}</td>
                <td>{cell(owner, control, 'PASS', t)}</td>
                <td>{both ? t('exp.compare.yes') : t('exp.compare.no')}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}

function cell(scene: SceneOutcome, control: ControlId, expectation: Expectation, t: TFunction): string {
  const outcome = scene.outcomes[control];
  const right = isRight(outcome, expectation, control === 'D' && scene.servedAfterCheck);
  const word =
    control === 'D' && scene.servedAfterCheck ? t('exp.lane.servedAfterCheck') : t(OUTCOME_KEYS[outcome]);
  const mark = right === null ? t('exp.lane.noDecision') : right ? t('exp.lane.right') : t('exp.lane.wrong');
  return `${word} · ${mark}`;
}
