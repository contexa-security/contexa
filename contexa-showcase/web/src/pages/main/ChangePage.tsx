import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useAnatomy } from '../../api/anatomy';
import { useBenchmark } from '../../api/benchmark';
import { useJourney, type RecapLine } from '../../api/journey';
import { startLabRun, useLabOptions, type LabConditions } from '../../api/lab';
import { useLabDelta } from '../../api/promptQuality';
import { useLiveAnalysis, useLiveRun, useVisitor } from '../../api/queries';
import { usePublicSettings } from '../../api/settings';
import type { LiveRunView } from '../../api/types';
import { Chip } from '../../components/main/Chip';
import { MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { CONTROL_ORDER } from '../../domain/verdict';
import { useLiveSend } from '../../hooks/useLiveSend';
import { count } from '../../journey/format';
import { ACTIVE } from '../try/steps/liveRun';
import { Lane } from './consoleParts';
import { latestOwnRun } from './latestRun';
import { blindNote, caseOf, isScored, laneChip, MAIN_CASES, runCell, splitChanged } from './mainCases';
import styles from './ComparePages.module.css';

/** The three conditions the main flow lets the visitor change, one at a time (설계서 5-2). */
const CHANGES = ['time', 'size', 'device'] as const;
type Change = (typeof CHANGES)[number];

/** The approaches the before-and-after table compares. */
const COMPARED = ['C1', 'C2', 'D'] as const;

/**
 * 7-2, change one condition and send again (설계서 5-2, FP-3 with the lab's own conditions): the attack of group 2
 * with only the hour, the size or the device changed from what the case defines (an afternoon to the dawn and back, the
 * smallest size, a new device to the usual one and back), sent for real through the lab. Its five lanes fill as before,
 * then the prompt lines the change changed (the portal's comparison of the two sealed prompts) and each approach's
 * result and Contexa's risk before and after. The change, the run and the comparison are the server's records. Before
 * the send the five lanes wait empty and the send is the one gold button, the way on quiet; after it the way on is
 * (L-38).
 */
export default function ChangePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params, setParams] = useSearchParams();
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const options = useLabOptions();
  const settings = usePublicSettings();
  const benchmark = useBenchmark(null);
  const found = caseOf(options.data, MAIN_CASES.attacker);
  const change: Change = (CHANGES as readonly string[]).includes(params.get('change') ?? '')
    ? (params.get('change') as Change)
    : 'time';
  const sent = params.get('sent');
  const live = useLiveRun(true);
  const view: LiveRunView | null = sent && live.data?.liveRunId === sent ? live.data : null;
  const following = view !== null && view.status !== 'QUEUED' && view.status !== 'STARTING';
  const analysis = useLiveAnalysis(view?.liveRunId ?? null, 1, following);
  const decision = analysis.data?.decision ?? null;
  const finished = view !== null && !ACTIVE.has(view.status) && view.runId !== null;
  const delta = useLabDelta(finished ? view.runId : null);
  const own = latestOwnRun(journey.data?.runs, MAIN_CASES.attacker);
  const measured = benchmark.data?.cases.find((candidate) => candidate.key === MAIN_CASES.attacker) ?? null;
  const baseRunId = own?.runId ?? measured?.runIds.at(-1) ?? null;
  const baseResults = own?.business ?? (baseRunId ? (measured?.runResults?.[baseRunId] ?? {}) : {});
  const afterLine = finished ? (journey.data?.runs.find((run) => run.runId === view.runId) ?? null) : null;
  const before = useAnatomy(baseRunId, 1);
  const after = useAnatomy(finished ? view.runId : null, 1);
  const labCase = found?.labCase ?? null;
  const slots = options.data?.timeSlots ?? [];
  const smallest = [...(options.data?.items ?? [])].sort((a, b) => a - b)[0] ?? null;
  // Each change turns the case's own condition the other way.
  const slotTo = labCase?.conditions.timeSlot === 'DAWN' ? 'AFTERNOON' : 'DAWN';
  const deviceTo = labCase?.conditions.device === 'NEW' ? 'USUAL' : 'NEW';
  const conditions: Readonly<Record<Change, Partial<LabConditions>>> = {
    time: { timeSlot: slotTo },
    size: smallest === null ? {} : { items: smallest },
    device: { device: deviceTo },
  };
  const {
    send: sendRun,
    sending,
    ready,
    refusal,
    waiting,
    turnstileContainer,
    turnstileRequired,
  } = useLiveSend(
    MAIN_CASES.attacker,
    (run) => {
      const next = new URLSearchParams(params);
      next.set('sent', run.liveRunId);
      setParams(next, { replace: true });
    },
    {
      post: async (token) => {
        const answer = await startLabRun(
          MAIN_CASES.attacker,
          conditions[change],
          { call: 'UNSURE', approaches: {} },
          token,
        );
        const run = answer.body?.run ?? null;
        const reason = answer.body?.reason;
        const body = run
          ? { ...run, ...(reason ? { reason } : {}) }
          : reason
            ? ({ reason } as LiveRunView & { readonly reason: string })
            : null;
        return { status: answer.status, body };
      },
      matches: () => true,
    },
  );

  if (options.isPending || !labCase) {
    return (
      <MainScreen title={t('main.7-2.title')} main={null}>
        <StateScreen kind={options.isPending ? 'loading' : 'notReady'} />
      </MainScreen>
    );
  }
  const from: Readonly<Record<Change, string>> = {
    time: slots.find((slot) => slot.slot === labCase.conditions.timeSlot)?.representativeTime ?? '-',
    size: t('main.items', {
      count: labCase.conditions.items ?? 0,
      items: count(labCase.conditions.items ?? 0, language),
    }),
    device: t(`main.device.${labCase.conditions.device ?? 'USUAL'}`),
  };
  const to: Readonly<Record<Change, string>> = {
    time: slots.find((slot) => slot.slot === slotTo)?.representativeTime ?? '-',
    size: smallest === null ? '-' : t('main.items', { count: smallest, items: count(smallest, language) }),
    device: t(`main.device.${deviceTo}`),
  };
  const layers = view?.steps.find((step) => step.stepNo === 1)?.layers ?? {};
  const threshold = settings.data?.threshold ?? null;
  const step = delta.data?.steps.find((candidate) => candidate.stepNo === 1) ?? null;
  // The run before: the visitor's own, else the measured one, whose decision and items out its stored record states.
  const beforeBusiness = before.data?.truth.business ?? null;
  const baseRun = own ?? {
    engineAction: beforeBusiness ? (before.data?.interpretation.recorded.finalAction ?? null) : null,
    exposedItems: beforeBusiness?.exposedItems ?? 0,
    business: baseResults,
  };
  // A run with a condition changed has no ground truth (V-05): every approach is named by what it did.
  const unscored = afterLine !== null && !isScored(afterLine.business['D']);
  const blind = benchmark.data?.suites.find((suite) => suite.suite === 'RULE_BLIND')?.cases ?? [];
  const note = blindNote(blind, [MAIN_CASES.attacker]);
  const riskBefore = before.data?.interpretation.recorded.riskScore ?? null;
  const riskAfter = after.data?.interpretation.recorded.riskScore ?? null;
  const going = view !== null && ACTIVE.has(view.status);
  const subOf = (control: (typeof CONTROL_ORDER)[number]) =>
    control === 'C1' && threshold?.nightStart && threshold.nightEnd && threshold.volumeLimit !== null
      ? t('main.lane.C1.sub', {
          start: threshold.nightStart,
          end: threshold.nightEnd,
          limit: count(threshold.volumeLimit, language),
        })
      : t(`main.lane.${control}.sub${control === 'C1' ? 'Plain' : ''}`);
  /**
   * The run after, in words: Contexa's own decision with the items that left; another approach's scored result, or on a
   * run with no ground truth what it did with the items that left, as its lane recorded it (Contexa too when a decision
   * in force refused the request without a decision of its own).
   */
  const afterCell = (line: RecapLine, control: (typeof COMPARED)[number]) => {
    const layer = layers[control] ?? null;
    if (
      isScored(line.business[control]) ||
      layer === null ||
      (control === 'D' && line.engineAction !== null)
    ) {
      return runCell(t, language, line, control);
    }
    const chip = laneChip(layer, null);
    return {
      kind: chip.kind,
      words: t('main.lane.out', {
        word: t(chip.key),
        count: layer.deliveredItems,
        items: count(layer.deliveredItems, language),
      }),
    };
  };
  return (
    <MainScreen
      title={t('main.7-2.title')}
      intro={t('main.7-2.intro')}
      live={going && view?.runId ? view.runId : null}
      waiting={going ? { label: t('main.console.deciding'), hint: t('main.console.decidingHint') } : null}
      quiet={!finished}
    >
      <div className={styles.change}>
        <section className={styles.card} aria-labelledby="change-controls">
          <h2 id="change-controls" className={styles.cardTitle}>
            {t('main.7-2.controls')}
          </h2>
          {/* The card's heading names the choices once; a legend of the same words was read twice (L-38). */}
          <fieldset className={styles.presets} disabled={going} aria-labelledby="change-controls">
            {CHANGES.map((preset) => (
              <label key={preset} className={styles.preset} data-selected={preset === change || undefined}>
                <input
                  type="radio"
                  name="change"
                  className="visually-hidden"
                  checked={preset === change}
                  onChange={() => {
                    const next = new URLSearchParams(params);
                    next.set('change', preset);
                    next.delete('sent');
                    setParams(next, { replace: true });
                  }}
                />
                <b className={styles.presetName}>{t(`main.7-2.change.${preset}`)}</b>
                <span className={styles.presetFrom}>{from[preset]}</span>
                <span className={styles.presetArrow} aria-hidden="true">
                  →
                </span>
                <span className={styles.presetTo}>{to[preset]}</span>
              </label>
            ))}
          </fieldset>
          <button
            type="button"
            className={styles.send}
            data-quiet={finished || undefined}
            disabled={!ready || going}
            onClick={() => void sendRun()}
          >
            {t(sending ? 'main.request.sending' : 'main.7-2.send')}
          </button>
          {turnstileRequired ? <div ref={turnstileContainer} /> : null}
          {waiting ? <p className={styles.note}>{t('p1.predict.waitEarlier')}</p> : null}
          {refusal ? (
            <StateScreen
              kind={refusal === 'dailyLimit' ? 'dailyLimit' : refusal === 'paused' ? 'paused' : 'outage'}
              recordTo="/benchmark"
            />
          ) : null}
        </section>
        <div className={styles.column}>
          <section className={styles.card} aria-label={t('main.console.lanes')}>
            {view ? null : <p className={styles.lanesNote}>{t('main.7-2.notSent')}</p>}
            <ul className={styles.lanes}>
              {CONTROL_ORDER.map((control) => (
                <Lane
                  key={control}
                  control={control}
                  sub={subOf(control)}
                  layer={layers[control] ?? null}
                  threat={null}
                  decision={decision}
                  holding={control === 'D'}
                  wait={control === 'D' ? (analysis.data?.decisionWait ?? null) : null}
                  idle={view === null}
                />
              ))}
            </ul>
          </section>
          {step ? (
            <section className={styles.diffLines} aria-labelledby="prompt-diff">
              <h2 id="prompt-diff" className={styles.cardTitle}>
                {t('main.7-2.promptDiff')}
              </h2>
              {splitChanged(step.changed, change).related.map((line) => (
                <div key={line.label} className={styles.diffPair}>
                  <code data-side="before">
                    - {line.label}: {line.before.join(', ')}
                  </code>
                  <code data-side="after">
                    + {line.label}: {line.after.join(', ')}
                  </code>
                </div>
              ))}
              {splitChanged(step.changed, change).other.length > 0 ? (
                // The other changed lines (earlier records counted from a later hour, the learned usual) fold away.
                <details className={styles.diffMore}>
                  <summary>
                    {t('main.7-2.otherLines', { count: splitChanged(step.changed, change).other.length })}
                  </summary>
                  {splitChanged(step.changed, change).other.map((line) => (
                    <div key={line.label} className={styles.diffPair}>
                      <code data-side="before">
                        - {line.label}: {line.before.join(', ')}
                      </code>
                      <code data-side="after">
                        + {line.label}: {line.after.join(', ')}
                      </code>
                    </div>
                  ))}
                </details>
              ) : null}
              {step.changed.length === 0 ? <p className={styles.note}>{t('main.7-2.noLine')}</p> : null}
              {step.unchangedLines != null ? (
                <p className={styles.note}>
                  {t('main.7-2.unchanged', {
                    n: count(step.unchangedLines, language),
                    count: step.unchangedLines,
                  })}
                </p>
              ) : null}
            </section>
          ) : null}
          {finished && afterLine ? (
            <section className={styles.card} aria-labelledby="change-compare">
              <h2 id="change-compare" className={styles.cardTitle}>
                {t('main.7-2.compare')}
              </h2>
              <div className={styles.grid3} data-head>
                <span />
                <span>{t('main.7-2.before')}</span>
                <span>
                  {t('main.7-2.after', { change: t(`main.7-2.change.${change}`) })}
                  {unscored ? ` · ${t('main.7-2.noAnswer')}` : ''}
                </span>
              </div>
              {COMPARED.map((control) => {
                const left = runCell(t, language, baseRun, control);
                const right = afterCell(afterLine, control);
                return (
                  <div key={control} className={styles.grid3} data-contexa={control === 'D' || undefined}>
                    <b className={styles.rowName}>{t(`main.lane.${control}`)}</b>
                    <span className={styles.chips}>
                      <Chip kind={left.kind}>{left.words}</Chip>
                    </span>
                    <span className={styles.chips}>
                      <Chip kind={right.kind}>{right.words}</Chip>
                    </span>
                  </div>
                );
              })}
              {unscored ? <p className={styles.note}>{t('main.7-2.unscored')}</p> : null}
              <p className={styles.why}>
                {t('main.7-2.risk', {
                  before: riskBefore === null ? '—' : riskBefore.toFixed(2),
                  after: riskAfter === null ? '—' : riskAfter.toFixed(2),
                })}
              </p>
              <div className={styles.badges}>
                {baseRunId ? (
                  <SourceBadge
                    kind={own ? 'run' : 'repeated'}
                    label={t(own ? 'main.7-2.before' : 'main.evidence.measured')}
                    runId={baseRunId}
                  />
                ) : null}
                {view?.runId ? (
                  <SourceBadge kind="run" label={t('main.7-2.afterShort')} runId={view.runId} />
                ) : null}
              </div>
              <p className={styles.note}>
                {note ? `${t('main.4-3.c2Note')} ${t(note)}` : t('main.4-3.c2Note')}
              </p>
            </section>
          ) : null}
        </div>
      </div>
    </MainScreen>
  );
}
