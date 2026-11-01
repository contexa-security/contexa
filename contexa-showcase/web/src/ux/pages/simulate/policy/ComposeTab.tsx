import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import type { BeforeSendView } from '../../../../api/anatomy';
import {
  startLabRun,
  useLabBefore,
  useLabOptions,
  useRecentLabRuns,
  useVersus,
  type LabCase,
  type LabConditions,
  type LabOptions,
  type LabPrediction,
  type VersusSide,
} from '../../../../api/lab';
import { postJson } from '../../../../api/http';
import { useLiveConfig, useLiveRun, useVisitor } from '../../../../api/queries';
import type { CaseResult, LiveRunView } from '../../../../api/types';
import { CONTROL_ORDER } from '../../../../domain/verdict';
import { useLiveSend } from '../../../../hooks/useLiveSend';
import {
  CONDITION_KEYS,
  ONE_CHANGE,
  changeable,
  choicesOf,
  conditionText,
  lineState,
  type ConditionKey,
} from '../../../../pages/lab/labPlace';
import { formatNumber } from '../../../format';
import { agentCell } from '../../../simulate/agent';
import { AgentCellBadge } from '../../../simulate/AgentParts';
import { ChallengeCard } from '../../../simulate/Recovery';
import { evalOf, verdictOf } from '../../../simulate/person';
import { useLiveActions } from '../../../simulate/useLiveActions';
import { useGroupRuns } from '../../../simulate/useFlow';
import { Badge, Button, CodeChip, EvalBadge, Field, Loading, Note, Select, VerdictBadge } from '../../../ui';
import review from '../../../simulate/Review.module.css';
import styles from './Policy.module.css';

const ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE', 'AWAITING', 'BLOCKED', 'CONFIRMING']);
const CALLS = ['ATTACK', 'NORMAL', 'UNSURE'] as const;
type Call = (typeof CALLS)[number];

/** The changed condition the address names, in the condition's own type; null when none or not a value of its list. */
function changeOf(
  params: URLSearchParams,
  labCase: LabCase | null,
  options: LabOptions | null,
): { readonly key: ConditionKey; readonly value: string | number | boolean } | null {
  const key = params.get('field') as ConditionKey | null;
  const raw = params.get('to');
  if (!labCase || !options || key === null || raw === null || !CONDITION_KEYS.includes(key)) {
    return null;
  }
  if (!ONE_CHANGE.includes(key) || !changeable(key, labCase)) {
    return null;
  }
  const value = choicesOf(key, options).find((choice) => String(choice) === raw);
  return value === undefined || value === labCase.conditions[key] ? null : { key, value };
}

/**
 * The composition of one changed condition (DEC-33): a designed scenario, one of its conditions changed, what the
 * engine would receive before and after the change (the latest real requests of each), the visitor's call and the
 * real run, and the server's comparison of the run against the latest run of the scenario as designed. The steps
 * keep their place in the address, so a refresh or a shared link opens the same composition.
 */
export function ComposeTab() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params, setParams] = useSearchParams();
  const options = useLabOptions();
  const data = options.data ?? null;
  const caseKey = params.get('case');
  const labCase = data?.cases.find((candidate) => candidate.key === caseKey) ?? null;
  const change = changeOf(params, labCase, data);
  const set = (next: Readonly<Record<string, string | null>>) => {
    const query = new URLSearchParams(params);
    query.set('tab', 'compose');
    Object.entries(next).forEach(([key, value]) => (value === null ? query.delete(key) : query.set(key, value)));
    setParams(query, { replace: true });
  };
  if (options.isPending) {
    return <Loading rows={6} />;
  }
  if (!data) {
    // ST-35: the options did not come; the old lab waited for ever.
    return <Note tone="warn">{t('ux.policy.compose.unavailable')}</Note>;
  }
  const text = (key: ConditionKey, raw: unknown) => conditionText(t, key, raw, data, language);
  const field = (params.get('field') as ConditionKey | null) ?? null;
  const fields = labCase ? ONE_CHANGE.filter((key) => changeable(key, labCase)) : [];
  return (
    <div className={styles.stack}>
      <section className={styles.card} aria-labelledby="compose-case">
        <header className={styles.cardHead}>
          <h2 id="compose-case" className={styles.cardTitle}>
            <span className={styles.no}>1</span>
            {t('ux.policy.compose.case')}
          </h2>
          <p className={styles.cardSub}>{t('ux.policy.compose.caseSub')}</p>
        </header>
        <div className={styles.pickers}>
          <Field label={t('ux.policy.compose.scenario')}>
            {(props) => (
              <Select
                {...props}
                value={labCase?.key ?? ''}
                onChange={(event) => set({ case: event.target.value || null, field: null, to: null, sent: null })}
              >
                <option value="">{t('ux.policy.compose.pick')}</option>
                {(['THREAT', 'NORMAL'] as const).map((kind) => (
                  <optgroup key={kind} label={t(`ux.policy.compose.group.${kind}`)}>
                    {data.cases
                      .filter((candidate) => (kind === 'THREAT') === (candidate.classification === 'THREAT'))
                      .map((candidate) => (
                        <option key={candidate.key} value={candidate.key}>
                          {candidate.key} · {candidate.title[language] ?? candidate.title.en}
                        </option>
                      ))}
                  </optgroup>
                ))}
              </Select>
            )}
          </Field>
        </div>
      </section>

      {labCase ? (
        <section className={styles.card} aria-labelledby="compose-change">
          <header className={styles.cardHead}>
            <h2 id="compose-change" className={styles.cardTitle}>
              <span className={styles.no}>2</span>
              {t('ux.policy.compose.change')}
            </h2>
            <p className={styles.cardSub}>
              {labCase.requests.length > 1 ? t('ux.policy.compose.changeSubSteps') : t('ux.policy.compose.changeSub')}
            </p>
          </header>
          <div className={styles.pickers}>
            <Field label={t('ux.policy.compose.field')}>
              {(props) => (
                <Select
                  {...props}
                  value={field && fields.includes(field) ? field : ''}
                  onChange={(event) => set({ field: event.target.value || null, to: null, sent: null })}
                >
                  <option value="">{t('ux.policy.compose.asDesigned')}</option>
                  {fields.map((key) => (
                    <option key={key} value={key}>
                      {t(`lab.field.${key}`)} · {text(key, labCase.conditions[key])}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            {field && fields.includes(field) ? (
              <Field label={t('ux.policy.compose.to')}>
                {(props) => (
                  <Select
                    {...props}
                    value={change ? String(change.value) : ''}
                    onChange={(event) => set({ to: event.target.value || null, sent: null })}
                  >
                    <option value="">{t('ux.policy.compose.pickValue')}</option>
                    {choicesOf(field, data)
                      .filter((choice) => choice !== labCase.conditions[field])
                      .map((choice) => (
                        <option key={String(choice)} value={String(choice)}>
                          {text(field, choice)}
                        </option>
                      ))}
                  </Select>
                )}
              </Field>
            ) : null}
          </div>
        </section>
      ) : null}

      {labCase ? <Before labCase={labCase} change={change} options={data} /> : null}
      {labCase ? <Send labCase={labCase} change={change} /> : null}
    </div>
  );
}

/** ST-36: what the engine received in the latest real request of the scenario as designed and of the changed one. */
function Before({
  labCase,
  change,
  options,
}: {
  readonly labCase: LabCase;
  readonly change: ReturnType<typeof changeOf>;
  readonly options: LabOptions;
}) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const conditions = change ? ({ [change.key]: change.value } as Partial<LabConditions>) : null;
  // A write needs the CSRF token the visitor answer writes.
  const ready = useVisitor().isSuccess;
  const designedQuery = useLabBefore(ready ? labCase.key : null, null);
  const composedQuery = useLabBefore(ready && change ? labCase.key : null, conditions);
  const designed = designedQuery.data?.comparison ?? null;
  const composed = change ? (composedQuery.data?.comparison ?? null) : designed;
  const pending = designedQuery.isPending || (change !== null && composedQuery.isPending);
  const n = (value: number) => formatNumber(value, i18n.language);
  const rows: readonly (readonly [string, (view: BeforeSendView | null) => string])[] = [
    ['usual', (view) => (view ? t('ux.policy.before.count', { n: n(view.departureCount) }) : '—')],
    ['company', (view) => (view ? t('ux.policy.before.count', { n: n(view.companyAdverseCount) }) : '—')],
    ['line', (view) => t(`lab.r7.before.line.${lineState(view)}`)],
  ];
  const differ =
    designed !== null && composed !== null && Boolean(designed.modelJudges) !== Boolean(composed.modelJudges);
  return (
    <section className={styles.card} aria-labelledby="compose-before">
      <header className={styles.cardHead}>
        <h2 id="compose-before" className={styles.cardTitle}>
          <span className={styles.no}>3</span>
          {t('ux.policy.before.title')}
        </h2>
        <p className={styles.cardSub}>
          {change
            ? t('ux.policy.before.changed', {
                name: t(`lab.field.${change.key}`),
                from: conditionText(t, change.key, labCase.conditions[change.key], options, language),
                to: conditionText(t, change.key, change.value, options, language),
              })
            : t('ux.policy.before.asDesigned')}
        </p>
      </header>
      {pending ? (
        <Loading rows={3} />
      ) : composed === null && designed === null ? (
        <Note>{t('ux.policy.before.noRecord')}</Note>
      ) : (
        <div className={styles.tableScroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
          <table className={styles.table}>
            <caption className="ux-sr-only">{t('ux.policy.before.title')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.policy.before.item')}</th>
                {change ? <th scope="col">{t('ux.policy.before.designed')}</th> : null}
                <th scope="col">{t(change ? 'ux.policy.before.composed' : 'ux.policy.before.designed')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(([row, value]) => {
                const was = change ? value(designed) : null;
                const is = value(composed);
                // A column without its record differs from nothing: no mark.
                const differs = was !== null && designed !== null && composed !== null && was !== is;
                return (
                  <tr key={row}>
                    <th scope="row">{t(`ux.policy.before.row.${row}`)}</th>
                    {was !== null ? <td>{was}</td> : null}
                    <td>
                      {is}{' '}
                      {differs ? <Badge tone="sel">{t('ux.policy.before.differs')}</Badge> : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {change && composed === null && !pending ? <Note>{t('ux.policy.before.noComposed')}</Note> : null}
      {differ ? <Note tone="warn">{t('ux.policy.before.versions')}</Note> : null}
      {composed ? (
        <p className={styles.source}>
          {t('ux.policy.before.source')} <CodeChip value={composed.runId} />
        </p>
      ) : null}
    </section>
  );
}

/** The visitor's call and the real run (ST-37), the run followed live, and the server's comparison (ST-38). */
function Send({ labCase, change }: { readonly labCase: LabCase; readonly change: ReturnType<typeof changeOf> }) {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const config = useLiveConfig();
  const runs = useGroupRuns([labCase.key]);
  const live = useLiveRun(true);
  const actions = useLiveActions();
  const [call, setCall] = useState<Call | null>(null);
  const sent = params.get('sent');
  const conditions = change ? ({ [change.key]: change.value } as Partial<LabConditions>) : null;
  const prediction: LabPrediction = { call: call ?? 'UNSURE', approaches: {} };
  const { send, sending, ready, refusal, reason, waiting, turnstileContainer, turnstileRequired } = useLiveSend(
    labCase.key,
    (run) => {
      const next = new URLSearchParams(params);
      next.set('sent', run.liveRunId);
      setParams(next, { replace: true });
    },
    {
      post: async (token) => {
        const answer = await startLabRun(labCase.key, conditions, prediction, token);
        const run = answer.body?.run ?? null;
        const reason = answer.body?.reason;
        // The lab answers with the run inside its composition; a refusal carries only its reason.
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
  const view: LiveRunView | null = live.data && live.data.liveRunId === sent ? live.data : null;
  const active = view !== null && ACTIVE.has(view.status);
  const why = !runs.visitorReady
    ? t('ux.review.reason.visitor')
    : call === null
      ? t('ux.review.reason.predict')
      : turnstileRequired && !ready && !sending && !waiting
        ? t('ux.review.reason.human')
        : undefined;
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <>
      <section className={styles.card} aria-labelledby="compose-send">
        <header className={styles.cardHead}>
          <h2 id="compose-send" className={styles.cardTitle}>
            <span className={styles.no}>4</span>
            {t('ux.policy.send.title')}
          </h2>
          <p className={styles.cardSub}>{t('ux.policy.send.sub')}</p>
        </header>
        <div className={styles.cardBody}>
          <div role="radiogroup" aria-labelledby="compose-send" className={styles.calls}>
            {CALLS.map((option) => (
              <button
                key={option}
                type="button"
                role="radio"
                aria-checked={call === option}
                className={styles.callChoice}
                onClick={() => setCall(option)}
              >
                <b>{t(`ux.policy.send.call.${option}`)}</b>
                <span className={review.radio} aria-hidden="true" />
              </button>
            ))}
          </div>
          {turnstileRequired ? <div ref={turnstileContainer} className={review.turnstile} /> : null}
          <div className={styles.sendRow}>
            <Button
              variant="primary"
              size="lg"
              icon="play"
              busy={sending || waiting || active}
              {...(why ? { disabledReason: why } : {})}
              onClick={() => void send()}
            >
              {t('ux.policy.send.run')}
            </Button>
            <span className={styles.source}>
              {config.data ? t('ux.review.daily', { n: n(config.data.dailyRuns), left: n(config.data.remainingToday) }) : null}
            </span>
          </div>
          {waiting ? <Note icon="hourglass">{t('ux.review.waiting')}</Note> : null}
          {refusal ? (
            <Note tone="warn">
              {reason === 'RUN_IN_PROGRESS'
                ? t('ux.policy.send.inProgress')
                : refusal === 'error' && reason
                  ? t('ux.policy.send.refused', { reason })
                  : t(`ux.review.refusal.${refusal}`)}
            </Note>
          ) : null}
          {reason === 'RUN_IN_PROGRESS' && live.data ? (
            <p className={styles.source}>
              {t('ux.policy.send.current')} <CodeChip value={live.data.scenario} />
            </p>
          ) : null}
        </div>
      </section>

      {view ? (
        <section className={styles.card} aria-labelledby="compose-live">
          <header className={styles.cardHead}>
            <h2 id="compose-live" className={styles.cardTitle}>
              <span className={styles.no}>5</span>
              {t('ux.policy.live.title')}
            </h2>
            <p className={styles.cardSub}>{t(`ux.policy.live.status.${active ? 'going' : 'done'}`)}</p>
          </header>
          <div className={styles.tableScroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
            <table className={styles.table}>
              <caption className="ux-sr-only">{t('ux.policy.live.title')}</caption>
              <thead>
                <tr>
                  <th scope="col">{t('ux.agent.steps.request')}</th>
                  {CONTROL_ORDER.map((control) => (
                    <th key={control} scope="col">
                      {t(`ux.control.short.${control}`)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {view.steps.map((step) => (
                  <tr key={step.stepNo}>
                    <th scope="row">{t('ux.pick.requestNo', { n: step.stepNo })}</th>
                    {CONTROL_ORDER.map((control) => (
                      <td key={control}>
                        <AgentCellBadge cell={agentCell(step.layers[control] ?? null)} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {view.challenge ? (
            <div className={styles.cardBody}>
              <ChallengeCard
                challenge={view.challenge}
                act={actions.act}
                onRestart={() => void send()}
                resumed={null}
              />
            </div>
          ) : null}
          {view.status === 'AWAITING' ? (
            <div className={styles.cardBody}>
              <Button
                variant="secondary"
                icon="arrow-right"
                onClick={() => void postJson('/api/live/runs/current/next', {})}
              >
                {t('ux.policy.live.next', { n: view.awaitingStep ?? '' })}
              </Button>
            </div>
          ) : null}
          {actions.failed ? <Note tone="warn">{t('ux.live.actionFailed')}</Note> : null}
        </section>
      ) : null}

      {view && !active && view.runId ? <Versus runId={view.runId} /> : null}
    </>
  );
}

/**
 * One control's result on one side: the grade against the scenario's ground truth when the server scored it, else (a
 * changed composition has no ground truth) the control's own answer.
 */
function SideCell({ side, control }: { readonly side: VersusSide; readonly control: string }) {
  const graded = evalOf(side.business[control] as CaseResult | undefined);
  if (graded) {
    return <EvalBadge result={graded} />;
  }
  const answer = side.outcomes[control];
  return answer ? <AgentCellBadge cell={agentCell({ outcome: answer, ruleId: null })} /> : <>—</>;
}

/** ST-38: the server's comparison of this run against the latest run of the same scenario as designed. */
function Versus({ runId }: { readonly runId: string }) {
  const { t, i18n } = useTranslation();
  const recent = useRecentLabRuns();
  const entry = recent.data?.find((item) => item.runId === runId) ?? null;
  const against = entry?.referenceRunId ?? null;
  const versus = useVersus(runId, against);
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <section className={styles.card} aria-labelledby="compose-result">
      <header className={styles.cardHead}>
        <h2 id="compose-result" className={styles.cardTitle}>
          <span className={styles.no}>6</span>
          {t('ux.policy.result.title')}
        </h2>
        <p className={styles.cardSub}>
          {against ? t('ux.policy.result.against') : t('ux.policy.result.only')}
        </p>
      </header>
      {recent.isPending || (against !== null && versus.isPending) ? (
        <Loading rows={4} />
      ) : !versus.data ? (
        <div className={styles.cardBody}>
          <Note>{t('ux.policy.result.noPair')}</Note>
          <Link to={`/runs/${encodeURIComponent(runId)}`}>{t('ux.live.raw')}</Link>
        </div>
      ) : (
        <>
          <div className={styles.tableScroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
            <table className={styles.table}>
              <caption className="ux-sr-only">{t('ux.policy.result.title')}</caption>
              <thead>
                <tr>
                  <th scope="col">{t('ux.lanes.control')}</th>
                  <th scope="col">{t('ux.policy.result.before')}</th>
                  <th scope="col">{t('ux.policy.result.now')}</th>
                </tr>
              </thead>
              <tbody>
                {CONTROL_ORDER.map((control) => {
                  const changed = versus.data.changedControls.includes(control);
                  return (
                    <tr key={control} data-contexa={control === 'D' || undefined}>
                      <th scope="row">{t(`ux.control.${control}`)}</th>
                      <td>
                        <SideCell side={versus.data.before} control={control} />
                      </td>
                      <td>
                        <SideCell side={versus.data.now} control={control} />{' '}
                        {changed ? <Badge tone="sel">{t('ux.policy.before.differs')}</Badge> : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className={styles.cardBody}>
            <p className={styles.source}>
              {t('ux.policy.result.contexa')}{' '}
              {versus.data.before.engineAction ? (
                <VerdictBadge verdict={verdictOf(versus.data.before.engineAction)} />
              ) : (
                '—'
              )}{' '}
              →{' '}
              {versus.data.now.engineAction ? <VerdictBadge verdict={verdictOf(versus.data.now.engineAction)} /> : '—'} ·{' '}
              {t('ux.policy.result.exposed', {
                before: n(versus.data.before.exposedItems),
                now: n(versus.data.now.exposedItems),
              })}
            </p>
            {versus.data.inputs.length > 0 ? (
              <ul className={styles.inputs}>
                {versus.data.inputs.map((input) => (
                  <li key={input.key}>
                    <code>{input.key}</code> {input.before ?? '—'} → {input.now ?? '—'}
                  </li>
                ))}
              </ul>
            ) : null}
            <p className={styles.source}>
              <CodeChip value={versus.data.before.runId} /> → <CodeChip value={versus.data.now.runId} copy />
            </p>
          </div>
        </>
      )}
    </section>
  );
}
