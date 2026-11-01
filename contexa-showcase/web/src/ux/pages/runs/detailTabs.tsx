import type { TFunction } from 'i18next';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { NO_CHOICE, useAgentCase, useAgentRun } from '../../../api/agentCase';
import {
  useExchanges,
  useReceived,
  type BeforeSendView,
  type DecisionAnatomyView,
} from '../../../api/anatomy';
import { useStepResult } from '../../../api/lab';
import {
  useOtherBundle,
  useRunFacts,
  useRunQuality,
  type BundleSide,
  type FactSufficiency,
  type InspectionCheck,
  type PromptFact,
  type QualityRibbonView,
} from '../../../api/promptQuality';
import { useTeasers } from '../../../api/teasers';
import type { ReasonCode, RunScore } from '../../../api/types';
import { downloadRunRecord } from '../../../api/runRecord';
import { factKey } from '../../runs/factKey';
import { CONTROL_ORDER } from '../../../domain/verdict';
import { formatDuration, formatNumber, formatUtc } from '../../format';
import { agentCell } from '../../simulate/agent';
import { AgentCellBadge } from '../../simulate/AgentParts';
import { CONTROL_TONE } from '../../simulate/controls';
import { contextChips, verdictOf } from '../../simulate/person';
import { Badge, Button, CodeChip, FlagBadge, Loading, Note, VerdictBadge } from '../../ui';
import sim from '../../simulate/Simulate.module.css';
import { appliedKey, challengeOutcomes, checkResult, noDecisionKey, pairCounts } from './detailWords';
import { breakable } from '../../ui/breakable';
import styles from './Detail.module.css';

interface TabProps {
  readonly runId: string;
  readonly step: number;
  readonly anatomy: DecisionAnatomyView;
  readonly score: RunScore | null;
}

const ASSESSMENT = { MOST_LIKELY: 3, POSSIBLE: 2, UNLIKELY: 1, NO_EVIDENCE: 0 } as const;

const QUOTE_SHORT = 220;

/** The facts of the delegated scope and of this request, as the engine received them (DEC-81, 기획안 11절 6-3). */
const SCOPE_LABELS = ['Delegation'] as const;
const REQUEST_LABELS = ['Action', 'Target', 'TargetScope', 'Size', 'Time', 'Credential', 'DelegationActivity'] as const;

/** A fact as the prompt wrote it; a long one shows its start and opens in full. */
function Quote({ text }: { readonly text: string }) {
  const { t } = useTranslation();
  if (text.length <= QUOTE_SHORT) {
    return (
      <code className={styles.quote} lang="en">
        {text}
      </code>
    );
  }
  return (
    <details className={styles.more}>
      <summary>
        <code className={styles.quote} lang="en">
          {text.slice(0, QUOTE_SHORT)}…
        </code>
        <span>{t('ux.detail.evidence.full')}</span>
      </summary>
      <code className={styles.quote} lang="en">
        {text}
      </code>
    </details>
  );
}

/** 요약: the decision, when and how it applied, what left, the learning, the right handling and the grade. */
export function SummaryTab({ runId, step, anatomy, score }: TabProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const result = useStepResult(runId, step);
  const contexa = result.data?.layers.find((layer) => layer.control === 'D') ?? null;
  const recorded = anatomy.interpretation.recorded;
  const timings = anatomy.interpretation.timings;
  const figures = anatomy.figures;
  const graded = score?.verdicts.find((verdict) => verdict.score.stepNo === step)?.score.result ?? null;
  const none = noDecisionKey(anatomy);
  const n = (value: number) => formatNumber(value, i18n.language);
  const applied = appliedKey(contexa?.evidence.timing, recorded.applied);
  const truthSource = anatomy.truth.truthSource;
  return (
    <div className={styles.columns}>
      <section className={styles.card} aria-labelledby="detail-summary">
        <h2 id="detail-summary" className={styles.cardTitle}>
          {t('ux.detail.summary.title')}
        </h2>
        {none ? (
          <Note tone={none === 'ux.detail.none.failed' ? 'warn' : 'neutral'}>
            {t(none, {
              status: contexa?.httpStatus ?? '—',
              rule: contexa?.ruleId ?? '—',
              failure: [recorded.failureType, recorded.fallbackCategory].filter(Boolean).join(' · ') || '—',
            })}
          </Note>
        ) : null}
        <dl className={styles.kv}>
          <dt>{t('ux.result.decision')}</dt>
          <dd>
            <VerdictBadge verdict={none === 'ux.detail.none.failed' ? 'NONE' : verdictOf(recorded.finalAction)} />
            {recorded.proposedAction && recorded.proposedAction !== recorded.finalAction ? (
              <span className={styles.muted}> {t('ux.detail.summary.proposed', { action: recorded.proposedAction })}</span>
            ) : null}
          </dd>
          <dt>{t('ux.detail.summary.applied')}</dt>
          <dd>
            {applied ? t(applied) : '—'}
            {timings?.totalAnalysisMs != null
              ? ` · ${t('ux.time.seconds', { value: formatDuration(timings.totalAnalysisMs, i18n.language) })}`
              : ''}
          </dd>
          <dt>{t('ux.detail.summary.exported')}</dt>
          <dd>
            {contexa
              ? t('ux.facts.items', { count: contexa.evidence.deliveredItems, n: n(contexa.evidence.deliveredItems) })
              : '…'}
            {contexa?.httpStatus ? <span className={styles.muted}> · HTTP {contexa.httpStatus}</span> : null}
          </dd>
          <dt>{t('ux.detail.summary.learning')}</dt>
          <dd>
            {figures.baselineBefore !== null && figures.baselineAfter !== null
              ? t('ux.detail.learning.value', { from: n(figures.baselineBefore), to: n(figures.baselineAfter) })
              : '—'}
          </dd>
          <dt>{t('ux.detail.summary.truth')}</dt>
          <dd>
            {anatomy.truth.classification
              ? t(`ux.detail.truth.${anatomy.truth.classification}`, { defaultValue: anatomy.truth.classification })
              : t('ux.flow.truth.undetermined')}
            {anatomy.truth.allowedEngineActions.length > 0 ? (
              <span className={styles.badges}>
                {anatomy.truth.allowedEngineActions.map((action) => (
                  <VerdictBadge key={action} verdict={verdictOf(action)} />
                ))}
              </span>
            ) : null}
          </dd>
          <dt>{t('ux.detail.summary.truthSource')}</dt>
          <dd>{t(`ux.detail.truthSource.${truthSource ?? 'NONE'}`, { defaultValue: truthSource ?? '—' })}</dd>
          <dt>{t('ux.detail.summary.scenarioHash')}</dt>
          <dd className={styles.wrap}>
            {anatomy.truth.scenarioSha256 ? <code className={styles.code}>{anatomy.truth.scenarioSha256}</code> : '—'}
          </dd>
          <dt>{t('ux.detail.summary.grade')}</dt>
          <dd>{graded ? t(`ux.detail.grade.${graded}`, { defaultValue: graded }) : '—'}</dd>
        </dl>
      </section>
      <section className={styles.card} aria-labelledby="detail-reason">
        <h2 id="detail-reason" className={styles.cardTitle}>
          {t('ux.detail.summary.reason')}
        </h2>
        {recorded.reasoning ? (
          <p className={styles.text} lang={recorded.reasoningCode ? undefined : 'en'}>
            {recorded.reasoningCode
              ? t(`reason.canonical.${recorded.reasoningCode}`, { defaultValue: recorded.reasoning })
              : recorded.reasoning}
          </p>
        ) : (
          <p className={styles.muted}>{t('ux.detail.summary.noReason')}</p>
        )}
        {anatomy.truth.rationale ? (
          <>
            <h3 className={styles.subTitle}>{t('ux.detail.summary.rationale')}</h3>
            <p className={styles.text}>{anatomy.truth.rationale[language] ?? anatomy.truth.rationale.en}</p>
          </>
        ) : null}
        {anatomy.truth.counterpoint ? (
          <>
            <h3 className={styles.subTitle}>{t('ux.detail.summary.counterpoint')}</h3>
            <p className={styles.text}>{anatomy.truth.counterpoint[language] ?? anatomy.truth.counterpoint.en}</p>
          </>
        ) : null}
      </section>
      <ProcessCard anatomy={anatomy} />
    </div>
  );
}

/**
 * 판정 과정 (the old details' process tab, P-8): what the engine gathered and how the decision went, as this request's
 * record says: the business-context lines and past records it received, how long the prompt and the model took,
 * whether it went on to the second pass, and what followed. The demo's step-up outcomes, as the portal counted them,
 * open below.
 */
function ProcessCard({ anatomy }: { readonly anatomy: DecisionAnatomyView }) {
  const { t, i18n } = useTranslation();
  const outcomes = challengeOutcomes(useTeasers().data);
  const n = (value: number) => formatNumber(value, i18n.language);
  const seconds = (ms: number | null | undefined) =>
    ms != null ? t('ux.time.seconds', { value: formatDuration(ms, i18n.language) }) : '—';
  const timings = anatomy.interpretation.timings;
  const events = timings?.events ?? [];
  const lines = anatomy.juxtaposition.companyFacts.length;
  const documents = anatomy.context.rag?.ragAuthorizedDocumentCount ?? null;
  const check = anatomy.recovery?.challenge ?? null;
  const pass = events.some((event) => event.type === 'LAYER2_COMPLETE')
    ? 'ux.detail.process.secondDone'
    : events.some((event) => event.type === 'LAYER1_COMPLETE')
      ? 'ux.detail.process.firstOnly'
      : null;
  return (
    <section className={styles.card} aria-labelledby="detail-process">
      <h2 id="detail-process" className={styles.cardTitle}>
        {t('ux.detail.process.title')}
      </h2>
      <dl className={styles.kv}>
        <dt>{t('ux.detail.process.company')}</dt>
        <dd>{t('ux.detail.process.lines', { count: lines, n: n(lines) })}</dd>
        <dt>{t('ux.detail.process.history')}</dt>
        <dd>{documents !== null ? t('ux.facts.items', { count: documents, n: n(documents) }) : '—'}</dd>
        <dt>{t('ux.detail.process.promptBuild')}</dt>
        <dd>{seconds(timings?.promptBuildMs)}</dd>
        <dt>{t('ux.detail.process.model')}</dt>
        <dd>{seconds(timings?.llmLatencyMs)}</dd>
        <dt>{t('ux.detail.process.second')}</dt>
        <dd>{pass ? t(pass) : '—'}</dd>
        <dt>{t('ux.detail.process.followUp')}</dt>
        <dd>
          {check
            ? t('ux.detail.check.value', {
                result: t(`ux.detail.check.${checkResult(check)}`, { defaultValue: checkResult(check) }),
              })
            : anatomy.recovery?.release
              ? t('ux.detail.process.release')
              : t('ux.detail.process.followUpNone')}
        </dd>
      </dl>
      {outcomes ? (
        <details className={styles.more}>
          <summary>{t('ux.detail.check.demo', { total: n(outcomes.total) })}</summary>
          <ul className={styles.documents}>
            {outcomes.outcomes.map((entry) => (
              <li key={entry.key}>
                {entry.key === 'ANSWERED' && outcomes.resumed !== null
                  ? t('ux.detail.check.answeredResumed', { n: n(entry.n), resumed: n(outcomes.resumed) })
                  : t('ux.detail.check.count', {
                      result: t(`ux.detail.check.${entry.key}`, { defaultValue: entry.key }),
                      n: n(entry.n),
                    })}
              </li>
            ))}
          </ul>
          <p className={styles.muted}>{t('ux.detail.check.demoNote')}</p>
        </details>
      ) : null}
    </section>
  );
}

/** 통제별 응답: each control's answer to the request, as the step's stored result records it. */
export function ControlsTab({ runId, step }: TabProps) {
  const { t, i18n } = useTranslation();
  const result = useStepResult(runId, step);
  if (result.isPending) {
    return <Loading rows={5} />;
  }
  if (!result.data) {
    return <Note tone="warn">{t('ux.detail.unavailable')}</Note>;
  }
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <section className={styles.card} aria-labelledby="detail-controls">
      <h2 id="detail-controls" className={styles.cardTitle}>
        {t('ux.detail.controls.title')}
      </h2>
      <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
        <table className={styles.table}>
          <caption className="ux-sr-only">{t('ux.detail.controls.title')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('ux.lanes.control')}</th>
              <th scope="col">{t('ux.lanes.decision')}</th>
              <th scope="col">HTTP</th>
              <th scope="col">{t('ux.lanes.items')}</th>
              <th scope="col">{t('ux.lanes.time')}</th>
              <th scope="col">{t('ux.detail.controls.rule')}</th>
            </tr>
          </thead>
          <tbody>
            {CONTROL_ORDER.map((control) => {
              const layer = result.data.layers.find((candidate) => candidate.control === control) ?? null;
              return (
                <tr key={control} data-contexa={control === 'D' || undefined}>
                  <th scope="row">
                    <span className={styles.controlName}>
                      <span className={sim.swatch} data-tone={CONTROL_TONE[control]} aria-hidden="true" />
                      {t(`ux.control.${control}`)}
                    </span>
                  </th>
                  <td>
                    {layer ? (
                      layer.verdict ? (
                        <VerdictBadge verdict={verdictOf(layer.verdict)} />
                      ) : (
                        <AgentCellBadge cell={agentCell({ outcome: layer.outcome, ruleId: layer.ruleId })} />
                      )
                    ) : (
                      '—'
                    )}
                  </td>
                  <td>{layer?.httpStatus ?? '—'}</td>
                  <td>{layer ? n(layer.evidence.deliveredItems) : '—'}</td>
                  <td>
                    {layer?.evidence.responseMs != null
                      ? t('ux.time.seconds', { value: formatDuration(layer.evidence.responseMs, i18n.language) })
                      : '—'}
                  </td>
                  <td>
                    {layer?.ruleId ? <code className={styles.code}>{layer.ruleId}</code> : '—'}
                    {layer?.reason ? <span className={styles.muted}> {layer.reason}</span> : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** 판정 근거: what the engine received against the usual, the facts it cited with its codes, and the hypotheses. */
export function EvidenceTab({ runId, step, anatomy, score }: TabProps) {
  const { t, i18n } = useTranslation();
  const quality = useRunQuality(runId, step);
  const facts = useRunFacts(runId, step);
  const received = useReceived(runId, step);
  const all = facts.data?.blocks.flatMap((block) => block.facts) ?? [];
  const factOf = (id: string | null) => (id ? (all.find((fact) => fact.factId === id) ?? null) : null);
  const named = (id: string) => {
    const fact = factOf(id);
    return fact ? `${id} ${t(`fact.label.${factKey(fact.label)}`, { defaultValue: fact.label })}` : id;
  };
  const codes = quality.data?.reasonCodes ?? [];
  const hypotheses = quality.data?.hypotheses ?? [];
  const recorded = anatomy.interpretation.recorded;
  // The distinct prompt lines the reason codes cite: the facts the decision weaves together (5-3).
  const woven = new Set(codes.map((code) => code.fact).filter((fact) => fact !== null)).size;
  const n = (value: number) => formatNumber(value, i18n.language);
  const ratio = received.data?.sizeRatio ?? null;
  return (
    <div className={styles.columns} data-wide-first="true">
      <section className={styles.card} aria-labelledby="detail-cited">
        <h2 id="detail-cited" className={styles.cardTitle}>
          {t('ux.detail.evidence.cited')}
        </h2>
        <p className={styles.cardSub}>
          {t('ux.detail.evidence.citedSub', { n: codes.length })}
          {woven > 0 ? ` · ${t('ux.detail.evidence.citedFacts', { n: woven })}` : ''}
        </p>
        {quality.isPending ? <Loading rows={4} /> : null}
        {!quality.isPending && codes.length === 0 ? (
          <Note>{quality.data?.reason ? t(`ux.detail.reason.${quality.data.reason}`, { defaultValue: quality.data.reason }) : t('ux.detail.evidence.noCodes')}</Note>
        ) : null}
        <ol className={styles.cites}>
          {codes.map((code, index) => {
            const fact = factOf(code.fact);
            // A fact cited by several codes is quoted once, at its first code (I-3 결과 화면과 같다).
            const first = codes.findIndex((other) => other.fact === code.fact) === index;
            return (
              <li key={`${code.code}-${index}`} className={styles.cite}>
                <div className={styles.citeFact}>
                  {code.fact ? <Badge tone="sel">{code.fact}</Badge> : null}
                  <b>{fact ? t(`fact.label.${factKey(fact.label)}`, { defaultValue: fact.label }) : t('ux.detail.evidence.noFact')}</b>
                  {fact && first ? <Quote text={fact.value} /> : null}
                  {fact && !first ? <span className={styles.muted}>{t('ux.detail.evidence.same', { id: code.fact })}</span> : null}
                </div>
                <div className={styles.citeReason}>
                  <p className={styles.text}>
                    {t(code.contract === 'V4' ? `reasonCodeV4.${code.code}` : `reasonCode.${code.code}`, { defaultValue: code.code })}
                  </p>
                  <CodeChip value={code.code} />
                </div>
              </li>
            );
          })}
        </ol>
        <DelegatedScope facts={all} />
        <NormalPair runId={runId} caseKey={score?.scenarioKey ?? null} />
        {received.data && received.data.usualVsNow.length > 0 ? (
          <>
            <h3 className={styles.subTitle}>{t('ux.detail.evidence.usual')}</h3>
            <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
              <table className={styles.table}>
                <caption className="ux-sr-only">{t('ux.detail.evidence.usual')}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t('ux.detail.evidence.dimension')}</th>
                    <th scope="col">{t('ux.detail.evidence.usualValue')}</th>
                    <th scope="col">{t('ux.detail.evidence.now')}</th>
                    <th scope="col">{t('ux.detail.evidence.mark')}</th>
                  </tr>
                </thead>
                <tbody>
                  {received.data.usualVsNow.map((row) => (
                    <tr key={row.dimension}>
                      <th scope="row">{t(`ux.compare.dim.${row.dimension}`, { defaultValue: row.dimension })}</th>
                      {/* Machine values (PASSWORD+ONE_TIME_CODE, 10.40.21.0/24) break at their parts, never one letter alone. */}
                      <td className={styles.wrap}>{breakable(received.data?.usual[row.dimension]?.values.join(', ') || '—')}</td>
                      <td className={styles.wrap}>{breakable(row.now ?? '—')}</td>
                      <td>
                        {row.inUsual === 'false' ? (
                          <FlagBadge />
                        ) : row.inUsual === 'true' ? (
                          <Badge tone="none">{t('ux.facts.mark.in')}</Badge>
                        ) : (
                          <Badge tone="none">{t('ux.facts.mark.unknown')}</Badge>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        ) : null}
        {ratio ? (
          <p className={styles.muted}>
            {t('ux.detail.evidence.sizeRatio', {
              items: n(ratio.items),
              largest: n(ratio.usualLargest),
              times: n(ratio.times),
            })}
          </p>
        ) : null}
        {received.data ? <BusinessContext received={received.data} lines={anatomy.juxtaposition.companyFacts} /> : null}
      </section>
      <section className={styles.card} aria-labelledby="detail-hypotheses">
        <h2 id="detail-hypotheses" className={styles.cardTitle}>
          {t('ux.detail.evidence.hypotheses')}
        </h2>
        <p className={styles.cardSub}>{t('ux.detail.evidence.hypothesesSub')}</p>
        {recorded.reasoning ? (
          <div className={styles.summaryBox}>
            <p className={styles.summaryHead}>
              {t('ux.result.evidence.summary')}{' '}
              <Badge tone="line">{t(recorded.reasoningCode ? 'ux.result.evidence.fixed' : 'ux.recovery.original')}</Badge>
            </p>
            <p className={styles.text} lang={recorded.reasoningCode ? undefined : 'en'}>
              {recorded.reasoningCode
                ? t(`reason.canonical.${recorded.reasoningCode}`, { defaultValue: recorded.reasoning })
                : recorded.reasoning}
            </p>
          </div>
        ) : null}
        {hypotheses.length === 0 ? <p className={styles.muted}>{t('ux.detail.evidence.noHypotheses')}</p> : null}
        <ul className={styles.hypotheses}>
          {hypotheses.map((hypothesis) => {
            const level = ASSESSMENT[hypothesis.assessment as keyof typeof ASSESSMENT] ?? 0;
            return (
              <li key={hypothesis.id} className={styles.hypothesis}>
                <div className={styles.hypothesisHead}>
                  <b>{hypothesis.name ?? t(`hypothesis.${hypothesis.id}.short`, { defaultValue: t(`hypothesis.${hypothesis.id}`) })}</b>
                  <span className={styles.level} aria-label={t(`hypothesis.assessment.${hypothesis.assessment}`, { defaultValue: hypothesis.assessment })}>
                    {[1, 2, 3].map((segment) => (
                      <i key={segment} data-on={segment <= level || undefined} aria-hidden="true" />
                    ))}
                    <span>{t(`hypothesis.assessment.${hypothesis.assessment}`, { defaultValue: hypothesis.assessment })}</span>
                  </span>
                </div>
                <dl className={styles.forAgainst}>
                  <dt>{t('ux.detail.evidence.for')}</dt>
                  <dd>{hypothesis.for.length ? hypothesis.for.map((id) => <Badge key={id} tone="sel">{named(id)}</Badge>) : '—'}</dd>
                  <dt>{t('ux.detail.evidence.against')}</dt>
                  <dd>{hypothesis.against.length ? hypothesis.against.map((id) => <Badge key={id} tone="line">{named(id)}</Badge>) : '—'}</dd>
                </dl>
              </li>
            );
          })}
        </ul>
      </section>
    </div>
  );
}

/**
 * 위임 범위 대비 요청 (DEC-81): an agent's delegated scope beside this request, each fact as the engine received it. The
 * screen weighs nothing itself; a run with no delegation fact (a person's account) has no such part.
 */
function DelegatedScope({ facts }: { readonly facts: readonly PromptFact[] }) {
  const { t } = useTranslation();
  const pick = (labels: readonly string[]) =>
    labels.flatMap((label) => facts.filter((fact) => factKey(fact.label) === label));
  const scope = pick(SCOPE_LABELS);
  if (scope.length === 0) {
    return null;
  }
  const side = (title: string, rows: readonly PromptFact[]) => (
    <div className={styles.scopeSide}>
      <h4 className={styles.scopeTitle}>{title}</h4>
      <dl className={styles.scopeFacts}>
        {rows.map((fact) => (
          <div key={fact.factId} className={styles.scopeFact}>
            <dt>
              <Badge tone="sel">{fact.factId}</Badge> {t(`fact.label.${factKey(fact.label)}`, { defaultValue: fact.label })}
            </dt>
            <dd>
              <Quote text={fact.value} />
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
  return (
    <>
      <h3 className={styles.subTitle}>{t('ux.detail.scope.title')}</h3>
      <p className={styles.cardSub}>{t('ux.detail.scope.sub')}</p>
      <div className={styles.scopeGrid}>
        {side(t('ux.detail.scope.delegated'), scope)}
        {side(t('ux.detail.scope.request'), pick(REQUEST_LABELS))}
      </div>
    </>
  );
}

/**
 * 같은 위임 범위의 정상 업무 (the old 6-3 normal pair, P-8): for an agent run, the operator's recorded run of the case's
 * legitimate pair, the same work within the delegation: how many requests it sent, how many all four existing controls
 * and Contexa delivered, and whether the agent finished. A person's run, or a case without a pair, has no such part.
 */
function NormalPair({ runId, caseKey }: { readonly runId: string; readonly caseKey: string | null }) {
  const { t, i18n } = useTranslation();
  const agent = useAgentRun(runId);
  const agentCase = useAgentCase(caseKey ?? '', NO_CHOICE, Boolean(agent.data && caseKey));
  const pairKey = agentCase.data?.normalPair ?? null;
  const pair = useAgentRun(agentCase.data?.normalRecorded?.runId ?? null);
  if (!pairKey || !pair.data) {
    return null;
  }
  const counts = pairCounts(pair.data);
  const items = (value: number) => t('ux.facts.items', { count: value, n: formatNumber(value, i18n.language) });
  return (
    <>
      <h3 className={styles.subTitle}>{t('ux.detail.pair.title')}</h3>
      <p className={styles.cardSub}>{t('ux.detail.pair.sub', { key: pairKey })}</p>
      <dl className={styles.kv}>
        <dt>{t('ux.detail.pair.run')}</dt>
        <dd>
          <Link to={`/runs/${encodeURIComponent(pair.data.runId)}`} className={styles.runLink}>
            {pair.data.runId}
          </Link>
        </dd>
        <dt>{t('ux.detail.pair.requests')}</dt>
        <dd>{items(counts.requests)}</dd>
        <dt>{t('ux.detail.pair.existing')}</dt>
        <dd>{items(counts.existing)}</dd>
        <dt>{t('ux.detail.pair.delivered')}</dt>
        <dd>{items(counts.delivered)}</dd>
        <dt>{t('ux.detail.pair.finished')}</dt>
        <dd>{t(pair.data.finalAnswer ? 'ux.detail.pair.done' : 'ux.detail.pair.notDone')}</dd>
      </dl>
    </>
  );
}

/**
 * 판정 엔진이 받은 업무 컨텍스트 (the old details' received tab, P-8): the business records the lookup returned, each
 * marked when the engine's response inspector read it as adverse (its company labels), the approval the company policy
 * asks for or does not, and the lines as the engine received them. The screen weighs nothing itself.
 */
function BusinessContext({ received, lines }: { readonly received: BeforeSendView; readonly lines: readonly string[] }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const flagged = new Set(received.companyAdverse.map((label) => label.label));
  const words = contextChips(t, received.businessFacts);
  const approvalRequired = received.company['approvalRequired'];
  const rows: readonly { readonly key: string; readonly text: string; readonly code: string | null; readonly flagged: boolean }[] = [
    ...received.companyAdverse
      .filter((label) => label.label === 'policysatisfied' && label.met)
      .map((label, index) => ({
        key: `policy-${index}`,
        text: t('ux.detail.context.policy'),
        code: label.values.join(', ') || null,
        flagged: true,
      })),
    ...(approvalRequired === true
      ? [
          {
            key: 'approvalRequired',
            text: t('ux.detail.context.approvalRequired'),
            code: null,
            flagged: flagged.has('approvalrequired'),
          },
        ]
      : []),
    ...received.businessFacts.map((fact, index) => ({
      key: `${fact.code}-${index}`,
      text: words[index] ?? fact.code,
      code: null,
      flagged: fact.code === 'NO_APPROVAL' && flagged.has('approvalmissing'),
    })),
  ];
  const notRequired = approvalRequired === false && received.businessFacts.some((fact) => fact.code === 'NO_APPROVAL');
  return (
    <>
      <h3 className={styles.subTitle}>{t('ux.detail.context.title')}</h3>
      <p className={styles.cardSub}>
        {t('ux.detail.context.sub', { lines: n(lines.length), flagged: n(received.companyAdverseCount) })}
      </p>
      {rows.length > 0 ? (
        <ul className={styles.contextRows}>
          {rows.map((row) => (
            <li key={row.key}>
              <span>{row.text}</span>
              {row.code ? <code className={styles.code}>{row.code}</code> : null}
              {row.flagged ? <FlagBadge>{t('ux.detail.context.adverse')}</FlagBadge> : null}
            </li>
          ))}
        </ul>
      ) : (
        <p className={styles.muted}>{t('ux.detail.context.none')}</p>
      )}
      {notRequired ? <p className={styles.muted}>{t('ux.detail.context.approvalNotRequired')}</p> : null}
      {lines.length > 0 ? (
        <details className={styles.more}>
          <summary>{t('ux.detail.context.raw', { n: n(lines.length) })}</summary>
          <ol className={styles.documents}>
            {lines.map((line, index) => (
              <li key={index}>
                <code className={styles.quote} lang="en">
                  {line}
                </code>
              </li>
            ))}
          </ol>
        </details>
      ) : null}
    </>
  );
}

/** 판정 프롬프트: the facts the engine was given, block by block, and how the prompt was built. */
export function PromptTab({ runId, step, anatomy }: TabProps) {
  const { t, i18n } = useTranslation();
  const facts = useRunFacts(runId, step);
  const quality = useRunQuality(runId, step);
  const received = useReceived(runId, step);
  const lines = anatomy.promptLines;
  const bundle = facts.data?.bundle ?? quality.data?.bundle ?? null;
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <div className={styles.stack}>
      {quality.isPending ? null : (
        <PromptChecks anatomy={anatomy} ribbon={quality.data?.available ? (quality.data.ribbon ?? null) : null} />
      )}
      <section className={styles.card} aria-labelledby="detail-prompt">
        <h2 id="detail-prompt" className={styles.cardTitle}>
          {t('ux.detail.prompt.title')}
        </h2>
        <p className={styles.cardSub}>
          {lines ? t('ux.detail.prompt.lines', { system: n(lines.system), user: n(lines.user), total: n(lines.total) }) : null}
          {bundle?.version ? ` · ${t('ux.detail.prompt.bundle', { version: bundle.version })}` : ''}
        </p>
        {facts.isPending ? <Loading rows={6} /> : null}
        {facts.data && !facts.data.available ? (
          <Note>{t(`ux.detail.reason.${facts.data.reason ?? 'other'}`, { defaultValue: facts.data.reason ?? '' })}</Note>
        ) : null}
        {(facts.data?.blocks ?? []).map((block) => (
          <section key={block.block} className={styles.block} aria-label={t(`ux.detail.block.${block.block}`, { defaultValue: block.block })}>
            <h3 className={styles.subTitle}>{t(`ux.detail.block.${block.block}`, { defaultValue: block.block })}</h3>
            <ol className={styles.lines}>
              {block.facts.map((fact) => (
                <li key={fact.line}>
                  <span className={styles.lineNo}>{fact.line}</span>
                  {fact.factId ? <Badge tone="sel">{fact.factId}</Badge> : null}
                  <span className={styles.lineLabel}>
                    {t(`fact.label.${factKey(fact.label)}`, { defaultValue: fact.label })}
                    {/* The source grade the line states (the dictionary's five), as in the old prompt tab. */}
                    <span className={styles.lineSource}>
                      {t(`ux.detail.source.${fact.source ?? 'NONE'}`, { defaultValue: fact.source ?? '' })}
                    </span>
                  </span>
                  <span className={styles.lineValue}>
                    <code className={styles.quote} lang="en">
                      {fact.value}
                    </code>
                    {fact.sufficiency ? (
                      <span className={styles.muted}>{sufficiencyWords(t, fact.sufficiency)}</span>
                    ) : null}
                  </span>
                </li>
              ))}
            </ol>
          </section>
        ))}
      </section>
      <MinimumRules received={received.data ?? null} />
      <OtherBundle runId={runId} step={step} />
    </div>
  );
}

/** The action sources a sufficiency cause names in words; any other is shown as recorded. */
const NAMED_SOURCES: ReadonlySet<string> = new Set(['protectableMethod', 'httpMethod', 'method']);

/** A baseline line's evidence grade below strong, its causes and its cautions, as the server read them (N-UI-1). */
function sufficiencyWords(t: TFunction, sufficiency: FactSufficiency): string {
  const causes = sufficiency.causes.map((cause) => {
    if (cause.kind !== 'ACTION_INFERRED') {
      return t(`ux.detail.sufficiency.${cause.kind}`, { n: cause.count, of: cause.of, defaultValue: cause.kind });
    }
    const from =
      cause.from === null
        ? t('ux.detail.sufficiency.from.other')
        : NAMED_SOURCES.has(cause.from)
          ? t(`ux.detail.sufficiency.from.${cause.from}`)
          : cause.from;
    return t(cause.count === cause.of ? 'ux.detail.sufficiency.ACTION_INFERRED_ALL' : 'ux.detail.sufficiency.ACTION_INFERRED', {
      n: cause.count,
      of: cause.of,
      from,
    });
  });
  const cautions = sufficiency.cautions > 0 ? [t('ux.detail.sufficiency.cautions', { n: sufficiency.cautions })] : [];
  return [t(`ux.detail.sufficiency.${sufficiency.grade}`, { defaultValue: sufficiency.grade }), ...causes, ...cautions].join(
    ' · ',
  );
}

/**
 * 프롬프트 검사 수치 (the old prompt tab's checks, P-8): the official inspection's counts of the sealed prompt as the
 * server gave them, and how many of the core inspector's conditions against passing the prompt met, with their labels.
 */
function PromptChecks({
  anatomy,
  ribbon,
}: {
  readonly anatomy: DecisionAnatomyView;
  readonly ribbon: QualityRibbonView | null;
}) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const juxtaposition = anatomy.juxtaposition;
  const met = juxtaposition.coreAdverseLabels.filter((label) => label.met).map((label) => label.label);
  // A decision whose inspector reads no conditions against passing (v21) states no count of them.
  const adverse = juxtaposition.adverseChecked > 0;
  return (
    <section className={styles.card} aria-labelledby="detail-prompt-checks">
      <h2 id="detail-prompt-checks" className={styles.cardTitle}>
        {t('ux.detail.prompt.checks')}
      </h2>
      {ribbon || adverse ? (
        <dl className={styles.kv}>
          {ribbon ? (
            <>
              <dt>{t('ux.detail.prompt.withSource')}</dt>
              <dd>{`${n(ribbon.withSource)} / ${n(ribbon.facts)}`}</dd>
              <dt>{t('ux.detail.prompt.accuracy')}</dt>
              <dd>
                {ribbon.factAccuracy
                  ? `${n(ribbon.factAccuracy.matched)} / ${n(ribbon.factAccuracy.total)}`
                  : t('ux.detail.prompt.pending')}
              </dd>
              <dt>{t('ux.detail.prompt.contradictions')}</dt>
              <dd>{ribbon.contradictions !== null ? n(ribbon.contradictions) : t('ux.detail.prompt.pending')}</dd>
              <dt>{t('ux.detail.prompt.unknown')}</dt>
              <dd>{n(ribbon.unknown)}</dd>
            </>
          ) : null}
          {adverse ? (
            <>
              <dt>{t('ux.detail.prompt.adverse')}</dt>
              <dd>
                {`${n(juxtaposition.adverseMet)} / ${n(juxtaposition.adverseChecked)}`}
                {met.length > 0 ? (
                  <>
                    {' · '}
                    <code className={styles.code}>{met.join(', ')}</code>
                  </>
                ) : null}
              </dd>
            </>
          ) : null}
        </dl>
      ) : null}
      {ribbon ? null : <Note>{t('ux.detail.prompt.noChecks')}</Note>}
    </section>
  );
}

/**
 * 최소 판정 규칙 (the old rules tab, P-8): the minimum action rules of the system prompt, each line as sent with the
 * floor it names and whether the engine found it met in this step's decision record. A prompt that states none (the
 * model judges by its own reasoning) has no such part; its whole system text is in the model answer tab.
 */
function MinimumRules({ received }: { readonly received: BeforeSendView | null }) {
  const { t } = useTranslation();
  const rules = received?.minimumRules?.rules ?? [];
  if (rules.length === 0) {
    return null;
  }
  return (
    <section className={styles.card} aria-labelledby="detail-rules">
      <h2 id="detail-rules" className={styles.cardTitle}>
        {t('ux.detail.rules.title')}
      </h2>
      <p className={styles.cardSub}>{t('ux.detail.rules.sub')}</p>
      <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
        <table className={styles.table}>
          <caption className="ux-sr-only">{t('ux.detail.rules.title')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('ux.detail.rules.code')}</th>
              <th scope="col">{t('ux.detail.rules.line')}</th>
              <th scope="col">{t('ux.detail.rules.floor')}</th>
              <th scope="col">{t('ux.detail.rules.met')}</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule, index) => (
              <tr key={`${rule.code}-${index}`}>
                <th scope="row">
                  <code className={styles.code}>{breakable(rule.code)}</code>
                </th>
                <td>
                  <Quote text={rule.line} />
                </td>
                <td>
                  {rule.floor === null ? (
                    '—'
                  ) : verdictOf(rule.floor) === 'NONE' ? (
                    <code className={styles.code}>{rule.floor}</code>
                  ) : (
                    <VerdictBadge verdict={verdictOf(rule.floor)} />
                  )}
                </td>
                <td>
                  {rule.met === null ? (
                    '—'
                  ) : (
                    <Badge tone={rule.met ? 'sel' : 'none'}>
                      {t(rule.met ? 'ux.detail.rules.metYes' : 'ux.detail.rules.metNo')}
                    </Badge>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/**
 * 다른 번들로 보낸 같은 시나리오 (U-2, the old prompt tab's comparison, P-8): not the same request, but the measured run
 * of the same scenario and conditions under the other prompt bundle, side by side with this one, with the server's
 * ordered line counts when it has them. Nothing when the server found no such run.
 */
function OtherBundle({ runId, step }: { readonly runId: string; readonly step: number }) {
  const { t, i18n } = useTranslation();
  const other = useOtherBundle(runId, step).data ?? null;
  if (!other?.available || !other.current || !other.other) {
    return null;
  }
  const n = (value: number) => formatNumber(value, i18n.language);
  const lines = other.lines ?? null;
  const side = (title: string, value: BundleSide) => (
    <div className={styles.scopeSide}>
      <h3 className={styles.scopeTitle}>{title}</h3>
      <dl className={styles.kv}>
        <dt>{t('ux.detail.other.bundle')}</dt>
        <dd>{value.bundle.version ?? '—'}</dd>
        <dt>{t('ux.detail.other.run')}</dt>
        <dd>
          <Link to={`/runs/${encodeURIComponent(value.runId)}?step=${value.stepNo}`} className={styles.runLink}>
            {value.runId}
          </Link>
        </dd>
        <dt>{t('ux.detail.other.rules')}</dt>
        <dd>{value.systemPromptLines !== null ? t('ux.detail.process.lines', { count: value.systemPromptLines, n: n(value.systemPromptLines) }) : '—'}</dd>
      </dl>
      {value.userPrompt !== null ? (
        <details className={styles.more}>
          <summary>{t('ux.detail.other.user')}</summary>
          <pre className={styles.raw} lang="en" tabIndex={0} aria-label={t('ux.detail.other.user')}>
            {value.userPrompt}
          </pre>
        </details>
      ) : (
        <p className={styles.muted}>{t('ux.detail.other.noText')}</p>
      )}
    </div>
  );
  return (
    <section className={styles.card} aria-labelledby="detail-other">
      <h2 id="detail-other" className={styles.cardTitle}>
        {t('ux.detail.other.title')}
      </h2>
      <p className={styles.cardSub}>{t('ux.detail.other.sub')}</p>
      {lines ? (
        <p className={styles.text}>
          {t('ux.detail.other.lines', {
            before: lines.before,
            beforeLines: n(lines.beforeLines),
            after: lines.after,
            afterLines: n(lines.afterLines),
          })}
        </p>
      ) : null}
      <div className={styles.scopeGrid}>
        {side(t('ux.detail.other.current'), other.current)}
        {side(t('ux.detail.other.other'), other.other)}
      </div>
    </section>
  );
}

/**
 * 모델 응답 원문: what the decision record holds of the model's answer and where each value came from, every model
 * call's figures (kept with the record), and each call as it was sent and answered (kept for the retention period).
 */
export function ResponseTab({ runId, step, anatomy }: TabProps) {
  const { t, i18n } = useTranslation();
  const exchanges = useExchanges(runId, step, true);
  const quality = useRunQuality(runId, step);
  const calls = exchanges.data?.kept ? exchanges.data.calls : [];
  const last = calls.length > 0 ? (calls[calls.length - 1]?.callNo ?? null) : null;
  const lines = anatomy.promptLines;
  const physical = (n: number) =>
    ` · ${t('ux.detail.process.lines', { count: n, n: formatNumber(n, i18n.language) })}`;
  return (
    <div className={styles.stack}>
      <RecordedValues anatomy={anatomy} codes={quality.data?.reasonCodes ?? []} />
      <CallFigures anatomy={anatomy} />
      {exchanges.isPending ? <Loading rows={6} /> : null}
      {!exchanges.isPending && !exchanges.data ? <Note tone="warn">{t('ux.detail.unavailable')}</Note> : null}
      {exchanges.data && !exchanges.data.kept ? (
        <Note>{t(`ux.detail.response.missing.${exchanges.data.missing ?? 'NOT_COLLECTED'}`)}</Note>
      ) : null}
      {calls.map((call) => (
        <section key={call.callNo} className={styles.card} aria-labelledby={`detail-call-${call.callNo}`}>
          <h2 id={`detail-call-${call.callNo}`} className={styles.cardTitle}>
            {t('ux.detail.response.call', { n: call.callNo })}
          </h2>
          <p className={styles.cardSub}>
            {[call.model, call.finishReason, call.capturedAt ? `${formatUtc(call.capturedAt)} ${t('ux.runs.utc')}` : null]
              .filter(Boolean)
              .join(' · ')}
            {call.maskedPlaces > 0 ? ` · ${t('ux.detail.response.masked', { n: call.maskedPlaces })}` : ''}
          </p>
          <h3 className={styles.subTitle}>{t('ux.detail.response.answer')}</h3>
          <pre className={styles.raw} lang="en" tabIndex={0} aria-label={t('ux.detail.response.answer')}>
            {call.answer ?? '—'}
          </pre>
          {/* The texts as sent; the physical line counts are the decision's own text, the last call's (D-38). */}
          {call.systemPrompt !== null ? (
            <details className={styles.more}>
              <summary>
                {t('ux.detail.response.system')}
                {lines && call.callNo === last ? physical(lines.systemPhysical) : ''}
              </summary>
              <pre className={styles.raw} lang="en" tabIndex={0} aria-label={t('ux.detail.response.system')}>
                {call.systemPrompt}
              </pre>
            </details>
          ) : null}
          {call.userPrompt !== null ? (
            <details className={styles.more}>
              <summary>
                {t('ux.detail.response.user')}
                {lines && call.callNo === last ? physical(lines.userPhysical) : ''}
              </summary>
              <pre className={styles.raw} lang="en" tabIndex={0} aria-label={t('ux.detail.response.user')}>
                {call.userPrompt}
              </pre>
            </details>
          ) : null}
          {call.providerResponse ? (
            <details className={styles.more}>
              <summary>{t('ux.detail.response.provider')}</summary>
              <pre className={styles.raw} lang="en" tabIndex={0} aria-label={t('ux.detail.response.provider')}>
                {call.providerResponse}
              </pre>
            </details>
          ) : null}
        </section>
      ))}
    </div>
  );
}

/** The fields of the decision record in the order the old original tab read them; others the record names follow. */
const RECORDED_FIELDS = ['riskScore', 'confidence', 'mitre', 'evidenceRefs', 'reasoning', 'reasonCodes'] as const;

/**
 * 기록된 판정 값 (the old original tab and 3-3 · 5-3's value sources, P-8): each field of the decision record with its
 * value and whether the model wrote it (the record's field provenance), then the second pass's own reason when there
 * was one. Values as recorded; the model's text stays in English.
 */
function RecordedValues({ anatomy, codes }: { readonly anatomy: DecisionAnatomyView; readonly codes: readonly ReasonCode[] }) {
  const { t } = useTranslation();
  const recorded = anatomy.interpretation.recorded;
  const provenance = recorded.fieldProvenance ?? {};
  const fields = [
    ...RECORDED_FIELDS,
    ...Object.keys(provenance).filter((field) => !(RECORDED_FIELDS as readonly string[]).includes(field)),
  ];
  const second =
    anatomy.interpretation.timings?.events.find((event) => event.type === 'LAYER2_COMPLETE')?.reasoning ?? null;
  const code = (text: string) => <code className={styles.code}>{breakable(text)}</code>;
  const valueOf = (field: string) => {
    switch (field) {
      case 'riskScore':
        return recorded.riskScore !== null ? recorded.riskScore.toFixed(2) : '—';
      case 'confidence':
        return recorded.confidence !== null ? recorded.confidence.toFixed(2) : '—';
      case 'mitre':
        return recorded.mitre ? code(recorded.mitre) : '—';
      case 'evidenceRefs':
        return recorded.evidenceRefs && recorded.evidenceRefs.length > 0 ? code(recorded.evidenceRefs.join(', ')) : '—';
      case 'reasoning':
        return recorded.reasoning ? <Quote text={recorded.reasoning} /> : '—';
      case 'reasonCodes':
        return codes.length > 0 ? code(codes.map((reason) => reason.code).join(', ')) : '—';
      default:
        return '—';
    }
  };
  return (
    <section className={styles.card} aria-labelledby="detail-recorded">
      <h2 id="detail-recorded" className={styles.cardTitle}>
        {t('ux.detail.response.recorded')}
      </h2>
      <p className={styles.cardSub}>{t('ux.detail.response.recordedSub')}</p>
      <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
        <table className={styles.table}>
          <caption className="ux-sr-only">{t('ux.detail.response.recorded')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('ux.detail.response.col.field')}</th>
              <th scope="col">{t('ux.detail.response.col.value')}</th>
              <th scope="col">{t('ux.detail.response.col.provenance')}</th>
            </tr>
          </thead>
          <tbody>
            {fields.map((field) => {
              const source = provenance[field] ?? null;
              return (
                <tr key={field}>
                  <th scope="row">{t(`ux.detail.response.field.${field}`, { defaultValue: field })}</th>
                  <td className={styles.wrap}>{valueOf(field)}</td>
                  <td>
                    {source === null
                      ? '—'
                      : source === 'MODEL' || source === 'ABSENT'
                        ? t(`ux.detail.provenance.${source}`)
                        : code(source)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {second ? (
        <>
          <h3 className={styles.subTitle}>{t('ux.detail.response.second')}</h3>
          <Quote text={second} />
        </>
      ) : null}
    </section>
  );
}

/**
 * 모델 호출 기록 (the old original tab's call figures, P-8): every model call of the decision with its model, its input
 * and output tokens, how long it took and whether it succeeded, as the record keeps them past the texts' retention.
 */
function CallFigures({ anatomy }: { readonly anatomy: DecisionAnatomyView }) {
  const { t, i18n } = useTranslation();
  const calls = anatomy.interpretation.calls;
  if (calls.length === 0) {
    return null;
  }
  const n = (value: number | null) => (value !== null ? formatNumber(value, i18n.language) : '—');
  return (
    <section className={styles.card} aria-labelledby="detail-calls">
      <h2 id="detail-calls" className={styles.cardTitle}>
        {t('ux.detail.response.calls')}
      </h2>
      <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
        <table className={styles.table}>
          <caption className="ux-sr-only">{t('ux.detail.response.calls')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('ux.detail.response.col.call')}</th>
              <th scope="col">{t('ux.detail.response.col.model')}</th>
              <th scope="col">{t('ux.detail.response.col.input')}</th>
              <th scope="col">{t('ux.detail.response.col.output')}</th>
              <th scope="col">{t('ux.detail.response.col.time')}</th>
              <th scope="col">{t('ux.detail.response.col.result')}</th>
            </tr>
          </thead>
          <tbody>
            {calls.map((call) => (
              <tr key={call.callNo}>
                <th scope="row">{call.callNo}</th>
                <td>{call.model ? <code className={styles.code}>{breakable(call.model)}</code> : '—'}</td>
                <td>{n(call.promptTokens)}</td>
                <td>{n(call.completionTokens)}</td>
                <td>
                  {call.elapsedMs !== null
                    ? t('ux.time.seconds', { value: formatDuration(call.elapsedMs, i18n.language) })
                    : '—'}
                </td>
                <td data-bad={!call.success || undefined}>
                  {t(call.success ? 'ux.detail.response.ok' : 'ux.detail.response.fail')}
                  {call.failure ? (
                    <>
                      {' '}
                      <code className={styles.code}>{breakable(call.failure)}</code>
                    </>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** 무결성 검증 (DEC-43): the seal, the official inspection with every check's counts, and the record to download. */
export function IntegrityTab({ runId, step, anatomy }: TabProps) {
  const { t } = useTranslation();
  const quality = useRunQuality(runId, step);
  const [hash, setHash] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const seal = quality.data?.seal ?? null;
  const inspection = quality.data?.inspection ?? null;
  async function download() {
    setFailed(false);
    try {
      setHash(await downloadRunRecord(runId, step, anatomy));
    } catch {
      setFailed(true);
    }
  }
  return (
    <div className={styles.columns}>
      <section className={styles.card} aria-labelledby="detail-seal">
        <h2 id="detail-seal" className={styles.cardTitle}>
          {t('ux.detail.integrity.seal')}
        </h2>
        {quality.isPending ? (
          <Loading rows={3} />
        ) : seal ? (
          <dl className={styles.kv}>
            <dt>{t('ux.detail.integrity.package')}</dt>
            <dd>
              <CodeChip value={seal.packageId} copy />
            </dd>
            <dt>{t('ux.detail.integrity.hash')}</dt>
            <dd className={styles.wrap}>
              <code className={styles.code}>{seal.packageHash ?? '—'}</code>
            </dd>
            <dt>{t('ux.detail.integrity.at')}</dt>
            <dd>{seal.capturedAt ? `${formatUtc(seal.capturedAt)} ${t('ux.runs.utc')}` : '—'}</dd>
            <dt>{t('ux.detail.integrity.bundle')}</dt>
            <dd>{quality.data?.bundle?.version ?? '—'}</dd>
            <dt>{t('ux.detail.integrity.bundleHash')}</dt>
            <dd className={styles.wrap}>
              {quality.data?.bundle?.hash ? <code className={styles.code}>{quality.data.bundle.hash}</code> : '—'}
            </dd>
            <dt>{t('ux.detail.integrity.selection')}</dt>
            <dd>
              {quality.data?.bundle?.selectionSource ? (
                <code className={styles.code}>{quality.data.bundle.selectionSource}</code>
              ) : (
                '—'
              )}
            </dd>
          </dl>
        ) : (
          <Note>{t('ux.detail.integrity.noSeal')}</Note>
        )}
        <div className={styles.download}>
          <Button variant="secondary" icon="download" onClick={() => void download()}>
            {t('ux.detail.integrity.download')}
          </Button>
          <p className={styles.muted}>{t('ux.detail.integrity.downloadNote')}</p>
          {hash ? (
            <p className={styles.wrap}>
              SHA-256 <code className={styles.code}>{hash}</code>
            </p>
          ) : null}
          {failed ? <Note tone="warn">{t('ux.detail.integrity.downloadFailed')}</Note> : null}
        </div>
      </section>
      <section className={styles.card} aria-labelledby="detail-inspection">
        <h2 id="detail-inspection" className={styles.cardTitle}>
          {t('ux.detail.integrity.inspection')}
        </h2>
        {quality.isPending ? (
          <Loading rows={4} />
        ) : inspection ? (
          <>
            <p className={styles.verdictLine}>
              <Badge tone={inspection.verdict === 'PASS' ? 'allow' : inspection.verdict === 'FAIL' ? 'block' : 'stepup'}>
                {t(`ux.detail.integrity.verdict.${inspection.verdict}`, { defaultValue: inspection.verdict })}
              </Badge>
              <span className={styles.muted}>
                {[inspection.inspectorVersion, inspection.inspectedAt ? formatUtc(inspection.inspectedAt) : null]
                  .filter(Boolean)
                  .join(' · ')}
              </span>
            </p>
            <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
              <table className={styles.table} data-fit>
                <caption className="ux-sr-only">{t('ux.detail.integrity.inspection')}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t('ux.detail.integrity.check')}</th>
                    <th scope="col">{t('ux.detail.integrity.matched')}</th>
                    <th scope="col">{t('ux.detail.integrity.mismatched')}</th>
                    <th scope="col">{t('ux.detail.integrity.unverifiable')}</th>
                  </tr>
                </thead>
                <tbody>
                  {inspection.checks.map((check) => (
                    <tr key={check.code}>
                      <th scope="row">
                        {t(`ux.detail.integrity.checks.${check.code}`, { defaultValue: check.code })}
                      </th>
                      <td>{check.matched}</td>
                      <td data-bad={check.mismatched > 0 || undefined}>{check.mismatched}</td>
                      <td>{check.unverifiable}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Mismatches checks={inspection.checks} />
          </>
        ) : (
          <Note>{t('ux.detail.integrity.noInspection')}</Note>
        )}
      </section>
    </div>
  );
}

/**
 * 어긋난 줄 (the old original tab's checks, P-8): each line the official inspector found wrong, as it recorded it: the
 * check, the fact, the entry, the line, what it expected, what it found and why.
 */
function Mismatches({ checks }: { readonly checks: readonly InspectionCheck[] }) {
  const { t } = useTranslation();
  const rows = checks.flatMap((check) => check.mismatches.map((mismatch) => ({ check: check.code, mismatch })));
  if (rows.length === 0) {
    return null;
  }
  const cell = (value: string | number | null) => (value === null ? '—' : breakable(String(value)));
  return (
    <>
      <h3 className={styles.subTitle}>{t('ux.detail.integrity.mismatches')}</h3>
      <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
        <table className={styles.table}>
          <caption className="ux-sr-only">{t('ux.detail.integrity.mismatches')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('ux.detail.integrity.check')}</th>
              <th scope="col">{t('ux.detail.integrity.factId')}</th>
              <th scope="col">{t('ux.detail.integrity.entry')}</th>
              <th scope="col">{t('ux.detail.integrity.line')}</th>
              <th scope="col">{t('ux.detail.integrity.expected')}</th>
              <th scope="col">{t('ux.detail.integrity.actual')}</th>
              <th scope="col">{t('ux.detail.integrity.reason')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ check, mismatch }, index) => (
              <tr key={`${check}-${index}`}>
                <th scope="row">{t(`ux.detail.integrity.checks.${check}`, { defaultValue: check })}</th>
                <td className={styles.wrap}>{cell(mismatch.factId)}</td>
                <td className={styles.wrap}>{cell(mismatch.entry)}</td>
                <td>{cell(mismatch.line)}</td>
                <td className={styles.wrap}>{cell(mismatch.expected)}</td>
                <td className={styles.wrap}>{cell(mismatch.actual)}</td>
                <td className={styles.wrap}>{cell(mismatch.reason)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/** 기준선 학습: what the baseline held before and after the run, and what the engine stored from it. */
export function LearningTab({ anatomy }: TabProps) {
  const { t, i18n } = useTranslation();
  const figures = anatomy.figures;
  const added = anatomy.learning?.newBehaviourDocuments ?? [];
  const n = (value: number) => formatNumber(value, i18n.language);
  const before = figures.baselineBefore;
  const after = figures.baselineAfter;
  return (
    <section className={styles.card} aria-labelledby="detail-learning">
      <h2 id="detail-learning" className={styles.cardTitle}>
        {t('ux.detail.learning.title')}
      </h2>
      <p className={styles.cardSub}>{t('ux.detail.learning.sub')}</p>
      <p className={styles.learning}>
        {before !== null && after !== null ? (
          <>
            <b>{n(before)}</b> → <b>{n(after)}</b>{' '}
            <Badge tone={after > before ? 'allow' : 'none'}>
              {after > before ? t('ux.detail.learning.added', { n: n(after - before) }) : t('ux.detail.learning.none')}
            </Badge>
          </>
        ) : (
          t('ux.detail.learning.unknown')
        )}
      </p>
      {figures.workProfileObservations !== null ? (
        <p className={styles.muted}>
          {t('ux.detail.learning.profile', { n: n(figures.workProfileObservations), window: figures.workProfileWindow ?? '—' })}
        </p>
      ) : null}
      {added.length > 0 ? (
        <ul className={styles.documents}>
          {added.map((document, index) => (
            <li key={index}>
              <code className={styles.code}>{document.action ?? '—'}</code> {document.requestPath ?? ''}
              {document.timestamp ? <span className={styles.muted}> · {formatUtc(document.timestamp)}</span> : null}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
