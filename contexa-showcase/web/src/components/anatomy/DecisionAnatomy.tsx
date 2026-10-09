import { Fragment, useState } from 'react';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import {
  useAnatomy,
  useCases,
  useExchanges,
  type DecisionAnatomyView,
  type ExchangeCall,
  type UsualVsNow,
} from '../../api/anatomy';
import { useStepResult } from '../../api/lab';
import { downloadRunRecord } from '../../api/runRecord';
import { useRunScore } from '../../api/queries';
import { VerdictChip } from '../VerdictChip';
import type { Verdict } from '../../domain/verdict';
import styles from './DecisionAnatomy.module.css';

/*
 * The verdict anatomy of one request (docs/showcase/데모-재설계.md 3, the W3 draft as approved): what the engine
 * received, how the model read it, the ground truth, the problems, what the engine learned afterwards, the export of the
 * records and the raw text. Every value comes from the stored run through the visitor API; nothing here computes a
 * judgement of its own. Text the engine received is shown as it was sent (English), with its origin named.
 */
const SCORED_PROBLEMS = new Set(['MISSED', 'FALSE_BLOCK', 'UNRESOLVED']);
const KNOWN_VERDICTS = new Set(['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK']);

function verdictOf(action: string | null | undefined): Verdict {
  return action && KNOWN_VERDICTS.has(action) ? (action as Verdict) : 'NONE';
}

/** The anatomy of request {@code stepNo} of a run, loaded from the visitor API. */
export function DecisionAnatomy({ runId, stepNo }: { readonly runId: string; readonly stepNo: number }) {
  const { t, i18n } = useTranslation();
  const anatomy = useAnatomy(runId, stepNo);
  const score = useRunScore(runId, 'anatomy', 0);
  const cases = useCases();
  const language = i18n.language === 'ko' ? 'ko' : 'en';

  const caseKey = score.data?.scenarioKey ?? null;
  const caseView = cases.data?.cases.find((candidate) => candidate.key === caseKey) ?? null;

  if (anatomy.isError) {
    return <p role="alert">{t('anatomy.loadFailed')}</p>;
  }
  if (!anatomy.data) {
    return <p>{t('anatomy.loading')}</p>;
  }
  return (
    <Anatomy
      anatomy={anatomy.data}
      title={caseView?.title[language] ?? caseKey ?? ''}
      caseKey={caseKey}
      steps={score.data?.executedSteps ?? null}
      language={language}
    />
  );
}

interface AnatomyProps {
  readonly anatomy: DecisionAnatomyView;
  readonly title: string;
  readonly caseKey: string | null;
  readonly steps: number | null;
  readonly language: 'ko' | 'en';
}

function Anatomy({ anatomy, title, caseKey, steps, language }: AnatomyProps) {
  const { t } = useTranslation();
  const recorded = anatomy.interpretation.recorded;
  const result = anatomy.truth.verdict?.score.result ?? 'NO_DECISION';
  const request = anatomy.context.request ?? {};
  const analysed = recorded.finalAction !== null || anatomy.interpretation.calls.length > 0;
  // A request the engine did not analyse has no engine input; its company time is the stored step's ("HH:mm" of the
  // company clock, the same form the engine input uses).
  const stored = useStepResult(analysed ? null : anatomy.runId, anatomy.stepNo);
  const companyTime = request['requestTimestamp'] ?? stored.data?.companyTime.slice(11, 16) ?? '-';
  return (
    <article className={styles.anatomy} aria-labelledby="anatomy-title">
      <header className={styles.head}>
        <p className={styles.eyebrow}>
          {t('anatomy.eyebrow', { case: caseKey ?? '-', step: anatomy.stepNo, steps: steps ?? '-' })}
        </p>
        <h1 id="anatomy-title" className={styles.title}>
          {title}
        </h1>
        <p className={styles.requestLine}>
          <code>
            <Breakable text={request['requestPath'] ?? anatomy.operation} />
          </code>
          <span>{t('anatomy.companyTime', { time: companyTime })}</span>
        </p>
        <dl className={styles.verdictRow}>
          <div>
            <dt>{t('anatomy.head.truth')}</dt>
            <dd>
              <span className={styles.truthChip} data-classification={anatomy.truth.classification ?? 'NONE'}>
                {t(`anatomy.class.${anatomy.truth.classification ?? 'NONE'}`)}
              </span>
            </dd>
          </div>
          <div>
            <dt>{t('anatomy.head.verdict')}</dt>
            <dd>
              <VerdictChip
                verdict={verdictOf(recorded.finalAction)}
                unresolved={recorded.unresolved}
                showCode
              />
            </dd>
          </div>
          <div>
            <dt>{t('anatomy.head.score')}</dt>
            <dd>
              <span className={styles.scoreChip} data-result={result}>
                {t(`anatomy.result.${result}`)}
              </span>
            </dd>
          </div>
        </dl>
      </header>

      {analysed ? (
        <>
          <ReceivedSection anatomy={anatomy} />
          <InterpretationSection anatomy={anatomy} />
        </>
      ) : (
        <NotAnalysedSection anatomy={anatomy} />
      )}
      <TruthSection anatomy={anatomy} language={language} />
      {analysed && SCORED_PROBLEMS.has(result) ? <ProblemSection anatomy={anatomy} /> : null}
      <LearningSection anatomy={anatomy} />
      <ExportSection anatomy={anatomy} />
      {analysed ? <RawSection anatomy={anatomy} /> : null}
    </article>
  );
}

/**
 * A request the engine did not analyse: where its answer came from (an earlier decision, the permission check, or no
 * decision at all), and Contexa's stored answer to it, as recorded.
 */
function NotAnalysedSection({ anatomy }: { readonly anatomy: DecisionAnatomyView }) {
  const { t } = useTranslation();
  const stored = useStepResult(anatomy.runId, anatomy.stepNo);
  const contexa = stored.data?.layers.find((layer) => layer.control === 'D') ?? null;
  return (
    <section className={styles.section} aria-labelledby="not-analysed-title">
      <h2 id="not-analysed-title" className={styles.sectionTitle}>
        {/* In place of sections 1 (what the engine received) and 2 (how the model read it). */}
        <span className={styles.sectionNumber}>1–2</span>
        {t('anatomy.notAnalysed.title')}
      </h2>
      <p>{t(`anatomy.notAnalysed.${anatomy.truth.verdict?.source ?? 'NOT_ANALYSED'}`)}</p>
      {contexa ? (
        <p className={styles.mono}>
          {t('anatomy.notAnalysed.answer', {
            status: contexa.httpStatus ?? '-',
            rule: contexa.ruleId ?? '-',
          })}
        </p>
      ) : null}
      <p className={styles.source}>{t('anatomy.notAnalysed.source')}</p>
    </section>
  );
}

/** One row of the usual-versus-now table: the value of this request and what the engine was told about it. */
function dimensionValue(dimension: string, value: string | null, t: TFunction) {
  if (value === null || value === '') {
    return '-';
  }
  if (dimension === 'accessHour') {
    return t('anatomy.hourValue', { hour: value });
  }
  if (dimension === 'dayOfWeek') {
    return t(`anatomy.day.${value}`);
  }
  return value;
}

/** A value shown whole, with line breaks allowed only after its slashes, so a path never breaks inside a number. */
function Breakable({ text }: { readonly text: string }) {
  const parts = text.split('/');
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={`${index}-${part}`}>
          {part}
          {index < parts.length - 1 ? (
            <>
              /<wbr />
            </>
          ) : null}
        </Fragment>
      ))}
    </>
  );
}

function usualValues(anatomy: DecisionAnatomyView, row: UsualVsNow, t: TFunction) {
  const usual = anatomy.context.usual;
  if (row.dimension === 'accessHour' && usual?.normalAccessHours?.length) {
    return usual.normalAccessHours.map((hour) => t('anatomy.hourValue', { hour })).join(', ');
  }
  if (row.dimension === 'dayOfWeek' && usual?.normalAccessDays?.length) {
    return usual.normalAccessDays.map((day) => t(`anatomy.day.${day}`)).join(', ');
  }
  return null;
}

function ReceivedSection({ anatomy }: { readonly anatomy: DecisionAnatomyView }) {
  const { t } = useTranslation();
  const matrix = anatomy.context.labelMatrix;
  const company = anatomy.context.company;
  const unknown = Object.entries(matrix).filter(([, value]) => value.startsWith('UNKNOWN'));
  const missing = [
    ...(anatomy.context.coverage?.missingCriticalFacts ?? []),
    ...(anatomy.context.learning?.carryMissingFacts ?? []),
  ];
  const observations = /Observations (\d+)/.exec(anatomy.context.usual?.summary ?? '')?.[1] ?? null;
  const window = /Window (\w+)/.exec(anatomy.context.usual?.summary ?? '')?.[1] ?? null;
  return (
    <section className={styles.section} aria-labelledby="received-title">
      <h2 id="received-title" className={styles.sectionTitle}>
        <span className={styles.sectionNumber}>1</span>
        {t('anatomy.received.title')}
      </h2>
      <div className={styles.split}>
        <div className={styles.splitSide}>
          <div className={styles.tableWrap} tabIndex={0} role="region" aria-labelledby="usual-title">
            <table className={`${styles.table} ${styles.usualTable}`}>
              <caption id="usual-title" className={styles.caption}>
                {t('anatomy.received.usualVsNow')}
              </caption>
              <thead>
                <tr>
                  <th scope="col">{t('anatomy.received.dimension')}</th>
                  <th scope="col">{t('anatomy.received.now')}</th>
                  <th scope="col">{t('anatomy.received.inUsual')}</th>
                  <th scope="col">{t('anatomy.received.usualValues')}</th>
                </tr>
              </thead>
              <tbody>
                {anatomy.context.usualVsNow.map((row) => {
                  const values = usualValues(anatomy, row, t);
                  const state = row.inUsual === 'true' ? 'yes' : row.inUsual === 'false' ? 'no' : 'unknown';
                  return (
                    <tr key={row.dimension} data-state={state}>
                      <th scope="row" className={styles.cellName}>
                        {t(`anatomy.dim.${row.dimension}`)}
                      </th>
                      <td className={`${styles.mono} ${styles.cellNow}`}>
                        <Breakable text={dimensionValue(row.dimension, row.now, t)} />
                      </td>
                      <td className={styles.cellPresence}>
                        <span className={styles.presence} data-state={state}>
                          {t(`anatomy.presence.${state}`)}
                        </span>
                      </td>
                      <td
                        className={`${values ? styles.mono : styles.muted} ${styles.cellUsual}`}
                        data-label={t('anatomy.received.usualValues')}
                        data-empty={values ? undefined : true}
                      >
                        {values ?? '—'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p className={styles.source}>{t('anatomy.received.presenceNote')}</p>
          <p className={styles.source}>
            {t('anatomy.received.usualSource', {
              observations: observations ?? '-',
              window: window ?? '-',
              deltas: matrix['CurrentVsObservedDeltaCount'] ?? '-',
            })}
          </p>

          {matrix['ObservedComparableCombination1'] ? (
            <div className={styles.block}>
              <h3 className={styles.blockTitle}>{t('anatomy.received.closest')}</h3>
              <p className={styles.mono}>{matrix['ObservedComparableCombination1']}</p>
              <p className={styles.muted}>
                {t('anatomy.received.closestOverlap', {
                  overlap: matrix['CurrentRequestClosestObservedOverlap'] ?? '-',
                  seen: matrix['CurrentRequestCombinationSeenCount'] ?? '-',
                })}
              </p>
            </div>
          ) : null}
        </div>
        <div className={styles.splitSide}>
          <div className={styles.block}>
            <h3 className={styles.blockTitle}>{t('anatomy.received.company')}</h3>
            <ul className={styles.facts}>
              {(company?.approvalLineage ?? []).map((line) => (
                <li key={line} className={styles.fact}>
                  {line}
                </li>
              ))}
            </ul>
            <p className={styles.source}>{t('anatomy.received.companySource')}</p>
            <dl className={styles.labels}>
              <div>
                <dt>ApprovalRequired</dt>
                <dd>
                  {company?.approvalRequired == null
                    ? t('anatomy.notSent')
                    : String(company.approvalRequired)}
                </dd>
              </div>
              <div>
                <dt>ApprovalMissing</dt>
                <dd>
                  {company?.approvalMissing == null ? t('anatomy.notSent') : String(company.approvalMissing)}
                </dd>
              </div>
              <div>
                <dt>ApprovalStatus</dt>
                <dd>{company?.approvalStatus ?? t('anatomy.notSent')}</dd>
              </div>
              <div>
                <dt>ApprovalDecisionAgeMinutes</dt>
                <dd>{company?.approvalDecisionAgeMinutes ?? t('anatomy.notSent')}</dd>
              </div>
              <div>
                <dt>Sensitivity</dt>
                <dd>{anatomy.context.resource?.sensitivity ?? t('anatomy.notSent')}</dd>
              </div>
            </dl>
            <p className={styles.source}>{t('anatomy.received.notSentNote')}</p>
          </div>

          <div className={styles.block}>
            <h3 className={styles.blockTitle}>{t('anatomy.received.unknown')}</h3>
            {unknown.length === 0 && missing.length === 0 ? (
              <p className={styles.muted}>{t('anatomy.received.unknownNone')}</p>
            ) : (
              <ul className={styles.facts}>
                {missing.map((fact) => (
                  <li key={`missing-${fact}`} className={styles.fact}>
                    {fact}
                  </li>
                ))}
                {unknown.map(([label, value]) => (
                  <li key={label} className={styles.fact}>
                    <span className={styles.mono}>{label}</span>: {value}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className={styles.block}>
            <h3 className={styles.blockTitle}>{t('anatomy.received.rag')}</h3>
            <p>
              {t('anatomy.received.ragLine', {
                state: anatomy.context.rag?.ragRetrievalState ?? 'UNKNOWN',
                relevance: anatomy.context.rag?.ragRelevance ?? 'UNKNOWN',
                documents: anatomy.context.rag?.ragAuthorizedDocumentCount ?? 0,
              })}
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

function InterpretationSection({ anatomy }: { readonly anatomy: DecisionAnatomyView }) {
  const { t } = useTranslation();
  const { recorded, timings, calls } = anatomy.interpretation;
  const answer = calls[0]?.parsedAnswer ?? null;
  const evidenceRefs = Array.isArray(answer?.['evidenceRefs']) ? (answer?.['evidenceRefs'] as string[]) : [];
  const total = timings.totalAnalysisMs ?? timings.llmLatencyMs ?? null;
  const parts = [
    { key: 'promptBuild', ms: timings.promptBuildMs },
    { key: 'rag', ms: timings.ragVectorMs },
    { key: 'llm', ms: timings.llmLatencyMs },
  ];
  return (
    <section className={styles.section} aria-labelledby="interpretation-title">
      <h2 id="interpretation-title" className={styles.sectionTitle}>
        <span className={styles.sectionNumber}>2</span>
        {t('anatomy.interpretation.title')}
      </h2>
      <div className={styles.split}>
        <div className={styles.splitSide}>
          <dl className={styles.numbers}>
            <div>
              <dt>{t('anatomy.interpretation.proposed')}</dt>
              <dd>
                <VerdictChip verdict={verdictOf(recorded.proposedAction)} showCode />
              </dd>
            </div>
            <div>
              <dt>{t('anatomy.interpretation.final')}</dt>
              <dd>
                <VerdictChip
                  verdict={verdictOf(recorded.finalAction)}
                  unresolved={recorded.unresolved}
                  showCode
                />
              </dd>
            </div>
            <div>
              <dt>{t('anatomy.interpretation.risk')}</dt>
              <dd className={recorded.riskScore === null ? styles.muted : styles.number}>
                {recorded.riskScore === null
                  ? t('anatomy.interpretation.notGiven')
                  : recorded.riskScore.toFixed(2)}
              </dd>
            </div>
            <div>
              <dt>{t('anatomy.interpretation.confidence')}</dt>
              <dd className={recorded.confidence === null ? styles.muted : styles.number}>
                {recorded.confidence === null
                  ? t('anatomy.interpretation.notGiven')
                  : recorded.confidence.toFixed(2)}
              </dd>
            </div>
            <div>
              <dt>{t('anatomy.interpretation.mitre')}</dt>
              <dd className={recorded.mitre ? styles.mono : styles.muted}>
                {recorded.mitre ?? t('anatomy.interpretation.notGiven')}
              </dd>
            </div>
          </dl>
          {recorded.riskScore === null || recorded.confidence === null ? (
            <p className={styles.source}>{t('anatomy.interpretation.notGivenNote')}</p>
          ) : null}
          {recorded.unresolved || recorded.failureType ? (
            <p className={styles.failure} role="note">
              {t('anatomy.interpretation.failure', {
                type: recorded.failureType ?? '-',
                category: recorded.fallbackCategory ?? '-',
              })}
            </p>
          ) : null}
          <LayerTwo anatomy={anatomy} />

          <div className={styles.block}>
            <h3 className={styles.blockTitle}>{t('anatomy.interpretation.modelReasoning')}</h3>
            <blockquote className={styles.quote}>{anatomy.interpretation.modelReasoning ?? '-'}</blockquote>
            <h3 className={styles.blockTitle}>{t('anatomy.interpretation.recordedReasoning')}</h3>
            <p className={styles.muted}>
              {anatomy.interpretation.reasoningDiffers
                ? t('anatomy.interpretation.differs')
                : t('anatomy.interpretation.same')}
            </p>
            {anatomy.interpretation.reasoningDiffers ? (
              <blockquote className={styles.quote}>{recorded.reasoning ?? '-'}</blockquote>
            ) : null}
            {anatomy.interpretation.contractLines.length > 0 ? (
              <div className={styles.contract}>
                <p className={styles.contractLead}>{t('anatomy.interpretation.contract')}</p>
                {anatomy.interpretation.contractLines.map((line) => (
                  <p key={line} className={styles.mono}>
                    {line}
                  </p>
                ))}
              </div>
            ) : null}
            <p>
              {t('anatomy.interpretation.evidenceRefs')}{' '}
              {evidenceRefs.length === 0
                ? t('anatomy.interpretation.notGiven')
                : evidenceRefs.map((ref) => (
                    <code key={ref} className={styles.tag}>
                      {ref}
                    </code>
                  ))}
            </p>
          </div>
        </div>
        <div className={styles.splitSide}>
          <div className={styles.block}>
            <h3 className={styles.blockTitle}>{t('anatomy.interpretation.timing')}</h3>
            {total ? (
              <div
                className={styles.timingBar}
                role="img"
                aria-label={t('anatomy.interpretation.timingAria', { total })}
              >
                {parts.map((part) =>
                  part.ms ? (
                    <span
                      key={part.key}
                      className={styles.timingPart}
                      data-part={part.key}
                      style={{ inlineSize: `${Math.max(2, (part.ms / total) * 100)}%` }}
                    />
                  ) : null,
                )}
              </div>
            ) : null}
            <dl className={styles.labels}>
              {parts.map((part) => (
                <div key={part.key}>
                  <dt>
                    <span className={styles.swatch} data-part={part.key} aria-hidden="true" />
                    {t(`anatomy.interpretation.part.${part.key}`)}
                  </dt>
                  <dd className={styles.number}>
                    {part.ms === null ? '-' : t('anatomy.ms', { ms: part.ms })}
                  </dd>
                </div>
              ))}
              <div>
                <dt>{t('anatomy.interpretation.part.total')}</dt>
                <dd className={styles.number}>{total === null ? '-' : t('anatomy.ms', { ms: total })}</dd>
              </div>
            </dl>
            <ol className={styles.timeline} data-testid="anatomy-timeline">
              {anatomy.interpretation.timeline.map((entry, index) => (
                <li key={`${entry.kind}-${entry.name}-${index}`}>
                  <span className={styles.number}>
                    {t('anatomy.plusMs', {
                      ms: elapsedSince(anatomy.interpretation.timeline[0]?.at, entry.at),
                    })}
                  </span>
                  <span className={styles.mono}>{entry.name}</span>
                  {entry.detail ? <span className={styles.muted}>{entry.detail}</span> : null}
                </li>
              ))}
            </ol>
            <h3 id="calls-title" className={styles.blockTitle}>
              {t('anatomy.interpretation.calls')}
            </h3>
            <ol className={styles.calls} aria-labelledby="calls-title">
              {calls.map((call) => (
                <li key={call.callNo} className={styles.call}>
                  <span className={styles.callNo}>#{call.callNo}</span>
                  <dl className={styles.callFacts}>
                    <div>
                      <dt>{t('anatomy.interpretation.model')}</dt>
                      <dd className={styles.mono}>{call.model ?? '-'}</dd>
                    </div>
                    <div>
                      <dt>{t('anatomy.interpretation.effort')}</dt>
                      <dd className={styles.mono}>
                        {String(call.requestOptions?.['reasoning_effort'] ?? '-')}
                      </dd>
                    </div>
                    <div>
                      <dt>{t('anatomy.interpretation.tokens')}</dt>
                      <dd className={styles.number}>
                        {t('anatomy.interpretation.tokenLine', {
                          prompt: call.promptTokens ?? '-',
                          completion: call.completionTokens ?? '-',
                          reasoning: call.reasoningTokens ?? '-',
                        })}
                      </dd>
                    </div>
                    <div>
                      <dt>{t('anatomy.interpretation.elapsed')}</dt>
                      <dd className={styles.number}>
                        {call.elapsedMs === null ? '-' : t('anatomy.ms', { ms: call.elapsedMs })}
                      </dd>
                    </div>
                    <div>
                      <dt>{t('anatomy.interpretation.finish')}</dt>
                      <dd className={styles.mono}>{call.success ? call.finishReason : call.failure}</dd>
                    </div>
                  </dl>
                </li>
              ))}
            </ol>
          </div>
        </div>
      </div>
    </section>
  );
}

function elapsedSince(first: string | undefined, at: string): number {
  if (!first) {
    return 0;
  }
  return Math.max(0, Math.round(Date.parse(at) - Date.parse(first)));
}

/** The second-layer analysis when the engine escalated to it: its verdict and its own reasoning, as the event says. */
function LayerTwo({ anatomy }: { readonly anatomy: DecisionAnatomyView }) {
  const { t } = useTranslation();
  const second = anatomy.interpretation.timings.events.find((event) => event.type === 'LAYER2_COMPLETE');
  if (!second) {
    return <p className={styles.source}>{t('anatomy.interpretation.layerOneOnly')}</p>;
  }
  return (
    <div className={styles.contract}>
      <p className={styles.contractLead}>
        {t('anatomy.interpretation.layerTwo', {
          action: second.action ?? '-',
          risk: second.riskScore ?? '-',
          confidence: second.confidence ?? '-',
        })}
      </p>
      <p>{second.reasoning ?? '-'}</p>
    </div>
  );
}

/**
 * What the engine learned after deciding: the behaviour records the run left (read when the run ended). A request it
 * allowed becomes part of the usual pattern the next request is compared with (approval Q-47).
 */
function LearningSection({ anatomy }: { readonly anatomy: DecisionAnatomyView }) {
  const { t } = useTranslation();
  const learning = anatomy.learning;
  if (!learning?.atRunEnd || !learning.template) {
    return null;
  }
  const path = anatomy.context.request?.['requestPath'] ?? null;
  const before = learning.template['baselineUpdateCount'] ?? 0;
  const after = learning.atRunEnd['baselineUpdateCount'] ?? 0;
  const thisRequest = learning.newBehaviourDocuments.filter((document) => document.requestPath === path);
  return (
    <section className={styles.section} aria-labelledby="learning-title">
      <h2 id="learning-title" className={styles.sectionTitle}>
        <span className={styles.sectionNumber}>5</span>
        {t('anatomy.learning.title')}
      </h2>
      <p>{t('anatomy.learning.counts', { before, after, added: after - before })}</p>
      <p>
        {t('anatomy.learning.documents', {
          before: learning.template['behaviourDocuments'] ?? 0,
          after: learning.atRunEnd['behaviourDocuments'] ?? 0,
        })}
      </p>
      {thisRequest.length > 0 ? (
        <ul className={styles.facts}>
          {thisRequest.map((document, index) => (
            <li key={`${document.timestamp}-${index}`} className={styles.fact}>
              {t('anatomy.learning.thisRequest', {
                action: document.action ?? '-',
                time: document.timestamp ?? '-',
                browser: document.userAgentBrowser ?? '-',
                os: document.userAgentOS ?? '-',
              })}
            </li>
          ))}
        </ul>
      ) : (
        <p className={styles.muted}>{t('anatomy.learning.notThisRequest')}</p>
      )}
      <p className={styles.source}>{t('anatomy.learning.source')}</p>
    </section>
  );
}

function TruthSection({
  anatomy,
  language,
}: {
  readonly anatomy: DecisionAnatomyView;
  readonly language: 'ko' | 'en';
}) {
  const { t } = useTranslation();
  const truth = anatomy.truth;
  const result = truth.verdict?.score.result ?? 'NO_DECISION';
  return (
    <section className={styles.section} aria-labelledby="truth-title">
      <h2 id="truth-title" className={styles.sectionTitle}>
        <span className={styles.sectionNumber}>3</span>
        {t('anatomy.truth.title')}
      </h2>
      <dl className={styles.numbers}>
        <div>
          <dt>{t('anatomy.truth.classification')}</dt>
          <dd>{t(`anatomy.class.${truth.classification ?? 'NONE'}`)}</dd>
        </div>
        <div>
          <dt>{t('anatomy.truth.allowed')}</dt>
          <dd className={styles.mono}>{truth.allowedEngineActions.join(' · ') || '-'}</dd>
        </div>
        <div>
          <dt>{t('anatomy.truth.verdictResult')}</dt>
          <dd>
            <span className={styles.scoreChip} data-result={result}>
              {t(`anatomy.result.${result}`)}
            </span>
          </dd>
        </div>
        <div>
          <dt>{t('anatomy.truth.business')}</dt>
          <dd>
            {truth.business
              ? t(`score.result.${truth.business.result}`, {
                  n: truth.business.exposedItems,
                  count: truth.business.exposedItems,
                })
              : '-'}
          </dd>
        </div>
      </dl>
      <h3 className={styles.blockTitle}>{t('anatomy.truth.rationale')}</h3>
      <p className={truth.rationale ? undefined : styles.muted}>
        {truth.rationale?.[language] ?? t('anatomy.truth.noRationale')}
      </p>
      {truth.counterpoint?.[language] ? (
        <>
          <h3 className={styles.blockTitle}>{t('anatomy.truth.counterpoint')}</h3>
          <p>{truth.counterpoint[language]}</p>
        </>
      ) : null}
      <p className={styles.source}>
        {t('anatomy.truth.source', {
          source: t(`anatomy.truthSource.${truth.truthSource ?? 'NONE'}`),
          sha: truth.scenarioSha256?.slice(0, 12) ?? '-',
        })}
      </p>
    </section>
  );
}

function ProblemSection({ anatomy }: { readonly anatomy: DecisionAnatomyView }) {
  const { t } = useTranslation();
  const juxtaposition = anatomy.juxtaposition;
  const met = juxtaposition.coreAdverseLabels.filter((label) => label.met);
  return (
    <section className={styles.section} aria-labelledby="problem-title">
      <h2 id="problem-title" className={styles.sectionTitle}>
        <span className={styles.sectionNumber}>4</span>
        {t('anatomy.problem.title')}
      </h2>
      <p className={styles.muted}>{t('anatomy.problem.lead')}</p>
      <div className={styles.versus}>
        <div className={styles.versusSide}>
          <h3 className={styles.blockTitle}>{t('anatomy.problem.signals')}</h3>
          <ul className={styles.facts}>
            {juxtaposition.departures.map((row) => (
              <li key={row.dimension} className={styles.signal}>
                {t('anatomy.problem.departure', {
                  dimension: t(`anatomy.dim.${row.dimension}`),
                  value: dimensionValue(row.dimension, row.now, t),
                })}
              </li>
            ))}
            {juxtaposition.sensitivity ? (
              <li className={styles.signal}>
                {t('anatomy.problem.sensitivity', { value: juxtaposition.sensitivity })}
              </li>
            ) : null}
            {met.map((label) => (
              <li key={label.label} className={styles.signal}>
                <span className={styles.mono}>{label.label}</span> {label.condition}:{' '}
                {label.values.join(', ')}
              </li>
            ))}
          </ul>
          <p className={styles.source}>
            {t('anatomy.problem.signalSource', {
              checked: juxtaposition.coreAdverseLabels.length,
              met: met.length,
            })}
          </p>
        </div>
        <div className={styles.versusSide}>
          <h3 className={styles.blockTitle}>{t('anatomy.problem.reasoning')}</h3>
          <blockquote className={styles.quote}>{juxtaposition.modelReasoning ?? '-'}</blockquote>
        </div>
      </div>
    </section>
  );
}

/** A prompt split into its sections ("=== NAME ==="), so a reader opens only the part they need. */
function sections(text: string | null): { readonly name: string; readonly body: string }[] {
  if (!text) {
    return [];
  }
  const result: { name: string; lines: string[] }[] = [{ name: '', lines: [] }];
  for (const line of text.split('\n')) {
    const header = /^=== (.+) ===$/.exec(line.trim());
    if (header?.[1]) {
      result.push({ name: header[1], lines: [] });
    } else {
      result[result.length - 1]?.lines.push(line);
    }
  }
  return result
    .map((section) => ({ name: section.name, body: section.lines.join('\n').trim() }))
    .filter((section) => section.body.length > 0);
}

/** The stored records of this step as one JSON file, with the SHA-256 of the file (the OSS report idea). */
function ExportSection({ anatomy }: { readonly anatomy: DecisionAnatomyView }) {
  const { t } = useTranslation();
  const [hash, setHash] = useState<string | null>(null);
  const exportRecords = async () => {
    setHash(await downloadRunRecord(anatomy.runId, anatomy.stepNo, anatomy));
  };
  return (
    <section className={styles.section} aria-labelledby="export-title">
      <h2 id="export-title" className={styles.sectionTitleInline}>
        {t('anatomy.export.title')}
      </h2>
      <p className={styles.source}>{t('anatomy.export.lead')}</p>
      <button type="button" className={styles.exportButton} onClick={() => void exportRecords()}>
        {t('anatomy.export.button')}
      </button>
      {hash ? <p className={styles.mono}>{t('anatomy.export.hash', { hash })}</p> : null}
    </section>
  );
}

function RawSection({ anatomy }: { readonly anatomy: DecisionAnatomyView }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const exchanges = useExchanges(anatomy.runId, anatomy.stepNo, open);
  return (
    <section className={styles.section} aria-labelledby="raw-title">
      <details
        className={styles.raw}
        onToggle={(event) => setOpen((event.currentTarget as HTMLDetailsElement).open)}
      >
        <summary className={styles.rawSummary}>
          <h2 id="raw-title" className={styles.sectionTitleInline}>
            {t('anatomy.raw.title')}
          </h2>
        </summary>
        {exchanges.isLoading ? <p>{t('anatomy.loading')}</p> : null}
        {exchanges.data && !exchanges.data.kept ? (
          <p className={styles.muted}>
            {t(
              exchanges.data.missing === 'PAST_RETENTION'
                ? 'anatomy.raw.expired'
                : 'anatomy.raw.notCollected',
            )}
          </p>
        ) : null}
        {exchanges.data?.calls.map((call) => (
          <RawCall key={call.callNo} call={call} />
        ))}
      </details>
    </section>
  );
}

function RawCall({ call }: { readonly call: ExchangeCall }) {
  const { t } = useTranslation();
  return (
    <div className={styles.rawCall}>
      <p className={styles.source}>
        {t('anatomy.raw.callLine', { n: call.callNo, model: call.model ?? '-', masked: call.maskedPlaces })}
      </p>
      {(['system', 'user'] as const).map((kind) => (
        <details key={kind} className={styles.rawGroup}>
          <summary>{t(`anatomy.raw.${kind}`)}</summary>
          {sections(kind === 'system' ? call.systemPrompt : call.userPrompt).map((section, index) => (
            <details key={`${kind}-${section.name}-${index}`} className={styles.rawPart}>
              <summary className={styles.mono}>{section.name || t('anatomy.raw.preamble')}</summary>
              <pre className={styles.pre} tabIndex={0}>
                {section.body}
              </pre>
            </details>
          ))}
        </details>
      ))}
      <details className={styles.rawGroup}>
        <summary>{t('anatomy.raw.answer')}</summary>
        <pre className={styles.pre} tabIndex={0}>
          {call.answer ?? '-'}
        </pre>
      </details>
      <details className={styles.rawGroup}>
        <summary>{t('anatomy.raw.provider')}</summary>
        <pre className={styles.pre} tabIndex={0}>
          {call.providerResponse ?? '-'}
        </pre>
      </details>
    </div>
  );
}
