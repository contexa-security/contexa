import { useRef, useState, type KeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import {
  useAnatomy,
  useExchanges,
  useReceived,
  type DecisionAnatomyView,
  type ExchangesView,
} from '../../api/anatomy';
import { useStepResult } from '../../api/lab';
import { useRunScore } from '../../api/queries';
import { downloadRunRecord } from '../../api/runRecord';
import type { StepResult } from '../../api/types';
import { VERDICTS, type Verdict } from '../../domain/verdict';
import { count, seconds } from '../../journey/format';
import { SourceMark } from '../common/SourceMark';
import { verdictKey } from '../../pages/try/steps/liveRun';
import shared from '../../pages/try/Experience.module.css';
import { ActionChip } from '../common/ActionChip';
import { Modal } from '../common/Modal';
import { Icon } from '../Icon';
import { Comparison } from '../inside/Comparison';
import { PromptBundles } from '../inside/PromptBundles';
import { StateScreen } from '../StateScreen';
import { VerdictChip } from '../VerdictChip';
import { DETAIL_TABS, useDetail, type DetailTab } from './useDetail';
import styles from './DecisionDetail.module.css';

type T = ReturnType<typeof useTranslation>['t'];

function verdictOf(action: string | null | undefined): Verdict {
  return action && action in VERDICTS ? (action as Verdict) : 'NONE';
}

/** A recorded score with two decimals, or "no value" when the model gave none. */
function scoreText(t: T, value: number | null): string {
  return value === null ? t('e1.reason.noValue') : value.toFixed(2);
}

/**
 * The decision details (anat-1, anat-2, 7.7): one window over the screen it was opened from, with its own address, the
 * case's name and the request in its title, and six tabs. Mounted once for every screen; any screen opens it with
 * useDetail().show(runId, step).
 */
export function DecisionDetailModal() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const score = useRunScore(detail.runId, 'detail', 1).data ?? null;
  const steps = score ? Math.max(1, score.executedSteps) : null;
  const title = score
    ? t('detail.title', {
        case: score.title?.[language] ?? t('detail.unnamed'),
        step: detail.step,
        steps,
      })
    : t('detail.titleLoading');
  return (
    <Modal open={detail.open} onClose={detail.hide} title={title} wide>
      {detail.runId ? (
        <DecisionDetail runId={detail.runId} step={detail.step} steps={steps ?? 1} tab={detail.tab} />
      ) : null}
    </Modal>
  );
}

interface DecisionDetailProps {
  readonly runId: string;
  readonly step: number;
  readonly steps: number;
  readonly tab: DetailTab;
}

function DecisionDetail({ runId, step, steps, tab }: DecisionDetailProps) {
  const { t } = useTranslation();
  const detail = useDetail();
  const anatomy = useAnatomy(runId, step);
  const view = anatomy.data ?? null;
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  // The arrow keys move between the tabs and select the one they reach (the ARIA tabs pattern).
  const onKey = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const last = DETAIL_TABS.length - 1;
    const next =
      event.key === 'ArrowRight'
        ? (index + 1) % DETAIL_TABS.length
        : event.key === 'ArrowLeft'
          ? (index + last) % DETAIL_TABS.length
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? last
              : null;
    if (next === null) {
      return;
    }
    event.preventDefault();
    detail.setTab(DETAIL_TABS[next] ?? 'summary');
    tabs.current[next]?.focus();
  };
  return (
    <div className={styles.detail}>
      <div>
        <SourceMark kind="ENGINE" runId={runId} step={step} record={{ runId, step }} />
      </div>
      {steps > 1 ? (
        <div className={styles.requests} role="group" aria-label={t('detail.requests')}>
          <ActionChip
            icon="arrowLeft"
            size="sm"
            disabled={step <= 1}
            onClick={() => detail.setStep(step - 1)}
          >
            {t('detail.previous')}
          </ActionChip>
          <span className={styles.requestNow}>{t('detail.request', { step, steps })}</span>
          <ActionChip
            icon="arrowRight"
            size="sm"
            disabled={step >= steps}
            onClick={() => detail.setStep(step + 1)}
          >
            {t('detail.next')}
          </ActionChip>
        </div>
      ) : null}
      <div className={styles.tabs} role="tablist" aria-label={t('detail.tabs')}>
        {DETAIL_TABS.map((name, index) => (
          <button
            key={name}
            ref={(element) => {
              tabs.current[index] = element;
            }}
            type="button"
            role="tab"
            id={`detail-tab-${name}`}
            aria-selected={tab === name}
            aria-controls="detail-panel"
            tabIndex={tab === name ? 0 : -1}
            className={styles.tab}
            onClick={() => detail.setTab(name)}
            onKeyDown={(event) => onKey(event, index)}
          >
            {t(`detail.tab.${name}`)}
          </button>
        ))}
      </div>
      <section
        id="detail-panel"
        role="tabpanel"
        aria-labelledby={`detail-tab-${tab}`}
        className={styles.panel}
      >
        {anatomy.isPending ? <StateScreen kind="loading" /> : null}
        {anatomy.isError ? <p className={shared.lead}>{t('detail.notFound')}</p> : null}
        {view ? <TabBody tab={tab} view={view} runId={runId} step={step} /> : null}
      </section>
    </div>
  );
}

interface TabProps {
  readonly view: DecisionAnatomyView;
  readonly runId: string;
  readonly step: number;
}

function TabBody({ tab, ...props }: TabProps & { readonly tab: DetailTab }) {
  switch (tab) {
    case 'received':
      return <Received {...props} />;
    case 'process':
      return <Process {...props} />;
    case 'prompt':
      return <Prompt {...props} />;
    case 'answer':
      return <Answer {...props} />;
    case 'original':
      return <Original {...props} />;
    default:
      return <Summary {...props} />;
  }
}

/** Whether the engine analysed the request: a decision of its own, not an earlier one or the permission check's. */
function analysed(view: DecisionAnatomyView): boolean {
  return view.interpretation.recorded.finalAction !== null;
}

/**
 * The summary (anat-1): what the decision was and whether it was right. The facts it rests on lead to the verdict in
 * the same figure the tries' reasons show; when, what went out and what was learned follow; the reason is the engine's
 * own sentence in plain words, its original behind the mark.
 */
function Summary({ view, runId, step }: TabProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const result: StepResult | null = useStepResult(runId, step).data ?? null;
  const contexa = result?.layers.find((layer) => layer.control === 'D') ?? null;
  const recorded = view.interpretation.recorded;
  const verdict = view.truth.verdict;
  if (!analysed(view)) {
    return (
      <div className={styles.block}>
        <p className={shared.callout}>
          {t(`anatomy.notAnalysed.${verdict?.source ?? 'NOT_ANALYSED'}`, {
            defaultValue: t('anatomy.notAnalysed.NOT_ANALYSED'),
          })}
        </p>
        {contexa ? (
          <p className={shared.lead}>
            {t('detail.refused')}{' '}
            <code className={styles.code} data-original>
              {contexa.httpStatus ?? '-'} · {contexa.ruleId ?? '-'}
            </code>
          </p>
        ) : null}
      </div>
    );
  }
  const company = view.context.company;
  const facts = [
    t('e1.reason.differs', { n: view.figures.departureCount ?? '-' }),
    ...(view.juxtaposition.sensitivity
      ? [
          t('e1.reason.sensitivity', {
            level: t(`dim.sensitivity.${view.juxtaposition.sensitivity}`, {
              defaultValue: view.juxtaposition.sensitivity,
            }),
          }),
        ]
      : []),
    ...(company?.approvalRequired
      ? [t(company.approvalMissing ? 'e1.reason.noApproval' : 'e1.reason.approval')]
      : []),
  ];
  const right = verdict?.score.result ?? 'NOT_SCORED';
  const applied = verdict?.score.applied ?? recorded.applied;
  const check = view.recovery?.challenge ?? null;
  const original = recorded.reasoning;
  return (
    <div className={styles.block}>
      <div className={shared.reasonFigure} aria-label={t('e1.reason.figure')}>
        <ul className={shared.reasonFacts}>
          {facts.map((fact) => (
            <li key={fact} className={shared.reasonFact}>
              {fact}
            </li>
          ))}
        </ul>
        <Icon name="arrowRight" className={shared.reasonArrow} />
        <VerdictChip verdict={verdictOf(recorded.finalAction)} unresolved={recorded.unresolved} size="lg" />
      </div>
      <p className={styles.verdictLine}>
        <span className={styles.label}>{t('detail.against')}</span>
        <span className={styles.rightMark} data-result={right}>
          {t(`anatomy.result.${right}`, { defaultValue: right })}
        </span>
        <span className={styles.allowed}>
          {t('e1.result.answerShort', {
            actions: view.truth.allowedEngineActions.map((action) => t(verdictKey(action))).join(', ') || '-',
          })}
        </span>
      </p>
      <dl className={styles.figures}>
        <div>
          <dt>{t('detail.when')}</dt>
          <dd>
            {applied && applied !== 'NONE' ? t(`timing.applied.${applied}`, { defaultValue: applied }) : '-'}
            {view.interpretation.timings.totalAnalysisMs !== null
              ? ` · ${t('detail.seconds', { s: seconds(view.interpretation.timings.totalAnalysisMs) })}`
              : ''}
          </dd>
        </div>
        <div>
          <dt>{t('detail.out')}</dt>
          <dd>
            {contexa
              ? t('e1.result.items', { items: count(contexa.evidence.deliveredItems, language) })
              : '-'}
          </dd>
        </div>
        <div>
          <dt>{t('detail.learned')}</dt>
          <dd>
            {view.figures.baselineBefore !== null && view.figures.baselineAfter !== null
              ? t('detail.learnedValue', {
                  before: count(view.figures.baselineBefore, language),
                  after: count(view.figures.baselineAfter, language),
                })
              : '-'}
            {view.figures.documentsBefore !== null && view.figures.documentsAfter !== null ? (
              <span className={styles.subValue}>
                {t('detail.documents', {
                  before: count(view.figures.documentsBefore, language),
                  after: count(view.figures.documentsAfter, language),
                  n: count(view.figures.documentsForThisRequest, language),
                })}
              </span>
            ) : null}
          </dd>
        </div>
      </dl>
      <figure className={shared.quote}>
        <figcaption className={shared.quoteLabel}>{t('e1.reason.wrote')}</figcaption>
        <blockquote className={shared.quoteText}>
          {recorded.reasoningCode
            ? t(`reason.canonical.${recorded.reasoningCode}`, { defaultValue: original ?? '' })
            : t('e1.reason.free')}
        </blockquote>
        {recorded.reasoningCode ? <p className={shared.quoteNote}>{t('e1.reason.canonical')}</p> : null}
        {original ? (
          <details className={shared.more}>
            <summary>{t('source.original')}</summary>
            <p className={shared.original}>{original}</p>
          </details>
        ) : null}
      </figure>
      <p className={styles.note}>
        {recorded.riskScore === null && recorded.confidence === null
          ? t('e1.reason.riskNone')
          : t('e1.reason.risk', {
              risk: scoreText(t, recorded.riskScore),
              confidence: scoreText(t, recorded.confidence),
            })}
      </p>
      {check ? (
        <p className={styles.note}>
          {t('detail.followUp', {
            result: t(`e1.after.reason.${check.reason ?? 'other'}`, {
              defaultValue: t('e1.after.reason.other'),
            }),
          })}
        </p>
      ) : null}
      {recorded.unresolved || recorded.failureType ? (
        <p className={styles.warning} role="note">
          {t('detail.failure')}{' '}
          <code className={styles.code} data-original>
            {recorded.failureType ?? '-'} · {recorded.fallbackCategory ?? '-'}
          </code>
        </p>
      ) : null}
    </div>
  );
}

/**
 * What the engine received (anat-2): the same comparison the tries show before sending, read from this request's own
 * record, then how many company record lines and past records it received, their originals folded.
 */
function Received({ view, runId, step }: TabProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const received = useReceived(analysed(view) ? runId : null, step);
  if (!analysed(view)) {
    return <p className={shared.lead}>{t('detail.received.notAnalysed')}</p>;
  }
  if (received.isPending) {
    return <StateScreen kind="loading" />;
  }
  const comparison = received.data ?? null;
  const facts = view.juxtaposition.companyFacts;
  const documents = view.context.rag?.ragAuthorizedDocumentCount ?? null;
  const closest = view.context.labelMatrix['ObservedComparableCombination1'] ?? null;
  return (
    <div className={styles.block}>
      {comparison ? (
        <Comparison comparison={comparison} level="h3" />
      ) : (
        <p className={shared.lead}>{t('detail.received.none')}</p>
      )}
      <p className={shared.lead}>
        {t('detail.received.records', {
          lines: count(facts.length, language),
          documents: documents === null ? '-' : count(documents, language),
        })}
      </p>
      <div className={styles.folds}>
        {facts.length > 0 ? (
          <details className={shared.more}>
            <summary>{t('detail.received.company')}</summary>
            <ul className={styles.originalLines}>
              {facts.map((line) => (
                <li key={line} data-original>
                  {line}
                </li>
              ))}
            </ul>
          </details>
        ) : null}
        {closest ? (
          <details className={shared.more}>
            <summary>{t('detail.received.closest')}</summary>
            <p className={styles.originalLines} data-original>
              {closest}
            </p>
          </details>
        ) : null}
      </div>
    </div>
  );
}

/**
 * How the decision came about (anat-2): the engine's steps and the model calls with the time each came after the
 * first, what the model proposed against what was applied, whether a second analysis ran, and each call's model,
 * tokens and time.
 */
function Process({ view }: TabProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const interpretation = view.interpretation;
  const recorded = interpretation.recorded;
  if (!analysed(view)) {
    return <p className={shared.lead}>{t('detail.received.notAnalysed')}</p>;
  }
  const second = interpretation.timings.events.find((event) => event.type === 'LAYER2_COMPLETE') ?? null;
  const cited = recorded.evidenceRefs ?? [];
  const timings = interpretation.timings;
  return (
    <div className={styles.block}>
      <section className={styles.part} aria-labelledby="detail-stages">
        <h3 id="detail-stages" className={shared.panelTitle}>
          {t('detail.process.stages')}
        </h3>
        <ol className={styles.stages}>
          {interpretation.timeline.map((entry, index) => (
            <li key={`${entry.kind}-${entry.name}-${index}`} className={styles.stage}>
              <span className={styles.stageTime}>
                {t('detail.after', { s: seconds(interpretation.sinceStartMs[index] ?? 0) })}
              </span>
              <span>
                {entry.kind === 'EVENT'
                  ? t(`show.analysis.stage.${entry.name}`, { defaultValue: entry.name })
                  : t(
                      // The call's number names it only when there is more than one.
                      `detail.process.${entry.kind === 'CALL_SENT' ? 'callSent' : 'callAnswered'}${
                        interpretation.calls.length > 1 ? 'Numbered' : ''
                      }`,
                      { n: entry.callNo ?? '-' },
                    )}
              </span>
            </li>
          ))}
        </ol>
        <p className={styles.note}>
          {t('detail.process.parts', {
            build:
              timings.promptBuildMs === null
                ? '-'
                : t('detail.seconds', { s: seconds(timings.promptBuildMs) }),
            rag:
              timings.ragVectorMs === null ? '-' : t('detail.seconds', { s: seconds(timings.ragVectorMs) }),
            model:
              timings.llmLatencyMs === null ? '-' : t('detail.seconds', { s: seconds(timings.llmLatencyMs) }),
          })}
        </p>
      </section>
      <section className={styles.part} aria-labelledby="detail-judged">
        <h3 id="detail-judged" className={shared.panelTitle}>
          {t('detail.process.judged')}
        </h3>
        <dl className={styles.figures}>
          <div>
            <dt>{t('detail.process.proposed')}</dt>
            <dd className={styles.chips}>
              <VerdictChip verdict={verdictOf(recorded.proposedAction)} />
              <Icon name="arrowRight" className={shared.diffArrow} />
              <VerdictChip verdict={verdictOf(recorded.finalAction)} unresolved={recorded.unresolved} />
            </dd>
          </div>
          <div>
            <dt>{t('detail.process.layers')}</dt>
            <dd>
              {second
                ? t('detail.process.second', { action: t(verdictKey(second.action ?? 'NONE')) })
                : t('detail.process.firstOnly')}
            </dd>
          </div>
          <div>
            <dt>{t('detail.process.mitre')}</dt>
            <dd>
              {recorded.mitre ? (
                <code className={styles.code} data-original>
                  {recorded.mitre}
                </code>
              ) : (
                t('e1.reason.noValue')
              )}
            </dd>
          </div>
        </dl>
        <p className={styles.note}>
          {cited.length > 0
            ? t('e1.reason.citedLine', {
                refs: cited.map((ref) => t(`evidenceRef.${ref}`, { defaultValue: ref })).join(' · '),
              })
            : t('detail.process.noCited')}
        </p>
        <p className={styles.note}>
          {t('e1.reason.inspector', {
            total: view.juxtaposition.adverseChecked,
            met: view.juxtaposition.adverseMet,
            names: '',
          })}
        </p>
        {second?.reasoning ? (
          <details className={shared.more}>
            <summary>{t('detail.process.secondReason')}</summary>
            <p className={shared.original}>{second.reasoning}</p>
          </details>
        ) : null}
      </section>
      {/* Each call's model, tokens and time back the steps above; they are one press away (C-3). */}
      <details className={shared.more}>
        <summary>{t('detail.process.calls', { n: interpretation.calls.length })}</summary>
        <ol className={styles.calls}>
          {interpretation.calls.map((call) => (
            <li key={call.callNo} className={styles.call}>
              <code className={styles.code} data-original>
                {call.model ?? '-'}
              </code>
              <span>
                {t('detail.process.tokens', {
                  input: count(call.promptTokens ?? 0, language),
                  output: count(call.completionTokens ?? 0, language),
                  reasoning: count(call.reasoningTokens ?? 0, language),
                })}
              </span>
              <span>
                {call.elapsedMs === null ? '-' : t('detail.seconds', { s: seconds(call.elapsedMs) })}
              </span>
              {call.success ? null : (
                <code className={styles.code} data-original>
                  {call.failure ?? '-'}
                </code>
              )}
            </li>
          ))}
        </ol>
      </details>
    </div>
  );
}

/** The prompt (anat-2): the same seven bundles as the tries' "inside the prompt", read from this request's record. */
function Prompt({ view, runId, step }: TabProps) {
  const { t } = useTranslation();
  const exchanges = useExchanges(runId, step, true);
  const data: ExchangesView | null = exchanges.data ?? null;
  const call = data?.calls[0] ?? null;
  if (exchanges.isPending) {
    return <StateScreen kind="loading" />;
  }
  if (!data?.kept || !view.promptLines || !call) {
    return <p className={shared.lead}>{t(missingKey(data))}</p>;
  }
  return <PromptBundles lines={view.promptLines} call={call} />;
}

function missingKey(data: ExchangesView | null): string {
  return data?.missing === 'PAST_RETENTION' ? 'source.retired' : 'detail.original.notKept';
}

/** The right answer (anat-2): the answer and where it comes from, the responses that count as right, and why. */
function Answer({ view }: TabProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const truth = view.truth;
  const answer =
    truth.classification === 'THREAT' ? 'stop' : truth.classification === 'NORMAL' ? 'pass' : 'none';
  return (
    <div className={styles.block}>
      <p className={styles.verdictLine}>
        <span className={styles.answer} data-answer={answer}>
          {t(`labCase.answer.${answer}`)}
        </span>
        <span className={styles.note}>
          {t('detail.answer.source', {
            source: t(`anatomy.truthSource.${truth.truthSource ?? 'NONE'}`, {
              defaultValue: truth.truthSource ?? '-',
            }),
          })}
        </span>
      </p>
      {truth.allowedEngineActions.length > 0 ? (
        <div className={styles.chipsRow}>
          <span className={styles.label}>{t('detail.answer.allowed')}</span>
          {truth.allowedEngineActions.map((action) => (
            <VerdictChip key={action} verdict={verdictOf(action)} />
          ))}
        </div>
      ) : null}
      <section className={styles.part} aria-labelledby="detail-rationale">
        <h3 id="detail-rationale" className={shared.panelTitle}>
          {t('detail.answer.rationale')}
        </h3>
        <p className={shared.lead}>{truth.rationale?.[language] ?? t('anatomy.truth.noRationale')}</p>
      </section>
      {truth.counterpoint?.[language] ? (
        <section className={styles.part} aria-labelledby="detail-counterpoint">
          <h3 id="detail-counterpoint" className={shared.panelTitle}>
            {t('detail.answer.counterpoint')}
          </h3>
          <p className={shared.lead}>{truth.counterpoint[language]}</p>
        </section>
      ) : null}
      {truth.business ? (
        <p className={styles.note}>
          {t('detail.answer.business', {
            result: t(`measured.${truth.business.result}`, { defaultValue: truth.business.result }),
            items: count(truth.business.exposedItems, language),
          })}
        </p>
      ) : null}
      {truth.scenarioSha256 ? (
        <p className={styles.note}>
          {t('detail.answer.hash')}{' '}
          <code className={styles.code} data-original>
            {truth.scenarioSha256.slice(0, 12)}
          </code>
        </p>
      ) : null}
    </div>
  );
}

/**
 * The record as it is (anat-2): how many lines the rules and the situation had, the model's answer, the texts sent and
 * the provider's body, each folded, and the whole record as one file with its SHA-256. Past the retention period the
 * texts are gone and the summary stays.
 */
function Original({ view, runId, step }: TabProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const exchanges = useExchanges(runId, step, true);
  const data: ExchangesView | null = exchanges.data ?? null;
  const [download, setDownload] = useState<{ readonly hash: string | null; readonly failed: boolean } | null>(
    null,
  );
  const lines = view.promptLines;
  return (
    <div className={styles.block}>
      {lines ? (
        <p className={shared.lead}>
          {t('detail.original.lines', {
            rules: count(lines.systemPhysical, language),
            sections: count(lines.sections.length, language),
            situation: count(lines.userPhysical, language),
          })}
        </p>
      ) : null}
      {exchanges.isPending ? <StateScreen kind="loading" /> : null}
      {data && (!data.kept || data.calls.length === 0) ? (
        <p className={styles.note}>{t(missingKey(data))}</p>
      ) : null}
      {data?.kept
        ? data.calls.map((call) => (
            <section
              key={call.callNo}
              className={styles.part}
              aria-label={t('detail.original.call', { n: call.callNo })}
            >
              <p className={styles.note}>
                {t('detail.original.call', { n: call.callNo })}{' '}
                <code className={styles.code} data-original>
                  {call.model ?? '-'}
                </code>
              </p>
              <div className={styles.folds}>
                {(
                  [
                    ['answer', call.answer],
                    ['rules', call.systemPrompt],
                    ['situation', call.userPrompt],
                    ['provider', call.providerResponse],
                  ] as const
                ).map(([name, text]) => (
                  <details key={name} className={shared.more}>
                    <summary>{t(`detail.original.${name}`)}</summary>
                    <pre className={styles.pre} data-original tabIndex={0}>
                      {text ?? '-'}
                    </pre>
                  </details>
                ))}
              </div>
            </section>
          ))
        : null}
      <div className={styles.download}>
        <ActionChip
          icon="download"
          variant="open"
          onClick={() => {
            void downloadRunRecord(runId, step, view)
              .then((hash) => setDownload({ hash, failed: false }))
              .catch(() => setDownload({ hash: null, failed: true }));
          }}
        >
          {t('source.download')}
        </ActionChip>
        {download?.hash ? (
          <p className={styles.hash}>
            {t('detail.original.hash')}{' '}
            <code className={styles.code} data-original>
              {download.hash}
            </code>
          </p>
        ) : null}
        {download?.failed ? <p className={styles.warning}>{t('source.downloadFailed')}</p> : null}
      </div>
    </div>
  );
}
