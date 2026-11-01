import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useExchanges, useReceived, type DecisionAnatomyView } from '../../../api/anatomy';
import { useStepResult } from '../../../api/lab';
import { useRunFacts, useRunQuality } from '../../../api/promptQuality';
import type { RunScore } from '../../../api/types';
import { downloadRunRecord } from '../../../api/runRecord';
import { factKey } from '../../../components/facts/factWords';
import { CONTROL_ORDER } from '../../../domain/verdict';
import { formatDuration, formatNumber, formatUtc } from '../../format';
import { agentCell } from '../../simulate/agent';
import { AgentCellBadge } from '../../simulate/AgentParts';
import { CONTROL_TONE } from '../../simulate/controls';
import { verdictOf } from '../../simulate/person';
import { Badge, Button, CodeChip, FlagBadge, Loading, Note, VerdictBadge } from '../../ui';
import sim from '../../simulate/Simulate.module.css';
import { noDecisionKey } from './detailWords';
import styles from './Detail.module.css';

interface TabProps {
  readonly runId: string;
  readonly step: number;
  readonly anatomy: DecisionAnatomyView;
  readonly score: RunScore | null;
}

const ASSESSMENT = { MOST_LIKELY: 3, POSSIBLE: 2, UNLIKELY: 1, NO_EVIDENCE: 0 } as const;

const QUOTE_SHORT = 220;

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
            {recorded.applied ? t(`ux.live.applied.${recorded.applied === 'NEXT_REQUEST' ? 'NEXT_REQUEST' : 'BEFORE_RESPONSE'}`) : '—'}
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
    </div>
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
export function EvidenceTab({ runId, step, anatomy }: TabProps) {
  const { t } = useTranslation();
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
  return (
    <div className={styles.columns} data-wide-first="true">
      <section className={styles.card} aria-labelledby="detail-cited">
        <h2 id="detail-cited" className={styles.cardTitle}>
          {t('ux.detail.evidence.cited')}
        </h2>
        <p className={styles.cardSub}>{t('ux.detail.evidence.citedSub', { n: codes.length })}</p>
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
                      <td className={styles.wrap}>{received.data?.usual[row.dimension]?.values.join(', ') || '—'}</td>
                      <td className={styles.wrap}>{row.now ?? '—'}</td>
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

/** 판정 프롬프트: the facts the engine was given, block by block, and how the prompt was built. */
export function PromptTab({ runId, step, anatomy }: TabProps) {
  const { t, i18n } = useTranslation();
  const facts = useRunFacts(runId, step);
  const quality = useRunQuality(runId, step);
  const lines = anatomy.promptLines;
  const bundle = facts.data?.bundle ?? quality.data?.bundle ?? null;
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <div className={styles.stack}>
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
                  <span className={styles.lineLabel}>{t(`fact.label.${factKey(fact.label)}`, { defaultValue: fact.label })}</span>
                  <code className={styles.quote} lang="en">
                    {fact.value}
                  </code>
                </li>
              ))}
            </ol>
          </section>
        ))}
      </section>
    </div>
  );
}

/** 모델 응답 원문: each call to the model as it was sent and answered, kept for the retention period. */
export function ResponseTab({ runId, step }: TabProps) {
  const { t } = useTranslation();
  const exchanges = useExchanges(runId, step, true);
  if (exchanges.isPending) {
    return <Loading rows={6} />;
  }
  if (!exchanges.data) {
    return <Note tone="warn">{t('ux.detail.unavailable')}</Note>;
  }
  if (!exchanges.data.kept) {
    return <Note>{t(`ux.detail.response.missing.${exchanges.data.missing ?? 'NOT_COLLECTED'}`)}</Note>;
  }
  return (
    <div className={styles.stack}>
      {exchanges.data.calls.map((call) => (
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
          </>
        ) : (
          <Note>{t('ux.detail.integrity.noInspection')}</Note>
        )}
      </section>
    </div>
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
