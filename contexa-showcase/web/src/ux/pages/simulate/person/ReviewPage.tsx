import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link, Navigate, useNavigate, useParams } from 'react-router-dom';
import { useAnatomy, useBeforeSend } from '../../../../api/anatomy';
import { useJourneyUpdate } from '../../../../api/journey';
import { useLabOptions } from '../../../../api/lab';
import { useLiveConfig, useStats } from '../../../../api/queries';
import { useLiveSend } from '../../../../hooks/useLiveSend';
import { formatNumber, formatSeconds } from '../../../format';
import { FlowSteps } from '../../../simulate/FlowFrame';
import {
  contextChips,
  factCells,
  flowPath,
  personCase,
  truthOf,
  type BaselineMark,
  type PersonCase,
} from '../../../simulate/person';
import { useRecordedRun } from '../../../simulate/RecordedFallback';
import { usePersonRuns } from '../../../simulate/useFlow';
import { CONTROL_TONE } from '../../../simulate/controls';
import { Badge, Button, ButtonLink, CodeChip, FlagBadge, Icon, Note, PageHead } from '../../../ui';
import styles from '../../../simulate/Review.module.css';

type Call = 'ALLOW' | 'BLOCK';

/**
 * Step 2 (기획안 7.0 d-review): the request as the controls receive it — the request line, five facts marked against
 * the behavioural baseline, the business context — the five controls in one line each, the visitor's expected
 * decision, and the run. The facts are what the engine received in the latest run of the same scenario (DEC-21); the
 * run goes through the visitor's gate (the human check, the daily runs, an earlier run still finishing, ST-1~ST-6).
 */
export default function ReviewPage() {
  const { caseKey } = useParams();
  const scenario = personCase(caseKey);
  if (!scenario) {
    return <Navigate replace to="/simulate/person" />;
  }
  return <Review scenario={scenario} />;
}

function Review({ scenario }: { readonly scenario: PersonCase }) {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const key = scenario.key;
  const options = useLabOptions();
  const labCase = options.data?.cases.find((candidate) => candidate.key === key) ?? null;
  const employee =
    options.data?.employees.find((candidate) => candidate.key === labCase?.conditions.employee) ?? null;
  const comparison = useBeforeSend(key, 1).data?.comparison ?? null;
  const request = useAnatomy(comparison?.runId ?? null, 1).data?.context.resource ?? null;
  const stats = useStats();
  const live = useLiveConfig();
  const runs = usePersonRuns();
  const saveJourney = useJourneyUpdate();
  const recorded = useRecordedRun(key);
  const earlier = runs.prediction(key)?.call.engine ?? null;
  const [call, setCall] = useState<Call | null>(null);
  const chosen: Call | null = call ?? (earlier === null ? null : earlier === 'ALLOW' ? 'ALLOW' : 'BLOCK');
  const { send, sending, ready, refusal, waiting, turnstileContainer, turnstileRequired } = useLiveSend(
    key,
    () => navigate(flowPath(key, 'live')),
  );
  const n = (value: number) => formatNumber(value, i18n.language);
  const items = labCase?.requests[0]?.items ?? null;
  const cells = factCells(t, n, comparison, labCase, employee);
  const chips = comparison ? contextChips(t, comparison.businessFacts) : [];
  const truth = truthOf(labCase?.classification);
  const decision = stats.data?.decisionTime ?? null;
  const reason = !runs.visitorReady
    ? t('ux.review.reason.visitor')
    : chosen === null
      ? t('ux.review.reason.predict')
      : turnstileRequired && !ready && !sending && !waiting
        ? t('ux.review.reason.human')
        : undefined;

  return (
    <>
      <FlowSteps current="review" />
      <PageHead
        kicker={
          <>
            <Badge tone="line" icon={scenario.icon}>
              {t(`ux.review.kind.${key}`)}
            </Badge>
            <CodeChip value={key} />
            <span className={styles.truth}>
              {t(`ux.flow.truth.${truth}`)} · {t('ux.flow.truthHidden')}
            </span>
          </>
        }
        title={t(`ux.review.title.${key}`, { n: items !== null ? n(items) : '' })}
        actions={
          <ButtonLink to="/simulate/person" variant="text">
            {t('ux.flow.changeScenario')}
          </ButtonLink>
        }
      />

      <section className={styles.request} aria-label={t('ux.review.requestLabel')}>
        <div className={styles.requestLine}>
          {request?.httpMethod ? <span className={styles.method}>{request.httpMethod}</span> : null}
          <code className={styles.path}>{request?.requestPath ?? '…'}</code>
          <span className={styles.to}>{t('ux.review.toControls')}</span>
        </div>
        <dl className={styles.facts}>
          {cells.map((cell) => (
            <div key={cell.id} className={styles.fact}>
              <dt>{t(`ux.facts.label.${cell.id}`)}</dt>
              <dd className={styles.factValue}>{cell.value}</dd>
              <dd className={styles.factMark}>
                <Mark mark={cell.mark} />
                {cell.note ? <span className={styles.factNote}>{cell.note}</span> : null}
              </dd>
            </div>
          ))}
        </dl>
        {chips.length > 0 ? (
          <div className={styles.context}>
            <span className={styles.contextLabel}>{t('ux.review.context')}</span>
            {chips.map((chip) => (
              <Badge key={chip} tone="line">
                {chip}
              </Badge>
            ))}
          </div>
        ) : null}
        {comparison ? (
          <p className={styles.source}>
            {t('ux.review.source')} <CodeChip value={comparison.runId} />
          </p>
        ) : null}
      </section>

      <ul className={styles.controls} aria-label={t('ux.review.controlsLabel')}>
        {(['A', 'B', 'C1', 'C2', 'D'] as const).map((control) => (
          <li key={control} className={styles.control} data-contexa={control === 'D' || undefined}>
            <b>
              <span className={styles.swatch} data-tone={CONTROL_TONE[control]} aria-hidden="true" />
              {t(`ux.control.short.${control}`)}
            </b>
            <span>{t(`ux.review.controls.${control}`)}</span>
          </li>
        ))}
      </ul>

      <section aria-labelledby="predict-title">
        <div className={styles.predictHead}>
          <h2 id="predict-title" className={styles.predictTitle}>
            {t('ux.review.predict.title')}
          </h2>
          <p className={styles.predictDesc}>{t('ux.review.predict.desc')}</p>
        </div>
        <div role="radiogroup" aria-labelledby="predict-title" className={styles.choices}>
          {(['ALLOW', 'BLOCK'] as const).map((option) => (
            <button
              key={option}
              type="button"
              role="radio"
              aria-checked={chosen === option}
              className={styles.choice}
              onClick={() => setCall(option)}
            >
              <span className={styles.choiceIcon} data-tone={option === 'ALLOW' ? 'allow' : 'block'}>
                <Icon name={option === 'ALLOW' ? 'check' : 'ban'} size="xl" />
              </span>
              <span className={styles.choiceText}>
                <b>{t(`ux.review.predict.${option}.title`)}</b>
                <span>
                  {t(`ux.review.predict.${option}.desc`, {
                    n: items !== null ? n(items) : '',
                    count: items ?? 0,
                  })}
                </span>
              </span>
              <span className={styles.radio} aria-hidden="true" />
            </button>
          ))}
        </div>
      </section>

      <section className={styles.runBar} aria-label={t('ux.review.run')}>
        <ul className={styles.runMeta}>
          <li>{t('ux.review.realAi')}</li>
          {decision?.p50Ms != null && decision.p95Ms != null ? (
            <li>
              {t('ux.review.latency', {
                p50: formatSeconds(decision.p50Ms, i18n.language),
                p95: formatSeconds(decision.p95Ms, i18n.language),
              })}
            </li>
          ) : null}
          {live.data ? (
            <li>{t('ux.review.daily', { n: n(live.data.dailyRuns), left: n(live.data.remainingToday) })}</li>
          ) : null}
        </ul>
        {turnstileRequired ? <div ref={turnstileContainer} className={styles.turnstile} /> : null}
        <div className={styles.runAction}>
          <Button
            variant="primary"
            size="lg"
            icon="play"
            busy={sending || waiting}
            {...(reason ? { disabledReason: reason } : {})}
            onClick={() =>
              void send(async () => {
                if (chosen) {
                  await saveJourney({ prediction: { experience: scenario.experience, engine: chosen } });
                }
              })
            }
          >
            {t('ux.review.run')}
          </Button>
        </div>
      </section>
      {waiting ? <Note icon="hourglass">{t('ux.review.waiting')}</Note> : null}
      {refusal ? (
        <div className={styles.refusal} role="alert">
          <Note tone="warn">{t(`ux.review.refusal.${refusal}`)}</Note>
          {recorded && refusal !== 'turnstile' ? (
            <Link to={`/runs/${recorded}`} className={styles.recordedLink}>
              {t('ux.review.recorded')}
            </Link>
          ) : null}
        </div>
      ) : null}
    </>
  );
}

function Mark({ mark }: { readonly mark: BaselineMark }) {
  const { t } = useTranslation();
  if (mark === 'out') {
    return <FlagBadge />;
  }
  if (mark === 'in') {
    return <Badge tone="none">{t('ux.facts.mark.in')}</Badge>;
  }
  if (mark === 'unknown') {
    return <Badge tone="none">{t('ux.facts.mark.unknown')}</Badge>;
  }
  return null;
}
