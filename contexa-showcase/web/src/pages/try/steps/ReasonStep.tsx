import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import type { LabCase } from '../../../api/lab';
import { ActionChip } from '../../../components/common/ActionChip';
import { useDetail } from '../../../components/detail/useDetail';
import { SourceMark } from '../../../components/common/SourceMark';
import { Icon } from '../../../components/Icon';
import { JustSaw } from '../../../components/journey/JourneyParts';
import { ActionBar, MoreRow, StepHeader } from '../../../components/journey/StepParts';
import { StateScreen } from '../../../components/StateScreen';
import { VerdictChip } from '../../../components/VerdictChip';
import type { Verdict } from '../../../domain/verdict';
import type { Difference } from '../../../journey/journey';
import { decisionDetail } from '../decision';
import { stepPath, type Mode, type Role, type StepFlow } from '../experience';
import styles from '../Experience.module.css';
import { useTryAnalysis, useTryRun } from './tryRun';

const TITLED_CODES = new Set(['CHALLENGE_ELEVATED_RISK_BOUNDARY']);
const ACTIONS = new Set(['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK']);

interface ReasonStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Try 1-6, the reasons (e1-reason): which recorded facts led to the decision, as one figure, and the reason the engine
 * wrote (the fixed Korean of a contract sentence, the original behind its fold). The evidence it cited and the core
 * inspector's adverse conditions are folded under "details" (D-41). Every value is control D's decision block of the
 * visitor's run.
 */
export function ReasonStep({ role, mode, labCase, see, flow }: ReasonStepProps) {
  const { t } = useTranslation();
  const details = useDetail();
  const run = useTryRun(labCase.key, labCase.requests.length);
  const view = run.view;
  const analysis = useTryAnalysis(view, run.stored);
  const decision = analysis.decision;

  useEffect(() => {
    if (decision) {
      see(4);
    }
    // Seen once the reasons are on screen; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [decision !== null]);

  if (run.pending) {
    return <StateScreen kind="loading" />;
  }
  if (!view?.runId) {
    return (
      <>
        <StepHeader title={t('experience.step.reason')} purpose={t('e1.run.notSent')} />
        <ActionBar back={{ to: stepPath(role, 'predict', mode), label: t('e1.run.toPredict') }} />
      </>
    );
  }
  if (!decision) {
    // A stored run without a decision of the engine says so; otherwise the decision is still coming.
    return analysis.missing ? (
      <>
        <StepHeader title={t('e1.reason.title.other')} purpose={t('e1.reason.none')} />
        <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
      </>
    ) : (
      <StateScreen kind="loading" />
    );
  }

  const runId = view.runId;
  const canonical = decision.reason?.canonical ?? null;
  const action = decision.finalAction;
  const titleKey =
    role === 'owner' && action === 'ALLOW'
      ? 'e2.reason.title.ALLOW'
      : canonical && TITLED_CODES.has(canonical)
        ? `e1.reason.title.${canonical}`
        : `e1.reason.title.${ACTIONS.has(action) ? action : 'other'}`;
  const met = new Set(decision.adverseLabels.filter((label) => label.met).map((label) => label.label));
  const approvalRead = decision.adverseLabels.some(
    (label) => label.label === 'approvalrequired' && label.met,
  );
  const detail = decisionDetail(t, decision);
  const facts = [
    t('e1.reason.differs', { n: decision.reason?.baselineDeltaCount ?? '-' }),
    ...(decision.reason?.resourceSensitivity
      ? [
          t('e1.reason.sensitivity', {
            level: t(`dim.sensitivity.${decision.reason.resourceSensitivity}`, {
              defaultValue: decision.reason.resourceSensitivity,
            }),
          }),
        ]
      : []),
    ...(approvalRead ? [t(met.has('approvalmissing') ? 'e1.reason.noApproval' : 'e1.reason.approval')] : []),
  ];

  return (
    <>
      <StepHeader
        title={t(titleKey)}
        purpose={t(role === 'owner' ? 'e2.purpose.reason' : 'e1.purpose.reason')}
        source={
          <SourceMark
            kind="ENGINE"
            runId={view.runId}
            step={1}
            original={decision.reason?.reasoning ?? null}
          />
        }
      />
      <div className={styles.reasonFigure} aria-label={t('e1.reason.figure')}>
        <ul className={styles.reasonFacts}>
          {facts.map((fact) => (
            <li key={fact} className={styles.reasonFact}>
              {fact}
            </li>
          ))}
        </ul>
        <Icon name="arrowRight" className={styles.reasonArrow} />
        <VerdictChip verdict={(ACTIONS.has(action) ? action : 'NONE') as Verdict} size="lg" />
      </div>
      <figure className={styles.quote}>
        <figcaption className={styles.quoteLabel}>{t('e1.reason.wrote')}</figcaption>
        {/* The sentence alone in the quote; whether the rules set it is said under it, not inside it. */}
        <blockquote className={styles.quoteText}>
          {canonical
            ? t(`reason.canonical.${canonical}`, { defaultValue: decision.reason?.reasoning ?? '' })
            : t('e1.reason.free')}
        </blockquote>
        {canonical ? (
          <p className={styles.quoteNote}>
            {t(role === 'owner' && action === 'ALLOW' ? 'e2.reason.allowNote' : 'e1.reason.canonical')}
          </p>
        ) : null}
        {detail.original ? (
          <details className={styles.more}>
            <summary>{t('source.original')}</summary>
            <p className={styles.original}>{detail.original}</p>
          </details>
        ) : null}
      </figure>
      <MoreRow>
        <details className={styles.more}>
          <summary>{t('e1.reason.details')}</summary>
          <div className={styles.foldText}>
            {detail.cited.length > 0 ? (
              <p>
                {t('e1.reason.citedLine', {
                  refs: detail.cited.map((ref) => t(`evidenceRef.${ref}`, { defaultValue: ref })).join(' · '),
                })}
              </p>
            ) : null}
            <p>
              {t('e1.reason.inspector', {
                total: detail.inspector.total,
                met: detail.inspector.met,
                names: detail.inspector.names.length > 0 ? `(${detail.inspector.names.join(', ')})` : '',
              })}
            </p>
            <p>
              {decision.riskScore === null && decision.confidence === null
                ? t('e1.reason.riskNone')
                : t('e1.reason.risk', {
                    risk: decision.riskScore ?? t('e1.reason.noValue'),
                    confidence: decision.confidence ?? t('e1.reason.noValue'),
                  })}
            </p>
          </div>
        </details>
        <ActionChip to="/try/prompt" icon="code" variant="open">
          {t('e1.reason.promptLink')}
        </ActionChip>
        <ActionChip onClick={() => details.show(runId)} icon="search" variant="open">
          {t('e1.result.detail')}
        </ActionChip>
      </MoreRow>
      {role === 'attacker' ? <JustSaw difference={4} sentence="e1Reason" /> : null}
      <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
    </>
  );
}
