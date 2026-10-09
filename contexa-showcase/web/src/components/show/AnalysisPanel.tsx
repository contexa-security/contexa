import { useTranslation } from 'react-i18next';
import type { AnalysisStage } from '../../api/types';
import type { Role } from '../../domain/show';
import { decision } from '../../domain/show';
import styles from './AnalysisPanel.module.css';

interface AnalysisPanelProps {
  readonly role: Role;
  /** The request went out and the engine has not applied its decision yet. */
  readonly working: boolean;
  /**
   * Contexa refused the request with a decision already in force, so the engine made no new analysis of it (an
   * analysis runs only while no decision holds).
   */
  readonly noNewAnalysis?: boolean;
  readonly stages: readonly AnalysisStage[];
}

const SHOWN = new Set([
  'CONTEXT_COLLECTED',
  'LAYER1_START',
  'LAYER1_COMPLETE',
  'LAYER2_START',
  'LAYER2_COMPLETE',
  'DECISION_APPLIED',
  'ANALYSIS_ERROR',
]);

/**
 * Contexa deciding, as the engine announces it (deck p.12): each analysis stage with the milliseconds since the
 * request was sent, and the applied decision. The stages are the engine's own events of this run, read while it goes.
 */
export function AnalysisPanel({ role, working, stages, noNewAnalysis = false }: AnalysisPanelProps) {
  const { t } = useTranslation();
  const shown = stages.filter((stage) => SHOWN.has(stage.type));
  const applied = decision(stages);
  const good = applied ? goodFor(role, applied.action) : null;
  return (
    <section className={styles.panel} aria-labelledby="analysis-title" aria-live="polite">
      <h2 id="analysis-title" className={styles.title}>
        {t('show.analysis.title')}
      </h2>
      {shown.length === 0 && noNewAnalysis ? <p className={styles.idle}>{t('show.analysis.none')}</p> : null}
      {shown.length === 0 && !working && !noNewAnalysis ? (
        <p className={styles.idle}>{t('show.analysis.idle')}</p>
      ) : null}
      <ol className={styles.stages}>
        {shown.map((stage, index) => (
          <li key={`${stage.type}-${index}`} className={styles.stage} data-type={stage.type}>
            <span className={styles.stageName}>{t(`show.analysis.stage.${stage.type}`)}</span>
            {stage.action ? (
              <span className={styles.stageAction}>{t(`show.action.${stage.action}`)}</span>
            ) : null}
            <span className={styles.at}>
              {stage.atMs === null ? '' : t('show.analysis.at', { ms: stage.atMs.toLocaleString() })}
            </span>
          </li>
        ))}
        {working && !applied && !noNewAnalysis ? (
          <li className={styles.working}>
            <span className={styles.pulse} aria-hidden="true" />
            {t('show.analysis.working')}
          </li>
        ) : null}
      </ol>
      {applied ? (
        <div className={styles.decision} data-good={good}>
          <span className={styles.decisionLabel}>{t('show.analysis.stage.DECISION_APPLIED')}</span>
          <strong className={styles.decisionAction}>{t(`show.action.${applied.action}`)}</strong>
          {applied.riskScore !== null && applied.confidence !== null ? (
            <span className={styles.risk}>
              {t('show.analysis.risk', {
                risk: applied.riskScore.toFixed(2),
                confidence: applied.confidence.toFixed(2),
              })}
            </span>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

/** Whether the decision is the right one for the scene: hold the attacker, let the real owner work. */
function goodFor(role: Role, action: string): boolean {
  return role === 'attacker' ? action !== 'ALLOW' : action === 'ALLOW';
}
