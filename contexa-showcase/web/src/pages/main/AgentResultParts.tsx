import { useTranslation } from 'react-i18next';
import type { AgentProof, AgentRunView } from '../../api/agentCase';
import { Chip } from '../../components/main/Chip';
import { CONTROL_ORDER } from '../../domain/verdict';
import { count } from '../../journey/format';
import { CONFIRMATION_RULE } from './agentGroup';
import styles from './AgentResultPage.module.css';

/**
 * The parts of an agent run's result (docs/agent Agent중심-화면 AS-8) that more than one screen shows: the summary of what
 * the work sent and where control D stopped it, and the five approaches as lanes. Every number is the portal's scoring
 * of the run (the proof), never a count a screen made.
 */

/** The requests sent, what the work needs, where control D first stopped it and what went to the delegating person. */
export function ResultSummary({
  run,
  proof,
  language,
}: {
  readonly run: AgentRunView;
  readonly proof: AgentProof;
  readonly language: string;
}) {
  const { t } = useTranslation();
  const stop = proof.controls['D']?.firstStopStep ?? null;
  // Control D asked the person when its rule says so, or the run holds the confirmation (a run stored before records
  // has only the rule).
  const asked = run.confirmation !== null || run.steps.some((step) => step.outcomes['D']?.rule === CONFIRMATION_RULE);
  return (
    <section className={styles.summary} aria-labelledby="agent-result-summary">
      <h2 id="agent-result-summary" className="visually-hidden">
        {t('main.6-7.summary')}
      </h2>
      <dl className={styles.facts}>
        <div className={styles.fact}>
          <dt>{t('main.6-7.sent')}</dt>
          <dd>{count(proof.sent, language)}</dd>
        </div>
        <div className={styles.fact}>
          <dt>{t('main.6-7.need')}</dt>
          <dd>{proof.workNeeds === null ? t('main.6-7.needNone') : count(proof.workNeeds, language)}</dd>
        </div>
        <div className={styles.fact}>
          <dt>{t('main.6-7.firstStop')}</dt>
          <dd>{stop === null ? t('main.6-7.neverStopped') : count(stop, language)}</dd>
        </div>
        <div className={styles.fact}>
          <dt>{t('main.6-7.toPerson')}</dt>
          <dd>{asked ? t('main.6-7.toPersonYes') : t('main.6-7.toPersonNo')}</dd>
        </div>
      </dl>
    </section>
  );
}

/** The five approaches, one lane each: what each let out of the protected data and where each first stopped the work. */
export function ResultLanes({ proof, language }: { readonly proof: AgentProof; readonly language: string }) {
  const { t } = useTranslation();
  return (
    <section className={styles.lanes} aria-labelledby="agent-result-lanes">
      <h2 id="agent-result-lanes" className={styles.label}>
        {t('main.6-7.lanes')}
      </h2>
      <ul className={styles.laneList}>
        {CONTROL_ORDER.map((control) => {
          const result = proof.controls[control];
          const stopped = result?.firstStopStep ?? null;
          return (
            <li key={control} className={styles.lane} data-control={control}>
              <span className={styles.laneName}>{t(`control.${control}.name`)}</span>
              <Chip kind={stopped === null ? 'bad' : 'block'}>
                {stopped === null ? t('main.6-7.neverStopped') : t('main.6-7.stoppedAt', { step: stopped })}
              </Chip>
              <span className={styles.laneValue}>
                {t('main.6-7.leaked', {
                  documents: count(result?.documents ?? 0, language),
                  items: count(result?.items ?? 0, language),
                  records: count(result?.records ?? 0, language),
                  changes: count(result?.changes ?? 0, language),
                })}
                {' · '}
                {t('main.6-7.beyond', { n: count(result?.beyondNeed ?? 0, language) })}
              </span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
