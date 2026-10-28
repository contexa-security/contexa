import { useTranslation } from 'react-i18next';
import { useAgentCase, useAgentCaseKey } from '../../api/agentCase';
import { Fold } from '../../components/main/Fold';
import { count } from '../../journey/format';
import styles from './MeasureNote.module.css';

/** The stop reasons of a live run's hard limits (docs/agent Agent중심-화면 AC-3), as the portal records them. */
const CAPS: ReadonlySet<string> = new Set(['CAP_TOOL_CALLS', 'CAP_DECISIONS', 'CAP_INPUT_TOKENS']);

/**
 * What the agent screens' numbers stand on (docs/agent Agent중심-화면 AS-5): whose run the screen shows, how many times
 * the operator recorded the same case and how many of them ended as the latest recording did (counted by the portal,
 * never by the screen), and the limit of one run of a model: its judgment can differ from run to run, and one case
 * is not all work.
 *
 * @param own        whether the screen shows the visitor's own run (else the operator's recording)
 * @param stopReason how the run's work ended; a live limit's CAP_* reason closes the screen as "so far" (AC-3)
 */
export function MeasureNote({
  own,
  stopReason = null,
}: {
  readonly own: boolean;
  readonly stopReason?: string | null;
}) {
  const { t, i18n } = useTranslation();
  const recorded = useAgentCase(useAgentCaseKey(true)).data?.recorded ?? null;
  const capped = stopReason !== null && CAPS.has(stopReason);
  return (
    <aside className={styles.note} aria-label={t('main.agent.measure.label')}>
      {capped ? (
        <p className={styles.line}>
          <b>{t('main.agent.cap.so_far')}</b> {t(`main.agent.cap.${stopReason}`)}
        </p>
      ) : null}
      {/* AC-N2: whose run it is stays in view; the counts and the limit of one run wait under that line. */}
      <Fold name="measure-note" summary={t(own ? 'main.agent.measure.own' : 'main.agent.measure.recorded')}>
        {recorded && recorded.runs > 0 ? (
          <p className={styles.line}>
            {t('main.agent.measure.stats', {
              runs: count(recorded.runs, i18n.language),
              same: count(recorded.sameAsLatest, i18n.language),
            })}
          </p>
        ) : null}
        <p className={styles.line}>{t('main.agent.measure.limit')}</p>
      </Fold>
    </aside>
  );
}
