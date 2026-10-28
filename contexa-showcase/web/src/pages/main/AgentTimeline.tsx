import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Chip } from '../../components/main/Chip';
import { CONTROL_ORDER } from '../../domain/verdict';
import { count } from '../../journey/format';
import { foldRows, groupFacts, type TimelineRow } from './timelineFolding';
import { outcomeChip } from './agentGroup';
import styles from './AgentPages.module.css';

/**
 * The agent's requests in order, each with the five approaches' answers (docs/agent Agent중심-화면 AS-9), drawn the same
 * for a stored run and for a live one. A burst of identical requests is folded into one line that says how many requests
 * it holds, how many of them had a verdict of their own and how many model calls they made; it opens row by row.
 */
export function AgentTimeline({ rows }: { readonly rows: readonly TimelineRow[] }) {
  const { t } = useTranslation();
  const folded = foldRows(rows);
  return (
    // A narrow screen scrolls the rows sideways: the region takes the focus so a keyboard can scroll it.
    <div className={styles.tableWrap} tabIndex={0} role="region" aria-labelledby="agent-rows-caption">
      <table className={styles.table}>
        <caption id="agent-rows-caption" className="visually-hidden">
          {t('main.6-2.caption')}
        </caption>
        <thead>
          <tr>
            <th scope="col">{t('main.6-2.request')}</th>
            {CONTROL_ORDER.map((control) => (
              <th key={control} scope="col">
                {t(`control.${control}.name`)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {folded.map((entry) =>
            entry.kind === 'row' ? (
              <TimelineLine key={entry.row.stepNo} row={entry.row} />
            ) : (
              <TimelineGroup key={`group-${(entry.rows[0] as TimelineRow).stepNo}`} rows={entry.rows} />
            ),
          )}
        </tbody>
      </table>
    </div>
  );
}

function TimelineLine({ row }: { readonly row: TimelineRow }) {
  const { t, i18n } = useTranslation();
  return (
    <tr>
      <th scope="row" className={styles.requestCell}>
        <span className={styles.requestNo}>{t('main.6-2.step', { n: row.stepNo })}</span>
        {row.step?.path ? <code className={styles.requestPath}>{row.step.path}</code> : null}
      </th>
      {CONTROL_ORDER.map((control) => {
        const layer = row.layers[control];
        if (!layer) {
          return (
            <td key={control}>
              <Chip kind="wait">{t('main.agent.outcome.WAITING')}</Chip>
            </td>
          );
        }
        const chip = outcomeChip(layer.outcome, layer.ruleId);
        return (
          <td key={control}>
            <Chip kind={chip.kind}>
              {i18n.exists(`main.agent.outcome.${chip.word}`) ? t(`main.agent.outcome.${chip.word}`) : chip.word}
            </Chip>
          </td>
        );
      })}
    </tr>
  );
}

/** A folded burst: one line that opens into its requests. */
function TimelineGroup({ rows }: { readonly rows: readonly TimelineRow[] }) {
  const { t, i18n } = useTranslation();
  const [open, setOpen] = useState(false);
  const facts = groupFacts(rows);
  const first = rows[0] as TimelineRow;
  const last = rows[rows.length - 1] as TimelineRow;
  return (
    <>
      <tr className={styles.groupRow}>
        <th scope="row" colSpan={1 + CONTROL_ORDER.length} className={styles.requestCell}>
          <button
            type="button"
            className={styles.groupToggle}
            aria-expanded={open}
            onClick={() => setOpen((value) => !value)}
          >
            {t(open ? 'main.agent.timeline.collapse' : 'main.agent.timeline.expand')}
            {' · '}
            {t('main.agent.timeline.group', {
              count: count(facts.count, i18n.language),
              from: first.stepNo,
              to: last.stepNo,
            })}
          </button>
          <span className={styles.groupFacts}>
            {t('main.agent.timeline.groupFacts', {
              verdicts: count(facts.withVerdict, i18n.language),
              calls: count(facts.modelCalls, i18n.language),
            })}
          </span>
        </th>
      </tr>
      {open ? rows.map((row) => <TimelineLine key={row.stepNo} row={row} />) : null}
    </>
  );
}
