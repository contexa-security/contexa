import { useTranslation } from 'react-i18next';
import type { BeforeSendView } from '../../api/anatomy';
import { Icon } from '../../components/Icon';
import { MINIMUM_ACTION_PLAIN } from '../../components/inside/promptSections';
import styles from './LabPages.module.css';

/** The four conditions of the judgment rules' elevated-risk boundary, in the rule's order. */
const BOUNDARY = ['sensitive', 'established', 'departs', 'approvalMissing'] as const;

type LineState = 'applies' | 'clear' | 'unknown' | 'none';

function lineState(view: BeforeSendView | null): LineState {
  if (!view) {
    return 'none';
  }
  // N-K5-1: the minimum action rules the engine found met, or the boundary of a text without them.
  const applies = view.minimumRules
    ? view.minimumRules.applies
    : view.boundary
      ? view.boundary.applies
      : null;
  return applies === null ? 'unknown' : applies ? 'applies' : 'clear';
}

function mark(value: boolean | null): 'check' | 'cross' | 'dash' {
  return value === true ? 'check' : value === false ? 'cross' : 'dash';
}

interface LineCellProps {
  readonly designed: BeforeSendView | null;
  readonly now: BeforeSendView | null;
  readonly changed: boolean;
}

/**
 * The cell of the lines the judgment rules always keep, in the comparison before sending (L2-2, lab-compare): whether
 * such a line applies in the engine's input, before and after the change, and what it consists of. N-K5-1: a v20 input
 * states the minimum action rules, each shown in the words of exactly its line with the engine's finding (neither the
 * portal nor the screen evaluates a rule); an input without them keeps the elevated-risk boundary's four conditions as
 * the portal read them.
 */
export function LineCell({ designed, now, changed }: LineCellProps) {
  const { t } = useTranslation();
  const rules = now?.minimumRules ?? null;
  const boundary = rules ? null : (now?.boundary ?? null);
  return (
    <section className={styles.compareCell} aria-labelledby="before-line">
      <h2 id="before-line" className={styles.panelTitle}>
        {t('labBefore.cell.line')}
      </h2>
      <p className={styles.compareValue}>
        {changed ? (
          <>
            <span>{t(`labBefore.line.${lineState(designed)}`)}</span>
            <Icon name="arrowRight" className={styles.compareArrow} />
          </>
        ) : null}
        <span className={styles.compareNow}>{t(`labBefore.line.${lineState(now)}`)}</span>
      </p>
      {rules ? (
        <ul className={styles.lineConditions}>
          {rules.rules.map((rule) => {
            // The words of exactly the rule's line; a rule of other settings shows its line as sent.
            const words = MINIMUM_ACTION_PLAIN.find((plain) => rule.line.startsWith(plain.starts));
            return (
              <li key={rule.code} data-met={rule.met === true || undefined}>
                <Icon name={mark(rule.met)} />
                {words ? t(words.key) : rule.line}
              </li>
            );
          })}
        </ul>
      ) : null}
      {boundary ? (
        <ul className={styles.lineConditions}>
          {BOUNDARY.map((condition) => (
            <li key={condition} data-met={boundary[condition] === true || undefined}>
              <Icon name={mark(boundary[condition])} />
              {t(`labBefore.condition.${condition}`)}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
