import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { useHook, type HookColumn } from '../../api/hook';
import { useLabOptions, type LabOptions } from '../../api/lab';
import { SourceLine } from '../../components/journey/FrameParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import { VerdictChip } from '../../components/VerdictChip';
import { count } from '../../journey/format';
import styles from './HookPage.module.css';

/** Keeps a line's height while the record loads, so nothing below it moves when it arrives. */
const HOLD = ' ';

/**
 * Screen 0, the start (hook, 화면재편-기획안 7절 T1): the question, then the two people who signed in with the same
 * password, each with the situation in one line, Contexa's judgment and how many files went out in the operator's
 * representative measured run, then what Contexa is in one line. The guide says Contexa tells the two apart only when
 * the measurement does (every attacker run stopped, every real-employee run through); otherwise a guide that claims
 * nothing takes its place. The one way on is the flow's "Start".
 */
export default function HookPage() {
  const { t } = useTranslation();
  const hook = useHook();
  const options = useLabOptions();
  const view = hook.data ?? null;
  const guide = view
    ? t(view.distinguished ? 'screen.0.guide' : 'p0.guide.fallback')
    : hook.isError
      ? t('p0.guide.fallback')
      : HOLD;

  return (
    <RouteScreen
      title={t('screen.0.title')}
      purpose={guide}
      sourceLine={view ? <SourceLine kind="measured" runId={view.attacker.runId} /> : null}
    >
      {hook.isPending ? <StateScreen kind="loading" /> : null}
      {hook.isError ? <StateScreen kind="notReady" /> : null}
      {view ? (
        <div className={styles.people}>
          <Person side="attacker" column={view.attacker} options={options.data ?? null} />
          <Person side="owner" column={view.owner} options={options.data ?? null} />
        </div>
      ) : null}
      <p className={styles.identity}>{t('identity.line')}</p>
    </RouteScreen>
  );
}

interface PersonProps {
  readonly side: 'attacker' | 'owner';
  readonly column: HookColumn;
  readonly options: LabOptions | null;
}

/**
 * One of the two people: who, the situation as the case defines it, and Contexa's recorded judgment and delivered
 * files of the representative run (its control D layer). Nothing here is counted or decided by the screen.
 */
function Person({ side, column, options }: PersonProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const id = useId();
  const items =
    options?.cases.find((candidate) => candidate.key === column.caseKey)?.requests[0]?.items ?? null;
  const contexa = column.result.layers.find((layer) => layer.control === 'D') ?? null;
  return (
    <section className={styles.person} aria-labelledby={id}>
      <h2 id={id} className={styles.name}>
        {t(`p0.${side}.name`)}
      </h2>
      <p className={styles.line}>
        {items === null ? HOLD : t(`p0.${side}.line`, { items: count(items, language) })}
      </p>
      <dl className={styles.facts}>
        <div className={styles.fact}>
          <dt className={styles.label}>{t('p0.verdict')}</dt>
          <dd className={styles.value}>
            {contexa ? (
              <VerdictChip verdict={contexa.verdict ?? 'NONE'} unresolved={contexa.evidence.unresolved} />
            ) : (
              '-'
            )}
          </dd>
        </div>
        <div className={styles.fact}>
          <dt className={styles.label}>{t('p0.delivered')}</dt>
          <dd className={styles.count}>
            {contexa ? t('p0.items', { n: count(contexa.evidence.deliveredItems, language) }) : '-'}
          </dd>
        </div>
      </dl>
    </section>
  );
}
