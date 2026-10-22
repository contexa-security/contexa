import { useTranslation } from 'react-i18next';
import { useAnatomy, useReceived } from '../../api/anatomy';
import { useEngineActions } from '../../api/engine';
import { useLabOptions } from '../../api/lab';
import { useBaseline } from '../../api/queries';
import { useDetail } from '../../components/detail/useDetail';
import { Icon } from '../../components/Icon';
import { HourBars } from '../../components/journey/HourBars';
import { GhostButton, MainLink, MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import { plainValue } from '../try/experience';
import { useTryRun } from '../try/steps/tryRun';
import { caseOf, MAIN_CASES, ROLE_PATHS } from './mainCases';
import { ProofPanel } from './ProofPanel';
import styles from './ResultPage.module.css';

/** The company records the business-record rule looked up, in the order a person reads them. */
const COMPANY = [
  ['ASSIGNED', 'NOT_ASSIGNED'],
  ['APPROVAL_COVERS', 'NO_APPROVAL'],
  ['TICKET_COVERS', 'NO_TICKET'],
  ['ON_CALL', 'NOT_ON_CALL'],
  ['ACCESS_DAYS_LAST_30'],
] as const;

/**
 * The dimensions the first card may show, in this order: the first the engine read as outside the usual pattern (the
 * stolen account's device, an attack's hour), else the hour.
 */
const FIRST = ['device', 'accessHour', 'network'] as const;

/**
 * 2-3, the result and its reasons (설계서 2-3, IN-6): the headline the visitor's own run makes true, then the two facts
 * the engine held the request against: the first of its comparisons that departs from the learned pattern and the size
 * against the largest usual export (FP-1, counted by the portal); beside them, for reference, the company records as
 * the business-record rule looked them up, with that rule's own answer. Every value is the run's own record.
 */
export default function ResultPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const key = MAIN_CASES.attacker;
  const options = useLabOptions();
  const found = caseOf(options.data, key);
  const run = useTryRun(key, 1);
  const runId = run.view?.status === 'COMPLETED' || run.stored ? run.runId : null;
  const anatomy = useAnatomy(runId, 1);
  const received = useReceived(runId, 1);
  const baseline = useBaseline(found?.employee.key ?? null);
  const engineActions = useEngineActions();
  const recorded = anatomy.data?.interpretation.recorded ?? null;
  const contexa = run.view?.steps.find((step) => step.stepNo === 1)?.layers.D ?? null;
  const comparison = received.data ?? null;

  if (run.pending) {
    return (
      <MainScreen title={t('main.2-3.title.pending')} main={null}>
        <StateScreen kind="loading" />
      </MainScreen>
    );
  }
  if (runId === null) {
    return (
      <MainScreen
        title={t('main.2-3.title.none')}
        intro={t('main.2-3.intro.none')}
        main={<MainLink to={ROLE_PATHS.attacker.request}>{t('main.console.toRequest')}</MainLink>}
        nextNote={null}
      >
        {null}
      </MainScreen>
    );
  }
  const action = recorded?.finalAction ?? null;
  const items = contexa?.deliveredItems ?? null;
  const title =
    action === null
      ? t('main.2-3.title.pending')
      : action === 'ALLOW' || (items !== null && items > 0)
        ? t('main.2-3.title.through', { items: count(items ?? 0, language) })
        : t(`main.2-3.title.${action}`);
  const first =
    FIRST.find((dimension) =>
      comparison?.usualVsNow.some((row) => row.dimension === dimension && row.inUsual === 'false'),
    ) ?? 'accessHour';
  const firstRow = comparison?.usualVsNow.find((row) => row.dimension === first) ?? null;
  const hourRow = comparison?.usualVsNow.find((row) => row.dimension === 'accessHour') ?? null;
  const hour =
    hourRow?.now !== null && hourRow?.now !== undefined && /^\d+$/.test(hourRow.now)
      ? Number(hourRow.now)
      : null;
  const usualHours = [...(comparison?.usual['accessHour']?.values ?? [])].sort(
    (a, b) => Number(a) - Number(b),
  );
  const ratio = comparison?.sizeRatio ?? null;
  // The two sizes are the engine's own input (the baseline's largest export, the business database's count); the
  // ratio between them is the portal's (FP-1), shown only when it came.
  const largest = ratio ? String(ratio.usualLargest) : (comparison?.usual['size']?.values[0] ?? null);
  const asked = ratio
    ? String(ratio.items)
    : (comparison?.businessFacts.find((fact) => fact.code === 'ITEMS')?.value ?? null);
  // The business-record rule's own answer to this request: it let the data out or refused it.
  const companyRule = run.view?.steps.find((step) => step.stepNo === 1)?.layers.C2 ?? null;
  const companyPassed = companyRule === null ? null : companyRule.deliveredItems > 0;
  return (
    <MainScreen
      title={title}
      intro={
        comparison
          ? t('main.2-3.intro', { n: comparison.departureCount, count: comparison.departureCount }) +
            (action === 'ESCALATE' || action === 'BLOCK' || action === 'CHALLENGE'
              ? ` ${releaseLine(t, action, engineActions.data?.ESCALATE?.ttlSeconds ?? null)}`
              : '')
          : null
      }
    >
      <div className={styles.cards}>
        {first !== 'accessHour' ? (
          <section className={styles.card} aria-labelledby="fact-first">
            <h2 id="fact-first" className={styles.cardLabel}>
              {t(`main.2-3.first.${first}`)}
            </h2>
            {firstRow?.now ? (
              <div className={styles.sizes}>
                <span className={styles.sizeName}>{t('main.2-3.first.usual')}</span>
                <b className={styles.sizeValue}>
                  {(comparison?.usual[first]?.values ?? [])
                    .map((value) => plainValue(t, first, value))
                    .join(' · ')}
                </b>
                <span className={styles.sizeName}>{t('main.2-3.size.now')}</span>
                <span className={styles.sizeBar} data-kind="now">
                  {plainValue(t, first, firstRow.now)}
                </span>
              </div>
            ) : null}
            <p className={styles.cardLine}>{firstRow?.now ? t('main.2-3.first.note') : '…'}</p>
          </section>
        ) : (
          <section className={styles.card} aria-labelledby="fact-hour">
            <h2 id="fact-hour" className={styles.cardLabel}>
              {t('main.2-3.hour.label')}
            </h2>
            {baseline.data ? (
              <HourBars
                hours={baseline.data.learned.hours}
                mark={hour}
                {...(hour === null
                  ? {}
                  : { markLabel: t('dim.hours', { hours: String(hour).padStart(2, '0') }) })}
              />
            ) : null}
            <p className={styles.cardLine}>
              {baseline.data && hour !== null
                ? t('main.2-3.hour.line', {
                    learned: count(baseline.data.learned.requests, language),
                    hours: usualHours.map((value) => plainValue(t, 'accessHour', value)).join(' · '),
                    now: plainValue(t, 'accessHour', String(hour).padStart(2, '0')),
                  })
                : '…'}
            </p>
          </section>
        )}
        <section className={styles.card} aria-labelledby="fact-size">
          <h2 id="fact-size" className={styles.cardLabel}>
            {t('main.2-3.size.label')}
          </h2>
          {largest !== null && asked !== null ? (
            <div className={styles.sizes}>
              <span className={styles.sizeName}>{t('main.2-3.size.usual')}</span>
              <span className={styles.sizeBar} data-kind="usual" />
              <b className={styles.sizeValue}>
                {t('main.items', { count: Number(largest), items: count(Number(largest), language) })}
              </b>
              <span className={styles.sizeName}>{t('main.2-3.size.now')}</span>
              <span className={styles.sizeBar} data-kind="now">
                {t('main.items', { count: Number(asked), items: count(Number(asked), language) })}
              </span>
            </div>
          ) : null}
          <p className={styles.cardLine}>
            {ratio
              ? t('main.2-3.size.line', { times: count(ratio.times, language) })
              : largest !== null && asked !== null
                ? t('main.2-3.size.lineNoRatio', {
                    items: count(Number(asked), language),
                    largest: count(Number(largest), language),
                  })
                : '…'}
          </p>
        </section>
        {/* V-07: the company records are a reference beside the two reasons, not a third; the rule that let the
            attack through reads as a miss, the one that refused it as a stop. */}
        <section className={styles.card} aria-labelledby="fact-company" data-reference>
          <h2 id="fact-company" className={styles.cardLabel}>
            {t('main.2-3.company.label')}
          </h2>
          {companyPassed === null ? null : (
            <p
              className={styles.companyMark}
              data-ok={companyPassed === false || undefined}
              aria-hidden="true"
            >
              <Icon name={companyPassed ? 'cross' : 'check'} className={styles.companyIcon} />
            </p>
          )}
          <b className={styles.companyName}>
            {companyPassed === null
              ? '…'
              : t(companyPassed ? 'main.2-3.company.passed' : 'main.2-3.company.refused', {
                  rule: t('main.lane.C2'),
                })}
          </b>
          <p className={styles.cardLine}>
            {comparison
              ? COMPANY.flatMap((codes) =>
                  comparison.businessFacts.filter((fact) => (codes as readonly string[]).includes(fact.code)),
                )
                  .map((fact) => t(`fact.${fact.code}`, { value: fact.value ?? '' }))
                  .join(' · ')
              : '…'}
          </p>
        </section>
      </div>
      <ProofPanel runId={runId} threat />
      <div className={styles.links}>
        <SourceBadge kind="run" label={t('badge.run')} runId={runId} />
        <GhostButton onClick={() => detail.show(runId, 1, 'summary')}>{t('main.2-3.reasons')}</GhostButton>
        <span className={styles.linkNote}>{t('main.2-3.nextNote')}</span>
      </div>
    </MainScreen>
  );
}

/**
 * What lifts the visitor's stopped request (FU-2): an extra check, a release with the administrator's approval, or for
 * a held request the hold the engine publishes, after which asking again turns it into a block.
 */
function releaseLine(
  t: ReturnType<typeof useTranslation>['t'],
  action: string,
  holdSeconds: number | null,
): string {
  if (action !== 'ESCALATE') {
    return t(`main.2-3.release.${action}`);
  }
  return holdSeconds !== null && holdSeconds % 60 === 0
    ? t('main.2-3.release.ESCALATE', { minutes: holdSeconds / 60 })
    : t('main.2-3.releasePlain.ESCALATE');
}
