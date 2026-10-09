import { useTranslation } from 'react-i18next';
import { useBenchmark } from '../../api/benchmark';
import { useJourney, type RecapLine } from '../../api/journey';
import { useVisitor } from '../../api/queries';
import { ActionChip } from '../../components/common/ActionChip';
import { useDetail } from '../../components/detail/useDetail';
import { SourceMark } from '../../components/common/SourceMark';
import { DifferenceMark, IdentityDefinition, IdentityLine } from '../../components/journey/JourneyParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import { VerdictChip } from '../../components/VerdictChip';
import { DIFFERENCES } from '../../journey/journey';
import { count, utcTime } from '../../journey/format';
import { useJourneyPlace } from '../../journey/useJourneyPlace';
import { VERDICTS, type Verdict } from '../../domain/verdict';
import styles from './RecapPage.module.css';

/** The existing approaches in the order of the five approaches (g3-five), Contexa apart. */
const EXISTING = ['A', 'B', 'C1', 'C2'] as const;

/** The differences each designed case of the default route shows (thread slide; the recap wire's last column). */
const SHOWN: Readonly<Record<string, readonly number[]>> = {
  A3: [1, 2, 4, 5],
  A3A: [1],
  A3T: [3, 5],
  A6T: [6],
  A6: [6],
};

/** The engine's recorded action as a verdict the chip draws; null for none. */
function verdictOf(action: string | null): Verdict | null {
  return action !== null && action in VERDICTS ? (action as Verdict) : null;
}

/** The cases whose "what you did" has its own words in the dictionary; any other case is named by its title. */
const OWN_WORDS = new Set(['A3', 'A3A', 'A3T', 'A3TA', 'A6T', 'A6']);

/**
 * What you did (recap, 7.4): every run the visitor sent, with what Contexa and the existing approaches did in it as
 * recorded and the differences it showed; the six differences; and the definition seen at the start, now checked. A
 * skipped try is not in the table; a run sent again is. Each row opens the run's decision in detail.
 */
export default function RecapPage() {
  const { t, i18n } = useTranslation();
  const detail = useDetail();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const place = useJourneyPlace();
  const benchmark = useBenchmark(null);
  const titles = new Map((benchmark.data?.cases ?? []).map((entry) => [entry.key, entry.title]));
  const runs = (journey.data?.runs ?? []).filter((line) => line.status === 'COMPLETED');
  const seen = new Set(place.differences);
  const did = (line: RecapLine) => {
    const items = line.requestedItems === null ? '-' : count(line.requestedItems, language);
    const words = OWN_WORDS.has(line.scenarioKey)
      ? t(`recap.did.${line.scenarioKey}`, { items, steps: line.steps })
      : (titles.get(line.scenarioKey)?.[language] ?? t('recap.did.other'));
    return line.lab ? t('recap.lab', { words }) : words;
  };
  return (
    <RouteScreen
      title={t('recap.title')}
      purpose={t('recap.purpose')}
      source={
        runs.length > 0 ? (
          <SourceMark kind="ENGINE">
            {t('recap.source', {
              n: count(runs.length, language),
              runs: runs
                .map((line) => (line.startedAt ? `${line.runId} ${utcTime(line.startedAt)}` : line.runId))
                .join(', '),
            })}
          </SourceMark>
        ) : null
      }
      nextLabel={t('recap.next')}
      more={
        <ActionChip to="/lab" icon="refresh" variant="open">
          {t('recap.lab.try')}
        </ActionChip>
      }
    >
      {journey.isPending ? <StateScreen kind="loading" /> : null}
      {journey.isSuccess && runs.length === 0 ? (
        <div className={styles.empty}>
          <p>{t('recap.empty')}</p>
          <ActionChip to="/try/attacker/scene" icon="play" variant="move" size="sm">
            {t('recap.emptyStart')}
          </ActionChip>
        </div>
      ) : null}
      {runs.length > 0 ? (
        <table className={styles.table}>
          <caption className={styles.caption}>{t('recap.caption')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('recap.col.did')}</th>
              <th scope="col">{t('recap.col.contexa')}</th>
              <th scope="col">{t('recap.col.existing')}</th>
              <th scope="col">{t('recap.col.difference')}</th>
              <th scope="col">
                <span className={styles.hidden}>{t('recap.col.open')}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {runs.map((line) => (
              <tr key={line.runId}>
                <th scope="row" className={styles.did} data-label={t('recap.col.did')}>
                  {did(line)}
                </th>
                <td data-label={t('recap.col.contexa')}>
                  <span className={styles.engine}>
                    {verdictOf(line.engineAction) ? (
                      <VerdictChip verdict={verdictOf(line.engineAction) ?? 'NONE'} />
                    ) : null}
                    <span>
                      {t('recap.engine', {
                        result: t(`recap.result.${line.business['D'] ?? 'NONE'}`),
                        items: count(line.exposedItems, language),
                      })}
                    </span>
                    {line.correct === false ? <span className={styles.wrong}>{t('recap.wrong')}</span> : null}
                  </span>
                </td>
                <td data-label={t('recap.col.existing')}>
                  <ExistingResults business={line.business} />
                </td>
                <td data-label={t('recap.col.difference')}>
                  {(SHOWN[line.scenarioKey] ?? []).length > 0 ? (
                    <span className={styles.marks}>
                      {(SHOWN[line.scenarioKey] ?? []).map((difference) => (
                        <DifferenceMark key={difference} difference={difference} seen />
                      ))}
                      <span className={styles.hidden}>
                        {(SHOWN[line.scenarioKey] ?? [])
                          .map((difference) => t(`difference.${difference}`))
                          .join(', ')}
                      </span>
                    </span>
                  ) : (
                    <span aria-label={t('recap.noDifference')}>-</span>
                  )}
                </td>
                <td className={styles.open}>
                  <ActionChip onClick={() => detail.show(line.runId)} icon="search" variant="open" size="sm">
                    {t('recap.open')}
                  </ActionChip>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      <section className={styles.differences} aria-labelledby="recap-differences">
        <h2 id="recap-differences" className={styles.sectionTitle}>
          {t('recap.differences', { n: place.differences.length })}
        </h2>
        <ol className={styles.differenceList}>
          {DIFFERENCES.map((difference) => (
            <li key={difference} className={styles.difference} data-seen={seen.has(difference) || undefined}>
              <DifferenceMark difference={difference} seen={seen.has(difference)} />
              {t(`difference.${difference}`)}
            </li>
          ))}
        </ol>
      </section>
      <section className={styles.definition} aria-labelledby="recap-definition">
        <h2 id="recap-definition" className={styles.sectionTitle}>
          {t('recap.definitionLead')}
        </h2>
        {place.route === 'DEFAULT' ? <IdentityLine /> : null}
        <IdentityDefinition />
      </section>
    </RouteScreen>
  );
}

/** The existing approaches' recorded results, each result once with the approaches that had it. */
function ExistingResults({ business }: { readonly business: Readonly<Record<string, string>> }) {
  const { t } = useTranslation();
  const byResult = new Map<string, string[]>();
  for (const control of EXISTING) {
    const result = business[control];
    if (result) {
      byResult.set(result, [...(byResult.get(result) ?? []), t(`control.${control}.name`)]);
    }
  }
  return (
    <ul className={styles.existing}>
      {[...byResult.entries()].map(([result, names]) => (
        <li key={result}>
          <span className={styles.result} data-result={result}>
            {t(`recap.result.${result}`)}
          </span>{' '}
          {names.join(', ')}
        </li>
      ))}
    </ul>
  );
}
