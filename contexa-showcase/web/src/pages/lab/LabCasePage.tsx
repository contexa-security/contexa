import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useBenchmark } from '../../api/benchmark';
import { useLabOptions } from '../../api/lab';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { LabScreen } from './LabScreen';
import styles from './LabPages.module.css';

const PAGE = 6;
const FILTERS = ['all', 'attack', 'normal'] as const;
type Filter = (typeof FILTERS)[number];

const CLASS_OF: Readonly<Record<Exclude<Filter, 'all'>, string>> = { attack: 'THREAT', normal: 'NORMAL' };

/**
 * L1, picking a case (lab-1, 7.6): every designed case as a card with its employee and situation, its right answer
 * (the case definition's) and how often Contexa got it right in the measurement (the benchmark's count), six at a
 * time with a filter. The picked case and the filter are in the address.
 */
export default function LabCasePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params, setParams] = useSearchParams();
  const options = useLabOptions();
  const benchmark = useBenchmark(null).data ?? null;
  const filter: Filter =
    params.get('filter') === 'attack' || params.get('filter') === 'normal'
      ? (params.get('filter') as Filter)
      : 'all';
  const picked = params.get('case');
  const cases = (options.data?.cases ?? []).filter(
    (candidate) => filter === 'all' || candidate.classification === CLASS_OF[filter],
  );
  // The picked case is always on screen: the list opens as far as its card, six at a time.
  const pickedAt = cases.findIndex((candidate) => candidate.key === picked);
  const shown = Math.max(
    PAGE,
    Number(params.get('show') ?? PAGE) || PAGE,
    pickedAt < 0 ? 0 : Math.ceil((pickedAt + 1) / PAGE) * PAGE,
  );
  const set = (changes: Record<string, string | null>) => {
    const next = new URLSearchParams(params);
    Object.entries(changes).forEach(([key, value]) =>
      value === null ? next.delete(key) : next.set(key, value),
    );
    setParams(next, { replace: true });
  };
  return (
    <LabScreen
      step="case"
      title={t('labCase.title')}
      purpose={t('labCase.purpose')}
      source={
        benchmark?.spec ? (
          <SourceMark kind="MEASUREMENT" measured>
            {t('labCase.source', { setting: benchmark.spec.settingHash.slice(0, 8) })}
          </SourceMark>
        ) : null
      }
      back={{ to: '/lab', label: t('labCase.back') }}
      more={
        cases.length > shown ? (
          <ActionChip icon="chevronDown" variant="open" onClick={() => set({ show: String(shown + PAGE) })}>
            {t('labCase.more', { shown, n: cases.length })}
          </ActionChip>
        ) : null
      }
      main={
        picked ? (
          <NextLink to={`/lab/change?case=${encodeURIComponent(picked)}`} label={t('labCase.next')} />
        ) : (
          <span className={styles.mainHint}>{t('labCase.pickFirst')}</span>
        )
      }
    >
      <div className={styles.filters} role="group" aria-label={t('labCase.filter')}>
        {FILTERS.map((value) => (
          <button
            key={value}
            type="button"
            className={styles.filter}
            aria-pressed={filter === value}
            onClick={() => set({ filter: value === 'all' ? null : value, show: null })}
          >
            {t(`labCase.filters.${value}`)}
          </button>
        ))}
      </div>
      {options.isPending ? <StateScreen kind="loading" /> : null}
      <ul className={styles.cards} aria-label={t('labCase.title')}>
        {cases.slice(0, shown).map((labCase) => {
          const employee = options.data?.employees.find((entry) => entry.key === labCase.conditions.employee);
          const cell = benchmark?.cases.find((entry) => entry.key === labCase.key)?.cells.D ?? null;
          const answer =
            labCase.classification === 'THREAT'
              ? 'stop'
              : labCase.classification === 'NORMAL'
                ? 'pass'
                : 'none';
          return (
            <li key={labCase.key}>
              <button
                type="button"
                className={styles.card}
                aria-pressed={picked === labCase.key}
                onClick={() => set({ case: labCase.key })}
              >
                <span className={styles.cardTitle}>
                  <span data-original>{employee?.displayName ?? '-'}</span> ·{' '}
                  {labCase.title[language] ?? labCase.key}
                </span>
                <span className={styles.answer} data-answer={answer}>
                  {t(`labCase.answer.${answer}`)}
                </span>
                <span className={styles.measured}>
                  {cell && cell.counted > 0
                    ? t('labCase.contexa', { k: cell.right, n: cell.counted })
                    : t('labCase.contexaNone')}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </LabScreen>
  );
}
