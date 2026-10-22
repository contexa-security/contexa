import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useBenchmark, type BenchmarkCase } from '../../api/benchmark';
import { useLabOptions, type LabCase, type LabOptions } from '../../api/lab';
import { SourceLine } from '../../components/journey/FrameParts';
import { NextLink } from '../../components/journey/StepParts';
import { Icon } from '../../components/Icon';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import { LabField } from './LabField';
import { LabScreen } from './LabScreen';
import { expectationOf, situationName, type Expectation } from './labPlace';
import styles from './LabScreens.module.css';

/** The groups of the list, in the order a visitor reads them: what to stop, what to let through, the rest. */
const GROUPS: readonly Expectation[] = ['stop', 'pass', 'none'];

/** Who the case's employee is, by name (the business database's own) and role. */
function Who({ labCase, options }: { readonly labCase: LabCase; readonly options: LabOptions }) {
  const { t } = useTranslation();
  const employee = options.employees.find((entry) => entry.key === labCase.conditions.employee);
  return employee ? (
    <>
      <span data-original>{employee.displayName}</span> · {t(`lab.role.${employee.role}`)}
    </>
  ) : (
    <>-</>
  );
}

/**
 * How often Contexa handled the case as its definition says in the repeated sends (the benchmark's count), in words
 * that say which handling was right; a case with nothing set in advance is not counted.
 */
function contexaLine(
  t: TFunction,
  expectation: Expectation,
  cell: NonNullable<BenchmarkCase['cells']['D']> | null,
  language: string,
): string {
  if (expectation === 'none') {
    return t('lab.r7.case.contexa.unscored');
  }
  if (!cell || cell.counted === 0) {
    return t('lab.r7.case.contexa.none');
  }
  return t(`lab.r7.case.contexa.${expectation}`, {
    k: count(cell.right, language),
    n: count(cell.counted, language),
  });
}

/**
 * Picking a situation (화면재편 R7, T3): one list of every designed case, grouped by what its definition sets (a request
 * to stop, one to let through, or nothing), and the picked one as one card: who, what is set in advance and how often
 * Contexa handled it so in the repeated sends. The pick is in the address.
 */
export default function LabCasePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params, setParams] = useSearchParams();
  const options = useLabOptions();
  const benchmark = useBenchmark(null);
  const cases = options.data?.cases ?? [];
  const picked = cases.find((candidate) => candidate.key === params.get('case')) ?? null;
  const expectation = picked ? expectationOf(picked.classification) : 'none';
  const measured = picked ? (benchmark.data?.cases.find((entry) => entry.key === picked.key) ?? null) : null;
  const cell = measured?.cells.D ?? null;
  const counted = expectation !== 'none' && cell !== null && cell.counted > 0;

  return (
    <LabScreen
      step="case"
      type="T3"
      title={t('lab.r7.case.title')}
      purpose={t('lab.r7.case.guide')}
      sourceLine={counted ? <SourceLine kind="measured" /> : null}
      back={{ to: '/lab', label: t('frame.back') }}
      main={
        picked ? (
          <NextLink to={`/lab/change?case=${encodeURIComponent(picked.key)}`} label={t('lab.r7.case.next')} />
        ) : (
          // L-20: the way on shows where it will be, off until a pick, with the reason beside it.
          <>
            <span className={styles.offNote}>{t('lab.r7.case.pickFirst')}</span>
            <button type="button" className={styles.nextOff} data-main disabled>
              {t('lab.r7.case.next')}
              <Icon name="arrowRight" />
            </button>
          </>
        )
      }
    >
      {options.isPending ? <StateScreen kind="loading" /> : null}
      {options.data ? (
        <LabField label={t('lab.r7.case.label')}>
          {(id) => (
            <select
              id={id}
              className={styles.select}
              value={picked?.key ?? ''}
              onChange={(event) => setParams({ case: event.target.value }, { replace: true })}
            >
              <option value="" disabled>
                {t('lab.r7.case.placeholder')}
              </option>
              {GROUPS.map((group) => {
                const members = cases.filter(
                  (candidate) => expectationOf(candidate.classification) === group,
                );
                return members.length > 0 ? (
                  <optgroup key={group} label={t(`lab.r7.case.group.${group}`)}>
                    {members.map((labCase) => (
                      <option key={labCase.key} value={labCase.key}>
                        {situationName(t, labCase.key, labCase.title, language)}
                      </option>
                    ))}
                  </optgroup>
                ) : null;
              })}
            </select>
          )}
        </LabField>
      ) : null}
      {picked && options.data ? (
        <section className={styles.card} aria-labelledby="lab-picked">
          <h2 id="lab-picked" className={styles.cardTitle}>
            {situationName(t, picked.key, picked.title, language)}
          </h2>
          <dl className={styles.facts} data-lines>
            <div>
              <dt>{t('lab.r7.case.who')}</dt>
              <dd>
                <Who labCase={picked} options={options.data} />
              </dd>
            </div>
            <div>
              <dt>{t('lab.r7.case.expect.label')}</dt>
              <dd>{t(`lab.r7.case.expect.${expectation}`)}</dd>
            </div>
            <div>
              <dt>{t('lab.r7.case.contexa.label')}</dt>
              <dd>
                {benchmark.isPending ? t('state.loading') : contexaLine(t, expectation, cell, language)}
              </dd>
            </div>
          </dl>
        </section>
      ) : null}
    </LabScreen>
  );
}
