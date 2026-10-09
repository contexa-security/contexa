import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import type { BenchmarkView } from '../../api/benchmark';
import { ActionChip } from '../../components/common/ActionChip';
import { useUrlModal } from '../../components/common/useUrlModal';
import { Icon } from '../../components/Icon';
import { NextLink } from '../../components/journey/StepParts';
import { CONTROL_ORDER } from '../../domain/verdict';
import { SourceMark } from '../../components/common/SourceMark';
import { count, dollars, seconds } from '../../journey/format';
import experience from '../try/Experience.module.css';
import { BenchScreen } from './BenchScreen';
import { controlName, useBenchView } from './benchData';
import { BENCH_MODALS, percent, useBenchSetting } from './benchPlace';
import styles from './Bench.module.css';

const PAGE_ROWS = 10;
const TABS = ['attack', 'normal', 'uncertain', 'ops'] as const;
type Tab = (typeof TABS)[number];
const CLASSIFICATION: Readonly<Record<Exclude<Tab, 'ops'>, 'THREAT' | 'NORMAL' | 'UNCERTAIN'>> = {
  attack: 'THREAT',
  normal: 'NORMAL',
  uncertain: 'UNCERTAIN',
};

/**
 * B2, case by case (bench-2, 7.8): the attack cases, the normal-work cases, the cases whose answer is disputed and the
 * operations figures as tabs; the cases Contexa got wrong as a filter; ten rows a page. A cell is the runs handled as
 * the ground truth says over the scored runs; a row opens its case. The tab, the filter and the page are in the
 * address.
 */
export default function BenchCasesPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const { search } = useBenchSetting();
  const { view, empty, state } = useBenchView();
  const asked = params.get('tab');
  const tab: Tab = (TABS as readonly string[]).includes(asked ?? '') ? (asked as Tab) : 'attack';
  const set = (changes: Readonly<Record<string, string | null>>) => {
    const next = new URLSearchParams(params);
    Object.entries(changes).forEach(([key, value]) =>
      value === null ? next.delete(key) : next.set(key, value),
    );
    setParams(next, { replace: true });
  };
  const shownTabs = TABS.filter((name) => name !== 'uncertain' || (view?.caseCounts.UNCERTAIN ?? 0) > 0);
  return (
    <BenchScreen
      view="cases"
      title={t('benchmark.cases.title')}
      purpose={t('benchmark.cases.purpose')}
      source={
        view?.spec ? (
          <SourceMark kind="MEASUREMENT" measured>
            {t('benchmark.cases.source', {
              protocol: view.scope.protocols.map((protocol) => protocol.protocolId).join(', '),
              setting: view.spec.settingHash.slice(0, 12),
            })}
          </SourceMark>
        ) : null
      }
      back={{ to: `/benchmark${search}`, label: t('benchmark.toSummary') }}
      main={<NextLink to={`/benchmark/judgment${search}`} label={t('benchmark.toJudgment')} />}
    >
      {state}
      {empty ? <p className={experience.lead}>{t('bench.empty')}</p> : null}
      {view ? (
        <>
          <div className={styles.filters} role="tablist" aria-label={t('benchmark.cases.tabs')}>
            {shownTabs.map((name) => (
              <button
                key={name}
                type="button"
                role="tab"
                className={styles.filter}
                aria-selected={tab === name}
                onClick={() => set({ tab: name === 'attack' ? null : name, wrong: null, page: null })}
              >
                {name === 'ops'
                  ? t('benchmark.cases.tab.ops')
                  : t(`benchmark.cases.tab.${name}`, { n: view.caseCounts[CLASSIFICATION[name]] })}
              </button>
            ))}
          </div>
          <section
            role="tabpanel"
            aria-label={t(`benchmark.cases.tabName.${tab}`)}
            className={styles.windowPart}
          >
            {tab === 'ops' ? <Operations view={view} /> : <Cases view={view} tab={tab} set={set} />}
          </section>
        </>
      ) : null}
    </BenchScreen>
  );
}

interface CasesProps {
  readonly view: BenchmarkView;
  readonly tab: Exclude<Tab, 'ops'>;
  readonly set: (changes: Readonly<Record<string, string | null>>) => void;
}

function Cases({ view, tab, set }: CasesProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params] = useSearchParams();
  const benchCase = useUrlModal(BENCH_MODALS.benchCase, ['case']);
  const classification = CLASSIFICATION[tab];
  const wrongOnly = params.get('wrong') === '1' && tab !== 'uncertain';
  const rows = view.cases.filter(
    (row) => row.classification === classification && (!wrongOnly || row.contexaWrong),
  );
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_ROWS));
  const page = Math.min(pages, Math.max(1, Number(params.get('page') ?? 1) || 1));
  const shown = rows.slice((page - 1) * PAGE_ROWS, page * PAGE_ROWS);
  return (
    <>
      {tab !== 'uncertain' ? (
        <div className={styles.filters} role="group" aria-label={t('benchmark.cases.filter')}>
          <button
            type="button"
            className={styles.filter}
            aria-pressed={!wrongOnly}
            onClick={() => set({ wrong: null, page: null })}
          >
            {t('benchmark.cases.all')}
          </button>
          <button
            type="button"
            className={styles.filter}
            aria-pressed={wrongOnly}
            onClick={() => set({ wrong: '1', page: null })}
          >
            {t('benchmark.cases.wrong', { n: view.contexaWrongCases[classification] })}
          </button>
        </div>
      ) : (
        <p className={experience.lead}>{t('benchmark.cases.uncertainNote')}</p>
      )}
      {shown.length === 0 ? <p className={experience.lead}>{t('benchmark.cases.none')}</p> : null}
      {shown.length > 0 ? (
        <table className={styles.table}>
          <caption className={styles.footnote}>{t('benchmark.cases.caption')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('benchmark.cases.case')}</th>
              {CONTROL_ORDER.map((control) => (
                <th key={control} scope="col">
                  {controlName(t, control)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((row) => (
              <tr key={row.key}>
                <th scope="row">
                  <button
                    type="button"
                    className={styles.rowButton}
                    onClick={() => benchCase.show({ case: row.key })}
                  >
                    <span>
                      {row.title[language] ?? row.key}
                      <span className={styles.caseKey} data-original>
                        {row.key}
                      </span>
                    </span>
                    <Icon name="chevronRight" className={styles.rowIcon} />
                  </button>
                </th>
                {CONTROL_ORDER.map((control) => {
                  const cell = row.cells[control];
                  return (
                    <td
                      key={control}
                      className={styles.cell}
                      data-state={cell?.state ?? 'NONE'}
                      data-label={controlName(t, control)}
                    >
                      <span className={styles.value}>{cell ? `${cell.right}/${cell.counted}` : '-'}</span>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      {pages > 1 ? (
        <nav className={styles.pager} aria-label={t('benchmark.cases.pages')}>
          <ActionChip
            icon="arrowLeft"
            size="sm"
            disabled={page <= 1}
            onClick={() => set({ page: page - 1 <= 1 ? null : String(page - 1) })}
          >
            {t('benchmark.cases.previous')}
          </ActionChip>
          <span className={styles.pageNow}>{t('benchmark.cases.page', { page, pages })}</span>
          <ActionChip
            icon="arrowRight"
            size="sm"
            disabled={page >= pages}
            onClick={() => set({ page: String(page + 1) })}
          >
            {t('benchmark.cases.next')}
          </ActionChip>
        </nav>
      ) : null}
      <p className={styles.footnote}>{t('benchmark.footnote')}</p>
    </>
  );
}

/** The operations figures (bench-2 '운영 지표'): what one decision takes and what visitors did, apart from the scores. */
function Operations({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const engine = view.engine;
  const observations = view.observations;
  return (
    <>
      {engine ? (
        <dl className={styles.bigNumbers}>
          <div>
            <dt>{t('benchmark.ops.time')}</dt>
            <dd>
              {engine.analysisP50Ms === null
                ? '-'
                : t('detail.seconds', { s: seconds(engine.analysisP50Ms) })}
            </dd>
          </div>
          <div>
            <dt>{t('benchmark.ops.cost')}</dt>
            <dd>{engine.costPerDecisionUsd === null ? '-' : `$${dollars(engine.costPerDecisionUsd)}`}</dd>
          </div>
          <div>
            <dt>{t('benchmark.ops.decisions')}</dt>
            <dd>{count(engine.decisions, language)}</dd>
          </div>
        </dl>
      ) : null}
      {engine ? (
        <p className={experience.lead}>
          {t('benchmark.ops.detail', {
            p95: engine.analysisP95Ms === null ? '-' : seconds(engine.analysisP95Ms),
            tokens:
              engine.tokensPerDecision === null ? '-' : count(Math.round(engine.tokensPerDecision), language),
            calls: engine.modelCallsPerDecision === null ? '-' : engine.modelCallsPerDecision.toFixed(1),
          })}
        </p>
      ) : null}
      {engine?.priceSource ? (
        <p className={styles.footnote}>
          {t('benchmark.ops.price')} <code data-original>{engine.priceSource}</code>
        </p>
      ) : null}
      <section className={styles.windowPart} aria-labelledby="ops-visitors">
        <h2 id="ops-visitors" className={experience.panelTitle}>
          {t('benchmark.ops.visitors')}
        </h2>
        <ul className={styles.plainList}>
          <li>
            {t('benchmark.ops.runs', {
              live: count(observations.liveRuns, language),
              lab: count(observations.labRuns, language),
            })}
          </li>
          <li>
            {t('benchmark.ops.predictions', {
              hits: observations.predictions.hits,
              total: observations.predictions.total,
              rate: percent(observations.predictions.rate),
            })}
          </li>
          <li>
            {t('benchmark.ops.assessments', {
              n: count(observations.assessments, language),
              people: count(observations.assessors, language),
            })}
          </li>
        </ul>
        <p className={styles.footnote}>{t('benchmark.ops.apart')}</p>
      </section>
    </>
  );
}
