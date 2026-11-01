import { useTranslation } from 'react-i18next';
import { Link, useSearchParams } from 'react-router-dom';
import { useCases } from '../../../api/anatomy';
import type { BenchmarkCase, BenchmarkView } from '../../../api/benchmark';
import { inCurrentWords } from '../../../domain/caseWords';
import { formatNumber } from '../../format';
import { useMedia, DRAWER_QUERY } from '../../useMedia';
import { Badge, DetailGroup, DetailPanel, Drawer, Switch } from '../../ui';
import { CONTROLS } from '../../validation/shapes';
import { DotLegend, RunDots } from './ValidationParts';
import styles from './Validation.module.css';

const KINDS = ['THREAT', 'NORMAL', 'UNCERTAIN'] as const;

/**
 * 시나리오별 (옛 B-cases · B-case, DEC-51): every scenario against the five controls, a dot per run with its result,
 * grouped by the server's named groups (the scenarios the rules were not written for first) and then by kind; the
 * scenario chosen (`?case=`) opens beside the list (a drawer below 1024 wide) with what handling it right means and why.
 */
export default function ScenariosTab({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const [params, setParams] = useSearchParams();
  const narrow = useMedia(DRAWER_QUERY);
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const n = (value: number) => formatNumber(value, i18n.language);
  const wrongOnly = params.get('wrong') === '1';
  const chosen = params.get('case');
  const set = (key: string, value: string | null) => {
    const next = new URLSearchParams(params);
    if (value) {
      next.set(key, value);
    } else {
      next.delete(key);
    }
    setParams(next, { replace: true });
  };
  const nameOf = (row: BenchmarkCase) => row.title[language] ?? row.key;
  const byKey = new Map(view.cases.map((row) => [row.key, row]));
  const named = new Set(view.suites.flatMap((suite) => suite.cases));
  const groups = [
    ...view.suites.map((suite) => ({
      key: suite.suite,
      title: t(`ux.validation.suite.${suite.suite}`, { defaultValue: suite.suite }),
      rows: suite.cases.flatMap((key) => (byKey.has(key) ? [byKey.get(key) as BenchmarkCase] : [])),
    })),
    ...KINDS.map((kind) => ({
      key: kind,
      title: t(`ux.validation.kind.${kind}`),
      rows: view.cases.filter((row) => row.classification === kind && !named.has(row.key)),
    })),
  ]
    .map((group) => ({ ...group, rows: group.rows.filter((row) => !wrongOnly || row.contexaWrong) }))
    .filter((group) => group.rows.length > 0)
    // The scenarios the rules were not written for first, then the others in the server's order.
    .sort((a, b) => Number(b.key === 'RULE_BLIND') - Number(a.key === 'RULE_BLIND'));
  const detail = chosen !== null ? <CaseDetail view={view} caseKey={chosen} /> : null;
  if (view.cases.length === 0) {
    return <p className={styles.line}>{t('ux.validation.cases.none')}</p>;
  }
  return (
    <div className={styles.casesLayout} data-panel={(chosen !== null && !narrow) || undefined}>
      <div className={styles.stack}>
        <p className={styles.line}>
          {t('ux.validation.cases.counts', {
            attacks: n(view.caseCounts.THREAT),
            attacksWrong: n(view.contexaWrongCases.THREAT),
            normals: n(view.caseCounts.NORMAL),
            normalsWrong: n(view.contexaWrongCases.NORMAL),
            open: n(view.caseCounts.UNCERTAIN),
          })}
        </p>
        <DotLegend />
        <Switch
          label={t('ux.validation.cases.wrongOnly')}
          checked={wrongOnly}
          onChange={(next) => set('wrong', next ? '1' : null)}
        />
        {groups.map((group) => (
          <section key={group.key} className={styles.caseGroup} aria-labelledby={`cases-${group.key}`}>
            <h3 id={`cases-${group.key}`} className={styles.groupTitle}>
              {group.title} <span className={styles.sub}>{n(group.rows.length)}</span>
            </h3>
            <div className={styles.scroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
              <table className={styles.table} data-stack>
                <caption className="ux-sr-only">{group.title}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t('ux.validation.col.case')}</th>
                    {CONTROLS.map((control) => (
                      <th key={control} scope="col">
                        {t(`ux.control.short.${control}`)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {group.rows.map((row) => (
                    <tr key={row.key} aria-current={row.key === chosen ? 'true' : undefined}>
                      <th scope="row">
                        <Link
                          to={`?${withParam(params, 'case', row.key)}`}
                          replace
                          className={styles.caseLink}
                        >
                          {nameOf(row)}
                        </Link>
                        <span className={styles.caseMeta}>
                          <span className={styles.sub}>{row.key}</span>
                          <Badge tone="line">
                            {t(`ux.validation.answer.${row.classification}`, {
                              defaultValue: row.classification,
                            })}
                          </Badge>
                        </span>
                      </th>
                      {CONTROLS.map((control) => (
                        <td key={control} data-k={t(`ux.control.short.${control}`)}>
                          <RunDots
                            label={t('ux.validation.cases.dots', {
                              name: nameOf(row),
                              control: t(`ux.control.short.${control}`),
                            })}
                            runs={Object.entries(row.runResults ?? {}).map(([runId, results]) => ({
                              runId,
                              result: results[control] ?? 'NOT_SCORED',
                            }))}
                          />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        ))}
        <p className={styles.note}>{t('ux.validation.footnote')}</p>
      </div>
      {chosen !== null && !narrow ? (
        <DetailPanel title={chosenTitle(view, chosen, language)} onClose={() => set('case', null)}>
          {detail}
        </DetailPanel>
      ) : null}
      {narrow ? (
        <Drawer
          open={chosen !== null}
          onClose={() => set('case', null)}
          title={chosen ? chosenTitle(view, chosen, language) : ''}
        >
          {chosen ? <div className={styles.drawerGroups}>{detail}</div> : null}
        </Drawer>
      ) : null}
    </div>
  );
}

function withParam(params: URLSearchParams, key: string, value: string): string {
  const next = new URLSearchParams(params);
  next.set(key, value);
  return next.toString();
}

function chosenTitle(view: BenchmarkView, key: string, language: 'ko' | 'en'): string {
  const row = view.cases.find((candidate) => candidate.key === key);
  return row ? `${row.title[language] ?? row.key} (${row.key})` : key;
}

/**
 * A scenario (옛 상황 창): what handling it right means and why, the handlings that count as right, every control's times
 * handled right over times counted, and the runs sent in it, each opening its decision details.
 */
function CaseDetail({ view, caseKey }: { readonly view: BenchmarkView; readonly caseKey: string }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const n = (value: number) => formatNumber(value, i18n.language);
  const catalog = useCases();
  const row = view.cases.find((candidate) => candidate.key === caseKey) ?? null;
  if (!row) {
    // ST-62: a scenario the record does not hold.
    return <p className={styles.note}>{t('ux.validation.case.notFound')}</p>;
  }
  const definition = catalog.data?.cases.find((candidate) => candidate.key === caseKey) ?? null;
  const answer = row.classification === 'THREAT' ? 'stop' : row.classification === 'NORMAL' ? 'pass' : 'none';
  return (
    <>
      <DetailGroup title={t('ux.validation.case.truth')}>
        <p className={styles.caseAnswer}>
          <Badge tone="line">{t(`ux.validation.case.answer.${answer}`)}</Badge>
        </p>
        {definition && definition.allowedActions.length > 0 ? (
          <p className={styles.chips}>
            <span className={styles.sub}>{t('ux.validation.case.allowed')}</span>
            {definition.allowedActions.map((action) => (
              <Badge key={action} tone="line">
                {t(`ux.validation.action.${action}`, { defaultValue: action })}
              </Badge>
            ))}
          </p>
        ) : null}
        {definition?.allowedActions.includes('ESCALATE') ? (
          <p className={styles.note}>{t('ux.validation.case.held')}</p>
        ) : null}
        {definition?.rationale[language] ? (
          <p className={styles.para}>{inCurrentWords(definition.rationale[language], language)}</p>
        ) : null}
        {definition?.counterpoint[language] ? (
          <details className={styles.more}>
            <summary>{t('ux.validation.case.counterpoint')}</summary>
            <p className={styles.para}>{inCurrentWords(definition.counterpoint[language], language)}</p>
          </details>
        ) : null}
      </DetailGroup>
      <DetailGroup title={t('ux.validation.case.cells')}>
        <dl className={styles.kv}>
          {CONTROLS.map((control) => {
            const cell = row.cells[control];
            return (
              <div key={control}>
                <dt>{t(`ux.control.short.${control}`)}</dt>
                <dd data-state={cell?.state ?? 'NONE'}>
                  {cell
                    ? t('ux.validation.case.cell', {
                        score: t(
                          answer === 'stop'
                            ? 'ux.validation.score.stoppedAny'
                            : 'ux.validation.score.notBlocked',
                        ),
                        right: n(cell.right),
                        counted: n(cell.counted),
                      })
                    : // ST-63: a scenario without a set answer is not counted.
                      t('ux.validation.notCounted')}
                </dd>
              </div>
            );
          })}
        </dl>
      </DetailGroup>
      <DetailGroup title={t('ux.validation.case.runs', { n: n(row.runs) })}>
        <ul className={styles.runLinks}>
          {row.runIds.map((runId) => (
            <li key={runId}>
              <Link to={`/runs/${encodeURIComponent(runId)}`} className={styles.code}>
                {runId}
              </Link>
            </li>
          ))}
        </ul>
      </DetailGroup>
    </>
  );
}
