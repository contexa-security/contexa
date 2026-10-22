import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import type { BeforeSendView } from '../../api/anatomy';
import { useLabBefore, useLabOptions } from '../../api/lab';
import { useDetail } from '../../components/detail/useDetail';
import { SourceLine } from '../../components/journey/FrameParts';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import { LabScreen } from './LabScreen';
import { CONDITION_KEYS, conditionText, expectationOf, labQuery, lineState, readChanges } from './labPlace';
import styles from './LabScreens.module.css';

/** The comparison's three lines: differences from usual, company records flagged, minimum response rules. */
const ROWS = ['usual', 'company', 'line'] as const;
type Row = (typeof ROWS)[number];

/** The minimum response rules the engine found met, by their plain names (a rule without one keeps its code). */
function metRules(t: TFunction, view: BeforeSendView): string | null {
  const met = (view.minimumRules?.rules ?? []).filter((rule) => rule.met === true);
  return met.length === 0
    ? null
    : met.map((rule) => t(`lab.r7.before.rule.${rule.code}`, { defaultValue: rule.code })).join(' · ');
}

/**
 * One line's value in one run as the engine received it; a dash without a run. The line of the rules names the rules
 * the engine found met (V-29), so "applies" says which.
 */
function value(t: TFunction, row: Row, view: BeforeSendView | null, language: string): string {
  if (!view) {
    return '-';
  }
  switch (row) {
    case 'usual':
      return t('lab.r7.before.count', { n: count(view.departureCount, language) });
    case 'company':
      return t('lab.r7.before.count', { n: count(view.companyAdverseCount, language) });
    default: {
      const state = lineState(view);
      const names = state === 'applies' ? metRules(t, view) : null;
      return names ? t('lab.r7.before.line.appliesNamed', { names }) : t(`lab.r7.before.line.${state}`);
    }
  }
}

/** Whether one record states the minimum response rules and the other is judged from the facts alone (v21). */
function versionsDiffer(before: BeforeSendView | null, now: BeforeSendView | null): boolean {
  return before !== null && now !== null && Boolean(before.modelJudges) !== Boolean(now.modelJudges);
}

/** The source line of two columns (V-29): each column names its own record, each record one press away. */
function ColumnSources({ before, now }: { readonly before: BeforeSendView; readonly now: BeforeSendView }) {
  const { t } = useTranslation();
  const detail = useDetail();
  return (
    <>
      {[
        { key: 'before', view: before },
        { key: 'now', view: now },
      ].map(({ key, view }) => (
        <span key={key}>
          <span>{t(`lab.r7.before.source.${key}`)}</span>{' '}
          <button
            type="button"
            className={styles.sourceOpen}
            onClick={() => detail.show(view.runId, view.stepNo)}
          >
            {t('frame.source.open')}
          </button>
        </span>
      ))}
    </>
  );
}

/**
 * The comparison before sending (화면재편 R7, T2): what Contexa received in the latest real request of the original
 * situation and of the changed one, side by side in three lines (differences from usual, company work records flagged,
 * which minimum response rules applied), then what is set in advance for the situation. A value that differs after the
 * change is marked, each column names its own record, and two records judged under different versions of the
 * criteria say so (V-29). A changed situation has nothing set in advance; without a request of the same conditions
 * there is nothing to compare yet, and the screen says so.
 */
export default function LabBeforePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params] = useSearchParams();
  const options = useLabOptions().data ?? null;
  const labCase = options?.cases.find((candidate) => candidate.key === params.get('case')) ?? null;
  const changes = readChanges(params);
  const changedKeys = CONDITION_KEYS.filter((key) => changes[key] !== undefined);
  const changed = changedKeys.length > 0;
  const designedQuery = useLabBefore(labCase ? labCase.key : null, null);
  const composed = useLabBefore(labCase && changed ? labCase.key : null, changes);
  const designed = designedQuery.data?.comparison ?? null;
  const now = changed ? (composed.data?.comparison ?? null) : designed;
  const pending = designedQuery.isPending || (changed && composed.isPending);

  if (!options) {
    return <StateScreen kind="loading" />;
  }
  if (!labCase) {
    return (
      <LabScreen
        step="before"
        type="T2"
        title={t('lab.r7.before.title')}
        purpose={t('lab.r7.change.noCase')}
        back={{ to: '/lab/case', label: t('frame.back') }}
        main={<NextLink to="/lab/case" label={t('lab.r7.toCase')} />}
      >
        {null}
      </LabScreen>
    );
  }
  const query = labQuery(labCase.key, changes);
  const text = (key: (typeof CONDITION_KEYS)[number], raw: unknown) =>
    conditionText(t, key, raw, options, language);
  // Two columns when a condition changed and the original was sent before; this one column otherwise.
  const both = changed && designed !== null;
  const shown = now !== null || both;
  const expectation = changed ? 'changed' : expectationOf(labCase.classification);

  return (
    <LabScreen
      step="before"
      type="T2"
      title={t('lab.r7.before.title')}
      purpose={t(changed ? 'lab.r7.before.guide' : 'lab.r7.before.guideAsDesigned')}
      sourceLine={
        both && now && designed ? (
          <ColumnSources before={designed} now={now} />
        ) : now ? (
          <SourceLine kind="latest" runId={now.runId} step={now.stepNo} />
        ) : null
      }
      back={{ to: `/lab/change?${query}`, label: t('frame.back') }}
      main={<NextLink to={`/lab/send?${query}`} label={t('lab.r7.before.next')} />}
    >
      {changed ? (
        <p className={styles.line}>
          {t('lab.r7.before.changed', {
            list: changedKeys
              .map((key) =>
                t('lab.r7.before.change', {
                  name: t(`lab.field.${key}`),
                  from: text(key, labCase.conditions[key]),
                  to: text(key, changes[key]),
                }),
              )
              .join(' · '),
          })}
        </p>
      ) : null}
      {pending ? <StateScreen kind="loading" /> : null}
      {!pending && shown ? (
        <table className={styles.table}>
          <thead>
            <tr>
              <th scope="col">{t('lab.r7.before.col.item')}</th>
              {both ? <th scope="col">{t('lab.r7.before.col.before')}</th> : null}
              <th scope="col">{t(both ? 'lab.r7.before.col.now' : 'lab.r7.before.col.asIs')}</th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((row) => {
              const was = both ? value(t, row, designed, language) : null;
              const is = value(t, row, now, language);
              const differs = was !== null && was !== is;
              return (
                <tr key={row}>
                  <th scope="row">{t(`lab.r7.before.row.${row}`)}</th>
                  {was !== null ? <td>{was}</td> : null}
                  <td data-now data-changed={differs || undefined}>
                    {is}
                    {differs ? (
                      <span className={styles.changedTag}>{t('lab.r7.result.changedTag')}</span>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : null}
      {!pending && both && versionsDiffer(designed, now) ? (
        <p className={styles.line}>{t('lab.r7.before.versionDiffers')}</p>
      ) : null}
      {!pending && now === null ? <p className={styles.line}>{t('lab.r7.before.noRecord')}</p> : null}
      <p className={styles.line}>{t(`lab.r7.before.expect.${expectation}`)}</p>
    </LabScreen>
  );
}
