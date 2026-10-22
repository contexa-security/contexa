import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useLabOptions, type LabConditions } from '../../api/lab';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import { LabField } from './LabField';
import { LabScreen } from './LabScreen';
import {
  CONDITION_KEYS,
  ONE_CHANGE,
  changeable,
  choicesOf,
  conditionText,
  labQuery,
  readChanges,
  situationName,
  withChange,
  type ConditionKey,
} from './labPlace';
import styles from './LabScreens.module.css';

/** The original situation's lines (lab-2): time, place, device, count and the approval record, after the employee. */
const SUMMARY: readonly ConditionKey[] = ['timeSlot', 'place', 'device', 'items', 'approval'];

/**
 * Changing one condition (화면재편 R7, T3): the original situation as one card, then two inputs, the one condition to
 * change (only the ones the case can change: a case of several requests keeps its requests) and its new value, the
 * original marked. One change at a time, so the result says what made the difference; it is in the address.
 */
export default function LabChangePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params, setParams] = useSearchParams();
  const options = useLabOptions().data ?? null;
  const labCase = options?.cases.find((candidate) => candidate.key === params.get('case')) ?? null;

  if (!options) {
    return <StateScreen kind="loading" />;
  }
  if (!labCase) {
    return (
      <LabScreen
        step="change"
        type="T3"
        title={t('lab.r7.change.title')}
        purpose={t('lab.r7.change.noCase')}
        back={{ to: '/lab/case', label: t('frame.back') }}
        main={<NextLink to="/lab/case" label={t('lab.r7.toCase')} />}
      >
        {null}
      </LabScreen>
    );
  }
  const changes = readChanges(params);
  const items = ONE_CHANGE.filter((key) => changeable(key, labCase));
  const asked = params.get('field') as ConditionKey | null;
  const changedKeys = CONDITION_KEYS.filter((key) => changes[key] !== undefined);
  const field: ConditionKey | null =
    asked && items.includes(asked) ? asked : (changedKeys.find((key) => items.includes(key)) ?? null);
  const employee = options.employees.find((entry) => entry.key === labCase.conditions.employee) ?? null;
  const text = (key: ConditionKey, value: unknown) => conditionText(t, key, value, options, language);
  const go = (next: Partial<LabConditions>, nextField: ConditionKey | null) => {
    const query = new URLSearchParams(labQuery(labCase.key, next));
    if (nextField) {
      query.set('field', nextField);
    }
    setParams(query, { replace: true });
  };
  const original = field ? labCase.conditions[field] : null;
  const current = field ? (changes[field] ?? original) : null;

  return (
    <LabScreen
      step="change"
      type="T3"
      title={t('lab.r7.change.title')}
      purpose={t('lab.r7.change.guide')}
      back={{ to: `/lab/case?case=${encodeURIComponent(labCase.key)}`, label: t('frame.back') }}
      main={<NextLink to={`/lab/before?${labQuery(labCase.key, changes)}`} label={t('lab.r7.change.next')} />}
    >
      <section className={styles.card} aria-labelledby="lab-original">
        <h2 id="lab-original" className={styles.cardName}>
          {t('lab.r7.change.original', { situation: situationName(t, labCase.key, labCase.title, language) })}
        </h2>
        <dl className={styles.facts}>
          <div>
            <dt>{t('lab.field.employee')}</dt>
            <dd>
              {employee ? (
                <>
                  <span data-original>{employee.displayName}</span> · {t(`lab.role.${employee.role}`)}
                </>
              ) : (
                '-'
              )}
            </dd>
          </div>
          {SUMMARY.filter(
            (key) => labCase.conditions[key] !== null && labCase.conditions[key] !== undefined,
          ).map((key) => (
            <div key={key}>
              <dt>{t(`lab.field.${key}`)}</dt>
              <dd>{text(key, labCase.conditions[key])}</dd>
            </div>
          ))}
        </dl>
      </section>
      <div className={styles.controls}>
        <LabField label={t('lab.r7.change.field')}>
          {(id) => (
            <select
              id={id}
              className={styles.select}
              value={field ?? ''}
              onChange={(event) => go({}, (event.target.value || null) as ConditionKey | null)}
            >
              <option value="">{t('lab.r7.change.fieldNone')}</option>
              {items.map((key) => (
                <option key={key} value={key}>
                  {t(`lab.field.${key}`)}
                </option>
              ))}
            </select>
          )}
        </LabField>
        {field ? (
          <LabField label={t('lab.r7.change.value')}>
            {(id) => (
              <select
                id={id}
                className={styles.select}
                value={String(current)}
                onChange={(event) => {
                  const raw = event.target.value;
                  const value =
                    typeof original === 'boolean'
                      ? raw === 'true'
                      : typeof original === 'number'
                        ? Number(raw)
                        : raw;
                  go(withChange({}, field, value, original), field);
                }}
              >
                {choicesOf(field, options).map((value) => (
                  <option key={String(value)} value={String(value)}>
                    {value === original
                      ? t('lab.r7.change.originalMark', { value: text(field, value) })
                      : text(field, value)}
                  </option>
                ))}
              </select>
            )}
          </LabField>
        ) : null}
      </div>
      {labCase.requests.length > 1 ? (
        <p className={styles.line}>
          {t('lab.r7.change.fixed', { n: count(labCase.requests.length, language) })}
        </p>
      ) : null}
    </LabScreen>
  );
}
