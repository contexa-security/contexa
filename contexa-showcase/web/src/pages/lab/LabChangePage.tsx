import { Trans, useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useLabOptions, type LabConditions } from '../../api/lab';
import { useBaseline } from '../../api/queries';
import { ActionChip } from '../../components/common/ActionChip';
import { Modal } from '../../components/common/Modal';
import { useUrlModal } from '../../components/common/useUrlModal';
import { HourBars } from '../../components/journey/HourBars';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { SourceMark } from '../../components/common/SourceMark';
import { count } from '../../journey/format';
import { LabScreen } from './LabScreen';
import {
  CONDITION_KEYS,
  ONE_CHANGE,
  changeable,
  choicesOf,
  conditionText,
  labQuery,
  readChanges,
  withChange,
  type ConditionKey,
} from './labPlace';
import styles from './LabPages.module.css';

/** The original case's summary lines (lab-2): employee and role, time, place, device, count and approval record. */
const SUMMARY: readonly ConditionKey[] = ['timeSlot', 'place', 'device', 'items', 'approval'];

/**
 * L2, changing one condition (lab-2, 7.6): the original case, the one item to change (only the ones the case can
 * change: a case of several requests keeps its requests), that item's one input, and every input together folded
 * under "advanced". What changed is in the address; the employee's usual behaviour opens in a window.
 */
export default function LabChangePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params, setParams] = useSearchParams();
  const options = useLabOptions().data ?? null;
  const caseKey = params.get('case');
  const labCase = options?.cases.find((candidate) => candidate.key === caseKey) ?? null;
  const changes = readChanges(params);
  const employeeKey = (changes.employee ?? labCase?.conditions.employee) || null;
  const employee = options?.employees.find((entry) => entry.key === employeeKey) ?? null;
  const usual = useUrlModal('usual');
  const baseline = useBaseline(usual.open ? employeeKey : null).data ?? null;

  if (!options) {
    return <StateScreen kind="loading" />;
  }
  if (!labCase) {
    return (
      <LabScreen
        step="change"
        title={t('labChange.title')}
        purpose={t('labChange.noCase')}
        back={{ to: '/lab/case', label: t('labChange.back') }}
      >
        {null}
      </LabScreen>
    );
  }
  const items = ONE_CHANGE.filter((key) => changeable(key, labCase));
  const asked = params.get('field') as ConditionKey | null;
  const changedKeys = CONDITION_KEYS.filter((key) => changes[key] !== undefined);
  const field: ConditionKey | null =
    asked && items.includes(asked) ? asked : (changedKeys.find((key) => items.includes(key)) ?? null);
  const go = (next: Partial<LabConditions>, nextField: ConditionKey | null) => {
    const query = new URLSearchParams(labQuery(labCase.key, next));
    if (nextField) {
      query.set('field', nextField);
    }
    setParams(query, { replace: true });
  };
  const text = (key: ConditionKey, value: unknown) => conditionText(t, key, value, options, language);
  const select = (key: ConditionKey, onlyThis: boolean) => {
    const original = labCase.conditions[key];
    const current = changes[key] ?? original;
    return (
      <select
        className={styles.select}
        aria-label={
          onlyThis ? t('labChange.newValue', { name: t(`lab.field.${key}`) }) : t(`lab.field.${key}`)
        }
        value={String(current)}
        onChange={(event) => {
          const raw = event.target.value;
          const value =
            typeof original === 'boolean' ? raw === 'true' : typeof original === 'number' ? Number(raw) : raw;
          go(withChange(onlyThis ? {} : changes, key, value, original), onlyThis ? key : field);
        }}
      >
        {choicesOf(key, options).map((value) => (
          <option key={String(value)} value={String(value)}>
            {text(key, value)}
            {value === original ? ` · ${t('labChange.original')}` : ''}
          </option>
        ))}
      </select>
    );
  };
  return (
    <LabScreen
      step="change"
      title={t('labChange.title')}
      purpose={t('labChange.purpose')}
      source={<SourceMark kind="CASE">{t('labChange.source', { key: labCase.key })}</SourceMark>}
      back={{ to: `/lab/case?case=${encodeURIComponent(labCase.key)}`, label: t('labChange.back') }}
      more={
        <ActionChip icon="user" variant="open" onClick={() => usual.show()}>
          <Trans
            i18nKey="labChange.usual"
            values={{ name: employee?.displayName ?? '-' }}
            components={{ name: <span data-original /> }}
          />
        </ActionChip>
      }
      main={<NextLink to={`/lab/before?${labQuery(labCase.key, changes)}`} label={t('labChange.next')} />}
    >
      <section className={styles.panel} aria-labelledby="lab-original">
        <h2 id="lab-original" className={styles.panelTitle}>
          {t('labChange.originalCase')} · {labCase.title[language] ?? labCase.key}
        </h2>
        <dl className={styles.summary}>
          <div>
            <dt>{t('lab.field.employee')}</dt>
            <dd>
              <span data-original>{employee?.displayName ?? '-'}</span>
              {employee ? ` · ${t(`lab.role.${employee.role}`)}` : ''}
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
      <section className={styles.panel} aria-labelledby="lab-pick">
        <h2 id="lab-pick" className={styles.panelTitle}>
          {t('labChange.pick')}
        </h2>
        <div className={styles.filters} role="group" aria-labelledby="lab-pick">
          {items.map((key) => (
            <button
              key={key}
              type="button"
              className={styles.filter}
              aria-pressed={field === key}
              onClick={() => go(changes[key] !== undefined ? { [key]: changes[key] } : {}, key)}
            >
              {t(`lab.field.${key}`)}
            </button>
          ))}
        </div>
        {field ? (
          <label className={styles.oneInput}>
            <span className={styles.oneInputName}>
              {t('labChange.from', { value: text(field, labCase.conditions[field]) })}
            </span>
            {select(field, true)}
          </label>
        ) : null}
        <details className={styles.advanced}>
          <summary>{t('labChange.advanced')}</summary>
          <div className={styles.advancedInputs}>
            {CONDITION_KEYS.filter((key) => changeable(key, labCase)).map((key) => (
              <label key={key} className={styles.advancedInput}>
                <span>{t(`lab.field.${key}`)}</span>
                {select(key, false)}
              </label>
            ))}
          </div>
        </details>
      </section>
      <Modal
        open={usual.open}
        onClose={usual.hide}
        title={
          <Trans
            i18nKey="labChange.usualTitle"
            values={{ name: employee?.displayName ?? '-' }}
            components={{ name: <span data-original /> }}
          />
        }
      >
        {employee ? (
          <dl className={styles.summary}>
            <div>
              <dt>{t('labChange.usualRole')}</dt>
              <dd>
                {t(`lab.role.${employee.role}`)} · <span data-original>{employee.department}</span>
              </dd>
            </div>
            <div>
              <dt>{t('labChange.usualNetwork')}</dt>
              <dd>
                <code data-original>{employee.officeNetwork}</code>
              </dd>
            </div>
            <div>
              <dt>{t('labChange.usualProjects')}</dt>
              <dd>{employee.assignedProjects.join(', ') || '-'}</dd>
            </div>
          </dl>
        ) : null}
        {baseline ? (
          <>
            <p className={styles.windowLead}>
              {t('labChange.usualLearned', { n: count(baseline.learned.requests, language) })}
            </p>
            <HourBars hours={baseline.learned.hours} />
          </>
        ) : (
          <p className={styles.windowLead}>{t('labChange.usualNone')}</p>
        )}
      </Modal>
    </LabScreen>
  );
}
