import type { TFunction } from 'i18next';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useBenchmark } from '../../api/benchmark';
import { useHook } from '../../api/hook';
import { useLabOptions } from '../../api/lab';
import { usePublicSettings, type PublicSettingsView } from '../../api/settings';
import { ActionChip } from '../../components/common/ActionChip';
import { Modal } from '../../components/common/Modal';
import { SourceMark } from '../../components/common/SourceMark';
import { useUrlModal } from '../../components/common/useUrlModal';
import { Icon } from '../../components/Icon';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { VerdictChip } from '../../components/VerdictChip';
import { CONTROL_ORDER, type ControlId } from '../../domain/verdict';
import { count } from '../../journey/format';
import { companyClock } from '../try/experience';
import styles from './ComparePage.module.css';

/** The case whose request the picture sends: try 1's (A3), the one the visitor will send first. */
const CASE = 'A3';

/** The three results every approach's answer is read as, in the order the design names them (g4-compare). */
const RESULTS = ['ALLOW', 'CHALLENGE', 'BLOCK'] as const;

/** What each approach judges by in this demo, from the settings the running stack publishes. */
function judgesBy(
  control: ControlId,
  settings: PublicSettingsView,
  t: TFunction,
  language: 'ko' | 'en',
): ReactNode {
  const none = t('settings.none');
  switch (control) {
    case 'A':
      return settings.waf.ruleSet ? <code data-original>{settings.waf.ruleSet}</code> : none;
    case 'B':
      return t('compare.env.B', { n: settings.permission.roleRules.length });
    case 'C1':
      return settings.threshold.nightStart &&
        settings.threshold.nightEnd &&
        settings.threshold.volumeLimit !== null
        ? t('compare.env.C1', {
            from: settings.threshold.nightStart,
            to: settings.threshold.nightEnd,
            n: count(settings.threshold.volumeLimit, language),
          })
        : none;
    case 'C2':
      return settings.businessRecord.exportPolicyKey ? (
        <code data-original>{settings.businessRecord.exportPolicyKey}</code>
      ) : (
        none
      );
    case 'D':
      return (
        <>
          {settings.engine.chatModel ? <code data-original>{settings.engine.chatModel}</code> : none}
          {settings.engine.effectiveMode
            ? ` · ${t(`settings.D.mode.${settings.engine.effectiveMode}`, { defaultValue: settings.engine.effectiveMode })}`
            : null}
        </>
      );
    default:
      return none;
  }
}

/**
 * G4, how we compare (g4-compare, 7.5): one request goes to five places at once, each approach in front of its own copy
 * of the company system; every answer reads as one of three results; the right answer is set in advance from company
 * records. "Are the conditions really the same?" opens what the runs share (the request, the company time, the company
 * records) and what each approach judges by, from the stored run, the published settings and the measurement setting.
 */
export default function ComparePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const modal = useUrlModal('same-conditions');
  const items =
    useLabOptions().data?.cases.find((candidate) => candidate.key === CASE)?.requests[0]?.items ?? null;
  const hook = useHook().data ?? null;
  const settings = usePublicSettings().data ?? null;
  const spec = useBenchmark(null).data?.spec ?? null;
  const request = t('compare.request', { items: items === null ? '-' : count(items, language) });
  return (
    <RouteScreen
      title={t('compare.title')}
      purpose={t('compare.purpose')}
      source={<SourceMark kind="CASE">{t('compare.sourceCase', { key: CASE })}</SourceMark>}
      more={
        <ActionChip icon="search" variant="open" onClick={() => modal.show()}>
          {t('compare.same')}
        </ActionChip>
      }
    >
      <figure className={styles.figure} aria-label={t('compare.figure')}>
        <span className={styles.request}>
          <Icon name="box" />
          {request}
        </span>
        <ol className={styles.lanes}>
          {CONTROL_ORDER.map((control) => (
            <li key={control} className={styles.lane} data-contexa={control === 'D' || undefined}>
              <span className={styles.approach}>{t(`control.${control}.name`)}</span>
              <Icon name="arrowRight" className={styles.arrow} />
              <span className={styles.copy}>{t('compare.copy')}</span>
              <Icon name="arrowRight" className={styles.arrow} />
              <span className={styles.unknown} aria-label={t('compare.unknown')}>
                ?
              </span>
            </li>
          ))}
        </ol>
      </figure>
      <dl className={styles.results}>
        {RESULTS.map((result) => (
          <div key={result} className={styles.result}>
            <dt>
              <VerdictChip verdict={result} />
            </dt>
            <dd>{t(`compare.result.${result}`)}</dd>
          </div>
        ))}
      </dl>
      <p className={styles.truth}>
        <span className={styles.truthName}>{t('compare.truthName')}</span>
        {t('compare.truth')}
      </p>
      <Modal open={modal.open} onClose={modal.hide} title={t('compare.same')} wide>
        <h3 className={styles.windowTitle}>{t('compare.shared')}</h3>
        <dl className={styles.facts}>
          <div className={styles.fact}>
            <dt>{t('compare.sameRequest')}</dt>
            <dd>{t('compare.sameRequestValue', { request })}</dd>
          </div>
          <div className={styles.fact}>
            <dt>{t('compare.sameTime')}</dt>
            <dd>
              {hook
                ? t('compare.sameTimeValue', {
                    when: companyClock(hook.attacker.result.companyTime, language),
                  })
                : '-'}
            </dd>
          </div>
          <div className={styles.fact}>
            <dt>{t('compare.sameRecords')}</dt>
            <dd>{t('compare.sameRecordsValue')}</dd>
          </div>
        </dl>
        <h3 className={styles.windowTitle}>{t('compare.each')}</h3>
        {settings ? (
          <dl className={styles.facts}>
            {CONTROL_ORDER.map((control) => (
              <div key={control} className={styles.fact}>
                <dt>{t(`control.${control}.name`)}</dt>
                <dd>{judgesBy(control, settings, t, language)}</dd>
              </div>
            ))}
          </dl>
        ) : (
          <p>{t('settings.unavailable')}</p>
        )}
        {spec ? (
          <p className={styles.spec}>
            {t('compare.spec')}{' '}
            <code data-original>
              {spec.codeCommit.slice(0, 8)} · {spec.engineVersion} · {spec.ruleVersion.slice(0, 8)}
            </code>
          </p>
        ) : null}
        {hook ? (
          <SourceMark kind="ENGINE" runId={hook.attacker.runId} step={1}>
            {t('compare.source')}
          </SourceMark>
        ) : null}
      </Modal>
    </RouteScreen>
  );
}
