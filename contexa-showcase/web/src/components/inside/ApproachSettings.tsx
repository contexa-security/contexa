import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { PublicSettingsView } from '../../api/settings';
import type { ControlId } from '../../domain/verdict';
import { count } from '../../journey/format';
import styles from './ApproachSettings.module.css';

/** One setting as a name and its value; a value the stack does not state reads "not stated". */
function Row({ name, value }: { readonly name: string; readonly value: ReactNode }) {
  return (
    <div className={styles.setting}>
      <dt>{name}</dt>
      <dd>{value}</dd>
    </div>
  );
}

/**
 * The settings of one approach exactly as the running demo publishes them (portal /api/settings), with the note on
 * where they come from: the five approaches window and the benchmark's approach card show the same.
 */
export function ApproachSettings({
  control,
  settings,
}: {
  readonly control: ControlId;
  readonly settings: PublicSettingsView;
}) {
  const { t } = useTranslation();
  return (
    <>
      <Values control={control} settings={settings} />
      <p className={styles.settingsNote}>{t('settings.note')}</p>
    </>
  );
}

function Values({
  control,
  settings,
}: {
  readonly control: ControlId;
  readonly settings: PublicSettingsView;
}) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const none = t('settings.none');
  const days = (n: number | null) => (n === null ? none : t('settings.days', { n }));
  const items = (n: number | null) => (n === null ? none : t('settings.items', { n: count(n, language) }));
  const yes = (value: boolean | null) => (value === null ? none : t(value ? 'settings.yes' : 'settings.no'));
  const code = (value: string | null) => (value === null ? none : <code data-original>{value}</code>);
  switch (control) {
    case 'A':
      return (
        <dl className={styles.settings}>
          <Row name={t('settings.A.image')} value={code(settings.waf.image)} />
          <Row name={t('settings.A.ruleSet')} value={code(settings.waf.ruleSet)} />
        </dl>
      );
    case 'B':
      return (
        <dl className={styles.settings}>
          <Row
            name={t('settings.B.rules', { n: settings.permission.roleRules.length })}
            value={
              <ul className={styles.codeList} data-original>
                {settings.permission.roleRules.map((rule) => (
                  <li key={rule}>
                    <code>{rule}</code>
                  </li>
                ))}
              </ul>
            }
          />
        </dl>
      );
    case 'C1':
      return (
        <dl className={styles.settings}>
          <Row
            name={t('settings.C1.night')}
            value={
              settings.threshold.nightStart && settings.threshold.nightEnd
                ? t('settings.C1.nightValue', {
                    from: settings.threshold.nightStart,
                    to: settings.threshold.nightEnd,
                  })
                : none
            }
          />
          <Row name={t('settings.C1.volume')} value={items(settings.threshold.volumeLimit)} />
          <Row name={t('settings.C1.dormant')} value={days(settings.threshold.dormantWindowDays)} />
        </dl>
      );
    case 'C2':
      return (
        <dl className={styles.settings}>
          <Row name={t('settings.C2.policy')} value={code(settings.businessRecord.exportPolicyKey)} />
          <Row name={t('settings.C2.assigned')} value={items(settings.businessRecord.assignedExportLimit)} />
          <Row name={t('settings.C2.ticket')} value={yes(settings.businessRecord.ticketAndOncallExempt)} />
          <Row name={t('settings.C2.history')} value={days(settings.businessRecord.historyWindowDays)} />
          <Row
            name={t('settings.C2.exportHistory')}
            value={days(settings.businessRecord.exportHistoryWindowDays)}
          />
          <Row
            name={t('settings.C2.access')}
            value={
              <ul className={styles.codeList}>
                {settings.businessRecord.accessPolicies.map((policy) => (
                  <li key={policy.policyKey ?? ''}>
                    <code data-original>{policy.policyKey ?? none}</code>{' '}
                    {t('settings.C2.accessValue', {
                      manager: yes(policy.accountManagerExempt),
                      assigned: yes(policy.assignedExempt),
                      days: days(policy.recentWorkDays),
                    })}
                  </li>
                ))}
              </ul>
            }
          />
        </dl>
      );
    case 'D':
      return (
        <dl className={styles.settings}>
          <Row name={t('settings.D.model')} value={code(settings.engine.chatModel)} />
          <Row
            name={t('settings.D.mode')}
            value={
              settings.engine.effectiveMode
                ? t(`settings.D.mode.${settings.engine.effectiveMode}`, {
                    defaultValue: settings.engine.effectiveMode,
                  })
                : none
            }
          />
          <Row
            name={t('settings.D.inspector')}
            value={t('settings.D.inspectorValue', { n: settings.engine.inspectorConditions })}
          />
        </dl>
      );
    default:
      return null;
  }
}
