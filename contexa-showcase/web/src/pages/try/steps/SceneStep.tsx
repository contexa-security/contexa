import { useTranslation } from 'react-i18next';
import { useBeforeSend } from '../../../api/anatomy';
import type { LabCase, LabEmployee, LabOptions } from '../../../api/lab';
import { Term } from '../../../components/common/Glossary';
import { Icon, type IconName } from '../../../components/Icon';
import { RoleBanner } from '../../../components/journey/JourneyParts';
import { ActionBar, StepHeader } from '../../../components/journey/StepParts';
import { SourceMark } from '../../../components/common/SourceMark';
import { count } from '../../../journey/format';
import { companyClock, type Mode, type Role, type StepFlow } from '../experience';
import styles from '../Experience.module.css';

interface SceneStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly employee: LabEmployee;
  readonly options: LabOptions;
  readonly flow: StepFlow;
}

/**
 * Try 1-1 and 2-1, the situation (e1-scene, e2-scene): who the visitor is now and what the request asks for, as one
 * request card, with the try's goal and right answer next to it. In try 2 the role change is announced first and the
 * one thing that changed, the company approval as the case defines it, sits above the same card. Nothing else: the
 * five approaches come where the visitor guesses them (your call), and the decision mode after the result (D-41). The
 * company clock is the one the engine received in the latest run of the same case.
 */
export function SceneStep({ role, mode, labCase, employee, options, flow }: SceneStepProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const before = useBeforeSend(labCase.key, 1);
  const request = labCase.requests[0];
  const slot = options.timeSlots.find((candidate) => candidate.slot === labCase.conditions.timeSlot);
  const companyTime = before.data?.comparison?.companyTime ?? null;
  const items = request?.items ?? null;
  const threat = labCase.classification === 'THREAT';
  const approval = labCase.facts.find((fact) => fact.kind === 'APPROVAL') ?? null;
  const facts: readonly { readonly icon: IconName; readonly text: string }[] = [
    { icon: 'user', text: t('e1.scene.signedIn', { role: t(`lab.role.${employee.role}`) }) },
    {
      icon: 'clock',
      text: t('e1.scene.companyTime', {
        when: companyTime
          ? companyClock(companyTime, language)
          : slot
            ? t(`lab.slot.${slot.slot}`, { time: slot.representativeTime })
            : '-',
      }),
    },
    {
      icon: 'pin',
      text: `${labCase.conditions.place ? t(`e1.scene.where.${labCase.conditions.place}`) : '-'} · ${
        labCase.conditions.device ? t(`e1.scene.device.${labCase.conditions.device}`) : '-'
      }`,
    },
    {
      icon: 'box',
      text: t('e1.scene.export', {
        project: request?.project ?? '-',
        items: items === null ? '-' : count(items, language),
      }),
    },
  ];

  return (
    <>
      {role === 'owner' ? <RoleBanner role="owner" name={employee.displayName} /> : null}
      {role === 'owner' ? (
        <StepHeader
          title={t('e2.scene.title', { items: items === null ? '-' : count(items, language) })}
          purpose={t('e2.purpose.scene')}
          source={<SourceMark kind="CASE">{t('scene.source', { key: labCase.key })}</SourceMark>}
        />
      ) : (
        <StepHeader
          title={t('e1.scene.title', { name: employee.displayName })}
          source={<SourceMark kind="CASE">{t('scene.source', { key: labCase.key })}</SourceMark>}
          purpose={
            <span>
              {t('e1.purpose.scene.before')}
              <Term term="stolenAccount">{t('glossary.stolenAccount.term')}</Term>
              {t('e1.purpose.scene.after')}
            </span>
          }
        />
      )}
      {role === 'owner' && approval ? (
        <section className={styles.changed} aria-labelledby="scene-changed">
          <h2 id="scene-changed" className={styles.cardLabel}>
            {t('e2.scene.changed')}
          </h2>
          <p className={styles.changedLine}>
            <span className={styles.changedBefore}>{t('e2.scene.before')}</span>
            <Icon name="arrowRight" className={styles.changedArrow} />
            <span className={styles.changedAfter}>
              {t('e2.scene.after', {
                purpose: t(`e2.scene.purpose.${approval.purpose ?? ''}`, {
                  defaultValue: approval.purpose ?? '-',
                }),
                max: approval.maxItems === null ? '-' : count(approval.maxItems, language),
              })}
            </span>
          </p>
        </section>
      ) : null}
      <div className={styles.sceneGrid} data-mode={mode}>
        <section className={styles.requestCard} aria-labelledby="scene-request">
          <h2 id="scene-request" className={styles.cardLabel}>
            {t(role === 'owner' ? 'e2.scene.same' : 'e1.scene.request')}
          </h2>
          <ul className={styles.facts}>
            {facts.map((fact) => (
              <li key={fact.icon} className={styles.factRow}>
                <Icon name={fact.icon} className={styles.factIcon} />
                <span>{fact.text}</span>
              </li>
            ))}
          </ul>
        </section>
        <dl className={styles.markers}>
          <div className={styles.marker} data-kind="goal">
            <dt>{t('e1.scene.goalLabel')}</dt>
            <dd>
              {t(threat ? 'e1.scene.goalValue' : 'e2.scene.goalValue', {
                items: items === null ? '-' : count(items, language),
              })}
            </dd>
          </div>
          <div className={styles.marker} data-kind="answer">
            <dt>{t('e1.scene.answerLabel')}</dt>
            <dd>{t(threat ? 'e1.scene.answerValue.THREAT' : 'e1.scene.answerValue.NORMAL')}</dd>
          </div>
        </dl>
      </div>
      <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
    </>
  );
}
