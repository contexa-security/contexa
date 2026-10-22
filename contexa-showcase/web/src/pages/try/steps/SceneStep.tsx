import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useBeforeSend } from '../../../api/anatomy';
import type { LabCase, LabEmployee, LabOptions } from '../../../api/lab';
import { RoleCard, SourceLine } from '../../../components/journey/FrameParts';
import { ScreenBody } from '../../../components/journey/ScreenBody';
import { count } from '../../../journey/format';
import { useJourneyPlace } from '../../../journey/useJourneyPlace';
import { companyClock, type Mode, type Role, type StepFlow } from '../experience';

interface SceneStepProps {
  readonly role: Role;
  /** The decision mode of the address; the cover reads the mode's case, which the address already chose. */
  readonly mode: Mode;
  readonly labCase: LabCase;
  /** Whose account it is: the role card names the account (화면재편-기획안 1-0 wire). */
  readonly employee: LabEmployee;
  readonly options: LabOptions;
  readonly flow: StepFlow;
}

/**
 * The cover of part 1 and part 2 (1-0 e1-scene, 2-0 e2-scene; 화면재편-기획안 T1): the part map, then who the visitor
 * is now and the situation in the role card. Part 1 states the situation in three lines: the company clock the
 * engine received in the latest run of the same case, the place and the device, and the files the request exports.
 * Part 2 states the one thing that changed, the company approval as the case defines it, and the same things in one
 * line; it takes the place of try 2's comparison. The goal and right-answer markers, the source chips and the role
 * band are gone (8절): the role card is the role, and the one source line opens the record.
 */
export function SceneStep({ role, labCase, employee, options, flow }: SceneStepProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const place = useJourneyPlace();
  const number = place.screen?.number ?? (role === 'owner' ? '2-0' : '1-0');
  const before = useBeforeSend(labCase.key, 1);
  const comparison = before.data?.comparison ?? null;
  const request = labCase.requests[0];
  const items = request?.items ?? null;
  const slot = options.timeSlots.find((candidate) => candidate.slot === labCase.conditions.timeSlot);
  const when = comparison?.companyTime
    ? companyClock(comparison.companyTime, language)
    : slot
      ? t(`lab.slot.${slot.slot}`, { time: slot.representativeTime })
      : '-';
  const where = labCase.conditions.place ? t(`e1.scene.where.${labCase.conditions.place}`) : '-';
  const device = labCase.conditions.device ? t(`e1.scene.device.${labCase.conditions.device}`) : '-';
  const itemCount = items === null ? '-' : count(items, language);
  const approval = labCase.facts.find((fact) => fact.kind === 'APPROVAL') ?? null;

  const lines: readonly ReactNode[] =
    role === 'owner'
      ? [
          ...(approval
            ? [
                <strong key="changed">
                  {t('p2.scene.changed', {
                    purpose: t(`e2.scene.purpose.${approval.purpose ?? ''}`, {
                      defaultValue: approval.purpose ?? '-',
                    }),
                    max: approval.maxItems === null ? '-' : count(approval.maxItems, language),
                  })}
                </strong>,
              ]
            : []),
          t('p2.scene.same', { when, where, device, items: itemCount }),
        ]
      : [
          // The plan wire (화면재편-기획안 1-0): the account works as usual; the count is in the guide line.
          t('p1.scene.normal'),
          t('p1.scene.time', { when }),
          t('p1.scene.place', { where, device }),
        ];

  return (
    <ScreenBody
      title={t(`screen.${number}.title`)}
      // The count is the case's; a guide written with {{items}} takes it, one with the number written in ignores it.
      purpose={t(`screen.${number}.guide`, { items: itemCount })}
      sourceLine={comparison ? <SourceLine kind="latest" runId={comparison.runId} /> : null}
      back={flow.back}
      main={flow.next}
    >
      <RoleCard role={t(role === 'owner' ? 'p2.scene.role' : 'p1.scene.role', { name: employee.displayName })} lines={lines} />
    </ScreenBody>
  );
}
