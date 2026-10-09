import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useBeforeSend } from '../../../api/anatomy';
import type { LabCase } from '../../../api/lab';
import { SourceMark } from '../../../components/common/SourceMark';
import { Comparison } from '../../../components/inside/Comparison';
import { Icon } from '../../../components/Icon';
import { JustSaw } from '../../../components/journey/JourneyParts';
import { ActionBar, StepHeader } from '../../../components/journey/StepParts';
import { StateScreen } from '../../../components/StateScreen';
import type { Difference } from '../../../journey/journey';
import type { Role, StepFlow } from '../experience';
import { count } from '../../../journey/format';
import styles from '../Experience.module.css';

interface CompareStepProps {
  readonly role: Role;
  readonly labCase: LabCase;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Try 1-2, compare with usual (e1-compare): what is different from usual and what the company records flag, as the
 * engine received them in the latest run sent with the same conditions, all in one answer. The differences are the
 * screen; the items that are the same and the records that flag nothing stay folded (D-41). Without such a run the
 * screen says so.
 */
export function CompareStep({ role, labCase, see, flow }: CompareStepProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const approval = role === 'owner' ? (labCase.facts.find((fact) => fact.kind === 'APPROVAL') ?? null) : null;
  const before = useBeforeSend(labCase.key, 1);
  const comparison = before.data?.comparison ?? null;

  useEffect(() => {
    if (comparison) {
      see(2);
    }
    // Seen once the comparison is on screen; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [comparison?.runId]);

  if (before.isPending) {
    return <StateScreen kind="loading" />;
  }
  if (!comparison) {
    return (
      <>
        <StepHeader title={t('e1.compare.noneTitle')} purpose={t('e1.compare.none')} />
        <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
      </>
    );
  }

  return (
    <>
      <StepHeader
        title={t(role === 'owner' ? 'e2.compare.title' : 'e1.compare.title', {
          usual: comparison.departureCount,
          company: comparison.companyAdverseCount,
        })}
        purpose={t(role === 'owner' ? 'e2.purpose.compare' : 'e1.purpose.compare')}
        source={
          <SourceMark kind="ENGINE" runId={comparison.runId} step={1} recordedAt={comparison.startedAt}>
            {t('e1.compare.source')}
          </SourceMark>
        }
      />
      <Comparison
        comparison={comparison}
        level="h2"
        approval={
          approval
            ? {
                leaveOut: 'APPROVAL_COVERS',
                card: (
                  <p className={styles.approvalRow}>
                    <Icon name="check" className={styles.approvalIcon} />
                    {t('e2.compare.approval', {
                      approver: approval.approver ?? '-',
                      purpose: t(`e2.scene.purpose.${approval.purpose ?? ''}`, {
                        defaultValue: approval.purpose ?? '-',
                      }),
                      max: approval.maxItems === null ? '-' : count(approval.maxItems, language),
                    })}
                  </p>
                ),
              }
            : null
        }
      />
      {approval ? <p className={styles.callout}>{t('e2.compare.allowed')}</p> : null}
      {role === 'attacker' ? (
        <JustSaw difference={2} sentence="e1Compare" values={{ n: comparison.departureCount }} />
      ) : null}
      <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
    </>
  );
}
