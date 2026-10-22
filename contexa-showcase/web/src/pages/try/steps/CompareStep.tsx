import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useBeforeSend } from '../../../api/anatomy';
import type { LabCase } from '../../../api/lab';
import { Comparison } from '../../../components/inside/Comparison';
import { SourceLine } from '../../../components/journey/FrameParts';
import { ScreenBody } from '../../../components/journey/ScreenBody';
import { StateScreen } from '../../../components/StateScreen';
import type { Difference } from '../../../journey/journey';
import { useJourneyPlace } from '../../../journey/useJourneyPlace';
import type { Role, StepFlow } from '../experience';

interface CompareStepProps {
  /** Only try 1 has this step; try 2's comparison is one line of its cover (2-0). */
  readonly role: Role;
  readonly labCase: LabCase;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/**
 * Screen 1-1, how this request differs from usual (e1-compare, 화면재편-기획안 T2): usual then this time, only the items
 * that differ (four at most), and what the company work records flag in one line, as the engine received them in
 * the latest run sent with the same conditions. The originals, the folds and the "just seen" band are gone; all of
 * the comparison stays in the decision details' "received" tab. Without such a run the guide says so.
 */
export function CompareStep({ labCase, see, flow }: CompareStepProps) {
  const { t } = useTranslation();
  const place = useJourneyPlace();
  const number = place.screen?.number ?? '1-1';
  const before = useBeforeSend(labCase.key, 1);
  const comparison = before.data?.comparison ?? null;

  useEffect(() => {
    if (comparison) {
      see(2);
    }
    // Seen once the comparison is on screen; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [comparison?.runId]);

  return (
    <ScreenBody
      title={t(`screen.${number}.title`)}
      purpose={comparison || before.isPending ? t(`screen.${number}.guide`) : t('p1.compare.none')}
      sourceLine={
        comparison ? <SourceLine kind="measured" runId={comparison.runId} step={comparison.stepNo} /> : null
      }
      back={flow.back}
      main={flow.next}
    >
      {before.isPending ? <StateScreen kind="loading" /> : null}
      {comparison ? <Comparison comparison={comparison} level="h2" compact /> : null}
    </ScreenBody>
  );
}
