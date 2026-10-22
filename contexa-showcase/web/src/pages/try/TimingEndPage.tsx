import { useTranslation } from 'react-i18next';
import { useActEnd } from '../../api/journey';
import { useVisitor } from '../../api/queries';
import { PartWrap } from '../../components/journey/Cards';
import { actEndSentence } from '../../journey/copy';
import { useJourneyPosition } from '../../journey/useJourneyPosition';

/**
 * The wrap-up of part 4, when to stop it (화면재편-기획안 7절 4-4, T8): one sentence from the record of the attack sent
 * "from the next request" on 4-1 (the portal's part 4 values, plan 7 P-2; the measurement's run when the visitor did
 * not send it, said so by the source line), then the differences seen. Without any run, the part's guide line only.
 */
export default function TimingEndPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  useVisitor();
  const position = useJourneyPosition();
  const actEnd = useActEnd(4, true);
  return (
    <PartWrap
      sentence={actEnd.data && actEnd.data.source !== 'NONE' ? actEndSentence(t, language, actEnd.data) : null}
      measured={actEnd.data?.source === 'MEASUREMENT'}
      differences={position.differences}
    />
  );
}
