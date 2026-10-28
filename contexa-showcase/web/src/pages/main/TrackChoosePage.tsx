import { useTranslation } from 'react-i18next';
import { ChoiceCards, type Choice } from '../../components/main/ChoiceCards';
import { ChooseScreen } from '../../components/main/ChooseScreen';
import { entryOf } from '../../journey/journey';

/**
 * C-1, which request to see first (구현계획 NW-2): the choice between the AI agent's request and the person's, the
 * landing's next screen. The card chosen opens that track.
 */
export default function TrackChoosePage() {
  const { t } = useTranslation();
  const cards: readonly Choice[] = [
    { id: 'agent', title: t('pick.agent.title'), sub: t('pick.agent.sub'), to: entryOf('A'), icon: 'agent' },
    {
      id: 'person',
      title: t('pick.person.title'),
      sub: t('pick.person.sub'),
      to: entryOf('H'),
      icon: 'user',
    },
  ];
  return (
    <ChooseScreen center title={t('main.C-1.title')} intro={t('main.C-1.intro')}>
      <ChoiceCards cards={cards} label={t('main.C-1.title')} />
    </ChooseScreen>
  );
}
