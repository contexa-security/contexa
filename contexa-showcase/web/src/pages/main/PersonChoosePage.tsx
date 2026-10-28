import { useTranslation } from 'react-i18next';
import { ChoiceCards, type Choice } from '../../components/main/ChoiceCards';
import { ChooseScreen } from '../../components/main/ChooseScreen';
import { ROLE_PATHS } from './mainCases';

/**
 * H-1, who sent the request (구현계획 NW-3): the person's track opens with one choice of three, the account's thief, the
 * real owner or the insider. Each card leads to that case's own screens, which are the old group covers' screens
 * without the cover: the request screen is the prediction.
 */
export default function PersonChoosePage() {
  const { t } = useTranslation();
  const cards: readonly Choice[] = [
    {
      id: 'attack',
      title: t('choose.person.attack.title'),
      sub: t('choose.person.attack.sub'),
      to: ROLE_PATHS.attacker.request,
      icon: 'key',
    },
    {
      id: 'normal',
      title: t('choose.person.normal.title'),
      sub: t('choose.person.normal.sub'),
      to: ROLE_PATHS.owner.request,
      icon: 'user',
    },
    {
      id: 'insider',
      title: t('choose.person.insider.title'),
      sub: t('choose.person.insider.sub'),
      to: ROLE_PATHS.insider.request,
      icon: 'lock',
    },
  ];
  return (
    <ChooseScreen title={t('main.H-1.title')} intro={t('main.H-1.intro')}>
      <ChoiceCards cards={cards} label={t('main.H-1.title')} />
    </ChooseScreen>
  );
}
