import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useJourney } from '../../api/journey';
import { useVisitor } from '../../api/queries';
import { ChoiceCards, type Choice } from '../../components/main/ChoiceCards';
import { ChooseScreen } from '../../components/main/ChooseScreen';
import { DEFAULT_ROUTE, entryOf } from '../../journey/journey';
import { rememberedTrack, rememberTrack, type OwnTrack } from '../../journey/trackMemory';
import { AGENT_PATHS } from './agentGroup';
import styles from './DeeperPage.module.css';

interface Deep {
  readonly id: string;
  readonly to: string;
  readonly icon: Choice['icon'];
}

/** The deeper screens each track offers, in the order they are told (기획안 5.4절). Nothing of the old screens is left out. */
const BOTH: readonly Deep[] = [
  { id: 'evidence', to: '/evidence/map', icon: 'search' },
  { id: 'rules', to: '/compare/rule', icon: 'chart' },
  { id: 'map', to: '/intro/map', icon: 'book' },
];
const PERSON: readonly Deep[] = [
  { id: 'diff', to: '/normal/diff', icon: 'refresh' },
  { id: 'suspected', to: '/normal/check', icon: 'user' },
];
const AGENT: readonly Deep[] = [
  { id: 'confirm', to: AGENT_PATHS.confirm, icon: 'check' },
  { id: 'end', to: '/agent/end', icon: 'delegate' },
  { id: 'burst', to: AGENT_PATHS.burst, icon: 'chart' },
];

function cardsOf(t: (key: string) => string, deeps: readonly Deep[]): readonly Choice[] {
  return deeps.map((deep) => ({
    id: deep.id,
    title: t(`deeper.${deep.id}.title`),
    to: deep.to,
    ...(deep.icon ? { icon: deep.icon } : {}),
  }));
}

/**
 * D-1, the deeper hub (구현계획 NW-5): the screens that were the old flow's explanations and proofs, behind one choice
 * each. A track lists its own first; a visitor who comes without a track sees both. Every one leads back here, and the
 * foot leads back to the next-chooser the visitor came from.
 */
export default function DeeperPage() {
  const { t } = useTranslation();
  const [params] = useSearchParams();
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const named = params.get('track');
  // without a named track, the track of the screen the visitor last stood on, else the one the hub was last opened for
  const last = DEFAULT_ROUTE.find((screen) => screen.id === journey.data?.state.step)?.track;
  const track: OwnTrack | null =
    named === 'A' || named === 'H' ? named : last === 'A' || last === 'H' ? last : rememberedTrack();
  useEffect(() => {
    if (track !== null) {
      rememberTrack(track);
    }
  }, [track]);
  const back =
    track === null
      ? { to: '/', label: t('frame.back') }
      : { to: `${entryOf(track)}/next`, label: t('deeper.back') };
  const own = track === 'A' ? AGENT : PERSON;
  return (
    <ChooseScreen title={t('main.D-1.title')} intro={t('main.D-1.intro')} back={back}>
      {track === null ? (
        <>
          <h2 className={styles.group}>{t('deeper.group.person')}</h2>
          <ChoiceCards cards={cardsOf(t, PERSON)} label={t('deeper.group.person')} />
          <h2 className={styles.group}>{t('deeper.group.agent')}</h2>
          <ChoiceCards cards={cardsOf(t, AGENT)} label={t('deeper.group.agent')} />
          <h2 className={styles.group}>{t('deeper.group.both')}</h2>
          <ChoiceCards cards={cardsOf(t, BOTH)} label={t('deeper.group.both')} />
        </>
      ) : (
        <ChoiceCards
          cards={cardsOf(t, [...own, ...BOTH])}
          label={t('main.D-1.title')}
          limit={4}
          more={t('choose.more')}
        />
      )}
    </ChooseScreen>
  );
}
