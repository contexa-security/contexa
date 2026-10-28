import { useTranslation } from 'react-i18next';
import { AGENT_CASE } from '../../api/agentCase';
import { useLiveConfig } from '../../api/queries';
import { ChoiceCards, type Choice } from '../../components/main/ChoiceCards';
import { ChooseScreen } from '../../components/main/ChooseScreen';
import { StateScreen } from '../../components/StateScreen';
import type { IconName } from '../../components/Icon';
import { AGENT_PATHS } from './agentGroup';

/** The order the open cases are offered in: the legitimate work first, then the attacks the demo measures most. */
const ORDER = ['N1', 'T5', 'M22A', 'M10A', 'M14A'] as const;
const ICONS: Readonly<Record<string, IconName>> = {
  N1: 'check',
  T5: 'clock',
  M22A: 'link',
  M10A: 'key',
  M14A: 'info',
};

function rank(key: string): number {
  const at = (ORDER as readonly string[]).indexOf(key);
  return at < 0 ? ORDER.length : at;
}

/**
 * A-1, what work to give the agent (구현계획 NW-3): the agent's track opens with the portal's open agent cases as
 * cards. A card has its words in the dictionary where the demo knows the case; any other open case shows its own
 * title. A case is told by its title alone, so the screen stays within 120 characters whatever the portal opens (AC-N1). The card leads to the give-the-work screen (6-1) with the case named in the address.
 */
export default function AgentChoosePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const config = useLiveConfig();
  // a portal that lists no agent case still opens the agent track with its first case
  const open = config.data?.agentCases ?? [];
  const keys = open.length > 0 ? [...open].sort((a, b) => rank(a.key) - rank(b.key)) : [];
  const cards: readonly Choice[] =
    keys.length > 0
      ? keys.map((found) => {
          const own = `choose.agent.${found.key}`;
          return {
            id: found.key,
            title: i18n.exists(`${own}.title`) ? t(`${own}.title`) : found.title[language],
            to: `${AGENT_PATHS.request}?case=${found.key}`,
            icon: ICONS[found.key] ?? 'agent',
          };
        })
      : [
          {
            id: AGENT_CASE,
            title: t(`choose.agent.${AGENT_CASE}.title`),
            to: AGENT_PATHS.request,
            icon: ICONS[AGENT_CASE] ?? 'agent',
          },
        ];
  return (
    <ChooseScreen title={t('main.A-1.title')} intro={t('main.A-1.intro')}>
      {config.isPending ? <StateScreen kind="loading" /> : null}
      {config.isError ? <StateScreen kind="error" /> : null}
      {config.isPending || config.isError ? null : (
        <ChoiceCards cards={cards} label={t('main.A-1.title')} limit={4} more={t('choose.more')} />
      )}
    </ChooseScreen>
  );
}
