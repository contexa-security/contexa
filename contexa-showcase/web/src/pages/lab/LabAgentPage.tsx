import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { AGENT_CASE, useAgentCase } from '../../api/agentCase';
import { useLiveConfig } from '../../api/queries';
import type { LiveAgentCase } from '../../api/types';
import { NextLink } from '../../components/journey/StepParts';
import { SubjectChip } from '../../components/main/SubjectChip';
import type { Subject } from '../../domain/subject';
import { subjectOfSender } from '../../domain/subject';
import { count } from '../../journey/format';
import { AGENT_PATHS } from '../main/agentGroup';
import { AgentMenuPanel } from './AgentMenuPanel';
import { DelegationEditPanel } from './DelegationEditPanel';
import { LabScreen } from './LabScreen';
import styles from './LabScreens.module.css';

/** The three ways an agent sends its requests, each told by its own subject chip. */
const PATHS: readonly { readonly subject: Subject; readonly key: 'delegated' | 'autonomous' | 'session' }[] = [
  { subject: 'delegated', key: 'delegated' },
  { subject: 'autonomous', key: 'autonomous' },
  { subject: 'session', key: 'session' },
];

/**
 * The agent lab (docs/agent Agent중심-화면 AS-6): beside the person lab's walk, a place to look at the agent cases: the
 * three ways an agent sends requests, each open case with the work its delegation records, its stored run, and, only
 * for a case the portal's settings open, the way to run it live. A run goes through the same gate as every live run
 * (the human check, the day's allotment, the visitor's points and agent runs), and the screen says how many agent runs
 * the portal counts as left today. Below them the agent menu (AC-4a) shows the results the portal runs ahead of time.
 */
export default function LabAgentPage() {
  const { t, i18n } = useTranslation();
  const config = useLiveConfig().data ?? null;
  const cases = config?.agentCases ?? [];
  return (
    <LabScreen
      step="agent"
      type="T1"
      title={t('labAgent.title')}
      purpose={t('labAgent.purpose')}
      back={{ to: '/lab', label: t('labAgent.back') }}
      main={
        cases.length > 0 ? (
          <NextLink to={AGENT_PATHS.request} label={t('labAgent.run')} />
        ) : null
      }
    >
      <section className={styles.agentBlock} aria-labelledby="lab-agent-paths">
        <h2 id="lab-agent-paths" className={styles.agentHeading}>
          {t('labAgent.paths')}
        </h2>
        <ul className={styles.agentList}>
          {PATHS.map((path) => (
            <li key={path.key} className={styles.agentRow}>
              <SubjectChip subject={path.subject} />
              <span>{t(`labAgent.path.${path.key}`)}</span>
            </li>
          ))}
        </ul>
      </section>
      <section className={styles.agentBlock} aria-labelledby="lab-agent-cases">
        <h2 id="lab-agent-cases" className={styles.agentHeading}>
          {t('labAgent.cases')}
        </h2>
        {cases.length === 0 ? <p className={styles.line}>{t('labAgent.none')}</p> : null}
        <ul className={styles.agentList}>
          {cases.map((found) => (
            <AgentCaseCard key={found.key} found={found} />
          ))}
        </ul>
        {config && cases.length > 0 && config.remainingAgentToday !== undefined ? (
          <p className={styles.line}>
            {t('labAgent.quota', {
              left: count(config.remainingAgentToday, i18n.language),
              daily: count(config.dailyAgentRuns ?? 0, i18n.language),
              points: count(config.agentRunPoints ?? 0, i18n.language),
            })}
          </p>
        ) : null}
      </section>
      <AgentMenuPanel />
      <DelegationEditPanel />
    </LabScreen>
  );
}

/** One open agent case: its title, the work its delegation records, its stored run, and the way to run it. */
function AgentCaseCard({ found }: { readonly found: LiveAgentCase }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  // The agent group's screens read the portal's one agent case; its record is the one every card of it shows.
  const view = useAgentCase(found.key || AGENT_CASE).data ?? null;
  const recorded = view?.recorded ?? null;
  return (
    <li className={styles.agentCard}>
      <SubjectChip subject={(view && subjectOfSender(view.sender)) || 'delegated'} />
      <b className={styles.agentCaseTitle}>{found.title[language]}</b>
      {view?.delegation ? (
        <span>{t('labAgent.work', { summary: view.delegation.summary[language] })}</span>
      ) : null}
      {recorded ? (
        <Link to={`${AGENT_PATHS.reason}?case=${found.key}`} className={styles.pathLink}>
          {t('labAgent.recorded')}
        </Link>
      ) : (
        <span className={styles.label}>{t('labAgent.noRecorded')}</span>
      )}
      <Link to={`${AGENT_PATHS.request}?case=${found.key}`} className={styles.pathLink}>
        {t('labAgent.run')}
      </Link>
    </li>
  );
}
