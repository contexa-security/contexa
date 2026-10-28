import { useTranslation } from 'react-i18next';
import { useAgentCase, useAgentCaseKey, type AgentDelegation, type AgentRunStep } from '../../api/agentCase';
import { Term } from '../../components/common/Glossary';
import { Icon } from '../../components/Icon';
import { operationName, periodWords, requestOperation, requestTarget } from './agentGroup';
import { count } from '../../journey/format';
import { companyClock } from './mainCases';
import styles from './DelegationParts.module.css';

/**
 * Who delegated, which agent works and on what (docs/agent Agent중심-화면 AS-4): one line of three, read left to right,
 * from the case's own record. A person, an agent and the target of the work, with an arrow between each.
 */
export function DelegationChain({
  delegator,
  agent,
  target,
}: {
  readonly delegator: string;
  readonly agent: string;
  readonly target: string;
}) {
  const { t } = useTranslation();
  const nodes = [
    { id: 'delegator', icon: 'user', name: <Term term="delegator">{t('main.agent.delegator')}</Term>, value: delegator },
    { id: 'agent', icon: 'agent', name: <Term term="businessAgent">{t('main.agent.agent')}</Term>, value: agent },
    { id: 'target', icon: 'box', name: t('main.agent.chain.target'), value: target },
  ] as const;
  return (
    <ol className={styles.chain} aria-label={t('main.agent.chain.label')}>
      {nodes.map((node, index) => (
        <li key={node.id} className={styles.node} data-node={node.id}>
          {index > 0 ? <Icon name="arrowRight" className={styles.arrow} /> : null}
          <Icon name={node.icon} className={styles.icon} />
          <span className={styles.nodeText}>
            <span className={styles.nodeName}>{node.name}</span>
            <b className={styles.nodeValue}>{node.value}</b>
          </span>
        </li>
      ))}
    </ol>
  );
}

/**
 * The chain of the agent group's case, read from the portal's case record: nothing until the case is read, so a screen
 * never shows a guess.
 */
export function AgentChainLine() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const found = useAgentCase(useAgentCaseKey(true)).data;
  if (!found) {
    return null;
  }
  const resources = found.delegation?.resources ?? [];
  return (
    <DelegationChain
      delegator={t(`person.${found.protagonist}`, { defaultValue: found.protagonist })}
      agent={found.agentTitle[language]}
      target={resources.length > 0 ? resources.join(', ') : (found.delegation?.project ?? '-')}
    />
  );
}

/**
 * The delegation record and the request set against each other, row by row (docs/agent Agent중심-화면 AS-4): what the
 * work may do against what the request does, the resources, and the period against the request's time. Both columns
 * read the same way: the screen does not mark a difference, the engine names it (the next card).
 */
export function DelegationCompare({
  delegation,
  request,
  runCompanyTime,
  ended = null,
}: {
  readonly delegation: AgentDelegation;
  readonly request: AgentRunStep;
  readonly runCompanyTime: string | null;
  /** When the delegation ended (the run's company time plus the record's end), if it did; said beside the period. */
  readonly ended?: string | null;
}) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const exists = (key: string) => i18n.exists(key);
  const operation = requestOperation(request);
  const rows = [
    {
      id: 'what',
      record: delegation.operations.map((name) => operationName(t, exists, name)).join(', '),
      requested: operation ? operationName(t, exists, operation) : (request.tool?.tool ?? '-'),
    },
    {
      id: 'target',
      record: delegation.resources.join(', '),
      requested: requestTarget(request),
    },
    {
      id: 'when',
      record: periodWords(t, delegation) + (ended ? ` · ${t('main.agent.endedAt', { at: companyClock(t, ended) })}` : ''),
      requested: companyClock(t, request.companyTime ?? runCompanyTime) ?? '-',
    },
    // AS-12: a delegation that states a quantity limit is set against the amount the request asks for
    ...(delegation.maxItemsPerRequest != null
      ? [
          {
            id: 'limit',
            record: t('main.agent.limit', { n: count(delegation.maxItemsPerRequest, i18n.language) }),
            requested:
              typeof request.tool?.arguments['items'] === 'number'
                ? t('main.agent.limit.asked', { n: count(request.tool.arguments['items'], i18n.language) })
                : '-',
          },
        ]
      : []),
  ];
  return (
    <section className={styles.compare} aria-labelledby="delegation-compare">
      <h2 id="delegation-compare" className={styles.compareTitle}>
        {t('main.agent.compare.title')}
      </h2>
      <p className={styles.goal}>{t('main.agent.compare.goal', { summary: delegation.summary[language] })}</p>
      <table className={styles.table}>
        <thead>
          <tr>
            <th scope="col" className={styles.corner} />
            <th scope="col">{t('main.agent.compare.record')}</th>
            <th scope="col">{t('main.agent.compare.requestN', { n: request.stepNo })}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <th scope="row">{t(`main.agent.compare.${row.id}`)}</th>
              <td data-label={t('main.agent.compare.record')}>{row.record}</td>
              <td data-label={t('main.agent.compare.requestN', { n: request.stepNo })}>{row.requested}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className={styles.address}>
        {t('main.6-3.address')}: <code>{request.path}</code>
      </p>
    </section>
  );
}
