import { useTranslation } from 'react-i18next';
import { useAgentCase } from '../../../../api/agentCase';
import { useLiveConfig } from '../../../../api/queries';
import { AGENT_MAIN, agentPath, delegationState, useAgentCases } from '../../../simulate/agent';
import { DelegationChain, Instruction } from '../../../simulate/AgentParts';
import { FlowProgress, FlowSteps, GroupTabs } from '../../../simulate/FlowFrame';
import { PERSON_KEYS, truthOf } from '../../../simulate/person';
import { Badge, ButtonLink, Loading, Note, PageHead } from '../../../ui';
import flow from '../../../simulate/Flow.module.css';
import styles from '../../../simulate/Agent.module.css';

/**
 * Step 1 of the agent delegation flow (기획안 7.0 d-pick-agent): a real business agent (Spring AI) sends requests of its
 * own choosing with a token it was delegated. The chain shows who delegated what to which agent; each card shows the
 * scenario's ground truth (never sent to any control), the instruction word for word and what the scenario checks.
 * Only the cases the portal opens are shown (DEC-27).
 */
export default function AgentPickPage() {
  const { t, i18n } = useTranslation();
  const live = useLiveConfig();
  const cases = useAgentCases();
  const main = useAgentCase(AGENT_MAIN);
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const resource = main.data?.delegation?.resources[0] ?? null;
  return (
    <>
      <FlowSteps current="pick" />
      <PageHead title={t('ux.pick.title')} desc={t('ux.agentPick.desc')} />
      <GroupTabs
        current="agent"
        counts={{
          person: PERSON_KEYS.length,
          agent: live.data?.agentCases?.length ?? null,
          surge: live.data ? (live.data.burst ? 1 : 0) : null,
        }}
      />
      <section className={styles.chainCard} aria-label={t('ux.agent.chain.label')}>
        <DelegationChain
          delegator={main.data ? t(`ux.person.${main.data.protagonist}`, { defaultValue: main.data.protagonist }) : '…'}
          agent={main.data?.agentTitle[language] ?? '…'}
          resource={resource ? t('ux.agent.chain.documents', { project: resource }) : '…'}
          checks
        />
      </section>
      {cases.pending ? (
        <Loading rows={4} />
      ) : cases.listed.length === 0 ? (
        <Note>{t('ux.agentPick.none')}</Note>
      ) : (
        <div className={styles.cards}>
          {cases.listed.map((key) => (
            <CaseCard key={key} caseKey={key} />
          ))}
        </div>
      )}
      <FlowProgress group="agent" />
    </>
  );
}

/** One scenario: its key, ground truth, the instruction the agent got, what it checks, and the way in. */
function CaseCard({ caseKey }: { readonly caseKey: string }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const agentCase = useAgentCase(caseKey);
  const data = agentCase.data ?? null;
  const main = caseKey === AGENT_MAIN;
  const pairOfMain = data?.classification === 'NORMAL' && caseKey !== AGENT_MAIN;
  const truth = truthOf(data?.classification);
  const title = data?.title[language] ?? caseKey;
  const state = delegationState(data?.delegation);
  const purpose = data?.delegation
    ? t(`ux.agent.purpose.${data.delegation.purpose}`, { defaultValue: data.delegation.purpose })
    : null;
  return (
    <article className={flow.branch} data-recommended={main || undefined} aria-labelledby={`agent-${caseKey}`}>
      <div className={flow.branchTop}>
        <Badge tone="line">
          <span className={styles.cardKey}>{caseKey}</span>
        </Badge>
        <span className={flow.branchTags}>
          {main ? (
            <Badge tone="line" icon="star">
              {t('ux.flow.recommended')}
            </Badge>
          ) : null}
          {pairOfMain ? <Badge tone="line">{t('ux.flow.controlRun')}</Badge> : null}
          <Badge tone="line">
            {t(`ux.flow.truth.${truth}`)}
            {truth === 'undetermined' ? ` · ${t('ux.agentPick.splits')}` : ''}
          </Badge>
        </span>
      </div>
      <h3 id={`agent-${caseKey}`} className={flow.branchTitle}>
        {title}
      </h3>
      {data ? <Instruction text={data.instruction[language] ?? data.instruction.en ?? ''} /> : <Loading rows={2} />}
      {i18n.exists(`ux.agent.check.${caseKey}`) ? <p className={styles.check}>{t(`ux.agent.check.${caseKey}`)}</p> : null}
      <div className={flow.branchFoot}>
        <span>
          {data
            ? [
                state === 'none' ? t('ux.agent.delegation.state.none') : purpose,
                state !== 'none' ? t(`ux.agent.delegation.state.${state}`) : null,
                truth === 'undetermined' ? t('ux.agentPick.unscored') : null,
              ]
                .filter(Boolean)
                .join(' · ')
            : null}
        </span>
        <ButtonLink
          to={agentPath(caseKey, 'review')}
          size="sm"
          variant={main ? 'primary' : 'secondary'}
          iconAfter="arrow-right"
          label={`${title} ${t('ux.flow.select')}`}
        >
          {t('ux.flow.select')}
        </ButtonLink>
      </div>
    </article>
  );
}
