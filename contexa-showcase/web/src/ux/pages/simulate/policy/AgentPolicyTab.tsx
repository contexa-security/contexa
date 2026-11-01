import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { NO_CHOICE, type DelegationChoice } from '../../../../api/agentCase';
import { useAgentMenu, useAgentMenuAnswer, type AgentMenuAnswer } from '../../../../api/agentMenu';
import { useLiveConfig } from '../../../../api/queries';
import { formatUtc } from '../../../format';
import { agentConclusion, agentPath, firstStop } from '../../../simulate/agent';
import { AgentSteps, DelegationFacts } from '../../../simulate/AgentParts';
import { useRecordRows } from '../../../simulate/agentRows';
import { Badge, ButtonLink, CodeChip, Field, Loading, Note, Select } from '../../../ui';
import styles from './Policy.module.css';

/**
 * The agent policy (기획안 11 L-agent, DEC-34): an agent's requests come with the same token; what happens when the
 * work goes outside what was delegated. The answers are the daily job's stored real runs (no model is called here):
 * one value of the editable case's delegation changed, and every case of the menu on each path an agent sends on.
 * "Run it for real" leads to the agent flow's second step with the same change.
 */
export function AgentPolicyTab() {
  return (
    <div className={styles.stack}>
      <DelegationEdit />
      <Menu />
    </div>
  );
}

function DelegationEdit() {
  const { t } = useTranslation();
  const config = useLiveConfig();
  const menu = useAgentMenu();
  const edit = config.data?.delegationEdit ?? null;
  const [choice, setChoice] = useState<DelegationChoice>(NO_CHOICE);
  const [path, setPath] = useState<string>('OAUTH2_DELEGATED');
  const picked: DelegationChoice = edit
    ? {
        quantity: choice.quantity ?? edit.quantities[0] ?? null,
        period: choice.period ?? edit.periods[0] ?? null,
        operations: choice.operations ?? edit.operations.at(-1) ?? null,
      }
    : NO_CHOICE;
  const answer = useAgentMenuAnswer(edit ? edit.case : null, path, picked);
  if (config.isPending) {
    return <Loading rows={4} />;
  }
  if (!edit) {
    return null;
  }
  const paths = menu.data?.paths ?? ['OAUTH2_DELEGATED', 'OAUTH2_AGENT', 'SESSION'];
  const query = new URLSearchParams({
    quantity: String(picked.quantity ?? ''),
    period: picked.period ?? '',
    operations: picked.operations ?? '',
  });
  return (
    <section className={styles.card} aria-labelledby="policy-edit">
      <header className={styles.cardHead}>
        <h2 id="policy-edit" className={styles.cardTitle}>
          {t('ux.policy.agent.edit.title')}
        </h2>
        <p className={styles.cardSub}>{t('ux.policy.agent.edit.sub', { key: edit.case })}</p>
      </header>
      <div className={styles.pickers} data-four="true">
        <Field label={t('ux.policy.agent.quantity')}>
          {(props) => (
            <Select
              {...props}
              value={String(picked.quantity ?? '')}
              onChange={(event) => setChoice({ ...choice, quantity: Number(event.target.value) })}
            >
              {edit.quantities.map((value) => (
                <option key={value} value={value}>
                  {t('ux.agent.delegation.limitValue', { n: value, count: value })}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t('ux.policy.agent.period')}>
          {(props) => (
            <Select
              {...props}
              value={picked.period ?? ''}
              onChange={(event) => setChoice({ ...choice, period: event.target.value })}
            >
              {edit.periods.map((value) => (
                <option key={value} value={value}>
                  {t(`ux.policy.agent.periods.${value}`, { defaultValue: value })}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t('ux.policy.agent.operations')}>
          {(props) => (
            <Select
              {...props}
              value={picked.operations ?? ''}
              onChange={(event) => setChoice({ ...choice, operations: event.target.value })}
            >
              {edit.operations.map((value) => (
                <option key={value} value={value}>
                  {t(`ux.policy.agent.ops.${value}`, { defaultValue: value })}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t('ux.policy.agent.path')}>
          {(props) => (
            <Select {...props} value={path} onChange={(event) => setPath(event.target.value)}>
              {paths.map((value) => (
                <option key={value} value={value}>
                  {t(`ux.policy.agent.paths.${value}`, { defaultValue: value })}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
      <Answer answer={answer.data ?? null} pending={answer.isPending} missing={answer.isError} showDelegation />
      <div className={styles.cardBody}>
        <ButtonLink to={agentPath(edit.case, 'review', `?${query.toString()}`)} variant="primary" iconAfter="arrow-right">
          {t('ux.policy.agent.runReal')}
        </ButtonLink>
      </div>
    </section>
  );
}

function Menu() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const menu = useAgentMenu();
  const data = menu.data ?? null;
  const [caseKey, setCaseKey] = useState<string | null>(null);
  const [path, setPath] = useState<string | null>(null);
  const first = data?.items.find((item) => item.choice === null) ?? null;
  const shownCase = caseKey ?? first?.caseKey ?? data?.cases[0]?.key ?? null;
  const shownPath = path ?? first?.path ?? data?.paths[0] ?? null;
  const answer = useAgentMenuAnswer(shownCase, shownPath);
  if (menu.isPending) {
    return <Loading rows={4} />;
  }
  if (!data || data.cases.length === 0) {
    return null;
  }
  return (
    <section className={styles.card} aria-labelledby="policy-menu">
      <header className={styles.cardHead}>
        <h2 id="policy-menu" className={styles.cardTitle}>
          {t('ux.policy.agent.menu.title')}
        </h2>
        <p className={styles.cardSub}>{t('ux.policy.agent.menu.sub')}</p>
      </header>
      <div className={styles.pickers}>
        <Field label={t('ux.policy.agent.menu.case')}>
          {(props) => (
            <Select {...props} value={shownCase ?? ''} onChange={(event) => setCaseKey(event.target.value)}>
              {data.cases.map((option) => (
                <option key={option.key} value={option.key}>
                  {option.key} · {option.title[language] ?? option.title.en}
                </option>
              ))}
            </Select>
          )}
        </Field>
        <Field label={t('ux.policy.agent.path')}>
          {(props) => (
            <Select {...props} value={shownPath ?? ''} onChange={(event) => setPath(event.target.value)}>
              {data.paths.map((value) => (
                <option key={value} value={value}>
                  {t(`ux.policy.agent.paths.${value}`, { defaultValue: value })}
                </option>
              ))}
            </Select>
          )}
        </Field>
      </div>
      <Answer answer={answer.data ?? null} pending={answer.isPending} missing={answer.isError} />
    </section>
  );
}

/** One stored answer (ST-39): what Contexa did with the agent's work, when it ran, and every request. */
function Answer({
  answer,
  pending,
  missing,
  showDelegation = false,
}: {
  readonly answer: AgentMenuAnswer | null;
  readonly pending: boolean;
  readonly missing: boolean;
  readonly showDelegation?: boolean;
}) {
  const { t } = useTranslation();
  const rows = useRecordRows(answer?.run ?? null);
  if (pending) {
    return <Loading rows={3} />;
  }
  if (missing || !answer) {
    return (
      <div className={styles.cardBody}>
        <Note>{t('ux.policy.agent.notYet')}</Note>
      </div>
    );
  }
  const stop = firstStop(answer.run);
  const conclusion = agentConclusion(answer.run);
  return (
    <>
      <div className={styles.cardBody}>
        <p className={styles.answerTitle}>
          {t(`ux.agentResult.conclusion.${conclusion}`, {
            n: stop?.stepNo ?? answer.run.steps.length,
            sent: answer.run.steps.length,
            count: answer.run.steps.length,
          })}
        </p>
        <p className={styles.source}>
          {t('ux.policy.agent.ranAt', { at: formatUtc(answer.ranAt) })}{' '}
          {answer.stale ? <Badge tone="none">{t('ux.policy.agent.stale')}</Badge> : null}{' '}
          <CodeChip value={answer.run.runId} />
        </p>
        {showDelegation ? <DelegationFacts delegation={answer.run.delegation ?? answer.caseView.delegation} /> : null}
      </div>
      {rows.length > 0 ? <AgentSteps rows={rows} caption={t('ux.agentLive.steps.title')} /> : null}
    </>
  );
}
