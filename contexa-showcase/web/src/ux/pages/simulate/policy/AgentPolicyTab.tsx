import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { NO_CHOICE, type AgentRunStep, type DelegationChoice } from '../../../../api/agentCase';
import { useAgentMenu, useAgentMenuAnswer, type AgentMenuAnswer } from '../../../../api/agentMenu';
import { useLiveConfig } from '../../../../api/queries';
import { CONTROL_ORDER } from '../../../../domain/verdict';
import { formatNumber, formatUtc } from '../../../format';
import { agentConclusion, agentPath, firstStop } from '../../../simulate/agent';
import { AgentSteps, DelegationFacts } from '../../../simulate/AgentParts';
import { useRecordRows } from '../../../simulate/agentRows';
import { Badge, ButtonLink, CodeChip, Field, KeyValue, Loading, Note, Select } from '../../../ui';
import styles from './Policy.module.css';

/** The fewest alike requests in a row the old timeline folded into one line (pages/main/timelineFolding.ts FOLD_AT). */
const FOLD_AT = 5;

/** What makes two requests alike, as the old timeline read it: the same address and every control's same answer. */
function sameness(step: AgentRunStep): string {
  const answers = Object.keys(step.outcomes)
    .sort()
    .map((control) => `${control}:${step.outcomes[control]?.outcome ?? ''}/${step.outcomes[control]?.rule ?? ''}`)
    .join(';');
  return `${step.path}|${answers}`;
}

interface Burst {
  readonly from: number;
  readonly to: number;
  readonly count: number;
  readonly verdicts: number;
  readonly calls: number;
}

/**
 * UC-5 L-agent: every run of {@link FOLD_AT} or more alike requests, with how many of them Contexa decided on their own
 * and how many model calls they made, read from each stored step's decision (the old timeline's folded line).
 */
function burstsOf(steps: readonly AgentRunStep[]): readonly Burst[] {
  const bursts: Burst[] = [];
  let at = 0;
  while (at < steps.length) {
    const key = sameness(steps[at] as AgentRunStep);
    let end = at + 1;
    while (end < steps.length && sameness(steps[end] as AgentRunStep) === key) {
      end += 1;
    }
    if (end - at >= FOLD_AT) {
      const group = steps.slice(at, end);
      bursts.push({
        from: (group[0] as AgentRunStep).stepNo,
        to: (group[group.length - 1] as AgentRunStep).stepNo,
        count: group.length,
        verdicts: group.filter((step) => Boolean(step.decision?.final_action)).length,
        calls: group.reduce((sum, step) => sum + Number(step.decision?.model_calls ?? 0), 0),
      });
    }
    at = end;
  }
  return bursts;
}

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
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
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
  const points = config.data?.agentRunPoints;
  const tickets = config.data?.liveTicketsLeft;
  const costs = [
    points === undefined ? null : t('ux.policy.agent.quota', { points: n(points) }),
    tickets === undefined ? null : t('ux.policy.agent.tickets', { n: n(tickets) }),
  ].filter((line): line is string => line !== null);
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
        {/* UC-5 L-agent: what a real agent run costs the visitor and how many the day's share still pays for. */}
        {costs.length > 0 ? <p className={styles.source}>{costs.join(' · ')}</p> : null}
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
      <div className={styles.cardBody}>
        <AnswerMore answer={answer} />
      </div>
    </>
  );
}

/**
 * UC-5 L-agent: the stored run's facts the old menu showed below its timeline, each as the portal gives it: who the
 * scenario and this run send as, the portal's scoring of the work (requests sent, what the work needs, and per control
 * the first stop, what it let out and what went beyond the need), and every burst of alike requests.
 */
function AnswerMore({ answer }: { readonly answer: AgentMenuAnswer }) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const sender = (value: string) => t(`ux.policy.agent.sender.${value}`, { defaultValue: value });
  const proof = answer.run.proof ?? null;
  const bursts = burstsOf(answer.run.steps);
  const head = `${styles.proofCell} ${styles.proofHead}`;
  const num = `${styles.proofCell} ${styles.proofNum}`;
  return (
    <details className={styles.more}>
      <summary>{t('ux.policy.more')}</summary>
      <div className={styles.moreBody}>
        <KeyValue
          items={[
            { label: t('ux.policy.agent.caseSender'), value: sender(answer.caseView.sender) },
            { label: t('ux.policy.agent.runSender'), value: sender(answer.run.sender) },
            { label: t('ux.policy.agent.sent'), value: proof ? n(proof.sent) : '—' },
            {
              label: t('ux.policy.agent.needs'),
              value: !proof ? '—' : proof.workNeeds === null ? t('ux.policy.agent.needsNone') : n(proof.workNeeds),
            },
          ]}
        />
        {proof ? (
          <div className={styles.tableScroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
            <table className={styles.proofTable}>
              <caption className="ux-sr-only">{t('ux.policy.agent.proof.title')}</caption>
              <thead>
                <tr>
                  {[
                    'ux.lanes.control',
                    'ux.policy.agent.proof.firstStop',
                    'ux.policy.agent.proof.documents',
                    'ux.policy.agent.proof.items',
                    'ux.policy.agent.proof.records',
                    'ux.policy.agent.proof.changes',
                    'ux.policy.agent.proof.beyond',
                  ].map((key) => (
                    <th key={key} scope="col" className={head}>
                      {t(key)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {CONTROL_ORDER.map((control) => {
                  const counts = proof.controls[control] ?? null;
                  const value = (count: number | undefined) => (count === undefined ? '—' : n(count));
                  return (
                    <tr key={control}>
                      <th scope="row" className={styles.proofCell}>
                        {t(`ux.control.short.${control}`)}
                      </th>
                      <td className={styles.proofCell}>
                        {!counts
                          ? '—'
                          : counts.firstStopStep === null
                            ? t('ux.policy.agent.proof.never')
                            : t('ux.pick.requestNo', { n: counts.firstStopStep })}
                      </td>
                      {[counts?.documents, counts?.items, counts?.records, counts?.changes, counts?.beyondNeed].map(
                        (count, index) => (
                          <td key={index} className={num}>
                            {value(count)}
                          </td>
                        ),
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <Note>{t('ux.policy.agent.proof.unscored')}</Note>
        )}
        {bursts.map((burst) => (
          <p key={burst.from} className={styles.source}>
            {t('ux.policy.agent.burst', {
              n: n(burst.count),
              from: burst.from,
              to: burst.to,
              verdicts: n(burst.verdicts),
              calls: n(burst.calls),
            })}
          </p>
        ))}
      </div>
    </details>
  );
}
