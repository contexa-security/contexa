import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { AgentDelegation, AgentRecorded } from '../../api/agentCase';
import { CONTROL_ORDER, type Verdict } from '../../domain/verdict';
import { formatNumber } from '../format';
import { Badge, DataTable, Icon, VerdictBadge, type Column, type UxIconName } from '../ui';
import {
  delegationState,
  offsetWords,
  operationWords,
  periodMarks,
  recordedWords,
  senderWords,
  type AgentCell,
} from './agent';
import type { AgentRow } from './agentRows';
import { CONTROL_TONE } from './controls';
import styles from './Agent.module.css';

/** Who sends the case's requests, as the portal's case names its sender (AS-1). */
export function SenderBadge({ sender }: { readonly sender: string }) {
  const { t } = useTranslation();
  return (
    <Badge tone="line">
      {t('ux.agent.sender.label')} · {senderWords(t, sender)}
    </Badge>
  );
}

/**
 * The facts every agent screen shows once beside the case: who sends its requests, and how many times the operator
 * recorded the case with how many of them ending as the latest did (AS-1, AS-5; counted by the portal).
 */
export function CaseFacts({
  sender,
  recorded,
}: {
  readonly sender: string;
  readonly recorded: AgentRecorded | null;
}) {
  const { t, i18n } = useTranslation();
  return (
    <>
      <SenderBadge sender={sender} />
      <span className={styles.caseRecorded}>
        {t('ux.agent.recorded.label')} {recordedWords(t, recorded, i18n.language) ?? '—'}
      </span>
    </>
  );
}

const OWN_VERDICTS: ReadonlySet<string> = new Set(['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK']);

/** Contexa's own decision of one request as stored: its badge, the code for any other word, a dash without one. */
function OwnVerdict({ verdict }: { readonly verdict: string | null | undefined }) {
  if (!verdict) {
    return <>—</>;
  }
  return OWN_VERDICTS.has(verdict) ? <VerdictBadge verdict={verdict as Verdict} /> : <code>{verdict}</code>;
}

/** The delegation chain (기획안 7.6): the person who delegated → the AI agent → the resource it works on. */
export function DelegationChain({
  delegator,
  agent,
  resource,
  checks = false,
}: {
  readonly delegator: ReactNode;
  readonly agent: ReactNode;
  readonly resource: ReactNode;
  /** The three things that hold for every case: the token, the permission and the person's delegation are valid. */
  readonly checks?: boolean;
}) {
  const { t } = useTranslation();
  const nodes: readonly (readonly [UxIconName, string, ReactNode])[] = [
    ['user', t('ux.agent.chain.delegator'), delegator],
    ['bot', t('ux.agent.chain.agent'), agent],
    ['folder-open', t('ux.agent.chain.resource'), resource],
  ];
  return (
    <div className={styles.chain} data-checks={checks || undefined}>
      <ol className={styles.nodes} aria-label={t('ux.agent.chain.label')}>
        {nodes.map(([icon, label, value]) => (
          <li key={label} className={styles.node}>
            <span className={styles.nodeIcon}>
              <Icon name={icon} />
            </span>
            <span className={styles.nodeText}>
              <span className={styles.nodeLabel}>{label}</span>
              <b className={styles.nodeValue}>{value}</b>
            </span>
          </li>
        ))}
      </ol>
      {checks ? (
        <ul className={styles.checks} aria-label={t('ux.agent.chain.checksLabel')}>
          {(['token', 'permission', 'delegation'] as const).map((check) => (
            <li key={check}>
              <Icon name="check" size="sm" />
              {t(`ux.agent.chain.check.${check}`)}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

/** What the delegating person told the agent, word for word (원문). */
export function Instruction({ text, label }: { readonly text: string; readonly label?: string }) {
  const { t } = useTranslation();
  return (
    <figure className={styles.instruction}>
      <figcaption className={styles.instructionLabel}>
        <Icon name="message-square-text" size="sm" />
        {label ?? t('ux.agent.instruction')}
      </figcaption>
      <blockquote className={styles.instructionText}>{text}</blockquote>
    </figure>
  );
}

/** The delegation as the company recorded it: purpose, scope, limit, period with the agent's request on its line. */
export function DelegationFacts({
  delegation,
  changed = [],
}: {
  readonly delegation: AgentDelegation | null;
  /** The values the visitor changed (the delegation-change case, ST-31), marked where they show. */
  readonly changed?: readonly ('quantity' | 'period' | 'operations')[];
}) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  if (!delegation) {
    return (
      <p className={styles.noDelegation}>
        <Icon name="triangle-alert" size="md" />
        {t('ux.agent.delegation.none')}
      </p>
    );
  }
  const state = delegationState(delegation);
  const marks = periodMarks(delegation);
  const changedMark = (what: 'quantity' | 'period' | 'operations') =>
    changed.includes(what) ? <Badge tone="sel">{t('ux.agent.delegation.changed')}</Badge> : null;
  return (
    <dl className={styles.delegation}>
      <dt>{t('ux.agent.delegation.purpose')}</dt>
      <dd>{delegation.summary[language] ?? delegation.summary.en ?? '—'}</dd>
      <dt>{t('ux.agent.delegation.scope')}</dt>
      <dd className={styles.scope}>
        {delegation.operations.map((operation) => (
          <Badge key={operation} tone="line">
            {operationWords(t, operation)}
          </Badge>
        ))}
        {delegation.resources.map((resource) => (
          <Badge key={resource} tone="line" icon="folder-open">
            {resource}
          </Badge>
        ))}
        {changedMark('operations')}
      </dd>
      {delegation.maxItemsPerRequest != null ? (
        <>
          <dt>{t('ux.agent.delegation.limit')}</dt>
          <dd>
            {t('ux.agent.delegation.limitValue', {
              n: formatNumber(delegation.maxItemsPerRequest, i18n.language),
              count: delegation.maxItemsPerRequest,
            })}{' '}
            {changedMark('quantity')}
          </dd>
        </>
      ) : null}
      <dt>{t('ux.agent.delegation.period')}</dt>
      <dd>
        <span className={styles.periodLine}>
          {delegation.validFromMinutes !== null && delegation.validUntilMinutes !== null
            ? t('ux.agent.delegation.periodValue', {
                from: offsetWords(t, delegation.validFromMinutes),
                until: offsetWords(t, delegation.validUntilMinutes),
              })
            : '—'}{' '}
          <Badge tone={state === 'active' ? 'none' : 'block'}>{t(`ux.agent.delegation.state.${state}`)}</Badge>{' '}
          {changedMark('period')}
        </span>
        {marks ? (
          <span className={styles.period} aria-hidden="true">
            <span className={styles.periodTrack} />
            <span
              className={styles.periodFill}
              style={{ insetInlineStart: `${marks.start * 100}%`, inlineSize: `${(marks.end - marks.start) * 100}%` }}
            />
            <span className={styles.periodNow} style={{ insetInlineStart: `${marks.now * 100}%` }} />
          </span>
        ) : null}
        {marks ? (
          <span className={styles.legend}>
            <span>
              <i className={styles.legendPeriod} aria-hidden="true" />
              {t('ux.agent.delegation.period')}
            </span>
            <span>
              <i className={styles.legendNow} aria-hidden="true" />
              {t('ux.agent.delegation.request')}
            </span>
          </span>
        ) : null}
      </dd>
    </dl>
  );
}

/** A control's answer to one of the agent's requests: the verdict badge, or "delegator check" when D asked. */
export function AgentCellBadge({ cell }: { readonly cell: AgentCell }) {
  const { t } = useTranslation();
  if (cell === null) {
    return <span className={styles.wait}>…</span>;
  }
  if (cell === 'CONFIRM') {
    return (
      <Badge tone="stepup" icon="user-round-check">
        {t('ux.agent.cell.confirm')}
      </Badge>
    );
  }
  return <VerdictBadge verdict={cell} />;
}

/** The agent's requests one row each (기획안 7.6 3단계), with each control's answer; a phone stacks each row. */
export function AgentSteps({
  rows,
  caption,
  marked = null,
  decisions = false,
}: {
  readonly rows: readonly AgentRow[];
  readonly caption: string;
  /** The request the delegating person was asked about: its row carries the mark. */
  readonly marked?: number | null;
  /** Adds each request's own stored decision and its model calls (a stored run's rows only). */
  readonly decisions?: boolean;
}) {
  const { t, i18n } = useTranslation();
  const columns: Column<AgentRow>[] = [
    {
      key: 'request',
      header: t('ux.agent.steps.request'),
      strong: true,
      render: (row) => (
        <span className={styles.request}>
          <span className={styles.requestNo}>{t('ux.pick.requestNo', { n: row.stepNo })}</span>
          <span>{row.name}</span>
          {row.path ? (
            <code className={styles.requestPath} title={row.path}>
              {row.path}
            </code>
          ) : null}
        </span>
      ),
    },
    ...CONTROL_ORDER.map(
      (control): Column<AgentRow> => ({
        key: control,
        header: t(`ux.control.short.${control}`),
        render: (row) => (
          <span className={styles.cell} data-control={CONTROL_TONE[control]}>
            <AgentCellBadge cell={row.cells[control]} />
          </span>
        ),
      }),
    ),
    {
      key: 'items',
      header: t('ux.agent.steps.items'),
      numeric: true,
      render: (row) =>
        row.items === null ? '…' : t('ux.facts.items', { count: row.items, n: formatNumber(row.items, i18n.language) }),
    },
    ...(decisions
      ? [
          {
            key: 'verdict',
            header: t('ux.agent.steps.verdict'),
            render: (row: AgentRow) => <OwnVerdict verdict={row.verdict} />,
          },
          {
            key: 'calls',
            header: t('ux.agent.steps.calls'),
            numeric: true,
            render: (row: AgentRow) =>
              row.modelCalls === null || row.modelCalls === undefined ? '—' : formatNumber(row.modelCalls, i18n.language),
          },
        ]
      : []),
  ];
  return (
    <DataTable
      caption={caption}
      columns={columns}
      rows={rows}
      rowKey={(row) => String(row.stepNo)}
      highlighted={(row) => row.stepNo === marked}
      stack
    />
  );
}
