import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { choiceQuery, NO_CHOICE, useAgentCase } from '../../api/agentCase';
import { useAgentMenuAnswer } from '../../api/agentMenu';
import { useLiveConfig } from '../../api/queries';
import { SubjectChip } from '../../components/main/SubjectChip';
import type { Subject } from '../../domain/subject';
import { count } from '../../journey/format';
import { AGENT_PATHS } from '../main/agentGroup';
import { StoredAnswer } from './AgentMenuPanel';
import { ChoiceGroup } from './ChoiceGroup';
import styles from './AgentMenuPanel.module.css';

/** What a visitor has picked: the three values of the delegation and the path the work is sent on. */
interface Picked {
  readonly quantity: number;
  readonly period: string;
  readonly operations: string;
  readonly path: string;
}

/** The case's own delegation: the limit it states, a valid period, the export allowed; the delegated path. */
const OWN: Picked = { quantity: 40, period: 'VALID', operations: 'READ_EXPORT', path: 'OAUTH2_DELEGATED' };

const SUBJECT_OF_PATH: Readonly<Record<string, Subject>> = {
  OAUTH2_DELEGATED: 'delegated',
  OAUTH2_AGENT: 'autonomous',
  SESSION: 'session',
};

/**
 * The delegation edit (docs/agent Agent중심-화면 AS-12). The work stays an export of 400 documents; the visitor changes what the
 * person allowed (the quantity limit, the period, the allowed operations, each from the portal's fixed lists) and picks
 * the path. The stored result of that combination is read first and calls no model; a real run of the same choice
 * goes through the portal's gate from 6-1, on the delegated path. Nothing shows while the portal offers no edit.
 */
export function DelegationEditPanel() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const config = useLiveConfig().data ?? null;
  const edit = config?.delegationEdit ?? null;
  const [picked, setPicked] = useState<Picked>(OWN);
  const asked = useAgentCase(edit?.case ?? '', NO_CHOICE, edit !== null).data ?? null;
  const answer = useAgentMenuAnswer(edit?.case ?? null, picked.path, {
    quantity: picked.quantity,
    period: picked.period,
    operations: picked.operations,
  });
  if (edit === null) {
    return null;
  }
  const set = (change: Partial<Picked>) => setPicked((now) => ({ ...now, ...change }));
  // A real run names only the values that differ from the case's own delegation.
  const differing = choiceQuery({
    quantity: picked.quantity === OWN.quantity ? null : picked.quantity,
    period: picked.period === OWN.period ? null : picked.period,
    operations: picked.operations === OWN.operations ? null : picked.operations,
  });
  const live = `${AGENT_PATHS.request}?case=${edit.case}${differing === '' ? '' : `&${differing.slice(1)}`}`;
  const tickets = config?.liveTicketsLeft;
  return (
    <section className={styles.menu} aria-labelledby="lab-agent-edit">
      <h2 id="lab-agent-edit" className={styles.heading}>
        {t('labAgent.edit.title')}
      </h2>
      <p className={styles.line}>{t('labAgent.edit.intro')}</p>
      {asked ? (
        <p className={styles.line}>
          <b>{t('labAgent.edit.asked')}</b> {asked.instruction[language]}
        </p>
      ) : null}
      <ChoiceGroup
        name="edit-quantity"
        label={t('labAgent.edit.quantity')}
        value={picked.quantity}
        onChange={(quantity) => set({ quantity })}
        choices={edit.quantities.map((n) => ({
          value: n,
          label: t('labAgent.edit.quantityValue', { n: count(n, i18n.language) }),
        }))}
      />
      <ChoiceGroup
        name="edit-period"
        label={t('labAgent.edit.period')}
        value={picked.period}
        onChange={(period) => set({ period })}
        choices={edit.periods.map((value) => ({ value, label: t(`main.agent.choice.period.${value}`) }))}
      />
      <ChoiceGroup
        name="edit-operations"
        label={t('labAgent.edit.operations')}
        value={picked.operations}
        onChange={(operations) => set({ operations })}
        choices={edit.operations.map((value) => ({ value, label: t(`main.agent.choice.operations.${value}`) }))}
      />
      <ChoiceGroup
        name="edit-path"
        label={t('labAgent.menu.path')}
        value={picked.path}
        onChange={(path) => set({ path })}
        choices={['OAUTH2_DELEGATED', 'OAUTH2_AGENT', 'SESSION'].map((value) => {
          const subject = SUBJECT_OF_PATH[value];
          return {
            value,
            label: (
              <>
                {subject ? <SubjectChip subject={subject} /> : null}
                <span>{t(`labAgent.menu.path.${value}`)}</span>
              </>
            ),
          };
        })}
      />
      <section className={styles.result} aria-labelledby="lab-agent-edit-result">
        <h3 id="lab-agent-edit-result" className="visually-hidden">
          {t('labAgent.edit.result')}
        </h3>
        {answer.isPending ? <p className={styles.line}>{t('labAgent.menu.loading')}</p> : null}
        {answer.isError ? <p className={styles.line}>{t('labAgent.menu.noAnswer')}</p> : null}
        {answer.data ? (
          <StoredAnswer key={`${picked.path}/${picked.quantity}/${picked.period}/${picked.operations}`} answer={answer.data} />
        ) : null}
      </section>
      <p className={styles.line}>
        <Link to={live} className={styles.guessButton}>
          {t('labAgent.edit.live')}
        </Link>
        {tickets === undefined ? null : <span> {t('labAgent.edit.tickets', { n: count(tickets, i18n.language) })}</span>}
      </p>
    </section>
  );
}
