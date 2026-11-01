import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { Bar, Icon, Stepper } from '../ui';
import { useAgentRuns, usePersonRuns } from './useFlow';
import styles from './Flow.module.css';

const STEPS = ['pick', 'review', 'live', 'result'] as const;
export type FlowStepName = (typeof STEPS)[number];

/** The four steps of a threat simulation above its one decision (기획안 7.0, F-3). */
export function FlowSteps({ current }: { readonly current: FlowStepName }) {
  const { t } = useTranslation();
  return <Stepper steps={STEPS.map((step) => t(`ux.flow.step.${step}`))} current={STEPS.indexOf(current)} />;
}

/** "Scenarios run in this group n / total" in business words only (F-9): no score, no badge, no game. */
export function FlowProgress({
  note,
  group = 'person',
}: {
  readonly note?: ReactNode;
  readonly group?: 'person' | 'agent';
}) {
  const { t } = useTranslation();
  const person = usePersonRuns();
  const agent = useAgentRuns();
  const runs = group === 'agent' ? agent : person;
  if (!runs.ready) {
    return null;
  }
  return (
    <section className={styles.progress} aria-label={t('ux.flow.progressLabel')}>
      <Icon name="list-checks" className={styles.progressIcon} />
      <b className={styles.progressText}>{t('ux.flow.progress', { n: runs.done, total: runs.total })}</b>
      <span className={styles.progressBar}>
        <Bar label={t('ux.flow.progressLabel')} value={runs.done / runs.total} tone="link" />
      </span>
      <span className={styles.progressNote}>
        {note ?? (
          <>
            {t('ux.flow.progressNote')} <Link to="/runs">{t('ux.menu.runs')}</Link>
          </>
        )}
      </span>
    </section>
  );
}

/** The group tabs of the first step: account threats, agent delegation, request surge, with the scenarios each holds. */
export function GroupTabs({
  current,
  counts,
}: {
  readonly current: 'person' | 'agent' | 'surge';
  readonly counts: Readonly<Record<'person' | 'agent' | 'surge', number | null>>;
}) {
  const { t } = useTranslation();
  const tabs = [
    { id: 'person', to: '/simulate/person', icon: 'user-round' },
    { id: 'agent', to: '/simulate/agent', icon: 'bot' },
    { id: 'surge', to: '/simulate/surge', icon: 'layers' },
  ] as const;
  return (
    <nav aria-label={t('ux.pick.groups')} className={styles.groups}>
      {tabs.map((tab) => (
        <Link
          key={tab.id}
          to={tab.to}
          className={styles.group}
          aria-current={tab.id === current ? 'page' : undefined}
        >
          <Icon name={tab.icon} size="md" />
          {t(`ux.pick.tab.${tab.id}`)}
          {counts[tab.id] !== null ? (
            <>
              {' '}
              <span className={styles.groupCount}>{counts[tab.id]}</span>
            </>
          ) : null}
        </Link>
      ))}
    </nav>
  );
}
