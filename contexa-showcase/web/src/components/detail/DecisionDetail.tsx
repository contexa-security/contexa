import { useRef, type KeyboardEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { useAgentRun } from '../../api/agentCase';
import { useAnatomy, type DecisionAnatomyView } from '../../api/anatomy';
import { HttpError } from '../../api/http';
import { useRunScore } from '../../api/queries';
import { subjectOfSender } from '../../domain/subject';
import { ActionChip } from '../common/ActionChip';
import { SubjectChip } from '../main/SubjectChip';
import { Modal } from '../common/Modal';
import { StateScreen } from '../StateScreen';
import { AnswerTab } from './AnswerTab';
import { OriginalTab } from './OriginalTab';
import { ProcessTab } from './ProcessTab';
import { PromptTab } from './PromptTab';
import { ReceivedTab } from './ReceivedTab';
import { RulesTab } from './RulesTab';
import { SummaryTab } from './SummaryTab';
import { TabFrame } from './TabFrame';
import { DETAIL_TABS, useDetail, type DetailTab } from './useDetail';
import styles from './DecisionDetail.module.css';

/**
 * The decision details (화면재편-구현계획 5절, RO-1, RO-8, RO-11): one window over the screen it was opened from, with
 * its own address, the situation's name in its title, the requests of a run when it has more than one, and seven tabs.
 * Each tab is the redesign's frame inside the window: a body and one source line, within the limits of one screen
 * (the tab buttons aside). Mounted once for every screen; any screen opens it with useDetail().show(runId, step).
 */
export function DecisionDetailModal() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const score = useRunScore(detail.runId, 'detail', 1).data ?? null;
  const steps = score ? Math.max(1, score.executedSteps) : null;
  // Who sent the requests (docs/agent Agent중심-화면 AS-1), read from the run's stored agent record: a run that has
  // none was sent by a person. Nothing is drawn until the record has answered, so the chip is never a guess.
  const agent = useAgentRun(detail.runId);
  const sender = agent.data
    ? subjectOfSender(agent.data.sender)
    : agent.error instanceof HttpError && agent.error.status === 404
      ? 'person'
      : null;
  // The situation's plain name, the same one the lab and the benchmark show (R7-검수 V-45); a situation without one
  // keeps the definition's own name, shown as stored (frozen with the definition).
  const stored = score?.title?.[language] ?? null;
  const plain = score ? t(`bench.r7.caseName.${score.scenarioKey}`, { defaultValue: '' }) : '';
  const title = score ? (
    <>
      {t('detail.r7.title')}{' '}
      {plain ? plain : stored ? <span data-original>{stored}</span> : t('detail.r7.unnamed')}
      {sender ? (
        <>
          {' '}
          <SubjectChip subject={sender} />
        </>
      ) : null}
    </>
  ) : (
    t('detail.r7.titleLoading')
  );
  return (
    <Modal open={detail.open} onClose={detail.hide} title={title} wide>
      {detail.runId ? (
        <DecisionDetail runId={detail.runId} step={detail.step} steps={steps ?? 1} tab={detail.tab} />
      ) : null}
    </Modal>
  );
}

interface DecisionDetailProps {
  readonly runId: string;
  readonly step: number;
  readonly steps: number;
  readonly tab: DetailTab;
}

function DecisionDetail({ runId, step, steps, tab }: DecisionDetailProps) {
  const { t } = useTranslation();
  const detail = useDetail();
  const anatomy = useAnatomy(runId, step);
  const view = anatomy.data ?? null;
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  // The arrow keys move between the tabs and select the one they reach (the ARIA tabs pattern).
  const onKey = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const last = DETAIL_TABS.length - 1;
    const next =
      event.key === 'ArrowRight'
        ? (index + 1) % DETAIL_TABS.length
        : event.key === 'ArrowLeft'
          ? (index + last) % DETAIL_TABS.length
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? last
              : null;
    if (next === null) {
      return;
    }
    event.preventDefault();
    detail.setTab(DETAIL_TABS[next] ?? 'summary');
    tabs.current[next]?.focus();
  };
  return (
    <div className={styles.detail}>
      {steps > 1 ? (
        <div className={styles.requests} role="group" aria-label={t('detail.r7.requests')}>
          <ActionChip
            icon="arrowLeft"
            size="sm"
            disabled={step <= 1}
            onClick={() => detail.setStep(step - 1)}
          >
            {t('detail.r7.previous')}
          </ActionChip>
          <span className={styles.requestNow}>{t('detail.r7.request', { step, steps })}</span>
          <ActionChip
            icon="arrowRight"
            size="sm"
            disabled={step >= steps}
            onClick={() => detail.setStep(step + 1)}
          >
            {t('detail.r7.next')}
          </ActionChip>
        </div>
      ) : null}
      <div className={styles.tabs} role="tablist" aria-label={t('detail.r7.tabs')}>
        {DETAIL_TABS.map((name, index) => (
          <button
            key={name}
            ref={(element) => {
              tabs.current[index] = element;
            }}
            type="button"
            role="tab"
            id={`detail-tab-${name}`}
            aria-selected={tab === name}
            aria-controls="detail-panel"
            tabIndex={tab === name ? 0 : -1}
            className={styles.tab}
            onClick={() => detail.setTab(name)}
            onKeyDown={(event) => onKey(event, index)}
          >
            {t(`detail.r7.tab.${name}`)}
          </button>
        ))}
      </div>
      {/* B-04: the panel scrolls inside the window of one height, so the keyboard reaches it too. */}
      <section
        id="detail-panel"
        role="tabpanel"
        aria-labelledby={`detail-tab-${tab}`}
        className={styles.panel}
        tabIndex={0}
      >
        {anatomy.isPending ? <StateScreen kind="loading" /> : null}
        {anatomy.isError ? (
          <TabFrame>
            <p className={styles.line}>{t('detail.r7.notFound')}</p>
          </TabFrame>
        ) : null}
        {view ? <TabBody key={`${tab}-${step}`} tab={tab} view={view} runId={runId} step={step} /> : null}
      </section>
    </div>
  );
}

interface TabBodyProps {
  readonly tab: DetailTab;
  readonly view: DecisionAnatomyView;
  readonly runId: string;
  readonly step: number;
}

function TabBody({ tab, ...props }: TabBodyProps) {
  switch (tab) {
    case 'received':
      return <ReceivedTab {...props} />;
    case 'process':
      return <ProcessTab {...props} />;
    case 'prompt':
      return <PromptTab {...props} />;
    case 'rules':
      return <RulesTab {...props} />;
    case 'answer':
      return <AnswerTab {...props} />;
    case 'original':
      return <OriginalTab {...props} />;
    default:
      return <SummaryTab {...props} />;
  }
}
