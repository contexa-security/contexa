import { useQueryClient } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { postJson } from '../api/http';
import { useCombination, useCombinationGrid, useLiveConfig, useLiveRun, useVisitor } from '../api/queries';
import type { CombinationView, LiveRunView } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import { BoundaryMap } from '../components/BoundaryMap';
import { FactPanel } from '../components/FactPanel';
import { LiveRunPanel } from '../components/LiveRunPanel';
import { OutcomeStrip } from '../components/OutcomeStrip';
import { StateScreen } from '../components/StateScreen';
import { VerdictChip } from '../components/VerdictChip';
import { keyOf, PRESETS, selectionOf, type Selection } from '../domain/explore';
import { refusalOf, type GateRefusal } from '../domain/live';
import { engineReasonLine } from '../domain/reasons';
import { useTurnstile } from '../hooks/useTurnstile';
import styles from './ExplorePage.module.css';

const COUNT = new Intl.NumberFormat('en-US');
const ACTIVE = new Set(['QUEUED', 'STARTING', 'RUNNING', 'CHALLENGE']);

type StartResult = (LiveRunView & { reason?: string }) | { recorded: true; combination: CombinationView } | null;

/**
 * Screen 3, exploring conditions (deck p.13): the visitor changes only the company's facts and finds the engine's
 * boundary cell by cell. A cell someone already ran shows that real run and its time; a new cell runs live once,
 * through the gate (deck p.28), and becomes the record for everyone after.
 */
export default function ExplorePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const queryClient = useQueryClient();
  useVisitor();
  const config = useLiveConfig();
  const [selection, setSelection] = useState<Selection>(PRESETS.night);
  const key = keyOf(selection);
  const grid = useCombinationGrid(selection.employee, selection.ticket, selection.device);
  const combination = useCombination(key);
  const live = useLiveRun(config.isSuccess);
  const {
    container: turnstileContainer,
    token: turnstileToken,
    required: turnstileRequired,
    reset: resetTurnstile,
  } = useTurnstile(config.data?.turnstileSiteKey ?? null);
  const [refusal, setRefusal] = useState<GateRefusal | null>(null);
  const run = live.data ?? null;
  const running = run !== null && ACTIVE.has(run.status);
  const finished = run !== null && (run.status === 'COMPLETED' || run.status === 'FAILED') ? run.liveRunId : null;

  useEffect(() => {
    if (finished) {
      void queryClient.invalidateQueries({ queryKey: ['grid'] });
      void queryClient.invalidateQueries({ queryKey: ['combination'] });
      void queryClient.invalidateQueries({ queryKey: ['live-config'] });
    }
  }, [finished, queryClient]);

  async function postLive(path: string, body: unknown) {
    const result = await postJson<LiveRunView>(path, body);
    if (result.body && result.status < 300) {
      queryClient.setQueryData(['live-run'], result.body);
    }
  }

  async function start(cellKey: string) {
    setRefusal(null);
    const result = await postJson<StartResult>('/api/live/combinations', {
      key: cellKey,
      turnstileToken: turnstileToken,
    });
    resetTurnstile();
    const body = result.body;
    if (result.status === 200 && body && 'recorded' in body) {
      queryClient.setQueryData(['combination', cellKey], body.combination);
      void queryClient.invalidateQueries({ queryKey: ['grid'] });
      return;
    }
    if (result.status === 202 && body && !('recorded' in body)) {
      queryClient.setQueryData(['live-run'], body);
      return;
    }
    setRefusal(refusalOf(result.status, body && 'reason' in body ? (body.reason ?? null) : null));
  }

  const view = combination.data ?? null;
  const runSelection = run ? selectionOf(run.scenario) : null;

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        <header className={styles.header}>
          <h1 className={styles.title}>{t('explore.title')}</h1>
          <p className={styles.lead}>{t('explore.lead')}</p>
        </header>
        <div className={styles.layout}>
          <FactPanel
            selection={selection}
            onChange={(next) => {
              setRefusal(null);
              setSelection(next);
            }}
          />
          <div className={styles.main}>
            <section className={styles.current} aria-labelledby="current-title">
              <h2 id="current-title" className={styles.sectionTitle}>
                {t('explore.current')}
              </h2>
              <p className={styles.request}>{describe(selection, t)}</p>
              {combination.isPending ? <StateScreen kind="loading" /> : null}
              {combination.isError ? <StateScreen kind="error" onRetry={() => void combination.refetch()} /> : null}
              {view?.recorded && view.result ? <RecordedResult view={view} language={language} /> : null}
              {view && !view.recorded ? (
                <div className={styles.notRun}>
                  <p className={styles.notRunText}>{t('explore.notRunYet')}</p>
                  {config.data ? (
                    <>
                      <button
                        type="button"
                        className={styles.run}
                        disabled={running || (turnstileRequired && !turnstileToken) || config.data.paused}
                        onClick={() => void start(key)}
                      >
                        {t('explore.run')}
                      </button>
                      <p className={styles.remaining}>
                        {t('explore.remaining', {
                          remaining: config.data.remainingToday,
                          daily: config.data.dailyRuns,
                        })}
                      </p>
                      {turnstileRequired ? <div ref={turnstileContainer} className={styles.turnstile} /> : null}
                    </>
                  ) : (
                    <p className={styles.remaining}>{t('explore.liveOff')}</p>
                  )}
                </div>
              ) : null}
              {refusal === 'dailyLimit' ? <StateScreen kind="dailyLimit" /> : null}
              {refusal === 'paused' || (config.data?.paused && view && !view.recorded) ? (
                <StateScreen kind="paused" />
              ) : null}
              {refusal === 'turnstile' ? (
                <p className={styles.alert} role="alert">
                  {t('explore.refused.turnstile')}
                </p>
              ) : null}
              {refusal === 'error' ? <StateScreen kind="outage" onRetry={() => void start(key)} /> : null}
            </section>
            {run && (running || (run.scenario === key && !view?.recorded)) ? (
              <LiveRunPanel
                run={run}
                title={runSelection ? describe(runSelection, t) : run.scenario}
                onRequestCode={() => void postLive('/api/live/runs/current/code', {})}
                onAnswer={(code) => void postLive('/api/live/runs/current/answer', { code })}
                onCancel={() => void postLive('/api/live/runs/current/cancel', {})}
                onRestart={() => void start(run.scenario)}
              />
            ) : null}
            <section className={styles.mapSection} aria-label={t('explore.map')}>
              {grid.data ? (
                <BoundaryMap
                  cells={grid.data.cells}
                  selected={key}
                  onSelect={(cell) => {
                    setRefusal(null);
                    setSelection({ ...selection, slot: cell.slot, items: cell.items });
                  }}
                />
              ) : null}
              {grid.isPending ? <StateScreen kind="loading" /> : null}
              {grid.isError ? <StateScreen kind="error" onRetry={() => void grid.refetch()} /> : null}
              <p className={styles.mapNote}>{t('explore.mapNote')}</p>
            </section>
          </div>
        </div>
      </main>
    </>
  );
}

function describe(selection: Selection, t: TFunction): string {
  return t('explore.request', {
    employee: t(`explore.employee.${selection.employee}`),
    slot: t(`explore.slot.${selection.slot}`),
    items: COUNT.format(selection.items),
    ticket: t(`explore.ticket.${selection.ticket}`),
    device: t(`explore.device.${selection.device}`),
  });
}

function RecordedResult({ view, language }: { readonly view: CombinationView; readonly language: 'ko' | 'en' }) {
  const { t } = useTranslation();
  const result = view.result;
  if (!result) {
    return null;
  }
  const engine = result.layers.find((layer) => layer.control === 'D');
  const when = view.recordedAt
    ? new Intl.DateTimeFormat(language, { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(
        new Date(view.recordedAt),
      )
    : '';
  return (
    <div className={styles.recorded}>
      <p className={styles.recordedAt}>{t('explore.recordedAt', { date: `${when} UTC` })}</p>
      <OutcomeStrip outcomes={result.layers.map(({ control, outcome }) => ({ control, outcome }))} />
      {engine ? (
        <div className={styles.engine}>
          <VerdictChip verdict={engine.verdict} showCode />
          <p className={styles.reason}>{engineReasonLine(engine, result.engineReason, t)}</p>
        </div>
      ) : null}
    </div>
  );
}
