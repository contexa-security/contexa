import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { postJson } from '../api/http';
import { useLiveConfig, useLiveRun, useVisitor } from '../api/queries';
import type { LiveRunView } from '../api/types';
import { AppHeader } from '../components/AppHeader';
import { LiveRunPanel } from '../components/LiveRunPanel';
import { StateScreen } from '../components/StateScreen';
import { refusalOf, type GateRefusal } from '../domain/live';
import { useTurnstile } from '../hooks/useTurnstile';
import styles from './TryPage.module.css';

/**
 * "Try it yourself" (docs/showcase/P3-설계.md 3절): the visitor runs a scenario live against the five security
 * approaches and, when Contexa asks for an additional check, answers it with the code from the demo inbox. A new run
 * passes the same gate as the exploration grid. Every result shown is the live result of this run.
 */
export default function TryPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const queryClient = useQueryClient();
  useVisitor();
  const config = useLiveConfig();
  const live = useLiveRun(config.isSuccess);
  const {
    container: turnstileContainer,
    token: turnstileToken,
    required: turnstileRequired,
    reset: resetTurnstile,
  } = useTurnstile(config.data?.turnstileSiteKey ?? null);
  const [refusal, setRefusal] = useState<GateRefusal | null>(null);

  async function post(path: string, body: unknown) {
    const result = await postJson<LiveRunView & { reason?: string }>(path, body);
    if (result.body && result.status < 300) {
      queryClient.setQueryData(['live-run'], result.body);
    }
    return result;
  }

  async function start(scenario: string) {
    setRefusal(null);
    const result = await post('/api/live/runs', { scenario, turnstileToken: turnstileToken });
    resetTurnstile();
    if (result.status !== 202) {
      setRefusal(refusalOf(result.status, result.body?.reason ?? null));
    }
  }

  const run = live.data ?? null;
  const scenario = config.data?.scenarios.find((option) => option.key === run?.scenario) ?? null;

  return (
    <>
      <a className="skip-link" href="#main">
        {t('app.skipToContent')}
      </a>
      <AppHeader />
      <main id="main" className={styles.page}>
        {config.isPending ? <StateScreen kind="loading" /> : null}
        {config.isError ? <StateScreen kind="notReady" /> : null}
        {config.data ? (
          <>
            <header className={styles.header}>
              <p className={styles.badge}>{t('try.devSpace')}</p>
              <h1 className={styles.title}>{t('try.title')}</h1>
              <p className={styles.lead}>{t('try.lead')}</p>
            </header>
            {refusal === 'dailyLimit' ? <StateScreen kind="dailyLimit" /> : null}
            {refusal === 'paused' ? <StateScreen kind="paused" /> : null}
            {refusal === 'turnstile' ? (
              <p className={styles.alert} role="alert">
                {t('explore.refused.turnstile')}
              </p>
            ) : null}
            {refusal === 'error' ? <StateScreen kind="error" onRetry={() => setRefusal(null)} /> : null}
            {run ? (
              <LiveRunPanel
                run={run}
                title={scenario ? scenario.title[language] : run.scenario}
                onRequestCode={() => void post('/api/live/runs/current/code', {})}
                onAnswer={(code) => void post('/api/live/runs/current/answer', { code })}
                onCancel={() => void post('/api/live/runs/current/cancel', {})}
                onRestart={() => void start(run.scenario)}
              />
            ) : (
              <ul className={styles.options}>
                {config.data.scenarios.map((option) => (
                  <li key={option.key} className={styles.option}>
                    <span className={styles.optionTitle}>{option.title[language]}</span>
                    <button
                      type="button"
                      className={styles.run}
                      disabled={turnstileRequired && !turnstileToken}
                      onClick={() => void start(option.key)}
                    >
                      {t('try.run')}
                    </button>
                  </li>
                ))}
              </ul>
            )}
            {turnstileRequired ? <div ref={turnstileContainer} className={styles.turnstile} /> : null}
          </>
        ) : null}
      </main>
    </>
  );
}
