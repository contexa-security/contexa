import { useState } from 'react';
import type { FormEvent } from 'react';
import { useTranslation } from 'react-i18next';
import type { LiveChallenge } from '../api/types';
import styles from './ChallengePanel.module.css';

interface ChallengePanelProps {
  readonly challenge: LiveChallenge;
  readonly onRequestCode: () => void;
  readonly onAnswer: (code: string) => void;
  readonly onCancel: () => void;
}

/**
 * Deck p.12, step 2: Contexa asked for an additional check and the data is on hold. The visitor asks for the code and
 * confirms it from the demo inbox, which stands in for the employee's mailbox. The engine's code is a long one-time
 * token, so the inbox offers it in one click like a mail button; typing it stays one step away. Either way the code
 * goes through the engine's own verification.
 */
export function ChallengePanel({ challenge, onRequestCode, onAnswer, onCancel }: ChallengePanelProps) {
  const { t } = useTranslation();
  const [code, setCode] = useState('');

  function submit(event: FormEvent) {
    event.preventDefault();
    if (code.trim()) {
      onAnswer(code.trim());
    }
  }

  return (
    <section className={styles.panel} aria-labelledby="challenge-title" data-stage={challenge.stage}>
      <h2 id="challenge-title" className={styles.title}>
        {t('try.challenge.title')}
      </h2>
      <p className={styles.body}>{t('try.challenge.body')}</p>
      <p className={styles.timer} role="timer">
        {t('try.challenge.secondsLeft', { seconds: challenge.secondsLeft })}
      </p>
      {challenge.stage === 'WAITING' ? (
        <div className={styles.actions}>
          <button type="button" className={styles.primary} onClick={onRequestCode}>
            {t('try.challenge.requestCode')}
          </button>
          <button type="button" className={styles.secondary} onClick={onCancel}>
            {t('try.challenge.cancel')}
          </button>
        </div>
      ) : null}
      {challenge.stage === 'CODE_SHOWN' && challenge.code ? (
        <>
          <section className={styles.inbox} aria-label={t('try.challenge.inbox')}>
            <p className={styles.inboxLabel}>{t('try.challenge.inbox')}</p>
            <p className={styles.inboxFrom}>{t('try.challenge.inboxFrom')}</p>
            <p className={styles.code} data-testid="inbox-code">
              {challenge.code}
            </p>
            <p className={styles.inboxNote}>{t('try.challenge.inboxNote')}</p>
            <div className={styles.actions}>
              <button type="button" className={styles.primary} onClick={() => onAnswer(challenge.code ?? '')}>
                {t('try.challenge.useCode')}
              </button>
              <button type="button" className={styles.secondary} onClick={onCancel}>
                {t('try.challenge.cancel')}
              </button>
            </div>
          </section>
          {challenge.error === 'WRONG_CODE' ? (
            <p className={styles.error} role="alert">
              {t('try.challenge.wrong', { attempts: challenge.attempts })}
            </p>
          ) : null}
          <details className={styles.manual}>
            <summary>{t('try.challenge.manual')}</summary>
            <form className={styles.form} onSubmit={submit}>
              <label className={styles.label} htmlFor="challenge-code">
                {t('try.challenge.codeLabel')}
              </label>
              <input
                id="challenge-code"
                className={styles.input}
                value={code}
                onChange={(event) => setCode(event.target.value)}
                autoComplete="one-time-code"
                spellCheck={false}
              />
              <div className={styles.actions}>
                <button type="submit" className={styles.secondary}>
                  {t('try.challenge.submit')}
                </button>
              </div>
            </form>
          </details>
        </>
      ) : null}
      {challenge.stage === 'VERIFYING' ? (
        <p className={styles.body} role="status">
          {t('try.challenge.verifying')}
        </p>
      ) : null}
    </section>
  );
}
