import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useJourneyUpdate, type EngineCall } from '../../../api/journey';
import type { LabCase } from '../../../api/lab';
import { Icon } from '../../../components/Icon';
import { ScreenBody } from '../../../components/journey/ScreenBody';
import { useRecordPath } from '../../../components/replay/replayLine';
import { StateScreen } from '../../../components/StateScreen';
import { VERDICTS } from '../../../domain/verdict';
import { useLiveSend } from '../../../hooks/useLiveSend';
import { useJourneyPlace } from '../../../journey/useJourneyPlace';
import { CASES, stepPath, type Mode, type Role, type StepFlow } from '../experience';
import styles from './PredictStep.module.css';

/** The four judgments to pick from, named with the judgment words every screen uses (화면재편-기획안 11.2). */
// ESCALATE is no final response: it hands the request to the second analysis (판정층 E-8b).
const CALLS: readonly EngineCall[] = ['ALLOW', 'CHALLENGE', 'BLOCK'];

interface PredictStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly flow: StepFlow;
}

/**
 * Screens 1-2 and 2-1, pick first (T3): one question, four judgments to pick from, and Send, off until one is picked.
 * The pick is stored on the server, which compares it with Contexa's judgment after the run; sending starts the live
 * run through the same gate as every live run (the human check, the daily runs).
 */
export function PredictStep({ role, mode, labCase, flow }: PredictStepProps) {
  const { t } = useTranslation();
  // The synchronous tries' record is the recorded pair the first screen replays; an asynchronous try's is its own.
  const recordPath = useRecordPath(mode === 'sync' ? CASES.attacker.sync : labCase.key);
  const navigate = useNavigate();
  const update = useJourneyUpdate();
  const number = useJourneyPlace().screen?.number ?? (role === 'attacker' ? '1-2' : '2-1');
  const [engine, setEngine] = useState<EngineCall | null>(null);
  const sender = useLiveSend(labCase.key, () => {
    void navigate(stepPath(role, 'run', mode));
  });
  const { turnstileContainer } = sender;
  const title = t(`screen.${number}.title`);

  /** Sends the run with the visitor's pick stored on the server first; only the judgment is asked now. */
  function send() {
    if (engine === null) {
      return;
    }
    const call = engine;
    void sender.send(async () => {
      await update({ prediction: { experience: role === 'attacker' ? 'E1' : 'E2', engine: call } });
    });
  }

  return (
    <ScreenBody
      title={title}
      purpose={t(`screen.${number}.guide`)}
      back={flow.back}
      main={
        <button
          type="button"
          className={styles.send}
          data-main
          disabled={!sender.ready || engine === null}
          onClick={send}
        >
          {t(sender.sending ? 'p1.predict.sending' : 'p1.predict.send')}
          <Icon name="arrowRight" className={styles.sendIcon} />
        </button>
      }
    >
      {/* The choices are counted apart from the screen's limits (RC-1) and read as one block. */}
      <fieldset className={styles.choices} data-count="exempt" data-block>
        <legend className="visually-hidden">{title}</legend>
        {CALLS.map((call) => (
          <label key={call} className={styles.choice} data-selected={engine === call || undefined}>
            <input
              type="radio"
              name="engine"
              className="visually-hidden"
              checked={engine === call}
              onChange={() => setEngine(call)}
            />
            <Icon name={VERDICTS[call].icon} className={styles.choiceIcon} />
            <span className={styles.choiceName}>{t(VERDICTS[call].labelKey)}</span>
            <span className={styles.choiceHint}>{t(`p1.predict.hint.${call}`)}</span>
          </label>
        ))}
      </fieldset>
      {sender.turnstileRequired ? <div ref={turnstileContainer} /> : null}
      {sender.waiting ? <p className={styles.note}>{t('p1.predict.waitEarlier')}</p> : null}
      {sender.refusal ? (
        <StateScreen
          kind={
            sender.refusal === 'dailyLimit' ? 'dailyLimit' : sender.refusal === 'paused' ? 'paused' : 'outage'
          }
          recordTo={recordPath}
          {...(sender.refusal === 'error' || sender.refusal === 'turnstile' ? { onRetry: send } : {})}
        />
      ) : null}
    </ScreenBody>
  );
}
