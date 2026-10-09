import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import {
  useJourneyUpdate,
  type EngineCall,
  type ExistingCall,
  type NumberRuleCall,
} from '../../../api/journey';
import type { LabCase } from '../../../api/lab';
import { useLiveConfig } from '../../../api/queries';
import { ActionChip } from '../../../components/common/ActionChip';
import { Icon, type IconName } from '../../../components/Icon';
import { ActionBar, StepHeader } from '../../../components/journey/StepParts';
import { useRecordPath } from '../../../components/replay/replayLine';
import { StateScreen } from '../../../components/StateScreen';
import { useLiveSend } from '../../../hooks/useLiveSend';
import { count } from '../../../journey/format';
import { CASES, stepPath, type Mode, type Role, type StepFlow } from '../experience';
import styles from '../Experience.module.css';

const ENGINE_CALLS: readonly { readonly call: EngineCall; readonly icon: IconName }[] = [
  { call: 'ALLOW', icon: 'check' },
  { call: 'CHALLENGE', icon: 'key' },
  { call: 'ESCALATE', icon: 'hourglass' },
  { call: 'BLOCK', icon: 'lock' },
];
const EXISTING_CALLS: readonly ExistingCall[] = ['ALL', 'SOME', 'NONE'];
const NUMBER_RULE_CALLS: readonly NumberRuleCall[] = ['STOP', 'PASS'];
const EXISTING = ['A', 'B', 'C1', 'C2'] as const;

interface PredictStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly flow: StepFlow;
}

/**
 * Try 1-3 and 2-3, your call (e1-predict): the visitor decides as Contexa before sending, then may add one guess: in
 * try 1 the four existing defences (what each looks at is folded under that question), in try 2 the threshold rule,
 * which is the point of act 2 (D-41). The call is stored on the server and scored there after the run. Sending starts
 * the live run through the same gate as every live run (the human check, the daily runs).
 */
export function PredictStep({ role, mode, labCase, flow }: PredictStepProps) {
  const { t, i18n } = useTranslation();
  // The synchronous tries' record is the recorded pair the first screen replays; an asynchronous try's is its own.
  const recordPath = useRecordPath(mode === 'sync' ? CASES.attacker.sync : labCase.key);
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const navigate = useNavigate();
  const update = useJourneyUpdate();
  const [engine, setEngine] = useState<EngineCall | null>(null);
  const [existing, setExisting] = useState<ExistingCall | null>(null);
  const [numberRule, setNumberRule] = useState<NumberRuleCall | null>(null);
  const config = useLiveConfig();
  const sender = useLiveSend(labCase.key, () => {
    void navigate(stepPath(role, 'run', mode));
  });
  const { turnstileContainer } = sender;
  const items = labCase.requests[0]?.items ?? null;
  const ready = sender.ready;

  /** Sends the run; with the visitor's call stored on the server first, which scores it after the run. */
  function send(withCall: boolean) {
    void sender.send(
      withCall && engine
        ? async () => {
            await update({
              prediction:
                role === 'attacker'
                  ? { experience: 'E1', engine, existing }
                  : { experience: 'E2', engine, numberRule },
            });
          }
        : undefined,
    );
  }

  return (
    <>
      <StepHeader title={t('e1.predict.title')} purpose={t('e1.purpose.predict')} />
      <fieldset className={styles.choices}>
        <legend className="visually-hidden">{t('e1.predict.title')}</legend>
        {ENGINE_CALLS.map(({ call, icon }) => (
          <label key={call} className={styles.choice} data-selected={engine === call || undefined}>
            <input
              type="radio"
              name="engine"
              className="visually-hidden"
              checked={engine === call}
              onChange={() => setEngine(call)}
            />
            <Icon name={icon} className={styles.choiceIcon} />
            <span className={styles.choiceName}>{t(`e1.predict.${call}`)}</span>
            <span className={styles.choiceHint}>{t(`e1.predict.${call}.hint`)}</span>
          </label>
        ))}
      </fieldset>
      {engine && role === 'owner' ? (
        <fieldset className={styles.guess}>
          <legend className={styles.guessTitle}>
            {t('e2.predict.numberRule')} <span className={styles.optional}>{t('e1.predict.optional')}</span>
          </legend>
          <div className={styles.guessOptions}>
            {NUMBER_RULE_CALLS.map((call) => (
              <label key={call} className={styles.pill} data-selected={numberRule === call || undefined}>
                <input
                  type="radio"
                  name="numberRule"
                  className="visually-hidden"
                  checked={numberRule === call}
                  onChange={() => setNumberRule(call)}
                />
                {t(`e2.predict.numberRule.${call}`)}
              </label>
            ))}
          </div>
        </fieldset>
      ) : null}
      {engine && role === 'attacker' ? (
        <fieldset className={styles.guess}>
          <legend className={styles.guessTitle}>
            {t('e1.predict.existingShort')}{' '}
            <span className={styles.optional}>{t('e1.predict.optional')}</span>
          </legend>
          <div className={styles.guessOptions}>
            {EXISTING_CALLS.map((call) => (
              <label key={call} className={styles.pill} data-selected={existing === call || undefined}>
                <input
                  type="radio"
                  name="existing"
                  className="visually-hidden"
                  checked={existing === call}
                  onChange={() => setExisting(call)}
                />
                {t(`e1.predict.existing.${call}`)}
              </label>
            ))}
          </div>
          <details className={styles.more}>
            <summary>{t('e1.predict.whatExisting')}</summary>
            <dl className={styles.approaches}>
              {EXISTING.map((control) => (
                <div key={control}>
                  <dt>{t(`control.${control}.name`)}</dt>
                  <dd>{t(`control.${control}.config`)}</dd>
                </div>
              ))}
            </dl>
          </details>
        </fieldset>
      ) : null}
      {sender.turnstileRequired ? <div ref={turnstileContainer} /> : null}
      {sender.waiting ? <p className={styles.lead}>{t('live.sendAfterEarlier')}</p> : null}
      {sender.refusal ? (
        <StateScreen
          kind={
            sender.refusal === 'dailyLimit' ? 'dailyLimit' : sender.refusal === 'paused' ? 'paused' : 'outage'
          }
          recordTo={recordPath}
          {...(sender.refusal === 'error' || sender.refusal === 'turnstile'
            ? { onRetry: () => send(engine !== null) }
            : {})}
        />
      ) : null}
      <ActionBar
        back={flow.back}
        main={
          <div className={styles.sendBlock}>
            <button
              type="button"
              className={styles.send}
              data-main
              disabled={!ready || engine === null}
              onClick={() => send(true)}
            >
              {sender.sending
                ? t('e1.predict.sending')
                : t('e1.predict.send', { items: items === null ? '-' : count(items, language) })}
              <Icon name="arrowRight" />
            </button>
            <span className={styles.sendNote}>
              {engine === null
                ? t('e1.predict.pickFirst')
                : config.data
                  ? t('exp.console.note', { remaining: config.data.remainingToday })
                  : null}
            </span>
            {/* The other way to send, right under the button it varies. */}
            <ActionChip icon="skip" variant="quiet" disabled={!ready} onClick={() => send(false)}>
              {t('e1.predict.sendWithout')}
            </ActionChip>
          </div>
        }
      />
    </>
  );
}
