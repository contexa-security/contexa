import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { postJson } from '../../api/http';
import { usePeerAssessments } from '../../api/lab';
import { useRunScore } from '../../api/queries';
import styles from './AssessPanel.module.css';

type AssessState = 'idle' | 'sending' | 'STORED' | 'DUPLICATE' | 'NOT_OWNER' | 'NO_STEP' | 'error';

/**
 * Activity 5 (docs/showcase/데모-재설계.md 0, 5A.1): the visitor assesses Contexa's decision of one request of their own
 * run, once (V-7), and then sees how other visitors assessed the same request (same case definition and engine
 * setting), counted after the delay. The lab and the story's acts use it.
 *
 * @param reasons the assessment reasons the portal offers (/api/lab/options)
 * @param number  the activity's number shown in the heading, when the screen numbers its sections
 */
export function AssessPanel({
  runId,
  reasons: offered,
  number,
}: {
  readonly runId: string;
  readonly reasons: readonly string[];
  readonly number?: string;
}) {
  const { t } = useTranslation();
  const score = useRunScore(runId, 'assess', 0);
  const decided = (score.data?.verdicts ?? [])
    .filter((verdict) => verdict.score.finalAction !== null)
    .map((verdict) => verdict.score.stepNo);
  const [chosenStep, setChosenStep] = useState<number | null>(null);
  const step = chosenStep ?? decided[0] ?? null;
  const [verdict, setVerdict] = useState<'SOUND' | 'UNSOUND' | 'UNSURE' | null>(null);
  const [reasons, setReasons] = useState<readonly string[]>([]);
  const [state, setState] = useState<AssessState>('idle');
  async function submit() {
    if (step === null || verdict === null) {
      return;
    }
    setState('sending');
    let result: string | undefined;
    try {
      const response = await postJson<{ result: string }>(
        `/api/runs/${encodeURIComponent(runId)}/steps/${step}/assessment`,
        { verdict, reasons },
      );
      result = response.body?.result;
    } catch {
      result = undefined;
    }
    setState(
      result === 'STORED' || result === 'DUPLICATE' || result === 'NOT_OWNER' || result === 'NO_STEP'
        ? result
        : 'error',
    );
  }
  const done = state === 'STORED' || state === 'DUPLICATE';
  return (
    <section className={styles.section} aria-labelledby="assess-title">
      <h2 id="assess-title" className={styles.sectionTitle}>
        {number ? <span className={styles.sectionNumber}>{number}</span> : null}
        {t('lab.assess.title')}
      </h2>
      {decided.length === 0 ? (
        <p className={styles.note}>{t('lab.assess.noDecision')}</p>
      ) : (
        <>
          {decided.length > 1 ? (
            <label className={styles.field}>
              <span className={styles.fieldName}>{t('lab.assess.step')}</span>
              <select
                className={styles.select}
                value={String(step)}
                disabled={done}
                onChange={(event) => setChosenStep(Number(event.target.value))}
              >
                {decided.map((number) => (
                  <option key={number} value={String(number)}>
                    {t('lab.result.step', { n: number })}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
          <fieldset className={styles.calls} disabled={done}>
            <legend className={styles.fieldName}>{t('lab.assess.question')}</legend>
            {(['SOUND', 'UNSOUND', 'UNSURE'] as const).map((value) => (
              <label key={value} className={styles.callChoice} data-selected={verdict === value || undefined}>
                <input
                  type="radio"
                  name="assess"
                  checked={verdict === value}
                  onChange={() => setVerdict(value)}
                />
                {t(`lab.assess.${value}`)}
              </label>
            ))}
          </fieldset>
          <fieldset className={styles.reasons} disabled={done}>
            <legend className={styles.fieldName}>{t('lab.assess.reasons')}</legend>
            {offered.map((reason) => (
              <label key={reason} className={styles.reasonChoice}>
                <input
                  type="checkbox"
                  checked={reasons.includes(reason)}
                  onChange={(event) =>
                    setReasons(
                      event.target.checked
                        ? [...reasons, reason]
                        : reasons.filter((value) => value !== reason),
                    )
                  }
                />
                {t(`lab.reason.${reason}`)}
              </label>
            ))}
          </fieldset>
          <button
            type="button"
            className={styles.send}
            disabled={verdict === null || done || state === 'sending'}
            onClick={() => void submit()}
          >
            {t('lab.assess.submit')}
          </button>
          {state !== 'idle' && state !== 'sending' ? (
            <p className={styles.note} role="status">
              {t(`lab.assess.result.${state}`)}
            </p>
          ) : null}
          {done && step !== null ? <PeerSection runId={runId} step={step} /> : null}
        </>
      )}
    </section>
  );
}

/** How other visitors assessed the same request, with the number of assessments (J-5). */
function PeerSection({ runId, step }: { readonly runId: string; readonly step: number }) {
  const { t } = useTranslation();
  const peers = usePeerAssessments(runId, step);
  if (!peers.data) {
    return peers.isError ? <p className={styles.note}>{t('lab.peers.none')}</p> : null;
  }
  const data = peers.data;
  return (
    <section className={styles.block} aria-labelledby="peers-title">
      <h3 id="peers-title" className={styles.blockTitle}>
        {t('lab.peers.title', { n: data.assessments, visitors: data.assessors })}
      </h3>
      {data.assessments === 0 ? (
        <p className={styles.note}>{t('lab.peers.empty')}</p>
      ) : (
        <ul className={styles.peerList}>
          {(['SOUND', 'UNSOUND', 'UNSURE'] as const).map((value) => (
            <li key={value}>
              <span>{t(`lab.assess.${value}`)}</span>
              <span className={styles.mono}>{data.verdicts[value] ?? 0}</span>
            </li>
          ))}
          {Object.entries(data.reasons).map(([reason, count]) => (
            <li key={reason}>
              <span>{t(`lab.reason.${reason}`)}</span>
              <span className={styles.mono}>{count}</span>
            </li>
          ))}
        </ul>
      )}
      <p className={styles.note}>{t('lab.peers.rule', { hours: data.delayHours })}</p>
    </section>
  );
}
