import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAnatomy } from '../../api/anatomy';
import { useRunQuality } from '../../api/promptQuality';
import { useStepResponses, type StepResponse } from '../../api/responses';
import { downloadRunRecord } from '../../api/runRecord';
import { Icon } from '../../components/Icon';
import { count, utcTime } from '../../journey/format';
import { CheckCounts } from './CheckCounts';
import { inOrder, learnedAdded, shortHash } from './evidence';
import styles from './ProofPanel.module.css';
import { Fold } from '../../components/main/Fold';

/** How many of the inspector's checks the panel names: the three that prove the record was not altered. */
const PROOF_CHECKS = 3;

interface ProofPanelProps {
  readonly runId: string;
  /** True when the request was an attack: items that went out are a leak, not a delivery. */
  readonly threat: boolean;
}

/**
 * EV-1, the proof that a result is real (최종화면-구현계획 5차): what each approach actually answered to the same
 * request (its HTTP status and the items its answer carried, with the answer itself one press away), the engine
 * inspector's re-computation of this run's sealed record, and what the run added to the learned usual pattern. Every
 * value is the run's stored record; the bars only scale the stored counts. What went out is in view; the inspector's
 * checks and the learning sit under one line (구현계획 NW-8), side by side, the learning across the row under them.
 */
export function ProofPanel({ runId, threat }: ProofPanelProps) {
  const { t } = useTranslation();
  return (
    <section className={styles.proof} aria-labelledby="proof-title">
      <h2 id="proof-title" className={styles.title}>
        <Icon name="check" className={styles.titleIcon} />
        {t('main.proof.title')}
      </h2>
      <div className={styles.grid} data-single>
        <OutCard runId={runId} threat={threat} />
      </div>
      {/* NW-8 (R-N2): what each approach answered is the result and stays in view; the proof that the record is real and
          what the run added to the learned pattern fold under one line. */}
      <Fold name="proof" summary={t('main.proof.fold')}>
        <div className={styles.grid}>
          <CheckCard runId={runId} />
          <LearnCard runId={runId} />
        </div>
      </Fold>
    </section>
  );
}

/** What went out: one bar per approach, scaled to the largest answer, each answer one press away. */
function OutCard({ runId, threat }: ProofPanelProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const responses = useStepResponses(runId, 1).data ?? [];
  const [open, setOpen] = useState<string | null>(null);
  const largest = Math.max(1, ...responses.map((response) => response.deliveredItems));
  return (
    <div className={styles.card} data-wide>
      <h3 className={styles.cardTitle}>{t('main.proof.out.title')}</h3>
      <p className={styles.cardSub}>{t('main.proof.out.sub')}</p>
      <ul className={styles.bars}>
        {responses.map((response) => (
          <li key={response.control} className={styles.barRow}>
            <button
              type="button"
              className={styles.barButton}
              aria-expanded={open === response.control}
              onClick={() => setOpen(open === response.control ? null : response.control)}
            >
              <span className={styles.barName} data-contexa={response.control === 'D' || undefined}>
                {t(`main.lane.${response.control}`)}
              </span>
              <span className={styles.barTrack}>
                <span
                  className={styles.barFill}
                  data-tone={response.deliveredItems > 0 ? (threat ? 'leak' : 'pass') : 'none'}
                  style={{ inlineSize: `${(response.deliveredItems / largest) * 100}%` }}
                />
              </span>
              <span className={styles.barValue}>
                <b
                  className={styles.barTag}
                  data-tone={response.deliveredItems > 0 ? (threat ? 'leak' : 'pass') : 'none'}
                >
                  {t(
                    response.deliveredItems > 0
                      ? threat
                        ? 'main.proof.out.leaked'
                        : 'main.proof.out.delivered'
                      : 'main.proof.out.stopped',
                    { items: count(response.deliveredItems, language) },
                  )}
                </b>
                <span className={styles.barStatus}>HTTP {response.httpStatus ?? '—'}</span>
              </span>
              <Icon name="chevronDown" className={styles.barIcon} />
            </button>
            {open === response.control ? <Answer response={response} /> : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** One approach's answer as it came back: the request line and the start of the body. */
function Answer({ response }: { readonly response: StepResponse }) {
  const { t } = useTranslation();
  return (
    <div className={styles.answer}>
      <p className={styles.answerLine}>
        <code>
          {response.method} {response.path}
        </code>
        {response.sentAt ? <span>{t('main.proof.out.sent', { time: utcTime(response.sentAt) })}</span> : null}
      </p>
      <pre className={styles.answerBody} tabIndex={0} aria-label={t('main.proof.out.body')}>
        {response.excerpt ?? '—'}
      </pre>
      <p className={styles.answerNote}>{t('main.proof.out.note')}</p>
    </div>
  );
}

/**
 * The engine inspector's re-computation of this run's sealed record, per check in the order 3-3 lists them and in its
 * words: matched, mismatched and not checkable (P-39).
 */
function CheckCard({ runId }: { readonly runId: string }) {
  const { t } = useTranslation();
  const quality = useRunQuality(runId, 1).data ?? null;
  const [hash, setHash] = useState<string | null>(null);
  const checks = inOrder(quality?.inspection?.checks ?? [], PROOF_CHECKS);
  return (
    <div className={styles.card}>
      <h3 className={styles.cardTitle}>{t('main.proof.check.title')}</h3>
      <p className={styles.cardSub}>{t('main.proof.check.sub')}</p>
      <ul className={styles.meters}>
        {checks.map((check) => {
          const compared = check.matched + check.mismatched;
          return (
            <li key={check.code} className={styles.meter}>
              <span className={styles.meterName}>{t(`main.3-3.check.${check.code}`)}</span>
              <span className={styles.meterTrack} data-mismatch={check.mismatched > 0 || undefined}>
                <span
                  className={styles.meterFill}
                  data-clean={check.mismatched === 0 || undefined}
                  style={{ inlineSize: compared > 0 ? `${(check.matched / compared) * 100}%` : '0%' }}
                />
              </span>
              <span className={styles.meterValue}>
                <CheckCounts
                  matched={check.matched}
                  mismatched={check.mismatched}
                  unverifiable={check.unverifiable}
                />
              </span>
            </li>
          );
        })}
      </ul>
      <p className={styles.seal}>
        <Icon name="lock" className={styles.sealIcon} />
        <code>SHA-256 {quality?.seal?.packageHash ? shortHash(quality.seal.packageHash) : '…'}</code>
        {quality?.seal?.capturedAt ? (
          <span className={styles.sealTime}>
            {utcTime(quality.seal.capturedAt)} {t('main.utc')}
          </span>
        ) : null}
      </p>
      <button
        type="button"
        className={styles.download}
        onClick={() => {
          void downloadRunRecord(runId, 1).then(setHash);
        }}
      >
        {t('main.3-1.download')}
      </button>
      {hash ? (
        <span className={styles.sealTime}>{t('main.3-1.downloaded', { hash: shortHash(hash) })}</span>
      ) : null}
    </div>
  );
}

/** What the run added to the learned usual pattern: the count before and after it, and the record it added. */
function LearnCard({ runId }: { readonly runId: string }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const learning = useAnatomy(runId, 1).data?.learning ?? null;
  const before = learning?.template?.['baselineUpdateCount'] ?? null;
  const after = learning?.atRunEnd?.['baselineUpdateCount'] ?? null;
  const added = learning?.newBehaviourDocuments ?? [];
  const record = added[0] ?? null;
  return (
    <div className={styles.card} data-row>
      <h3 className={styles.cardTitle}>{t('main.proof.learn.title')}</h3>
      <p className={styles.cardSub}>
        {before === null ? '…' : t('main.proof.learn.sub', { n: count(before, language) })}
      </p>
      <p className={styles.learn} data-added={added.length > 0 || undefined}>
        <span className={styles.learnSide}>
          <span className={styles.learnWord}>{t('main.proof.learn.before')}</span>
          <b className={styles.learnCount}>{before === null ? '…' : count(before, language)}</b>
        </span>
        <Icon name="arrowRight" className={styles.learnArrow} />
        <span className={styles.learnSide}>
          <span className={styles.learnWord}>{t('main.proof.learn.after')}</span>
          <b className={styles.learnCount}>{after === null ? '…' : count(after, language)}</b>
        </span>
      </p>
      <p className={styles.learnLine} data-added={added.length > 0 || undefined}>
        {added.length > 0
          ? t('main.proof.learn.added', { n: count(learnedAdded(before, after, added.length), language) })
          : t('main.proof.learn.none')}
      </p>
      {record ? (
        <p className={styles.learnRecord}>
          <span className={styles.learnWord}>{t('main.proof.learn.record')}</span>
          <code>
            {[record.action, record.requestPath, record.timestamp].filter((part) => part).join(' · ')}
          </code>
        </p>
      ) : null}
    </div>
  );
}

/** EV-2, one run's learning in a line: the count before and after it, and whether it added its request. */
export function LearnLine({ runId, name }: { readonly runId: string; readonly name: string }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const learning = useAnatomy(runId, 1).data?.learning ?? null;
  const before = learning?.template?.['baselineUpdateCount'] ?? null;
  const after = learning?.atRunEnd?.['baselineUpdateCount'] ?? null;
  const added = learnedAdded(before, after, learning?.newBehaviourDocuments.length ?? 0);
  return (
    <li className={styles.learnRow} data-added={added > 0 || undefined}>
      <span className={styles.learnRowName}>{name}</span>
      <b className={styles.learnRowCount}>{before === null ? '…' : count(before, language)}</b>
      <Icon name="arrowRight" className={styles.learnRowArrow} />
      <b className={styles.learnRowCount} data-after>
        {after === null ? '…' : count(after, language)}
      </b>
      <span className={styles.learnRowTag}>
        {added > 0
          ? t('main.proof.learn.addedShort', { n: count(added, language) })
          : t('main.proof.learn.noneShort')}
      </span>
    </li>
  );
}

interface LedgerRow {
  readonly key: string;
  readonly name: string;
  readonly runId: string;
}

/** A ledger row's name with its run number under it, so a row of another run reads as that run (V-09). */
function LedgerName({ name, runId }: { readonly name: string; readonly runId: string }) {
  return (
    <span className={styles.ledgerName}>
      <span className={styles.learnRowName}>{name}</span>
      <code className={styles.ledgerRun}>{runId}</code>
    </span>
  );
}

/**
 * EV-7, how learning accumulates: for each run, the learned usual pattern when it started (grey) and what it added
 * (green), on one scale. A stopped request adds nothing; allowed requests add one each. Every count is the run's stored
 * learning record.
 */
export function LedgerChart({ rows }: { readonly rows: readonly LedgerRow[] }) {
  const { t } = useTranslation();
  return (
    <section className={styles.ledger} aria-labelledby="ledger-title">
      <h2 id="ledger-title" className={styles.cardTitle}>
        {t('main.proof.ledger.title')}
      </h2>
      <p className={styles.cardSub}>{t('main.proof.ledger.sub')}</p>
      <ul className={styles.ledgerRows}>
        {rows.map((row) => (
          <LedgerBar key={row.key} name={row.name} runId={row.runId} />
        ))}
      </ul>
    </section>
  );
}

/** The scale every ledger bar shares: the largest count a demo run ends with stays well inside it. */
const LEDGER_SCALE = 40;

function LedgerBar({ name, runId }: { readonly name: string; readonly runId: string }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const learning = useAnatomy(runId, 1).data?.learning ?? null;
  const before = learning?.template?.['baselineUpdateCount'] ?? null;
  const after = learning?.atRunEnd?.['baselineUpdateCount'] ?? null;
  const added = learnedAdded(before, after, learning?.newBehaviourDocuments.length ?? 0);
  return (
    <li className={styles.ledgerRow}>
      <LedgerName name={name} runId={runId} />
      <span className={styles.ledgerTrack} aria-hidden="true">
        <span
          className={styles.ledgerBase}
          style={{ inlineSize: `${((before ?? 0) / LEDGER_SCALE) * 100}%` }}
        />
        {added > 0 ? (
          <span className={styles.ledgerAdded} style={{ inlineSize: `${(added / LEDGER_SCALE) * 100}%` }} />
        ) : null}
      </span>
      <span className={styles.ledgerValue} data-added={added > 0 || undefined}>
        {before === null || after === null
          ? '…'
          : t('main.proof.ledger.value', {
              before: count(before, language),
              after: count(after, language),
              tag:
                added > 0
                  ? t('main.proof.learn.addedShort', { n: count(added, language) })
                  : t('main.proof.learn.noneShort'),
            })}
      </span>
    </li>
  );
}
