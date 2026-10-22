import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useExchanges, type DecisionAnatomyView, type ExchangeCall } from '../../api/anatomy';
import { useRunQuality, type RunQuality } from '../../api/promptQuality';
import { downloadRunRecord } from '../../api/runRecord';
import { count, seconds, utcTime } from '../../journey/format';
import { ActionChip } from '../common/ActionChip';
import { failuresFirst } from '../facts/factWords';
import { Icon } from '../Icon';
import { StateScreen } from '../StateScreen';
import { TabFrame, type TabProps } from './TabFrame';
import styles from './DecisionDetail.module.css';

/** The texts of one AI call, in the order they are offered. */
const TEXTS = ['answer', 'rules', 'situation', 'provider'] as const;
type Text = (typeof TEXTS)[number];

/** What the chooser shows: the AI's own reason, the deeper analysis's reason, one text of one call, or the checks. */
type Shown = 'reason' | 'second' | 'checks' | `${Text}-${number}`;

/** The evidence kinds the AI can cite, with words of their own; any other kind is shown as it was recorded. */
const REFS = new Set([
  'approval',
  'authorization',
  'baseline',
  'delegation',
  'device',
  'location',
  'rag',
  'resource',
  'sensitivity',
  'session',
  'threat',
]);

function textOf(call: ExchangeCall, text: Text): string | null {
  switch (text) {
    case 'answer':
      return call.answer;
    case 'rules':
      return call.systemPrompt;
    case 'situation':
      return call.userPrompt;
    default:
      return call.providerResponse;
  }
}

/**
 * The original record (RO-1, V-6): the record as it is. One chooser picks what to read: the reason the AI wrote (the
 * model's own sentence, with its risk and confidence, attack technique and the evidence kinds or, of a v21 answer,
 * the reason codes it cited, each line only when it has a value), the deeper
 * analysis's reason when there was one, each AI call's answer, the rules and the situation it was sent and the
 * provider's body, or the checks of the record (the bundle, the seal and the official inspection). The whole record
 * downloads as one file with its SHA-256. Past the retention period the texts are gone and the summary values stay.
 */
export function OriginalTab({ view, runId, step }: TabProps & { readonly view: DecisionAnatomyView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const exchanges = useExchanges(runId, step, true);
  const quality = useRunQuality(runId, step).data ?? null;
  const [shown, setShown] = useState<Shown>('reason');
  const [download, setDownload] = useState<{ readonly hash: string | null; readonly failed: boolean } | null>(
    null,
  );
  const chooserId = useId();
  if (exchanges.isPending) {
    return <StateScreen kind="loading" />;
  }
  const interpretation = view.interpretation;
  const recorded = interpretation.recorded;
  const second =
    interpretation.timings.events.find((event) => event.type === 'LAYER2_COMPLETE')?.reasoning ?? null;
  const data = exchanges.data ?? null;
  const calls = data?.kept ? data.calls : [];
  const refs = recorded.evidenceRefs ?? [];
  const codes = quality?.reasonCodes ?? [];
  const last = calls.length > 0 ? (calls[calls.length - 1]?.callNo ?? null) : null;
  const options: readonly Shown[] = [
    'reason',
    ...(second ? (['second'] as const) : []),
    ...calls.flatMap((call) => TEXTS.map((text): Shown => `${text}-${call.callNo}`)),
    'checks',
  ];
  const current: Shown = options.includes(shown) ? shown : 'reason';
  const [textName, callText] = current.split('-') as [string, string | undefined];
  const call =
    callText === undefined ? null : (calls.find((entry) => entry.callNo === Number(callText)) ?? null);
  const callFigures = call
    ? (interpretation.calls.find((entry) => entry.callNo === call.callNo) ?? null)
    : null;
  const lines = view.promptLines;

  return (
    <TabFrame
      source={t(
        data && !data.kept
          ? `detail.r7.original.${data.missing ?? 'NOT_COLLECTED'}`
          : 'detail.r7.original.source',
      )}
    >
      <div className={styles.chooser}>
        <label htmlFor={chooserId} className={styles.label}>
          {t('detail.r7.original.choose')}
        </label>
        <select
          id={chooserId}
          className={styles.select}
          value={current}
          onChange={(event) => setShown(event.target.value as Shown)}
        >
          <option value="reason">{t('detail.r7.original.reason')}</option>
          {second ? <option value="second">{t('detail.r7.original.second')}</option> : null}
          {calls.map((entry) => (
            <optgroup key={entry.callNo} label={t('detail.r7.original.call', { n: entry.callNo })}>
              {TEXTS.map((text) => (
                <option key={text} value={`${text}-${entry.callNo}`}>
                  {t(`detail.r7.original.text.${text}`)}
                </option>
              ))}
            </optgroup>
          ))}
          <option value="checks">{t('detail.r7.original.checks')}</option>
        </select>
      </div>
      {current === 'reason' ? (
        <div className={styles.group} data-block>
          {recorded.reasoning ? (
            // L-43: the AI's own text is marked as the original, in English, over its own ground.
            <>
              <p className={styles.aside}>{t('detail.r7.original.originalMark')}</p>
              <pre className={styles.pre} data-original tabIndex={0}>
                {recorded.reasoning}
              </pre>
            </>
          ) : (
            <p className={styles.line}>{t('detail.r7.original.noReason')}</p>
          )}
          <p className={styles.aside}>
            {recorded.riskScore === null && recorded.confidence === null ? (
              t('detail.r7.original.riskNone')
            ) : (
              <>
                {t('detail.r7.original.risk', {
                  risk: recorded.riskScore === null ? t('detail.r7.noValue') : recorded.riskScore.toFixed(2),
                  confidence:
                    recorded.confidence === null ? t('detail.r7.noValue') : recorded.confidence.toFixed(2),
                })}{' '}
                {/* V-63: the number is the AI's own, written with its judgment; it does not set the judgment. */}
                {t('detail.r7.original.riskNote')}
              </>
            )}
          </p>
          {/* V-42: a line without a value is left out rather than shown as missing. */}
          {recorded.mitre ? (
            <p className={styles.aside}>
              {t('detail.r7.original.mitre')}{' '}
              <code className={styles.original} data-original>
                {recorded.mitre}
              </code>
            </p>
          ) : null}
          {refs.length > 0 ? (
            <p className={styles.aside}>
              {t('detail.r7.original.cited', {
                refs: refs.map((ref) => (REFS.has(ref) ? t(`detail.r7.ref.${ref}`) : ref)).join(' · '),
              })}
            </p>
          ) : codes.length > 0 ? (
            // V-42 (R-08): a v21 answer cites reason codes, the ones screen 3-1 counts, instead of evidence kinds.
            <p className={styles.aside}>
              {t('detail.r7.original.codes', { n: codes.length })}{' '}
              <code className={styles.original} data-original>
                {codes.map((reason) => reason.code).join(' · ')}
              </code>
            </p>
          ) : null}
        </div>
      ) : null}
      {current === 'second' && second ? (
        <div className={styles.group} data-block>
          <p className={styles.aside}>{t('detail.r7.original.originalMark')}</p>
          <pre className={styles.pre} data-original tabIndex={0}>
            {second}
          </pre>
        </div>
      ) : null}
      {call ? (
        <div className={styles.group} data-block>
          <p className={styles.aside}>
            {t('detail.r7.original.model')}{' '}
            <code className={styles.original} data-original>
              {call.model ?? '-'}
            </code>
            {callFigures
              ? ` · ${t('detail.r7.original.tokens', {
                  input: count(callFigures.promptTokens ?? 0, language),
                  output: count(callFigures.completionTokens ?? 0, language),
                })}${
                  callFigures.elapsedMs === null
                    ? ''
                    : ` · ${t('detail.r7.seconds', { s: seconds(callFigures.elapsedMs) })}`
                }`
              : ''}
            {lines && call.callNo === last && (textName === 'rules' || textName === 'situation')
              ? ` · ${t('detail.r7.original.lines', {
                  n: count(textName === 'rules' ? lines.systemPhysical : lines.userPhysical, language),
                })}`
              : ''}
          </p>
          {callFigures && !callFigures.success ? (
            <p className={styles.warning}>
              {t('detail.r7.original.callFailed')}{' '}
              <code className={styles.original} data-original>
                {callFigures.failure ?? '-'}
              </code>
            </p>
          ) : null}
          <pre className={styles.pre} data-original tabIndex={0}>
            {textOf(call, textName as Text) ?? '-'}
          </pre>
        </div>
      ) : null}
      {current === 'checks' ? <Checks quality={quality} /> : null}
      <div className={styles.actions}>
        <ActionChip
          icon="download"
          variant="open"
          onClick={() => {
            void downloadRunRecord(runId, step, view)
              .then((hash) => setDownload({ hash, failed: false }))
              .catch(() => setDownload({ hash: null, failed: true }));
          }}
        >
          {t('detail.r7.original.download')}
        </ActionChip>
        {download?.hash ? (
          <p className={styles.aside}>
            {t('detail.r7.original.hash')}{' '}
            <code className={styles.original} data-original>
              {download.hash}
            </code>
          </p>
        ) : null}
        {download?.failed ? <p className={styles.warning}>{t('detail.r7.original.downloadFailed')}</p> : null}
      </div>
    </TabFrame>
  );
}

/**
 * The checks of the record (U-4): the bundle the judgment used, whether its input and judgment were sealed, whether the
 * sealed text is the one the last AI call sent, and the official inspection's result with the checks that did not hold
 * and those it could not check, by name. A part the server has no record of says so; nothing is shown as checked that
 * was not.
 */
function Checks({ quality }: { readonly quality: RunQuality | null }) {
  const { t } = useTranslation();
  const bundle = quality?.bundle ?? null;
  const seal = quality?.seal ?? null;
  const inspection = quality?.inspection ?? null;
  const sealCheck = inspection?.checks.find((check) => check.code === 'SEAL_INTEGRITY') ?? null;
  const names = (filter: (mismatched: number, unverifiable: number) => boolean) =>
    failuresFirst(inspection?.checks ?? [])
      .filter((check) => filter(check.mismatched, check.unverifiable))
      .map((check) =>
        t(`detail.r7.checkName.${check.code}`, { defaultValue: t('detail.r7.checkName.other') }),
      )
      .join(' · ');
  const failed = names((mismatched) => mismatched > 0);
  const mismatches = failuresFirst(inspection?.checks ?? []).flatMap((check) => check.mismatches);
  const unchecked = names((mismatched, unverifiable) => mismatched === 0 && unverifiable > 0);
  return (
    <ul className={styles.list} aria-label={t('detail.r7.original.checks')}>
      {quality && !quality.available ? (
        <li>
          {t(`detail.r7.prompt.reason.${quality.reason ?? 'other'}`, {
            defaultValue: t('detail.r7.prompt.reason.other'),
          })}
        </li>
      ) : null}
      <li className={styles.item}>
        <span className={styles.itemHead}>{t('detail.r7.verify.bundle')}</span>
        {bundle ? (
          <code className={styles.original} data-original>
            {bundle.version ?? '-'} · {(bundle.hash ?? '-').slice(0, 12)} · {bundle.selectionSource ?? '-'}
          </code>
        ) : (
          <span>{t('detail.r7.verify.bundleNone')}</span>
        )}
      </li>
      <li className={styles.item}>
        <span className={styles.itemHead}>{t('detail.r7.verify.seal')}</span>
        {seal ? (
          <span className={styles.value}>
            <Icon name="check" />
            {t('detail.r7.verify.sealed')}
            <code className={styles.original} data-original>
              {seal.packageId}
            </code>
          </span>
        ) : (
          <span>{t('detail.r7.verify.sealNone')}</span>
        )}
      </li>
      <li className={styles.item}>
        <span className={styles.itemHead}>{t('detail.r7.verify.sealCheck')}</span>
        {sealCheck ? (
          <span className={styles.value}>
            <Icon name={sealCheck.mismatched === 0 ? 'check' : 'cross'} />
            {t(sealCheck.mismatched === 0 ? 'detail.r7.verify.sealSame' : 'detail.r7.verify.sealCheckFailed')}
            <span className={styles.from}>
              {t('detail.r7.verify.sealCheckCounts', {
                matched: sealCheck.matched,
                mismatched: sealCheck.mismatched,
                unverifiable: sealCheck.unverifiable,
              })}
            </span>
          </span>
        ) : (
          <span>{t('detail.r7.verify.sealCheckNone')}</span>
        )}
      </li>
      <li className={styles.item}>
        <span className={styles.itemHead}>{t('detail.r7.verify.inspection')}</span>
        {inspection ? (
          <>
            <span className={styles.value}>
              <Icon name={inspection.verdict === 'PASS' ? 'check' : 'cross'} />
              {t('detail.r7.verify.inspected', {
                verdict: t(`quality.verdict.${inspection.verdict}`, {
                  defaultValue: t('quality.verdict.ERROR'),
                }),
              })}
              <code className={styles.original} data-original>
                {inspection.inspectorVersion ?? '-'}
              </code>
              {inspection.inspectedAt ? (
                <span className={styles.from}>
                  {t('detail.r7.verify.inspectedAt', { time: utcTime(inspection.inspectedAt) })}
                </span>
              ) : null}
            </span>
            <span>
              {failed ? t('detail.r7.verify.failed', { names: failed }) : t('detail.r7.verify.noneFailed')}
            </span>
            {mismatches.length > 0 ? (
              <ul className={styles.list} aria-label={t('detail.r7.verify.mismatches')}>
                {mismatches.map((mismatch, index) => (
                  // The inspector's own line of what did not match, as it recorded it.
                  <li key={`${mismatch.line ?? '-'}-${index}`} className={styles.original} data-original>
                    {[mismatch.factId, mismatch.entry, mismatch.line, mismatch.expected, mismatch.actual]
                      .map((part) => (part === null ? '-' : String(part)))
                      .join(' · ')}
                    {mismatch.reason ? ` (${mismatch.reason})` : ''}
                  </li>
                ))}
              </ul>
            ) : null}
            {unchecked ? (
              <span className={styles.from}>{t('detail.r7.verify.unchecked', { names: unchecked })}</span>
            ) : null}
          </>
        ) : (
          <span>{t('detail.r7.verify.inspectionNone')}</span>
        )}
      </li>
    </ul>
  );
}
