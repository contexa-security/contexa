import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useAnatomy, useBeforeSend } from '../../api/anatomy';
import { useJourneyUpdate, type EngineCall } from '../../api/journey';
import { useLabOptions, type LabCase, type LabEmployee } from '../../api/lab';
import { usePublicSettings } from '../../api/settings';
import { GuidePreview } from '../../components/guide/GuidePreview';
import { MainButton, MainScreen } from '../../components/main/MainScreen';
import { useRecordPath } from '../../components/replay/replayLine';
import { StateScreen } from '../../components/StateScreen';
import { useLiveSend } from '../../hooks/useLiveSend';
import { count } from '../../journey/format';
import { plainValue } from '../try/experience';
import {
  caseOf,
  companyClock,
  MAIN_CASES,
  personName,
  ROLE_EXPERIENCES,
  ROLE_NUMBERS,
  ROLE_PATHS,
  type Role,
} from './mainCases';
import styles from './RequestPage.module.css';

/** The visitor's call before sending (설계서 2-1, FP-2): whether the data leaves. ALLOW lets it out, BLOCK keeps it in. */
const CALLS: readonly EngineCall[] = ['ALLOW', 'BLOCK'];

type T = ReturnType<typeof useTranslation>['t'];

/**
 * 2-1, 4-1 and 5-1, the request (설계서 2-1, 4-1; IN-6 for the insider): the case definition as it is sent, the real request line the engine
 * received in the latest run of the same case, the visitor's call (does the data leave?) and Send. The call is stored
 * on the server, which scores it against Contexa's judgment after the run; sending goes through the same gate as every
 * live run (the human check, the daily runs) and opens the live console.
 */
export default function RequestPage({ role }: { readonly role: Role }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const navigate = useNavigate();
  const update = useJourneyUpdate();
  const key = MAIN_CASES[role];
  const number = ROLE_NUMBERS[role].request;
  const options = useLabOptions();
  const settings = usePublicSettings();
  const found = caseOf(options.data, key);
  const before = useBeforeSend(key, 1);
  const comparison = before.data?.comparison ?? null;
  const latest = useAnatomy(comparison?.runId ?? null, 1);
  const recordPath = useRecordPath(key);
  const [call, setCall] = useState<EngineCall | null>(null);
  const {
    send: sendRun,
    sending,
    ready,
    refusal,
    waiting,
    turnstileContainer,
    turnstileRequired,
  } = useLiveSend(key, () => {
    void navigate(ROLE_PATHS[role].console);
  });
  const resource = latest.data?.context.resource ?? null;
  const authentication =
    comparison?.usualVsNow.find((row) => row.dimension === 'authenticationType')?.now ?? null;

  function send() {
    if (call === null) {
      return;
    }
    const picked = call;
    void sendRun(async () => {
      await update({ prediction: { experience: ROLE_EXPERIENCES[role], engine: picked } });
    });
  }

  return (
    <MainScreen
      title={t(`main.${number}.title`)}
      intro={t(`main.${number}.intro`)}
      // The guide to the console the send opens, before the first send of the attack (가이드영상-계획.md 3절, 1편).
      guide={role === 'attacker' ? <GuidePreview id="console" /> : null}
      // The send waits for the visitor's call; the footer says so beside the button (B-09).
      nextNote={found && call === null ? t('main.request.pickFirst') : undefined}
      main={
        <MainButton onClick={send} disabled={!ready || call === null}>
          {t(sending ? 'main.request.sending' : 'main.request.send')}
        </MainButton>
      }
    >
      {options.isPending ? <StateScreen kind="loading" /> : null}
      {options.data && !found ? <StateScreen kind="notReady" /> : null}
      {found ? (
        <div className={styles.layout}>
          <section className={styles.info} aria-labelledby="request-info">
            <h2 id="request-info" className={styles.label}>
              {t('main.request.info')}
            </h2>
            <dl className={styles.rows}>
              {requestRows(t, language, role, found.labCase, found.employee, {
                clock: companyClock(t, comparison?.companyTime),
                authentication:
                  authentication === null ? null : plainValue(t, 'authenticationType', authentication),
                exportLimit: settings.data?.businessRecord.assignedExportLimit ?? null,
              }).map((row) => (
                <div key={row.id} className={styles.row} data-mark={row.mark ?? undefined}>
                  <dt className={styles.rowName}>{t(`main.request.row.${row.id}`)}</dt>
                  <dd className={styles.rowValue}>{row.value}</dd>
                </div>
              ))}
            </dl>
            {/* The case number stays as a small reference, out of the heading (V-48). */}
            <p className={styles.caseKey}>{t('main.request.caseKey', { key })}</p>
            <p className={styles.http}>
              <span className={styles.httpLabel}>{t('main.request.line')}</span>
              {resource?.httpMethod && resource.requestPath ? (
                <code className={styles.httpLine}>
                  <b>{resource.httpMethod}</b> {resource.requestPath}
                </code>
              ) : (
                <span className={styles.httpLine}>…</span>
              )}
              <span className={styles.httpTo}>{t('main.request.toFive')}</span>
            </p>
          </section>
          <fieldset className={styles.predict}>
            <legend className={styles.label}>{t('main.request.predict')}</legend>
            {CALLS.map((choice) => (
              <label key={choice} className={styles.choice} data-selected={call === choice || undefined}>
                <input
                  type="radio"
                  name="call"
                  className="visually-hidden"
                  checked={call === choice}
                  onChange={() => setCall(choice)}
                />
                <b className={styles.choiceName}>{t(`main.request.call.${choice}`)}</b>
                <span className={styles.choiceHint}>{t(`main.request.call.${choice}.hint`)}</span>
              </label>
            ))}
            <p className={styles.note}>{t('main.request.noAnswer')}</p>
          </fieldset>
        </div>
      ) : null}
      {turnstileRequired ? <div ref={turnstileContainer} /> : null}
      {waiting ? <p className={styles.note}>{t('p1.predict.waitEarlier')}</p> : null}
      {refusal ? (
        <StateScreen
          kind={refusal === 'dailyLimit' ? 'dailyLimit' : refusal === 'paused' ? 'paused' : 'outage'}
          recordTo={recordPath}
          {...(refusal === 'error' || refusal === 'turnstile' ? { onRetry: send } : {})}
        />
      ) : null}
    </MainScreen>
  );
}

interface Row {
  readonly id: string;
  readonly value: string;
  /**
   * The row that sets the try apart: the stolen account and its device, the owner's usual device, the insider's
   * documents (IN-6).
   */
  readonly mark?: true;
}

/**
 * The six rows of the request, each from the case definition, the employee record, the published rule settings or the
 * latest run's input; the company records are stated as they are, never judged here.
 */
function requestRows(
  t: T,
  language: string,
  role: Role,
  labCase: LabCase,
  employee: LabEmployee,
  recorded: {
    readonly clock: string | null;
    readonly authentication: string | null;
    readonly exportLimit: number | null;
  },
): readonly Row[] {
  const request = labCase.requests[0];
  const approval = labCase.facts.find((fact) => fact.kind === 'APPROVAL') ?? null;
  // The documents an insider's requests download, as the case defines them (IN-6).
  const documents = labCase.facts
    .filter((fact) => fact.kind === 'DOCUMENT')
    .map((fact) => fact.document?.title?.[language] ?? fact.document?.title?.en ?? '')
    .filter((title) => title !== '');
  const conditions = labCase.conditions;
  return [
    {
      id: 'account',
      value: t(`main.request.account.${role}`, { name: personName(t, employee) }),
      ...(role === 'attacker' ? { mark: true as const } : {}),
    },
    { id: 'time', value: recorded.clock ?? '…' },
    {
      id: 'place',
      value: t('main.request.place', {
        place: t(`main.place.${conditions.place}`),
        network: employee.officeNetwork,
        device: t(`main.device.${conditions.device}`),
      }),
      ...(role !== 'insider' ? { mark: true as const } : {}),
    },
    {
      id: 'auth',
      value: recorded.authentication ? t('main.request.auth', { methods: recorded.authentication }) : '…',
    },
    {
      id: 'what',
      value:
        request && request.items !== null
          ? t('main.request.what', { project: request.project ?? '-', items: count(request.items, language) })
          : documents.length > 0
            ? t('main.request.documents', {
                project: request?.document?.project ?? '-',
                n: count(documents.length, language),
                titles: documents.join(' · '),
              })
            : '-',
      ...(role === 'insider' ? { mark: true as const } : {}),
    },
    {
      id: 'records',
      value: [
        request?.target
          ? t(`main.request.records.${request.target}`, {
              project: request.project ?? request.document?.project ?? '-',
            })
          : null,
        request?.operation === 'EXPORT' && recorded.exportLimit !== null
          ? t('main.request.records.limit', { limit: count(recorded.exportLimit, language) })
          : null,
        approval
          ? t('main.request.approval.yes', {
              purpose: t(`main.purpose.${approval.purpose ?? 'OTHER'}`),
              max: count(approval.maxItems ?? 0, language),
              approver: approval.approver ?? '-',
            })
          : t('main.request.records.noApproval'),
      ]
        .filter((part) => part !== null)
        .join(' · '),
    },
  ];
}
