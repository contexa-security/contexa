import { useTranslation } from 'react-i18next';
import { useAnatomy, type StoredCheck } from '../../api/anatomy';
import type { LabFact, LabRequest } from '../../api/lab';
import type { LiveLayer, LiveRunView } from '../../api/types';
import { Icon } from '../../components/Icon';
import { Chip } from '../../components/main/Chip';
import type { ControlId } from '../../domain/verdict';
import { count, utcTime } from '../../journey/format';
import { useTryAnalysis } from '../try/steps/tryRun';
import { resentOf } from './consoleData';
import { laneChip, verdictChip } from './mainCases';
import styles from './CheckPage.module.css';

/**
 * The requests of a case with more than one request, one row each (4-4 FU-3, and the insider's documents of IN-6): what
 * each asks for, the four existing approaches' answers and Contexa's, a decision applied from the next request on, and a
 * request sent again after an extra check, as the run recorded them.
 */

/** The existing security of each request, in the console's order. */
const EXISTING: readonly ControlId[] = ['A', 'B', 'C1', 'C2'];

type T = ReturnType<typeof useTranslation>['t'];

interface StepRowProps {
  readonly stepNo: number;
  readonly request: LabRequest;
  /** The case's company records, for the title of a document the case adds (IN-6). */
  readonly facts: readonly LabFact[];
  readonly view: LiveRunView | null;
  readonly stored: boolean;
  readonly runId: string | null;
  readonly threat: boolean;
  readonly language: string;
  /** The request opens another document of a project an earlier request opened (4-4's second drawing, L-36). */
  readonly again?: boolean;
}

/**
 * One request of the case: what it asks for, the four existing approaches' answers and Contexa's, with the extra check
 * and the request sent again after it as the run recorded them. The four existing approaches sit in the same two
 * columns on every request, so a long chip never moves one of them to a line of its own (L-36).
 */
export function StepRow({
  stepNo,
  request,
  facts,
  view,
  stored,
  runId,
  threat,
  language,
  again = false,
}: StepRowProps) {
  const { t } = useTranslation();
  const layers = view?.steps.find((step) => step.stepNo === stepNo)?.layers ?? null;
  const analysis = useTryAnalysis(layers ? view : null, stored, stepNo);
  const anatomy = useAnatomy(runId, stepNo);
  const check = anatomy.data?.recovery?.challenge ?? null;
  const live = view?.challenge ?? null;
  const contexa = layers?.D ?? null;
  // A check belongs to the request Contexa answered with it (HTTP 401), not to the latest request sent.
  const resent = resentOf(check, live, stored, contexa?.httpStatus);
  return (
    <li className={styles.step} data-step={stepNo} data-sent={layers ? true : undefined}>
      <span className={styles.stepNo}>{t('main.4-4.step', { n: stepNo })}</span>
      <b className={styles.stepName}>{requestName(t, request, facts, language, again)}</b>
      {layers === null ? (
        <span className={styles.unsent}>{t('main.4-4.notYet')}</span>
      ) : (
        <>
          <ul className={styles.existing} aria-label={t('main.4-4.existing')}>
            {EXISTING.map((control) => (
              <li key={control} className={styles.existingItem}>
                <span className={styles.existingName}>{t(`main.lane.${control}`)}</span>
                <ExistingChip layer={layers?.[control] ?? null} threat={threat} />
              </li>
            ))}
          </ul>
          <div className={styles.contexa}>
            <span className={styles.contexaName}>{t('main.lane.D')}</span>
            <span className={styles.contexaChips}>
              {contexa === null ? (
                <Chip kind="wait">{t(layers ? 'main.lane.deciding' : 'main.4-4.notYet')}</Chip>
              ) : contexa.outcome === 'DELIVERED' ? (
                <Chip kind="allow">
                  {t(threat ? 'main.lane.leaked' : 'main.lane.exported', {
                    count: contexa.deliveredItems,
                    items: count(contexa.deliveredItems, language),
                  })}
                </Chip>
              ) : contexa.httpStatus === 401 ? (
                <Chip kind="auth">{t('main.verdict.CHALLENGE')}</Chip>
              ) : (
                <Chip kind="block">{t('main.lane.stopped')}</Chip>
              )}
              {resent ? (
                <Chip kind="allow">
                  {t('main.recovery.retried', {
                    count: resent.items,
                    items: count(resent.items, language),
                    status: resent.status,
                  })}
                </Chip>
              ) : null}
            </span>
            {contexa?.outcome === 'DELIVERED' && analysis.decision?.applied === 'NEXT_REQUEST' ? (
              <span className={styles.after}>
                {t('main.4-4.decidedAfter', { verdict: t(verdictChip(analysis.decision).key) })}
              </span>
            ) : null}
          </div>
        </>
      )}
    </li>
  );
}

/** An existing approach's answer in the console's words (the same reading as the console's lanes). */
function ExistingChip({ layer, threat }: { readonly layer: LiveLayer | null; readonly threat: boolean }) {
  const { t } = useTranslation();
  if (layer === null) {
    return <Chip kind="wait">{t('main.4-4.notYet')}</Chip>;
  }
  const chip = laneChip(layer, threat);
  return <Chip kind={chip.kind}>{t(chip.key)}</Chip>;
}

/** The four steps of an extra check and the time the run recorded for each (설계서 4-2 추가 인증). */
const CHECK_STEPS = [
  { id: 'asked', at: 'challenged_at' },
  { id: 'code', at: 'code_requested_at' },
  { id: 'check', at: 'verified_at' },
  { id: 'retry', at: 'reissue_sent_at' },
] as const;

/** A stored check with the times the portal keeps for its steps. */
type TimedCheck = StoredCheck & Partial<Record<(typeof CHECK_STEPS)[number]['at'], string | null>>;

/**
 * The extra check of one request as the run recorded it, kept on 4-4 once the run is over (L-36): its four steps, the
 * clock time (UTC) the record holds for each, and the request sent again. The code itself is never stored or shown.
 * Nothing is drawn for a request without an answered check.
 */
export function CheckRecord({ runId, stepNo }: { readonly runId: string; readonly stepNo: number }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const check: TimedCheck | null = useAnatomy(runId, stepNo).data?.recovery?.challenge ?? null;
  if (!check?.answered) {
    return null;
  }
  return (
    <div className={styles.record}>
      <h3 className={styles.recordTitle}>{t('main.4-4.record', { n: stepNo })}</h3>
      <ol className={styles.recordSteps}>
        {CHECK_STEPS.map((step) => {
          const at = check[step.at] ?? null;
          return (
            <li key={step.id} className={styles.recordStep} data-step={step.id}>
              <Icon name="check" className={styles.recordIcon} />
              <span className={styles.recordName}>{t(`main.recovery.${step.id}`)}</span>
              {step.id === 'retry' && typeof check.reissue_status === 'number' ? (
                <Chip kind="allow">
                  {t('main.recovery.retried', {
                    count: check.reissue_delivered ?? 0,
                    items: count(check.reissue_delivered ?? 0, language),
                    status: check.reissue_status,
                  })}
                </Chip>
              ) : null}
              {at ? (
                <time className={styles.recordTime} dateTime={at}>
                  {utcTime(at).slice(11)}
                </time>
              ) : null}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

/**
 * A request of the case in the visitor's words: the items exported, the document the case adds downloaded by its title,
 * or the drawing opened (another drawing when an earlier request opened one of the same project).
 */
function requestName(
  t: T,
  request: LabRequest,
  facts: readonly LabFact[],
  language: string,
  again: boolean,
): string {
  if (request.operation === 'EXPORT') {
    return t('main.4-4.export', {
      project: request.project ?? '-',
      items: count(request.items ?? 0, language),
    });
  }
  const title = documentTitle(facts, request.document?.fact ?? null, language);
  if (request.operation === 'DOCUMENT_DOWNLOAD' && title !== null) {
    return t('main.steps.download', { title });
  }
  return t(again ? 'main.4-4.readAnother' : 'main.4-4.read', {
    project: request.document?.project ?? request.project ?? '-',
  });
}

/** The title of the n-th document the case adds (its DOCUMENT facts counted from 1, as the run numbers them). */
function documentTitle(facts: readonly LabFact[], fact: number | null, language: string): string | null {
  if (fact === null) {
    return null;
  }
  const document = facts.filter((candidate) => candidate.kind === 'DOCUMENT')[fact - 1]?.document ?? null;
  return document?.title?.[language] ?? document?.title?.['en'] ?? null;
}
