import type { TFunction } from 'i18next';
import type { BeforeSendView, StoredCheck } from '../../api/anatomy';
import type { LabCase, LabEmployee } from '../../api/lab';
import type { CaseResult, LiveDecision, LiveLayer, RunScore } from '../../api/types';
import type { Verdict } from '../../domain/verdict';
import type { EvalResult } from '../verdict';
import type { UxIconName } from '../ui/Icon';

/**
 * The person threat scenarios of the threat simulation (기획안 7.0): the compromised account (S13), the legitimate user
 * sending the same request (S13T, the control run) and the insider inside the permission (S16). The role and the
 * experience key are the ones the portal stores the visitor's prediction under.
 */
export const PERSON_KEYS = ['S13', 'S13T', 'S16'] as const;
export type PersonKey = (typeof PERSON_KEYS)[number];

/** A person case's role: the attacker with the stolen account, the account's owner, the insider. */
export type Role = 'attacker' | 'owner' | 'insider';

export interface PersonCase {
  readonly key: PersonKey;
  readonly role: Role;
  readonly experience: 'E1' | 'E2' | 'E3';
  readonly icon: UxIconName;
  /** The other scenario of the same request (the control run), whose result the comparison sets beside this one. */
  readonly pair: PersonKey | null;
}

export const PERSON: Readonly<Record<PersonKey, PersonCase>> = {
  S13: { key: 'S13', role: 'attacker', experience: 'E1', icon: 'user-round-x', pair: 'S13T' },
  S13T: { key: 'S13T', role: 'owner', experience: 'E2', icon: 'user-round-check', pair: 'S13' },
  S16: { key: 'S16', role: 'insider', experience: 'E3', icon: 'user-round-cog', pair: null },
};

export function personCase(key: string | undefined): PersonCase | null {
  return key !== undefined && (PERSON_KEYS as readonly string[]).includes(key)
    ? PERSON[key as PersonKey]
    : null;
}

export type FlowStep = 'review' | 'live' | 'result';

export function flowPath(key: PersonKey, step: FlowStep, search = ''): string {
  return `/simulate/person/${key}/${step}${search}`;
}

/** The ground truth as the screens name it; it is never sent to any control. */
export type Truth = 'threat' | 'normal' | 'undetermined';

export function truthOf(classification: string | null | undefined): Truth {
  return classification === 'THREAT' ? 'threat' : classification === 'NORMAL' ? 'normal' : 'undetermined';
}

/** A device as the engine records it ("Safari/18 on MAC") in the screen's words ("Safari 18 · macOS"). */
const SYSTEMS: Readonly<Record<string, string>> = {
  MAC: 'macOS',
  MACOS: 'macOS',
  WINDOWS: 'Windows',
  LINUX: 'Linux',
  IOS: 'iOS',
  ANDROID: 'Android',
};

export function deviceWords(value: string | null | undefined): string {
  if (!value) {
    return '—';
  }
  const [browser, system, ...rest] = value.split(' on ');
  if (browser === undefined || system === undefined || rest.length > 0) {
    return value;
  }
  return `${browser.replace('/', ' ')} · ${SYSTEMS[system.toUpperCase()] ?? system}`;
}

/** A login as recorded ("PASSWORD+ONE_TIME_CODE") in words, one method after another. */
export function authWords(t: TFunction, value: string | null | undefined): string {
  if (!value) {
    return '—';
  }
  return value
    .split('+')
    .map((method) => t(`ux.auth.${method}`, { defaultValue: method }))
    .join(' + ');
}

/** The demo company's clock: the record's time is written in UTC and read as the company's own time (mainCases.ts). */
export function companyClock(t: TFunction, iso: string | null | undefined): string {
  if (!iso) {
    return '—';
  }
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) {
    return '—';
  }
  const weekday = ((at.getUTCDay() + 6) % 7) + 1;
  const clock = `${String(at.getUTCHours()).padStart(2, '0')}:${String(at.getUTCMinutes()).padStart(2, '0')}`;
  return t('ux.clock', { day: t(`ux.weekday.${weekday}`), clock });
}

/** Whether a value lies within the behavioural baseline, outside it, or could not be compared this time. */
export type BaselineMark = 'in' | 'out' | 'unknown' | null;

function markOf(comparison: BeforeSendView | null, dimension: string): BaselineMark {
  const row = comparison?.usualVsNow.find((candidate) => candidate.dimension === dimension) ?? null;
  if (!row) {
    return null;
  }
  return row.inUsual === 'true' ? 'in' : row.inUsual === 'false' ? 'out' : 'unknown';
}

function nowOf(comparison: BeforeSendView | null, dimension: string): string | null {
  return comparison?.usualVsNow.find((candidate) => candidate.dimension === dimension)?.now ?? null;
}

export interface FactCell {
  readonly id: 'account' | 'time' | 'device' | 'auth' | 'size';
  readonly value: string;
  readonly mark: BaselineMark;
  /** A short line under the value (the usual largest export); null without one. */
  readonly note: string | null;
}

/**
 * The five facts of the request card (기획안 7.0 d-review): the account, the request time, the device, the login and
 * the size of the request, each marked against the behavioural baseline as the engine received it.
 */
export function factCells(
  t: TFunction,
  formatCount: (value: number) => string,
  comparison: BeforeSendView | null,
  labCase: LabCase | null,
  employee: LabEmployee | null,
): readonly FactCell[] {
  const items = labCase?.requests[0]?.items ?? null;
  const documents = labCase?.requests.filter((request) => request.document !== null).length ?? 0;
  const usualLargest = comparison?.sizeRatio?.usualLargest ?? null;
  return [
    {
      id: 'account',
      value: employee ? t(`ux.person.${employee.key}`, { defaultValue: employee.displayName }) : '—',
      mark: null,
      note: null,
    },
    {
      id: 'time',
      value: companyClock(t, comparison?.companyTime),
      mark: markOf(comparison, 'accessHour'),
      note: null,
    },
    {
      id: 'device',
      value: deviceWords(nowOf(comparison, 'device')),
      mark: markOf(comparison, 'device'),
      note: null,
    },
    {
      id: 'auth',
      value: authWords(t, nowOf(comparison, 'authenticationType')),
      mark: markOf(comparison, 'authenticationType'),
      note: null,
    },
    {
      id: 'size',
      value:
        items !== null
          ? t('ux.facts.items', { count: items, n: formatCount(items) })
          : t('ux.facts.documents', { count: documents, n: formatCount(documents) }),
      mark: markOf(comparison, items !== null ? 'size' : 'target'),
      note:
        items !== null && usualLargest !== null
          ? t('ux.facts.usualLargest', { n: formatCount(usualLargest) })
          : null,
    },
  ];
}

/** The business-context records the business lookup returned for the request, in words (9절 업무 컨텍스트). */
export function contextChips(
  t: TFunction,
  facts: readonly { readonly code: string; readonly value: string | null }[],
): readonly string[] {
  // An approval that states its purpose names it (the old console's APPROVAL_COVERS line, P-8 · DEC-82).
  return facts.map((fact) =>
    fact.code === 'APPROVAL_COVERS' && fact.value
      ? t('ux.biz.APPROVAL_COVERS_value', { value: fact.value })
      : t(`ux.biz.${fact.code}`, { value: fact.value ?? '', defaultValue: fact.code }),
  );
}

/**
 * The decision a control's answer amounts to. Rule controls make no decision: their answer is read by its business
 * outcome (delivered → allow, stopped → block). Contexa's is its own decision; a request a decision already in force
 * refused has none of its own.
 */
export function controlVerdict(
  control: string,
  layer: Pick<LiveLayer, 'outcome' | 'ruleId'> | null,
  decision: Pick<LiveDecision, 'finalAction' | 'unresolved'> | null,
): Verdict | 'PRIOR' | null {
  if (layer === null) {
    return null;
  }
  if (control === 'D') {
    if (layer.ruleId === 'ACCOUNT_BLOCKED' || layer.ruleId === 'MFA_CHALLENGE_REQUIRED') {
      return 'PRIOR';
    }
    if (decision === null) {
      return layer.outcome === 'HELD' ? 'PENDING' : null;
    }
    if (decision.unresolved) {
      return 'NONE';
    }
    const action = decision.finalAction;
    return action === 'ALLOW' || action === 'CHALLENGE' || action === 'ESCALATE' || action === 'BLOCK'
      ? action
      : 'NONE';
  }
  switch (layer.outcome) {
    case 'DELIVERED':
      return 'ALLOW';
    case 'STOPPED':
    case 'CUT':
      return 'BLOCK';
    case 'HELD':
      return 'ESCALATE';
    default:
      return 'NONE';
  }
}

/** A control's business result over the run graded against the scenario's ground truth (평가 뱃지); null when ungraded. */
export function evalOf(result: CaseResult | null | undefined): EvalResult | null {
  switch (result) {
    case 'STOPPED':
      return 'correct';
    case 'PASSED':
      return 'normal';
    case 'PASSED_AFTER_CHECK':
      return 'afterCheck';
    case 'PARTLY_STOPPED':
      return 'partial';
    case 'MISSED':
      return 'missed';
    case 'HALTED':
      return 'falsePositive';
    default:
      return null;
  }
}

/**
 * The key of the result's conclusion sentence (기획안 F-6 결론 한 문장), from Contexa's business result and decision
 * as the server scored them. The screen never judges the run itself.
 */
export function conclusionKey(score: RunScore): string {
  const result = score.business.D?.result ?? 'NOT_SCORED';
  const action = score.verdicts[0]?.score.finalAction ?? null;
  switch (result) {
    case 'STOPPED':
      return action === 'CHALLENGE'
        ? 'ux.result.conclusion.stoppedChallenge'
        : action === 'ESCALATE'
          ? 'ux.result.conclusion.stoppedHold'
          : 'ux.result.conclusion.stoppedBlock';
    case 'PARTLY_STOPPED':
      return 'ux.result.conclusion.partly';
    case 'MISSED':
      return 'ux.result.conclusion.missed';
    case 'PASSED':
      return 'ux.result.conclusion.passed';
    case 'PASSED_AFTER_CHECK':
      return 'ux.result.conclusion.passedAfterCheck';
    case 'HALTED':
      return 'ux.result.conclusion.halted';
    default:
      return 'ux.result.conclusion.unresolved';
  }
}

/** The four existing controls, in the order of the security layers they look at. */
export const EXISTING = ['A', 'B', 'C1', 'C2'] as const;

/** An engine action as the verdict the screens draw; anything that is not one of the four is "no decision". */
export function verdictOf(action: string | null | undefined): Verdict {
  return action === 'ALLOW' || action === 'CHALLENGE' || action === 'ESCALATE' || action === 'BLOCK'
    ? action
    : 'NONE';
}

/** A request path cut to its last two segments for a narrow cell ("…/HX-310/exports"); the full path goes in its title. */
export function shortPath(path: string | null | undefined): string {
  if (!path) {
    return '…';
  }
  const segments = path.split('/').filter(Boolean);
  return segments.length > 2 ? `…/${segments.slice(-2).join('/')}` : path;
}

const RESTRICTIVE = new Set(['CHALLENGE', 'ESCALATE', 'BLOCK']);

/**
 * The request whose decision a run's result rests on: the first step the engine restricted (step-up, hold, block) as
 * the server scored it, else the last step it decided. A case of one request is its first step.
 */
export function decidingStep(score: RunScore): number {
  const restricting = score.verdicts.find((verdict) => RESTRICTIVE.has(verdict.score.finalAction ?? ''));
  return restricting?.score.stepNo ?? score.verdicts[score.verdicts.length - 1]?.score.stepNo ?? 1;
}

/**
 * The request sent again after a passed check, as the run stored it (run_challenge): the items it handed over and its
 * HTTP status; null when the check was not passed or the request was not sent again.
 */
export function storedResend(
  check: StoredCheck | null | undefined,
): { readonly items: number; readonly status: number } | null {
  return check?.answered && typeof check.reissue_status === 'number'
    ? { items: check.reissue_delivered ?? 0, status: check.reissue_status }
    : null;
}
