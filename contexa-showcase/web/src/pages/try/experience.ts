import type { TFunction } from 'i18next';
import type { RouteFlow } from '../../components/journey/flow';
import { modeOfSearch, TRY_CASES } from '../../firstScreens';

/**
 * The tries of the default route (screen design v2.3, 7.1 and 7.2): who the visitor is and which designed case each
 * decision mode sends. The asynchronous cases send the same export to an address control D decides from the next
 * request on (work 1, decision 3).
 */
export type Role = 'attacker' | 'owner';
export type Mode = 'sync' | 'async';

/** The table is kept in src/firstScreens.ts, where index.html's first-screen script reads it too. */
export const CASES: Readonly<Record<Role, Readonly<Record<Mode, string>>>> = TRY_CASES;

/** How a step connects to its neighbours: the same flow every screen of a route has (components/journey/flow). */
export type StepFlow = RouteFlow;

export function modeOf(params: URLSearchParams): Mode {
  return modeOfSearch(params.toString());
}

/** The address of a step of the same try, keeping the decision mode. */
export function stepPath(role: Role, step: string, mode: Mode): string {
  return `/try/${role}/${step}${mode === 'async' ? '?mode=async' : ''}`;
}

/**
 * The dimensions of the comparison table in the design's order; the browser and the system make one device
 * row. A v20 step also compares the target, the size and the request rate (N-DEP-1); a step without one
 * leaves it out.
 */
export const COMPARED = [
  'accessHour',
  'dayOfWeek',
  'network',
  'device',
  'authenticationType',
  'target',
  'pathFamily',
  'actionFamily',
  'resourceFamily',
  'size',
  'rate',
] as const;
export type Compared = (typeof COMPARED)[number];

/**
 * A recorded value in the visitor's words. These only name what the record holds (an hour, a weekday number, an
 * action family, a path); they never decide or count anything.
 */
export function plainValue(t: TFunction, dimension: string, value: string): string {
  switch (dimension) {
    case 'accessHour':
      // A value that is no single hour stays as the engine wrote it (N-DEP-1).
      return /^[0-9]{1,2}$/.test(value) ? t('dim.hours', { hours: value }) : value;
    case 'dayOfWeek':
      return t(`dim.day.${value}`, { defaultValue: value });
    case 'authenticationType':
      // A v20 login of several methods names each (PASSWORD+ONE_TIME_CODE, N-DEP-1).
      return value
        .split('+')
        .map((method) => t(`dim.auth.${method}`, { defaultValue: method }))
        .join('+');
    case 'actionFamily':
      return t(`dim.action.${value}`, { defaultValue: value });
    case 'operatingSystem':
      return t(`dim.os.${value.toUpperCase()}`, { defaultValue: value });
    case 'resourceFamily':
      return t(`dim.sensitivity.${value}`, { defaultValue: value });
    case 'pathFamily':
      return plainPath(t, value);
    case 'device':
      return plainDevice(t, value);
    case 'target':
      return plainTarget(t, value);
    case 'size':
      return plainItems(t, value);
    case 'rate':
      return plainRate(t, value);
    default:
      return value;
  }
}

/** A v20 device as the engine names it ("Chrome/140 on WINDOWS"): the browser, then the system in words. */
function plainDevice(t: TFunction, value: string): string {
  const [browser, system, ...rest] = value.split(' on ');
  return browser !== undefined && system !== undefined && rest.length === 0
    ? `${browser} · ${plainValue(t, 'operatingSystem', system)}`
    : value;
}

/**
 * A v20 target: a usual one by its kind and name (projectKey=PLM-OPS); the request's by its kind only,
 * since the engine names the request's target by its variables (N-INJ-1).
 */
function plainTarget(t: TFunction, value: string): string {
  const named = /^([A-Za-z]+)=(.+)$/.exec(value);
  if (named) {
    return t(`dim.target.${named[1] ?? ''}`, { value: named[2], defaultValue: value });
  }
  return /^[A-Za-z]+$/.test(value) ? t(`dim.targetKind.${value}`, { defaultValue: value }) : value;
}

/** A count of items as the engine writes it ("4,831 items"), or a bare count, in the visitor's words. */
function plainItems(t: TFunction, value: string): string {
  const count = /^([0-9,]+) items$/.exec(value)?.[1] ?? (/^[0-9,]+$/.test(value) ? value : null);
  return count === null ? value : t('dim.items', { n: count });
}

/** A v20 request rate as the engine writes it ("1 requests in the last 60 min"). */
function plainRate(t: TFunction, value: string): string {
  const rate = /^([0-9]+) requests in the last ([0-9]+) min$/.exec(value);
  return rate ? t('dim.rate.recent', { n: rate[1], minutes: rate[2] }) : value;
}

/** A business API path as the operation it is: an export of a project, a document read or download, a customer. */
export function plainPath(t: TFunction, path: string): string {
  const exportOf = /^\/api\/projects\/([^/]+)\/exports/.exec(path);
  if (exportOf) {
    return t('dim.path.export', { project: exportOf[1] });
  }
  // A document is named by its project (document IDs read <project>-<type>-<number>), never by its ID (C-5).
  const document = /^\/api\/documents\/(.+)-[A-Z]{3}-\d+(\/download)?/.exec(path);
  if (document) {
    return t(document[2] ? 'dim.path.download' : 'dim.path.document', { project: document[1] });
  }
  if (path.startsWith('/api/customers')) {
    return t('dim.path.customer');
  }
  return path;
}

/** The engine's membership label: "true" (in the usual), "false", or an UNKNOWN sentence. */
export function membership(inUsual: string | null): 'same' | 'different' | 'unknown' {
  return inUsual === 'true' ? 'same' : inUsual === 'false' ? 'different' : 'unknown';
}

/** A company time as the case's clock shows it: the weekday and the time, as recorded (stored in UTC form). */
export function companyClock(iso: string, language: string): string {
  const locale = language === 'ko' ? 'ko-KR' : 'en-US';
  const date = new Date(iso);
  const weekday = new Intl.DateTimeFormat(locale, { weekday: 'long', timeZone: 'UTC' }).format(date);
  const time = new Intl.DateTimeFormat(locale, {
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
    timeZone: 'UTC',
  }).format(date);
  return `${weekday} ${time}`;
}
