import { useTranslation } from 'react-i18next';
import { Navigate, useLocation } from 'react-router-dom';
import { useJourney, type RecapLine } from '../../api/journey';
import { useVisitor } from '../../api/queries';
import { MainScreen } from '../../components/main/MainScreen';
import { ThemePair } from '../../components/main/ThemePair';
import { screenAt } from '../../journey/journey';
import { MAIN_CASES } from '../main/mainCases';

/** Contexa's business results that kept data in, wholly or after some left. */
const STOPPED_RESULTS: ReadonlySet<string> = new Set(['STOPPED', 'PARTLY_STOPPED']);
import styles from './BriefingPage.module.css';

/** The four cells of a cover, in the design's order (설계서 그룹 표지). */
const CELLS = ['do', 'check', 'try', 'learn'] as const;

/** The judgments that keep the data in: a stop, an extra check or a hold for the administrator. */
const KEPT_IN = new Set(['BLOCK', 'ESCALATE', 'CHALLENGE']);

/** The existing security, whose results the insider's line names. */
const EXISTING = ['A', 'B', 'C1', 'C2'];

/** The owner's results that let the work through: at once, or after an extra check. */
const WORK_DONE = new Set(['PASSED', 'PASSED_AFTER_CHECK']);

/** The visitor's latest own run of a case on the main flow (lab runs are the lab's). */
function latestRun(runs: readonly RecapLine[] | undefined, caseKey: string): RecapLine | null {
  const own = (runs ?? []).filter((run) => run.scenarioKey === caseKey && !run.lab);
  return own.length > 0 ? (own[own.length - 1] ?? null) : null;
}

/** The line of the group before: its key, a count, and the keys of the words it names in its places. */
interface PastLine {
  readonly key: string;
  readonly n?: number;
  readonly parts?: Readonly<Record<string, string>>;
}

/**
 * What the group before showed, as one line of the visitor's own runs (설계서: 지난 주제 한 줄): it names a result only
 * when the visitor's run recorded it, and otherwise says what the group before was about, never a result it did not
 * have. Covers 2 and 4 follow a group without a run of its own and say what it showed.
 */
function pastLine(group: number, runs: readonly RecapLine[] | undefined): PastLine {
  if (group === 3) {
    const attack = latestRun(runs, MAIN_CASES.attacker);
    if (!attack || attack.engineAction === null) {
      return { key: 'cover.3.past.none' };
    }
    if (KEPT_IN.has(attack.engineAction) && attack.exposedItems === 0) {
      return { key: `cover.3.past.${attack.engineAction}` };
    }
    return { key: 'cover.3.past.through' };
  }
  if (group === 5) {
    const attack = latestRun(runs, MAIN_CASES.attacker);
    const normal = latestRun(runs, MAIN_CASES.owner);
    const owner = normal?.business['D'] ?? '';
    const action = attack?.engineAction ?? null;
    // P-05: the split names what Contexa did on each side, as each run recorded it.
    return action !== null && KEPT_IN.has(action) && attack?.exposedItems === 0 && WORK_DONE.has(owner)
      ? {
          key: 'cover.5.past.split',
          parts: { attack: `cover.5.past.attack.${action}`, owner: `cover.5.past.owner.${owner}` },
        }
      : { key: 'cover.5.past.none' };
  }
  if (group === 6) {
    // IN-6: the insider's run, named by what the four existing approaches and Contexa did with it.
    const insider = latestRun(runs, MAIN_CASES.insider);
    if (!insider || insider.engineAction === null) {
      return { key: 'cover.6.past.none' };
    }
    // A run of several documents is named by what Contexa did with them, not by its first judgment alone.
    if (!KEPT_IN.has(insider.engineAction) && !STOPPED_RESULTS.has(insider.business['D'] ?? '')) {
      return { key: 'cover.6.past.through' };
    }
    const allPassed = EXISTING.every((control) => insider.business[control] === 'MISSED');
    return { key: allPassed ? 'cover.6.past.held' : 'cover.6.past.heldOnly', n: insider.exposedItems };
  }
  return { key: `cover.${group}.past` };
}

/**
 * A group's cover (T0, 최종화면-구현계획 F0-7): the line the group before ended on, then a warm panel with the group's
 * number, its question and four cells (what you do, what you check, what you try, what you will know), and one button
 * into the group. It draws no place label; the group bar and the panel say where it is.
 */
export default function BriefingPage() {
  const { t, i18n } = useTranslation();
  const location = useLocation();
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const screen = screenAt('DEFAULT', location.pathname);
  if (!screen || screen.type !== 'T0') {
    return <Navigate to="/" replace />;
  }
  const group = screen.act;
  const name = t(`group.${group}`);
  const past = pastLine(group, journey.data?.runs);
  const words = {
    ...(past.n === undefined ? {} : { n: past.n }),
    ...Object.fromEntries(Object.entries(past.parts ?? {}).map(([place, key]) => [place, t(key)])),
  };
  return (
    <MainScreen cover title={t(`cover.${group}.question`)} titleInCore cta={t('cover.start', { name })}>
      <p className={styles.past} data-block>
        <b className={styles.pastLabel}>{t('cover.pastLabel')}</b>
        <span key={`${past.key}-${i18n.language}`}>{t(past.key, words)}</span>
      </p>
      <section className={styles.hero} aria-labelledby="cover-question" data-block>
        <span className={styles.numeral} aria-hidden="true">
          {group}
        </span>
        <p className={styles.eyebrow}>{t('cover.eyebrow', { group, name })}</p>
        <p id="cover-question" className={styles.question} aria-hidden="true">
          {t(`cover.${group}.question`)}
        </p>
        <dl className={styles.cells}>
          {CELLS.map((cell, index) => (
            <div
              key={cell}
              className={styles.cell}
              style={{ animationDelay: `calc(var(--cover-step) * ${index})` }}
            >
              <dt className={styles.cellLabel}>{t(`cover.label.${cell}`)}</dt>
              <dd className={styles.cellText}>{t(`cover.${group}.${cell}`)}</dd>
            </div>
          ))}
        </dl>
      </section>
      {/* IN-6: the covers of the two themes carry the same card that sets them apart. */}
      {group === 2 || group === 5 ? <ThemePair current={group === 2 ? 'outside' : 'inside'} /> : null}
    </MainScreen>
  );
}
