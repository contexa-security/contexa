import { useTranslation } from 'react-i18next';
import { useMeasuredCase, type MeasuredCase } from '../../../api/measured';
import { routeFlow } from '../../../components/journey/flow';
import { SourceLine } from '../../../components/journey/FrameParts';
import { RouteScreen } from '../../../components/journey/RouteScreen';
import { StateScreen } from '../../../components/StateScreen';
import { useJourneyPosition } from '../../../journey/useJourneyPosition';
import { CASES } from '../experience';
import styles from './Timing.module.css';
import { itemsRange, onlyResult, secondsRange } from './timingFormat';

/** The plain word of each result (화면재편-기획안 11.2), the same words the results of part 1 use. */
const RESULT_WORDS: Readonly<Record<string, string>> = {
  STOPPED: 'p1.result.word.STOPPED',
  PARTLY_STOPPED: 'p1.result.word.PARTLY_STOPPED',
  MISSED: 'p1.result.word.MISSED',
  PASSED: 'p1.result.word.PASSED',
  PASSED_AFTER_CHECK: 'p1.result.word.PASSED_AFTER_CHECK',
  HALTED: 'p1.result.word.HALTED',
  UNRESOLVED: 'p1.result.word.UNRESOLVED',
};

/** The results that are not the right handling of their situation: marked by word and color together. */
const WRONG = new Set(['PARTLY_STOPPED', 'MISSED', 'HALTED', 'UNRESOLVED']);

/**
 * The title states the trade-off only when the server's results make it true: stopping before the response stopped
 * the attack with nothing out, stopping from the next request let some out before stopping it, and normal work got
 * through both ways. Otherwise the title only names what the table is.
 */
function tradeOffHolds(
  attackSync: MeasuredCase,
  attackAsync: MeasuredCase,
  workSync: MeasuredCase,
  workAsync: MeasuredCase,
): boolean {
  const passed = (result: string | null) => result === 'PASSED' || result === 'PASSED_AFTER_CHECK';
  const leaked = onlyResult(attackAsync);
  return (
    onlyResult(attackSync) === 'STOPPED' &&
    (leaked === 'PARTLY_STOPPED' || leaked === 'MISSED') &&
    passed(onlyResult(workSync)) &&
    passed(onlyResult(workAsync))
  );
}

interface CellProps {
  readonly measured: MeasuredCase | null;
  readonly threat: boolean;
  /** The way the column sent it: stopping from the next request lets the first request's records out. */
  readonly mode: 'sync' | 'async';
  readonly label: string;
  /** The cell's value is what its way costs normal work (the wait for the answer): marked so the trade-off shows. */
  readonly cost?: boolean;
}

/**
 * One cell of the two by two: Contexa's result over the runs in plain words, then the one value that matters for the
 * row, what went out for the attack and how long the answer took for normal work, as the server's range.
 */
function Cell({ measured, threat, mode, label, cost = false }: CellProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  if (!measured) {
    return (
      <td data-label={label}>
        <span className={styles.cellLine}>{t('p4.none')}</span>
      </td>
    );
  }
  const result = onlyResult(measured);
  // An attack stopped from the next request after its first one went out says how much left (V-06).
  const leaked = threat && mode === 'async' && result === 'PARTLY_STOPPED';
  const figure = threat
    ? measured.exposedItems
      ? t(leaked ? 'p4.compare.leaked' : 'p4.items', { items: itemsRange(measured.exposedItems, language) })
      : null
    : measured.responseMs
      ? t('p4.response', { seconds: secondsRange(measured.responseMs) })
      : null;
  return (
    <td data-label={label}>
      <span className={styles.cellWord} data-wrong={(result !== null && WRONG.has(result)) || undefined}>
        {result && RESULT_WORDS[result] ? t(RESULT_WORDS[result]) : t('p4.compare.mixed')}
      </span>
      {figure ? (
        <span className={styles.cellLine} data-cost={cost || undefined}>
          {figure}
        </span>
      ) : null}
    </td>
  );
}

/**
 * Screen 4-2, the measured comparison (화면재편 T5): one sentence the server's results pick as the title, then one two
 * by two of the attack and normal work, each sent both ways several times (A3, A3A, A3T, A3TA). A cell is Contexa's
 * result in plain words and its range as the server counted it.
 */
export default function CompareScreen() {
  const { t } = useTranslation();
  const position = useJourneyPosition();
  const flow = routeFlow(t, position);
  const number = position.screen?.number ?? '4-2';
  const queries = {
    attackSync: useMeasuredCase(CASES.attacker.sync),
    attackAsync: useMeasuredCase(CASES.attacker.async),
    workSync: useMeasuredCase(CASES.owner.sync),
    workAsync: useMeasuredCase(CASES.owner.async),
  };
  const cells = {
    attackSync: queries.attackSync.data ?? null,
    attackAsync: queries.attackAsync.data ?? null,
    workSync: queries.workSync.data ?? null,
    workAsync: queries.workAsync.data ?? null,
  };
  const loading = Object.values(queries).some((query) => query.isPending);
  const any = Object.values(cells).some((cell) => cell !== null);
  const holds =
    cells.attackSync && cells.attackAsync && cells.workSync && cells.workAsync
      ? tradeOffHolds(cells.attackSync, cells.attackAsync, cells.workSync, cells.workAsync)
      : false;
  const sync = t('p4.mode.sync');
  const async = t('p4.mode.async');

  return (
    <RouteScreen
      title={holds ? t(`screen.${number}.title`) : t('p4.compare.title.other')}
      purpose={t(`screen.${number}.guide`)}
      sourceLine={any ? <SourceLine kind="measured" /> : null}
      back={flow.back}
      main={flow.next}
    >
      {loading ? <StateScreen kind="loading" /> : null}
      {!loading && any ? (
        <table className={styles.grid}>
          <caption className="visually-hidden">{t('p4.compare.table')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('p4.compare.situation')}</th>
              <th scope="col">{sync}</th>
              <th scope="col">{async}</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <th scope="row">{t('p4.compare.attack')}</th>
              <Cell measured={cells.attackSync} threat mode="sync" label={sync} />
              <Cell measured={cells.attackAsync} threat mode="async" label={async} />
            </tr>
            <tr>
              <th scope="row">{t('p4.compare.work')}</th>
              <Cell measured={cells.workSync} threat={false} mode="sync" label={sync} cost />
              <Cell measured={cells.workAsync} threat={false} mode="async" label={async} />
            </tr>
          </tbody>
        </table>
      ) : null}
      {!loading && !any ? <p className={styles.note}>{t('p4.compare.none')}</p> : null}
    </RouteScreen>
  );
}
