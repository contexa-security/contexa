import { useTranslation } from 'react-i18next';
import type { UsualVsNow } from '../../api/anatomy';
import type { DecisionWait, LiveDecision, LiveLayer } from '../../api/types';
import { Chip } from '../../components/main/Chip';
import type { ControlId } from '../../domain/verdict';
import { count, seconds } from '../../journey/format';
import type { FactRow } from './consoleData';
import { laneChip, PRIOR_REFUSALS, verdictChip, type ChipKind } from './mainCases';
import styles from './ConsolePage.module.css';

interface LaneProps {
  readonly control: ControlId;
  readonly sub: string;
  readonly layer: LiveLayer | null;
  /** Whether the case is an attack; null for a run with no set answer (a condition changed on 6-2). */
  readonly threat: boolean | null;
  /** Contexa's decision, for its own lane. */
  readonly decision?: LiveDecision | null;
  /** Contexa holds the response while it decides (a decision before the response). */
  readonly holding?: boolean;
  readonly wait?: DecisionWait | null;
  /** Nothing is sent yet (6-2 before its send): the lane waits empty, named as not sent (L-38). */
  readonly idle?: boolean;
}

/**
 * One lane of the console (설계서 2-2): the approach, the bar of its real answer (filled when the response carried data,
 * red when an attack's data left, blue when work went through; empty with its words when nothing left, B-03), its
 * result chip and its HTTP status and response time. Contexa's lane shows the response held while the engine decides.
 * Before anything is sent every lane waits empty, named as not sent.
 */
export function Lane({
  control,
  sub,
  layer,
  threat,
  decision = null,
  holding = false,
  wait = null,
  idle = false,
}: LaneProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const contexa = control === 'D';
  let chip: { readonly key: string; readonly kind: ChipKind } | null = null;
  if (layer && contexa && decision) {
    chip = verdictChip(decision);
  } else if (layer && (!contexa || PRIOR_REFUSALS.has(layer.ruleId ?? ''))) {
    chip = laneChip(layer, threat);
  }
  const deciding = contexa && !layer && !idle;
  const waited = wait?.waitedMs ?? null;
  const tone = threat === null ? 'plain' : threat ? 'leak' : 'pass';
  // Only data that went out fills a bar; an answer that let nothing out leaves it empty (B-03).
  const full = layer !== null && layer.deliveredItems > 0;
  // The held bar grows toward the same situation's median decision time and never reaches the end before it ends.
  const holdWidth =
    waited !== null && wait && wait.medianMs > 0
      ? Math.min(92, Math.round((waited / wait.medianMs) * 80))
      : 8;
  return (
    <li className={styles.lane} data-contexa={contexa || undefined} data-control={control}>
      <div className={styles.laneName}>
        <b>{t(`main.lane.${control}`)}</b>
        <span className={styles.laneSub}>{sub}</span>
      </div>
      <div className={styles.track} aria-hidden="true">
        {layer ? (
          <>
            {full ? <span className={styles.fill} data-tone={tone} data-full /> : null}
            {/* Words over a full bar take the ink that reads on the bar's colour. */}
            <span className={styles.fillLabel} data-on-fill={full || undefined}>
              {contexa && decision?.totalAnalysisMs != null
                ? t('main.lane.contexaDone', {
                    seconds: seconds(decision.totalAnalysisMs),
                    items: count(layer.deliveredItems, language),
                  })
                : t(outWord(threat), {
                    count: layer.deliveredItems,
                    items: count(layer.deliveredItems, language),
                  })}
            </span>
          </>
        ) : deciding ? (
          <>
            <span
              className={styles.hold}
              data-holding={holding || undefined}
              style={{ inlineSize: `${holdWidth}%` }}
            />
            <span className={styles.fillLabel}>
              {t(holding ? 'main.lane.holding' : 'main.lane.deciding')}
              {waited !== null ? ` · ${seconds(waited)}${t('main.unit.seconds')}` : ''}
            </span>
          </>
        ) : null}
      </div>
      <div className={styles.laneEnd}>
        {chip ? (
          <Chip kind={chip.kind}>{t(chip.key)}</Chip>
        ) : (
          <Chip kind="wait">
            {t(idle ? 'main.4-4.notYet' : deciding ? 'main.lane.deciding' : 'main.lane.sent')}
          </Chip>
        )}
        {idle ? null : (
          <span className={styles.laneMeta}>
            {layer
              ? t('main.lane.meta', {
                  status: layer.httpStatus ?? '—',
                  seconds: seconds(layer.elapsedMs),
                })
              : t('main.lane.metaWaiting')}
          </span>
        )}
      </div>
    </li>
  );
}

/** The mark of a fact row: never by color alone. */
export function FactMark({ mark, lit }: { readonly mark: FactRow['mark']; readonly lit: boolean }) {
  const { t } = useTranslation();
  if (!lit) {
    return <span className={styles.factWait}>{t('main.facts.waiting')}</span>;
  }
  return (
    <b className={styles.factMark} data-mark={mark}>
      {t(`main.facts.mark.${mark}`)}
    </b>
  );
}

/**
 * EV-4, the engine's whole comparison at a glance: one cell per dimension of the learned usual pattern, red where the
 * engine read the request as outside it, dashed where it could not compare it this time, and the names of both (V-10).
 * The membership is the engine's own label; the portal counted the departures.
 */
export function CompareStrip({
  rows,
  departures,
  compared = null,
}: {
  readonly rows: readonly UsualVsNow[];
  readonly departures: number;
  /** How many items the engine compared, counted by the portal; null when the record is older than the count. */
  readonly compared?: number | null;
}) {
  const { t } = useTranslation();
  const differing = rows.filter((row) => row.inUsual === 'false');
  const unknown = rows.filter((row) => row.inUsual !== 'false' && row.inUsual !== 'true');
  const names = (found: readonly UsualVsNow[]) => found.map((row) => t(`dim.${row.dimension}`)).join(' · ');
  return (
    <div className={styles.compare}>
      <p className={styles.compareLine}>
        {compared !== null && compared < rows.length
          ? departures > 0
            ? t('main.facts.comparedOf', { n: rows.length, c: compared, d: departures, count: departures })
            : t('main.facts.comparedOfNone', { n: rows.length, c: compared })
          : departures > 0
            ? t('main.facts.compared', { n: rows.length, d: departures, count: departures })
            : t('main.facts.comparedNone', { n: rows.length })}
      </p>
      <ol className={styles.compareCells} aria-hidden="true">
        {rows.map((row) => (
          <li
            key={row.dimension}
            className={styles.compareCell}
            data-state={row.inUsual === 'false' ? 'out' : row.inUsual === 'true' ? 'in' : 'unknown'}
            title={t(`dim.${row.dimension}`)}
          />
        ))}
      </ol>
      {differing.length > 0 ? (
        <p className={styles.compareNames}>{t('main.facts.differs', { names: names(differing) })}</p>
      ) : null}
      {unknown.length > 0 ? (
        <p className={styles.compareUnknown}>{t('main.facts.unknown', { names: names(unknown) })}</p>
      ) : null}
    </div>
  );
}

/** The deck's word for data that left (T-04): a leak of an attack, an export of normal work, plain without an answer. */
function outWord(threat: boolean | null): string {
  if (threat === null) {
    return 'main.lane.delivered';
  }
  return threat ? 'main.lane.leaked' : 'main.lane.exported';
}
