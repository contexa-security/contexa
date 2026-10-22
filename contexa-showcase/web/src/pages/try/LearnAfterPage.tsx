import { useTranslation } from 'react-i18next';
import { useAnatomies, type DecisionAnatomyView } from '../../api/anatomy';
import { useActEnd, useJourney } from '../../api/journey';
import { useLabOptions } from '../../api/lab';
import { useMeasuredCase } from '../../api/measured';
import { useVisitor } from '../../api/queries';
import { PartWrap } from '../../components/journey/Cards';
import { routeFlow } from '../../components/journey/flow';
import { SourceLine } from '../../components/journey/FrameParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import { actEndSentence } from '../../journey/copy';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import { CASES } from './experience';
import { latestRun, learnedText } from './learned';
import styles from './LearnAfterPage.module.css';

/** The three kinds of learning a run of this demo can show; the fourth line (an admin unblocking) has no run here. */
type Kind = 'allow' | 'checked' | 'stopped';

/** The case whose runs show each kind: try 3's real work, try 2's real employee, try 1's stolen account. */
const CASE_OF: Readonly<Record<Kind, string>> = {
  allow: 'A6T',
  checked: CASES.owner.sync,
  stopped: CASES.attacker.sync,
};

/** Whether a run's stored records really are of the kind its line names, read from the records alone. */
const FITS: Readonly<Record<Kind, (records: readonly DecisionAnatomyView[]) => boolean>> = {
  allow: (records) => records.every((record) => record.interpretation.recorded.finalAction === 'ALLOW'),
  checked: (records) => {
    const check = records[0]?.recovery?.challenge ?? null;
    return check?.answered === true && check.reissue_outcome !== null;
  },
  stopped: (records) => {
    const action = records[0]?.interpretation.recorded.finalAction ?? null;
    return action !== null && action !== 'ALLOW' && records[0]?.recovery?.challenge?.answered !== true;
  },
};

interface LineRecord {
  readonly pending: boolean;
  /** The values are the visitor's own run's. */
  readonly own: boolean;
  /** The figures of the run shown, null when no run of this kind exists. */
  readonly figures: DecisionAnatomyView['figures'] | null;
  readonly found: boolean;
}

/**
 * The run behind a line: the visitor's latest run of the case when its records are of the line's kind, else the
 * current measurement's run of that kind (the middle run, or the latest one that passed a check), else none.
 */
function useLine(kind: Kind, steps: number): LineRecord {
  const caseKey = CASE_OF[kind];
  const journey = useJourney();
  const measured = useMeasuredCase(caseKey);
  const ownId = latestRun(journey.data?.runs, caseKey);
  const own = useAnatomies(ownId, steps);
  const ownSettled = !journey.isPending && steps > 0 && own.every((query) => !query.isPending);
  const ownRecords = own.flatMap((query) => (query.data ? [query.data] : []));
  const ownFits = ownId !== null && ownSettled && ownRecords.length === steps && FITS[kind](ownRecords);
  const fallback =
    kind === 'checked' ? (measured.data?.resumed?.runId ?? null) : (measured.data?.middleRun ?? null);
  const otherId = ownSettled && !ownFits && fallback !== ownId ? fallback : null;
  const other = useAnatomies(otherId, steps);
  const otherSettled = other.every((query) => !query.isPending);
  const otherRecords = other.flatMap((query) => (query.data ? [query.data] : []));
  const otherFits =
    otherId !== null && otherSettled && otherRecords.length === steps && FITS[kind](otherRecords);
  const records = ownFits ? ownRecords : otherFits ? otherRecords : null;
  return {
    pending: !ownSettled || (!ownFits && (measured.isPending || !otherSettled)),
    own: ownFits,
    figures: records ? (records[records.length - 1]?.figures ?? null) : null,
    found: records !== null,
  };
}

/**
 * After a judgment (learn-after), screens 3-4 and 3-5. The end of the part is its wrap-up (PartWrap, T8): the sentence
 * of the visitor's own learning, from the server, and the differences seen.
 */
export default function LearnAfterPage({ ending }: { readonly ending: boolean }) {
  return ending ? <ActThreeEnd /> : <LearnAfter />;
}

/**
 * Screen 3-4, what it learns and what not (화면재편 T7): four lines, one per kind of request, saying what Contexa does
 * with it for learning, each with the learned requests of a real run of that kind (the visitor's own, else an earlier
 * real request of the same situation, named in the source line); the admin's unblocking has no run in this demo and
 * says it is Contexa's set behaviour. One plain warning line closes it: one pass is usual at once.
 */
function LearnAfter() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const position = useJourneyPosition();
  const flow = routeFlow(t, position);
  const options = useLabOptions();
  // Try 3's run is read whole (every request must have passed); the others are one-request cases.
  const allowSteps = options.isError
    ? 1
    : (options.data?.cases.find((candidate) => candidate.key === CASE_OF.allow)?.requests.length ?? 0);
  const lines: Readonly<Record<Kind, LineRecord>> = {
    allow: useLine('allow', allowSteps),
    checked: useLine('checked', 1),
    stopped: useLine('stopped', 1),
  };
  const kinds: readonly Kind[] = ['allow', 'checked', 'stopped'];
  const pending = kinds.some((kind) => lines[kind].pending);
  const shown = kinds.filter((kind) => lines[kind].found);
  const ownShown = shown.filter((kind) => lines[kind].own).length;
  const sourceLine =
    pending || shown.length === 0 ? null : ownShown === shown.length ? (
      <span>{t('p3.after.source.own')}</span>
    ) : ownShown > 0 ? (
      <span>{t('p3.after.source.mixed')}</span>
    ) : (
      <SourceLine kind="earlier" />
    );
  const value = (kind: Kind) =>
    lines[kind].found ? learnedText(t, language, lines[kind].figures) : t('p3.after.value.none');

  return (
    <RouteScreen
      title={t('screen.3-4.title')}
      purpose={t('screen.3-4.guide')}
      sourceLine={sourceLine}
      back={flow.back}
      main={flow.next}
    >
      {pending ? (
        <StateScreen kind="loading" />
      ) : (
        <ol className={styles.lines} aria-label={t('screen.3-4.title')}>
          {kinds.map((kind) => (
            <li key={kind} className={styles.line} data-learns={kind !== 'stopped'}>
              <span className={styles.kind}>{t(`p3.after.kind.${kind}`)}</span>
              <span className={styles.rule}>{t(`p3.after.rule.${kind}`)}</span>
              <span className={styles.value}>{value(kind)}</span>
            </li>
          ))}
          <li className={styles.line} data-learns>
            <span className={styles.kind}>{t('p3.after.kind.released')}</span>
            <span className={styles.rule}>{t('p3.after.rule.released')}</span>
            <span className={styles.value} data-set>
              {t('p3.after.value.set')}
            </span>
          </li>
        </ol>
      )}
      <p className={styles.warning}>
        <span className={styles.warningName}>{t('p3.after.warningName')}</span> {t('p3.after.warning')}
      </p>
    </RouteScreen>
  );
}

/** Screen 3-5, the part's wrap-up (T8): the visitor's own learning sentence and the differences seen. */
function ActThreeEnd() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  useVisitor();
  const position = useJourneyPosition();
  const actEnd = useActEnd(3, true);
  return (
    <PartWrap
      sentence={
        actEnd.data && actEnd.data.source !== 'NONE' ? actEndSentence(t, language, actEnd.data) : null
      }
      measured={actEnd.data?.source === 'MEASUREMENT'}
      differences={position.differences}
    />
  );
}
