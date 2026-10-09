import { useTranslation } from 'react-i18next';
import { useAnatomies, useAnatomy } from '../../api/anatomy';
import { useActEnd, useJourney } from '../../api/journey';
import { useMeasuredCase } from '../../api/measured';
import { useVisitor } from '../../api/queries';
import { useTeasers } from '../../api/teasers';
import { AppHeader } from '../../components/AppHeader';
import { SourceMark } from '../../components/common/SourceMark';
import { Icon } from '../../components/Icon';
import { ActEndCard } from '../../components/journey/Cards';
import { JourneyBar, JustSaw } from '../../components/journey/JourneyParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { actEndSentence, teaserCopy } from '../../journey/copy';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import { CASES } from './experience';
import experience from './Experience.module.css';
import styles from './LearnAfterPage.module.css';

/**
 * The run of a case that shows one kind of learning: the visitor's latest run of it when that run is of that kind,
 * else the measured run the screen names (and says so). A passed check is told by the stored check; a stopped request
 * by a decision other than allow.
 */
function useCaseRun(caseKey: string, kind: 'allow' | 'checked' | 'stopped') {
  const journey = useJourney();
  const measured = useMeasuredCase(caseKey).data ?? null;
  const own =
    [...(journey.data?.runs ?? [])]
      .reverse()
      .find((line) => line.scenarioKey === caseKey && line.status === 'COMPLETED')?.runId ?? null;
  const ownFirst = useAnatomy(kind === 'allow' ? null : own, 1).data ?? null;
  const check = ownFirst?.recovery?.challenge ?? null;
  const ownFits =
    own !== null &&
    (kind === 'allow' ||
      (kind === 'checked' && check?.answered === true && check.reissue_outcome !== null) ||
      (kind === 'stopped' &&
        ownFirst !== null &&
        ownFirst.interpretation.recorded.finalAction !== null &&
        ownFirst.interpretation.recorded.finalAction !== 'ALLOW'));
  const fallback = kind === 'checked' ? (measured?.resumed?.runId ?? null) : (measured?.middleRun ?? null);
  return { runId: ownFits ? own : fallback, measured: !ownFits };
}

type LineKind = 'allow' | 'checked' | 'stopped' | 'released';

interface LineProps {
  readonly kind: LineKind;
  readonly rule: string;
  readonly example: string | null;
  readonly measured: boolean;
  /** The line has no run of this demo behind it: the core's documented behaviour. */
  readonly core?: boolean;
}

/** One decision, what the engine does with it for learning, and this demo's record of it. */
function Line({ kind, rule, example, measured, core = false }: LineProps) {
  const { t } = useTranslation();
  return (
    <li className={styles.line}>
      <span className={styles.kind} data-kind={kind}>
        {t(`learnAfter.kind.${kind}`)}
      </span>
      <Icon name="arrowRight" className={styles.arrow} />
      <span className={styles.rule}>{rule}</span>
      <span className={styles.example} data-core={core || undefined}>
        {core ? t('learnAfter.core') : (example ?? '-')}
        {measured && !core ? <span className={styles.measured}>{t('learnAfter.measured')}</span> : null}
      </span>
    </li>
  );
}

/**
 * After a decision (learn-after, 7.3): what each decision does to the usual behaviour, each with the record of this
 * demo that shows it (the visitor's own run, or else the measured run, said so), the warning that one allow is already
 * "usual", and the difference revisited. The end of act 3 is a screen of its own (D-41).
 */
export default function LearnAfterPage({ ending }: { readonly ending: boolean }) {
  return ending ? <ActThreeEnd /> : <LearnAfter />;
}

function LearnAfter() {
  const { t } = useTranslation();
  const allowRun = useCaseRun('A6T', 'allow');
  const checkRun = useCaseRun(CASES.owner.sync, 'checked');
  const stopRun = useCaseRun(CASES.attacker.sync, 'stopped');
  const allow = useAnatomies(allowRun.runId, 5).map((query) => query.data);
  const check = useAnatomy(checkRun.runId, 1).data ?? null;
  const stop = useAnatomy(stopRun.runId, 1).data ?? null;
  const allowFigures = allow[allow.length - 1]?.figures ?? null;
  const change = (
    try_: string,
    figures: { baselineBefore: number | null; baselineAfter: number | null } | null,
  ) =>
    figures && figures.baselineBefore !== null && figures.baselineAfter !== null
      ? t(figures.baselineBefore === figures.baselineAfter ? 'learnAfter.same' : 'learnAfter.grew', {
          try: try_,
          from: figures.baselineBefore,
          to: figures.baselineAfter,
        })
      : null;
  // "The runs you saw today" holds while one line is the visitor's own run; with none, the lines are measured runs.
  const title = t(
    allowRun.measured && checkRun.measured && stopRun.measured ? 'learnAfter.titleMeasured' : 'learnAfter.title',
  );
  return (
    <RouteScreen
      title={title}
      purpose={t('learnAfter.purpose')}
      source={
        <SourceMark kind="ENGINE" runId={allowRun.runId}>
          {t('learnAfter.source', {
            allow: allowRun.runId ?? '-',
            check: checkRun.runId ?? '-',
            stop: stopRun.runId ?? '-',
          })}
        </SourceMark>
      }
      justSaw={<JustSaw difference={6} sentence="learnAfter" again />}
      nextLabel={t('learnAfter.next')}
      nextLabelFor="act-end-3"
    >
      <ol className={styles.lines} aria-label={title}>
        <Line
          kind="allow"
          rule={t('learnAfter.rule.allow')}
          example={change(t('learnAfter.try3'), allowFigures)}
          measured={allowRun.measured}
        />
        <Line
          kind="checked"
          rule={t('learnAfter.rule.checked')}
          example={change(t('learnAfter.try2'), check?.figures ?? null)}
          measured={checkRun.measured}
        />
        <Line
          kind="stopped"
          rule={t('learnAfter.rule.stopped')}
          example={change(t('learnAfter.try1'), stop?.figures ?? null)}
          measured={stopRun.measured}
        />
        <Line kind="released" rule={t('learnAfter.rule.released')} example={null} measured={false} core />
      </ol>
      <p className={styles.warning}>
        <span className={styles.warningName}>{t('learnAfter.warningName')}</span>
        {t('learnAfter.warning')}
      </p>
    </RouteScreen>
  );
}

/** The end of act 3 (act-end): the visitor's own learning sentence, the six differences and act 4's teaser. */
function ActThreeEnd() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  useVisitor();
  const position = useJourneyPosition();
  const teasers = useTeasers();
  const actEnd = useActEnd(3, true);
  return (
    <>
      <AppHeader />
      <main id="main" className={experience.page}>
        <JourneyBar />
        <ActEndCard
          act={3}
          differences={position.differences}
          sentence={
            actEnd.data && actEnd.data.source !== 'NONE' ? actEndSentence(t, language, actEnd.data) : null
          }
          measured={actEnd.data?.source === 'MEASUREMENT'}
          runId={actEnd.data?.runId ?? null}
          next={teaserCopy(
            t,
            language,
            'LEARN_AFTER_FALSE_BLOCKS',
            teasers.data,
            position.differences.length,
          )}
          continueTo={position.next?.path ?? '/intro/approaches'}
          back={{ to: '/try/summary/learning', label: t('step.back', { step: t('place.step.learn-after') }) }}
          benchmarkTo="/benchmark"
          shareUrl={window.location.href}
        />
      </main>
    </>
  );
}
