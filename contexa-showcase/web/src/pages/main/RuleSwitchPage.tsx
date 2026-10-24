import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useJourney } from '../../api/journey';
import { useVisitor } from '../../api/queries';
import { usePublicSettings } from '../../api/settings';
import { Chip } from '../../components/main/Chip';
import { MainLink, MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import { latestOwnRun } from './latestRun';
import { MAIN_CASES, resultChip, ROLE_PATHS, runCell } from './mainCases';
import styles from './ComparePages.module.css';

/** The owner's results that let the work through: at once, or after an extra check. */
const WORK_DONE = new Set(['PASSED', 'PASSED_AFTER_CHECK']);

/**
 * 7-1, the fixed rule turned on (설계서 5-1, IN-6): the visitor's two runs, with the fixed rule's real result for each
 * when the switch is on and the sign-in check's alone when it is off, against Contexa's in the same runs. Nothing is
 * recomputed: each rule cell is the run's own recorded and scored result, Contexa's cell its own decision with the items
 * that left, and the headline is the one the two results make true: the rule stopped the attack and the work alike, let
 * both through alike, or neither. When the rule met neither request, a line says the switch changes nothing here.
 * The two run badges are named alike (공격자 실행, 정상 사용자 실행) and the note that nothing is recomputed stands once
 * beside them (L-38).
 */
export default function RuleSwitchPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const settings = usePublicSettings();
  const [on, setOn] = useState(true);
  const attack = latestOwnRun(journey.data?.runs, MAIN_CASES.attacker);
  const normal = latestOwnRun(journey.data?.runs, MAIN_CASES.owner);

  if (journey.isPending) {
    return (
      <MainScreen title={t('main.7-1.titlePlain')} main={null}>
        <StateScreen kind="loading" />
      </MainScreen>
    );
  }
  if (!attack || !normal) {
    const missing = attack ? 'owner' : 'attacker';
    return (
      <MainScreen
        title={t('main.7-1.titlePlain')}
        intro={t(`main.4-3.missing.${missing}`)}
        main={<MainLink to={ROLE_PATHS[missing].request}>{t('main.console.toRequest')}</MainLink>}
        nextNote={null}
      >
        {null}
      </MainScreen>
    );
  }
  const threshold = settings.data?.threshold ?? null;
  const rule =
    threshold && threshold.nightStart && threshold.nightEnd && threshold.volumeLimit !== null
      ? t('main.7-1.rule', {
          start: threshold.nightStart,
          end: threshold.nightEnd,
          limit: count(threshold.volumeLimit, language),
        })
      : t('main.lane.C1.subPlain');
  const control = on ? 'C1' : 'B';
  const left = resultChip(attack.business[control]);
  const right = resultChip(normal.business[control]);
  const contexaLeft = runCell(t, language, attack, 'D');
  const contexaRight = runCell(t, language, normal, 'D');
  // The sentence names what the rule did only when the two runs recorded it: the attack stopped, the work halted.
  const dilemma = attack.business['C1'] === 'STOPPED' && normal.business['C1'] === 'HALTED';
  // The rule let the attack and the work through alike: it cannot tell them apart (the blind spot of IN-6).
  const blind = attack.business['C1'] === 'MISSED' && WORK_DONE.has(normal.business['C1'] ?? '');
  const variant = dilemma ? '' : blind ? '.blind' : 'Plain';
  // V-32: when the rule met neither request, turning it on or off shows the same results; the screen says so.
  const same =
    blind && attack.business['C1'] === attack.business['B'] && normal.business['C1'] === normal.business['B'];
  return (
    <MainScreen title={t(`main.7-1.title${variant}`)} intro={t('main.7-1.intro', { rule })}>
      <section className={styles.card} aria-labelledby="switch-table">
        <h2 id="switch-table" className="visually-hidden">
          {t('main.7-1.table')}
        </h2>
        <div className={styles.grid3} data-head>
          <span />
          <span>{t('main.4-3.attack')}</span>
          <span>{t('main.4-3.normal')}</span>
        </div>
        <div className={styles.grid3}>
          <label className={styles.switch}>
            <input
              type="checkbox"
              role="switch"
              className={styles.switchInput}
              checked={on}
              onChange={(event) => setOn(event.target.checked)}
            />
            <span className={styles.switchTrack} aria-hidden="true" />
            <b className={styles.rowName}>{t(on ? 'main.7-1.on' : 'main.7-1.off')}</b>
          </label>
          <span className={styles.flip} key={`${control}-attack`}>
            <Chip kind={left.kind}>{t(left.key)}</Chip>
          </span>
          <span className={styles.flip} key={`${control}-normal`}>
            <Chip kind={right.kind}>{t(right.key)}</Chip>
          </span>
        </div>
        <div className={styles.grid3} data-contexa>
          <b className={styles.rowName}>{t('main.7-1.contexa')}</b>
          <span className={styles.chips}>
            <Chip kind={contexaLeft.kind}>{contexaLeft.words}</Chip>
          </span>
          <span className={styles.chips}>
            <Chip kind={contexaRight.kind}>{contexaRight.words}</Chip>
          </span>
        </div>
        {same ? <p className={styles.note}>{t('main.7-1.same')}</p> : null}
      </section>
      <p className={styles.why}>{t(`main.7-1.why${variant}`)}</p>
      <div className={styles.badges}>
        <SourceBadge kind="run" label={t('main.4-3.attack')} runId={attack.runId} />
        <SourceBadge kind="run" label={t('main.4-3.normal')} runId={normal.runId} />
        <span className={styles.note}>{t('main.7-1.source')}</span>
      </div>
    </MainScreen>
  );
}
