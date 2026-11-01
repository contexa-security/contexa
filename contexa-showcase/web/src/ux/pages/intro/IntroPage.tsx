import type { CSSProperties } from 'react';
import { useTranslation } from 'react-i18next';
import { useHook, type HookColumn } from '../../../api/hook';
import { useStats } from '../../../api/queries';
import { CONTROL_ORDER } from '../../../domain/verdict';
import { setLanguage } from '../../../i18n';
import { formatNumber, formatSeconds } from '../../format';
import { useHookRepeats } from '../../runs/hookMeasurement';
import { EXISTING, controlVerdict } from '../../simulate/person';
import { useTheme } from '../../theme';
import { ButtonLink, Icon, VerdictBadge, type UxIconName } from '../../ui';
import { UX_VERDICTS } from '../../verdict';
import styles from './Intro.module.css';

const WORDMARK = 'CONTEXA';
const STOPPING = new Set(['CHALLENGE', 'ESCALATE', 'BLOCK']);
const PILLARS: readonly { readonly id: 'run' | 'see' | 'mean'; readonly icon: UxIconName }[] = [
  { id: 'run', icon: 'play' },
  { id: 'see', icon: 'git-compare-arrows' },
  { id: 'mean', icon: 'shield-check' },
];

/** A step of the entrance: its order sets its delay, so the screen unfolds wordmark → value → figure → pillars. */
const step = (order: number) => ({ '--step': order }) as CSSProperties;

/**
 * The introduction (DEC-76): the first screen of the demo, on its own without the menu. The wordmark, the one-line
 * value, a figure of the core value drawn from the published recorded run (the same request, four existing controls
 * allowing it, Contexa deciding otherwise), what the demo does, shows and means, and the way in. The entrance unfolds
 * once; with reduced motion the screen is simply there.
 */
export default function IntroPage() {
  const { t, i18n } = useTranslation();
  const { theme, toggle } = useTheme();
  const hook = useHook();
  const stats = useStats();
  const other = i18n.language === 'ko' ? 'en' : 'ko';
  const p50 = stats.data?.decisionTime.p50Ms ?? null;
  const decisions = stats.data ? (stats.data.engineDecisions ?? stats.data.decisionTime.decisions) : null;
  return (
    <div className={styles.intro}>
      <div className={styles.glow} aria-hidden="true" />
      <header className={styles.top}>
        <span className={styles.brand}>
          <span className={styles.brandMark} aria-hidden="true">
            C
          </span>
          Contexa
        </span>
        <span className={styles.topActions}>
          <button
            type="button"
            className={styles.iconButton}
            aria-label={t('ux.top.language', { other: other === 'en' ? 'English' : '한국어' })}
            onClick={() => void setLanguage(other)}
          >
            <Icon name="globe" size="md" />
            <span aria-hidden="true">{i18n.language === 'ko' ? 'KO' : 'EN'}</span>
          </button>
          <button
            type="button"
            className={styles.iconButton}
            aria-label={t(theme === 'dark' ? 'ux.top.theme.toLight' : 'ux.top.theme.toDark')}
            onClick={toggle}
          >
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} />
          </button>
        </span>
      </header>
      <main id="main" className={styles.main} tabIndex={-1}>
        <section className={styles.hero} aria-labelledby="intro-title">
          <p className={styles.eyebrow} style={step(0)}>
            <span className={styles.liveDot} aria-hidden="true" />
            {t('ux.intro.eyebrow')}
          </p>
          {/* Read as one word; the letters are drawn one by one. */}
          <h1 id="intro-title" className={styles.wordmark} aria-label="Contexa">
            {WORDMARK.split('').map((letter, index) => (
              <span key={index} className={styles.letter} style={step(index + 1)} aria-hidden="true">
                {letter}
              </span>
            ))}
          </h1>
          <p className={styles.tagline} style={step(9)}>
            {t('ux.intro.tagline')}
          </p>
          <p className={styles.lead} style={step(10)}>
            {t('ux.intro.lead')}
          </p>
          <div className={styles.actions} style={step(11)}>
            <ButtonLink to="/start" variant="primary" size="lg" iconAfter="arrow-right">
              {t('ux.intro.enter')}
            </ButtonLink>
            <ButtonLink to="/benchmarks" variant="secondary" size="lg" icon="clipboard-check">
              {t('ux.intro.benchmarks')}
            </ButtonLink>
          </div>
          {decisions !== null && decisions > 0 && p50 !== null ? (
            <p className={styles.liveLine} style={step(12)}>
              {t('ux.intro.live', {
                n: formatNumber(decisions, i18n.language),
                p50: formatSeconds(p50, i18n.language),
              })}
            </p>
          ) : null}
        </section>
        <ValueFigure column={hook.data?.attacker ?? null} />
        <section className={styles.pillars} aria-labelledby="intro-pillars" style={step(14)}>
          <h2 id="intro-pillars" className={styles.pillarsTitle}>
            {t('ux.intro.pillars')}
          </h2>
          <ol className={styles.pillarList}>
            {PILLARS.map((pillar, index) => (
              <li key={pillar.id} className={styles.pillar}>
                <span className={styles.pillarHead}>
                  <span className={styles.pillarIcon}>
                    <Icon name={pillar.icon} size="lg" />
                  </span>
                  <span className={styles.pillarNo} aria-hidden="true">
                    {String(index + 1).padStart(2, '0')}
                  </span>
                </span>
                <h3 className={styles.pillarTitle}>{t(`ux.intro.pillar.${pillar.id}.title`)}</h3>
                <p className={styles.pillarBody}>{t(`ux.intro.pillar.${pillar.id}.body`)}</p>
              </li>
            ))}
          </ol>
        </section>
      </main>
    </div>
  );
}

/**
 * The core value as a figure: one request into the five security controls at once, each control's decision on the
 * published recorded run. The sentence under it states the run's real result only when the four existing controls all
 * allowed it and Contexa stopped it; otherwise (or before the run is read) it says how the controls differ.
 */
function ValueFigure({ column }: { readonly column: HookColumn | null }) {
  const { t, i18n } = useTranslation();
  const layers = column?.result.layers ?? [];
  const layerOf = (control: string) => layers.find((layer) => layer.control === control) ?? null;
  const verdictOf = (control: string) => {
    const layer = layerOf(control);
    return layer
      ? controlVerdict(
          control,
          { outcome: layer.outcome, ruleId: layer.ruleId },
          control === 'D' && layer.verdict
            ? { finalAction: layer.verdict, unresolved: layer.evidence.unresolved }
            : null,
        )
      : null;
  };
  const repeats = useHookRepeats(column);
  const n = (value: number) => formatNumber(value, i18n.language);
  const items = Math.max(0, ...EXISTING.map((control) => layerOf(control)?.evidence.deliveredItems ?? 0));
  const contexa = verdictOf('D');
  const proven =
    column !== null &&
    EXISTING.every((control) => verdictOf(control) === 'ALLOW') &&
    contexa !== null &&
    STOPPING.has(contexa);
  return (
    <figure className={styles.figure} aria-labelledby="intro-value" style={step(13)}>
      <h2 id="intro-value" className={styles.figureTitle}>
        {t('ux.intro.value.label')}
      </h2>
      <div className={styles.diagram}>
        <div className={styles.request}>
          <span className={styles.requestLabel}>{t('ux.intro.value.request')}</span>
          <span className={styles.requestValue}>
            {column?.caseKey === 'S13' && items > 0
              ? t('ux.review.title.S13', { n: formatNumber(items, i18n.language) })
              : t('ux.intro.value.request')}
          </span>
        </div>
        <span className={styles.stub} aria-hidden="true" />
        <ol className={styles.branches} aria-label={t('ux.intro.value.lanes')}>
          {CONTROL_ORDER.map((control, index) => {
            const verdict = verdictOf(control);
            return (
              <li key={control} className={styles.branch} data-contexa={control === 'D' || undefined}>
                <span className={styles.branchLine} aria-hidden="true">
                  <span className={styles.flowDot} style={step(index)} />
                </span>
                <span className={styles.lane}>
                  <span className={styles.laneName}>{t(`ux.control.${control}`)}</span>
                  {verdict !== null && verdict !== 'PRIOR' ? (
                    <VerdictBadge verdict={verdict} />
                  ) : (
                    <span className={styles.laneNone}>—</span>
                  )}
                </span>
              </li>
            );
          })}
        </ol>
      </div>
      <figcaption className={styles.caption}>
        {proven && column && contexa
          ? t('ux.intro.value.caption', {
              run: column.runId,
              case: column.caseKey,
              verdict: t(UX_VERDICTS[contexa as keyof typeof UX_VERDICTS].labelKey),
            })
          : t('ux.intro.value.captionPlain')}
        {/* The one run's result with how often it came back, so the figure never stands for more than it is (DEC-83). */}
        {proven && repeats
          ? ` ${t('ux.intro.value.repeats', { runs: n(repeats.runs), same: n(repeats.same) })}`
          : null}
      </figcaption>
    </figure>
  );
}
