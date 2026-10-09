import type { ReactNode } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { useBenchmark } from '../../api/benchmark';
import { usePublicSettings } from '../../api/settings';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { NextLink } from '../../components/journey/StepParts';
import { count, dollars, seconds } from '../../journey/format';
import { useJourneyPlace } from '../../journey/useJourneyPlace';
import styles from './AdoptChangePage.module.css';

/** The eight things that change when a system adopts Contexa, in the design's order (adopt-change). */
const CELLS = ['code', 'flow', 'time', 'cost', 'data', 'employee', 'admin', 'start'] as const;
type Cell = (typeof CELLS)[number];

/**
 * What changes when you adopt it (adopt-change, 7.4): eight cells, from the code to how to start. The time and the cost
 * are the benchmark's measurement, the retention periods are the running settings, the employee line is Contexa's
 * normal-work record; the rest is what the library does. The default route ends here and goes on to the install steps.
 */
export default function AdoptChangePage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const place = useJourneyPlace();
  const benchmark = useBenchmark(null);
  const settings = usePublicSettings().data ?? null;
  const engine = benchmark.data?.engine ?? null;
  const contexa = benchmark.data?.controls.find((entry) => entry.control === 'D') ?? null;
  const time = (ms: number | null | undefined) => (typeof ms === 'number' ? seconds(ms) : '-');
  const values: Readonly<Record<Cell, ReactNode>> = {
    code: (
      <Trans
        i18nKey="adoptChange.value.code"
        components={{ code: <code className={styles.inline} data-original /> }}
      />
    ),
    flow: t('adoptChange.value.flow'),
    time: t('adoptChange.value.time', { p50: time(engine?.analysisP50Ms), p95: time(engine?.analysisP95Ms) }),
    cost:
      engine && engine.costPerDecisionUsd !== null
        ? t('adoptChange.value.cost', {
            usd: dollars(engine.costPerDecisionUsd),
            tokens:
              engine.tokensPerDecision === null ? '-' : count(Math.round(engine.tokensPerDecision), language),
          })
        : t('adoptChange.value.costNone'),
    data:
      settings?.retention.behaviorDays !== null && settings?.retention.behaviorDays !== undefined
        ? t('adoptChange.value.data', {
            behavior: count(settings.retention.behaviorDays, language),
            prompt: count(settings.retention.promptOriginalDays, language),
          })
        : t('adoptChange.value.dataNoBehavior', {
            prompt: settings ? count(settings.retention.promptOriginalDays, language) : '-',
          }),
    employee: contexa
      ? t('adoptChange.value.employee', {
          normal: count(contexa.falseBlock.total, language),
          blocked: count(contexa.falseBlock.hits, language),
          checked: count(contexa.friction.hits, language),
        })
      : '-',
    admin: t('adoptChange.value.admin'),
    start: t('adoptChange.value.start'),
  };
  const mode = settings?.engine.effectiveMode ?? null;
  const intro = place.route === 'INTRO';
  return (
    <RouteScreen
      title={t('adoptChange.title')}
      purpose={t('adoptChange.purpose')}
      source={
        <SourceMark kind="MEASUREMENT" measured>
          {t('adoptChange.source', { setting: benchmark.data?.spec?.settingHash.slice(0, 8) ?? '-' })}
        </SourceMark>
      }
      more={
        intro ? (
          <ActionChip to="/adopt" icon="code" variant="open">
            {t('adoptChange.main')}
          </ActionChip>
        ) : null
      }
      main={intro ? undefined : <NextLink to="/adopt" label={t('adoptChange.main')} />}
    >
      <dl className={styles.cells} aria-label={t('adoptChange.title')}>
        {CELLS.map((cell) => (
          <div key={cell} className={styles.cell} data-cell={cell}>
            <dt className={styles.name}>{t(`adoptChange.name.${cell}`)}</dt>
            <dd className={styles.value}>
              <span>{values[cell]}</span>
              {cell === 'start' && mode ? (
                <span className={styles.mode}>
                  {t('adoptChange.mode', { mode: t(`adoptChange.modeName.${mode}`, { defaultValue: mode }) })}
                </span>
              ) : null}
            </dd>
          </div>
        ))}
      </dl>
    </RouteScreen>
  );
}
