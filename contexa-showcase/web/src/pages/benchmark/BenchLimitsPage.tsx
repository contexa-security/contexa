import { useTranslation } from 'react-i18next';
import { useCases } from '../../api/anatomy';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { useDetail } from '../../components/detail/useDetail';
import { NextLink } from '../../components/journey/StepParts';
import { count } from '../../journey/format';
import experience from '../try/Experience.module.css';
import { BenchScreen } from './BenchScreen';
import { useBenchView } from './benchData';
import { fraction, useBenchSetting } from './benchPlace';
import styles from './Bench.module.css';

/**
 * B4, the limits (honest, 7.8): the attack cases Contexa let through in every measured run, each with its designed
 * reason and its decision details; Contexa's three numbers that show the limit (stopped from the start, stopped at
 * some step, items out before a decision); why the first is low, from the judgment-and-timing count; and the two
 * limits of the explanations. The main button leads to the lab, to change a condition and try.
 */
export default function BenchLimitsPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const { search } = useBenchSetting();
  const detail = useDetail();
  const catalog = useCases().data ?? null;
  const { view, empty, state } = useBenchView();
  const contexa = view?.controls.find((score) => score.control === 'D') ?? null;
  const repeat = view?.scope.protocols.map((protocol) => protocol.repeat).join(', ') ?? '-';
  const missed = (view?.missedEveryRunCases ?? [])
    .map((key) => view?.cases.find((row) => row.key === key))
    .filter((row) => row !== undefined);
  return (
    <BenchScreen
      view="limits"
      title={
        view
          ? missed.length > 0
            ? t('benchmark.limits.title', { repeat, n: view.missedEveryRunCases.length })
            : t('benchmark.limits.titleNone', { repeat })
          : t('benchmark.limits.titleLoading')
      }
      purpose={t('benchmark.limits.purpose')}
      source={
        view ? (
          <SourceMark kind="MEASUREMENT" measured>
            {t('benchmark.judgment.source', {
              protocol: view.scope.protocols.map((protocol) => protocol.protocolId).join(', '),
            })}
          </SourceMark>
        ) : null
      }
      back={{ to: `/benchmark/judgment${search}`, label: t('benchmark.toJudgment') }}
      main={<NextLink to="/lab" label={t('benchmark.limits.toLab')} />}
    >
      {state}
      {empty ? <p className={experience.lead}>{t('bench.empty')}</p> : null}
      {view && contexa ? (
        <>
          {missed.length > 0 ? (
            <ul className={styles.cards}>
              {missed.map((row) => {
                const definition = catalog?.cases.find((candidate) => candidate.key === row.key) ?? null;
                const first = row.runIds[0] ?? null;
                return (
                  <li key={row.key} className={styles.card}>
                    <h2 className={styles.cardTitle}>{row.title[language] ?? row.key}</h2>
                    {definition?.rationale[language] ? (
                      <p className={styles.cardText}>{definition.rationale[language]}</p>
                    ) : null}
                    <p className={styles.cardCount}>{t('benchmark.limits.missed', { runs: row.runs })}</p>
                    {first ? (
                      <ActionChip onClick={() => detail.show(first)} icon="search" variant="open" size="sm">
                        {t('e1.result.detail')}
                      </ActionChip>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          ) : null}
          <dl className={styles.bigNumbers}>
            <div>
              <dt>{t('benchmark.limits.stopped')}</dt>
              <dd>{fraction(contexa.stopped)}</dd>
            </div>
            <div>
              <dt>{t('benchmark.limits.stoppedAny')}</dt>
              <dd>{fraction(contexa.stoppedAny)}</dd>
            </div>
            <div>
              <dt>{t('benchmark.limits.exposed')}</dt>
              <dd>{t('e1.result.items', { items: count(contexa.exposedItems, language) })}</dd>
            </div>
          </dl>
          <p className={styles.callout}>
            {t('benchmark.limits.why', {
              timing: view.judgmentTiming.NEXT_REQUEST,
              judged: view.judgmentTiming.JUDGED_ALLOW,
            })}
          </p>
          <section className={styles.windowPart} aria-labelledby="limits-explain">
            <h2 id="limits-explain" className={experience.panelTitle}>
              {t('benchmark.limits.explainTitle')}
            </h2>
            <ul className={styles.plainList}>
              <li>{t('benchmark.limits.explain.approval')}</li>
              <li>{t('benchmark.limits.explain.inspector')}</li>
            </ul>
          </section>
        </>
      ) : null}
    </BenchScreen>
  );
}
