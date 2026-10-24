import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useBenchmark } from '../../api/benchmark';
import { useJourney } from '../../api/journey';
import { useRunStepResults } from '../../api/lab';
import { usePromptQuality } from '../../api/promptQuality';
import { useVisitor } from '../../api/queries';
import { Chip } from '../../components/main/Chip';
import { MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { count } from '../../journey/format';
import { screenAt } from '../../journey/journey';
import { latestOwnRun } from './latestRun';
import { AGENT_CASE } from '../../api/agentCase';
import { MAIN_CASES } from './mainCases';
import styles from './SummaryPages.module.css';
import { useCountUp } from './useCountUp';

/**
 * The insider's results whose own sentence 8-1 has (V-40): stopped before, after some documents left, or not at all;
 * the business agent's run has the same three (docs/agent A7-3).
 */
const INSIDER_LINES: ReadonlySet<string> = new Set(['STOPPED', 'PARTLY_STOPPED', 'MISSED']);

/** A big number that counts up from 0 when it shows (설계서 모션 6-1: 0.9초). */
function Counted({
  value,
  total,
}: {
  readonly value: number | null;
  readonly total?: number | null | undefined;
}) {
  const { i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const shown = useCountUp(value, 900);
  if (shown === null) {
    return <>—</>;
  }
  return (
    <>
      {count(shown, language)}
      {total === undefined || total === null ? null : ` / ${count(total, language)}`}
    </>
  );
}

/**
 * 8-1, the three things confirmed (설계서 6-1): the visitor's calls against the judgments, then three cards, each
 * one number from its record with its source (the visitor's run, the repeated runs, the prompt-quality measurement)
 * and a way back to the screen that showed it. A card says its sentence only when its number makes it true. Under the
 * calls, the insider's run is named by what Contexa did with it, as the server scored it.
 */
export default function SummaryPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const benchmark = useBenchmark(null);
  const quality = usePromptQuality(null);
  const attack = latestOwnRun(journey.data?.runs, MAIN_CASES.attacker);
  // V-40: the insider's own run, named by what Contexa did with it over all its documents, as the server scored it.
  const insider = latestOwnRun(journey.data?.runs, MAIN_CASES.insider);
  const insiderResult = insider?.business['D'] ?? '';
  // docs/agent A7-3 (화면설계 4.5): the business agent's own run, named by what Contexa did with its requests.
  const agent = latestOwnRun(journey.data?.runs, AGENT_CASE);
  const agentResult = agent?.business['D'] ?? '';
  const [result] = useRunStepResults(attack?.runId ?? null, 1);
  const legacy = result?.layers.find((layer) => layer.control === 'B')?.evidence.deliveredItems ?? null;
  const contexa = benchmark.data?.controls.find((score) => score.control === 'D') ?? null;
  const fixed = benchmark.data?.controls.find((score) => score.control === 'C1') ?? null;
  const reason = quality.data?.reasonMatch ?? null;
  const predictions = (journey.data?.predictions ?? []).filter((score) => score.engineActual !== null);
  const cards = [
    {
      id: 'request',
      value: attack ? attack.exposedItems : null,
      total: undefined,
      unit: true,
      holds: attack !== null && attack.exposedItems === 0,
      line: attack
        ? t('main.8-1.request.line', { legacy: legacy === null ? '-' : count(legacy, language) })
        : t('main.8-1.request.none'),
      source: attack ? <SourceBadge kind="run" label={t('badge.run')} runId={attack.runId} /> : null,
      to: '/attack/console',
    },
    {
      id: 'normal',
      value: contexa ? contexa.falseBlock.hits : null,
      total: contexa ? contexa.falseBlock.total : null,
      unit: false,
      holds: contexa !== null && contexa.falseBlock.hits === 0,
      line: t('main.8-1.normal.line', {
        hits: fixed ? fixed.falseBlock.hits : '-',
        total: fixed ? fixed.falseBlock.total : '-',
      }),
      source: (
        <SourceBadge
          kind="repeated"
          label={t('main.8-1.repeated', { runs: benchmark.data?.scope.runs ?? '-' })}
        />
      ),
      to: '/compare/runs',
    },
    {
      id: 'record',
      value: reason ? reason.hits : null,
      total: reason ? reason.total : null,
      unit: false,
      holds: reason !== null && reason.total > 0 && reason.hits === reason.total,
      line: t('main.8-1.record.line'),
      source: <SourceBadge kind="repeated" label={t('main.8-1.quality')} />,
      to: '/evidence/map',
    },
  ] as const;
  return (
    <MainScreen
      title={t('main.8-1.title')}
      intro={
        <>
          {predictions.length > 0 ? (
            <span className={styles.calls}>
              {predictions.map((score) => (
                <Chip key={score.experience} kind={score.engineSameStop ? 'ok' : 'wait'}>
                  {t(`main.8-1.call.${score.engineSameStop ? 'right' : 'other'}`, {
                    what: t(`main.8-1.call.${score.experience}`),
                  })}
                </Chip>
              ))}
              <span className={styles.callNote}>{t('main.8-1.call.note')}</span>
            </span>
          ) : (
            t('main.8-1.noCalls')
          )}
          {insider && INSIDER_LINES.has(insiderResult) ? (
            <span className={styles.insider}>
              {t(`main.8-1.insider.${insiderResult}`, {
                n: count(insider.exposedItems, language),
                count: insider.exposedItems,
              })}
            </span>
          ) : null}
          {agent && INSIDER_LINES.has(agentResult) ? (
            <span className={styles.insider}>{t(`main.8-1.agent.${agentResult}`)}</span>
          ) : null}
        </>
      }
    >
      <ul className={styles.cards}>
        {cards.map((card) => (
          <li key={card.id} className={styles.card}>
            <b className={styles.cardTitle}>
              {t(`main.8-1.${card.id}.${card.holds ? 'title' : 'titlePlain'}`)}
            </b>
            <p className={styles.big} data-holds={card.holds || undefined}>
              <Counted value={card.value} total={card.total} />
              {card.unit && card.value !== null ? t('main.unit.items') : null}
            </p>
            <p className={styles.cardLine}>{card.line}</p>
            <div className={styles.cardFoot}>
              {card.source}
              <Link to={card.to} className={styles.back}>
                {t('main.8-1.back', { screen: screenAt('DEFAULT', card.to)?.number ?? '' })}
              </Link>
            </div>
          </li>
        ))}
      </ul>
    </MainScreen>
  );
}
