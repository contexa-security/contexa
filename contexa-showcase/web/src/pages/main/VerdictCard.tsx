import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { DecisionAnatomyView } from '../../api/anatomy';
import type { PromptFact, RunFacts } from '../../api/promptQuality';
import type { ReasonCode } from '../../api/types';
import { Icon } from '../../components/Icon';
import { reasonCodeKey } from '../../components/facts/reasonMeaning';
import { Fold } from '../../components/main/Fold';
import { breakable } from './breakable';
import { factById } from './evidence';
import styles from './VerdictCard.module.css';

type Recorded = DecisionAnatomyView['interpretation']['recorded'];

/**
 * A cited line longer than this may not fit in two lines of its narrowest column, so it shows its first two lines and
 * offers the whole line (B-19: a line of 71 characters was cut without the link).
 */
const LONG_LINE = 48;

/** The verdicts a card colours, by the engine's action. */
const TONE: Readonly<Record<string, string>> = {
  ALLOW: 'allow',
  CHALLENGE: 'auth',
  ESCALATE: 'block',
  BLOCK: 'block',
};

/**
 * EV-3, the LLM's structured answer as a card (최종화면-구현계획 5차, 사용자 지시: LLM 구조화 출력은 임팩트 있게):
 * the verdict it chose, its risk score and confidence as gauges, each marked when the model wrote it, and the reason
 * it wrote in its own words. Every value is the run's stored record.
 */
export function VerdictHero({
  recorded,
  compact = false,
}: {
  readonly recorded: Recorded;
  /**
   * The first layers of a screen (구현계획 AC-N2): the model's own words are long, so they wait behind their label, and
   * "applied as proposed" is left unsaid (a change of the verdict is still said).
   */
  readonly compact?: boolean;
}) {
  const { t } = useTranslation();
  const action = recorded.finalAction ?? recorded.proposedAction;
  const provenance = recorded.fieldProvenance ?? {};
  const changed =
    recorded.proposedAction !== null &&
    recorded.finalAction !== null &&
    recorded.proposedAction !== recorded.finalAction;
  return (
    <section
      className={styles.hero}
      aria-labelledby="verdict-hero"
      data-tone={action ? TONE[action] : undefined}
    >
      <div className={styles.decision}>
        <h2 id="verdict-hero" className={compact ? 'visually-hidden' : styles.label}>
          {t('main.verdictCard.label')}
        </h2>
        <p className={styles.action}>{action ? t(`main.verdict.${action}`) : t('main.verdict.failed')}</p>
        <p className={styles.actionMeta}>
          {compact ? null : <code>{action ?? '—'}</code>}
          {changed || !compact ? (
            <span>
              {changed
                ? t('main.verdictCard.changed', {
                    proposed: t(`main.verdict.${recorded.proposedAction ?? ''}`),
                  })
                : t('main.verdictCard.same')}
            </span>
          ) : null}
        </p>
      </div>
      <Gauge
        label={t('main.verdictCard.risk')}
        value={recorded.riskScore}
        kind="risk"
        source={provenance['riskScore'] ?? null}
        compact={compact}
      />
      <Gauge
        label={t('main.verdictCard.confidence')}
        value={recorded.confidence}
        kind="confidence"
        source={provenance['confidence'] ?? null}
        compact={compact}
      />
      {recorded.reasoning ? (
        compact ? (
          <div className={styles.reasonFold}>
            <Fold name="reason" summary={t('main.verdictCard.reason')}>
              <blockquote className={styles.reason}>
                <q className={styles.reasonText}>{recorded.reasoning}</q>
              </blockquote>
            </Fold>
          </div>
        ) : (
          <blockquote className={styles.reason}>
            <span className={styles.reasonLabel}>{t('main.verdictCard.reason')}</span>
            <q className={styles.reasonText}>{recorded.reasoning}</q>
          </blockquote>
        )
      ) : null}
    </section>
  );
}

/** A score between 0 and 1 as a gauge, with where it came from. */
function Gauge({
  label,
  value,
  kind,
  source,
  compact,
}: {
  readonly label: string;
  readonly value: number | null;
  readonly kind: 'risk' | 'confidence';
  readonly source: string | null;
  /** The first layers say only what the model did not write; what it wrote is named once, by the label above. */
  readonly compact: boolean;
}) {
  const { t } = useTranslation();
  return (
    <div className={styles.gauge}>
      <span className={styles.label}>{label}</span>
      <b className={styles.gaugeValue}>{value === null ? t('main.verdictCard.none') : value.toFixed(2)}</b>
      <span className={styles.gaugeTrack} data-kind={kind}>
        {value === null ? null : (
          <span className={styles.gaugeMark} style={{ insetInlineStart: `${value * 100}%` }} />
        )}
      </span>
      <span className={styles.gaugeScale} aria-hidden="true">
        <span>0</span>
        <span>1</span>
      </span>
      {source && !(compact && source === 'MODEL') ? (
        <span className={styles.source} data-model={source === 'MODEL' || undefined}>
          {t(source === 'MODEL' ? 'main.verdictCard.fromModel' : 'main.verdictCard.notModel')}
        </span>
      ) : null}
    </div>
  );
}

/**
 * The chain from the facts to the verdict: each prompt line the model cited, once, beside the reason codes it gave for
 * that line in plain words, all leading to the verdict. A long line shows its start and opens whole on a press.
 */
export function ReasonChain({
  codes,
  facts,
  action,
}: {
  readonly codes: readonly ReasonCode[];
  readonly facts: RunFacts | null;
  readonly action: string | null;
}) {
  const { t } = useTranslation();
  // One row per cited line, in the order the model first cited it.
  const rows: { readonly fact: string | null; readonly codes: ReasonCode[] }[] = [];
  for (const code of codes) {
    const row = rows.find((candidate) => candidate.fact === code.fact);
    if (row) {
      row.codes.push(code);
    } else {
      rows.push({ fact: code.fact, codes: [code] });
    }
  }
  return (
    <section className={styles.chain} aria-labelledby="chain-title">
      <h2 id="chain-title" className={styles.chainTitle}>
        {t('main.verdictCard.chainTitle')}
      </h2>
      <p className={styles.chainHead} aria-hidden="true">
        <span>{t('main.verdictCard.fact')}</span>
        <span />
        <span>{t('main.verdictCard.code')}</span>
      </p>
      <ol className={styles.links}>
        {rows.map((row) => (
          <ChainRow
            key={row.fact ?? 'none'}
            fact={row.fact ? factById(facts, row.fact) : null}
            codes={row.codes}
          />
        ))}
      </ol>
      <p className={styles.chainEnd} data-tone={action ? TONE[action] : undefined}>
        <Icon name="arrowRight" className={styles.linkArrow} />
        <span>{t('main.verdictCard.leadsTo')}</span>
        <b>{action ? t(`main.verdict.${action}`) : t('main.verdict.failed')}</b>
      </p>
    </section>
  );
}

/** One cited prompt line and the reason codes the model gave for it. */
function ChainRow({
  fact,
  codes,
}: {
  readonly fact: PromptFact | null;
  readonly codes: readonly ReasonCode[];
}) {
  const { t } = useTranslation();
  const [whole, setWhole] = useState(false);
  return (
    <li className={styles.link}>
      <span className={styles.fact}>
        {fact ? (
          <>
            <b className={styles.factName}>
              {fact.factId ? `${fact.factId} · ` : ''}
              {t(`fact.label.${fact.label}`, { defaultValue: fact.label })}
            </b>
            <code className={styles.factValue} data-whole={whole || undefined}>
              {fact.value}
            </code>
            {fact.value.length > LONG_LINE ? (
              <button type="button" className={styles.factMore} onClick={() => setWhole(!whole)}>
                {t(whole ? 'main.verdictCard.less' : 'main.verdictCard.more')}
              </button>
            ) : null}
          </>
        ) : (
          <span className={styles.factValue}>{t('main.3-3.citesNone')}</span>
        )}
      </span>
      <Icon name="arrowRight" className={styles.linkArrow} />
      <ul className={styles.codes}>
        {codes.map((code) => {
          const plain = t(reasonCodeKey(code), { defaultValue: '' });
          return (
            <li key={code.code} className={styles.code}>
              <b className={styles.codePlain}>{plain || breakable(code.code)}</b>
              {plain ? (
                <span className={styles.codeName} data-original>
                  <span className={styles.codeTag}>{t('main.verdictCard.codeOriginal')}</span>{' '}
                  <code>{breakable(code.code)}</code>
                </span>
              ) : null}
            </li>
          );
        })}
      </ul>
    </li>
  );
}
