import { useTranslation } from 'react-i18next';
import type { BenchmarkRate } from '../../api/benchmark';
import {
  notPublished,
  promptQualityRawHref,
  usePromptQuality,
  type PromptQualityView,
} from '../../api/promptQuality';
import { ActionChip } from '../../components/common/ActionChip';
import { Term } from '../../components/common/Glossary';
import type { GlossaryTerm } from '../../components/common/glossaryTerms';
import { Modal } from '../../components/common/Modal';
import { SourceMark } from '../../components/common/SourceMark';
import { useUrlModal } from '../../components/common/useUrlModal';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { utcTime } from '../../journey/format';
import experience from '../try/Experience.module.css';
import { BenchScreen } from './BenchScreen';
import { fraction, percent, useBenchSetting } from './benchPlace';
import styles from './BenchPrompt.module.css';

/** The prompt-quality window's name in the address (?modal=prompt-method). */
const METHOD_MODAL = 'prompt-method';

/** N-PQ-1: the batches a view's numbers come from, one when every number comes from the same batch. */
function batchesOf(view: PromptQualityView): readonly string[] {
  if (view.batch === null && view.batches) {
    return [...new Set([view.batches.delivery, view.batches.reaction, view.batches.injection])];
  }
  return [view.batch ?? '-'];
}

/** A bundle's version as the line names it ('2026.10.16-v20.24' is 'v20.24'). */
function shortBundle(bundle: string | null): string {
  return bundle ? bundle.slice(bundle.lastIndexOf('-') + 1) : '-';
}

type Comparison = NonNullable<PromptQualityView['comparison']>;

/** U6-4: the earlier measurement against this one by run (A1 attacks reacted, A2 normal work verified). */
function ComparisonLine({ comparison }: { readonly comparison: Comparison }) {
  const { t } = useTranslation();
  const counted = (rate: BenchmarkRate | null) => (rate ? fraction(rate) : '-');
  return (
    <p className={styles.measured} data-comparison>
      {t('promptQuality.comparison', {
        before: shortBundle(comparison.baselineBundle),
        now: shortBundle(comparison.bundle),
        attackBefore: counted(comparison.attackBefore),
        attackNow: counted(comparison.attackNow),
        normalBefore: counted(comparison.normalBefore),
        normalNow: counted(comparison.normalNow),
      })}
    </p>
  );
}

type CardName = 'delivery' | 'reaction' | 'invariance' | 'injection';
const CARD_TERMS: Readonly<Record<CardName, GlossaryTerm>> = {
  delivery: 'delivery',
  reaction: 'reaction',
  invariance: 'invariance',
  injection: 'injection',
};
type MoreName = 'accuracy' | 'reasonMatch' | 'consistency';
const MORE: readonly MoreName[] = ['accuracy', 'reasonMatch', 'consistency'];

/** A rate's 95% interval and, for a small sample, the preliminary mark, as every benchmark view writes them. */
function Interval({ rate }: { readonly rate: BenchmarkRate }) {
  const { t } = useTranslation();
  return (
    <>
      {t('benchmark.interval', { low: percent(rate.low), high: percent(rate.high) })}
      {rate.preliminary ? ` · ${t('benchmark.preliminary')}` : ''}
    </>
  );
}

/**
 * B1-3, prompt quality (bench-prompt, U-6): can the AI's input be trusted? Four big numbers of the published batch,
 * delivery, reaction, invariance and injection defence, then fact accuracy, reasons matching facts and repeat
 * consistency, each with its sample and 95% interval and the measured date (C-23); "preliminary" where the server
 * says the sample is small. Before an operator publishes a batch the server answers 404 and the view says nothing is
 * measured yet. How each number is measured is in its window, and the published record (every number
 * with its counts) downloads as the raw data (N-UI-1, U6-5). On phones the four cards slide sideways.
 */
export default function BenchPromptPage() {
  const { t } = useTranslation();
  const { setting, search } = useBenchSetting();
  const quality = usePromptQuality(setting);
  const method = useUrlModal(METHOD_MODAL);
  const view = quality.data ?? null;
  const missing = quality.isError && notPublished(quality.error);
  // Each card's big number, the sub line that names its denominator, and the rate whose interval it shows.
  const cards: readonly {
    readonly name: CardName;
    readonly value: string;
    readonly sample: string | null;
    readonly rate: BenchmarkRate;
  }[] = view
    ? [
        { name: 'delivery', value: fraction(view.delivery), sample: null, rate: view.delivery },
        {
          name: 'reaction',
          value: percent(view.reaction.direction.rate),
          sample: t('promptQuality.sample', { n: fraction(view.reaction.direction) }),
          rate: view.reaction.direction,
        },
        {
          name: 'invariance',
          value: t('promptQuality.card.invariance.value', { n: view.invariance.decisionChanges }),
          sample: t('promptQuality.unchanged', { n: fraction(view.invariance.firstStepFacts) }),
          rate: view.invariance.firstStepFacts,
        },
        {
          name: 'injection',
          value: t('promptQuality.card.injection.value', {
            n: view.injection.changed,
            total: view.injection.unchanged.total,
          }),
          sample: t('promptQuality.unchanged', { n: fraction(view.injection.unchanged) }),
          rate: view.injection.unchanged,
        },
      ]
    : [];
  return (
    <BenchScreen
      view="prompt"
      title={t('promptQuality.title')}
      purpose={t('promptQuality.purpose')}
      source={
        view ? (
          <SourceMark kind="MEASUREMENT" measured recordedAt={view.measuredAt}>
            {view.batch === null && view.batches
              ? t('promptQuality.sources', { ...view.batches, protocol: view.protocol ?? '-' })
              : t('promptQuality.source', { batch: view.batch ?? '-', protocol: view.protocol ?? '-' })}
          </SourceMark>
        ) : null
      }
      more={
        view ? (
          <>
            <ActionChip icon="book" variant="open" onClick={() => method.show()}>
              {t('promptQuality.method')}
            </ActionChip>
            <ActionChip
              download={{ href: promptQualityRawHref(view.setting), name: 'contexa-prompt-quality.json' }}
              icon="download"
              variant="open"
            >
              {t('promptQuality.raw')}
            </ActionChip>
          </>
        ) : null
      }
      back={{ to: `/benchmark/judgment${search}`, label: t('benchmark.toJudgment') }}
      main={<NextLink to={`/benchmark/limits${search}`} label={t('benchmark.toLimits')} />}
    >
      {quality.isPending ? <StateScreen kind="loading" /> : null}
      {missing ? (
        <p className={experience.lead} data-state="not-measured">
          {t('promptQuality.notMeasured')}
        </p>
      ) : null}
      {quality.isError && !missing ? <StateScreen kind="error" onRetry={() => void quality.refetch()} /> : null}
      {view ? (
        <>
          <p className={styles.measured}>
            {t('promptQuality.measured', { date: utcTime(view.measuredAt).slice(0, 10) })}
          </p>
          {/* Sideways on phones: the region scrolls inside and is reached by the keyboard (axe). */}
          <div className={styles.cardsScroll} role="region" aria-label={t('promptQuality.cards')} tabIndex={0}>
            <dl className={styles.cards}>
              {cards.map((card) => (
                <div key={card.name} className={styles.card} data-card={card.name}>
                  <dt className={styles.cardName}>
                    <Term term={CARD_TERMS[card.name]}>{t(`promptQuality.card.${card.name}`)}</Term>
                  </dt>
                  <dd className={styles.cardValue}>{card.value}</dd>
                  <dd className={styles.cardWhat}>{t(`promptQuality.card.${card.name}.what`)}</dd>
                  <dd className={styles.cardNote}>
                    {card.sample ? `${card.sample} · ` : ''}
                    <Interval rate={card.rate} />
                  </dd>
                </div>
              ))}
            </dl>
          </div>
          <ul className={styles.more} aria-label={t('promptQuality.more')}>
            {MORE.map((name) => (
              <li key={name} data-more={name}>
                <span className={styles.moreName}>
                  {t(`promptQuality.more.${name}`, { rate: percent(view[name].rate) })}
                </span>
                <span className={styles.moreNote}>
                  {t('promptQuality.sample', { n: fraction(view[name]) })} · <Interval rate={view[name]} />
                </span>
              </li>
            ))}
          </ul>
          {view.comparison ? <ComparisonLine comparison={view.comparison} /> : null}
        </>
      ) : null}
      <Modal open={method.open} onClose={method.hide} title={t('promptQuality.method')} wide>
        {view ? <MethodWindow view={view} /> : null}
      </Modal>
    </BenchScreen>
  );
}

/** How it was measured: what each number means, the numbers measured with them, the interval, the record. */
function MethodWindow({ view }: { readonly view: PromptQualityView }) {
  const { t } = useTranslation();
  const extra: readonly (readonly [string, BenchmarkRate])[] = [
    ['minimumKept', view.reaction.minimumKept],
    ['reactionConsistency', view.reaction.consistency],
    ['decisions', view.invariance.decisions],
  ];
  return (
    <div className={styles.window}>
      <section aria-labelledby="prompt-method-metrics">
        <h3 id="prompt-method-metrics" className={experience.panelTitle}>
          {t('promptQuality.method.metrics')}
        </h3>
        <ul className={styles.plainList}>
          {(['delivery', 'reaction', 'invariance', 'injection', ...MORE] as const).map((name) => (
            <li key={name}>{t(`promptQuality.method.${name}`)}</li>
          ))}
        </ul>
        <p className={experience.lead}>{t('benchmark.method.interval')}</p>
      </section>
      <section aria-labelledby="prompt-method-extra">
        <h3 id="prompt-method-extra" className={experience.panelTitle}>
          {t('promptQuality.method.extra')}
        </h3>
        <ul className={styles.plainList}>
          {extra.map(([name, rate]) => (
            <li key={name}>
              {t(`promptQuality.method.${name}`, { value: fraction(rate) })} · <Interval rate={rate} />
            </li>
          ))}
        </ul>
      </section>
      <section aria-labelledby="prompt-method-record">
        <h3 id="prompt-method-record" className={experience.panelTitle}>
          {t('promptQuality.method.record')}
        </h3>
        <p className={styles.codes}>
          {batchesOf(view).map((batch) => (
            <code key={batch} data-original>
              {batch}
            </code>
          ))}
          <code data-original>{view.protocol ?? '-'}</code>
          <code data-original>{(view.setting ?? '-').slice(0, 12)}</code>
          <span>{t('promptQuality.measured', { date: utcTime(view.measuredAt) })}</span>
        </p>
      </section>
    </div>
  );
}
