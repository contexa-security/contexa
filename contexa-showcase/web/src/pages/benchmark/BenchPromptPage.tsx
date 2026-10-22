import { useTranslation } from 'react-i18next';
import type { BenchmarkRate } from '../../api/benchmark';
import {
  notPublished,
  promptQualityRawHref,
  usePromptQuality,
  type PromptQualityView,
} from '../../api/promptQuality';
import { ActionChip } from '../../components/common/ActionChip';
import { Modal } from '../../components/common/Modal';
import { useUrlModal } from '../../components/common/useUrlModal';
import { StateScreen } from '../../components/StateScreen';
import { utcTime } from '../../journey/format';
import { BenchScreen, BenchSource, RateRange } from './BenchScreen';
import { fraction, percent, useBenchSetting } from './benchPlace';
import benchStyles from './Bench.module.css';
import styles from './BenchPrompt.module.css';

/** The window of how the record was made, in the address (?modal=prompt-method). */
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

/** U6-4: the earlier record against this one (attacks reacted to, normal work asked to verify). */
function ComparisonLine({ comparison }: { readonly comparison: Comparison }) {
  const { t } = useTranslation();
  const counted = (rate: BenchmarkRate | null) => (rate ? fraction(rate) : '-');
  return (
    <p className={styles.comparison} data-comparison>
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

const ROWS = [
  'delivery',
  'reaction',
  'invariance',
  'injection',
  'accuracy',
  'reasonMatch',
  'consistency',
] as const;
type RowName = (typeof ROWS)[number];

interface Row {
  readonly name: RowName;
  readonly value: string;
  /** The line that names the value's denominator, where the value does not show it. */
  readonly sample: string | null;
  /** The rate whose range of variation the row shows. */
  readonly rate: BenchmarkRate;
}

/**
 * The text sent to the AI (화면재편-구현계획 RO-3, a table view; U-6, C-23): can it be trusted? One table of the seven
 * values of the published record, each with what it checks, its sample and its range of variation (95% interval), and
 * "few runs yet" where the server says the sample is small; the earlier record against this one under it. Before an
 * operator publishes a record the server answers 404 and the view says there is nothing to show yet. How each value is
 * made and the whole record to download are in the window the source line opens.
 */
export default function BenchPromptPage() {
  const { t } = useTranslation();
  const { setting } = useBenchSetting();
  const quality = usePromptQuality(setting);
  const method = useUrlModal(METHOD_MODAL);
  const view = quality.data ?? null;
  const missing = quality.isError && notPublished(quality.error);
  const sample = (rate: BenchmarkRate) => t('bench.r7.prompt.sample', { n: fraction(rate) });
  const rows: readonly Row[] = view
    ? [
        { name: 'delivery', value: fraction(view.delivery), sample: null, rate: view.delivery },
        {
          name: 'reaction',
          value: percent(view.reaction.direction.rate),
          sample: sample(view.reaction.direction),
          rate: view.reaction.direction,
        },
        {
          name: 'invariance',
          value: t('bench.r7.prompt.invariance.value', { n: view.invariance.decisionChanges }),
          sample: t('bench.r7.prompt.unchanged', { n: fraction(view.invariance.firstStepFacts) }),
          rate: view.invariance.firstStepFacts,
        },
        {
          name: 'injection',
          value: t('bench.r7.prompt.injection.value', {
            n: view.injection.changed,
            total: view.injection.unchanged.total,
          }),
          sample: t('bench.r7.prompt.unchanged', { n: fraction(view.injection.unchanged) }),
          rate: view.injection.unchanged,
        },
        ...(['accuracy', 'reasonMatch', 'consistency'] as const).map((name) => ({
          name,
          value: percent(view[name].rate),
          sample: sample(view[name]),
          rate: view[name],
        })),
      ]
    : [];
  return (
    <BenchScreen
      view="prompt"
      type="table"
      title={t('bench.r7.prompt.title')}
      purpose={t('bench.r7.prompt.guide')}
      sourceLine={
        view ? (
          <BenchSource
            text={t('bench.r7.prompt.source', { date: utcTime(view.measuredAt).slice(0, 10) })}
            onOpen={() => method.show()}
          />
        ) : null
      }
      windows={
        <Modal open={method.open} onClose={method.hide} title={t('bench.r7.method.title')} wide>
          {view ? <MethodWindow view={view} /> : null}
        </Modal>
      }
    >
      {quality.isPending ? <StateScreen kind="loading" /> : null}
      {missing ? (
        <p className={benchStyles.line} data-state="not-measured">
          {t('bench.r7.prompt.notMeasured')}
        </p>
      ) : null}
      {quality.isError && !missing ? (
        <StateScreen kind="error" onRetry={() => void quality.refetch()} />
      ) : null}
      {view ? (
        <>
          {/* Sideways on phones: the region scrolls inside and is reached by the keyboard (axe). */}
          <div
            className={benchStyles.tableScroll}
            role="region"
            aria-label={t('bench.r7.prompt.caption')}
            tabIndex={0}
          >
            <table className={styles.table}>
              <caption className={benchStyles.caption}>{t('bench.r7.prompt.caption')}</caption>
              <thead>
                <tr>
                  <th scope="col">{t('bench.r7.prompt.column.name')}</th>
                  <th scope="col">{t('bench.r7.prompt.column.value')}</th>
                  <th scope="col">{t('bench.r7.prompt.column.what')}</th>
                  <th scope="col">{t('bench.r7.prompt.column.range')}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.name} data-row={row.name}>
                    <th scope="row">{t(`bench.r7.prompt.row.${row.name}`)}</th>
                    <td className={styles.value}>{row.value}</td>
                    <td>{t(`bench.r7.prompt.row.${row.name}.what`)}</td>
                    <td className={styles.range}>
                      {row.sample ? `${row.sample} · ` : ''}
                      <RateRange rate={row.rate} label={false} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {view.comparison ? <ComparisonLine comparison={view.comparison} /> : null}
        </>
      ) : null}
    </BenchScreen>
  );
}

/** How the record was made: what each value means, the values made with them, the record and its download. */
function MethodWindow({ view }: { readonly view: PromptQualityView }) {
  const { t } = useTranslation();
  const extra: readonly (readonly [string, BenchmarkRate])[] = [
    ['minimumKept', view.reaction.minimumKept],
    ['reactionConsistency', view.reaction.consistency],
    ['decisions', view.invariance.decisions],
  ];
  return (
    <div className={benchStyles.window}>
      <section className={benchStyles.windowPart} aria-labelledby="prompt-method-metrics">
        <h3 id="prompt-method-metrics" className={benchStyles.windowTitle}>
          {t('bench.r7.prompt.method.metrics')}
        </h3>
        <ul className={benchStyles.plainList}>
          {ROWS.map((name) => (
            <li key={name}>{t(`bench.r7.prompt.method.${name}`)}</li>
          ))}
        </ul>
        <p className={benchStyles.windowText}>{t('bench.r7.method.interval')}</p>
      </section>
      <section className={benchStyles.windowPart} aria-labelledby="prompt-method-extra">
        <h3 id="prompt-method-extra" className={benchStyles.windowTitle}>
          {t('bench.r7.prompt.method.extra')}
        </h3>
        <ul className={benchStyles.plainList}>
          {extra.map(([name, rate]) => (
            <li key={name}>
              {t(`bench.r7.prompt.method.${name}`, { value: fraction(rate) })} · <RateRange rate={rate} />
            </li>
          ))}
        </ul>
      </section>
      <section className={benchStyles.windowPart} aria-labelledby="prompt-method-record">
        <h3 id="prompt-method-record" className={benchStyles.windowTitle}>
          {t('bench.r7.prompt.method.record')}
        </h3>
        <p className={styles.codes}>
          {batchesOf(view).map((batch) => (
            <code key={batch} data-original>
              {batch}
            </code>
          ))}
          <code data-original>{view.protocol ?? '-'}</code>
          <code data-original>{(view.setting ?? '-').slice(0, 12)}</code>
          <span>{t('bench.r7.prompt.recordedAt', { date: utcTime(view.measuredAt) })}</span>
        </p>
      </section>
      <div className={benchStyles.windowActions}>
        <ActionChip
          download={{ href: promptQualityRawHref(view.setting), name: 'contexa-prompt-quality.json' }}
          icon="download"
          variant="open"
        >
          {t('bench.r7.raw')}
        </ActionChip>
      </div>
    </div>
  );
}
