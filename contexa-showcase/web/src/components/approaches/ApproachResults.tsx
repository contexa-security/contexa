import { useTranslation } from 'react-i18next';
import type { Layer } from '../../api/types';
import { CONTROL_ORDER, OUTCOME_KEYS } from '../../domain/verdict';
import { VerdictChip } from '../VerdictChip';
import styles from './ApproachResults.module.css';

type Expectation = 'BLOCK' | 'PASS';

interface ApproachResultsProps {
  readonly layers: readonly Layer[];
  /**
   * What the visitor expected of each approach before sending (the lab); left out where the visitor made no such call
   * (a replay), so the row is not shown at all.
   */
  readonly expected?: Readonly<Partial<Record<string, Expectation>>>;
}

/**
 * The five approaches' results of one request, each as its stored record says (docs/showcase/데모-재설계.md 5A.1,
 * T-7): the response, what it did and why, and what it looked at. A rule control has no verdict of its own, so its
 * row states the rule and the HTTP status it recorded (H-08b); only Contexa's row carries the engine's decision.
 */
export function ApproachResults({ layers, expected }: ApproachResultsProps) {
  return (
    <ol className={styles.layers}>
      {CONTROL_ORDER.map((control) => {
        const layer = layers.find((candidate) => candidate.control === control);
        return layer ? (
          <LayerRow
            key={control}
            layer={layer}
            expected={expected === undefined ? undefined : (expected[control] ?? null)}
          />
        ) : null;
      })}
    </ol>
  );
}

function factText(value: unknown): string {
  if (value === null || value === undefined) {
    return '-';
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    for (const key of ['covered', 'onCall', 'assigned', 'owner', 'kind', 'days']) {
      if (key in record) {
        return `${key}=${String(record[key])}`;
      }
    }
    return '{…}';
  }
  return String(value);
}

/**
 * One approach's result of the step: what it looked at, what it did and why, as its stored record says, and what the
 * visitor expected of it when they called it. The WAF stands in front of the same application as the role check, so a
 * refusal it lets through is recorded with that application's rule; the row says so (H-08b, as approved with the W3
 * draft).
 */
function LayerRow({
  layer,
  expected,
}: {
  readonly layer: Layer;
  readonly expected: Expectation | null | undefined;
}) {
  const { t, i18n } = useTranslation();
  const evidence = layer.evidence;
  const facts = Object.entries(layer.ruleFacts ?? {});
  return (
    <li className={styles.layer} data-outcome={layer.outcome} data-control={layer.control}>
      <div className={styles.layerHead}>
        <span className={styles.approachName}>{t(`control.${layer.control}.name`)}</span>
        <span className={styles.outcome} data-outcome={layer.outcome}>
          {t(OUTCOME_KEYS[layer.outcome])}
        </span>
      </div>
      <dl className={styles.layerFacts}>
        <div>
          <dt>{t('lab.layer.http')}</dt>
          <dd className={styles.mono}>{layer.httpStatus ?? '-'}</dd>
        </div>
        <div>
          <dt>{t('lab.layer.response')}</dt>
          <dd className={styles.mono}>
            {evidence.responseMs === null ? '-' : t('anatomy.ms', { ms: evidence.responseMs })}
          </dd>
        </div>
        <div>
          <dt>{t('lab.layer.items')}</dt>
          <dd className={styles.mono}>{evidence.deliveredItems.toLocaleString(i18n.language)}</dd>
        </div>
        <div>
          <dt>{t('lab.layer.reason')}</dt>
          <dd>
            {layer.control === 'D' && layer.verdict ? (
              <VerdictChip verdict={layer.verdict} unresolved={evidence.unresolved} showCode />
            ) : (
              <span className={styles.mono}>{layer.ruleId ?? '-'}</span>
            )}
          </dd>
        </div>
        {expected === undefined ? null : (
          <div>
            <dt>{t('lab.layer.expected')}</dt>
            <dd>{expected ? t(`lab.expect.${expected}`) : t('lab.expect.none')}</dd>
          </div>
        )}
      </dl>
      <p className={styles.reason}>
        {layer.control === 'D'
          ? (evidence.engineReasoning ?? t('lab.layer.noReasoning'))
          : (layer.reason ?? '-')}
      </p>
      {layer.control === 'A' && layer.ruleId === 'RBAC' ? (
        <p className={styles.note}>{t('lab.layer.wafBehind')}</p>
      ) : null}
      {facts.length > 0 ? (
        <details className={styles.seen}>
          <summary>{t('lab.layer.seen', { n: facts.length })}</summary>
          <ul className={styles.seenList}>
            {facts.map(([key, value]) => (
              <li key={key} className={styles.mono}>
                {key}: {factText(value)}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </li>
  );
}
