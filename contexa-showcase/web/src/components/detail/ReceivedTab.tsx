import { useTranslation } from 'react-i18next';
import { useReceived, type BeforeSendView, type DecisionAnatomyView } from '../../api/anatomy';
import { COMPARED, membership } from '../../pages/try/experience';
import { Comparison } from '../inside/Comparison';
import { StateScreen } from '../StateScreen';
import { analysed } from './detailWords';
import { TabFrame, type TabProps } from './TabFrame';
import styles from './DecisionDetail.module.css';

/** The compact comparison (screen 1-1's table) shows this many differing items; the rest are named below it. */
const SHOWN = 4;

type State = 'same' | 'different' | 'unknown';

/**
 * Each compared item's state as the engine labelled it, in the comparison's order; the browser, the system and the
 * device are one item, as the comparison draws them. Only the engine's own labels are read.
 */
function states(comparison: BeforeSendView): readonly { readonly name: string; readonly state: State }[] {
  return COMPARED.flatMap((dimension) => {
    const rows = (dimension === 'device' ? ['operatingSystem', 'browser', 'device'] : [dimension])
      .map((key) => comparison.usualVsNow.find((candidate) => candidate.dimension === key))
      .filter((row) => row !== undefined);
    if (rows.length === 0) {
      return [];
    }
    const all = rows.map((row) => membership(row.inUsual));
    const state: State = all.includes('different')
      ? 'different'
      : all.includes('unknown')
        ? 'unknown'
        : 'same';
    return [{ name: dimension, state }];
  });
}

/**
 * What Contexa received (RO-1): this request against the person's usual pattern, in screen 1-1's table (the differing
 * items, usual then this time, and what the company work records flag), then the items it did not show there named in
 * one line each: other differences, the items seen before in the usual pattern (the engine counts a value seen even
 * once as usual, V-62) and those it could not compare, and a missing approval the policy does not ask for (R-07).
 * Every value is the engine's input as recorded for this request; the full text is the original record's.
 */
export function ReceivedTab({ view, runId, step }: TabProps & { readonly view: DecisionAnatomyView }) {
  const { t } = useTranslation();
  const received = useReceived(analysed(view) ? runId : null, step);
  if (!analysed(view)) {
    return (
      <TabFrame>
        <p className={styles.line}>{t('detail.r7.notAnalysedTab')}</p>
      </TabFrame>
    );
  }
  if (received.isPending) {
    return <StateScreen kind="loading" />;
  }
  const comparison = received.data ?? null;
  if (!comparison) {
    return (
      <TabFrame>
        <p className={styles.line}>{t('detail.r7.received.none')}</p>
      </TabFrame>
    );
  }
  const items = states(comparison);
  const names = (state: State, from = 0) =>
    items
      .filter((item) => item.state === state)
      .slice(from)
      .map((item) => t(`dim.${item.name}`))
      .join(' · ');
  const moreDifferent = names('different', SHOWN);
  const same = names('same');
  const unknown = names('unknown');
  // R-07: the business records hold no approval, yet the engine read the company policy as needing none for this
  // request, so nothing was flagged; screens that list the record itself show "no approval".
  const approvalNotRequired =
    comparison.company['approvalRequired'] === false &&
    comparison.businessFacts.some((fact) => fact.code === 'NO_APPROVAL');
  return (
    <TabFrame source={t('detail.r7.received.source')}>
      {/* L-27: the comparison takes the tab's width, as the other tabs' tables do. */}
      <div className={styles.fill}>
        <Comparison comparison={comparison} level="h3" compact />
      </div>
      {moreDifferent || same || unknown || approvalNotRequired ? (
        <ul className={styles.list}>
          {moreDifferent ? <li>{t('detail.r7.received.moreDifferent', { names: moreDifferent })}</li> : null}
          {same ? <li>{t('detail.r7.received.same', { names: same })}</li> : null}
          {unknown ? <li>{t('detail.r7.received.unknown', { names: unknown })}</li> : null}
          {approvalNotRequired ? <li>{t('detail.r7.received.approvalNotRequired')}</li> : null}
        </ul>
      ) : null}
    </TabFrame>
  );
}
