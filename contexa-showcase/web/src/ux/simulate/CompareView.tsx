import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import {
  useAnatomy,
  useInputChanges,
  useReceived,
  type BeforeSendView,
  type DecisionAnatomyView,
  type InputChange,
} from '../../api/anatomy';
import { useLabOptions } from '../../api/lab';
import { useRunScore } from '../../api/queries';
import type { RunScore } from '../../api/types';
import { formatNumber } from '../format';
import {
  Badge,
  ButtonLink,
  CodeChip,
  EvalBadge,
  FlagBadge,
  Icon,
  Loading,
  Note,
  PageHead,
  VerdictBadge,
} from '../ui';
import {
  EXISTING,
  authWords,
  companyClock,
  contextChips,
  deviceWords,
  evalOf,
  flowPath,
  truthOf,
  verdictOf,
} from './person';
import { usePersonRuns } from './useFlow';
import styles from './Result.module.css';

interface Side {
  readonly key: 'S13' | 'S13T';
  readonly runId: string;
  readonly score: RunScore | undefined;
  readonly received: BeforeSendView | undefined;
  readonly anatomy: DecisionAnatomyView | undefined;
}

function useSide(key: 'S13' | 'S13T', runId: string): Side {
  const score = useRunScore(runId, 'compare', 1);
  const received = useReceived(runId, 1);
  const anatomy = useAnatomy(runId, 1);
  return { key, runId, score: score.data, received: received.data, anatomy: anatomy.data };
}

/**
 * "Same request, different decision" (기획안 7.0 d-compare, F-7): the compromised account's run and the account owner's
 * run of the same request side by side, the request facts the engine received row by row with the different ones
 * marked, what the existing controls did with both, and what the baseline learned from each. The sentence on the rule
 * controls appears only when the two scores make it true.
 */
export function CompareView({
  attackerRun,
  ownerRun,
}: {
  readonly attackerRun: string;
  readonly ownerRun: string;
}) {
  const { t, i18n } = useTranslation();
  const attacker = useSide('S13', attackerRun);
  const owner = useSide('S13T', ownerRun);
  // The portal's own comparison of what the engine received in the two runs (before: the attacker's, now: the owner's).
  const changes = useInputChanges(ownerRun, attackerRun, 1);
  const options = useLabOptions();
  const runs = usePersonRuns();
  const n = (value: number) => formatNumber(value, i18n.language);
  if (!attacker.score || !owner.score || !attacker.received || !owner.received) {
    return <Loading rows={6} />;
  }
  const employeeKey =
    options.data?.cases.find((labCase) => labCase.key === 'S13')?.conditions.employee ?? null;
  const name = employeeKey ? t(`ux.person.${employeeKey}`, { defaultValue: employeeKey }) : '—';
  const now = (view: BeforeSendView, dimension: string) =>
    view.usualVsNow.find((row) => row.dimension === dimension) ?? null;
  const network = (view: BeforeSendView) => {
    const fact = view.businessFacts.find((candidate) => candidate.code.startsWith('NETWORK_')) ?? null;
    const cidr = now(view, 'network')?.now ?? '';
    return [fact ? contextChips(t, [fact])[0] : null, cidr].filter(Boolean).join(' ');
  };
  const request = (anatomy: DecisionAnatomyView | undefined) => {
    const resource = anatomy?.context.resource as
      { readonly requestPath?: string | null; readonly requestedItems?: number | null } | null | undefined;
    return resource?.requestPath
      ? `${resource.requestPath}${resource.requestedItems != null ? ` · ${t('ux.facts.items', { count: resource.requestedItems, n: n(resource.requestedItems) })}` : ''}`
      : '—';
  };
  const departures = (view: BeforeSendView) =>
    t('ux.compare.departures', {
      departed: n(view.departureCount),
      compared: n(view.comparedCount ?? 0),
      list: view.departures
        .map((row) => t(`ux.compare.dim.${row.dimension}`, { defaultValue: row.dimension }))
        .join(' · '),
    });
  const rows = [
    { id: 'account', a: name, b: name },
    {
      id: 'time',
      a: companyClock(t, attacker.received.companyTime),
      b: companyClock(t, owner.received.companyTime),
    },
    { id: 'network', a: network(attacker.received), b: network(owner.received) },
    {
      id: 'auth',
      a: authWords(t, now(attacker.received, 'authenticationType')?.now),
      b: authWords(t, now(owner.received, 'authenticationType')?.now),
    },
    { id: 'request', a: request(attacker.anatomy), b: request(owner.anatomy) },
    {
      id: 'device',
      a: deviceWords(now(attacker.received, 'device')?.now),
      b: deviceWords(now(owner.received, 'device')?.now),
    },
    { id: 'departures', a: departures(attacker.received), b: departures(owner.received) },
  ];
  const deviceMark = (view: BeforeSendView) => now(view, 'device')?.inUsual;
  const differing = rows
    .filter((row) => row.a !== row.b && row.id !== 'departures')
    .map((row) => t(`ux.compare.row.${row.id}`));
  const stoppedThreat = ['STOPPED', 'PARTLY_STOPPED'].includes(attacker.score.business.D?.result ?? '');
  const passedNormal = ['PASSED', 'PASSED_AFTER_CHECK'].includes(owner.score.business.D?.result ?? '');
  const existingBlind =
    EXISTING.every((control) => attacker.score?.business[control]?.result === 'MISSED') &&
    EXISTING.every((control) => owner.score?.business[control]?.result === 'PASSED');
  const split = stoppedThreat && passedNormal && existingBlind;
  return (
    <>
      <PageHead
        title={t('ux.compare.title')}
        desc={
          differing.length === 1
            ? t('ux.compare.descOne', { row: differing[0] })
            : t('ux.compare.desc', { rows: differing.join(' · ') })
        }
      />
      <div className={styles.runs}>
        {[attacker, owner].map((side) => (
          <RunCard key={side.key} side={side} />
        ))}
      </div>
      <section className={styles.card} aria-labelledby="facts-title">
        <header className={styles.cardHead}>
          <h2 id="facts-title" className={styles.cardTitle}>
            {t('ux.compare.facts.title')}
          </h2>
          <p className={styles.cardSub}>{t('ux.compare.facts.sub')}</p>
        </header>
        <div className={styles.tableScroll}>
          <table className={styles.table}>
            <caption className="ux-sr-only">{t('ux.compare.facts.title')}</caption>
            <thead>
              <tr>
                <th scope="col">{t('ux.compare.col.item')}</th>
                <th scope="col">{t('ux.pick.S13.title')}</th>
                <th scope="col">{t('ux.pick.S13T.title')}</th>
                <th scope="col">{t('ux.compare.col.same')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const same = row.a === row.b;
                return (
                  <tr key={row.id} data-diff={!same || undefined}>
                    <th scope="row">{t(`ux.compare.row.${row.id}`)}</th>
                    <td>
                      {row.a}{' '}
                      {row.id === 'device' && deviceMark(attacker.received as BeforeSendView) === 'false' ? (
                        <FlagBadge />
                      ) : null}
                    </td>
                    <td>
                      {row.b}{' '}
                      {row.id === 'device' && deviceMark(owner.received as BeforeSendView) === 'true' ? (
                        <Badge tone="none">{t('ux.facts.mark.in')}</Badge>
                      ) : null}
                    </td>
                    <td>
                      {same ? t('ux.compare.same') : <Badge tone="line">{t('ux.compare.different')}</Badge>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {changes.data ? <InputChanges lines={changes.data} /> : null}
      </section>
      <div className={styles.bottom}>
        {split ? (
          <section className={styles.insight} aria-labelledby="insight-title">
            <Icon name="lightbulb" size="xl" />
            <div>
              <h2 id="insight-title" className={styles.cardTitle}>
                {t('ux.compare.insight.title')}
              </h2>
              <p className={styles.cardSub}>{t('ux.compare.insight.body')}</p>
            </div>
          </section>
        ) : null}
        <section className={styles.card} aria-labelledby="learning-title">
          <header className={styles.cardHead}>
            <h2 id="learning-title" className={styles.cardTitle}>
              {t('ux.compare.learning.title')}
            </h2>
            <p className={styles.cardSub}>{t('ux.compare.learning.sub')}</p>
          </header>
          <ul className={styles.learning}>
            {[attacker, owner].map((side) => {
              const figures = side.anatomy?.figures ?? null;
              const added = figures?.baselineAdded ?? null;
              return (
                <li key={side.key}>
                  <span>
                    {t(`ux.pick.${side.key}.title`)} ·{' '}
                    <VerdictBadge verdict={verdictOf(side.score?.verdicts[0]?.score.finalAction)} />
                  </span>
                  <span className={styles.learningNumbers}>
                    {figures?.baselineBefore != null && figures.baselineAfter != null
                      ? `${n(figures.baselineBefore)} → ${n(figures.baselineAfter)}`
                      : '—'}
                  </span>
                  {added !== null ? (
                    added > 0 ? (
                      <Badge tone="allow">{t('ux.compare.learning.added', { n: n(added) })}</Badge>
                    ) : (
                      <Badge tone="none">{t('ux.compare.learning.none')}</Badge>
                    )
                  ) : null}
                </li>
              );
            })}
          </ul>
        </section>
      </div>
      {runs.latest('S16') === null ? (
        <div className={styles.nextNote}>
          <Note>{t('ux.compare.next', { n: runs.done, total: runs.total })}</Note>
          <ButtonLink to={flowPath('S16', 'review')} variant="primary" size="sm" iconAfter="arrow-right">
            {t('ux.result.next.run', { key: 'S16' })}
          </ButtonLink>
        </div>
      ) : null}
    </>
  );
}

/**
 * One engine input line as the portal compares it: a comparison with the baseline (`dim.device`, `Safari/18 on MAC ·
 * false`) is named by its dimension, with the engine's membership label in words; any other input stays as the engine
 * received it (`ApprovalMissing`).
 */
function inputText(t: TFunction, value: string | null): string {
  if (value === null) {
    return '—';
  }
  const at = value.lastIndexOf(' · ');
  const label = at < 0 ? null : value.slice(at + 3);
  const words = label === 'false' ? t('ux.flag.deviation') : label === 'true' ? t('ux.facts.mark.in') : null;
  return words === null ? value : `${value.slice(0, at)} · ${words}`;
}

/**
 * Where the engine's input differed between the two runs, line by line, as the portal compared it (P-8, the old 4-3
 * table): folded under the request facts, with the count of lines in its summary.
 */
function InputChanges({ lines }: { readonly lines: readonly InputChange[] }) {
  const { t, i18n } = useTranslation();
  if (lines.length === 0) {
    return <p className={styles.inputsNone}>{t('ux.compare.inputs.none')}</p>;
  }
  return (
    <details className={styles.inputs}>
      <summary>{t('ux.compare.inputs.more', { n: formatNumber(lines.length, i18n.language) })}</summary>
      <p className={styles.inputsSub}>{t('ux.compare.inputs.sub')}</p>
      <div className={styles.tableScroll}>
        <table className={styles.table}>
          <caption className="ux-sr-only">{t('ux.compare.inputs.col')}</caption>
          <thead>
            <tr>
              <th scope="col">{t('ux.compare.inputs.col')}</th>
              <th scope="col">{t('ux.pick.S13.title')}</th>
              <th scope="col">{t('ux.pick.S13T.title')}</th>
            </tr>
          </thead>
          <tbody>
            {lines.map((line) => (
              <tr key={line.key}>
                <th scope="row">
                  {line.key.startsWith('dim.')
                    ? t(`ux.compare.dim.${line.key.slice(4)}`, { defaultValue: line.key.slice(4) })
                    : line.key}
                </th>
                <td>{inputText(t, line.before)}</td>
                <td>{inputText(t, line.now)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

function RunCard({ side }: { readonly side: Side }) {
  const { t, i18n } = useTranslation();
  const score = side.score as RunScore;
  const contexa = score.business.D;
  const graded = evalOf(contexa?.result);
  const existing = EXISTING.map((control) => score.business[control]?.result ?? null);
  const existingGraded = existing.every((value) => value === existing[0]) ? evalOf(existing[0]) : null;
  const recorded = side.anatomy?.interpretation?.recorded ?? null;
  const n = (value: number) => formatNumber(value, i18n.language);
  return (
    <section className={styles.runCard} aria-labelledby={`run-${side.key}`}>
      <div className={styles.runHead}>
        <div>
          <h2 id={`run-${side.key}`} className={styles.cardTitle}>
            {t(`ux.pick.${side.key}.title`)}
          </h2>
          <p className={styles.cardSub}>
            {side.key} · {t(`ux.flow.truth.${truthOf(score.truth.classification)}`)}
          </p>
        </div>
        <CodeChip value={side.runId} copy />
      </div>
      <p className={styles.runBig}>
        <VerdictBadge verdict={verdictOf(score.verdicts[0]?.score.finalAction)} />
        <b>{t('ux.facts.items', { count: contexa?.exposedItems ?? 0, n: n(contexa?.exposedItems ?? 0) })}</b>
        {graded ? <EvalBadge result={graded} /> : null}
      </p>
      <dl className={styles.runFacts}>
        <dt>{t('ux.compare.scores')}</dt>
        <dd>
          {recorded?.riskScore != null ? recorded.riskScore.toFixed(2) : '—'} ·{' '}
          {recorded?.confidence != null ? recorded.confidence.toFixed(2) : '—'}
        </dd>
        <dt>{t('ux.control.existing')}</dt>
        <dd>
          {t('ux.compare.existing', {
            n: n(score.business.A?.exposedItems ?? 0),
          })}{' '}
          {existingGraded ? <EvalBadge result={existingGraded} /> : null}
        </dd>
      </dl>
    </section>
  );
}
