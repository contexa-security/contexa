import { useTranslation } from 'react-i18next';
import { useLabOptions } from '../../api/lab';
import { useBaseline } from '../../api/queries';
import { ActionChip } from '../../components/common/ActionChip';
import { Modal } from '../../components/common/Modal';
import { SourceMark } from '../../components/common/SourceMark';
import { useUrlModal } from '../../components/common/useUrlModal';
import { HourBars } from '../../components/journey/HourBars';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import { VerdictChip } from '../../components/VerdictChip';
import type { Verdict } from '../../domain/verdict';
import { count } from '../../journey/format';
import { CASES, plainPath } from '../try/experience';
import styles from './LearningPages.module.css';

const REQUESTS_MODAL = 'learned-requests';
const VERDICTS = new Set(['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK']);
const WEEKDAYS = [0, 1, 2, 3, 4, 5, 6] as const;

/** A company date as the record holds it (month and day), for the period of the learned work. */
function day(iso: string | null): string {
  return iso ? `${Number(iso.slice(5, 7))}/${Number(iso.slice(8, 10))}` : '-';
}

/**
 * Prior learning 2 (g-learned, 7.3): what Contexa learned about the employee, as the records hold it: the learned
 * hours and weekdays (the engine's baseline), the facts of the work sent to teach it (period, office band, device,
 * actions, export sizes, projects), and how far the engine itself judged each kind of learning (the state lines of
 * its latest prompt). The 25 learned requests open in a table; the two hour lists are in the source tag.
 */
export default function LearnedPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const options = useLabOptions();
  const attack = options.data?.cases.find((candidate) => candidate.key === CASES.attacker.sync) ?? null;
  const employee = options.data?.employees.find((candidate) => candidate.key === attack?.conditions.employee);
  const baseline = useBaseline(attack?.conditions.employee ?? null);
  const modal = useUrlModal(REQUESTS_MODAL);
  const card = baseline.data ?? null;
  const engine = card?.hours ?? null;
  const state = (value: string | null) =>
    value === null ? t('learned.state.none') : t(`learned.state.${value}`, { defaultValue: value });

  return (
    <RouteScreen
      title={t('learned.title', { name: employee?.displayName ?? '' })}
      purpose={t('learned.purpose')}
      source={
        engine ? (
          <SourceMark
            kind="ENGINE"
            runId={engine.runId}
            step={engine.stepNo}
            original={engine.observedScopeSummary}
          >
            {t('learned.source', {
              normal: engine.normalAccessHours.join(', ') || '-',
              observed: engine.observedHours.join(', ') || '-',
            })}
          </SourceMark>
        ) : null
      }
      more={
        card ? (
          <ActionChip icon="search" variant="open" onClick={() => modal.show()}>
            {t('learned.requestsOpen', { n: card.sent })}
          </ActionChip>
        ) : null
      }
    >
      {baseline.isPending || options.isPending ? <StateScreen kind="loading" /> : null}
      {card ? (
        <>
          <section className={styles.learnedChart} aria-labelledby="learned-hours">
            <h2 id="learned-hours" className={styles.panelLabel}>
              {t('learned.hours', { n: count(card.learned.requests, language) })}
            </h2>
            <HourBars hours={card.learned.hours} />
            <ol className={styles.weekdays} aria-label={t('learned.weekdays')}>
              {WEEKDAYS.map((weekday) => (
                <li key={weekday} className={styles.weekday}>
                  <span
                    className={styles.weekdayBar}
                    data-learned={(card.learned.weekdays[weekday] ?? 0) > 0 || undefined}
                  />
                  {t(`learned.weekday.${weekday}`)}
                </li>
              ))}
            </ol>
          </section>
          <dl className={styles.facts}>
            <div className={styles.fact}>
              <dt>{t('learned.fact.period')}</dt>
              <dd>
                {t('learned.fact.periodValue', { from: day(card.taught.from), to: day(card.taught.to) })}
              </dd>
            </div>
            <div className={styles.fact}>
              <dt>{t('learned.fact.office')}</dt>
              <dd>{card.learned.networks.join(', ') || '-'}</dd>
            </div>
            <div className={styles.fact}>
              <dt>{t('learned.fact.device')}</dt>
              <dd>{card.learned.devices.join(' · ') || '-'}</dd>
            </div>
            <div className={styles.fact}>
              <dt>{t('learned.fact.actions')}</dt>
              <dd>
                {t('learned.fact.actionsValue', {
                  reads: count(card.taught.reads, language),
                  downloads: count(card.taught.downloads, language),
                  exports: count(card.taught.exports, language),
                })}
              </dd>
            </div>
            <div className={styles.fact}>
              <dt>{t('learned.fact.exportSize')}</dt>
              <dd>
                {card.taught.exportItemsMin === null || card.taught.exportItemsMax === null
                  ? '-'
                  : t('learned.fact.exportSizeValue', {
                      min: count(card.taught.exportItemsMin, language),
                      max: count(card.taught.exportItemsMax, language),
                    })}
              </dd>
            </div>
            <div className={styles.fact}>
              <dt>{t('learned.fact.projects')}</dt>
              <dd>{Object.keys(card.taught.projects).join(', ') || '-'}</dd>
            </div>
          </dl>
          {engine ? (
            <ul className={styles.states} aria-label={t('learned.states')}>
              <li className={styles.state} data-state={engine.personalBaselineStatus ?? undefined}>
                <span className={styles.stateName}>{t('learned.state.personal')}</span>
                <span className={styles.stateValue}>{state(engine.personalBaselineStatus)}</span>
              </li>
              <li className={styles.state} data-state={engine.roleScopeState ?? undefined}>
                <span className={styles.stateName}>{t('learned.state.scope')}</span>
                <span className={styles.stateValue}>{state(engine.roleScopeState)}</span>
                {engine.roleScopeState === 'PROVISIONAL' ? (
                  <span className={styles.stateWhy}>{t('learned.state.scopeWhy')}</span>
                ) : null}
              </li>
            </ul>
          ) : null}
          <Modal
            open={modal.open}
            onClose={modal.hide}
            title={t('learned.requestsTitle', { n: card.sent, name: card.displayName })}
            wide
          >
            <table className={styles.requests}>
              <thead>
                <tr>
                  <th scope="col">{t('learned.table.no')}</th>
                  <th scope="col">{t('learned.table.time')}</th>
                  <th scope="col">{t('learned.table.request')}</th>
                  <th scope="col">{t('learned.table.items')}</th>
                  <th scope="col">{t('learned.table.decision')}</th>
                </tr>
              </thead>
              <tbody>
                {card.requests.map((request) => (
                  <tr key={request.no}>
                    <td>{request.no}</td>
                    <td>{request.companyTime.slice(5, 16).replace('T', ' ')}</td>
                    <td className={styles.path}>{plainPath(t, request.path)}</td>
                    <td>{request.items === null ? '-' : count(request.items, language)}</td>
                    <td>
                      {request.finalAction && VERDICTS.has(request.finalAction) ? (
                        <VerdictChip verdict={request.finalAction as Verdict} />
                      ) : (
                        '-'
                      )}
                      {request.identityCheckPassed ? ` ${t('learned.table.checked')}` : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Modal>
        </>
      ) : null}
    </RouteScreen>
  );
}
