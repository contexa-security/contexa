import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useLabOptions } from '../../api/lab';
import { useBaseline } from '../../api/queries';
import type { BaselineCardView } from '../../api/types';
import { Modal } from '../../components/common/Modal';
import { useUrlModal } from '../../components/common/useUrlModal';
import { Icon } from '../../components/Icon';
import { routeFlow } from '../../components/journey/flow';
import { HourBars } from '../../components/journey/HourBars';
import { SourceLine } from '../../components/journey/FrameParts';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { StateScreen } from '../../components/StateScreen';
import { VerdictChip } from '../../components/VerdictChip';
import type { Verdict } from '../../domain/verdict';
import { count } from '../../journey/format';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import { personName } from '../main/mainCases';
import { CASES, plainPath } from '../try/experience';
import styles from './LearningPages.module.css';

/** The window keeps its old address name, so a shared link to it still opens it. */
const REQUESTS_MODAL = 'learned-requests';
const VERDICTS = new Set(['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK']);
/** The kinds of work sent to teach the engine, in the order the record counts them. */
const KINDS = ['reads', 'downloads', 'exports'] as const;

/** A company date as the record holds it (month and day), for the period of the learning work. */
function day(iso: string | null): string {
  return iso ? `${Number(iso.slice(5, 7))}/${Number(iso.slice(8, 10))}` : '-';
}

/** A learning state as the engine wrote it, in plain words; a state without plain words is named as another one. */
function stateWords(t: TFunction, value: string | null): string {
  if (value === null) {
    return t('p3.learned.window.value.none');
  }
  return t(`p3.learned.window.value.${value}`, { defaultValue: t('p3.learned.window.value.other') });
}

/** An hour list the engine received, as hours of the day; an empty or missing list is said to have no record. */
function hourList(t: TFunction, hours: readonly number[] | null | undefined): string {
  return hours && hours.length > 0
    ? hours.map((hour) => t('hourBars.tick', { hour })).join(', ')
    : t('p3.learned.window.value.none');
}

/** The four facts of the learning: the period, the place, the device and the work, as the records hold them. */
function Facts({ card, office }: { readonly card: BaselineCardView; readonly office: string | null }) {
  const { t } = useTranslation();
  const kinds = KINDS.filter((kind) => card.taught[kind] > 0)
    .map((kind) => t(`p3.learned.kind.${kind}`))
    .join(' · ');
  const projects = Object.keys(card.taught.projects).join(', ');
  return (
    <dl className={styles.facts}>
      <div className={styles.fact}>
        <dt>{t('p3.learned.fact.period')}</dt>
        <dd>{t('p3.learned.fact.periodValue', { from: day(card.taught.from), to: day(card.taught.to) })}</dd>
      </div>
      <div className={styles.fact}>
        <dt>{t('p3.learned.fact.place')}</dt>
        <dd>
          {card.learned.networks
            .map((band) => (band === office ? t('p3.learned.fact.office', { band }) : band))
            .join(', ') || '-'}
        </dd>
      </div>
      <div className={styles.fact}>
        <dt>{t('p3.learned.fact.device')}</dt>
        <dd>
          {card.learned.devices
            .map((device) => t(`p3.learned.os.${device}`, { defaultValue: device }))
            .join(' · ') || '-'}
        </dd>
      </div>
      <div className={styles.fact}>
        <dt>{t('p3.learned.fact.work')}</dt>
        <dd>{kinds ? (projects ? t('p3.learned.fact.workValue', { projects, kinds }) : kinds) : '-'}</dd>
      </div>
    </dl>
  );
}

/**
 * The learning requests window: how many were sent, how many passed and how many the engine learned, with the reason
 * of a difference only when the record shows it (the learned count equals the passed count); the learning states and
 * the two hour lists of the engine's latest judgment; and every request sent, with the judgment it got.
 */
function RequestsWindow({ card }: { readonly card: BaselineCardView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const engine = card.hours;
  return (
    <div className={styles.window}>
      <p className={styles.counts}>
        {t('p3.learned.window.counts', {
          sent: count(card.sent, language),
          allowed: count(card.allowed, language),
          learned: count(card.learned.requests, language),
        })}
      </p>
      {card.sent !== card.allowed && card.allowed === card.learned.requests ? (
        <p className={styles.text}>{t('p3.learned.window.why')}</p>
      ) : null}
      <section className={styles.windowPart} aria-labelledby="learned-states">
        <h3 id="learned-states" className={styles.label}>
          {t('p3.learned.window.states')}
        </h3>
        {engine ? (
          <dl className={styles.states}>
            <div className={styles.fact}>
              <dt>{t('p3.learned.window.state.personal')}</dt>
              <dd>{stateWords(t, engine.personalBaselineStatus)}</dd>
            </div>
            <div className={styles.fact}>
              <dt>{t('p3.learned.window.state.scope')}</dt>
              <dd>
                {stateWords(t, engine.roleScopeState)}
                {engine.roleScopeState === 'PROVISIONAL' ? (
                  <span className={styles.why}>{t('p3.learned.window.scopeWhy')}</span>
                ) : null}
              </dd>
            </div>
            <div className={styles.fact}>
              <dt>{t('p3.learned.window.state.normalHours')}</dt>
              <dd>{hourList(t, engine.normalAccessHours)}</dd>
            </div>
            <div className={styles.fact}>
              <dt>{t('p3.learned.window.state.observedHours')}</dt>
              <dd>{hourList(t, engine.observedHours)}</dd>
            </div>
          </dl>
        ) : (
          <p className={styles.text}>{t('p3.learned.window.noDecision')}</p>
        )}
      </section>
      <div className={styles.tableWrap}>
        <table className={styles.requests} aria-label={t('p3.learned.table.label')}>
          <thead>
            <tr>
              <th scope="col">{t('p3.learned.table.no')}</th>
              <th scope="col">{t('p3.learned.table.time')}</th>
              <th scope="col">{t('p3.learned.table.request')}</th>
              <th scope="col">{t('p3.learned.table.items')}</th>
              <th scope="col">{t('p3.learned.table.decision')}</th>
            </tr>
          </thead>
          <tbody>
            {card.requests.map((request) => (
              <tr key={request.no}>
                <td>{request.no}</td>
                <td>{request.companyTime.slice(5, 16).replace('T', ' ')}</td>
                <td>{plainPath(t, request.path)}</td>
                <td>{request.items === null ? '-' : count(request.items, language)}</td>
                <td>
                  {request.finalAction && VERDICTS.has(request.finalAction) ? (
                    <VerdictChip verdict={request.finalAction as Verdict} />
                  ) : (
                    '-'
                  )}
                  {request.identityCheckPassed ? ` ${t('p3.learned.table.checked')}` : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * Screen 3-1, what Contexa learned (화면재편 T7): the hours of the requests the engine learned (its baseline's own
 * count, F-4) and four facts: the period of the learning work, the place, the device and the work. One chip under the
 * body opens the learning requests window, which holds what the body leaves out: how many were sent and why that differs
 * from the learned count, the engine's learning states and hour lists, and the request table.
 */
export default function LearnedPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const flow = routeFlow(t, useJourneyPosition());
  const options = useLabOptions();
  const attack = options.data?.cases.find((candidate) => candidate.key === CASES.attacker.sync) ?? null;
  const employee =
    options.data?.employees.find((candidate) => candidate.key === attack?.conditions.employee) ?? null;
  const baseline = useBaseline(attack?.conditions.employee ?? null);
  const modal = useUrlModal(REQUESTS_MODAL);
  const card = baseline.data ?? null;
  const loading = options.isPending || baseline.isLoading;
  // The person in the visitor's words (관리자 A, T-08), the record's display name only when the case names nobody.
  const name = employee ? personName(t, employee) : (card?.displayName ?? '');

  return (
    <RouteScreen
      title={t('screen.3-1.title', { name })}
      purpose={t('screen.3-1.guide')}
      more={
        card ? (
          <button type="button" className={styles.open} onClick={() => modal.show()}>
            <Icon name="search" className={styles.openIcon} />
            {t('p3.learned.open')}
          </button>
        ) : null
      }
      sourceLine={card ? <SourceLine kind="learned" /> : null}
      back={flow.back}
      main={flow.next}
    >
      {loading ? <StateScreen kind="loading" /> : null}
      {!loading && !card ? <p className={styles.text}>{t('p3.learned.none')}</p> : null}
      {card ? (
        <>
          <section className={styles.chart} aria-labelledby="learned-hours">
            <h2 id="learned-hours" className={styles.chartTitle}>
              {t('p3.learned.hours', { n: count(card.learned.requests, language) })}
            </h2>
            <HourBars hours={card.learned.hours} />
          </section>
          <Facts card={card} office={employee?.officeNetwork ?? null} />
          <Modal
            open={modal.open}
            onClose={modal.hide}
            title={t('p3.learned.window.title', { name })}
            wide
          >
            <RequestsWindow card={card} />
          </Modal>
        </>
      ) : null}
    </RouteScreen>
  );
}
