import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import {
  CONCEPT_STEPS,
  DIFFERENCES,
  actScreens,
  actStart,
  type Act,
  type Difference,
} from '../../journey/journey';
import { useJourneyPlace } from '../../journey/useJourneyPlace';
import { ActionChip } from '../common/ActionChip';
import { Icon } from '../Icon';
import { Modal } from '../common/Modal';
import { useUrlModal } from '../common/useUrlModal';
import styles from './JourneyParts.module.css';

/** The act where each difference is first seen on the default route (thread slide). */
const SEEN_IN: Readonly<Record<Difference, Act>> = { 1: 1, 2: 1, 3: 2, 4: 1, 5: 1, 6: 3 };

/** The short identity line under the menu, on the hook and on every act-end card (decision 11, D-16). */
export function IdentityLine() {
  const { t } = useTranslation();
  return <p className={styles.identity}>{t('identity.line')}</p>;
}

/** The long definition on the introduction and in "what you did" (decision 11, D-16). */
export function IdentityDefinition() {
  const { t } = useTranslation();
  return <p className={styles.definition}>{t('identity.definition')}</p>;
}

/**
 * The place band at the top of every screen of a route (common-1, redrawn 2026-10-08 so the parts and their relations
 * read at a glance): the four acts as one row of tabs where only the current act is spelled out, and under it, joined
 * to the current tab, the screens of that act as numbered steps. A past act's tab leads to its start; later acts are
 * dimmed and not links ("skip" sits in the action area). The concept path draws the same band with its nine steps
 * (D-33). The difference badge is the band's only other part, on the right.
 */
export function JourneyBar() {
  const { t } = useTranslation();
  const place = useJourneyPlace();
  const screen = place.screen;
  if (!screen) {
    return null;
  }
  if (place.route === 'INTRO') {
    if (screen.conceptStep === null) {
      return null;
    }
    return (
      <nav className={styles.band} aria-label={t('place.label')}>
        <ol className={styles.tabs}>
          <li className={styles.tab} data-state="current" data-first aria-current="step">
            <span className={styles.tabDot} aria-hidden="true" />
            <span className={styles.tabNumber}>{t('place.concept')}</span>
            <span className={styles.tabName}>{t('concept.progress', { n: screen.conceptStep })}</span>
          </li>
        </ol>
        <DifferenceBadge differences={place.differences} />
        <Steps
          names={CONCEPT_STEPS.map((step) => t(`concept.step.${step}`))}
          current={screen.conceptStep - 1}
          label={t('concept.progress', { n: screen.conceptStep })}
          first
        />
      </nav>
    );
  }
  const act = screen.act;
  if (act === null) {
    return null;
  }
  const steps = actScreens(act);
  return (
    <nav className={styles.band} aria-label={t('place.label')}>
      <ol className={styles.tabs}>
        {([1, 2, 3, 4] as const).map((n) => (
          <li
            key={n}
            className={styles.tab}
            data-state={n < act ? 'past' : n === act ? 'current' : 'later'}
            data-first={n === 1 || undefined}
            aria-current={n === act ? 'step' : undefined}
          >
            {n < act ? (
              <Link to={actStart(n).path} className={styles.tabLink} title={t('act.past', { n })}>
                <Icon name="check" className={styles.tabCheck} />
                <span className={styles.tabNumber} data-past>
                  {t('act.label', { n })}
                </span>
                <span className={styles.srOnly}>{t('act.past', { n })}</span>
              </Link>
            ) : n === act ? (
              <>
                <span className={styles.tabDot} aria-hidden="true" />
                <span className={styles.tabNumber}>{t('act.label', { n })}</span>
                <span className={styles.tabName}>{t(`act.${n}.name`)}</span>
              </>
            ) : (
              <span className={styles.tabNumber}>
                <span className={styles.tabLabel}>{t('act.label', { n })}</span>
                <span className={styles.tabShort} aria-hidden="true">
                  {n}
                </span>
              </span>
            )}
          </li>
        ))}
      </ol>
      <DifferenceBadge differences={place.differences} />
      <Steps
        names={steps.map((step) => t(`place.step.${step.id}`))}
        current={steps.findIndex((step) => step.id === screen.id)}
        label={t('place.steps', { n: act, name: t(`act.${act}.name`) })}
        actName={t(`act.${act}.name`)}
        first={act === 1}
      />
    </nav>
  );
}

/** The lab's steps (lab-1): the case, the condition (with the comparison before sending), sending and comparing. */
export type LabStep = 'entrance' | 'case' | 'change' | 'send' | 'rules';

const LAB_STEPS = ['case', 'change', 'send'] as const;

/**
 * The lab's place band (common-1: the lab shows its own steps): the same look as the routes' band, one "lab" tab and
 * under it the lab's three steps, or the rule tightening as the one step of its own screen.
 */
export function LabBar({ step }: { readonly step: LabStep }) {
  const { t } = useTranslation();
  const place = useJourneyPlace();
  const rules = step === 'rules';
  return (
    <nav className={styles.band} aria-label={t('place.label')}>
      <ol className={styles.tabs}>
        <li className={styles.tab} data-state="current" data-first aria-current="step">
          <span className={styles.tabDot} aria-hidden="true" />
          <span className={styles.tabNumber}>{t('labBar.tab')}</span>
          <span className={styles.tabName}>{t(rules ? 'labBar.rules' : 'labBar.name')}</span>
        </li>
      </ol>
      <DifferenceBadge differences={place.differences} />
      <Steps
        names={rules ? [t('labBar.rules')] : LAB_STEPS.map((name) => t(`labBar.step.${name}`))}
        current={rules ? 0 : LAB_STEPS.indexOf(step as (typeof LAB_STEPS)[number])}
        label={t('labBar.steps')}
        actName={t(rules ? 'labBar.rules' : 'labBar.name')}
        first
      />
    </nav>
  );
}

/** The benchmark's views (7.8): parallel ways into one measurement, not steps one after another. */
export type BenchView = 'summary' | 'cases' | 'judgment' | 'limits';

const BENCH_VIEWS: Readonly<Record<BenchView, string>> = {
  summary: '/benchmark',
  cases: '/benchmark/cases',
  judgment: '/benchmark/judgment',
  limits: '/benchmark/limits',
};

/**
 * The benchmark's place band in the same shape as the others: the tab 'Benchmark', and under it its four views as
 * pressable links (each opens a view of the same measurement), the current one marked. `search` keeps the chosen
 * measurement setting across the views.
 */
export function BenchBar({ view, search = '' }: { readonly view: BenchView; readonly search?: string }) {
  const { t } = useTranslation();
  const place = useJourneyPlace();
  return (
    <nav className={styles.band} aria-label={t('place.label')}>
      <ol className={styles.tabs}>
        <li className={styles.tab} data-state="current" data-first aria-current="step">
          <span className={styles.tabDot} aria-hidden="true" />
          <span className={styles.tabNumber}>{t('benchBar.tab')}</span>
          <span className={styles.tabName}>{t('benchBar.name')}</span>
        </li>
      </ol>
      <DifferenceBadge differences={place.differences} />
      <div className={styles.panel} data-first>
        <ul className={styles.views} aria-label={t('benchBar.views')}>
          {(Object.keys(BENCH_VIEWS) as BenchView[]).map((name) => (
            <li key={name}>
              <Link
                to={`${BENCH_VIEWS[name]}${search}`}
                className={styles.view}
                aria-current={name === view ? 'page' : undefined}
              >
                {t(`benchBar.view.${name}`)}
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  );
}

interface StepsProps {
  readonly names: readonly string[];
  readonly current: number;
  readonly label: string;
  /** The act's question, written over the steps on phones, where the tab keeps only the number. */
  readonly actName?: string;
  /** The current tab is the first, so the panel's top left corner is square under it. */
  readonly first?: boolean;
}

/** The steps of the current act (or of the concept path), joined to the current tab: checked, current, ahead. */
function Steps({ names, current, label, actName, first = false }: StepsProps) {
  return (
    <div className={styles.panel} data-first={first || undefined}>
      {actName ? <p className={styles.phoneActName}>{actName}</p> : null}
      <ol className={styles.steps} aria-label={label}>
        {names.map((name, index) => (
          <li
            key={`${index}-${name}`}
            className={styles.step}
            data-state={index < current ? 'past' : index === current ? 'current' : 'later'}
            aria-current={index === current ? 'step' : undefined}
            title={index < current ? name : undefined}
          >
            <span className={styles.stepDot} aria-hidden="true">
              {index < current ? <Icon name="check" /> : index + 1}
            </span>
            <span className={styles.stepName}>{name}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

const CARDS_MODAL = 'differences';

interface DifferenceBadgeProps {
  readonly differences: readonly number[];
  /** Per seen difference, the measured line and the screen where it was seen (thread slide). */
  readonly lines?: Readonly<Partial<Record<Difference, { readonly text: ReactNode; readonly to: string }>>>;
}

/**
 * "Differences seen n/6" (thread): clicking opens the six cards; a seen card has its measured line and a link back to
 * where it was seen, an unseen one names the act that shows it, without giving the answer.
 */
export function DifferenceBadge({ differences, lines = {} }: DifferenceBadgeProps) {
  const { t } = useTranslation();
  const modal = useUrlModal(CARDS_MODAL);
  const seen = new Set(differences);
  return (
    <>
      <button
        type="button"
        className={styles.badge}
        aria-label={t('difference.badgeAria', { n: seen.size })}
        onClick={() => modal.show()}
      >
        <span className={styles.badgeLabel}>{t('difference.badgeLabel')}</span>
        <span className={styles.badgeShort}>{t('difference.badgeShort')}</span>
        <DifferenceMarks differences={differences} />
        <span className={styles.badgeCount}>{t('difference.count', { n: seen.size })}</span>
      </button>
      <Modal open={modal.open} onClose={modal.hide} title={t('difference.cards.title')}>
        <ol className={styles.cards}>
          {DIFFERENCES.map((difference) => {
            const line = lines[difference];
            return (
              <li key={difference} className={styles.card} data-seen={seen.has(difference) || undefined}>
                <span className={styles.cardName}>
                  <DifferenceMark difference={difference} seen={seen.has(difference)} />
                  {seen.has(difference)
                    ? t(`difference.${difference}`)
                    : t(`difference.question.${difference}`)}
                </span>
                {seen.has(difference) ? (
                  <>
                    <span className={styles.cardState}>{t('difference.seen')}</span>
                    {line ? (
                      <>
                        <span className={styles.cardLine}>{line.text}</span>
                        <ActionChip to={line.to} icon="arrowLeft" size="sm">
                          {t('difference.back')}
                        </ActionChip>
                      </>
                    ) : null}
                  </>
                ) : (
                  <span className={styles.cardState}>
                    {t('difference.pending', { n: SEEN_IN[difference] })}
                  </span>
                )}
              </li>
            );
          })}
        </ol>
      </Modal>
    </>
  );
}

/** One difference's numbered circle: filled once seen, dashed while still ahead (the same everywhere it is named). */
export function DifferenceMark({
  difference,
  seen,
}: {
  readonly difference: number;
  readonly seen: boolean;
}) {
  return (
    <span className={styles.markCircle} data-seen={seen || undefined} aria-hidden="true">
      {difference}
    </span>
  );
}

/** The six differences as numbered circles, filled once seen: the same marks the "just seen" band names (thread). */
export function DifferenceMarks({ differences }: { readonly differences: readonly number[] }) {
  const seen = new Set(differences);
  return (
    <span className={styles.marks} aria-hidden="true">
      {DIFFERENCES.map((difference) => (
        <DifferenceMark key={difference} difference={difference} seen={seen.has(difference)} />
      ))}
    </span>
  );
}

/** "Differences to see in this try" when a try starts (thread). */
export function GoalChips({ differences }: { readonly differences: readonly Difference[] }) {
  const { t } = useTranslation();
  return (
    <div className={styles.goals}>
      <span className={styles.goalsTitle}>{t('goals.title')}</span>
      <ul className={styles.chips}>
        {differences.map((difference) => (
          <li key={difference} className={styles.chip}>
            <DifferenceMark difference={difference} seen={false} />
            {t(`difference.${difference}`)}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** The sentences of the "just seen" band, by place (7.0 copy table). */
export type JustSawSentence =
  | 'e1Run'
  | 'e1Compare'
  | 'e1Reason'
  | 'e1After'
  | 'e2Result'
  | 'e2Check'
  | 'syncWhen'
  | 'e3Stack'
  | 'learnAfter';

interface JustSawProps {
  readonly difference: Difference;
  readonly sentence: JustSawSentence;
  /** Values the sentence states (a count, seconds), as the server gave them. */
  readonly values?: Readonly<Record<string, string | number>>;
  /** "Difference revisited" on the learning-after screen instead of "just seen". */
  readonly again?: boolean;
}

/** One line at the bottom of a screen that names the difference just seen (thread). */
export function JustSaw({ difference, sentence, values = {}, again = false }: JustSawProps) {
  const { t } = useTranslation();
  return (
    <p className={styles.justSaw} role="note">
      <span className={styles.justSawHead}>
        <DifferenceMark difference={difference} seen />
        <span className={styles.justSawLabel}>{again ? t('justSaw.againTitle') : t('justSaw.title')}</span>
      </span>
      <span className={styles.justSawText}>{t(`justSaw.${sentence}`, values)}</span>
    </p>
  );
}

/** Announced the same way whenever the visitor's role changes (e2-scene, D-36). */
export function RoleBanner({
  role,
  name,
}: {
  readonly role: 'owner' | 'securityAdmin';
  readonly name?: string;
}) {
  const { t } = useTranslation();
  return (
    <p className={styles.role} role="status">
      <span className={styles.roleChanged}>{t('role.changed')}</span> ·{' '}
      {role === 'owner' ? t('role.owner', { name }) : t('role.securityAdmin')}
    </p>
  );
}
