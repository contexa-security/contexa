import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import {
  useRuleCasesView,
  useRuleResult,
  type RuleDefaults,
  type RuleSettings,
  type RuleTally,
} from '../../api/rules';
import { keepWhole } from '../../components/detail/keepWhole';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { count, utcTime } from '../../journey/format';
import { LabField } from './LabField';
import { LabScreen } from './LabScreen';
import { situationName } from './labPlace';
import styles from './LabScreens.module.css';

/** The settings a visitor can change, by the rule approach they belong to, in the order the list offers them. */
const KNOBS = {
  C1: ['volumeLimit', 'nightStartHour', 'nightEndHour', 'dormant'],
  C2: ['approval', 'ticket', 'assigned', 'assignedLimit', 'history', 'external', 'falseClaim'],
} as const;
type Control = keyof typeof KNOBS;
type Knob = (typeof KNOBS)[Control][number];
const ALL_KNOBS: readonly Knob[] = [...KNOBS.C1, ...KNOBS.C2];
const HOURS = Array.from({ length: 24 }, (_, hour) => hour);
const SWITCHES = new Set<Knob>([
  'dormant',
  'approval',
  'ticket',
  'assigned',
  'history',
  'external',
  'falseClaim',
]);
/** How many changed situations one page of the list shows. */
const PAGE = 3;
/** A date and time as the source line writes them (UTC), kept whole on a line (L-24). */
const DATE_TIME = /\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?/g;

function controlOf(knob: Knob): Control {
  return (KNOBS.C1 as readonly Knob[]).includes(knob) ? 'C1' : 'C2';
}

/** A setting's value as the rules run with it by default (the company's policy row for the assigned-project limit). */
function defaultOf(knob: Knob, defaults: RuleDefaults): number | boolean {
  return knob === 'assignedLimit'
    ? (defaults.settings.assignedLimit ?? defaults.assignedLimit)
    : defaults.settings[knob];
}

/** The value the address carries for a setting, read as the setting's kind; none when it is not one. */
function readValue(knob: Knob, raw: string | null): number | boolean | null {
  if (raw === null) {
    return null;
  }
  if (SWITCHES.has(knob)) {
    return raw === 'on' ? true : raw === 'off' ? false : null;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 0) {
    return null;
  }
  return knob === 'nightStartHour' || knob === 'nightEndHour' ? (value <= 23 ? value : null) : value;
}

/** A setting's value in words: an hour, a count, or on and off. */
function valueText(t: TFunction, knob: Knob, value: number | boolean, language: string): string {
  if (typeof value === 'boolean') {
    return t(value ? 'lab.r7.rules.on' : 'lab.r7.rules.off');
  }
  return knob === 'nightStartHour' || knob === 'nightEndHour'
    ? t('labRules.hour', { h: value })
    : count(value, language);
}

/** One approach's two counts: attacks stopped and legitimate work blocked, out of the cases with a ground truth. */
function Counts({ tally }: { readonly tally: RuleTally }) {
  const { t } = useTranslation();
  return (
    <>
      <td>{t('labRules.ofTotal', { k: tally.attacksStopped, n: tally.attacks })}</td>
      <td>{t('labRules.ofTotal', { k: tally.normalsBlocked, n: tally.normals })}</td>
    </>
  );
}

/**
 * Tightening the rules (화면재편 R7, a table screen): the recorded runs of this demo decided again by the server's real
 * rule classes with one setting changed at a time. Three inputs (the security, one of its settings, its value), what
 * the counts are out of, one table of the two counts (attacks stopped, legitimate work blocked) for that rule approach
 * and for Contexa as recorded, and the situations the change moved, a few at a time. Every count and change is the server's (POST /api/rules/evaluate); the screen computes
 * nothing. The setting and its value are in the address.
 */
export default function LabRulesPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params, setParams] = useSearchParams();
  const view = useRuleCasesView();
  const defaults = view.data?.defaults ?? null;
  const askedKnob = params.get('rule') as Knob | null;
  const knob: Knob = askedKnob && ALL_KNOBS.includes(askedKnob) ? askedKnob : (ALL_KNOBS[0] ?? 'volumeLimit');
  const control = controlOf(knob);
  const chosen = readValue(knob, params.get('value'));
  const settings: RuleSettings | null = defaults
    ? chosen === null
      ? defaults.settings
      : { ...defaults.settings, [knob]: chosen }
    : null;
  const result = useRuleResult(settings);
  const page = Math.max(0, Number(params.get('page') ?? 0) || 0);
  const set = (next: Readonly<Record<string, string | null>>) => {
    const query = new URLSearchParams(params);
    Object.entries(next).forEach(([key, value]) =>
      value === null ? query.delete(key) : query.set(key, value),
    );
    setParams(query, { replace: true });
  };
  const tally = result.data?.tallies[control] ?? null;
  const contexa = result.data?.tallies.D ?? null;
  const changes = result.data?.changed.filter((change) => change.control === control) ?? [];
  const pages = Math.max(1, Math.ceil(changes.length / PAGE));
  const shownPage = page < pages ? page : 0;
  const titleOf = (scenario: string) =>
    situationName(
      t,
      scenario,
      view.data?.cases.find((entry) => entry.scenario === scenario)?.title,
      language,
    );
  const state = (stopped: boolean | null) =>
    t(stopped === null ? 'lab.r7.rules.unknown' : stopped ? 'lab.r7.rules.stops' : 'lab.r7.rules.passes');
  const original = defaults ? defaultOf(knob, defaults) : null;
  const current = chosen ?? original;
  const choose = (value: number | boolean) => {
    const raw = typeof value === 'boolean' ? (value ? 'on' : 'off') : String(value);
    set({ value: value === original ? null : raw, page: null });
  };

  return (
    <LabScreen
      step="rules"
      type="table"
      title={t('lab.r7.rules.title')}
      purpose={t('lab.r7.rules.guide')}
      sourceLine={
        result.data && view.data ? (
          <span>
            {keepWhole(
              t('lab.r7.rules.source', {
                n: count(view.data.cases.length, language),
                from: view.data.recordedFrom ? utcTime(view.data.recordedFrom) : '-',
                to: view.data.recordedTo ? utcTime(view.data.recordedTo) : '-',
              }),
              DATE_TIME,
              styles.whole,
            )}
          </span>
        ) : null
      }
      back={{ to: '/lab', label: t('frame.back') }}
      main={<NextLink to="/lab/case" label={t('lab.r7.rules.next')} />}
    >
      {view.isPending ? <StateScreen kind="loading" /> : null}
      {view.data && !defaults ? <p className={styles.line}>{t('lab.r7.rules.unavailable')}</p> : null}
      {defaults && current !== null && original !== null ? (
        <div className={styles.controls} data-three>
          {/* V-31: the security first, then only its own settings: the approval and assignment checks belong to
              the approval-record rule, never to the fixed rule's list. */}
          <LabField label={t('lab.r7.rules.control')}>
            {(id) => (
              <select
                id={id}
                className={styles.select}
                value={control}
                onChange={(event) =>
                  set({ rule: KNOBS[event.target.value as Control][0], value: null, page: null })
                }
              >
                {(Object.keys(KNOBS) as Control[]).map((group) => (
                  <option key={group} value={group}>
                    {t(`control.${group}.name`)}
                  </option>
                ))}
              </select>
            )}
          </LabField>
          <LabField label={t('lab.r7.rules.knob')}>
            {(id) => (
              <select
                id={id}
                className={styles.select}
                value={knob}
                onChange={(event) => set({ rule: event.target.value, value: null, page: null })}
              >
                {KNOBS[control].map((name) => (
                  <option key={name} value={name}>
                    {t(`lab.r7.rules.knob.${name}`)}
                  </option>
                ))}
              </select>
            )}
          </LabField>
          {knob === 'volumeLimit' || knob === 'assignedLimit' ? (
            <LabField label={t('lab.r7.rules.valueCount', { value: valueText(t, knob, original, language) })}>
              {(id) => (
                <input
                  id={id}
                  className={styles.select}
                  type="number"
                  min={0}
                  value={Number(current)}
                  onChange={(event) => choose(Math.max(0, Math.floor(Number(event.target.value) || 0)))}
                />
              )}
            </LabField>
          ) : (
            <LabField label={t('lab.r7.rules.value')}>
              {(id) => (
                <select
                  id={id}
                  className={styles.select}
                  value={String(current)}
                  onChange={(event) =>
                    choose(SWITCHES.has(knob) ? event.target.value === 'true' : Number(event.target.value))
                  }
                >
                  {(SWITCHES.has(knob) ? [true, false] : HOURS).map((value) => (
                    <option key={String(value)} value={String(value)}>
                      {value === original
                        ? t('lab.r7.rules.default', { value: valueText(t, knob, value, language) })
                        : valueText(t, knob, value, language)}
                    </option>
                  ))}
                </select>
              )}
            </LabField>
          )}
        </div>
      ) : null}
      {tally ? (
        // V-31: what the counts are out of, above them; the benchmark counts other runs.
        <p className={styles.line}>
          {t('lab.r7.rules.scope', {
            attacks: count(tally.attacks, language),
            normals: count(tally.normals, language),
          })}
        </p>
      ) : null}
      {tally && contexa ? (
        <table className={styles.table} data-numbers>
          <thead>
            <tr>
              <th scope="col">{t('lab.r7.rules.col.approach')}</th>
              <th scope="col">{t('lab.r7.rules.col.stopped')}</th>
              <th scope="col">{t('lab.r7.rules.col.blocked')}</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              {/* L-24: the row says whether the rule runs with the visitor's value or the default one. */}
              <th scope="row">
                {t(chosen === null ? 'lab.r7.rules.rowRuleDefault' : 'lab.r7.rules.rowRule', {
                  name: t(`control.${control}.name`),
                })}
              </th>
              <Counts tally={tally} />
            </tr>
            <tr data-contexa>
              <th scope="row">{t('lab.r7.rules.rowContexa')}</th>
              <Counts tally={contexa} />
            </tr>
          </tbody>
        </table>
      ) : null}
      {contexa && contexa.normalsChecked > 0 ? (
        <p className={styles.line}>
          {t('lab.r7.rules.checked', { c: count(contexa.normalsChecked, language) })}
        </p>
      ) : null}
      {tally && tally.undecided > 0 ? (
        <p className={styles.line}>{t('lab.r7.rules.undecided', { n: count(tally.undecided, language) })}</p>
      ) : null}
      {/* L-24: nothing moved is one line; a heading is drawn only over a list of moved situations. */}
      {result.data && changes.length === 0 ? <p className={styles.line}>{t('lab.r7.rules.noChange')}</p> : null}
      {result.data && changes.length > 0 ? (
        <section className={styles.group} aria-labelledby="rules-changed">
          <h2 id="rules-changed" className={styles.changesTitle}>
            {t('lab.r7.rules.changed')}
          </h2>
          <ul className={styles.changes}>
            {changes.slice(shownPage * PAGE, shownPage * PAGE + PAGE).map((change) => (
              <li key={`${change.scenario}-${change.control}`}>
                <span className={styles.strong}>{titleOf(change.scenario)}</span>
                {' · '}
                {t('lab.r7.rules.change', { before: state(change.before), now: state(change.now) })}
              </li>
            ))}
          </ul>
          {pages > 1 ? (
            <button
              type="button"
              className={styles.pageButton}
              onClick={() => set({ page: String((shownPage + 1) % pages) })}
            >
              {t('lab.r7.rules.page', {
                from: shownPage * PAGE + 1,
                to: Math.min(changes.length, shownPage * PAGE + PAGE),
                total: changes.length,
              })}
            </button>
          ) : null}
        </section>
      ) : null}
    </LabScreen>
  );
}
