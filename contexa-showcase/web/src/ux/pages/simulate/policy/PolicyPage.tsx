import { useEffect, useState } from 'react';
import { useQueries } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { postJson } from '../../../../api/http';
import { useVisitor } from '../../../../api/queries';
import { useRuleCasesView, useRuleResult, type RuleResult, type RuleSettings } from '../../../../api/rules';
import { formatNumber, formatUtc } from '../../../format';
import { CONTROL_TONE } from '../../../simulate/controls';
import {
  Bar,
  Button,
  Field,
  Loading,
  Note,
  PageHead,
  Range,
  Select,
  Switch,
  TabPanel,
  Tabs,
  TextInput,
} from '../../../ui';
import { AgentPolicyTab } from './AgentPolicyTab';
import { ComposeTab } from './ComposeTab';
import sim from '../../../simulate/Simulate.module.css';
import styles from './Policy.module.css';

type TabId = 'threshold' | 'compose' | 'agent';
const TABS: readonly TabId[] = ['threshold', 'compose', 'agent'];

/** The settings a visitor may change, by the rule control that holds them (the rule classes of the plain workload). */
const KNOBS = {
  C1: ['volumeLimit', 'nightStartHour', 'nightEndHour', 'dormant'],
  C2: ['approval', 'ticket', 'assigned', 'assignedLimit', 'history', 'external', 'falseClaim'],
} as const;
type RuleControl = keyof typeof KNOBS;
type Knob = (typeof KNOBS)[RuleControl][number];
const COUNTS: readonly Knob[] = ['volumeLimit', 'assignedLimit'];
const HOURS: readonly Knob[] = ['nightStartHour', 'nightEndHour'];
/** The values the per-value table decides again (기획안 7.7, DEC-32). */
const SWEEP = [0, 50, 100, 200, 300, 400, 500, 1000];
/** The most a count may be: the server refuses more (RuleEvaluation.MAX_ITEMS). */
const MAX_COUNT = 1_000_000;

const controlOf = (knob: Knob): RuleControl => ((KNOBS.C1 as readonly string[]).includes(knob) ? 'C1' : 'C2');
const isKnob = (value: string | null): value is Knob =>
  value !== null && [...KNOBS.C1, ...KNOBS.C2].includes(value as Knob);

/**
 * The policy simulator (기획안 7.7): the rule controls' thresholds decided again over this demo's real runs by the
 * server's rule engine (no request is sent, no model is called), the composition of one changed condition sent as a
 * real run, and the agent policy's stored answers. Each tab keeps its place in the address (`?tab=`).
 */
export default function PolicyPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const asked = params.get('tab');
  const tab: TabId = TABS.includes(asked as TabId) ? (asked as TabId) : 'threshold';
  const select = (id: string) => setParams(new URLSearchParams({ tab: id }), { replace: true });
  return (
    <>
      <PageHead
        title={t('ux.policy.title')}
        desc={t(`ux.policy.desc.${tab}`)}
        actions={
          tab === 'threshold' && (params.has('knob') || params.has('value')) ? (
            <Button variant="secondary" icon="rotate-ccw" onClick={() => select('threshold')}>
              {t('ux.policy.reset')}
            </Button>
          ) : null
        }
      />
      <Tabs
        idBase="policy"
        label={t('ux.policy.tabs')}
        value={tab}
        onChange={select}
        items={TABS.map((id) => ({ id, label: t(`ux.policy.tab.${id}`) }))}
      />
      <TabPanel idBase="policy" id={tab}>
        {tab === 'threshold' ? <ThresholdTab /> : tab === 'compose' ? <ComposeTab /> : <AgentPolicyTab />}
      </TabPanel>
    </>
  );
}

/** The value as the address holds it, in the knob's own type; null keeps the company's default. */
function readValue(knob: Knob, raw: string | null): number | boolean | null {
  if (raw === null) {
    return null;
  }
  if (COUNTS.includes(knob)) {
    const value = Math.floor(Number(raw));
    return Number.isFinite(value) ? Math.min(MAX_COUNT, Math.max(0, value)) : null;
  }
  if (HOURS.includes(knob)) {
    const value = Math.floor(Number(raw));
    return Number.isFinite(value) && value >= 0 && value <= 23 ? value : null;
  }
  return raw === 'on' ? true : raw === 'off' ? false : null;
}

function writeValue(value: number | boolean): string {
  return typeof value === 'boolean' ? (value ? 'on' : 'off') : String(value);
}

/** A value that settles 0.3 s after the last change (DEC-32): the server is asked once the visitor stops. */
function useSettled<T>(value: T, ms = 300): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(timer);
  }, [value, ms]);
  return settled;
}

function ThresholdTab() {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const [params, setParams] = useSearchParams();
  const view = useRuleCasesView();
  // A write needs the CSRF token the visitor answer writes; the rule engine is asked once the visitor is known.
  const visitor = useVisitor();
  const defaults = view.data?.defaults ?? null;
  const asked = params.get('knob');
  const knob: Knob = isKnob(asked) ? asked : 'volumeLimit';
  const control = controlOf(knob);
  const chosen = readValue(knob, params.get('value'));
  const original: number | boolean | null = defaults
    ? knob === 'assignedLimit'
      ? (defaults.settings.assignedLimit ?? defaults.assignedLimit)
      : (defaults.settings[knob] as number | boolean)
    : null;
  const current = chosen ?? original;
  const [draft, setDraft] = useState<number | boolean | null>(null);
  const shown = draft ?? current;
  const settled = useSettled(shown);
  useEffect(() => {
    if (settled === null || settled === current) {
      return;
    }
    const next = new URLSearchParams(params);
    next.set('tab', 'threshold');
    next.set('knob', knob);
    next.set('value', writeValue(settled));
    setParams(next, { replace: true });
    // The address follows the settled value only; the other parameters are read when it settles.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [settled]);
  const settings: RuleSettings | null =
    visitor.isSuccess && defaults && current !== null ? { ...defaults.settings, [knob]: current } : null;
  const result = useRuleResult(settings);
  const choose = (next: Knob) => {
    setDraft(null);
    setParams(new URLSearchParams({ tab: 'threshold', knob: next }), { replace: true });
  };

  if (view.isPending) {
    return <Loading rows={6} />;
  }
  if (!defaults || !view.data) {
    return <Note tone="warn">{t('ux.policy.unavailable')}</Note>;
  }
  const cases = view.data.cases;
  const attacks = cases.filter((item) => item.classification === 'THREAT').length;
  const normals = cases.filter((item) => item.classification === 'NORMAL').length;
  const changes = result.data?.changed.filter((change) => change.control === control) ?? [];
  const isDefault = current === original;
  // UC-5 L-rules: the control's handling with the default and with this value, as the rule engine gave it (null unknown).
  const stateOf = (stopped: boolean | null) =>
    t(`ux.policy.changes.state.${stopped === null ? 'unknown' : stopped ? 'stops' : 'passes'}`);
  return (
    <div className={styles.stack}>
      <section className={styles.card} aria-label={t('ux.policy.setting')}>
        <div className={styles.pickers}>
          <Field label={t('ux.policy.control')}>
            {(props) => (
              <Select {...props} value={control} onChange={(event) => choose(KNOBS[event.target.value as RuleControl][0])}>
                {(['C1', 'C2'] as const).map((id) => (
                  <option key={id} value={id}>
                    {t(`ux.control.${id}`)} ({id})
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label={t('ux.policy.knob')}>
            {(props) => (
              <Select {...props} value={knob} onChange={(event) => choose(event.target.value as Knob)}>
                {KNOBS[control].map((id) => (
                  <option key={id} value={id}>
                    {t(`ux.policy.knobs.${id}`)}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <div className={styles.value}>
          {COUNTS.includes(knob) && typeof shown === 'number' ? (
            <>
              <div className={styles.valueHead}>
                <div>
                  <p className={styles.valueTitle}>{t(`ux.policy.knobs.${knob}`)}</p>
                  <p className={styles.valueHint}>
                    {t(`ux.policy.hint.${knob}`, { n: typeof original === 'number' ? n(original) : '—' })}
                  </p>
                </div>
                <label className={styles.valueBox}>
                  <TextInput
                    compact
                    inputMode="numeric"
                    aria-label={t(`ux.policy.knobs.${knob}`)}
                    value={String(shown)}
                    onChange={(event) => {
                      const value = Math.floor(Number(event.target.value.replace(/[^0-9]/g, '')) || 0);
                      setDraft(Math.min(MAX_COUNT, Math.max(0, value)));
                    }}
                  />
                  <span>{t('ux.policy.unit')}</span>
                </label>
              </div>
              <Range
                label={t('ux.policy.range', { name: t(`ux.policy.knobs.${knob}`) })}
                min={0}
                max={1000}
                step={10}
                value={Math.min(1000, shown)}
                onChange={(value) => setDraft(value)}
                display={t('ux.facts.items', { count: shown, n: n(shown) })}
              />
            </>
          ) : HOURS.includes(knob) && typeof shown === 'number' ? (
            <Field label={t(`ux.policy.knobs.${knob}`)} hint={t(`ux.policy.hint.${knob}`, { n: original ?? '—' })}>
              {(props) => (
                <Select {...props} value={shown} onChange={(event) => setDraft(Number(event.target.value))}>
                  {Array.from({ length: 24 }, (_, hour) => (
                    <option key={hour} value={hour}>
                      {t('ux.policy.hour', { n: hour })}
                      {hour === original ? ` · ${t('ux.policy.default')}` : ''}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          ) : typeof shown === 'boolean' ? (
            <div className={styles.valueHead}>
              <div>
                <p className={styles.valueTitle}>{t(`ux.policy.knobs.${knob}`)}</p>
                <p className={styles.valueHint}>{t(`ux.policy.hint.${knob}`)}</p>
              </div>
              <Switch
                label={t(shown ? 'ux.policy.on' : 'ux.policy.off')}
                checked={shown}
                onChange={(value) => setDraft(value)}
              />
            </div>
          ) : null}
        </div>
        {result.isError ? <Note tone="warn">{t('ux.policy.failed')}</Note> : null}
        <Tallies result={result.data ?? null} control={control} knob={knob} current={current} isDefault={isDefault} />
      </section>

      {COUNTS.includes(knob) && visitor.isSuccess ? (
        <Sweep knob={knob} defaults={defaults.settings} chosen={current} />
      ) : null}

      {changes.length > 0 ? (
        <section className={styles.card} aria-labelledby="policy-changes">
          <header className={styles.cardHead}>
            <h2 id="policy-changes" className={styles.cardTitle}>
              {t('ux.policy.changes.title', { n: changes.length })}
            </h2>
            <p className={styles.cardSub}>{t('ux.policy.changes.sub')}</p>
          </header>
          <ul className={styles.changes}>
            {changes.map((change) => {
              const title = cases.find((item) => item.scenario === change.scenario)?.title;
              return (
                <li key={change.scenario}>
                  <span className={styles.changeKey}>{change.scenario}</span>
                  <span>{title?.[i18n.language === 'ko' ? 'ko' : 'en'] ?? change.scenario}</span>
                  <span className={styles.changeWas}>
                    {t(`ux.policy.changes.${change.classification === 'THREAT' ? 'attack' : 'normal'}`)} ·{' '}
                    {t('ux.policy.changes.move', { before: stateOf(change.before), now: stateOf(change.now) })}
                  </span>
                </li>
              );
            })}
          </ul>
        </section>
      ) : result.data ? (
        // UC-5 L-rules: the server found no scenario decided differently; the old screen said so in one line.
        <Note>{t('ux.policy.changes.none')}</Note>
      ) : null}

      <Note>
        {t('ux.policy.scope', {
          n: n(cases.length),
          attacks: n(attacks),
          normals: n(normals),
          from: view.data.recordedFrom ? formatUtc(view.data.recordedFrom).slice(0, 10) : '—',
          to: view.data.recordedTo ? formatUtc(view.data.recordedTo).slice(0, 10) : '—',
        })}
      </Note>
    </div>
  );
}

/** Each rule control and Contexa over the same runs: attacks stopped and normal work blocked, with a word on each. */
function Tallies({
  result,
  control,
  knob,
  current,
  isDefault,
}: {
  readonly result: RuleResult | null;
  readonly control: RuleControl;
  readonly knob: Knob;
  readonly current: number | boolean | null;
  readonly isDefault: boolean;
}) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  if (!result) {
    return <Loading rows={3} />;
  }
  const value =
    typeof current === 'number'
      ? COUNTS.includes(knob)
        ? t('ux.facts.items', { count: current, n: n(current) })
        : t('ux.policy.hour', { n: current })
      : t(current ? 'ux.policy.on' : 'ux.policy.off');
  const rows = (['C1', 'C2', 'D'] as const).map((id) => {
    const tally = result.tallies[id];
    const note =
      id === 'D'
        ? tally && tally.normalsChecked > 0
          ? t('ux.policy.note.contexaChecked', { n: n(tally.normalsChecked) })
          : t('ux.policy.note.contexa')
        : id === control
          ? isDefault
            ? t('ux.policy.note.default')
            : t('ux.policy.note.changed')
          : t('ux.policy.note.unrelated');
    const sub =
      id === 'D'
        ? t('ux.policy.sub.contexa')
        : id === control
          ? `${t(`ux.policy.knobs.${knob}`)} ${value}`
          : t('ux.policy.sub.unrelated');
    return { id, tally, note, sub };
  });
  return (
    <div className={styles.tableScroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
      <table className={styles.table}>
        <caption className="ux-sr-only">{t('ux.policy.tallies')}</caption>
        <thead>
          <tr>
            <th scope="col">{t('ux.lanes.control')}</th>
            <th scope="col">{t('ux.policy.col.attacks')}</th>
            <th scope="col">{t('ux.policy.col.normals')}</th>
            <th scope="col">{t('ux.policy.col.note')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ id, tally, note, sub }) => (
            <tr key={id} data-contexa={id === 'D' || undefined}>
              <th scope="row">
                <span className={styles.rowName}>
                  <span className={sim.swatch} data-tone={CONTROL_TONE[id]} aria-hidden="true" />
                  <span>
                    {t(`ux.control.${id}`)}
                    <small>{sub}</small>
                  </span>
                </span>
              </th>
              <td>
                {tally ? (
                  <span className={styles.meter}>
                    <Bar
                      label={t('ux.policy.col.attacks')}
                      value={tally.attacks ? tally.attacksStopped / tally.attacks : 0}
                      tone={id === 'D' ? 'brand' : CONTROL_TONE[id] === 'rule' ? 'rule' : 'approval'}
                    />
                    <b>
                      {n(tally.attacksStopped)} / {n(tally.attacks)}
                    </b>
                  </span>
                ) : (
                  '—'
                )}
              </td>
              <td>
                {tally ? (
                  <span className={styles.meter}>
                    <Bar
                      label={t('ux.policy.col.normals')}
                      value={tally.normals ? tally.normalsBlocked / tally.normals : 0}
                      tone="block"
                    />
                    <b>
                      {n(tally.normalsBlocked)} / {n(tally.normals)}
                    </b>
                  </span>
                ) : (
                  '—'
                )}
              </td>
              <td className={styles.note}>
                {note}
                {tally && tally.undecided > 0 ? ` · ${t('ux.policy.note.undecided', { n: n(tally.undecided) })}` : ''}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** The same runs decided again at each value of the count (기획안 7.7 상한값별 결과): eight calls to the rule engine. */
function Sweep({
  knob,
  defaults,
  chosen,
}: {
  readonly knob: Knob;
  readonly defaults: RuleSettings;
  readonly chosen: number | boolean | null;
}) {
  const { t, i18n } = useTranslation();
  const n = (value: number) => formatNumber(value, i18n.language);
  const control = controlOf(knob);
  const answers = useQueries({
    queries: SWEEP.map((value) => {
      const settings = { ...defaults, [knob]: value };
      return {
        queryKey: ['rule-result', settings],
        queryFn: async () => {
          const answer = await postJson<RuleResult>('/api/rules/evaluate', settings);
          if (answer.status !== 200 || answer.body === null) {
            throw new Error(`The rule evaluation answered ${answer.status}`);
          }
          return answer.body;
        },
        staleTime: Infinity,
        retry: false,
      };
    }),
  });
  const tallies = answers.map((answer) => answer.data?.tallies[control] ?? null);
  const contexa = answers.find((answer) => answer.data)?.data?.tallies.D ?? null;
  const base = knob === 'assignedLimit' ? (defaults.assignedLimit ?? null) : (defaults[knob] as number);
  const lowest = tallies[0] ?? null;
  const atBase = base !== null ? (tallies[SWEEP.indexOf(base)] ?? null) : null;
  const insight =
    lowest && atBase && base !== null && base !== 0
      ? {
          detected: lowest.attacksStopped - atBase.attacksStopped,
          blocked: lowest.normalsBlocked - atBase.normalsBlocked,
          lowest,
          atBase,
        }
      : null;
  return (
    <section className={styles.card} aria-labelledby="policy-sweep">
      <header className={styles.cardHead}>
        <h2 id="policy-sweep" className={styles.cardTitle}>
          {t('ux.policy.sweep.title')}
        </h2>
        <p className={styles.cardSub}>{t('ux.policy.sweep.sub')}</p>
      </header>
      {answers.some((answer) => answer.isError) ? <Note tone="warn">{t('ux.policy.failed')}</Note> : null}
      <div className={styles.tableScroll} role="region" aria-label={t('ux.table.scroll')} tabIndex={0}>
        <table className={styles.sweep}>
          <caption className="ux-sr-only">{t('ux.policy.sweep.title')}</caption>
          <thead>
            <tr>
              <th scope="col">{t(`ux.policy.knobs.${knob}`)}</th>
              {SWEEP.map((value) => (
                <th key={value} scope="col" data-current={value === chosen || undefined}>
                  {n(value)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            <tr>
              <th scope="row">{t('ux.policy.sweep.attacks', { n: tallies.find(Boolean)?.attacks ?? '' })}</th>
              {tallies.map((tally, index) => (
                <td key={SWEEP[index]} data-current={SWEEP[index] === chosen || undefined}>
                  {tally ? n(tally.attacksStopped) : '…'}
                </td>
              ))}
            </tr>
            <tr>
              <th scope="row">{t('ux.policy.sweep.normals', { n: tallies.find(Boolean)?.normals ?? '' })}</th>
              {tallies.map((tally, index) => (
                <td key={SWEEP[index]} data-current={SWEEP[index] === chosen || undefined}>
                  {tally ? n(tally.normalsBlocked) : '…'}
                </td>
              ))}
            </tr>
          </tbody>
        </table>
      </div>
      {contexa ? (
        <p className={styles.contexaLine}>
          <span>{t('ux.policy.sweep.contexa')}</span>
          <span>
            {t('ux.policy.sweep.contexaValue', {
              stopped: n(contexa.attacksStopped),
              attacks: n(contexa.attacks),
              blocked: n(contexa.normalsBlocked),
              normals: n(contexa.normals),
            })}
          </span>
        </p>
      ) : null}
      {insight ? (
        <div className={styles.insight}>
          <p className={styles.insightTitle}>
            {t(
              insight.blocked > insight.detected
                ? 'ux.policy.insight.moreBlocked'
                : insight.blocked < insight.detected
                  ? 'ux.policy.insight.moreDetected'
                  : 'ux.policy.insight.even',
            )}
          </p>
          <p className={styles.insightText}>
            {t('ux.policy.insight.text', {
              from: n(base ?? 0),
              to: n(SWEEP[0] ?? 0),
              a1: n(insight.atBase.attacksStopped),
              a2: n(insight.lowest.attacksStopped),
              b1: n(insight.atBase.normalsBlocked),
              b2: n(insight.lowest.normalsBlocked),
            })}
          </p>
        </div>
      ) : null}
    </section>
  );
}
