import { useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useSearchParams } from 'react-router-dom';
import { useRuleCasesView, useRuleResult, type RuleSettings, type RuleTally } from '../../api/rules';
import { ActionChip } from '../../components/common/ActionChip';
import { SourceMark } from '../../components/common/SourceMark';
import { utcTime } from '../../journey/format';
import { NextLink } from '../../components/journey/StepParts';
import { StateScreen } from '../../components/StateScreen';
import { LabScreen } from './LabScreen';
import styles from './LabPages.module.css';

const TABS = ['c1', 'c2'] as const;
type Tab = (typeof TABS)[number];
const HOURS = Array.from({ length: 24 }, (_, hour) => hour);
type Switch = 'dormant' | 'external' | 'falseClaim' | 'approval' | 'ticket' | 'assigned' | 'history';

/** A switch of a rule control: on means the rule checks it. */
function Toggle({
  name,
  checked,
  onChange,
}: {
  readonly name: string;
  readonly checked: boolean;
  readonly onChange: (value: boolean) => void;
}) {
  return (
    <label className={styles.toggle}>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {name}
    </label>
  );
}

/** One approach's two counts: attacks stopped and legitimate work blocked, out of the cases with a ground truth. */
function Counts({ tally, children }: { readonly tally: RuleTally; readonly children?: ReactNode }) {
  const { t } = useTranslation();
  return (
    <dl className={styles.counts}>
      <div className={styles.count} data-tone="good">
        <dt>{t('labRules.stopped')}</dt>
        <dd>{t('labRules.ofTotal', { k: tally.attacksStopped, n: tally.attacks })}</dd>
      </div>
      <div className={styles.count} data-tone={tally.normalsBlocked > 0 ? 'bad' : 'good'}>
        <dt>{t('labRules.blocked')}</dt>
        <dd>{t('labRules.ofTotal', { k: tally.normalsBlocked, n: tally.normals })}</dd>
      </div>
      {children}
    </dl>
  );
}

/**
 * R, tightening the rules (lab-rules, 7.6, H-10): the recorded runs of this demo decided again by the server's real
 * rule classes with the visitor's settings. The two counts, Contexa's recorded counts on the same cases and the cases
 * that changed are the server's (POST /api/rules/evaluate); the screen computes nothing. The tab is in the address.
 */
export default function LabRulesPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get('tab') === 'c2' ? 'c2' : 'c1';
  const view = useRuleCasesView();
  const defaults = view.data?.defaults ?? null;
  const [changed, setChanged] = useState<RuleSettings | null>(null);
  const settings = changed ?? defaults?.settings ?? null;
  const result = useRuleResult(settings);
  const set = (next: Partial<RuleSettings>) => {
    if (settings) {
      setChanged({ ...settings, ...next });
    }
  };
  const control = tab === 'c1' ? 'C1' : 'C2';
  const tally = result.data?.tallies[control] ?? null;
  const contexa = result.data?.tallies.D ?? null;
  const titleOf = (scenario: string) =>
    view.data?.cases.find((entry) => entry.scenario === scenario)?.title[language] ?? scenario;
  const state = (stopped: boolean | null) =>
    t(stopped === null ? 'labRules.unknown' : stopped ? 'labRules.stops' : 'labRules.passes');
  const toggle = (key: Switch) =>
    settings ? (
      <Toggle
        name={t(`labRules.switch.${key}`)}
        checked={settings[key]}
        onChange={(value) => set({ [key]: value })}
      />
    ) : null;
  return (
    <LabScreen
      step="rules"
      title={t('labRules.title')}
      purpose={t('labRules.purpose')}
      source={
        result.data ? (
          <SourceMark kind="ENGINE">
            {t('labRules.source', {
              n: view.data?.cases.length ?? 0,
              from: view.data?.recordedFrom ? utcTime(view.data.recordedFrom) : '-',
              to: view.data?.recordedTo ? utcTime(view.data.recordedTo) : '-',
            })}
          </SourceMark>
        ) : null
      }
      back={{ to: '/lab', label: t('labRules.back') }}
      more={
        changed ? (
          <ActionChip icon="refresh" variant="open" onClick={() => setChanged(null)}>
            {t('labRules.reset')}
          </ActionChip>
        ) : null
      }
      main={<NextLink to="/lab/case" label={t('labRules.next')} />}
    >
      {view.isPending ? <StateScreen kind="loading" /> : null}
      {view.data && !defaults ? <p className={styles.note}>{t('labRules.unavailable')}</p> : null}
      <div className={styles.filters} role="tablist" aria-label={t('labRules.tabs')}>
        {TABS.map((value) => (
          <button
            key={value}
            type="button"
            role="tab"
            className={styles.filter}
            aria-selected={tab === value}
            onClick={() => setParams(value === 'c1' ? {} : { tab: value }, { replace: true })}
          >
            {t(`labRules.tab.${value}`)}
          </button>
        ))}
      </div>
      {settings ? (
        <section className={styles.panel} role="tabpanel" aria-label={t(`labRules.tab.${tab}`)}>
          {tab === 'c1' ? (
            <div className={styles.ruleInputs}>
              <label className={styles.advancedInput}>
                <span>{t('labRules.night')}</span>
                <span className={styles.hours}>
                  <select
                    className={styles.select}
                    aria-label={t('labRules.nightStart')}
                    value={settings.nightStartHour}
                    onChange={(event) => set({ nightStartHour: Number(event.target.value) })}
                  >
                    {HOURS.map((hour) => (
                      <option key={hour} value={hour}>
                        {t('labRules.hour', { h: hour })}
                      </option>
                    ))}
                  </select>
                  ~
                  <select
                    className={styles.select}
                    aria-label={t('labRules.nightEnd')}
                    value={settings.nightEndHour}
                    onChange={(event) => set({ nightEndHour: Number(event.target.value) })}
                  >
                    {HOURS.map((hour) => (
                      <option key={hour} value={hour}>
                        {t('labRules.hour', { h: hour })}
                      </option>
                    ))}
                  </select>
                </span>
              </label>
              <label className={styles.advancedInput}>
                <span>{t('labRules.volume')}</span>
                <input
                  className={styles.select}
                  type="number"
                  min={0}
                  value={settings.volumeLimit}
                  onChange={(event) => set({ volumeLimit: Math.max(0, Number(event.target.value) || 0) })}
                />
              </label>
              {toggle('dormant')}
            </div>
          ) : (
            <div className={styles.ruleInputs}>
              {toggle('approval')}
              {toggle('ticket')}
              {toggle('assigned')}
              <details className={styles.advanced}>
                <summary>{t('labRules.more')}</summary>
                <div className={styles.ruleInputs}>
                  <label className={styles.advancedInput}>
                    <span>{t('labRules.assignedLimit')}</span>
                    <input
                      className={styles.select}
                      type="number"
                      min={0}
                      value={settings.assignedLimit ?? defaults?.assignedLimit ?? 0}
                      onChange={(event) =>
                        set({ assignedLimit: Math.max(0, Number(event.target.value) || 0) })
                      }
                    />
                  </label>
                  {toggle('history')}
                  {toggle('external')}
                  {toggle('falseClaim')}
                </div>
              </details>
            </div>
          )}
        </section>
      ) : null}
      {tally ? (
        <Counts tally={tally}>
          {tally.undecided > 0 ? (
            <p className={styles.note}>{t('labRules.undecided', { n: tally.undecided })}</p>
          ) : null}
        </Counts>
      ) : null}
      {contexa ? (
        <p className={styles.contexaLine}>
          {t('labRules.contexa', {
            k: contexa.attacksStopped,
            n: contexa.attacks,
            m: contexa.normalsBlocked,
            p: contexa.normals,
            c: contexa.normalsChecked,
          })}
        </p>
      ) : null}
      {result.data ? (
        <section className={styles.panel} aria-labelledby="rules-changed">
          <h2 id="rules-changed" className={styles.panelTitle}>
            {t('labRules.changed')}
          </h2>
          {result.data.changed.filter((change) => change.control === control).length === 0 ? (
            <p className={styles.note}>{t('labRules.noChange')}</p>
          ) : (
            <ul className={styles.changes}>
              {result.data.changed
                .filter((change) => change.control === control)
                .map((change) => (
                  <li key={`${change.scenario}-${change.control}`}>
                    <span className={styles.changeCase}>{titleOf(change.scenario)}</span>
                    {t('labRules.change', { before: state(change.before), now: state(change.now) })}
                  </li>
                ))}
            </ul>
          )}
        </section>
      ) : null}
    </LabScreen>
  );
}
