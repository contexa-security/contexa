import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { RuleCase, RuleSettings } from '../../domain/rules';
import { DEFAULT_SETTINGS, score, stoppedByContexa, stoppedByRules } from '../../domain/rules';
import styles from './RulesScene.module.css';

interface RulesSceneProps {
  readonly cases: readonly RuleCase[];
  readonly onNext: () => void;
}

const VOLUME_STEPS = [20, 100, 300, 500, 1000, 5000, 10000] as const;
const HOURS = Array.from({ length: 24 }, (_, hour) => hour);

type Switch = 'dormant' | 'external' | 'falseClaim' | 'approval' | 'ticket' | 'assigned' | 'history';
const THRESHOLD_SWITCHES: readonly Switch[] = ['dormant'];
const RECORD_SWITCHES: readonly Switch[] = [
  'approval',
  'ticket',
  'assigned',
  'history',
  'external',
  'falseClaim',
];

/**
 * Scene 4 of docs/showcase/화면설계서.md: the visitor tightens and loosens the two rule controls and sees, on real
 * runs, that a setting which stops more attacks halts more legitimate work. The rules are recomputed with the
 * server's own formulas; Contexa's score is the same cases' real outcome, shown on request.
 */
export function RulesScene({ cases, onNext }: RulesSceneProps) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [settings, setSettings] = useState<RuleSettings>(DEFAULT_SETTINGS);
  const [revealed, setRevealed] = useState(false);
  const rules = score(cases, (rule) => stoppedByRules(rule, settings));
  const contexa = score(cases, stoppedByContexa);
  const date = new Intl.DateTimeFormat(language === 'ko' ? 'ko-KR' : 'en-US', {
    dateStyle: 'medium',
    timeZone: 'UTC',
  });

  function set<K extends keyof RuleSettings>(key: K, value: RuleSettings[K]) {
    setSettings((current) => ({ ...current, [key]: value }));
  }

  return (
    <div className={styles.scene}>
      <header className={styles.head}>
        <h1 className={styles.title} tabIndex={-1}>
          {t('rules.title')}
        </h1>
        <p className={styles.lead}>{t('rules.lead')}</p>
      </header>

      <section className={styles.board} aria-live="polite" aria-label={t('rules.board')}>
        <p className={styles.score} data-tone="safe">
          <span className={styles.number}>
            {rules.attacksStopped}/{rules.attacks}
          </span>
          <span className={styles.label}>{t('rules.attacksStopped')}</span>
        </p>
        <p className={styles.score} data-tone="halt">
          <span className={styles.number}>
            {rules.workHalted}/{rules.work}
          </span>
          <span className={styles.label}>{t('rules.workHalted')}</span>
        </p>
        {revealed ? (
          <p className={styles.contexa}>
            <span className={styles.contexaName}>Contexa</span>
            {t('rules.contexaScore', {
              stopped: contexa.attacksStopped,
              attacks: contexa.attacks,
              halted: contexa.workHalted,
              work: contexa.work,
            })}
            <span className={styles.contexaNote}>{t('rules.contexaNote')}</span>
          </p>
        ) : (
          <button type="button" className={styles.reveal} onClick={() => setRevealed(true)}>
            {t('rules.reveal')}
          </button>
        )}
      </section>

      <section className={styles.controls} aria-labelledby="rules-threshold">
        <h2 id="rules-threshold" className={styles.groupTitle}>
          {t('control.C1.name')}
        </h2>
        <div className={styles.row}>
          <label className={styles.field}>
            <span>{t('rules.nightStart')}</span>
            <select
              value={settings.nightStart}
              onChange={(event) => set('nightStart', Number(event.target.value))}
            >
              {HOURS.map((hour) => (
                <option key={hour} value={hour}>
                  {t('rules.hour', { hour })}
                </option>
              ))}
            </select>
          </label>
          <label className={styles.field}>
            <span>{t('rules.nightEnd')}</span>
            <select
              value={settings.nightEnd}
              onChange={(event) => set('nightEnd', Number(event.target.value))}
            >
              {HOURS.map((hour) => (
                <option key={hour} value={hour}>
                  {t('rules.hour', { hour })}
                </option>
              ))}
            </select>
          </label>
          <label className={styles.field}>
            <span>{t('rules.volume', { n: settings.volumeLimit.toLocaleString() })}</span>
            <input
              type="range"
              min={0}
              max={VOLUME_STEPS.length - 1}
              value={Math.max(0, VOLUME_STEPS.indexOf(settings.volumeLimit as (typeof VOLUME_STEPS)[number]))}
              onChange={(event) => set('volumeLimit', VOLUME_STEPS[Number(event.target.value)] ?? 500)}
            />
          </label>
        </div>
        {THRESHOLD_SWITCHES.map((key) => (
          <SwitchRow key={key} name={key} on={settings[key]} onChange={(on) => set(key, on)} />
        ))}
        <h2 className={styles.groupTitle}>{t('control.C2.name')}</h2>
        {RECORD_SWITCHES.map((key) => (
          <SwitchRow key={key} name={key} on={settings[key]} onChange={(on) => set(key, on)} />
        ))}
        <p className={styles.formula}>{t('rules.formula')}</p>
        <button type="button" className={styles.reset} onClick={() => setSettings(DEFAULT_SETTINGS)}>
          {t('rules.reset')}
        </button>
      </section>

      <section className={styles.cases} aria-labelledby="rules-cases">
        <h2 id="rules-cases" className={styles.groupTitle}>
          {t('rules.cases')}
        </h2>
        <ul className={styles.caseList}>
          {cases.map((rule) => {
            const stopped = stoppedByRules(rule, settings);
            const threat = rule.classification === 'THREAT';
            const tone = threat ? (stopped ? 'safe' : 'loss') : stopped ? 'halt' : 'flow';
            return (
              <li key={rule.scenario} className={styles.case} data-tone={tone}>
                <span className={styles.caseKind}>{t(threat ? 'rules.attack' : 'rules.work')}</span>
                <span className={styles.caseTitle}>{rule.title[language] ?? rule.scenario}</span>
                <span className={styles.caseResult}>{t(stopped ? 'rules.stopped' : 'rules.passed')}</span>
                {revealed ? (
                  <span className={styles.caseContexa}>
                    {t(stoppedByContexa(rule) ? 'rules.contexaStopped' : 'rules.contexaPassed')}
                  </span>
                ) : null}
                <span className={styles.caseMeta}>
                  {t('rules.record', {
                    run: rule.runId,
                    date: rule.finishedAt ? date.format(new Date(rule.finishedAt)) : '—',
                  })}
                </span>
              </li>
            );
          })}
        </ul>
      </section>

      <nav className={styles.next} aria-label={t('show.act.label')}>
        <button type="button" className={styles.primary} onClick={onNext}>
          {t('show.next.adopt')}
        </button>
      </nav>
    </div>
  );
}

function SwitchRow({
  name,
  on,
  onChange,
}: {
  readonly name: Switch;
  readonly on: boolean;
  readonly onChange: (on: boolean) => void;
}) {
  const { t } = useTranslation();
  return (
    <label className={styles.switch}>
      <input type="checkbox" checked={on} onChange={(event) => onChange(event.target.checked)} />
      <span>{t(`rules.switch.${name}`)}</span>
    </label>
  );
}
