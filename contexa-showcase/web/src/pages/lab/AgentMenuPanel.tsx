import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAgentMenu, useAgentMenuAnswer, type AgentMenuAnswer } from '../../api/agentMenu';
import { Chip } from '../../components/main/Chip';
import { SourceBadge } from '../../components/main/SourceBadge';
import { SubjectChip } from '../../components/main/SubjectChip';
import type { Subject } from '../../domain/subject';
import { count } from '../../journey/format';
import { AgentTimeline } from '../main/AgentTimeline';
import { ResultLanes, ResultSummary } from '../main/AgentResultParts';
import { layersOf } from '../main/agentGroup';
import { ageOf } from './menuAge';
import styles from './AgentMenuPanel.module.css';

/** Who sends the requests on each path of the menu. */
const SUBJECT_OF_PATH: Readonly<Record<string, Subject>> = {
  OAUTH2_DELEGATED: 'delegated',
  OAUTH2_AGENT: 'autonomous',
  SESSION: 'session',
};

type Guess = 'stop' | 'pass' | 'show';

/**
 * The agent menu (docs/agent Agent중심-화면 AC-4a): a finite table of cases and the paths an agent sends on, each
 * combination run once a day with the real engine and stored. The visitor picks a case and a path, may guess first
 * whether Contexa will stop the work, and then reads the stored run: the proof, the five approaches as lanes and every
 * request. Nothing is sent to a model; the screen says so and how long ago the run was made, and marks an answer that is
 * old or ran an older definition of the case.
 */
export function AgentMenuPanel() {
  const { t } = useTranslation();
  const menu = useAgentMenu().data ?? null;
  const [picked, setPicked] = useState<{ readonly caseKey: string; readonly path: string } | null>(null);
  if (menu === null || menu.cases.length === 0) {
    return null;
  }
  // The first combination with a stored answer is shown until the visitor picks one, so the screen is never empty.
  const first = menu.items[0];
  const caseKey = picked?.caseKey ?? first?.caseKey ?? menu.cases[0]?.key ?? null;
  const path = picked?.path ?? first?.path ?? menu.paths[0] ?? null;
  const stored = new Set(menu.items.map((item) => `${item.caseKey}/${item.path}`));
  return (
    <section className={styles.menu} aria-labelledby="lab-agent-menu">
      <h2 id="lab-agent-menu" className={styles.heading}>
        {t('labAgent.menu.title')}
      </h2>
      <p className={styles.line}>{t('labAgent.menu.intro')}</p>
      <fieldset className={styles.group} role="radiogroup" aria-label={t('labAgent.menu.case')}>
        <legend className={styles.legend}>{t('labAgent.menu.case')}</legend>
        {menu.cases.map((option) => (
          <label key={option.key} className={styles.choice} data-selected={caseKey === option.key || undefined}>
            <input
              type="radio"
              name="agent-menu-case"
              className="visually-hidden"
              value={option.key}
              checked={caseKey === option.key}
              onChange={() => setPicked({ caseKey: option.key, path: path ?? '' })}
            />
            <MenuText title={option.title} />
          </label>
        ))}
      </fieldset>
      <fieldset className={styles.group} role="radiogroup" aria-label={t('labAgent.menu.path')}>
        <legend className={styles.legend}>{t('labAgent.menu.path')}</legend>
        {menu.paths.map((option) => {
          const subject = SUBJECT_OF_PATH[option];
          return (
            <label key={option} className={styles.choice} data-selected={path === option || undefined}>
              <input
                type="radio"
                name="agent-menu-path"
                className="visually-hidden"
                value={option}
                checked={path === option}
                onChange={() => setPicked({ caseKey: caseKey ?? '', path: option })}
              />
              {subject ? <SubjectChip subject={subject} /> : null}
              <span>{t(`labAgent.menu.path.${option}`)}</span>
              {caseKey && !stored.has(`${caseKey}/${option}`) ? (
                <span className={styles.hint}>{t('labAgent.menu.notYet')}</span>
              ) : null}
            </label>
          );
        })}
      </fieldset>
      <MenuResult caseKey={caseKey} path={path} />
    </section>
  );
}

/** A case's title in the visitor's language. */
function MenuText({ title }: { readonly title: Readonly<Record<'ko' | 'en', string>> }) {
  const { i18n } = useTranslation();
  return <span>{title[i18n.language === 'ko' ? 'ko' : 'en']}</span>;
}

function MenuResult({ caseKey, path }: { readonly caseKey: string | null; readonly path: string | null }) {
  const { t } = useTranslation();
  const answer = useAgentMenuAnswer(caseKey, path);
  return (
    <section className={styles.result} aria-labelledby="lab-agent-menu-result">
      <h3 id="lab-agent-menu-result" className="visually-hidden">
        {t('labAgent.menu.result')}
      </h3>
      {answer.isPending ? <p className={styles.line}>{t('labAgent.menu.loading')}</p> : null}
      {answer.isError ? <p className={styles.line}>{t('labAgent.menu.noAnswer')}</p> : null}
      {answer.data ? <StoredAnswer key={`${answer.data.caseKey}/${answer.data.path}`} answer={answer.data} /> : null}
    </section>
  );
}

/** One stored answer: the case, how long ago it ran for real, the visitor's guess, and then the run itself. */
export function StoredAnswer({ answer }: { readonly answer: AgentMenuAnswer }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const [guess, setGuess] = useState<Guess | null>(null);
  // The age is read once when the answer is shown; it does not tick while the visitor reads.
  const [shownAt] = useState(() => Date.now());
  const run = answer.run;
  const proof = run.proof ?? null;
  const stopped = proof?.controls['D']?.firstStopStep != null;
  const age = ageOf(answer.ranAt, shownAt);
  const summary = answer.caseView.delegation?.summary[language];
  return (
    <div className={styles.answer}>
      <b className={styles.caseTitle}>{answer.caseView.title[language]}</b>
      {summary ? <span className={styles.line}>{t('labAgent.work', { summary })}</span> : null}
      <p className={styles.badges}>
        <SourceBadge
          kind="other"
          label={t(`labAgent.menu.age.${age.unit}`, { n: count(age.n, i18n.language) })}
        />
        {answer.stale ? <Chip kind="wait">{t('labAgent.menu.stale')}</Chip> : null}
      </p>
      <fieldset className={styles.guess}>
        <legend className={styles.legend}>{t('labAgent.menu.guess')}</legend>
        <button type="button" className={styles.guessButton} data-selected={guess === 'stop' || undefined}
          onClick={() => setGuess('stop')}>
          {t('labAgent.menu.guess.stop')}
        </button>
        <button type="button" className={styles.guessButton} data-selected={guess === 'pass' || undefined}
          onClick={() => setGuess('pass')}>
          {t('labAgent.menu.guess.pass')}
        </button>
        {guess === null ? (
          <button type="button" className={styles.guessButton} onClick={() => setGuess('show')}>
            {t('labAgent.menu.guess.show')}
          </button>
        ) : null}
      </fieldset>
      {guess === 'stop' || guess === 'pass' ? (
        <p className={styles.verdict} role="status">
          {(guess === 'stop') === stopped ? t('labAgent.menu.guess.right') : t('labAgent.menu.guess.wrong')}
        </p>
      ) : null}
      {guess !== null && proof ? (
        <div className={styles.run}>
          <ResultSummary run={run} proof={proof} language={i18n.language} />
          <ResultLanes proof={proof} language={i18n.language} />
          <AgentTimeline rows={run.steps.map((step) => ({ stepNo: step.stepNo, layers: layersOf(step), step }))} />
        </div>
      ) : null}
    </div>
  );
}
