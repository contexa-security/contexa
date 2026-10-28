import { useTranslation } from 'react-i18next';
import { useLabOptions } from '../../api/lab';
import type { PromptFact } from '../../api/promptQuality';
import { useDetail } from '../../components/detail/useDetail';
import { GhostButton, MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { Icon } from '../../components/Icon';
import { StateScreen } from '../../components/StateScreen';
import { Fold } from '../../components/main/Fold';
import { count } from '../../journey/format';
import { plainValue } from '../try/experience';
import { factLine, learnedCompared, useEvidenceRun } from './evidence';
import { caseOf, companyClock, MAIN_CASES } from './mainCases';
import styles from './EvidencePages.module.css';

/**
 * The four kinds of input and the prompt lines each became (설계서 3-2): the labels are the engine's own dictionary
 * names of the sealed prompt, so the lines shown are the very lines the model read. The approval line is PolicySatisfied
 * in a v20 prompt and Policy in a v21 one.
 */
const GROUPS = [
  { id: 'learned', labels: ['BaselineStatus', 'UsualHours', 'UsualDevices', 'UsualExportSize'] },
  { id: 'request', labels: ['Time', 'Size', 'Network', 'LoginMethod'] },
  { id: 'company', labels: ['PolicySatisfied', 'Policy', 'Assignment', 'Ticket'] },
  { id: 'sensitivity', labels: ['ResourceClass'] },
] as const;

type GroupId = (typeof GROUPS)[number]['id'];

/**
 * 3-2, what was learned and the company records became which prompt lines (설계서 3-2): on the left the real values
 * of the four kinds of input in plain words, on the right the lines of the sealed prompt they became, each with its
 * line number, fact ID and source grade as the engine wrote them. The lines keep the prompt's own order, each card names
 * the lines it became, and one line says what a line's colour and its mark are (L-33); a card is as tall as its words
 * (L-04).
 */
export default function EvidencePromptPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const evidence = useEvidenceRun();
  const options = useLabOptions();
  const found = caseOf(options.data, MAIN_CASES.attacker);
  const { anatomy, facts, received, runId } = evidence;

  if (evidence.pending || runId === null || anatomy === null) {
    return (
      <MainScreen title={t('main.3-2.title')} intro={t('main.3-2.intro')} main={null}>
        <StateScreen kind={evidence.pending ? 'loading' : 'notReady'} />
      </MainScreen>
    );
  }
  const request = found?.labCase.requests[0] ?? null;
  const usualHours = [...(received?.usual['accessHour']?.values ?? [])]
    .sort((a, b) => Number(a) - Number(b))
    .map((value) => plainValue(t, 'accessHour', value))
    .join(' · ');
  // V-08: the run's own learned requests and the recent ones compared, as 2-2 and 3-1 name them.
  const learned = learnedCompared(t, anatomy.figures, language);
  const plain: Readonly<Record<GroupId, string>> = {
    // The usual hours, devices and largest export are the prompt's own lines (004, 007, 012): they sit with them, in the fold.
    learned: learned ?? '…',
    request: t('main.3-2.request.value', {
      clock: companyClock(t, received?.companyTime) ?? '-',
      project: request?.project ?? '-',
      items: request?.items === null || request?.items === undefined ? '-' : count(request.items, language),
    }),
    company:
      received?.businessFacts
        .filter((fact) =>
          ['NO_APPROVAL', 'APPROVAL_COVERS', 'NOT_ASSIGNED', 'ACCESS_DAYS_LAST_30'].includes(fact.code),
        )
        .map((fact) => t(`fact.${fact.code}`, { value: fact.value ?? '' }))
        .join(' · ') ?? '…',
    sensitivity: t('main.3-2.sensitivity.value', {
      project: request?.project ?? '-',
      level: t(`dim.sensitivity.${received?.sensitivity ?? 'NORMAL'}`, {
        defaultValue: received?.sensitivity ?? '-',
      }),
    }),
  };
  const rows: readonly { readonly group: GroupId; readonly fact: PromptFact }[] = GROUPS.flatMap((group) =>
    group.labels
      .map((label) => factLine(facts, label))
      .filter((fact): fact is PromptFact => fact !== null)
      .map((fact) => ({ group: group.id, fact })),
  ).sort((a, b) => a.fact.line - b.fact.line);
  const linesOf = (group: GroupId) =>
    rows.filter((row) => row.group === group).map((row) => lineNumber(row.fact));
  const lines = anatomy.promptLines;
  return (
    <MainScreen title={t('main.3-2.title')} intro={t('main.3-2.intro')}>
      <div className={styles.flow}>
        <ul className={styles.sources}>
          {GROUPS.map((group, index) => (
            <li
              key={group.id}
              className={styles.source}
              data-group={group.id}
              style={{ animationDelay: `calc(var(--pipe-step) * ${index})` }}
            >
              <b className={styles.sourceName}>{t(`main.3-2.${group.id}`)}</b>
              <span className={styles.sourceValue}>{plain[group.id]}</span>
            </li>
          ))}
        </ul>
        {/* AC-N2: the four inputs are the view; the prompt lines they became wait under one line. */}
        <Fold name="prompt-lines" summary={t('main.3-2.promptFold')}>
          <p className={styles.promptNote}>
            {t('main.3-2.learned.detail', {
              hours: usualHours || '-',
              devices: received?.usual['device']?.values.join(' · ') ?? '-',
              largest: received?.usual['size']?.values[0] ?? '-',
            })}
          </p>
          <GhostButton onClick={() => detail.show(runId, 1, 'prompt')}>{t('main.3-2.whole')}</GhostButton>
          <ul className={styles.refs}>
            {GROUPS.map((group) =>
              linesOf(group.id).length > 0 ? (
                <li key={group.id} className={styles.sourceLines} data-group={group.id}>
                  <Icon name="arrowRight" className={styles.sourceLinesIcon} />
                  <b>{t(`main.3-2.${group.id}`)}</b>
                  {t('main.3-2.lines', {
                    lines: linesOf(group.id).join(' · '),
                    count: linesOf(group.id).length,
                  })}
                </li>
              ) : null,
            )}
          </ul>
          <section className={styles.prompt} aria-labelledby="prompt-title">
            <div className={styles.promptHead}>
              <h2 id="prompt-title" className={styles.promptTitle}>
                {lines
                  ? t('main.3-2.promptTitle', { user: count(lines.user, language) })
                  : t('main.3-2.promptTitlePlain')}
              </h2>
              {lines ? (
                <span className={styles.promptNote}>
                  {t('main.3-2.systemApart', { system: count(lines.system, language) })}
                </span>
              ) : null}
            </div>
            {facts && !facts.available ? (
              <p className={styles.promptNote}>{t(`main.3-2.notAvailable.${facts.reason ?? 'NO_STEP'}`)}</p>
            ) : (
              <p className={styles.promptNote}>{t('main.3-2.legend')}</p>
            )}
            <ol className={styles.promptLines}>
              {rows.map(({ group, fact }, index) => (
                <li
                  key={`${group}-${fact.line}`}
                  className={styles.promptLine}
                  data-group={group}
                  data-line={fact.line}
                  style={{ animationDelay: `calc(var(--line-step) * ${index})` }}
                >
                  <span className={styles.lineNo}>{lineNumber(fact)}</span>
                  <code className={styles.lineText}>
                    {fact.factId ? `${fact.factId} ` : ''}
                    {fact.label}: {fact.value}
                  </code>
                  {fact.source ? (
                    <span className={styles.grade}>{t(`main.grade.${fact.source}`)}</span>
                  ) : null}
                </li>
              ))}
            </ol>
            <p className={styles.promptNote}>{t('main.3-2.asIs')}</p>
          </section>
        </Fold>
      </div>
      <SourceBadge
        kind={evidence.own ? 'run' : 'repeated'}
        label={t(evidence.own ? 'badge.run' : 'main.evidence.measured')}
        runId={runId}
      />
    </MainScreen>
  );
}

/** A prompt line's number as the prompt panel writes it: three digits. */
function lineNumber(fact: PromptFact): string {
  return String(fact.line).padStart(3, '0');
}
