import { useTranslation } from 'react-i18next';
import { useInputChanges } from '../../api/anatomy';
import { useBenchmark } from '../../api/benchmark';
import { useJourney } from '../../api/journey';
import { useLabOptions, type LabOptions } from '../../api/lab';
import { useVisitor } from '../../api/queries';
import { Chip } from '../../components/main/Chip';
import { MainLink, MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { count } from '../../journey/format';
import { blindNote, caseOf, MAIN_CASES, personName, ROLE_PATHS, runCell } from './mainCases';
import { breakable } from './breakable';
import { inputLine } from './inputLine';
import { latestOwnRun } from './latestRun';
import { LearnLine } from './ProofPanel';
import styles from './DiffPage.module.css';

/** The approaches the result card compares: the existing security, the two rules and Contexa. */
const COMPARED = ['B', 'C1', 'C2', 'D'] as const;

type T = ReturnType<typeof useTranslation>['t'];

/** The rows of a request as its case defines it, in the request screen's order. */
function rowsOf(
  t: T,
  language: string,
  options: LabOptions | undefined,
  found: NonNullable<ReturnType<typeof caseOf>>,
): readonly { readonly id: string; readonly value: string }[] {
  const { labCase, employee } = found;
  const request = labCase.requests[0];
  const approval = labCase.facts.find((fact) => fact.kind === 'APPROVAL') ?? null;
  return [
    { id: 'account', value: personName(t, employee) },
    {
      id: 'time',
      value: t('main.4-3.time', {
        slot: t(`main.slot.${labCase.conditions.timeSlot}`),
        clock:
          options?.timeSlots.find((slot) => slot.slot === labCase.conditions.timeSlot)?.representativeTime ??
          '',
      }),
    },
    {
      id: 'place',
      value: t('main.4-3.place', {
        place: t(`main.place.${labCase.conditions.place}`),
        device: t(`main.device.${labCase.conditions.device}`),
      }),
    },
    {
      id: 'what',
      value:
        request && request.items !== null
          ? t('main.4-3.what', { project: request.project ?? '-', items: count(request.items, language) })
          : '-',
    },
    {
      id: 'approval',
      value: approval
        ? t('main.4-3.approval', {
            purpose: t(`main.purpose.${approval.purpose ?? 'OTHER'}`),
            max: count(approval.maxItems ?? 0, language),
          })
        : t('main.request.approval.no'),
    },
  ];
}

/**
 * 4-3, one line apart (설계서 4-3, IN-6): the visitor's two runs side by side. The request rows come from the two case
 * definitions (a row the two define alike once, a row they define apart in both columns, and the headline names it),
 * the changed input lines from the portal's comparison of what the engine received in each run, and the results from
 * the server's scoring of each run; Contexa's cells are its own decision with the items that left. Contexa holds no rule
 * written for these cases; the footnote keeps the deck's words for the approval-record rule and adds that these cases
 * are not in its conditions when the measurement's case groups record them as such.
 */
export default function DiffPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const visitor = useVisitor();
  const journey = useJourney(visitor.isSuccess);
  const options = useLabOptions();
  const attackCase = caseOf(options.data, MAIN_CASES.attacker);
  const normalCase = caseOf(options.data, MAIN_CASES.owner);
  const attack = latestOwnRun(journey.data?.runs, MAIN_CASES.attacker);
  const normal = latestOwnRun(journey.data?.runs, MAIN_CASES.owner);
  const changes = useInputChanges(normal?.runId ?? null, attack?.runId ?? null, 1);
  const benchmark = useBenchmark(null);
  // The footnote adds that the two cases are not in the rule's conditions only when the measurement records them in
  // the group no rule was written for (RULE_BLIND).
  const blind = benchmark.data?.suites.find((suite) => suite.suite === 'RULE_BLIND')?.cases ?? [];
  const note = blindNote(blind, [MAIN_CASES.attacker, MAIN_CASES.owner]);

  if (journey.isPending || options.isPending) {
    return (
      <MainScreen title={t('main.4-3.title')} main={null}>
        <StateScreen kind="loading" />
      </MainScreen>
    );
  }
  if (!attack || !normal || !attackCase || !normalCase) {
    const missing = attack ? 'owner' : 'attacker';
    return (
      <MainScreen
        title={t('main.4-3.title')}
        intro={t(`main.4-3.missing.${missing}`)}
        main={<MainLink to={ROLE_PATHS[missing].request}>{t('main.console.toRequest')}</MainLink>}
        nextNote={null}
      >
        {null}
      </MainScreen>
    );
  }
  const attackRows = rowsOf(t, language, options.data, attackCase);
  const normalRows = rowsOf(t, language, options.data, normalCase);
  const rows = attackRows.map((row, index) => ({
    id: row.id,
    attack: row.value,
    normal: normalRows[index]?.value ?? '-',
  }));
  const apart = rows.filter((row) => row.attack !== row.normal);
  const [only] = apart;
  const title =
    apart.length === 1 && only
      ? t('main.4-3.title.one', { row: t(`main.request.row.${only.id}`) })
      : t('main.4-3.title');
  const lines = changes.data ?? [];
  // One changed engine input is named (V-34): only the device line differs, while the request rows differ in one row.
  const [line] = lines;
  const intro = !changes.data
    ? t('main.4-3.introPending')
    : lines.length === 1 && line
      ? t('main.4-3.intro.one', {
          name: line.key.startsWith('dim.') ? t(line.key, { defaultValue: line.key }) : line.key,
        })
      : t('main.4-3.intro', { n: lines.length });
  const split =
    ['STOPPED', 'PARTLY_STOPPED'].includes(attack.business['D'] ?? '') && normal.business['D'] === 'PASSED';
  return (
    <MainScreen title={title} intro={intro}>
      <div className={styles.layout}>
        <section className={styles.card} aria-labelledby="diff-title">
          <h2 id="diff-title" className="visually-hidden">
            {t('main.4-3.diff')}
          </h2>
          <table className={styles.table}>
            <thead>
              <tr>
                <td />
                <th scope="col">{t('main.4-3.attack')}</th>
                <th scope="col">{t('main.4-3.normal')}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) =>
                row.attack === row.normal ? (
                  <tr key={row.id}>
                    <th scope="row">{t(`main.request.row.${row.id}`)}</th>
                    <td>{row.attack}</td>
                    <td>{row.normal}</td>
                  </tr>
                ) : (
                  <tr key={row.id} data-changed>
                    <th scope="row">{t(`main.request.row.${row.id}`)}</th>
                    <td data-side="attack">{row.attack}</td>
                    <td data-side="normal">{row.normal}</td>
                  </tr>
                ),
              )}
              {lines.map((line) => (
                <tr key={line.key} data-changed data-line>
                  <th scope="row">{t('main.4-3.inputLine')}</th>
                  <td data-side="attack">
                    <code>{breakable(inputLine(t, line.key, line.before))}</code>
                  </td>
                  <td data-side="normal">
                    <code>{breakable(inputLine(t, line.key, line.now))}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
        <section className={styles.card} aria-labelledby="diff-results">
          <h2 id="diff-results" className={styles.cardTitle}>
            {t('main.4-3.results')}
          </h2>
          <ul className={styles.results}>
            {/* The columns are the two runs, in the table's order; each result also names its run for a reader. */}
            <li className={styles.resultHead} aria-hidden="true">
              <span />
              <span>{t('main.4-3.attack')}</span>
              <span>{t('main.4-3.normal')}</span>
            </li>
            {COMPARED.map((control) => {
              // Contexa's cells are its own decision with the items that left (V-06); the others their scored result.
              const left = runCell(t, language, attack, control);
              const right = runCell(t, language, normal, control);
              return (
                <li key={control} className={styles.result} data-contexa={control === 'D' || undefined}>
                  <b className={styles.resultName}>{t(`main.lane.${control}`)}</b>
                  <span className={styles.resultCell}>
                    <span className={styles.resultSide}>{t('main.4-3.attack')}</span>
                    <Chip kind={left.kind}>{left.words}</Chip>
                  </span>
                  <span className={styles.resultCell}>
                    <span className={styles.resultSide}>{t('main.4-3.normal')}</span>
                    <Chip kind={right.kind}>{right.words}</Chip>
                  </span>
                </li>
              );
            })}
          </ul>
          <div className={styles.learning}>
            <h3 className={styles.learningTitle}>{t('main.proof.learn.title')}</h3>
            <ul className={styles.learningRows}>
              <LearnLine runId={attack.runId} name={t('main.4-3.attack')} />
              <LearnLine runId={normal.runId} name={t('main.4-3.normal')} />
            </ul>
          </div>
          <p className={styles.conclusion}>{t(split ? 'main.4-3.split' : 'main.4-3.noSplit')}</p>
          <p className={styles.footnote}>
            {note ? `${t('main.4-3.c2Note')} ${t(note)}` : t('main.4-3.c2Note')}
          </p>
          <div className={styles.badges}>
            <SourceBadge kind="run" label={t('main.4-3.attack')} runId={attack.runId} />
            <SourceBadge kind="run" label={t('main.4-3.normal')} runId={normal.runId} />
          </div>
        </section>
      </div>
    </MainScreen>
  );
}
