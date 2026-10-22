import { useTranslation } from 'react-i18next';
import type { BenchmarkView, BlindSpotCase } from '../../api/benchmark';
import { usePromptQuality } from '../../api/promptQuality';
import { caseName } from './benchData';
import styles from './Bench.module.css';

type Translate = ReturnType<typeof useTranslation>['t'];

/** Contexa's results in a case's counted runs, in words with their counts: "차단 4 · 공격 통과(미탐) 1". */
function contexaLine(t: Translate, contexa: Readonly<Record<string, number>>): string {
  return Object.entries(contexa)
    .filter(([, n]) => n > 0)
    .map(([result, n]) =>
      t('bench.r7.proof.result', { word: t(`main.result.${result}`, { defaultValue: result }), n }),
    )
    .join(' · ');
}

/**
 * 4.8 of docs/showcase/프롬프트-v21-구현계획.md (PB-1 to PB-4), the benchmark's first layer: the attack runs every
 * existing approach let through and the rule-blind normal runs every existing approach let pass, each with what
 * Contexa did in those same runs (misses included), then how many decisions are the model's own answer and how many
 * reasons match the facts. Every number is the portal's count of the setting's runs; nothing is computed here.
 */
export function BlindSpotProof({ view }: { readonly view: BenchmarkView }) {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const quality = usePromptQuality(view.spec?.settingHash ?? null);
  const proof = view.blindSpot;
  if (!proof) {
    return null;
  }
  const nameOf = (key: string) => {
    const row = view.cases.find((candidate) => candidate.key === key);
    return row ? caseName(t, row, language) : key;
  };
  const agreement = view.engine?.agreement ?? null;
  const reasons = quality.data?.reasonMatch ?? null;
  const table = (id: 'attacks' | 'normals', rows: readonly BlindSpotCase[]) => (
    <div className={styles.tableScroll} role="region" aria-label={t(`bench.r7.proof.${id}`)} tabIndex={0}>
      <table className={styles.table} data-proof={id}>
        <caption className={styles.caption}>{t(`bench.r7.proof.${id}`)}</caption>
        <thead>
          <tr>
            <th scope="col">{t('bench.r7.cases.case')}</th>
            <th scope="col">{t('bench.r7.proof.allPassed')}</th>
            <th scope="col">{t('bench.r7.proof.contexa')}</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key} data-case={row.key}>
              <th scope="row">{nameOf(row.key)}</th>
              <td>
                <span className={styles.value}>{`${row.allPassed}/${row.runs}`}</span>
              </td>
              <td>{row.allPassed > 0 ? contexaLine(t, row.contexa) : '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
  return (
    <section className={styles.proof} aria-labelledby="proof-title">
      <h2 id="proof-title" className={styles.proofTitle}>
        {t('bench.r7.proof.title')}
      </h2>
      <p className={styles.line}>{t('bench.r7.proof.guide')}</p>
      {proof.attacks.length > 0 ? (
        table('attacks', proof.attacks)
      ) : (
        <p className={styles.line}>{t('bench.r7.proof.noAttacks')}</p>
      )}
      {proof.normals.length > 0 ? table('normals', proof.normals) : null}
      <ul className={styles.proofLines}>
        {agreement && agreement.modelAnswered > 0 ? (
          <li>
            {t('bench.r7.proof.agreement', {
              as: agreement.asAnswered,
              answered: agreement.modelAnswered,
              technical: agreement.technical,
              held: agreement.held,
            })}
          </li>
        ) : null}
        {reasons && reasons.total > 0 ? (
          <li>{t('bench.r7.proof.reasons', { hits: reasons.hits, total: reasons.total })}</li>
        ) : null}
      </ul>
    </section>
  );
}
