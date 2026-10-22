import { useTranslation } from 'react-i18next';
import type { Hypothesis, RunFacts } from '../../api/promptQuality';
import { factKey } from '../../components/facts/factWords';
import { factById } from './evidence';
import styles from './EvidencePages.module.css';

/** The explanations the v21 decision text names itself; another one (H5) is named by the model. */
const NAMED = ['H1', 'H2', 'H3', 'H4'];

/**
 * SC-8 (docs/showcase/프롬프트-v21-구현계획.md): the explanations a v21 decision weighed, in the model's order, each
 * with the model's assessment and the facts it named for and against it. H1 to H4 carry the decision text's own names;
 * an H5 is shown with the name the model wrote, marked as the original. A lead line says, as the decision text does,
 * that the verdict weighs the other possibilities too, not the most likely one alone (V-59); an empty list reads
 * "none", and a fact the model named on both sides is said so as the model wrote it (V-47). Each assessment is marked
 * by its strength (L-34). Nothing is ranked or counted here, and a decision before v21 has none, so the panel is not
 * drawn.
 */
export function Hypotheses({
  hypotheses,
  facts,
}: {
  readonly hypotheses: readonly Hypothesis[];
  readonly facts: RunFacts | null;
}) {
  const { t } = useTranslation();
  if (hypotheses.length === 0) {
    return null;
  }
  const named = (id: string) => {
    const fact = factById(facts, id);
    return fact ? `${id} ${t(`fact.label.${factKey(fact.label)}`)}` : id;
  };
  const listed = (ids: readonly string[]) =>
    ids.length > 0 ? ids.map(named).join(', ') : t('main.3-3.hypothesisNone');
  return (
    <section className={styles.panel} aria-labelledby="hypotheses-title">
      <h2 id="hypotheses-title" className={styles.panelTitle}>
        {t('main.3-3.hypothesesTitle')}
      </h2>
      <p className={styles.panelNote}>{t('main.3-3.hypothesesLead')}</p>
      <ul className={styles.codes}>
        {hypotheses.map((hypothesis) => {
          const both = hypothesis.for.filter((id) => hypothesis.against.includes(id));
          return (
            <li key={hypothesis.id} className={styles.code}>
              <span className={styles.hypothesisName}>
                {NAMED.includes(hypothesis.id) ? (
                  t(`hypothesis.${hypothesis.id}`)
                ) : (
                  <>
                    {t('hypothesis.H5')}{' '}
                    {hypothesis.name ? (
                      <code className={styles.codeName} data-original>
                        {hypothesis.name}
                      </code>
                    ) : null}
                  </>
                )}{' '}
                <span className={styles.assessment} data-level={hypothesis.assessment}>
                  {t(`hypothesis.assessment.${hypothesis.assessment}`, {
                    defaultValue: hypothesis.assessment,
                  })}
                </span>
              </span>
              <span className={styles.codeCites}>
                {t('main.3-3.hypothesisFacts', {
                  for: listed(hypothesis.for),
                  against: listed(hypothesis.against),
                })}
              </span>
              {both.length > 0 ? (
                <span className={styles.codeBoth}>
                  {t('main.3-3.hypothesisBoth', { facts: both.map(named).join(', ') })}
                </span>
              ) : null}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
