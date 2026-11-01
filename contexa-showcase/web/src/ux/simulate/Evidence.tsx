import { useTranslation } from 'react-i18next';
import { useRunFacts, useRunQuality } from '../../api/promptQuality';
import { Badge, ButtonLink, CodeChip, Loading } from '../ui';
import styles from './Result.module.css';

/** The evidence the engine recorded: its reason codes with the facts they cite, its own summary and its scores. */
export function Evidence({
  runId,
  stepNo,
  risk,
  confidence,
  reasoning,
  reasoningCode,
}: {
  readonly runId: string;
  readonly stepNo: number;
  readonly risk: number | null;
  readonly confidence: number | null;
  readonly reasoning: string | null;
  readonly reasoningCode: string | null;
}) {
  const { t } = useTranslation();
  const quality = useRunQuality(runId, stepNo);
  const facts = useRunFacts(runId, stepNo);
  const codes = quality.data?.reasonCodes ?? [];
  const shown = codes.slice(0, 3);
  const factOf = (id: string | null) =>
    id === null
      ? null
      : (facts.data?.blocks.flatMap((block) => block.facts).find((fact) => fact.factId === id) ?? null);
  return (
    <section className={styles.card} aria-labelledby="evidence-title">
      <header className={styles.cardHead}>
        <h2 id="evidence-title" className={styles.cardTitle}>
          {t('ux.result.evidence.title')}
        </h2>
        <p className={styles.cardSub}>{t('ux.result.evidence.sub')}</p>
      </header>
      {quality.isPending ? <Loading rows={3} /> : null}
      <ol className={styles.reasons}>
        {shown.map((code, index) => {
          // A fact cited by several codes is quoted once, at its first code.
          const first = shown.findIndex((other) => other.fact === code.fact) === index;
          const fact = first ? factOf(code.fact) : null;
          return (
            <li key={`${code.code}-${index}`} className={styles.reason}>
              <span className={styles.reasonNo}>{index + 1}</span>
              <div>
                <p className={styles.reasonText}>
                  {t(code.contract === 'V4' ? `reasonCodeV4.${code.code}` : `reasonCode.${code.code}`, {
                    defaultValue: code.code,
                  })}
                </p>
                <p className={styles.reasonCodes}>
                  <CodeChip value={code.code} />
                  {code.fact ? <Badge tone="sel">{code.fact}</Badge> : null}
                  {fact ? (
                    <span className={styles.reasonFact} lang="en" title={fact.value}>
                      {fact.value}
                    </span>
                  ) : null}
                </p>
              </div>
            </li>
          );
        })}
      </ol>
      {codes.length > shown.length ? (
        <p className={styles.more}>{t('ux.result.evidence.more', { n: codes.length - shown.length })}</p>
      ) : null}
      {reasoning ? (
        <div className={styles.summary}>
          <p className={styles.summaryHead}>
            {t('ux.result.evidence.summary')}{' '}
            <Badge tone="line">
              {t(reasoningCode ? 'ux.result.evidence.fixed' : 'ux.recovery.original')}
            </Badge>
          </p>
          <p lang={reasoningCode ? undefined : 'en'} className={styles.summaryText}>
            {reasoningCode ? t(`reason.canonical.${reasoningCode}`, { defaultValue: reasoning }) : reasoning}
          </p>
        </div>
      ) : null}
      <div className={styles.evidenceFoot}>
        <span>
          {risk !== null
            ? t('ux.result.evidence.scores', {
                risk: risk.toFixed(2),
                confidence: confidence?.toFixed(2) ?? '—',
              })
            : null}
        </span>
        <ButtonLink to={`/runs/${encodeURIComponent(runId)}?tab=evidence`} size="sm">
          {t('ux.result.evidence.detail')}
        </ButtonLink>
      </div>
    </section>
  );
}
