import { useTranslation } from 'react-i18next';
import { Link, useParams } from 'react-router-dom';
import { useRunScore } from '../api/queries';
import { AppHeader } from '../components/AppHeader';
import { DecisionAnatomy } from '../components/anatomy/DecisionAnatomy';
import styles from './AnatomyPage.module.css';

/** Run IDs the portal issues: "run-" and twelve lowercase hexadecimal digits. */
const RUN_ID = /^run-[0-9a-f]{12}$/;

/**
 * The verdict anatomy of one request of a run (/runs/:runId/steps/:stepNo), opened from the lab, the benchmark, the
 * replay and the story. The run's requests are listed so a visitor moves between them; a request the engine did not
 * analyse is listed too, with what was recorded for it.
 */
export default function AnatomyPage() {
  const { t } = useTranslation();
  const params = useParams<{ runId: string; stepNo: string }>();
  const runId = params.runId ?? '';
  const stepNo = Number(params.stepNo ?? '1');
  const valid = RUN_ID.test(runId) && Number.isInteger(stepNo) && stepNo >= 1;
  const score = useRunScore(valid ? runId : null, 'anatomy', 0);
  const steps = score.data?.executedSteps ?? 0;
  return (
    <>
      <AppHeader />
      <main id="main" className={styles.page}>
        {valid ? (
          <>
            {steps > 1 ? (
              <nav aria-label={t('anatomy.stepsNav')}>
                <ol className={styles.steps}>
                  {Array.from({ length: steps }, (_, index) => index + 1).map((n) => (
                    <li key={n}>
                      <Link
                        to={`/runs/${runId}/steps/${n}`}
                        className={styles.step}
                        aria-current={n === stepNo ? 'page' : undefined}
                      >
                        {t('anatomy.stepTab', { n })}
                      </Link>
                    </li>
                  ))}
                </ol>
              </nav>
            ) : null}
            <DecisionAnatomy runId={runId} stepNo={stepNo} />
          </>
        ) : (
          <p role="alert">{t('anatomy.notFound')}</p>
        )}
      </main>
    </>
  );
}
