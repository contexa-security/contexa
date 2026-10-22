import { useTranslation } from 'react-i18next';
import { useDetail } from '../../components/detail/useDetail';
import { Icon } from '../../components/Icon';
import { GhostButton, MainScreen } from '../../components/main/MainScreen';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { count, seconds, utcTime } from '../../journey/format';
import { CheckCounts } from './CheckCounts';
import { inOrder, modelSummary, shortHash, useEvidenceRun } from './evidence';
import { Hypotheses } from './Hypotheses';
import { ReasonChain, VerdictHero } from './VerdictCard';
import styles from './EvidencePages.module.css';

/** The model's answer as it came back, laid out when it is JSON and as written otherwise. */
function answerText(answer: string | null): string | null {
  if (answer === null) {
    return null;
  }
  try {
    return JSON.stringify(JSON.parse(answer), null, 2);
  } catch {
    return answer;
  }
}

/**
 * 3-3, from the LLM's answer to the verdict and the seal (설계서 3-3): the model call (model, calls, tokens, time) and
 * its answer as it came back, the reason codes with the prompt line each cites, the inspector's counts of what matched
 * the facts (in the order 2-3 lists them, P-39), and how the verdict was applied, learned and sealed; under both
 * columns the possibilities the AI compared, so neither column ends half way (B-13). Every value is the run's stored
 * record.
 */
export default function EvidenceVerdictPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const evidence = useEvidenceRun();
  const { anatomy, facts, quality, runId, contexa } = evidence;

  if (evidence.pending || runId === null || anatomy === null) {
    return (
      <MainScreen title={t('main.3-3.title')} intro={t('main.3-3.intro')} main={null}>
        <StateScreen kind={evidence.pending ? 'loading' : 'notReady'} />
      </MainScreen>
    );
  }
  const calls = anatomy.interpretation.calls;
  const call = calls[calls.length - 1] ?? null;
  const recorded = anatomy.interpretation.recorded;
  const answer = answerText(call?.answer ?? null);
  const checks = inOrder(quality?.inspection?.checks ?? []);
  const added = anatomy.learning?.newBehaviourDocuments.length ?? 0;
  const adverse = anatomy.juxtaposition;
  return (
    <MainScreen
      title={t('main.3-3.title')}
      intro={t('main.3-3.intro')}
      extra={<GhostButton onClick={() => detail.show(runId, 1, 'original')}>{t('main.3-3.raw')}</GhostButton>}
    >
      <VerdictHero recorded={recorded} />
      <div className={styles.verdict}>
        <div className={styles.column}>
          <ReasonChain
            codes={quality?.reasonCodes ?? []}
            facts={facts}
            action={recorded.finalAction ?? recorded.proposedAction}
          />
        </div>
        <div className={styles.column}>
          <section className={styles.panel} aria-labelledby="codes-title">
            <h2 id="codes-title" className={styles.panelTitle}>
              {t('main.3-3.checksTitle')}
            </h2>
            <ul className={styles.checks}>
              {checks.map((check) => (
                <li key={check.code} className={styles.check}>
                  <span>{t(`main.3-3.check.${check.code}`)}</span>
                  <CheckCounts
                    matched={check.matched}
                    mismatched={check.mismatched}
                    unverifiable={check.unverifiable}
                  />
                </li>
              ))}
            </ul>
            {adverse.adverseChecked > 0 ? (
              <p className={styles.panelNote}>
                {t('main.3-3.adverse', { met: adverse.adverseMet, checked: adverse.adverseChecked })}
              </p>
            ) : null}
          </section>
          <section className={styles.panel} aria-labelledby="apply-title">
            <h2 id="apply-title" className={styles.panelTitle}>
              {t('main.3-3.applyTitle')}
            </h2>
            <p className={styles.panelLine}>
              {t('main.3-3.applied', {
                when: t(
                  `main.applied.${recorded.applied === 'NEXT_REQUEST' ? 'NEXT_REQUEST' : 'BEFORE_RESPONSE'}`,
                ),
                status: contexa?.httpStatus ?? '—',
                items: contexa ? count(contexa.evidence.deliveredItems, language) : '—',
              })}
            </p>
            <p className={styles.panelLine}>
              {t(added > 0 ? 'main.3-1.seal.added' : 'main.3-1.seal.notAdded', { n: added })}
            </p>
            <p className={styles.sealLine}>
              <span className={styles.sealWord}>{t('main.3-1.sealWord')}</span>
              <code>sha256 {quality?.seal?.packageHash ? shortHash(quality.seal.packageHash) : '…'}</code>
              {quality?.seal?.capturedAt ? (
                <span className={styles.sealTime}>
                  {utcTime(quality.seal.capturedAt)} {t('main.utc')}
                </span>
              ) : null}
            </p>
          </section>
          <section className={styles.call} aria-labelledby="call-title">
            <h2 id="call-title" className={styles.panelTitle}>
              {t('main.3-3.callTitle')}
            </h2>
            <div className={styles.badges}>
              <span className={styles.callBadge} data-code>
                {call?.model ?? '-'}
              </span>
              <span className={styles.callBadge}>{t('main.3-3.calls', { n: calls.length })}</span>
              <span className={styles.callBadge}>
                {t('main.3-3.tokens', {
                  input: count(anatomy.interpretation.promptTokens ?? 0, language),
                  output: count(anatomy.interpretation.completionTokens ?? 0, language),
                })}
              </span>
              {modelSummary(anatomy).ms != null ? (
                <span className={styles.callBadge}>
                  {seconds(modelSummary(anatomy).ms ?? 0)}
                  {t('main.unit.seconds')}
                </span>
              ) : null}
            </div>
            {answer ? (
              <details className={styles.answerFold}>
                <summary className={styles.answerSummary}>
                  <Icon name="chevronRight" className={styles.answerIcon} />
                  {t('main.3-3.answer')}
                </summary>
                <pre className={styles.answer} tabIndex={0} aria-label={t('main.3-3.answer')}>
                  {answer}
                </pre>
              </details>
            ) : (
              <p>{t('main.3-3.noAnswer')}</p>
            )}
          </section>
        </div>
      </div>
      <Hypotheses hypotheses={quality?.hypotheses ?? []} facts={facts} />
      <SourceBadge
        kind={evidence.own ? 'run' : 'repeated'}
        label={t(evidence.own ? 'badge.run' : 'main.evidence.measured')}
        runId={runId}
      />
    </MainScreen>
  );
}
