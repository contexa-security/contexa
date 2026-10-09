import { useTranslation } from 'react-i18next';
import { useAnatomy, useExchanges } from '../../api/anatomy';
import { useVisitor } from '../../api/queries';
import { useTeasers } from '../../api/teasers';
import { AppHeader } from '../../components/AppHeader';
import { ActionChip } from '../../components/common/ActionChip';
import { Modal } from '../../components/common/Modal';
import { SourceMark } from '../../components/common/SourceMark';
import { useUrlModal } from '../../components/common/useUrlModal';
import { Icon, type IconName } from '../../components/Icon';
import { routeFlow } from '../../components/journey/flow';
import { JourneyBar } from '../../components/journey/JourneyParts';
import { ActionBar, MoreRow, StepHeader } from '../../components/journey/StepParts';
import { VerdictChip } from '../../components/VerdictChip';
import { useJourneyPosition } from '../../journey/useJourneyPosition';
import experience from '../try/Experience.module.css';
import styles from './RulesPage.module.css';

const VERDICTS = ['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK'] as const;
const LINES: readonly { readonly key: string; readonly icon: IconName }[] = [
  { key: 'elevated', icon: 'lock' },
  { key: 'lowRisk', icon: 'check' },
  { key: 'least', icon: 'arrowRight' },
];

/**
 * Which rule lines of the original get a plain-words note, by how the line begins. Only lines are matched, never
 * counted or numbered here: the numbers are the original text's own lines.
 */
const PLAIN_LINES: readonly { readonly starts: string; readonly key: string }[] = [
  { starts: 'ALLOW =', key: 'ALLOW' },
  { starts: 'CHALLENGE =', key: 'CHALLENGE' },
  { starts: 'ESCALATE =', key: 'ESCALATE' },
  { starts: 'BLOCK =', key: 'BLOCK' },
  { starts: 'Required low-risk boundary', key: 'lowRisk' },
  { starts: 'Required elevated-risk boundary', key: 'elevated' },
  { starts: '6. Choose the least disruptive', key: 'least' },
];

const ORIGINAL_MODAL = 'rules-original';

/**
 * G-rules (g-rules, 7.2): the AI judges by published rules. The screen is the four decisions with what each means and
 * the lines the rules always keep; the original rules, as the model received them in the designated prompt run, open
 * from a chip with their own line numbers and a plain-words note on the lines the cards come from. On the default route
 * the teaser band leads on; on the concept path a "next" button does (D-33).
 */
export default function RulesPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  useVisitor();
  const position = useJourneyPosition();
  const teasers = useTeasers();
  const modal = useUrlModal(ORIGINAL_MODAL);
  const promptRun = teasers.data?.teasers.find((teaser) => teaser.key === 'G_HOW_LINES')?.source?.ref ?? null;
  const anatomy = useAnatomy(promptRun, 1).data ?? null;
  const exchanges = useExchanges(promptRun, 1, modal.open);
  const systemLines = anatomy?.promptLines?.systemPhysical ?? null;
  const flow = routeFlow(t, language, position, teasers.data);

  return (
    <>
      <AppHeader />
      <main id="main" className={experience.page}>
        <JourneyBar />
        <div className={experience.step}>
          <StepHeader
            title={t('gRules.title')}
            purpose={t('gRules.purpose')}
            source={promptRun ? <SourceMark kind="ENGINE" runId={promptRun} step={1} /> : null}
          />
          <ul className={styles.verdicts}>
            {VERDICTS.map((verdict) => (
              <li key={verdict} className={styles.verdict}>
                <VerdictChip verdict={verdict} />
                <span className={styles.verdictMeaning}>{t(`gRules.verdict.${verdict}`)}</span>
              </li>
            ))}
          </ul>
          <section className={styles.lines} aria-labelledby="rules-lines">
            <h2 id="rules-lines" className={experience.panelTitle}>
              {t('gRules.lines.title')}
            </h2>
            <ol className={styles.lineList}>
              {LINES.map((line) => (
                <li key={line.key} className={styles.line}>
                  <Icon name={line.icon} className={styles.lineIcon} />
                  {t(`gRules.line.${line.key}`)}
                </li>
              ))}
            </ol>
          </section>
          {systemLines !== null ? (
            <MoreRow>
              <ActionChip icon="code" variant="open" onClick={() => modal.show()}>
                {t('gRules.original', { lines: systemLines })}
              </ActionChip>
            </MoreRow>
          ) : null}
          <ActionBar back={flow.back} main={flow.next} teaser={flow.teaser} />
        </div>
        <Modal
          open={modal.open}
          onClose={modal.hide}
          title={t('gRules.originalTitle', { runId: promptRun ?? '-' })}
          wide
        >
          {exchanges.isPending ? <p className={experience.lead}>{t('gRules.originalLoading')}</p> : null}
          {exchanges.data && !exchanges.data.kept ? (
            <p className={experience.lead}>{t('gRules.originalGone')}</p>
          ) : null}
          {exchanges.data?.calls[0]?.systemPrompt ? (
            <>
              <p className={experience.lead}>{t('gRules.source', { runId: promptRun ?? '-' })}</p>
              <ol className={styles.original}>
                {exchanges.data.calls[0].systemPrompt.split('\n').map((text, index) => {
                  const plain = PLAIN_LINES.find((candidate) => text.startsWith(candidate.starts));
                  return (
                    // The original's own line order is the identity of a line.
                    <li key={index} className={styles.originalLine} data-plain={plain ? true : undefined}>
                      <code className={styles.originalText}>{text}</code>
                      {plain ? (
                        <span className={styles.originalPlain}>{t(`gRules.plain.${plain.key}`)}</span>
                      ) : null}
                    </li>
                  );
                })}
              </ol>
            </>
          ) : null}
        </Modal>
      </main>
    </>
  );
}
