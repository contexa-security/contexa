import { useTranslation } from 'react-i18next';
import { useAnatomy, useExchanges } from '../../api/anatomy';
import { useJourney } from '../../api/journey';
import { useTeasers } from '../../api/teasers';
import { ActionChip } from '../../components/common/ActionChip';
import { Modal } from '../../components/common/Modal';
import { SourceMark } from '../../components/common/SourceMark';
import { useUrlModal } from '../../components/common/useUrlModal';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { PromptBundles } from '../../components/inside/PromptBundles';
import { StateScreen } from '../../components/StateScreen';
import { count, seconds } from '../../journey/format';
import experience from './Experience.module.css';
import styles from './PromptPage.module.css';

/**
 * The prompt (e1-prompt, 7.3): what was really sent to the AI, as the seven bundles of the stored prompt with their line
 * counts (the server counts them), and for the bundle pressed its original lines next to plain words. The run is the
 * visitor's own try 1 run, or else the measured run the teasers name, which the screen says.
 */
export default function PromptPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const journey = useJourney();
  const teasers = useTeasers();
  const own =
    journey.data?.runs.find((line) => line.scenarioKey === 'A3' && line.status === 'COMPLETED') ?? null;
  const measured = teasers.data?.teasers.find((teaser) => teaser.key === 'G_HOW_LINES')?.source?.ref ?? null;
  const runId = own?.runId ?? measured;
  const anatomy = useAnatomy(runId, 1);
  const exchanges = useExchanges(runId, 1, runId !== null);
  const modal = useUrlModal('prompt-original');
  const lines = anatomy.data?.promptLines ?? null;
  const call = exchanges.data?.calls[0] ?? null;
  const modelCall = anatomy.data?.interpretation.calls[0] ?? null;
  return (
    <RouteScreen
      title={t('prompt.title')}
      purpose={t('prompt.purpose')}
      source={runId ? <SourceMark kind="ENGINE" runId={runId} step={1} record={{ runId, step: 1 }} /> : null}
      more={
        call ? (
          <ActionChip icon="code" variant="open" onClick={() => modal.show()}>
            {t('prompt.originalAll')}
          </ActionChip>
        ) : null
      }
    >
      {runId ? (
        <p className={experience.exampleTag}>
          {own ? t('prompt.ownRun') : t('prompt.measuredRun', { runId })}
        </p>
      ) : null}
      {anatomy.isPending || exchanges.isPending ? <StateScreen kind="loading" /> : null}
      {exchanges.data && !exchanges.data.kept ? <p className={experience.lead}>{t('prompt.gone')}</p> : null}
      {lines && call ? <PromptBundles lines={lines} call={call} /> : null}
      {modelCall ? (
        <p className={styles.callLine}>
          {t('prompt.call', {
            input: count(modelCall.promptTokens ?? 0, language),
            output: count(modelCall.completionTokens ?? 0, language),
            seconds:
              anatomy.data?.interpretation.timings.totalAnalysisMs == null
                ? '-'
                : seconds(anatomy.data.interpretation.timings.totalAnalysisMs),
          })}
          {/* The model's name is the record's own value, shown as it was recorded. */}
          <span className={styles.model}>
            {t('prompt.model')}
            <code data-original>{modelCall.model ?? '-'}</code>
          </span>
        </p>
      ) : null}
      <Modal open={modal.open} onClose={modal.hide} title={t('prompt.originalAll')} wide>
        <pre className={styles.full} data-original>
          {`${call?.systemPrompt ?? ''}\n\n${call?.userPrompt ?? ''}`}
        </pre>
      </Modal>
    </RouteScreen>
  );
}
