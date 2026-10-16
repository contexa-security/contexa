import { useTranslation } from 'react-i18next';
import { useAnatomy, useExchanges } from '../../api/anatomy';
import { useJourney } from '../../api/journey';
import { useOtherBundle, useRunFacts, useRunQuality } from '../../api/promptQuality';
import { useTeasers } from '../../api/teasers';
import { ActionChip } from '../../components/common/ActionChip';
import { Modal } from '../../components/common/Modal';
import { SourceMark } from '../../components/common/SourceMark';
import { useUrlModal } from '../../components/common/useUrlModal';
import { compareOffered } from '../../components/facts/factWords';
import { PromptChunks } from '../../components/facts/PromptChunks';
import { PromptCompare } from '../../components/facts/PromptCompare';
import { QualityRibbon } from '../../components/facts/QualityRibbon';
import { RouteScreen } from '../../components/journey/RouteScreen';
import { PromptBundles } from '../../components/inside/PromptBundles';
import { countedCall, shownBundles } from '../../components/inside/promptSections';
import { StateScreen } from '../../components/StateScreen';
import { count, seconds } from '../../journey/format';
import experience from './Experience.module.css';
import styles from './PromptPage.module.css';

/**
 * The prompt (e1-prompt, U-2): what the AI received, read the way it reads it. The quality ribbon of the run's
 * official inspection on top, then the five parts in reading order with their source chips and the two folds; a part
 * opens its fact cards in place. The line counts per block, the call's tokens and the whole text are under "the whole
 * original"; the same case under the other bundle (a measured run, not the same request) is offered only when the
 * server found one. A step whose sealed prompt cannot be read as facts says why and keeps the blocks with their plain lines
 * (W3-10). The run is the visitor's own try 1 run, or else the measured run the teasers name, which the screen says.
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
  const facts = useRunFacts(runId, 1);
  const quality = useRunQuality(runId, 1);
  const modal = useUrlModal('prompt-original');
  const compare = useUrlModal('prompt-compare');
  const other = useOtherBundle(runId, 1).data ?? null;
  const lines = anatomy.data?.promptLines ?? null;
  const call = exchanges.data ? countedCall(exchanges.data.calls) : null;
  const modelCall = anatomy.data ? countedCall(anatomy.data.interpretation.calls) : null;
  const shown = facts.data?.available ? facts.data : null;
  const ribbon = quality.data?.available ? (quality.data.ribbon ?? null) : null;
  // The facts view answers 404 for a run it does not know; a view without facts names its reason.
  const factsMissing = facts.isError || (facts.data !== undefined && !facts.data.available);
  return (
    <RouteScreen
      title={t('prompt.title')}
      purpose={t('prompt.purpose')}
      source={runId ? <SourceMark kind="ENGINE" runId={runId} step={1} record={{ runId, step: 1 }} /> : null}
      more={
        call || compareOffered(other) ? (
          <>
            {call ? (
              <ActionChip icon="code" variant="open" onClick={() => modal.show()}>
                {t('prompt.originalAll')}
              </ActionChip>
            ) : null}
            {compareOffered(other) ? (
              <ActionChip icon="search" variant="open" onClick={() => compare.show()}>
                {t('prompt.compare.open')}
              </ActionChip>
            ) : null}
          </>
        ) : null
      }
    >
      {runId ? (
        <p className={experience.exampleTag}>
          {own ? t('prompt.ownRun') : t('prompt.measuredRun', { runId })}
        </p>
      ) : null}
      {runId && (facts.isPending || anatomy.isPending) ? <StateScreen kind="loading" /> : null}
      {exchanges.data && !exchanges.data.kept ? <p className={experience.lead}>{t('prompt.gone')}</p> : null}
      {shown ? <PromptChunks facts={shown} quality={quality.data?.available ? quality.data : null} /> : null}
      {factsMissing ? (
        <p className={experience.lead} data-state="no-facts">
          {t(`factsReason.${facts.data?.reason ?? 'other'}`, { defaultValue: t('factsReason.other') })}{' '}
          {lines && call ? t('prompt.factsUnavailable') : null}
        </p>
      ) : null}
      {factsMissing && lines && call ? (
        <>
          {ribbon ? <QualityRibbon ribbon={ribbon} /> : null}
          <PromptBundles lines={lines} call={call} />
        </>
      ) : null}
      <Modal open={modal.open} onClose={modal.hide} title={t('prompt.originalAll')} wide>
        {lines ? (
          <section className={styles.counts} aria-labelledby="prompt-counts">
            <h3 id="prompt-counts" className={styles.viewTitle}>
              {t('prompt.counts')}
            </h3>
            <ul className={styles.countList}>
              {shownBundles(lines).map((bundle) => (
                <li key={bundle}>
                  <span>
                    {t(lines.layout === 'V20_BLOCKS' ? `prompt.block.${bundle}` : `prompt.bundle.${bundle}`)}
                  </span>{' '}
                  <span className={styles.countLines}>
                    {t('prompt.lines', {
                      n: count(lines.bundles.find((entry) => entry.bundle === bundle)?.lines ?? 0, language),
                    })}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        ) : null}
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
        <pre className={styles.full} data-original>
          {`${call?.systemPrompt ?? ''}\n\n${call?.userPrompt ?? ''}`}
        </pre>
      </Modal>
      <Modal open={compare.open} onClose={compare.hide} title={t('prompt.compare.title')} wide>
        {other ? <PromptCompare view={other} /> : null}
      </Modal>
    </RouteScreen>
  );
}
