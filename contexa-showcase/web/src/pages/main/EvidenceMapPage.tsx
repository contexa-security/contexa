import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useLabOptions } from '../../api/lab';
import { downloadRunRecord } from '../../api/runRecord';
import type { DetailTab } from '../../components/detail/useDetail';
import { useDetail } from '../../components/detail/useDetail';
import { MainScreen } from '../../components/main/MainScreen';
import { useMeasuredCase } from '../../api/measured';
import { SourceBadge } from '../../components/main/SourceBadge';
import { StateScreen } from '../../components/StateScreen';
import { count, seconds, utcTime } from '../../journey/format';
import { breakable } from './breakable';
import { factLine, learnedCompared, modelSummary, shortHash, useEvidenceRun } from './evidence';
import { caseOf, personName } from './mainCases';
import { LedgerChart } from './ProofPanel';
import styles from './EvidencePages.module.css';

/** The seven stages of a decision (설계서 3-1), each with the window tab its record opens on. */
const STAGES: readonly { readonly id: string; readonly tab: DetailTab }[] = [
  { id: 'learn', tab: 'received' },
  { id: 'context', tab: 'received' },
  { id: 'compare', tab: 'received' },
  { id: 'prompt', tab: 'prompt' },
  { id: 'llm', tab: 'original' },
  { id: 'verdict', tab: 'process' },
  { id: 'seal', tab: 'answer' },
];

/** The case of five ordinary requests in a row (the stacking topic's work case). */
const STACK_CASE = 'A6T';

/** The raw name under a stage's value: the words that name it, and the code as the record holds it. */
interface Raw {
  readonly label: string | null;
  readonly code: string;
}

/**
 * 3-1, the whole path (설계서 3-1): the seven stages of the decision just made, each with this run's own values and its
 * record one click away, and the seal of the record under them. A visitor who did not send the attack sees the latest
 * measured run of the same case, named as such. The seven stages are drawn alike, each with the raw name of its record
 * (L-32), and the words of a raw line are not set as code (L-02).
 */
export default function EvidenceMapPage() {
  const { t, i18n } = useTranslation();
  const language = i18n.language === 'ko' ? 'ko' : 'en';
  const detail = useDetail();
  const evidence = useEvidenceRun();
  // EV-7: the measured run of five ordinary requests in a row, to show learning accumulate. It is another employee's
  // run, from that employee's learned state, so its row names the employee and the run (V-09).
  const stack = useMeasuredCase(STACK_CASE).data?.middleRun ?? null;
  const stackCase = caseOf(useLabOptions().data, STACK_CASE);
  const [hash, setHash] = useState<string | null>(null);
  const { anatomy, facts, quality, received, runId, contexa } = evidence;

  if (evidence.pending || runId === null || anatomy === null) {
    return (
      <MainScreen title={t('main.3-1.title')} intro={t('main.3-1.intro')} main={null}>
        <StateScreen kind={evidence.pending ? 'loading' : 'notReady'} />
      </MainScreen>
    );
  }
  const call = anatomy.interpretation.calls[0] ?? null;
  const recorded = anatomy.interpretation.recorded;
  const lines = anatomy.promptLines;
  const accuracy = quality?.ribbon?.factAccuracy ?? null;
  const added = anatomy.learning?.newBehaviourDocuments.length ?? 0;
  const baseline = factLine(facts, 'BaselineStatus');
  const company = received?.businessFacts
    .filter((fact) =>
      ['NO_APPROVAL', 'APPROVAL_COVERS', 'NOT_ASSIGNED', 'ACCESS_DAYS_LAST_30'].includes(fact.code),
    )
    .map((fact) => t(`fact.${fact.code}`, { value: fact.value ?? '' }))
    .join(' · ');
  const values: Readonly<Record<string, { readonly line: string; readonly raw: Raw | null }>> = {
    learn: {
      line: learnedCompared(t, anatomy.figures, language) ?? '…',
      raw: factTag(baseline),
    },
    // The approval line of the prompt: PolicySatisfied in a v20 prompt, Policy in a v21 one.
    context: {
      line: company || '…',
      raw: factTag(factLine(facts, 'PolicySatisfied') ?? factLine(facts, 'Policy')),
    },
    compare: {
      line: t('main.3-1.compare.line', {
        n: anatomy.figures.departureCount ?? 0,
        sensitivity: t(`dim.sensitivity.${anatomy.juxtaposition.sensitivity ?? 'NORMAL'}`, {
          defaultValue: anatomy.juxtaposition.sensitivity ?? '-',
        }),
      }),
      raw: factTag(factLine(facts, 'DeviationsFromBaseline')),
    },
    prompt: {
      line: lines
        ? t('main.3-1.prompt.line', {
            system: count(lines.system, language),
            user: count(lines.user, language),
            total: count(lines.total, language),
          })
        : '…',
      raw: quality?.bundle?.version ? { label: t('main.3-1.prompt.bundle'), code: quality.bundle.version } : null,
    },
    llm: {
      line: call
        ? t('main.3-1.llm.line', {
            model: modelSummary(anatomy).model ?? '-',
            calls: modelSummary(anatomy).calls,
            tokens: count(modelSummary(anatomy).promptTokens, language),
            seconds: seconds(modelSummary(anatomy).ms ?? 0),
          })
        : '…',
      // What the model itself answered, before the checks of the next stage.
      raw: recorded.proposedAction ? { label: null, code: `proposedAction: ${recorded.proposedAction}` } : null,
    },
    verdict: {
      line: t('main.3-1.verdict.line', {
        codes: quality?.reasonCodes.length ?? 0,
        matched: accuracy?.matched ?? 0,
        total: accuracy?.total ?? 0,
        when: t(`main.applied.${recorded.applied === 'NEXT_REQUEST' ? 'NEXT_REQUEST' : 'BEFORE_RESPONSE'}`),
        status: contexa?.httpStatus ?? '—',
      }),
      raw: recorded.finalAction ? { label: null, code: `finalAction: ${recorded.finalAction}` } : null,
    },
    seal: {
      line: t(added > 0 ? 'main.3-1.seal.added' : 'main.3-1.seal.notAdded', { n: added }),
      raw: quality?.seal?.packageHash ? { label: null, code: `sha256 ${shortHash(quality.seal.packageHash)}` } : null,
    },
  };
  return (
    <MainScreen title={t('main.3-1.title')} intro={t('main.3-1.intro')}>
      <ol className={styles.pipe}>
        {STAGES.map((stage, index) => (
          <li
            key={stage.id}
            className={styles.stage}
            style={{ animationDelay: `calc(var(--pipe-step) * ${index})` }}
          >
            <span className={styles.stageNumber}>{index + 1}</span>
            <b className={styles.stageName}>{t(`main.3-1.${stage.id}`)}</b>
            <span className={styles.stageSub}>{t(`main.3-1.${stage.id}.sub`)}</span>
            <p className={styles.stageLine}>{values[stage.id]?.line}</p>
            {values[stage.id]?.raw ? <RawLine raw={values[stage.id]?.raw ?? null} /> : null}
            <button
              type="button"
              className={styles.stageOpen}
              onClick={() => detail.show(runId, 1, stage.tab)}
            >
              {t('main.3-1.open')}
            </button>
          </li>
        ))}
      </ol>
      <div className={styles.sealLine}>
        <span className={styles.sealWord}>{t('main.3-1.sealWord')}</span>
        <code>sha256 {quality?.seal?.packageHash ? shortHash(quality.seal.packageHash) : '…'}</code>
        <code className={styles.sealMeta}>{runId}</code>
        {quality?.seal?.capturedAt ? (
          <span className={styles.sealTime}>
            {utcTime(quality.seal.capturedAt)} {t('main.utc')}
          </span>
        ) : null}
        <button
          type="button"
          className={styles.sealDownload}
          onClick={() => {
            void downloadRunRecord(runId, 1).then(setHash);
          }}
        >
          {t('main.3-1.download')}
        </button>
        {hash ? (
          <span className={styles.sealTime}>{t('main.3-1.downloaded', { hash: shortHash(hash) })}</span>
        ) : null}
      </div>
      {runId ? (
        <LedgerChart
          rows={[
            {
              key: 'run',
              name: t(evidence.own ? 'main.proof.ledger.attack' : 'main.proof.ledger.attackMeasured'),
              runId,
            },
            ...(stack && stackCase
              ? [
                  {
                    key: 'stack',
                    name: t('main.proof.ledger.stack', { name: personName(t, stackCase.employee) }),
                    runId: stack,
                  },
                ]
              : []),
          ]}
        />
      ) : null}
      <SourceBadge
        kind={evidence.own ? 'run' : 'repeated'}
        label={t(evidence.own ? 'badge.run' : 'main.evidence.measured')}
        runId={runId}
      />
    </MainScreen>
  );
}

/**
 * The prompt line a stage card names, by its fact ID and label only (EV-5): short enough to show whole, the whole line
 * one press away under the card's "raw" button.
 */
function factTag(fact: ReturnType<typeof factLine>): Raw | null {
  return fact ? { label: null, code: `${fact.factId ? `${fact.factId} ` : ''}${fact.label}` } : null;
}

/** A stage's raw name: its words in the body font, its code fixed-width. */
function RawLine({ raw }: { readonly raw: Raw | null }) {
  if (raw === null) {
    return null;
  }
  return (
    <p className={styles.stageRaw} data-raw>
      {raw.label ? <span className={styles.stageRawLabel}>{raw.label}</span> : null}
      <code>{breakable(raw.code)}</code>
    </p>
  );
}
