import type { TFunction } from 'i18next';
import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import type { LabCase } from '../../../api/lab';
import { useRunFacts, useRunQuality, type RunFacts } from '../../../api/promptQuality';
import type { LiveDecision } from '../../../api/types';
import {
  ReasonChain,
  ReasonFigure,
  type ChangedFact,
  type ReasonItem,
} from '../../../components/facts/ReasonChain';
import { DetailChip } from '../../../components/journey/FrameParts';
import { ScreenBody } from '../../../components/journey/ScreenBody';
import { NextLink } from '../../../components/journey/StepParts';
import { StateScreen } from '../../../components/StateScreen';
import type { Verdict } from '../../../domain/verdict';
import type { Difference } from '../../../journey/journey';
import { approvalFact } from '../decision';
import { stepPath, type Mode, type Role, type StepFlow } from '../experience';
import { useTryAnalysis, useTryRun } from './tryRun';

const ACTIONS = new Set(['ALLOW', 'CHALLENGE', 'ESCALATE', 'BLOCK']);

/** The lines of the company approval among the facts the AI received, in the order they are looked for. */
const APPROVAL_LABELS = ['PolicySatisfied', 'Approval'] as const;

interface ReasonStepProps {
  readonly role: Role;
  readonly mode: Mode;
  readonly labCase: LabCase;
  readonly see: (difference: Difference) => void;
  readonly flow: StepFlow;
}

/** The ID of the approval line among the facts the AI received; null when the facts cannot be read or hold none. */
function approvalFactId(facts: RunFacts | null): string | null {
  if (!facts?.available) {
    return null;
  }
  for (const label of APPROVAL_LABELS) {
    for (const block of facts.blocks) {
      const line = block.facts.find((fact) => fact.label === label && fact.factId !== null);
      if (line?.factId) {
        return line.factId;
      }
    }
  }
  return null;
}

/**
 * The figure's cards when the decision recorded no reason codes: the decision's own facts (how many compared items
 * differ, the sensitivity, the approval as the inspector read it), each as one card.
 */
function recordedItems(t: TFunction, decision: LiveDecision, changedTag: string | null): readonly ReasonItem[] {
  const approval = approvalFact(t, decision.adverseLabels);
  const sensitivity = decision.reason?.resourceSensitivity ?? null;
  return [
    ...(changedTag ? [{ key: 'approval', tag: changedTag, words: approval ? [approval] : [] }] : []),
    { key: 'differs', name: t('e1.reason.differs', { n: decision.reason?.baselineDeltaCount ?? '-' }), words: [] },
    ...(sensitivity
      ? [
          {
            key: 'sensitivity',
            name: t('e1.reason.sensitivity', {
              level: t(`dim.sensitivity.${sensitivity}`, { defaultValue: sensitivity }),
            }),
            words: [],
          },
        ]
      : []),
    ...(!changedTag && approval ? [{ key: 'approval', name: approval, words: [] }] : []),
  ];
}

/**
 * The reasons (화면재편 1-5 and 2-4, T6): why Contexa judged the visitor's run as it did, as one figure, each fact the
 * reasons cite once in plain words, then the judgment, and the one "see details" chip. Engine codes, fact IDs, the
 * model's own sentence (English, in the decision details' original record), the inspector and the prompt stay in the
 * decision details (F-1, F-2, V-6). Try 2 marks the one thing that changed, the company approval. Every value is
 * control D's record of the run: the sealed reason codes and facts, else the decision's own.
 */
export function ReasonStep({ role, mode, labCase, see, flow }: ReasonStepProps) {
  const { t } = useTranslation();
  const run = useTryRun(labCase.key, labCase.requests.length);
  const view = run.view;
  const analysis = useTryAnalysis(view, run.stored);
  const decision = analysis.decision;
  // The sealed decision's reason codes and the facts they cite, read once the engine has decided.
  const sealedRun = decision ? (view?.runId ?? null) : null;
  const quality = useRunQuality(sealedRun, 1);
  const runFacts = useRunFacts(sealedRun, 1);
  const number = role === 'owner' ? '2-4' : '1-5';

  useEffect(() => {
    if (decision) {
      see(4);
    }
    // Seen once the reasons are on screen; `see` is recreated on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [decision !== null]);

  if (run.pending) {
    return <StateScreen kind="loading" />;
  }
  if (!view?.runId) {
    return (
      <ScreenBody
        title={t(`screen.${number}.title`)}
        purpose={t('p1.unsent.guide')}
        back={null}
        main={<NextLink to={stepPath(role, 'predict', mode)} label={t('p1.unsent.go')} />}
      >
        {null}
      </ScreenBody>
    );
  }
  if (!decision) {
    // A stored run without a decision of the engine says so; otherwise the decision is still coming.
    return analysis.missing ? (
      <ScreenBody title={t(`screen.${number}.title`)} purpose={t('p1.reason.none')} back={flow.back} main={flow.next}>
        {null}
      </ScreenBody>
    ) : (
      <StateScreen kind="loading" />
    );
  }
  if (quality.isLoading || runFacts.isLoading) {
    return <StateScreen kind="loading" />;
  }

  const facts = runFacts.data ?? null;
  const sealed = quality.data?.available ? quality.data.reasonCodes : [];
  const recorded = decision.reason?.reasonCodes ?? [];
  const reasonCodes = sealed.length > 0 ? sealed : recorded;
  const action = decision.finalAction;
  const verdict = (ACTIONS.has(action) ? action : 'NONE') as Verdict;
  // A try 1 that Contexa let through is asked the other way round; the copy source's question presumes a stop.
  const passed = role === 'attacker' && action === 'ALLOW';
  const changedTag = role === 'owner' ? t('p2.reason.changed') : null;
  const changed: ChangedFact | null = changedTag
    ? {
        fact: approvalFactId(facts),
        tag: changedTag,
        words: approvalFact(t, decision.adverseLabels),
      }
    : null;

  return (
    <ScreenBody
      title={t(passed ? 'p1.reason.title.pass' : `screen.${number}.title`)}
      purpose={t(passed ? 'p1.reason.guide.pass' : `screen.${number}.guide`)}
      more={<DetailChip runId={view.runId} />}
      back={flow.back}
      main={flow.next}
    >
      {reasonCodes.length > 0 ? (
        <ReasonChain
          mode="plain"
          reasonCodes={reasonCodes}
          facts={facts}
          verdict={verdict}
          unresolved={decision.unresolved}
          changed={changed}
        />
      ) : (
        <ReasonFigure
          items={recordedItems(t, decision, changedTag)}
          verdict={verdict}
          unresolved={decision.unresolved}
        />
      )}
    </ScreenBody>
  );
}
