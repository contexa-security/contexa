import { useTranslation } from 'react-i18next';
import type { AgentRunView } from '../../api/agentCase';
import type { LiveRunView } from '../../api/types';
import { CONTROL_ORDER, type ControlId } from '../../domain/verdict';
import { agentCell, operationWords, storedLayers, type AgentCell } from './agent';

/** One request of the agent's work as a row: what it asked and each control's answer. */
export interface AgentRow {
  readonly stepNo: number;
  /** The request in the visitor's words: the tool the agent used, or the operation while it is followed live. */
  readonly name: string;
  readonly path: string | null;
  readonly cells: Readonly<Record<ControlId, AgentCell>>;
  /** Items control D handed over for the request; null while unknown. */
  readonly items: number | null;
  /** Contexa's own decision of the request as stored (decision.final_action); null without one, absent while live. */
  readonly verdict?: string | null;
  /** The model calls of the request's own decision as stored; null without one, absent while live. */
  readonly modelCalls?: number | null;
}

export function useLiveRows(view: LiveRunView | null): readonly AgentRow[] {
  const { t } = useTranslation();
  return (view?.steps ?? []).map((step) => ({
    stepNo: step.stepNo,
    name: operationWords(t, step.operation),
    path: null,
    cells: Object.fromEntries(
      CONTROL_ORDER.map((control) => [control, agentCell(step.layers[control] ?? null)]),
    ) as Record<ControlId, AgentCell>,
    items: step.layers.D?.deliveredItems ?? null,
  }));
}

export function useRecordRows(run: AgentRunView | null | undefined): readonly AgentRow[] {
  const { t } = useTranslation();
  return (run?.steps ?? []).map((step) => {
    const layers = storedLayers(step);
    return {
      stepNo: step.stepNo,
      name: step.tool ? t(`ux.agent.tool.${step.tool.tool}`, { defaultValue: step.tool.tool }) : t('ux.agent.scripted'),
      path: step.path,
      cells: Object.fromEntries(
        CONTROL_ORDER.map((control) => [
          control,
          agentCell(layers[control] ?? null, control === 'D' ? (step.decision?.final_action ?? null) : null),
        ]),
      ) as Record<ControlId, AgentCell>,
      items: layers.D?.deliveredItems ?? null,
      verdict: step.decision?.final_action ?? null,
      modelCalls: step.decision?.model_calls ?? null,
    };
  });
}
