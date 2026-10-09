import { useQuery } from '@tanstack/react-query';
import { getJson } from './http';

/**
 * The demo's real settings of the five approaches and its retention periods (portal PublicSettings): every value is
 * the running stack's own, null where a source does not state it.
 */
export interface PublicSettingsView {
  readonly waf: { readonly image: string | null; readonly ruleSet: string | null };
  readonly permission: { readonly roleRules: readonly string[] };
  readonly threshold: {
    readonly nightStart: string | null;
    readonly nightEnd: string | null;
    readonly volumeLimit: number | null;
    readonly dormantWindowDays: number | null;
  };
  readonly businessRecord: {
    readonly exportPolicyKey: string | null;
    readonly assignedExportLimit: number | null;
    readonly ticketAndOncallExempt: boolean | null;
    readonly historyWindowDays: number | null;
    readonly exportHistoryWindowDays: number | null;
    readonly accessPolicies: readonly {
      readonly policyKey: string | null;
      readonly accountManagerExempt: boolean;
      readonly assignedExempt: boolean;
      readonly recentWorkDays: number | null;
    }[];
  };
  readonly engine: {
    readonly chatModel: string | null;
    readonly effectiveMode: string | null;
    /** How many adverse conditions the core's response inspector checks in every answer. */
    readonly inspectorConditions: number;
  };
  readonly retention: { readonly behaviorDays: number | null; readonly promptOriginalDays: number };
  readonly ruleVersion: string | null;
}

export function usePublicSettings() {
  return useQuery({
    queryKey: ['public-settings'],
    queryFn: () => getJson<PublicSettingsView>('/api/settings'),
    staleTime: 60_000,
    retry: false,
  });
}
