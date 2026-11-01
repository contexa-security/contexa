/**
 * The decision prompt's line names (the v20 · v21 dictionary, core SecurityDecisionPromptDictionary) and which entry a
 * line belongs to, so the decision details can name each fact in the visitor's words (moved from the old screens'
 * components/facts/factWords.ts at I-10, DEC-80).
 */

/** Every entry of the v20 dictionary (core SecurityDecisionPromptDictionary), numbered entries by their stem. */
export const FACT_LABELS = [
  'Evidence',
  'BaselineStatus',
  'UsualHours',
  'UsualDays',
  'UsualNetworks',
  'UsualDevices',
  'UsualLoginMethods',
  'UsualTargets',
  'UsualActions',
  'UsualResourceClass',
  'UsualExportSize',
  'UsualRequestRate',
  'UsualSessionLength',
  'UsualPrivilegedActions',
  'SeasonalPattern',
  'KnownRareTasks',
  'WorkProfile',
  'PeerReference',
  'SessionAge',
  'LoginMethod',
  'ChallengeVerified',
  'RecentMfaElsewhere',
  'FailedLogins',
  'MfaFailures',
  'RequestsInSession',
  'RecentRequests',
  'ConcurrentSessions',
  'PasswordAge',
  'RecentSensitiveAccess',
  'RecentDenied',
  'Subject',
  'Roles',
  'Permissions',
  'Time',
  'Action',
  'Target',
  'TargetScope',
  'Size',
  'ResourceClass',
  'Network',
  'Device',
  'DeviationsFromBaseline',
  'SameAsBaseline',
  'Policy',
  'PolicySatisfied',
  'Approval',
  'Assignment',
  'Ticket',
  'OnCall',
  'Travel',
  'RepeatInSession',
  'RoleScope',
  'RecentPermissionChanges',
  'TemporaryElevation',
  'AuthorizationEffect',
  'DataConflicts',
  'Movement',
  'SessionDeviceChange',
  'SessionNetworkChange',
  'ClientSignals',
  'BlockedUser',
  'BreakGlass',
  'PeerCohort',
  'Delegation',
  'ThreatMatch',
  'PastRecordsState',
  'PastRecordCounts',
  'PastRecord',
  'PastDeniedDecision',
  'SupportingCases',
  'ValidatedCases',
  'Coverage',
  'Unknown',
  'UntrustedText',
  'FirstPassVerdict',
  'NewlyKnown',
  'NewPastRecord',
  // docs/agent A2, A4, F-5: the v21 dictionary's lines of an agent's request.
  'Credential',
  'Confirmation',
  'DelegationActivity',
  'RecordProvenance',
  'RecordsHolder',
  'BaselineSubject',
  'UsualSequence',
  'UsualClients',
  // v21.18 (CQ-1): where a value of the protected call's arguments first appeared (a tool's output).
  'ArgumentOrigin',
] as const;
export type FactLabel = (typeof FACT_LABELS)[number];

/** The entries drawn once per item, their label the stem and the item's number (PastRecord1, UntrustedText2). */
const NUMBERED: readonly FactLabel[] = ['PastRecord', 'PastDeniedDecision', 'UntrustedText', 'NewPastRecord'];

/** The dictionary key of a line's label: its entry, or 'other' for a label the dictionary does not list. */
export function factKey(label: string): FactLabel | 'other' {
  if ((FACT_LABELS as readonly string[]).includes(label)) {
    return label as FactLabel;
  }
  return NUMBERED.find((stem) => label.startsWith(stem) && /^\d+$/.test(label.slice(stem.length))) ?? 'other';
}
