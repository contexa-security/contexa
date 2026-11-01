// The security glossary's terms (기획안 9절 + 9 terms of the old glossary, DEC-69): written by
// docs/showcase/ux-r1-시안/_tools/ux_glossary_gen.py from one table; the names and definitions are dictionary keys
// (`ux.glossary.term.<id>.name|def`).

export interface GlossaryTerm {
  readonly id: string;
  /** The official English name, shown beside the Korean one and searched in either language. */
  readonly en: string;
  /** The screen the term names, when it names one. */
  readonly link?: string;
  /** A short form for narrow cells (기획안 9절 "줄임"). */
  readonly short?: boolean;
}

export interface GlossaryGroup {
  readonly id: string;
  readonly terms: readonly GlossaryTerm[];
}

export const GLOSSARY: readonly GlossaryGroup[] = [
  {
    id: 'decisions',
    terms: [
      { id: 'decision', en: 'Decision' },
      { id: 'allow', en: 'Allow' },
      { id: 'stepUp', en: 'Step-up authentication' },
      { id: 'holdForReview', en: 'Hold for review' },
      { id: 'block', en: 'Block' },
      { id: 'noDecision', en: 'No decision' },
      { id: 'reusedDecision', en: 'Reused prior decision' },
      { id: 'syncAsync', en: 'Synchronous · asynchronous decision' },
      { id: 'shadowMode', en: 'Shadow mode', link: '/adopt?tab=shadow' },
      { id: 'enforceMode', en: 'Enforce mode' },
      { id: 'unblock', en: 'Unblocking' },
    ],
  },
  {
    id: 'controls',
    terms: [
      { id: 'fiveControls', en: 'Five security controls' },
      { id: 'existingControls', en: 'Existing controls', short: true },
      { id: 'waf', en: 'Web application firewall (WAF)' },
      { id: 'iam', en: 'Identity & access (IAM)' },
      { id: 'thresholdRules', en: 'Threshold rules' },
      { id: 'approvalRules', en: 'Approval policy rules' },
    ],
  },
  {
    id: 'evidence',
    terms: [
      { id: 'baseline', en: 'Behavioral baseline', link: '/engine?tab=baseline' },
      { id: 'baselineDeviation', en: 'Baseline deviation' },
      { id: 'baselineLearning', en: 'Baseline learning' },
      { id: 'businessContext', en: 'Business context' },
      { id: 'device', en: 'Device' },
      { id: 'network', en: 'Network' },
      { id: 'export', en: 'Export · exported items' },
      { id: 'riskScore', en: 'Risk score' },
      { id: 'confidence', en: 'Confidence' },
      { id: 'hypotheses', en: 'Hypothesis assessment' },
      { id: 'decisionSummary', en: 'Decision summary' },
      { id: 'citedFact', en: 'Cited fact', link: '/engine?tab=facts' },
      { id: 'reasonCode', en: 'Reason code' },
      { id: 'integritySeal', en: 'Integrity seal · integrity verification', link: '/engine?tab=seal' },
      { id: 'prompt', en: 'Prompt', link: '/engine?tab=prompt' },
      { id: 'token', en: 'Token' },
      { id: 'promptChecks', en: 'Prompt checks', link: '/validation?tab=quality' },
    ],
  },
  {
    id: 'threats',
    terms: [
      { id: 'exfiltration', en: 'Data exfiltration' },
      { id: 'compromisedAccount', en: 'Compromised account · threat actor' },
      { id: 'accountOwner', en: 'Account owner' },
      { id: 'atoInsider', en: 'ATO & insider threat', link: '/simulate/person' },
      { id: 'insiderMisuse', en: 'Insider privilege misuse' },
      { id: 'injection', en: 'Prompt injection', link: '/benchmarks' },
      { id: 'agentRequest', en: 'AI agent request', link: '/simulate/agent' },
      { id: 'businessAgent', en: 'Business agent' },
      { id: 'delegation', en: 'Delegation' },
      { id: 'delegator', en: 'Delegator' },
      { id: 'delegationScope', en: 'Delegated scope · delegation period' },
      { id: 'delegatorCheck', en: 'Delegator check' },
      { id: 'requestSurge', en: 'Request surge', link: '/simulate/surge' },
    ],
  },
  {
    id: 'measurement',
    terms: [
      { id: 'simulation', en: 'Threat simulation · run' },
      { id: 'scenario', en: 'Scenario' },
      { id: 'expectedDecision', en: 'Expected decision' },
      { id: 'controlRun', en: 'Control run' },
      { id: 'undetermined', en: 'Undetermined ground truth' },
      { id: 'missed', en: 'Missed (false negative)' },
      { id: 'falsePositive', en: 'False positive' },
      { id: 'correct', en: 'Correct' },
      { id: 'publishedRun', en: 'Published recorded run' },
      { id: 'consistency', en: 'Decision consistency', link: '/metrics?tab=agreement' },
      { id: 'latency', en: 'Decision latency', link: '/metrics?tab=latency' },
    ],
  },
  {
    id: 'screens',
    terms: [
      { id: 'startDemo', en: 'Start the demo', link: '/start' },
      { id: 'next', en: 'Next' },
      { id: 'focusMode', en: 'Focus mode' },
      { id: 'policySimulator', en: 'Policy simulator', link: '/simulate/policy' },
      { id: 'decisionLog', en: 'Decision log', link: '/runs' },
      { id: 'engine', en: 'AI decision engine · decision flow', link: '/engine' },
      { id: 'detectionComparison', en: 'Detection comparison', link: '/compare' },
      { id: 'standardBenchmarks', en: 'Standard benchmarks', link: '/benchmarks' },
      { id: 'scenarioValidation', en: 'Scenario validation', link: '/validation' },
      { id: 'metrics', en: 'Operational metrics', link: '/metrics' },
      { id: 'adoption', en: 'Deployment & integration', link: '/adopt' },
      { id: 'tour', en: 'Product tour', link: '/tour' },
      { id: 'glossary', en: 'Security glossary' },
    ],
  },
];

/** The old glossary's ids (`?modal=glossary&term=`) and the term of the same meaning; any other opens the list. */
export const OLD_GLOSSARY_TERMS: Readonly<Record<string, string>> = {
  approaches: 'fiveControls',
  waf: 'waf',
  access: 'iam',
  permission: 'iam',
  session: 'iam',
  limits: 'thresholdRules',
  approval: 'approvalRules',
  lab: 'policySimulator',
  result: 'decision',
  judgment: 'decision',
  pass: 'allow',
  identityCheck: 'stepUp',
  hold: 'holdForReview',
  block: 'block',
  rightStop: 'correct',
  rightPass: 'correct',
  missed: 'missed',
  falseBlock: 'falsePositive',
  noDecision: 'noDecision',
  sync: 'syncAsync',
  async: 'syncAsync',
  usual: 'baseline',
  workRecord: 'businessContext',
  learned: 'baselineLearning',
  learnAdd: 'baselineLearning',
  reason: 'decisionSummary',
  prompt: 'prompt',
  prior: 'reusedDecision',
  situation: 'scenario',
  stolenAccount: 'compromisedAccount',
  realUser: 'accountOwner',
  export: 'export',
  unblock: 'unblock',
  shadow: 'shadowMode',
  businessAgent: 'businessAgent',
  delegation: 'delegation',
  delegator: 'delegator',
  delegationRecord: 'delegationScope',
  delegationScope: 'delegationScope',
  delegationPeriod: 'delegationScope',
  delegatorCheck: 'delegatorCheck',
  fact: 'citedFact',
  reasonCode: 'reasonCode',
  seal: 'integritySeal',
  token: 'token',
  riskScore: 'riskScore',
  delivery: 'promptChecks',
  reaction: 'promptChecks',
  invariance: 'promptChecks',
  injection: 'injection',
};
