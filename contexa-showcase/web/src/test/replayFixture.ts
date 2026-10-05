import type { Pair } from '../api/types';

/**
 * Test-only copy of the shape the portal returned for the development recording of pair A3 (2026-10-05, five of five
 * runs agreed). It is imported by tests only, so it never reaches the production bundle.
 */
export const replayFixture: Pair = {
  key: 'A3',
  question: {
    ko: '관리자 A가 새벽 03:17, 담당이 아닌 프로젝트의 설계 문서 4,831건을 내보내려 합니다.',
    en: 'At 03:17, admin A tries to export 4,831 design documents from a project they are not assigned to.',
  },
  scenes: [
    {
      kind: 'ATTACK',
      sentence: {
        ko: '관리자 A가 새벽 03:17, 담당이 아닌 프로젝트의 설계 문서 4,831건을 내보내려 합니다.',
        en: 'At 03:17, admin A tries to export 4,831 design documents from a project they are not assigned to.',
      },
      recordId: 'rec-a3-a-test',
      agreeing: 5,
      repetitions: 5,
      recordedAt: '2026-10-05T02:56:37Z',
      specHash: 'a'.repeat(64),
      companyTime: '2026-09-30T03:17:00Z',
      featuredStep: 1,
      steps: 1,
      layers: [
        layer('A', 'DELIVERED', 'ALLOW', 200, 'RBAC', { role: 'ADMIN' }),
        layer('B', 'DELIVERED', 'ALLOW', 200, 'RBAC', { role: 'ADMIN' }),
        layer('C1', 'STOPPED', 'BLOCK', 403, 'C1-NIGHT', { items: 4831, night: true }),
        layer('C2', 'STOPPED', 'BLOCK', 403, 'C2-NO-CONTEXT', { items: 4831 }),
        {
          control: 'D',
          outcome: 'DELIVERED',
          verdict: 'ALLOW',
          httpStatus: 200,
          ruleId: null,
          reason: null,
          ruleFacts: {},
          evidence: {
            decisionId: '3522bb83-0f99-481d-9466-f1249f5094df',
            verdict: 'ALLOW',
            timing: 'BEFORE_RESPONSE',
            httpStatus: 200,
            outcome: 'DELIVERED',
            deliveredItems: 4831,
            engineReasoning:
              'Authorization allows access with a limited baseline, and no concrete risk or verification requirement is present.',
            riskScore: 0.2,
            confidence: 0.6,
            unresolved: false,
            stream: null,
            responseMs: 1702,
            timeline: [
              { type: 'CONTEXT_COLLECTED', layer: null, action: null, atMs: 38, elapsedMs: null },
              { type: 'LAYER1_START', layer: 'LAYER1', action: null, atMs: 38, elapsedMs: null },
              { type: 'LAYER1_COMPLETE', layer: 'LAYER1', action: 'ALLOW', atMs: 1666, elapsedMs: 1627 },
              { type: 'DECISION_APPLIED', layer: 'LAYER1', action: 'ALLOW', atMs: 1666, elapsedMs: null },
            ],
          },
        },
      ],
      engineReason: {
        canonical: 'ALLOW_LIMITED_BASELINE_NO_RISK',
        reasoning:
          'Authorization allows access with a limited baseline, and no concrete risk or verification requirement is present.',
        evidenceRefs: ['baseline', 'authorization', 'session', 'resource', 'mfa.freshness.stale'],
        deltas: [],
        resourceSensitivity: 'RESTRICTED',
      },
      companyFacts: [
        { code: 'NOT_ASSIGNED', value: 'GB-500' },
        { code: 'NO_APPROVAL', value: null },
        { code: 'ACCESS_DAYS_LAST_30', value: '0' },
        { code: 'ITEMS', value: '4831' },
      ],
    },
    {
      kind: 'LEGITIMATE',
      sentence: {
        ko: '관리자 A가 새벽 03:17, 승인된 프로젝트 이관으로 같은 설계 문서 4,831건을 내보냅니다.',
        en: 'At 03:17, admin A exports the same 4,831 design documents under an approved project transfer.',
      },
      recordId: 'rec-a3-l-test',
      agreeing: 5,
      repetitions: 5,
      recordedAt: '2026-10-05T02:56:50Z',
      specHash: 'a'.repeat(64),
      companyTime: '2026-09-30T03:17:00Z',
      featuredStep: 1,
      steps: 1,
      layers: [
        layer('A', 'DELIVERED', 'ALLOW', 200, 'RBAC', { role: 'ADMIN' }),
        layer('B', 'DELIVERED', 'ALLOW', 200, 'RBAC', { role: 'ADMIN' }),
        layer('C1', 'STOPPED', 'BLOCK', 403, 'C1-NIGHT', { items: 4831, night: true }),
        layer('C2', 'DELIVERED', 'ALLOW', 200, 'C2-APPROVAL', { items: 4831 }),
        {
          control: 'D',
          outcome: 'DELIVERED',
          verdict: 'ALLOW',
          httpStatus: 200,
          ruleId: null,
          reason: null,
          ruleFacts: {},
          evidence: {
            decisionId: 'd2e30915-0000-4000-8000-000000000001',
            verdict: 'ALLOW',
            timing: 'BEFORE_RESPONSE',
            httpStatus: 200,
            outcome: 'DELIVERED',
            deliveredItems: 4831,
            engineReasoning: 'A free text reason the engine wrote.',
            riskScore: 0.1,
            confidence: 0.7,
            unresolved: false,
            stream: null,
            responseMs: 2410,
            timeline: [
              { type: 'CONTEXT_COLLECTED', layer: null, action: null, atMs: 12, elapsedMs: null },
              { type: 'LAYER1_START', layer: 'LAYER1', action: null, atMs: 13, elapsedMs: null },
              { type: 'LAYER1_COMPLETE', layer: 'LAYER1', action: 'ALLOW', atMs: 2380, elapsedMs: 2366 },
              { type: 'DECISION_APPLIED', layer: 'LAYER1', action: 'ALLOW', atMs: 2381, elapsedMs: null },
            ],
          },
        },
      ],
      engineReason: {
        canonical: null,
        reasoning: 'A free text reason the engine wrote.',
        evidenceRefs: ['approval', 'baseline'],
        deltas: [],
        resourceSensitivity: 'RESTRICTED',
      },
      companyFacts: [{ code: 'APPROVAL_COVERS', value: 'PROJECT_TRANSFER' }],
    },
  ],
};

function layer(
  control: 'A' | 'B' | 'C1' | 'C2',
  outcome: 'DELIVERED' | 'STOPPED',
  verdict: 'ALLOW' | 'BLOCK',
  httpStatus: number,
  ruleId: string,
  ruleFacts: Record<string, unknown>,
) {
  return {
    control,
    outcome,
    verdict,
    httpStatus,
    ruleId,
    reason: 'raw rule reason',
    ruleFacts,
    evidence: {
      decisionId: `request-${control}`,
      verdict,
      timing: 'BEFORE_RESPONSE' as const,
      httpStatus,
      outcome,
      deliveredItems: outcome === 'DELIVERED' ? 4831 : 0,
      engineReasoning: null,
      riskScore: null,
      confidence: null,
      unresolved: false,
      stream: null,
      responseMs: 12,
      timeline: [],
    },
  };
}
