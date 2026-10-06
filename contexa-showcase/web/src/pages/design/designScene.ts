import type { BusinessOutcome, ControlId, Verdict } from '../../domain/verdict';
import type { EvidenceChain } from '../../components/EvidenceDrawer';

/**
 * Sample data of the verdict-comparison design mock. It is used only by the development-only /design
 * route, is labelled "design mock, sample data" on screen and never ships in the production bundle.
 */
interface SceneLayer {
  readonly control: ControlId;
  readonly outcome: BusinessOutcome;
  readonly verdict: Verdict;
  readonly reason: Readonly<Record<'ko' | 'en', string>>;
  readonly evidence: EvidenceChain;
}

export const designScene = {
  badge: { ko: '디자인 시안 · 예시 데이터', en: 'Design mock · sample data' },
  title: { ko: '판정 비교 화면 시안', en: 'Verdict comparison mock' },
  specLabel: 'engine 0.1.0 · gpt-5-nano',
  request: {
    ko: '관리자 A가 회사 시각 03:17, 담당이 아닌 프로젝트의 설계 문서 4,831건을 내보내려 합니다.',
    en: 'Admin A tries to export 4,831 design documents from a project they are not assigned to, at 03:17 company time.',
  },
  nextScene: {
    ko: '겉모습이 같은 정당한 이관',
    en: 'A legitimate transfer that looks the same',
  },
  layers: [
    {
      control: 'A',
      outcome: 'DELIVERED',
      verdict: 'ALLOW',
      reason: { ko: 'WAF 규칙에 걸리지 않음', en: 'No WAF rule matched' },
      evidence: { decisionId: 'sample-a-0001', verdict: 'ALLOW', timing: 'Before response', httpStatus: 200, outcome: 'Passed · data left' },
    },
    {
      control: 'B',
      outcome: 'DELIVERED',
      verdict: 'ALLOW',
      reason: { ko: 'ROLE_ADMIN 보유', en: 'Holds ROLE_ADMIN' },
      evidence: { decisionId: 'sample-b-0001', verdict: 'ALLOW', timing: 'Before response', httpStatus: 200, outcome: 'Passed · data left' },
    },
    {
      control: 'C1',
      outcome: 'STOPPED',
      verdict: 'BLOCK',
      reason: { ko: '야간·대량 임계값 초과', en: 'Night-time and volume thresholds exceeded' },
      evidence: { decisionId: 'sample-c1-0001', verdict: 'BLOCK', timing: 'Before response', httpStatus: 403, outcome: 'Stopped' },
    },
    {
      control: 'C2',
      outcome: 'STOPPED',
      verdict: 'BLOCK',
      reason: { ko: '맞는 승인과 당번 기록 없음', en: 'No matching approval or on-call duty' },
      evidence: { decisionId: 'sample-c2-0001', verdict: 'BLOCK', timing: 'Before response', httpStatus: 403, outcome: 'Stopped' },
    },
    {
      control: 'D',
      outcome: 'STOPPED',
      verdict: 'BLOCK',
      reason: { ko: '담당 아님 · 평소의 300배 · 처음 보는 시간대', en: 'Not assigned · 300x usual volume · unseen hour' },
      evidence: {
        decisionId: 'sample-d-0001',
        verdict: 'BLOCK',
        timing: 'Before response (synchronous)',
        httpStatus: 403,
        outcome: 'Stopped',
        engineReasoning:
          'Sample text. The requester is not assigned to the project, the export volume is far above the personal baseline and the hour has never been observed.',
      },
    },
  ] satisfies readonly SceneLayer[],
} as const;
