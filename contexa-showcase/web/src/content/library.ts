/**
 * The scenario library (deck p.14): eight attack groups with a legitimate request that looks the same, and W1, the
 * layer comparison where perimeter security stops the attack first. A card plays only a pair the portal has
 * published; the others say they are being prepared.
 */
export interface LibraryEntry {
  readonly key: string;
  readonly standard: string;
  readonly attack: { readonly ko: string; readonly en: string };
  readonly twin: { readonly ko: string; readonly en: string };
  /** The representative scene of the first screen and screen 1. */
  readonly featured?: boolean;
  /** A layer comparison rather than a look-alike pair: the second line is not a legitimate request. */
  readonly comparison?: boolean;
}

export const LIBRARY: readonly LibraryEntry[] = [
  {
    key: 'A1',
    standard: 'ATT&CK T1078',
    attack: { ko: '탈취 계정 사용', en: 'Use of a stolen account' },
    twin: { ko: '출장지에서의 정상 접속', en: 'A normal sign-in on a business trip' },
  },
  {
    key: 'A2',
    standard: 'ATT&CK T1539',
    attack: { ko: '세션 탈취 재사용', en: 'Reuse of a stolen session' },
    twin: { ko: '이동 중 네트워크 전환', en: 'A network switch on the move' },
  },
  {
    key: 'A3',
    standard: 'ATT&CK T1213',
    attack: { ko: '내부자 대량 반출', en: 'Insider bulk export' },
    twin: { ko: '승인된 프로젝트 이관', en: 'An approved project transfer' },
    featured: true,
  },
  {
    key: 'A4',
    standard: 'ATT&CK T1030',
    attack: { ko: '저속 분할 반출', en: 'Slow export in small pieces' },
    twin: { ko: '정기 보고서 작성', en: 'Writing the regular report' },
  },
  {
    key: 'A5',
    standard: 'ATT&CK T1098',
    attack: { ko: '관리 기능 남용', en: 'Abuse of an admin function' },
    twin: { ko: '승인된 권한 변경', en: 'An approved permission change' },
  },
  {
    key: 'A6',
    standard: 'OWASP API6',
    attack: { ko: '객체 접근 방식 악용', en: 'Abuse of object access' },
    twin: { ko: '고객 지원 일괄 처리', en: 'Batch work in customer support' },
  },
  {
    key: 'A7',
    standard: 'OWASP LLM06',
    attack: { ko: 'AI 에이전트 위임 남용', en: 'Abuse of an AI agent’s delegation' },
    twin: { ko: '승인된 자동화 작업', en: 'An approved automation job' },
  },
  {
    key: 'A8',
    standard: 'OWASP LLM01',
    attack: { ko: '컨텍스트 조작', en: 'Context manipulation' },
    twin: { ko: '실제 긴급 장애 대응', en: 'A real urgent incident response' },
  },
  {
    key: 'W1',
    standard: 'OWASP A03',
    comparison: true,
    attack: { ko: '경계보안이 막는 공격', en: 'An attack perimeter security stops' },
    twin: {
      ko: '층 비교 · SQL 인젝션은 경계보안이 먼저 막는다',
      en: 'Layer comparison · the perimeter stops SQL injection first',
    },
  },
];
