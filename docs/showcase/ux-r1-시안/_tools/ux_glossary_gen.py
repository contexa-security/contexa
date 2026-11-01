"""Writes the glossary (DEC-69): the keys file for add_keys.py and src/ux/glossary/terms.ts, from one table.

    python -X utf8 ux_glossary_gen.py <keys.json to write>

Rows: (group, id, ko name, en name, ko definition, en definition, link or None, short ko or None).
The 62 rows of 기획안 9절 keep its Korean names and definitions as written; 9 rows come from the old glossary.
"""
import json
import pathlib
import sys

ROWS = [
    # Decisions and enforcement
    ('decisions', 'decision', '판정', 'Decision', 'Contexa가 요청에 내린 처분(허용 · 추가 인증 · 검토 보류 · 차단)', 'The disposition Contexa gives a request: allow, step-up authentication, hold for review or block', None, None),
    ('decisions', 'allow', '허용', 'Allow', '요청을 그대로 처리', 'The request is served as asked', None, None),
    ('decisions', 'stepUp', '추가 인증', 'Step-up authentication', '추가 인증을 통과해야 요청이 이어짐', 'The request continues only after an extra authentication passes', None, None),
    ('decisions', 'holdForReview', '검토 보류', 'Hold for review', '응답 전에 멈추고 검토로 넘김(HTTP 423)', 'Stopped before the response and passed to review (HTTP 423)', None, None),
    ('decisions', 'block', '차단', 'Block', '요청을 거부', 'The request is refused', None, None),
    ('decisions', 'noDecision', '판정 없음', 'No decision', '분석 미완료 · 기술적 실패', 'The analysis did not complete, or a technical failure', None, None),
    ('decisions', 'reusedDecision', '직전 판정 재사용', 'Reused prior decision', '유효한 이전 판정으로 처리', 'Handled with an earlier decision that still applies', None, None),
    ('decisions', 'syncAsync', '동기 판정 · 비동기 판정', 'Synchronous · asynchronous decision', '적용 시점. 동기 판정은 응답 전에, 비동기 판정은 다음 요청부터 적용', 'When a decision applies: a synchronous one before the response, an asynchronous one from the next request', None, None),
    ('decisions', 'shadowMode', '관찰 모드', 'Shadow mode', '판정을 기록만 함', 'Decisions are recorded only, not applied', '/adopt?tab=shadow', None),
    ('decisions', 'enforceMode', '적용 모드', 'Enforce mode', '판정을 적용', 'Decisions are applied', None, None),
    ('decisions', 'unblock', '차단 해제', 'Unblocking', '오판으로 차단된 계정이 추가 인증을 거쳐 보안 담당자에게 해제를 요청하고, 승인되면 원래 요청이 다시 나가는 절차', 'For an account blocked by mistake: after step-up authentication it asks the security administrator for a release, and once approved the original request goes out again', None, None),
    # Security controls
    ('controls', 'fiveControls', '5개 보안 통제', 'Five security controls', '같은 요청을 동시에 받는 비교 대상 5개', 'The five compared controls that receive the same request at once', None, None),
    ('controls', 'existingControls', '기존 보안 통제', 'Existing controls', '웹 방화벽 · 인증 · 권한 · 임계값 규칙 · 승인 정책 규칙', 'The web application firewall, identity and access, threshold rules and approval policy rules', None, '기존 통제'),
    ('controls', 'waf', '웹 방화벽(WAF)', 'Web application firewall (WAF)', 'OWASP CRS 기반 요청 검사', 'Request inspection based on the OWASP CRS', None, None),
    ('controls', 'iam', '인증 · 권한(IAM)', 'Identity & access (IAM)', '계정 인증 · 역할 기반 권한', 'Account authentication and role-based permissions', None, None),
    ('controls', 'thresholdRules', '임계값 규칙', 'Threshold rules', '시각 · 건수 · 휴면 기준', 'Rules on the time of day, the number of items and dormancy', None, None),
    ('controls', 'approvalRules', '승인 정책 규칙', 'Approval policy rules', '승인 · 티켓 · 담당 기준', 'Rules on approvals, tickets and assignments', None, None),
    # Decision evidence
    ('evidence', 'baseline', '행위 기준선', 'Behavioral baseline', '주체의 학습된 정상 행위 범위', "The learned range of a subject's normal behaviour", '/engine?tab=baseline', None),
    ('evidence', 'baselineDeviation', '기준선 이탈', 'Baseline deviation', '기준선 밖의 값', 'A value outside the baseline', None, None),
    ('evidence', 'baselineLearning', '기준선 학습', 'Baseline learning', '허용된 요청만 기준선에 반영', 'Only allowed requests are learned into the baseline', None, None),
    ('evidence', 'businessContext', '업무 컨텍스트', 'Business context', '배정 · 승인 · 티켓 · 당번 · 출장 기록', 'Assignment, approval, ticket, on-call and business-trip records', None, None),
    ('evidence', 'device', '단말', 'Device', '요청을 보낸 브라우저 · OS', 'The browser and OS a request came from', None, None),
    ('evidence', 'network', '네트워크', 'Network', 'IP 대역 · 영역', 'The IP range and zone', None, None),
    ('evidence', 'export', '반출 · 반출 건수', 'Export · exported items', '요청으로 나간 문서 수', 'The documents a request took out', None, None),
    ('evidence', 'riskScore', '위험도', 'Risk score', '모델이 낸 0~1 값', 'A value from 0 to 1 the model gave', None, None),
    ('evidence', 'confidence', '확신도', 'Confidence', '모델이 낸 0~1 값', 'A value from 0 to 1 the model gave', None, None),
    ('evidence', 'hypotheses', '가설 평가', 'Hypothesis assessment', '설명 4~5개를 지지 · 반박 사실로 비교', 'Four or five explanations compared by the facts for and against them', None, None),
    ('evidence', 'decisionSummary', 'AI 판정 요약', 'Decision summary', '모델이 쓴 한 문장(번역 표시)', 'The one sentence the model wrote (shown translated)', None, None),
    ('evidence', 'citedFact', '인용 사실(F · S · R · P · B 번호)', 'Cited fact', '프롬프트 사실 줄', 'A fact line of the prompt', '/engine?tab=facts', None),
    ('evidence', 'reasonCode', '근거 코드', 'Reason code', '사실마다 붙인 정해진 코드', 'The fixed code attached to each fact', None, None),
    ('evidence', 'integritySeal', '무결성 봉인 · 무결성 검증', 'Integrity seal · integrity verification', '판정 입력 · 프롬프트 · 응답의 해시 봉인과 재계산 검사', "A hash seal over a decision's input, prompt and answer, and the check that recomputes it", '/engine?tab=seal', None),
    ('evidence', 'prompt', '프롬프트', 'Prompt', '판정 모델에 보낸 글 전체', 'The whole text sent to the decision model', '/engine?tab=prompt', None),
    ('evidence', 'token', '토큰', 'Token', '두 뜻으로 쓰임. 접근 토큰은 에이전트가 위임받아 요청에 쓰는 인증 토큰, 모델 토큰은 판정 모델이 읽고 쓴 글의 양을 세는 비용 단위', 'Used in two senses: an access token is the authentication token an agent was delegated and sends with its requests; a model token is the unit, counted for cost, of the text the decision model read and wrote', None, None),
    ('evidence', 'promptChecks', '프롬프트 검사', 'Prompt checks', '판정 입력이 정해진 대로 만들어지는지 보는 검사. 전달(바꾼 조건이 기대한 줄에만 들어감) · 반응(판정이 정책대로 바뀜) · 불변(관계없는 값을 바꿔도 그대로) · 지시문 막기(끼워 넣은 지시문에 판정이 흔들리지 않음)', 'Checks that a decision input is built as intended: delivery (a changed condition reaches only its expected line), reaction (the decision moves as the policy says), invariance (an unrelated change leaves it as it was) and injection resistance (an inserted instruction does not move the decision)', '/validation?tab=quality', None),
    # Threats and subjects
    ('threats', 'exfiltration', '데이터 유출', 'Data exfiltration', '업무 밖 목적의 반출', 'An export for a purpose outside the work', None, None),
    ('threats', 'compromisedAccount', '탈취된 계정 · 위협 행위자', 'Compromised account · threat actor', '시나리오의 정답(통제에는 전달되지 않음)', "The scenario's ground truth (never passed to a control)", None, None),
    ('threats', 'accountOwner', '계정 주인', 'Account owner', '계정의 실제 주인. 대조군 시나리오에서 같은 요청을 정상 업무로 보냄', 'The real owner of the account; in a control run it sends the same request as normal work', None, None),
    ('threats', 'atoInsider', '계정 탈취 · 내부자 위협', 'ATO & insider threat', '사람 주체 위협 시나리오 묶음', 'The group of threat scenarios with a person as the subject', '/simulate/person', None),
    ('threats', 'insiderMisuse', '내부자 권한 남용', 'Insider privilege misuse', '권한 안의 업무 외 목적 행위', 'An act within the permissions for a purpose outside the work', None, None),
    ('threats', 'injection', '프롬프트 주입', 'Prompt injection', '요청 · 문서 · 도구 응답에 지시문을 끼워 넣어 AI 모델이나 에이전트를 움직이려는 공격. 도구 응답 속에 넣으면 간접 프롬프트 주입', 'An attack that inserts instructions into a request, a document or a tool response to steer an AI model or agent; inside a tool response it is an indirect prompt injection', '/benchmarks', None),
    ('threats', 'agentRequest', 'AI 에이전트 요청', 'AI agent request', '에이전트가 위임받아 보낸 요청', 'A request an agent sent under a delegation', '/simulate/agent', None),
    ('threats', 'businessAgent', '업무 에이전트', 'Business agent', '직원이 업무를 맡기는 AI 에이전트(이 데모는 Spring AI 에이전트)', 'An AI agent employees hand work to (in this demo a Spring AI agent)', None, None),
    ('threats', 'delegation', '위임', 'Delegation', '사람이 에이전트에게 업무를 맡긴 것. 위임 범위 · 위임 기간과 함께 기록됨', 'A person handing work to an agent, recorded with its scope and period', None, None),
    ('threats', 'delegator', '위임자', 'Delegator', '에이전트에게 업무를 맡긴 사람', 'The person who handed the work to the agent', None, None),
    ('threats', 'delegationScope', '위임 범위 · 위임 기간', 'Delegated scope · delegation period', '에이전트가 할 수 있는 대상 · 동작 · 기간', 'What an agent may act on, how and until when', None, None),
    ('threats', 'delegatorCheck', '위임자 확인', 'Delegator check', '에이전트 요청에 대한 추가 인증. 위임자가 승인하거나 거절함', "Step-up authentication for an agent's request: the delegator approves or rejects it", None, None),
    ('threats', 'requestSurge', '요청 급증', 'Request surge', '같은 요청의 동시 유입', 'The same request arriving many times at once', '/simulate/surge', None),
    # Scenarios and measurement
    ('measurement', 'simulation', '위협 시뮬레이션 · 실행', 'Threat simulation · run', '실제 판정으로 시나리오를 실행', 'Running a scenario with real decisions', None, None),
    ('measurement', 'scenario', '시나리오', 'Scenario', '정답이 정해진 요청 묶음(S13 등)', 'A set of requests with a fixed ground truth (S13 and others)', None, None),
    ('measurement', 'expectedDecision', '예상 판정', 'Expected decision', '실행 전에 기록하는 판정 예측', 'The decision predicted and recorded before a run', None, None),
    ('measurement', 'controlRun', '대조군', 'Control run', '같은 요청을 정상 주체가 보낸 시나리오(S13T · N1)', 'A scenario in which a legitimate subject sends the same request (S13T · N1)', None, None),
    ('measurement', 'undetermined', '정답 미지정', 'Undetermined ground truth', '판정이 갈리는 시나리오, 점수에서 제외(M14A 등)', 'A scenario whose right decision is disputed, left out of the scores (M14A and others)', None, None),
    ('measurement', 'missed', '미탐', 'Missed (false negative)', '위협을 허용함', 'A threat was allowed', None, None),
    ('measurement', 'falsePositive', '오탐', 'False positive', '정상 업무를 차단함', 'Normal work was blocked', None, None),
    ('measurement', 'correct', '적중', 'Correct', '정답과 같은 처리', 'Handled as the ground truth says', None, None),
    ('measurement', 'publishedRun', '공개 녹화 실행', 'Published recorded run', '공개용으로 저장한 실제 실행', 'A real run stored for the public', None, None),
    ('measurement', 'consistency', '반복 판정 일치', 'Decision consistency', '같은 입력의 판정 일치 비율', 'The share of identical decisions for the same input', '/metrics?tab=agreement', None),
    ('measurement', 'latency', '판정 시간(p50 · p95)', 'Decision latency', '요청 수신부터 판정 기록까지', "From the request's arrival to the stored decision", '/metrics?tab=latency', None),
    # Screens and menus
    ('screens', 'startDemo', '데모 시작', 'Start the demo', '첫 화면 — 실제 판정 기록과 바로 실행', 'The first screen: real decision records and a run straight away', '/start', None),
    ('screens', 'next', '다음 확인', 'Next', '결과 화면의 추천 3개', 'The three suggestions on a result screen', None, None),
    ('screens', 'focusMode', '집중 모드', 'Focus mode', '위협 시뮬레이션 중 메뉴를 아이콘 레일로 접는 화면 틀', 'The frame that folds the menu into an icon rail during a threat simulation', None, None),
    ('screens', 'policySimulator', '정책 시뮬레이터', 'Policy simulator', '임계값 · 조건을 바꿔 다시 판정', 'Deciding again with thresholds and conditions changed', '/simulate/policy', None),
    ('screens', 'decisionLog', '판정 이력', 'Decision log', '실행 목록과 판정 상세', 'The list of runs and their decision details', '/runs', None),
    ('screens', 'engine', 'AI 판정 엔진 · 판정 흐름', 'AI decision engine · decision flow', '7단계 판정 과정', 'The seven-step decision process', '/engine', None),
    ('screens', 'detectionComparison', '탐지 방식 비교', 'Detection comparison', '규칙 기반 통제와 문맥 기반 판정의 비교', 'Rule-based controls compared with context-based decisions', '/compare', None),
    ('screens', 'standardBenchmarks', '표준 벤치마크', 'Standard benchmarks', '공식 하니스 · 채점 그대로 돌린 공개 벤치마크', 'Public benchmarks run with their official harness and scoring as they are', '/benchmarks', None),
    ('screens', 'scenarioValidation', '시나리오 검증', 'Scenario validation', '데모 시나리오의 반복 측정', "Repeated measurement of the demo's scenarios", '/validation', None),
    ('screens', 'metrics', '운영 지표', 'Operational metrics', '판정 수 · 시간 · 실행 · 일치', 'Decisions, latency, runs and consistency', '/metrics', None),
    ('screens', 'adoption', '도입 · 연동 가이드', 'Deployment & integration', '의존성 · 어노테이션 · 모드 · 보관', 'Dependency, annotations, modes and retention', '/adopt', None),
    ('screens', 'tour', '제품 투어', 'Product tour', '메뉴별 안내 영상', 'Guide videos by menu', '/tour', None),
    ('screens', 'glossary', '보안 용어집', 'Security glossary', '용어 정의', 'The definitions of the terms', None, None),
]

GROUPS = [
    ('decisions', '판정과 적용', 'Decisions and enforcement'),
    ('controls', '보안 통제', 'Security controls'),
    ('evidence', '판정 근거', 'Decision evidence'),
    ('threats', '위협과 주체', 'Threats and subjects'),
    ('measurement', '시나리오와 측정', 'Scenarios and measurement'),
    ('screens', '화면과 메뉴', 'Screens and menus'),
]

# The old glossary's ids (components/common/glossaryTerms.ts) and the term of the same meaning; the rest open the list.
OLD = {
    'approaches': 'fiveControls', 'waf': 'waf', 'access': 'iam', 'permission': 'iam', 'session': 'iam',
    'limits': 'thresholdRules', 'approval': 'approvalRules', 'lab': 'policySimulator', 'result': 'decision',
    'judgment': 'decision', 'pass': 'allow', 'identityCheck': 'stepUp', 'hold': 'holdForReview', 'block': 'block',
    'rightStop': 'correct', 'rightPass': 'correct', 'missed': 'missed', 'falseBlock': 'falsePositive',
    'noDecision': 'noDecision', 'sync': 'syncAsync', 'async': 'syncAsync', 'usual': 'baseline',
    'workRecord': 'businessContext', 'learned': 'baselineLearning', 'learnAdd': 'baselineLearning',
    'reason': 'decisionSummary', 'prompt': 'prompt', 'prior': 'reusedDecision', 'situation': 'scenario',
    'stolenAccount': 'compromisedAccount', 'realUser': 'accountOwner', 'export': 'export', 'unblock': 'unblock',
    'shadow': 'shadowMode', 'businessAgent': 'businessAgent', 'delegation': 'delegation', 'delegator': 'delegator',
    'delegationRecord': 'delegationScope', 'delegationScope': 'delegationScope', 'delegationPeriod': 'delegationScope',
    'delegatorCheck': 'delegatorCheck', 'fact': 'citedFact', 'reasonCode': 'reasonCode', 'seal': 'integritySeal',
    'token': 'token', 'riskScore': 'riskScore', 'delivery': 'promptChecks', 'reaction': 'promptChecks',
    'invariance': 'promptChecks', 'injection': 'injection',
}

ids = [row[1] for row in ROWS]
assert len(ids) == len(set(ids)) == 71, len(ids)
assert set(OLD.values()) <= set(ids)
keys = {}
for gid, ko, en in GROUPS:
    keys[f'ux.glossary.group.{gid}'] = [ko, en]
for group, tid, ko, en, kdef, edef, link, short in ROWS:
    keys[f'ux.glossary.term.{tid}.name'] = [ko, en]
    keys[f'ux.glossary.term.{tid}.def'] = [kdef, edef]
    if short:
        keys[f'ux.glossary.term.{tid}.short'] = [short, en]
keys.update({
    'ux.glossary.title': ['보안 용어집', 'Security glossary'],
    'ux.glossary.desc': ['데모 화면의 모든 이름은 이 용어집의 한국어 · 영어 정식 이름을 씁니다. 메뉴 이름인 용어는 그 화면으로 이어집니다.', 'Every name on the demo screens is an official Korean and English name of this glossary. A term that names a menu leads to its screen.'],
    'ux.glossary.search': ['용어 검색', 'Search the terms'],
    'ux.glossary.searchHint': ['한국어 · 영어 이름이나 정의', 'Korean or English name, or definition'],
    'ux.glossary.count': ['용어 {{n}}개', '{{n}} terms'],
    'ux.glossary.count_one': ['용어 {{n}}개', '{{n}} term'],
    'ux.glossary.found': ['검색 결과 {{n}}개', '{{n}} found'],
    'ux.glossary.found_one': ['검색 결과 {{n}}개', '{{n}} found'],
    'ux.glossary.empty': ['맞는 용어가 없습니다.', 'No term matches.'],
    'ux.glossary.clear': ['검색 지우기', 'Clear the search'],
    'ux.glossary.list': ['용어 목록', 'Terms'],
    'ux.glossary.pick': ['목록에서 용어를 고르면 정의가 여기에 나옵니다.', 'Pick a term in the list and its definition appears here.'],
    'ux.glossary.english': ['영어 이름', 'English name'],
    'ux.glossary.short': ['좁은 칸의 줄임', 'Short form in narrow cells'],
    'ux.glossary.group': ['묶음', 'Group'],
    'ux.glossary.open': ['이 화면 열기', 'Open this screen'],
    'ux.glossary.detail': ['용어 정의', 'Definition'],
    'ux.glossary.close': ['정의 닫기', 'Close the definition'],
})
out = pathlib.Path(sys.argv[1])
out.write_bytes(json.dumps(keys, ensure_ascii=False, indent=1).encode('utf-8'))

lines = [
    "// The security glossary's terms (기획안 9절 + 9 terms of the old glossary, DEC-69): written by",
    "// docs/showcase/ux-r1-시안/_tools/ux_glossary_gen.py from one table; the names and definitions are dictionary keys",
    "// (`ux.glossary.term.<id>.name|def`).",
    '',
    'export interface GlossaryTerm {',
    '  readonly id: string;',
    '  /** The official English name, shown beside the Korean one and searched in either language. */',
    '  readonly en: string;',
    '  /** The screen the term names, when it names one. */',
    '  readonly link?: string;',
    '  /** A short form for narrow cells (기획안 9절 "줄임"). */',
    '  readonly short?: boolean;',
    '}',
    '',
    'export interface GlossaryGroup {',
    '  readonly id: string;',
    '  readonly terms: readonly GlossaryTerm[];',
    '}',
    '',
    'export const GLOSSARY: readonly GlossaryGroup[] = [',
]
for gid, _, _ in GROUPS:
    lines.append(f"  {{")
    lines.append(f"    id: '{gid}',")
    lines.append('    terms: [')
    for group, tid, ko, en, kdef, edef, link, short in ROWS:
        if group != gid:
            continue
        assert "'" not in en, en
        parts = [f"id: '{tid}'", f"en: '{en}'"]
        if link:
            parts.append(f"link: '{link}'")
        if short:
            parts.append('short: true')
        lines.append('      { ' + ', '.join(parts) + ' },')
    lines.append('    ],')
    lines.append('  },')
lines.append('];')
lines.append('')
lines.append("/** The old glossary's ids (`?modal=glossary&term=`) and the term of the same meaning; any other opens the list. */")
lines.append('export const OLD_GLOSSARY_TERMS: Readonly<Record<string, string>> = {')
for old, new in OLD.items():
    lines.append(f"  {old}: '{new}',")
lines.append('};')
lines.append('')
target = pathlib.Path('E:/projects/contexa/contexa-showcase/web/src/ux/glossary/terms.ts')
target.parent.mkdir(exist_ok=True)
target.write_bytes('\n'.join(lines).encode('utf-8'))
print(len(keys), 'keys;', len(ids), 'terms;', len(OLD), 'old ids')
