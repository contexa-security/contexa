import pathlib, re
s = pathlib.Path('d-home.html').read_text(encoding='utf-8')
s = s.replace('<html lang="ko">', '<html lang="en">').replace('<title>데모 시작</title>', '<title>Start the Demo</title>')
s = s.replace('data-lang="ko" data-crumbs="라이브 데모|데모 시작"', 'data-lang="en" data-crumbs="Live demo|Start the demo"')
T = {
 'LIVE · 실제 AI 판정': 'LIVE · real AI decisions',
 '같은 계정 · 같은 시각 · 같은 요청,<br>그중 하나는 탈취된 계정입니다': 'Same account, same request —<br>one of them is compromised.',
 'Contexa는 로그인 이후의 요청을 행위 기준선과 업무 컨텍스트로 판정합니다. 실제 요청을 5개 보안 통제에 동시에 보내, 어느 통제가 무엇을 막는지 직접 확인합니다.': 'Contexa decides every post-login request against the behavioral baseline and the business context. Send a real request to five security controls at once and see which control stops what.',
 '계정 탈취 시나리오 실행': 'Run the account takeover scenario',
 '시나리오 선택': 'Choose a scenario',
 '가입 없음': 'No sign-up', '실제 AI 판정 · p50 6.0초': 'Real AI decision · p50 6.0 s', '방문자당 하루 10회': '10 runs per visitor per day',
 '공개 녹화 실행': 'Published recorded run',
 '설계 자료 480건 반출 · 엔지니어 K 계정 · 처음 확인된 단말 · 수 14:20': 'Export of 480 design documents · Engineer K account · first-seen device · Wed 14:20',
 '웹 방화벽(WAF)': 'Web application firewall', '인증 · 권한(IAM)': 'Identity & access (IAM)', '임계값 규칙': 'Threshold rules', '승인 정책 규칙': 'Approval policy rules',
 '추가 인증': 'Step-up', '480건': '480', '0건': '0', '0.027초': '0.027 s', '0.021초': '0.021 s', '0.025초': '0.025 s', '0.041초': '0.041 s', '10.2초': '10.2 s',
 '기존 보안 통제 4개 · 미탐': 'Four existing controls · missed', '건 × 4 반출': 'items exported × 4', 'Contexa · 응답 전 판정': 'Contexa · decided before the response', '건 반출': 'items exported',
 '위협 시나리오': 'Threat scenarios', '시나리오를 고르면 요청 검토 → 실시간 판정 → 결과까지 4단계로 진행합니다': 'Each scenario runs in four steps: review the request, live decision, result',
 '전체 시나리오': 'All scenarios',
 '권장 시작': 'Start here', '위협 · 대조군': 'Threat · control', '계정 탈취(ATO)': 'Account takeover (ATO)',
 '탈취된 계정이 처음 확인된 단말에서 설계 자료 480건을 반출합니다.': 'A compromised account exports 480 design documents from a first-seen device.',
 '확인하는 것': 'What it checks',
 '같은 요청을 정상 사용자가 보내면 판정이 달라지는가': 'Does the decision change when the legitimate user sends the same request?',
 '요청 1건 · 대조군 1건': '1 request · 1 control run', '실행': 'Run',
 '위협': 'Threat', '내부자 위협': 'Insider threat',
 '담당 프로젝트 안에서 업무와 무관한 영업 기밀 문서를 수집합니다.': 'Collects sales-confidential documents unrelated to the job inside an assigned project.',
 '권한 안의 요청 가운데 업무 밖 목적을 찾아내는가': 'Does it find the non-business purpose among in-permission requests?',
 '요청 3건': '3 requests', '시나리오 5종': '5 scenarios', 'AI 에이전트 위임 남용': 'AI agent delegation abuse',
 '위임 기간이 끝난 뒤 보고서 에이전트가 같은 토큰으로 예약 실행을 이어 갑니다.': 'After the delegation expires, a report agent keeps a scheduled run going with the same token.',
 '토큰 · 권한이 유효해도 위임 밖 요청을 멈추는가': 'Does it stop out-of-delegation requests while the token and permissions are valid?',
 'Spring AI 업무 에이전트': 'Spring AI business agent', '운영 성능': 'Operations', '요청 급증 대응': 'Request surge handling',
 '같은 목록 요청이 한꺼번에 몰릴 때 판정을 하나로 통합합니다.': 'Merges the decision when identical list requests arrive at once.',
 '판정을 통합해도 전달 결과가 같은가, 모델 호출은 얼마나 줄어드는가': 'Are delivered results unchanged, and how many model calls are saved?',
 '요청 최대 60건 동시': 'Up to 60 at once', '허용': 'Allow',
 '위협 시나리오 선택': 'Choose a threat scenario', '정답(위협 · 정상 업무)은 통제에 전달되지 않음': 'The ground truth is never sent to any control',
 '요청 검토 · 판정 예측': 'Review and predict', '요청 사실을 보고 예상 판정을 기록': 'Read the request facts, record your expected decision',
 '실시간 판정': 'Live decision', '5개 보안 통제가 같은 요청을 동시에 판정': 'Five controls decide the same request at once',
 '결과 · 판정 근거': 'Result and evidence', '반출 건수 비교와 AI가 인용한 근거': 'Exported items compared, with the facts the AI cited',
 '표준 벤치마크': 'Standard benchmarks', '공식 하니스 · 채점 그대로': 'Official harnesses and scoring, unchanged', '전체 결과': 'All results',
}
for k in sorted(T, key=len, reverse=True):
    s = s.replace('>' + k + '<', '>' + T[k] + '<')
s = s.replace('>같은 계정 · 같은 시각 · 같은 요청,<br>그중 하나는 탈취된 계정입니다<', '>' + T['같은 계정 · 같은 시각 · 같은 요청,<br>그중 하나는 탈취된 계정입니다'] + '<')
left = sorted(set(re.findall(r'>[^<>]*[가-힣][^<>]*<', s)))
print('korean left:', left[:15])
pathlib.Path('d-home-en.html').write_text(s, encoding='utf-8')
