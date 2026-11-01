# UC-5 사실 되살리기 · A5 묶음(정책 시뮬레이터 · 개인정보 처리방침 · 제품 투어)

- 날짜: 2026-11-01 03:57(세계 표준시)
- 근거: 기획안 P-8, DEC-82, 초안 `uc5-facts-draft.md` 3절 없음 목록(L-case · L-change · L-before · L-send · L-result · L-rules · L-agent · O-privacy · O-videos)과 5절 "함께 본 점"의 정답 미지정 시나리오 묶음, 조정자가 보탠 4-4(S14 출장 도시).
- 경로 기준: 옛 줄과 새 줄은 `contexa-showcase/web/src` 아래. 포털 근거는 `contexa-showcase/showcase-portal/src/main` 아래(`java/io/contexa/showcase/portal/…`, `resources/db/migration/portal/…`).
- 확인 방법: 행마다 옛 줄을 열어 방문자에게 보이는 값인지 보고, 새 화면(`ux/`) 전체에서 같은 값을 그리는 곳이 없는지 확인한 뒤 넣었습니다. 값은 포털 응답 그대로 쓰고, 숫자는 `formatNumber` · `formatDuration`, 값이 없으면 "—"입니다. 길거나 부차적인 사실은 접힌 "자세히"(`details`)에 넣었습니다.

| 번호 | 사실 | 옛 줄(열어 본 file:line) | 판정 | 새 위치(file:line) 또는 이유 |
|---|---|---|---|---|
| L-case | 시나리오 직원 이름 · 역할(`LabOptions.employees[].displayName` · `role`) | `pages/lab/LabCasePage.tsx:20-29`(25) | 되살림 | `ux/pages/simulate/policy/ComposeTab.tsx:178-184`(1단계 카드 "직원") |
| L-case(5절) | 정답 미지정(`classification` UNCERTAIN, S07 · S08) 시나리오가 "정답이 정상 업무" 묶음에 들어감 | `pages/lab/LabCasePage.tsx:108-121` · `pages/lab/labPlace.ts:96-98`(옛 화면은 따로 "미리 정하지 않은 상황") | 되살림(고침) | `ux/pages/simulate/policy/ComposeTab.tsx:52-59`(묶음 3개), `:159-170`(묶음 "정답을 정하지 않은 시나리오", 빈 묶음은 그리지 않음), `:185-190`(1단계 "정답 · 정하지 않음(UNCERTAIN)") |
| L-change | 직원 이름 · 역할(L-case와 같은 값) | `pages/lab/LabChangePage.tsx:61,88-97` | 되살림 | 같은 탭 1단계 카드 `ComposeTab.tsx:178-184`에 한 번만 둠 |
| L-change | 요청이 여러 개인 시나리오의 원래 조건(바꿀 수 없는 건수 포함) | `pages/lab/LabChangePage.tsx:24,99-106` | 되살림 | `ComposeTab.tsx:252-268`(2단계 "원래 조건" 접힌 구획: 시각 · 장소 · 단말 · 건수 · 승인 기록 중 시나리오가 정한 값) |
| L-change | 요청 수 n(`LabCase.requests.length`) | `pages/lab/LabChangePage.tsx:157-161` | 되살림 | `ComposeTab.tsx:209-212`(2단계 부제 "요청 n개가 이어지는 시나리오라…"), `:258-261`("요청 수") |
| L-before | 충족된 최소 대응 규칙 이름(`minimumRules.rules[].code`, `met=true`) | `pages/lab/LabBeforePage.tsx:19-25,40-44` | 되살림 | `ComposeTab.tsx:279-290`(`lineText`) → 3단계 표 "최소 대응 규칙" 줄 "해당 · 규칙 이름"(이름이 없는 코드는 코드 그대로) |
| L-send | 대기 순서 · 대기 예상 초(`queuePosition` · `queueWaitSeconds`) | `pages/lab/LabSendPage.tsx:254-260` | 되살림 | `ComposeTab.tsx:503-512`(5단계 카드 안내) |
| L-send | 통제별 응답 시간 · 내준 건수 · 스트림 진행(`layers[].elapsedMs` · `deliveredItems`, `streams[].delivered` · `total` · `atMs`) | `pages/lab/LabSendPage.tsx:228-234,269-289` → `pages/try/steps/LiveRunBar.tsx:55-85,118-160` | 되살림 | `ComposeTab.tsx:532-535`, `:583-608`(`LiveMeta`, 칸마다 배지 아래 "0.027초 · 480건", 스트림 중 "2.4초 · 120 / 480건") |
| L-send | Contexa 판정 대기 남은 초(`decisionWait.remainingSeconds`) | `pages/lab/LabSendPage.tsx:204-205,235,282-286` | 되살림 | `ComposeTab.tsx:391-395`, `:543-547`("Contexa 판정 대기 · 약 n초 남음") |
| L-send | 끝난 추가 인증 단계 NO_MAILBOX · ABANDONED | `pages/lab/LabSendPage.tsx:302-309`(`pages/try/steps/liveRun.tsx:18`) | 되살림 | `ComposeTab.tsx:61`, `:548-560`. `ux/simulate/Recovery.tsx:51`이 이 두 단계에 아무것도 그리지 않아 이 탭에서 안내 한 줄로 그림(Recovery는 고치지 않음) |
| L-result | 두 실행에서 다른 조건(`Versus.changedConditions`) | `pages/lab/LabResultPage.tsx:26-45,173-181` | 되살림 | `ComposeTab.tsx:746-757`(6단계 "서버가 찾은 두 실행의 다른 조건", 빈 목록은 "없음", null은 "—"). 옛 화면은 직전 실험실 실행과 비교할 때 제목에 썼고, 새 6단계는 설계대로 실행과 비교하므로 그 비교의 서버 값을 그대로 보임 |
| L-result | 예상이 맞았는지(`RecentLabRun.callRight`, 같은 줄의 `call`) | `pages/lab/LabResultPage.tsx:215-224` | 되살림 | `ComposeTab.tsx:738-745`("예상 판정 공격" + "정답과 같음/다름" 배지, 새로고침 뒤에도 서버 값) |
| L-result | 바꾼 조건이 판정 프롬프트에 닿았는지(`LabDelta`) | `pages/lab/LabResultPage.tsx:77-109,134,184,262` | 되살림 | `ComposeTab.tsx:758-770`(6단계 "자세히", 비교 기준 실행 ID와 함께), `:786-813`(옛 줄 고르기 규칙 그대로) |
| L-result | 다른 방문자 평가(`PeerAssessments`: 건수 · 방문자 수 · 답별 · 이유별 · 지연 시간) | `components/assessment/AssessPanel.tsx:132,139-172` | 되살림 | `ComposeTab.tsx:771-774`, `:815-855`(요청마다, "자세히" 안, 읽기만) |
| L-result | 평가 창의 입력 선택지(`assessmentReasons` 체크 상자, 판정된 요청 고르기, 평가 보내기) | `components/assessment/AssessPanel.tsx:28-31,65-131` | 사실 아님 | 방문자가 자기 평가를 쓰는 입력 양식(POST `/api/runs/{id}/steps/{n}/assessment`)의 선택지이지 실행의 사실이 아님. 새 화면에는 평가 쓰기가 없음(DEC-70 ②). 같은 이유 코드의 집계는 위 행에서 되살림 |
| L-rules | 기본값에서의 처리(`RuleChange.before`) | `pages/lab/LabRulesPage.tsx:133-134,298` | 되살림 | `ux/pages/simulate/policy/PolicyPage.tsx:170-172,286`("기본값 허용 → 바꾼 값 차단". null은 "알 수 없음"; 전에는 null도 "이제 허용"으로 보였음) |
| L-rules | 바뀐 상황 0개(`changed` 빈 목록) | `pages/lab/LabRulesPage.tsx:287` | 되살림 | `PolicyPage.tsx:293-296`("기본값과 결과가 달라진 시나리오가 없습니다.") |
| L-agent | 요청 주체(`AgentCaseView.sender`) | `pages/lab/LabAgentPage.tsx:92,96` | 되살림 | `ux/pages/simulate/policy/AgentPolicyTab.tsx:313-314`(저장된 답의 "자세히": 시나리오 정의의 요청 주체 `caseView.sender`, 이 실행의 요청 주체 `run.sender`. 메뉴 답은 경로에 따라 둘이 다름) |
| L-agent | 에이전트 실행 1회의 점수(`LiveConfig.agentRunPoints`) | `pages/lab/LabAgentPage.tsx:71-79` | 되살림 | `AgentPolicyTab.tsx:100-106,183`("이 값으로 실제 실행" 아래) |
| L-agent | 업무에 필요한 양(`proof.workNeeds`) | `pages/main/AgentResultParts.tsx:40-43` | 되살림 | `AgentPolicyTab.tsx:316-319`(null은 "필요 없음") |
| L-agent | 통제별 내준 것(`proof.controls[].documents` · `items` · `records` · `changes`) | `pages/main/AgentResultParts.tsx:75-82` | 되살림 | `AgentPolicyTab.tsx:322-372`(통제별 표, 처음 멈춘 요청과 함께) |
| L-agent | 통제별 필요 이상(`proof.controls[].beyondNeed`) | `pages/main/AgentResultParts.tsx:83` | 되살림 | 같은 표 마지막 열(`AgentPolicyTab.tsx:359-364`) |
| L-agent | 반복 요청 묶음 요약(건수 · 자체 판정 · 모델 호출) | `pages/main/AgentTimeline.tsx:80-115` · `pages/main/timelineFolding.ts:17-68` | 되살림 | `AgentPolicyTab.tsx:14-62`(`burstsOf`, 옛 규칙 그대로: 같은 주소 · 같은 답 5건 이상), `:375-385` |
| L-agent | 오늘 모든 방문자에게 남은 실제 에이전트 실행(`LiveConfig.liveTicketsLeft`) | `pages/lab/DelegationEditPanel.tsx:61,129` | 되살림 | `AgentPolicyTab.tsx:100-106,183` |
| 4-4(S14 출장 도시) | 시나리오의 업무 기록 `labCase.facts[TRAVEL].city`(S14 Singapore) | `pages/main/CheckPage.tsx:126-127,157` | 되살림 | `ComposeTab.tsx:63-86`(`factText`), `:191-195`(1단계 카드에 시나리오의 업무 기록 전부; S14는 "출장 · 싱가포르 · SG · 198.51.100.0/24"). 값은 `/api/lab/options`의 `LabCase.facts` 그대로(`src/api` 고치지 않음) |
| O-privacy | 진행 위치 세부(경로 · 그룹 · 단계 · 확인한 차이 · 처음 연 그룹) | `content/policies.ts:41-45` | 되살림 | `ux/pages/privacy/PrivacyPage.tsx:23,113-117`(`ux.privacy.old.journey`). 포털이 아직 저장: `V21__visitor_journey.sql:4-16`(5행 방문자 삭제 때 함께 삭제), `journey/JourneyStore.java:59-70`, `journey/JourneyViews.java:215-239`(새 화면의 예상 저장도 이 행을 다시 씀), `retention/RetentionJob.java:75-76` |
| O-privacy | 판정 평가(평가한 요청 · 답과 이유 · 시각), 다른 방문자에게 건수로만, 보관 | `content/policies.ts:46-50` | 되살림 | `PrivacyPage.tsx:113-117`(`ux.privacy.old.assessment`). 포털이 아직 저장 · 공개: `V14__lab.sql:26-35`, `lab/LabController.java:245-266`(받음), `:272-280`(건수 공개), `retention/RetentionJob.java:87,93-97`(식별자만 지움). 금지어 "판단" 대신 "판정 평가". DEC-70 ②(평가 문장을 뺌)와 다르므로 사용자 승인 필요 |
| O-privacy | 상황별 예측, 방문자 식별자와 함께 삭제 | `content/policies.ts:76` | 되살림 | `PrivacyPage.tsx:113-117`(`ux.privacy.old.scene`). 포털이 아직 저장: `V4__replay_and_prediction.sql:10-18`(12행 방문자 삭제 때 함께 삭제), `visitor/VisitorStore.java:29`, `visitor/VisitorController.java:73-90`, `retention/RetentionJob.java:75-76` |
| O-videos | 영상별 다루는 화면 목록(이름 · 링크, `guides.json.<id>.screens`) | `pages/GuidesPage.tsx:101-113` | 사실 아님 | 옛 화면 번호(1-1, 2-1 …)와 옛 주소(`journey/route.json`)로 가는 이동 링크. 대상 화면 · 주소가 개편으로 없어짐. 또 옛 목록은 legacy 영상을 빼서(`pages/GuidesPage.tsx:48`) 지금 매니페스트(console · agent, 둘 다 legacy)로는 한 줄도 그리지 않았음. 영상이 녹화된 화면 판은 새 투어가 이미 보임(`ux/pages/tour/TourPage.tsx:122`) |
| O-videos | 묶음 머리글(`guides.group.S/H/A/C`) | `pages/GuidesPage.tsx:23,64-76`(68) · `components/guide/guideConfig.ts:35-42` | 사실 아님 | 첫 화면 번호의 track(`route.json`)으로 정한 목록 분류 머리글. 포털 응답이나 영상의 값이 아님. 위와 같이 지금은 그려지지 않았음 |

참고

- 개인정보 처리방침의 "전에 있던 화면이 남긴 기록"은 한 문장에서 목록 6줄로 나눴습니다(`PrivacyPage.tsx:113-117`). 이미 있던 세 가지(이해 확인 문항 건수 30일, 결과 공유 카드 90일, 그룹을 처음 연 익명 건수 30일)도 각자의 기간과 함께 한 줄씩 적어, 초안이 지적한 "기간이 익명 건수 30일에 묶여 모호함"도 풀었습니다. 기존 시험의 "판단 평가 없음" · "지금 화면이 보내지 않습니다" 확인은 그대로 통과합니다(새 문구는 "판정 평가").
- 사전에서 쓰지 않게 된 키: `ux.policy.changes.stops` · `ux.policy.changes.passes`(기본값 → 바꾼 값 표현으로 바뀜). 키 도구는 지우지 못하므로 남겨 둡니다.
- 같은 탭의 옛 키 `lab.field.device`("기기")는 금지어지만 이 작업 전부터 조건 선택에 쓰였고, 새 "원래 조건" · "다른 조건" 줄도 탭 안에서 같은 이름을 쓰도록 이 키를 따랐습니다.

## 확인한 것

| 확인 | 결과 |
|---|---|
| `npx tsc -p tsconfig.app.json --noEmit --incremental false` | 오류 0 |
| `npx eslint src/ux/pages/simulate/policy src/ux/simulate/labConditions.ts src/ux/pages/privacy src/ux/pages/tour` | 문제 0 |
| `npx stylelint` Policy · Privacy · Tour 모듈 CSS | 문제 0(처음 `no-descending-specificity` 4건 → 통제별 표를 클래스 선택자로 바꿔 해결) |
| `npx vitest run src/ux/pages/simulate/policy src/ux/pages/privacy src/ux/pages/tour src/ux/ux-wording.test.ts` | 4개 파일 84개 통과(정책 20 · 개인정보 5 · 투어 6 · 문구 53). 새 시험 11개(정책 10 · 개인정보 1)와 기존 ST-38 시험에 확인 1개 추가 |
| 사전 키 | `ux_keys_locked.py`로 85개 추가 · 2개 변경(`ux.policy.compose.changeSubSteps`, `ux.privacy.external.old`), 넣기 전 금지어 대조 0건 |
