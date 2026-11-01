# UC-5 사실 보존 점검 초안

- 날짜: 2026-11-01
- 성격: 에이전트가 만든 초안입니다. 사람이 다시 확인해야 합니다. 코드만 읽고 판단했고, 화면을 띄우거나 포털을 부르지는 않았습니다.
- 기준: 기획안 P-8(사실은 버리지 않는다)과 11절 "64화면 제목 다시 쓰기" 표의 모든 행(59행)입니다.
- 경로 기준: `contexa-showcase/web/src`. 옛 화면은 `pages/`, `components/`, `journey/`, 새 화면은 `ux/`입니다.
- 옛 화면 찾기: 기획안의 옛 제목을 `i18n/ko.json`의 옛 키(`ux.`로 시작하지 않는 키)에서 찾고, 그 키를 옛 코드에서 찾았습니다. 옛 주소와 화면 대응은 UX-R1 이전 `App.tsx`(커밋 99ef9605c)와 `screens.tsx`로 확인했습니다.
- 대조 방법: 행을 12묶음으로 나눠 하위 점검이 옛 화면과 그 부품을 열고 사실을 뽑아 새 화면과 맞췄습니다. 그 뒤 이 문서를 만들면서 다음을 확인했습니다.
  - 표에 인용한 file:line 1,998개가 모두 실제 파일의 줄 범위 안에 있음(스크립트로 확인).
  - 인용 줄 약 1,100개(절반 남짓)를 내용까지 열어 사실과 맞는지 확인.
  - "없음" 필드 40여 개를 `ux/` 전체에서 다시 grep 해 그리는 곳이 없음을 확인.
- 판정 뜻
  - 있음: 기획안 11절의 새 위치에서 그 사실을 그립니다.
  - 다른 위치: 새 위치에는 없고, `ux/`의 다른 화면에서 그립니다(주소는 새 위치 칸이나 메모에 있음).
  - 없음: `ux/` 전체에서 그 사실을 그리는 곳을 찾지 못했습니다.
- 표의 "옛 화면(파일)" 칸은 옛 화면이 그 사실을 그린 줄입니다. "새 위치" 칸은 새 화면이 그리는 줄입니다. `A→B`는 A가 값을 넘기고 B가 그린다는 뜻입니다.

## 1. 집계

- 행: 59행 모두 옛 화면을 찾았고, 59행을 대조했습니다. 옛 화면을 찾지 못한 행은 0행입니다.
- 사실: 784개. 표의 한 줄이 사실 하나입니다. 한 단위로 함께 보이는 필드 묶음은 한 줄로 셌습니다.
- 판정: 있음 476 · 다른 위치 163 · 없음 145.
- 같은 옛 화면을 여러 행이 함께 쓰면(예: 2-1 · 4-1 · 5-1의 RequestPage, 2-2 · 4-2 · 5-2의 ConsolePage) 사실을 첫 행에 한 번만 적었습니다.

| 번호 | 사실 | 있음 | 다른 위치 | 없음 | 비고 |
|---|---|---|---|---|---|
| 1-1 | 5 | 2 | 3 | 0 |  |
| C-1 | 0 | 0 | 0 | 0 | 사실 없음(이동 카드 · 고정 문구) |
| H-1 | 0 | 0 | 0 | 0 | 사실 없음(이동 카드 · 고정 문구) |
| 2-1 | 15 | 10 | 4 | 1 |  |
| 2-2 | 52 | 32 | 12 | 8 |  |
| 2-3 | 15 | 4 | 9 | 2 |  |
| 2-4 | 9 | 4 | 4 | 1 |  |
| 4-1 | 0 | 0 | 0 | 0 | 2-1 행에 함께 적음 |
| 4-2 | 0 | 0 | 0 | 0 | 2-2 행에 함께 적음 |
| 4-3 | 13 | 9 | 3 | 1 |  |
| 4-4 | 19 | 6 | 10 | 3 |  |
| 5-1 | 1 | 0 | 1 | 0 | 공통 사실은 2-1 행에 함께 적음 |
| 5-2 | 6 | 4 | 1 | 1 | 공통 사실은 2-2 행에 함께 적음 |
| 5-3 | 18 | 8 | 8 | 2 |  |
| H-6 · A-6 · D-1 · M-more | 4 | 4 | 0 | 0 |  |
| A-1 | 2 | 2 | 0 | 0 |  |
| 6-1 | 17 | 12 | 1 | 4 |  |
| 6-2 | 19 | 9 | 5 | 5 |  |
| 6-7 | 16 | 9 | 3 | 4 |  |
| 6-3 | 25 | 8 | 11 | 6 |  |
| 6-4 | 24 | 10 | 5 | 9 |  |
| 6-5 | 7 | 3 | 1 | 3 |  |
| 6-6 | 20 | 11 | 0 | 9 |  |
| 1-2 | 4 | 0 | 4 | 0 |  |
| 3-1 | 23 | 17 | 5 | 1 |  |
| 3-2 | 15 | 13 | 1 | 1 |  |
| 3-3 | 20 | 7 | 11 | 2 |  |
| 7-1 | 6 | 6 | 0 | 0 |  |
| 7-2 | 11 | 0 | 9 | 2 |  |
| 7-3 | 10 | 7 | 3 | 0 |  |
| 8-1 | 10 | 6 | 4 | 0 |  |
| 8-2 · O-adopt | 19 | 13 | 4 | 2 |  |
| M-learn | 5 | 3 | 2 | 0 |  |
| M-learned | 16 | 8 | 1 | 7 |  |
| M-how | 0 | 0 | 0 | 0 | 사실 없음(이동 카드 · 고정 문구) |
| M-stack | 13 | 10 | 1 | 2 |  |
| M-learnafter | 3 | 2 | 1 | 0 |  |
| M-timing | 11 | 3 | 6 | 2 |  |
| M-follow | 10 | 2 | 5 | 3 |  |
| M-approaches | 8 | 1 | 7 | 0 |  |
| L-entrance | 2 | 2 | 0 | 0 |  |
| L-case | 6 | 3 | 2 | 1 |  |
| L-change | 7 | 4 | 0 | 3 |  |
| L-before | 8 | 7 | 0 | 1 |  |
| L-send | 11 | 7 | 0 | 4 |  |
| L-result | 11 | 5 | 2 | 4 |  |
| L-rules | 16 | 14 | 0 | 2 |  |
| L-agent | 30 | 18 | 5 | 7 |  |
| B-summary | 19 | 16 | 2 | 1 |  |
| B-approaches | 12 | 12 | 0 | 0 |  |
| B-cases · B-case | 15 | 14 | 0 | 1 |  |
| B-judgment | 13 | 13 | 0 | 0 |  |
| B-reasoning | 8 | 8 | 0 | 0 |  |
| B-limits | 28 | 27 | 0 | 1 |  |
| B-agent | 9 | 9 | 0 | 0 |  |
| O-videos | 9 | 7 | 0 | 2 |  |
| O-privacy | 18 | 15 | 0 | 3 |  |
| O-replay | 14 | 8 | 2 | 4 |  |
| O-detail | 77 | 42 | 5 | 30 |  |

## 2. 행별 대조

### 1-1

- 옛 제목: 로그인 이후의 위협을 판단하는 AI 보안
- 옛 화면: `pages/main/OpeningPage.tsx` (키 `main.1-1.title`)
- 새 위치: 라이브 데모 › 데모 시작 = /start · `ux/pages/home/HomePage.tsx`, `ux/pages/home/HomeParts.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 1-1 | `components/AppHeader.tsx:88` | 오늘 방문자 실행 `stats.runs.today` | `ux/shell/TopBar.tsx:43` | 있음 | 옛 화면 전체 공통 막대라 여기서 한 번만 셈. /start도 Shell 안에 있음 |
| 1-1 | `components/AppHeader.tsx:93` | 누적 판단 `stats.engineDecisions` | `ux/shell/TopBar.tsx:47` | 있음 | 새 화면은 값이 없으면 `decisionTime.decisions`를 씀 |
| 1-1 | `components/guide/GuidePreview.tsx:39` (pages/main/OpeningPage.tsx:30) | 시작 안내 영상 길이 `guides.start.durationSec` (/guides/guides.json) | `ux/pages/tour/TourPage.tsx:88` | 다른 위치 | /tour. /start에는 영상 링크가 없음 |
| 1-1 | `components/guide/GuideWindow.tsx:31` | 영상 녹화 날짜 `guides.start.recordedAt` | `ux/pages/tour/TourPage.tsx:89` | 다른 위치 | /tour |
| 1-1 | `components/guide/GuideWindow.tsx:31` | 영상의 화면 판 `guides.start.screens` | `ux/pages/tour/TourPage.tsx:93` | 다른 위치 | /tour. 값 자체 대신 '이전 화면' 뱃지만 보임(값 ≠ 'ux-r1'일 때) |

### C-1

- 옛 제목: 체험할 요청 유형을 선택하세요
- 옛 화면: `pages/main/TrackChoosePage.tsx` (키 `main.C-1.title`)
- 새 위치: 위협 시뮬레이션 1단계 묶음 탭 = /start, /simulate/person, /simulate/agent · `ux/pages/simulate/person/PickPage.tsx`, `ux/pages/simulate/agent/PickPage.tsx`
- 참고: 옛 화면(TrackChoosePage.tsx)은 고정 문구로 된 이동 카드뿐이라 포털 값이 없습니다(A 묶음 보고).

### H-1

- 옛 제목: 요청을 보낸 주체를 선택하세요
- 옛 화면: `pages/main/PersonChoosePage.tsx` (키 `main.H-1.title`)
- 새 위치: 1단계(사람 계정 위협 탭) = /simulate/person · `ux/pages/simulate/person/PickPage.tsx`
- 참고: 옛 화면(PersonChoosePage.tsx)은 고정 문구로 된 이동 카드뿐이라 포털 값이 없습니다(A 묶음 보고).

### 2-1

- 옛 제목: 공격자가 되어 대량 다운로드를 요청합니다
- 옛 화면: `pages/main/RequestPage.tsx:88` role attacker (키 `main.2-1.title`)
- 새 위치: 같은 메뉴 2단계(S13) = /simulate/person/S13/review · `ux/pages/simulate/person/ReviewPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:215→126` | 계정 이름 `labOptions.employees[conditions.employee].displayName`(person.{key}) | `ux/pages/simulate/person/ReviewPage.tsx:112` (ux/simulate/person.ts:140) | 있음 | 2-1의 "(탈취됨)"은 역할마다 정해진 고정 문구 |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:218→127` | 요청 시각 `beforeSend.comparison.companyTime` | `ux/pages/simulate/person/ReviewPage.tsx:112` (ux/simulate/person.ts:146) | 있음 | 새 화면에 기준선 표시가 덧붙음 |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:222→127` | 접속 장소 `labOptions.cases[].conditions.place` | `ux/pages/simulate/person/ReviewPage.tsx:125` | 있음 | 새 화면은 `comparison.businessFacts`의 NETWORK_* 칩에서 읽음. `ux/pages/simulate/person/PickPage.tsx:73`에도 있음 |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:223→127` | 사무실 네트워크 대역 `labOptions.employees[].officeNetwork` | `ux/pages/simulate/person/PickPage.tsx:72→157` | 다른 위치 | /simulate/person. 2단계 검토 화면에는 없음. 새 출처는 `usualVsNow[network].now`(S13 값) |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:224→127` | 기기 `conditions.device`(NEW/USUAL) | `ux/pages/simulate/person/ReviewPage.tsx:112`, `:114` | 있음 | 표현이 바뀜: `usualVsNow[device].now` 문자열 + 기준선 이탈/평소 범위 뱃지 |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:230→127` | 로그인 인증 `comparison.usualVsNow[authenticationType].now` | `ux/pages/simulate/person/ReviewPage.tsx:112` (ux/simulate/person.ts:158) | 있음 |  |
| 2-1 · 4-1 | `pages/main/RequestPage.tsx:236→127` | 반출 프로젝트·건수 `labCase.requests[0].project`, `.items` | `ux/pages/simulate/person/ReviewPage.tsx:94`(제목의 n), `:112`(반출 규모), `:125`(ASSIGNED 칩에 프로젝트) | 있음 |  |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:250-252→127` | 담당 여부와 프로젝트 `requests[0].target` + project / document.project | `ux/pages/simulate/person/ReviewPage.tsx:125` | 있음 | 새 출처는 businessFacts의 ASSIGNED/NOT_ASSIGNED(value = 프로젝트) |
| 2-1 · 4-1 | `pages/main/RequestPage.tsx:255→127` | 담당 반출 한도 `publicSettings.businessRecord.assignedExportLimit` | `ux/pages/validation/ValidationPage.tsx:802→854` | 다른 위치 | /validation?tab=controls에서 C2를 골랐을 때 |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:257-263→127` | 승인 기록 유무 `labCase.facts[kind=APPROVAL]` 존재 여부 | `ux/pages/simulate/person/ReviewPage.tsx:125` | 있음 | 새 출처는 businessFacts의 NO_APPROVAL/APPROVAL_COVERS. 고정 응답 before-S16에는 승인 코드가 없어 S16에서는 안 보일 수 있음(실서버 값은 확인 못 함) |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:260-261→127` | 승인 최대 건수·승인자 `APPROVAL.maxItems`, `.approver` | `ux/simulate/Recovery.tsx:273` (ux/pages/simulate/person/LivePage.tsx:333-334) | 다른 위치 | S13T live의 해제 요청 사유 기본값. 고정 응답 세 사례 모두 APPROVAL 사실이 없음 |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:259→127` | 승인 목적 `APPROVAL.purpose` | — | 없음 | 고정 응답 세 사례 모두 APPROVAL 사실이 없음. 옛 화면에서도 실제로 그려진 적 없는 갈래 |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:133` | 사례 번호 `static:mainCases.MAIN_CASES` | `ux/pages/simulate/person/ReviewPage.tsx:88` | 있음 |  |
| 2-1 · 4-1 · 5-1 | `pages/main/RequestPage.tsx:138` | 보낼 요청 줄 `anatomy(comparison.runId).context.resource.httpMethod/requestPath` | `ux/pages/simulate/person/ReviewPage.tsx:104-105` | 있음 |  |
| 2-1 · 4-1 · 5-1 | `components/main/MainScreen.tsx:108→components/guide/GuidePreview.tsx:39` | 요청 안내 영상 길이·녹화일 `guides.request.durationSec/recordedAt` | `ux/pages/tour/TourPage.tsx:88-89` | 다른 위치 | /tour |

### 2-2

- 옛 제목: 같은 요청이 다섯 보안에 동시에 도착했습니다
- 옛 화면: `pages/main/ConsolePage.tsx:171` role attacker (키 `main.2-2.title`)
- 새 위치: 3단계 = /simulate/person/S13/live · `ux/pages/simulate/person/LivePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:264`→`components/AppHeader.tsx:81` | `liveRun.runId` (진행 중 머리) | `ux/pages/simulate/person/LivePage.tsx:144` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:283-284`→`components/StateScreen.tsx:101,105` | `liveRun.queuePosition`, `liveRun.queueWaitSeconds` | `ux/pages/simulate/person/LivePage.tsx:226-229` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:209-215`→`pages/main/consoleParts.tsx:65` | `settings.threshold.nightStart/nightEnd/volumeLimit` (C1 부제) | `ux/pages/compare/ComparePage.tsx:137-143` (/compare?tab=rule) | 다른 위치 | Live 부제는 고정 문구(ux/pages/simulate/person/LivePage.tsx:370) |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:76,78-81` | `liveRun.steps[1].layers[A·B·C1·C2·D].deliveredItems` | `ux/simulate/ControlLanes.tsx:64` | 있음 | 2-2·4-2 막대 |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:48-50,100` | `layers[c].outcome` (미탐·오탐·일부 차단 칩) | `ux/simulate/ControlLanes.tsx:56` | 있음 | 새 화면은 허용/차단 판정만 보임. 미탐·오탐 평가는 `ux/pages/simulate/person/ResultPage.tsx:279` |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:109-111` | `layers[c].httpStatus` (통제별) | `ux/pages/runs/detailTabs.tsx:214` (/runs/:runId?tab=controls) | 다른 위치 | Live에는 D만 있음(`ux/simulate/DecisionProgress.tsx:123→153`) |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:111` | `layers[c].elapsedMs` | `ux/simulate/ControlLanes.tsx:68` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:47,100`; `pages/main/ConsolePage.tsx:351-355` | `analysis.decision.finalAction`/`unresolved` (Contexa 칩·도장) | `ux/simulate/ControlLanes.tsx:56` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:73-77` | `analysis.decision.totalAnalysisMs` ("n초 판단 → n건") | `ux/pages/simulate/person/ResultPage.tsx:207-208` (/simulate/person/S13/result, timings.totalAnalysisMs) | 다른 위치 | Live의 D 행 시간은 layers.D.elapsedMs(ux/pages/simulate/person/LivePage.tsx:369) |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:93` | `analysis.decisionWait.waitedMs` | `ux/pages/simulate/person/LivePage.tsx:215` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:48-49→100` | `layers.D.ruleId` (ACCOUNT_BLOCKED·MFA_CHALLENGE_REQUIRED, 앞선 판정으로 거절) | `ux/simulate/ControlLanes.tsx:51-54` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:334-336` | 기존 보안이 내준 건수 `layers.B.deliveredItems` (요청 합) | `ux/pages/simulate/person/LivePage.tsx:428-429` | 있음 | 새 화면은 기존 4개 건수(같으면 ×4, 다르면 합) |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:346-348` | `layers.D.deliveredItems` (요청 합) | `ux/pages/simulate/person/LivePage.tsx:439-442` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:369`→`components/main/SourceBadge.tsx:36` | `received.runId`/`beforeSend.comparison.runId` (사실 출처 실행) | `ux/pages/simulate/person/LivePage.tsx:262` | 있음 | 저장 뒤 자기 실행은 ux/pages/simulate/person/LivePage.tsx:144 |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:156-162` | `received.comparedCount`, `received.departureCount` | `ux/simulate/DecisionProgress.tsx:76-83→153` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:156-161` | `received.usualVsNow.length` (평소 패턴 항목 수 n) | `ux/pages/runs/detailTabs.tsx:300` (/runs/:runId?tab=evidence, 행 전체) | 다른 위치 | 개수 숫자는 ux 어디에도 없음 |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleParts.tsx:165-171,175,178` | `received.usualVsNow[].dimension/inUsual` (칸별 다름·같음·비교 못 함, 이름 목록) | `ux/pages/runs/detailTabs.tsx:302,307-313` | 다른 위치 | 다른 항목 이름은 `ux/simulate/CompareView.tsx:91-93`에도 있음 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:394-397` (pages/main/consoleData.ts:130-139) | 다른 항목(최대 3) `usualVsNow[].now` + `received.usual[dim].values` | `ux/pages/runs/detailTabs.tsx:302-305` | 다른 위치 | Live에는 값이 없음 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:394-397` (pages/main/consoleData.ts:104-119) | 평소 단말 `usualVsNow[device·browser·operatingSystem].now` (같음) | `ux/pages/simulate/person/ReviewPage.tsx:112,114` (/…/review); `ux/simulate/CompareView.tsx:172-175` | 다른 위치 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:396-397` (pages/main/consoleData.ts:140-163) | `received.businessFacts[APPROVAL_COVERS·NO_APPROVAL·NO_TICKET·NOT_ON_CALL·NOT_ASSIGNED].code/value` | `ux/simulate/DecisionProgress.tsx:69→153` (ux/pages/simulate/person/LivePage.tsx:255) | 있음 | 업무 사실 전부를 칩으로 보임 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:397` (pages/main/consoleData.ts:150-155) | 승인 목적 `businessFacts[APPROVAL_COVERS].value` | — | 없음 | ux.biz.APPROVAL_COVERS 문구에 {{value}}가 없음 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:396` (pages/main/consoleData.ts:164-176) | `received.sensitivity` (HIGH·CRITICAL) | `ux/pages/engine/EnginePage.tsx:214→287` (/engine?tab=flow&run=…) | 다른 위치 | 새 화면은 anatomy.context.resource.sensitivity를 그림 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:410,416` | `analysis.decision.riskScore` | `ux/simulate/DecisionProgress.tsx:106-108→153` | 있음 | 새 화면은 stages[LAYER*_COMPLETE].riskScore를 그림 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:421-422` | `analysis.decision.modelCalls` | `ux/pages/engine/EnginePage.tsx:230-232→287` | 다른 위치 | 새 화면은 calls.length를 그림 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:423-424` | `decision.promptTokens`, `completionTokens` | `ux/simulate/DecisionProgress.tsx:101-104→153` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:427` | `decisionWait.medianMs` | `ux/simulate/DecisionProgress.tsx:170-173` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:433` (:556-570) | `benchmark.cases[key].runs` (같은 상황 측정 n회) | `ux/pages/validation/ScenariosTab.tsx:239` (/validation?tab=scenarios&case=S13) | 다른 위치 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:433` (:561-569) | `benchmark.cases[key].engineActions` (판단 n건 모두 차단 등) | — | 없음 | ux에는 전체 stats.engineActions만 있음 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:442` | 직원 이름 `labOptions.employees[].key/displayName` (요청 수신 줄) | `ux/pages/simulate/person/ReviewPage.tsx:112` (/…/review 계정) | 다른 위치 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:249→447` | `analysis.stages[CONTEXT_COLLECTED].atMs` | `ux/simulate/DecisionProgress.tsx:68→163` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleData.ts:218-220`→`pages/main/ConsolePage.tsx:448` | `anatomy.figures.baselineBefore` (학습 요청 n건) | `ux/simulate/DecisionProgress.tsx:78-79→153` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleData.ts:218`→`pages/main/ConsolePage.tsx:448` | `figures.workProfileObservations`, `workProfileWindow` (최근 기간 n건과 비교) | `ux/pages/engine/EnginePage.tsx:192-196→287`; `ux/pages/runs/detailTabs.tsx:635` | 다른 위치 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleData.ts:225-233`→`pages/main/ConsolePage.tsx:448` | `anatomy.interpretation.calls[0].model`, `promptLines.total` | `ux/simulate/DecisionProgress.tsx:99,90→153` | 있음 | 새 화면은 줄 수를 system·user로 나눠 보임(합계는 ux/pages/runs/detailTabs.tsx:427) |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:249→447` | `stages[LAYER1_START·LAYER*_COMPLETE].atMs` (+n.nn초) | — | 없음 | 새 model 행은 stage.elapsedMs를 그림(ux/simulate/DecisionProgress.tsx:95) |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleData.ts:239-257`→`pages/main/ConsolePage.tsx:448` | 2차 분석: `stages[LAYER2_START]`, 1차 `LAYER1_COMPLETE.action/riskScore/confidence` | — | 없음 | ux/simulate/DecisionProgress.tsx:58은 마지막 패스 하나만 그림 |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleData.ts:241-256`→`pages/main/ConsolePage.tsx:448` | 마지막 패스 `stages[LAYER*_COMPLETE].action/riskScore/confidence` | `ux/simulate/DecisionProgress.tsx:106-110→153`; 판정은 ux/simulate/ControlLanes.tsx:56 | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleData.ts:258-265`→`pages/main/ConsolePage.tsx:447-448` | `decision.applied`, `layers.D.httpStatus/deliveredItems`, `stages[DECISION_APPLIED].atMs` | `ux/simulate/DecisionProgress.tsx:119-126→153,163`; 건수 ux/simulate/ControlLanes.tsx:64 | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleData.ts:267-268`→`pages/main/ConsolePage.tsx:448` | `stages[ANALYSIS_ERROR]` | `ux/simulate/DecisionProgress.tsx:96-97→153` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/consoleData.ts:302-307`→`pages/main/ConsolePage.tsx:236,448` | 호출별 `anatomy.interpretation.calls[].callNo/elapsedMs/promptTokens/completionTokens` | — | 없음 | 호출 번호만 ux/pages/runs/detailTabs.tsx:474에 있음 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:461-464` | `liveRun.challenge.stage` (추가 인증 4단계) | `ux/simulate/Recovery.tsx:65-69` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `components/ChallengePanel.tsx:56,38,70` | `challenge.code`, `secondsLeft`, `attempts` | `ux/simulate/Recovery.tsx:24(:90),74,92` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:466-472` | `challenge.reissueDeliveredItems`, `reissueStatus` | `ux/simulate/Recovery.tsx:133-137` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `components/RecoveryFlow.tsx:24-27,33,39-42→55,57` | `challenge.codeRequestedMs/verifiedMs/reissueSentMs/reissueDoneMs/reissueOutcome` | — | 없음 |  |
| 2-2 · 4-2 · 5-2 | `components/LiveChallenge.tsx:31,50-58`→`components/StateScreen.tsx:114` | `challenge.cause` | `ux/simulate/Recovery.tsx:159-161` | 있음 | 재전송 실패의 HTTP는 cause 원문으로만 보임 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:484-489` | `teasers[CHALLENGE_OUTCOMES].values.resumed` | `ux/simulate/Recovery.tsx:139-141` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:505-510` | `release.reissueDeliveredItems`, `reissueStatus` | `ux/simulate/Recovery.tsx:327-331` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:516`→`components/StateScreen.tsx:114` | `release.cause` | `ux/simulate/Recovery.tsx:340` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `components/show/ReleasePanel.tsx:47,55,61,66,70` | `release.approverName`, `release.block.username/reasoning/mfaVerified/unblockReason` | `ux/simulate/Recovery.tsx:292,300,304,307,309` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `components/show/ReleasePanel.tsx:111,121` | `release.code`, `release.attempts` | `ux/simulate/Recovery.tsx:241(→24),243` | 있음 |  |
| 2-2 · 4-2 · 5-2 | `components/show/ReleasePanel.tsx:96` | `release.secondsLeft` | — | 없음 | ReleaseCard에 남은 시간 표시가 없음 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:521,547-552`→`components/show/ReleasePanel.tsx:135` | 해제 사유 기본값 `labCase.requests[0].project`, `facts[APPROVAL].approver/maxItems` | `ux/pages/simulate/person/LivePage.tsx:282,331-335`→`ux/simulate/Recovery.tsx:273` | 있음 | 지금 S13·S13T·S16에는 APPROVAL이 없어 일반 문장만 나옴 |
| 2-2 · 4-2 · 5-2 | `pages/main/ConsolePage.tsx:549` | 해제 사유의 승인 목적 `facts[APPROVAL].purpose` | — | 없음 | reasonApproval 문구에 목적이 없음 |

### 2-3

- 옛 제목: Contexa는 추가 인증을 요구했고, 자료는 한 건도 나가지 않았습니다
- 옛 화면: `pages/main/ResultPage.tsx` (키 `main.2-3.title.CHALLENGE`)
- 새 위치: 4단계 = /simulate/person/S13/result · `ux/pages/simulate/person/ResultPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 2-3 | `pages/main/ResultPage.tsx:53-60` | `anatomy.interpretation.recorded.finalAction` (제목) | `ux/pages/simulate/person/ResultPage.tsx:170,190` | 있음 | 새 결론은 score.verdicts·business 기준 |
| 2-3 | `pages/main/ResultPage.tsx:54,59` | `liveRun.steps[1].layers.D.deliveredItems` (제목의 n건) | `ux/pages/simulate/person/ResultPage.tsx:170,278` | 있음 | 새 화면은 score.business.D.exposedItems를 그림 |
| 2-3 | `pages/main/ResultPage.tsx:66` | `received.departureCount` (소개 "n가지가 달랐습니다") | `ux/simulate/CompareView.tsx:88-89` (?tab=compare); `ux/simulate/DecisionProgress.tsx:83` (/S13/live) | 다른 위치 |  |
| 2-3 | `pages/main/ResultPage.tsx:68,94-95` | `engineActions.ESCALATE.ttlSeconds` (보류 n분) | `ux/pages/engine/EnginePage.tsx:469-471` (/engine?tab=flow) | 다른 위치 | 결론이 CHALLENGE일 때는 쓰이지 않음 |
| 2-3 | `pages/main/ProofPanel.tsx:80,94` | `responses[c].deliveredItems` (통제별 막대) | `ux/pages/simulate/person/ResultPage.tsx:278` | 있음 | 새 화면은 score.business[c].exposedItems를 그림 |
| 2-3 | `pages/main/ProofPanel.tsx:97` | `responses[c].httpStatus` | `ux/pages/runs/detailTabs.tsx:214` (/runs/:runId?tab=controls) | 다른 위치 |  |
| 2-3 | `pages/main/ProofPanel.tsx:116` | `responses[c].method/path` | `ux/pages/runs/RunDetailPage.tsx:136`; `ux/pages/simulate/person/ReviewPage.tsx:104-105` | 다른 위치 | 엔진이 받은 요청 한 줄만 있고 통제별 줄은 없음 |
| 2-3 | `pages/main/ProofPanel.tsx:118` | `responses[c].sentAt` | — | 없음 |  |
| 2-3 | `pages/main/ProofPanel.tsx:121` | `responses[c].excerpt` (응답 원문 앞부분) | — | 없음 | ResponseTab은 모델 응답이라 다른 것 |
| 2-3 | `pages/main/ProofPanel.tsx:155-159`→`pages/main/CheckCounts.tsx:20-21` | `quality.inspection.checks[].matched/mismatched/unverifiable` (3개) | `ux/pages/runs/detailTabs.tsx:588-592` (?tab=integrity) | 다른 위치 |  |
| 2-3 | `pages/main/ProofPanel.tsx:167,170` | `quality.seal.packageHash`, `seal.capturedAt` | `ux/pages/runs/detailTabs.tsx:532,535`; `ux/pages/engine/EnginePage.tsx:378,382` | 다른 위치 |  |
| 2-3 | `pages/main/ProofPanel.tsx:184` | 내려받은 기록 sha256 (`downloadRunRecord`) | `ux/pages/runs/detailTabs.tsx:549` | 다른 위치 |  |
| 2-3 | `pages/main/ProofPanel.tsx:203,208,213` | `anatomy.learning.template/atRunEnd.baselineUpdateCount` | `ux/pages/runs/detailTabs.tsx:624` (?tab=learning) | 다른 위치 | 새 화면은 figures.baselineBefore/After를 그림. ux/simulate/CompareView.tsx:218에도 있음 |
| 2-3 | `pages/main/ProofPanel.tsx:218,225` | 학습 추가 수 + `learning.newBehaviourDocuments[0].action/requestPath/timestamp` | `ux/pages/runs/detailTabs.tsx:626,642-643` | 다른 위치 |  |
| 2-3 | `pages/main/ResultPage.tsx:75`→`components/main/SourceBadge.tsx:36` | `runId` | `ux/pages/simulate/person/ResultPage.tsx:216` | 있음 |  |

### 2-4

- 옛 제목: AI가 판단에 사용한 근거
- 옛 화면: `pages/main/AttackReasonPage.tsx` (키 `main.2-4.title`)
- 새 위치: 판정 상세 › 판정 근거 = /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 2-4 | pages/main/AttackReasonPage.tsx:102, :108-110, :114 | 평소 밖 첫 차원(기기/접속망): `received.usualVsNow[dim].{dimension,now,inUsual='false'}` + `received.usual[dim].values` | ux/pages/runs/detailTabs.tsx:302, :304, :305, :307-308 | 있음 | 평소 대비 표에서 모든 차원을 평소값·이번값·밖 표시로 보여 줌 |
| 2-4 | pages/main/AttackReasonPage.tsx:128-131, :138-139 | 시각 카드: `received.usualVsNow[accessHour].now`, `received.usual.accessHour.values` | ux/pages/runs/detailTabs.tsx:304-305 | 있음 | accessHour 행 |
| 2-4 | pages/main/AttackReasonPage.tsx:127 → components/journey/HourBars.tsx:30-36 | 시간대별 학습 건수: `baseline.learned.hours` | ux/pages/engine/EnginePage.tsx:526-533 (/engine?tab=baseline) | 다른 위치 | 판정 근거 탭에는 막대그림이 없음 |
| 2-4 | pages/main/AttackReasonPage.tsx:137 | 학습한 요청 수: `baseline.learned.requests` | ux/pages/engine/EnginePage.tsx:516 (/engine?tab=baseline) | 다른 위치 |  |
| 2-4 | pages/main/AttackReasonPage.tsx:154, :158, :167-168 | 평소 최대 반출 건수와 이번 건수: `received.sizeRatio.usualLargest`(없으면 `usual.size.values[0]`), `received.sizeRatio.items`(없으면 `businessFacts[ITEMS].value`) | ux/pages/runs/detailTabs.tsx:304-305 | 있음 | size 행이 `usual.size.values`와 `usualVsNow.size.now`로 보여 줌. 같은 값을 다른 필드에서 읽음(포털 BeforeSend.sizeRatio가 usual.size.values[0]을 씀). 봉인된 SIZE 차원이 없으면 행도 없음 |
| 2-4 | pages/main/AttackReasonPage.tsx:164 | 평소 최대 대비 배수: `received.sizeRatio.times` | — | 없음 | 아래 "없음" 참조 |
| 2-4 | pages/main/AttackReasonPage.tsx:185, :191 | 승인 기록 규칙(C2)의 응답(통과/차단): `stepResult.layers[C2].evidence.deliveredItems`(>0이면 통과), useTryRun을 거쳐 읽음 | ux/pages/runs/detailTabs.tsx:208, :215 (/runs/:runId?tab=controls) | 다른 위치 | 같은 판정 상세의 통제별 응답 탭 |
| 2-4 | pages/main/AttackReasonPage.tsx:197-201 | 회사 기록: `received.businessFacts[ASSIGNED/NOT_ASSIGNED, APPROVAL_COVERS/NO_APPROVAL, TICKET_COVERS/NO_TICKET, ON_CALL/NOT_ON_CALL, ACCESS_DAYS_LAST_30].{code,value}` | ux/pages/simulate/person/LivePage.tsx:255 → ux/simulate/DecisionProgress.tsx:69, :153 (/simulate/person/S13/live) | 다른 위치 | 기록된 실행이면 그 실행의 received를 씀. /engine?tab=flow(ux/pages/engine/EnginePage.tsx:203)는 앞 3개만 보여 줌 |
| 2-4 | pages/main/AttackReasonPage.tsx:207 → components/main/SourceBadge.tsx:36 | run id: `runId` | ux/pages/runs/RunDetailPage.tsx:111 | 있음 | 페이지 제목 |

### 4-1

- 옛 제목: 같은 요청을 정상 사용자로 보냅니다
- 옛 화면: `pages/main/RequestPage.tsx:88` role owner (키 `main.4-1.title`)
- 새 위치: 2단계(S13T) = /simulate/person/S13T/review · `ux/pages/simulate/person/ReviewPage.tsx`
- 참고: 같은 옛 화면의 사실을 2-1 행 표에 함께 적었습니다(번호 칸에 이 행 번호가 함께 있음).

### 4-2

- 옛 제목: 동일 요청에 대한 판단 결과
- 옛 화면: `pages/main/ConsolePage.tsx:171` role owner (키 `main.4-2.title`)
- 새 위치: 3단계(S13T) = /simulate/person/S13T/live · `ux/pages/simulate/person/LivePage.tsx`
- 참고: 같은 옛 화면의 사실을 2-2 행 표에 함께 적었습니다(번호 칸에 이 행 번호가 함께 있음).

### 4-3

- 옛 제목: 같은 요청, 다른 것은 접속 환경뿐입니다
- 옛 화면: `pages/main/DiffPage.tsx` (키 `main.4-3.title`, `main.4-3.title.one`)
- 새 위치: 4단계 › 같은 요청 비교 탭 = /simulate/person/S13T/result?tab=compare · `ux/simulate/CompareView.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 4-3 | `pages/main/DiffPage.tsx:35→161-162,167-168` | 계정 `labOptions.employees[conditions.employee]` | `ux/simulate/CompareView.tsx:96→166,172` | 있음 |  |
| 4-3 | `pages/main/DiffPage.tsx:37-43→161-168` | 시각 `conditions.timeSlot` + `timeSlots[].representativeTime` | `ux/simulate/CompareView.tsx:97-100→166,172` | 있음 | 새 화면은 received.companyTime을 그림 |
| 4-3 | `pages/main/DiffPage.tsx:46-50→167-168` | 접속 환경 `conditions.place/device` | `ux/simulate/CompareView.tsx:102,111-112→166,172` | 있음 | 새 화면은 엔진 입력(네트워크 칩·CIDR, 단말)을 그림 |
| 4-3 | `pages/main/DiffPage.tsx:53-57` | 요청 `requests[0].project/items` | `ux/simulate/CompareView.tsx:80-85,108→166,172` | 있음 | 새 화면은 resource.requestPath/requestedItems를 그림 |
| 4-3 | `pages/main/DiffPage.tsx:60-66` | 승인 기록 `facts[APPROVAL].purpose/maxItems` (없으면 "없음") | `ux/simulate/DecisionProgress.tsx:69→153` (NO_APPROVAL 칩, /…/live) | 다른 위치 | 비교 탭에 승인 행이 없음. 목적·최대 건수는 ux에 없음(지금 S13·S13T는 승인 없음) |
| 4-3 | `pages/main/DiffPage.tsx:132-138,172-181` | `inputChanges[].key/before/now` + 바뀐 줄 수 | — | 없음 | ux/pages/simulate/policy/ComposeTab.tsx:539-541은 다른 실행 쌍의 비교 |
| 4-3 | `pages/main/DiffPage.tsx:199-200,206,210` | 두 실행의 `journey.runs[].business[B·C1·C2]` | `ux/pages/simulate/person/ResultPage.tsx:279` (?tab=S13 / ?tab=S13T) | 다른 위치 | 비교 탭은 ux/simulate/CompareView.tsx:281-284에서 A 건수만 보이고, 평가는 4개가 같을 때만 묶어 보임 |
| 4-3 | `pages/main/DiffPage.tsx:206,210` | 두 실행의 `engineAction`, `exposedItems` | `ux/simulate/CompareView.tsx:269-270` | 있음 |  |
| 4-3 | `pages/main/DiffPage.tsx:219-220`→`pages/main/ProofPanel.tsx:244-252` | 두 실행의 학습 `baselineUpdateCount` 전·후·추가 | `ux/simulate/CompareView.tsx:217-227` | 있음 | 새 화면은 figures.baselineBefore/After/Added를 그림 |
| 4-3 | `pages/main/DiffPage.tsx:139-140,223` | 결론(두 실행의 `business.D`) | `ux/simulate/CompareView.tsx:120-125,188-197` | 있음 | 새 화면은 기존 4개 MISSED/PASSED 조건이 더 붙음 |
| 4-3 | `pages/main/DiffPage.tsx:93-94,225` | `benchmark.suites[RULE_BLIND].cases` (각주) | `ux/pages/validation/ScenariosTab.tsx:81,108` (/validation?tab=scenarios) | 다른 위치 |  |
| 4-3 | `pages/main/DiffPage.tsx:228-229`→`components/main/SourceBadge.tsx:36` | 두 `runId` | `ux/simulate/CompareView.tsx:266` | 있음 |  |
| 4-3 | `pages/main/DiffPage.tsx:123-128` | 다른 행 이름(제목 title.one) | `ux/simulate/CompareView.tsx:117-119,131-133` | 있음 |  |

### 4-4

- 옛 제목: 정상 사용자는 추가 인증을 거쳐 업무를 끝까지 이어 갔습니다
- 옛 화면: `pages/main/CheckPage.tsx` (키 `main.4-4.title.afterCheck`)
- 새 위치: 4단계(S13T) = /simulate/person/S13T/result · `ux/pages/simulate/person/ResultPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 4-4 | `pages/main/CheckPage.tsx:157` | 직원 이름 | `ux/pages/simulate/person/ReviewPage.tsx:112` (S13T) | 다른 위치 | S14 직원은 ux에 안 보임 |
| 4-4 | `pages/main/CheckPage.tsx:127,157` | 출장 도시 `labCase.facts[TRAVEL].city` | — | 없음 |  |
| 4-4 | `pages/main/CheckPage.tsx:133,157` | 회사 시각 `beforeSend.comparison.companyTime` (없으면 대표 시각) | `ux/pages/simulate/person/ReviewPage.tsx:112`; `ux/simulate/CompareView.tsx:99-100` | 다른 위치 | S13T 값 |
| 4-4 | `pages/main/CheckPage.tsx:176-180` | `facts[TRAVEL].network`, `conditions.device` | `ux/simulate/CompareView.tsx:102,111`; `ux/pages/runs/detailTabs.tsx:305` | 다른 위치 |  |
| 4-4 | `pages/main/CheckPage.tsx:166-167`→`components/StateScreen.tsx:101,105` | `queuePosition`, `queueWaitSeconds` | `ux/pages/simulate/person/LivePage.tsx:226-229` (/S13T/live) | 다른 위치 | ComposeTab(S14 실행)에는 대기 표시가 없음 |
| 4-4 | `pages/main/CheckPage.tsx:158,230` | `runId` (진행 중·저장 후) | `ux/pages/simulate/person/ResultPage.tsx:216` | 있음 |  |
| 4-4 | `pages/main/RequestSteps.tsx:67` (:188-208) | 요청 이름 `requests[].operation/project/items/document` | `ux/pages/simulate/person/ReviewPage.tsx:104-105`; `ux/pages/simulate/person/ResultPage.tsx:170`(건수) | 다른 위치 | S14의 3개 요청 이름은 ux에 없음(ComposeTab은 "요청 n"만 보임) |
| 4-4 | `pages/main/RequestSteps.tsx:76→126` | 요청별 `layers[A·B·C1·C2]` | `ux/pages/simulate/person/ResultPage.tsx:278-279` | 있음 | S13T는 요청 1개. S14 단계별은 ux/pages/simulate/policy/ComposeTab.tsx:414 |
| 4-4 | `pages/main/RequestSteps.tsx:83-96` | 요청별 `layers.D.outcome/deliveredItems/httpStatus` | `ux/pages/simulate/person/ResultPage.tsx:190,278` | 있음 | S14: ux/pages/simulate/policy/ComposeTab.tsx:414, ux/pages/runs/detailTabs.tsx:206,214-215 |
| 4-4 | `pages/main/RequestSteps.tsx:97-104` | 진행 중 재전송 `challenge.reissueDeliveredItems/reissueStatus` | `ux/simulate/Recovery.tsx:133-137` (/S13T/live; ux/pages/simulate/policy/ComposeTab.tsx:424) | 다른 위치 |  |
| 4-4 | `pages/main/RequestSteps.tsx:107-110` | `decision.applied` (다음 요청부터) | `ux/pages/simulate/person/ResultPage.tsx:210-211` | 있음 | S14 단계별은 ux/pages/runs/detailTabs.tsx:98(?step=n) |
| 4-4 | `components/ChallengePanel.tsx:56,38,70` | `challenge.code/secondsLeft/attempts` | `ux/simulate/Recovery.tsx:24,74,92` (/S13T/live; ux/pages/simulate/policy/ComposeTab.tsx:424) | 다른 위치 |  |
| 4-4 | `pages/main/CheckPage.tsx:134-141` | `journey.runs[].business.D` (PASSED_AFTER_CHECK 제목) | `ux/pages/simulate/person/ResultPage.tsx:170` | 있음 | S13T 값. ux/simulate/person.ts:232-233은 PASSED_AFTER_CHECK를 '정상'으로 묶어, 정책·이력 화면에서는 "추가 인증 후"를 구분할 수 없음 |
| 4-4 | `pages/main/CheckPage.tsx:144-146→216` | `business.C1` HALTED (결론) | `ux/pages/simulate/person/ResultPage.tsx:279,177` | 있음 |  |
| 4-4 | `pages/main/RequestSteps.tsx:157,172-174` | 저장된 추가 인증 시각 `recovery.challenge.challenged_at/code_requested_at/verified_at/reissue_sent_at` | — | 없음 |  |
| 4-4 | `pages/main/RequestSteps.tsx:162-168` | 저장된 `recovery.challenge.reissue_delivered/reissue_status` | — | 없음 |  |
| 4-4 | `pages/main/CheckPage.tsx:223`→`pages/main/ProofPanel.tsx:244-252` | 학습 `baselineUpdateCount` 전·후·추가 | `ux/simulate/CompareView.tsx:217-227` (?tab=compare); `ux/pages/runs/detailTabs.tsx:624` | 다른 위치 |  |
| 4-4 | `pages/main/CheckPage.tsx:72-74,227` | `benchmark.suites[RULE_BLIND].cases` (S14 각주) | `ux/pages/validation/ScenariosTab.tsx:81,108` | 다른 위치 |  |
| 4-4 | `pages/main/CheckPage.tsx:231-235` | `teasers[CHALLENGE_OUTCOMES].values.resumed` | `ux/simulate/Recovery.tsx:139-141` (/S13T/live, 추가 인증이 열렸을 때만) | 다른 위치 |  |

### 5-1

- 옛 제목: 본인 계정으로 담당 프로젝트 문서를 내려받습니다
- 옛 화면: `pages/main/RequestPage.tsx:88` role insider (키 `main.5-1.title`)
- 새 위치: 2단계(S16) = /simulate/person/S16/review · `ux/pages/simulate/person/ReviewPage.tsx`
- 참고: 같은 옛 화면의 사실을 2-1 행 표에 함께 적었습니다(번호 칸에 이 행 번호가 함께 있음).

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 5-1 | `pages/main/RequestPage.tsx:241→114` | 내부자 문서 제목 `labCase.facts[kind=DOCUMENT].document.title[lang]` | `ux/pages/simulate/person/PickPage.tsx:276` (+`ux/pages/simulate/person/LivePage.tsx:382`) | 다른 위치 | 검토 화면에는 "문서 n건"(ReviewPage:112)만 보임. 순번을 세는 방식이 다름(새: facts[fact-1], 옛: DOCUMENT만 센 순번). 고정 응답에서는 결과가 같음 |

### 5-2

- 옛 제목: 권한 안의 요청에 대한 다섯 보안의 판단
- 옛 화면: `pages/main/ConsolePage.tsx:171` role insider (키 `main.5-2.title`)
- 새 위치: 3단계(S16) = /simulate/person/S16/live · `ux/pages/simulate/person/LivePage.tsx`
- 참고: 같은 옛 화면의 사실을 2-2 행 표에 함께 적었습니다(번호 칸에 이 행 번호가 함께 있음).

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 5-2 | `pages/main/ConsolePage.tsx:82-85,106-107,363,438` | S16 요청 1 기준의 사실·위험도·토큰·이벤트 (`useTryAnalysis(…,1)`, `useReceived/useAnatomy(runId,1)`) | `ux/pages/runs/RunDetailPage.tsx:165-175` (/runs/:runId?step=1) | 다른 위치 | 새 Live 패널은 마지막으로 판정된 요청(panelStep, ux/pages/simulate/person/LivePage.tsx:101-109)을 따라감 |
| 5-2 | `pages/main/RequestSteps.tsx:67` (:211-216) | 문서 제목 `labOptions.cases[S16].facts[DOCUMENT].document.title` | `ux/pages/simulate/person/LivePage.tsx:381-382` | 있음 | 새 화면은 facts[fact-1](전체 순번)으로 찾음. 옛 화면은 DOCUMENT만 센 순번. 지금 S16 facts는 모두 DOCUMENT라 결과가 같음 |
| 5-2 | `pages/main/RequestSteps.tsx:76→126` | 요청별 `steps[n].layers[A·B·C1·C2]` | `ux/simulate/ControlLanes.tsx:56` (ux/pages/simulate/person/LivePage.tsx:363-373) | 있음 |  |
| 5-2 | `pages/main/RequestSteps.tsx:83-96` | 요청별 `steps[n].layers.D.outcome/deliveredItems/httpStatus` | `ux/simulate/ControlLanes.tsx:56,64` | 있음 |  |
| 5-2 | `pages/main/RequestSteps.tsx:97-104` (pages/main/consoleData.ts:48-49) | 저장된 재전송 `anatomy(n).recovery.challenge.reissue_delivered/reissue_status` | — | 없음 | 진행 중 값만 ux/simulate/Recovery.tsx:133-137에 있음 |
| 5-2 | `pages/main/RequestSteps.tsx:107-110` | 요청별 `analysis(n).decision.applied`=NEXT_REQUEST + 판정 | `ux/simulate/ControlLanes.tsx:56`; `ux/simulate/DecisionProgress.tsx:122→153`; `ux/pages/simulate/person/LivePage.tsx:446` | 있음 | 요청별 문장은 없고 판정과 적용 방식으로 보임 |

### 5-3

- 옛 제목: 기록은 모두 정상이며, AI는 가능성을 비교했습니다
- 옛 화면: `pages/main/InsidePage.tsx` (키 `main.5-3.title`)
- 새 위치: 판정 상세 › 판정 근거 = /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 5-3 | pages/main/InsidePage.tsx:152-153 | 판정된 요청마다 번호와 판정: `score.verdicts[].score.{stepNo,finalAction}` | ux/pages/runs/RunDetailPage.tsx:173 (요청 이동), :112 (고른 요청의 판정) | 있음 | 한 번에 한 요청만 보임(옛것은 한꺼번에 칩으로) |
| 5-3 | pages/main/InsidePage.tsx:120-123; pages/main/VerdictCard.tsx:62 | 고른 요청 번호와 판정: `stepNo`, `anatomy.interpretation.recorded.finalAction ?? proposedAction` | ux/pages/runs/RunDetailPage.tsx:112, :176 | 있음 |  |
| 5-3 | pages/main/InsidePage.tsx:114-115, :120 | 판정이 엮은 서로 다른 인용 사실 수 n: `quality.reasonCodes[].fact`의 서로 다른 개수 | — | 없음 | 개별 인용 사실은 ux/pages/runs/detailTabs.tsx:269-272에 보임. 수 n 자체는 그리지 않음(256은 코드 수) |
| 5-3 | pages/main/InsidePage.tsx:122 | 내부자를 막은 요청 번호(처음 제한한 요청): `score.verdicts` 중 BLOCK/ESCALATE/CHALLENGE인 첫 `stepNo` | ux/pages/simulate/person/ResultPage.tsx:185 (/simulate/person/S16/result) | 다른 위치 | 판정 상세는 step 없이 열면 그 요청을 고름(ux/pages/runs/RunDetailPage.tsx:52, :176). "막은 요청"이라고 이름 붙이지는 않음 |
| 5-3 | pages/main/VerdictCard.tsx:68-70 | AI 제안과 다르게 바뀐 판정: `recorded.proposedAction` ≠ `finalAction` | ux/pages/runs/detailTabs.tsx:92-93 (/runs/:runId?tab=summary) | 다른 위치 |  |
| 5-3 | pages/main/VerdictCard.tsx:129 | 위험 점수·신뢰도: `recorded.riskScore`, `recorded.confidence` | ux/pages/runs/RunDetailPage.tsx:146-147 | 있음 | 위쪽 요약 막대(모든 탭에 보임) |
| 5-3 | pages/main/VerdictCard.tsx:139-142 | 값 출처(모델이 내지 않음): `recorded.fieldProvenance.{riskScore,confidence}` | — | 없음 | 아래 "없음" 참조 |
| 5-3 | pages/main/VerdictCard.tsx:95 | AI 판단 요약: `recorded.reasoning` | ux/pages/runs/detailTabs.tsx:334-337 | 있음 |  |
| 5-3 | pages/main/InsidePage.tsx:161 | 다음 요청부터 적용되기 전에 이 실행에서 나간 문서 수: `score.business.D.exposedItems` (조건: `recorded.applied=NEXT_REQUEST`, D outcome=DELIVERED) | ux/pages/simulate/person/ResultPage.tsx:278 (/simulate/person/S16/result); ux/pages/runs/RunsPage.tsx:472 (/runs?run=) | 다른 위치 | 적용 시점은 ux/pages/runs/RunDetailPage.tsx:155에 따로 보임 |
| 5-3 | pages/main/Hypotheses.tsx:67-82 | 가설 이름·평가: `quality.hypotheses[].{id,name,assessment}` | ux/pages/runs/detailTabs.tsx:348-353 | 있음 | H5 이름 포함 |
| 5-3 | pages/main/Hypotheses.tsx:48-51, :55 | 가설의 찬성/반대 사실(이름은 `facts.blocks[].facts[].label`), 양쪽 모두에 든 사실 | ux/pages/runs/detailTabs.tsx:358, :360 | 있음 | 양쪽에 든 사실은 두 목록에 모두 나타남. 따로 말해 주는 줄은 없음 |
| 5-3 | pages/main/InsidePage.tsx:180-185 | 기존 보안 4개(A/B/C1/C2)의 실행 결과: `journey.runs[].business[c]` 또는 `benchmark.cases[S16].runResults[runId][c]`(넷 다 MISSED인지는 intro.proof 조건) | ux/pages/simulate/person/ResultPage.tsx:279, :173-174 (/simulate/person/S16/result) | 다른 위치 | 같은 뜻인 `score.business[c].result`로 보여 줌 |
| 5-3 | pages/main/VerdictCard.tsx:215-221, :238-242, :194 | 근거 코드와 인용한 사실 줄: `quality.reasonCodes[].{code,fact}` + `facts.blocks[].facts[].{factId,label,value}`, 끝의 판정 | ux/pages/runs/detailTabs.tsx:269-278 | 있음 |  |
| 5-3 | pages/main/InsidePage.tsx:207-218 (문구 :52) | 반복 측정표 S16·S16T × C1/C2/D 결과별 횟수: `benchmark.cases[key].results[c]`, `.runs` | ux/pages/validation/ScenariosTab.tsx:118-126 (/validation?tab=scenarios) | 다른 위치 | 결과별 횟수 대신 실행마다 점(`runResults`) |
| 5-3 | pages/main/InsidePage.tsx:224-228 | 측정 횟수와 측정일: `benchmark.cases[S16].runs`, `benchmark.scope.protocols[-1].finishedAt` | ux/pages/validation/ScenariosTab.tsx:239 (?case=S16); ux/pages/compare/ComparePage.tsx:418 (/compare?tab=runs) | 다른 위치 |  |
| 5-3 | pages/main/InsidePage.tsx:231 | 규칙이 미리 모르는 사례인지: `benchmark.suites[RULE_BLIND].cases`에 S16이 있는지 | ux/pages/validation/ScenariosTab.tsx:41-45, :81 | 다른 위치 | RULE_BLIND 묶음 머리 아래에 S16 행 |
| 5-3 | pages/main/InsidePage.tsx:234-239 → components/main/SourceBadge.tsx:36 | run id와 요청 번호 | ux/pages/runs/RunDetailPage.tsx:111, :173 | 있음 |  |
| 5-3 | pages/main/InsidePage.tsx:235-236 | 내 실행인지 측정 실행인지: `useEvidenceRun.own`(journey) | ux/pages/runs/RunsPage.tsx:120 (/runs) | 다른 위치 | 판정 상세에는 출처 표시가 없음 |

### H-6 · A-6 · D-1 · M-more

- 옛 제목: 다음 단계를 선택하세요 등
- 옛 화면: `pages/main/NextChoosePage.tsx:81` (키 `main.H-6.title`, `main.A-6.title`), `pages/main/DeeperPage.tsx` (키 `main.D-1.title`), `pages/more/MorePage.tsx` (키 `more.title`)
- 새 위치: 4단계 "다음 확인" 3개 + 왼쪽 메뉴 = 4단계 다음 확인 · `ux/pages/simulate/person/ResultPage.tsx`, `ux/pages/simulate/agent/ResultPage.tsx`, 왼쪽 메뉴 `ux/shell/SideNav.tsx`
- 참고: D-1(DeeperPage.tsx)과 M-more(MorePage.tsx)는 고정 문구 이동 카드뿐이라 사실이 없습니다. 아래 사실은 H-6 · A-6(NextChoosePage.tsx)의 요약 문장에서 나왔습니다.

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| H-6 · A-6 · D-1 · M-more | `pages/main/NextChoosePage.tsx:83` (pages/main/recap.ts:53-56) | 공격 실행의 Contexa 판정과 나간 건수가 0인지 `journey.runs[S13].engineAction, exposedItems` | `ux/pages/simulate/person/ResultPage.tsx:170`, `:190` | 있음 | 새 출처는 runScore |
| H-6 · A-6 · D-1 · M-more | `pages/main/NextChoosePage.tsx:83` (pages/main/recap.ts:64-68) | 공격 판정 + 정상 사용자 결과 `runs[S13].engineAction/exposedItems`, `runs[S13T].business.D` | `ux/simulate/CompareView.tsx:269-271` | 있음 | …/result?tab=compare(두 실행이 모두 있을 때) |
| H-6 · A-6 · D-1 · M-more | `pages/main/NextChoosePage.tsx:83` (pages/main/recap.ts:78-82) | 내부자 판정·결과, 기존 4곳 모두 MISSED, 나간 문서 n `runs[S16].engineAction, business.D/A~C2, exposedItems` | `ux/pages/simulate/person/ResultPage.tsx:170`, `:173-177`, `:190`, `:279` | 있음 |  |
| H-6 · A-6 · D-1 · M-more | `pages/main/NextChoosePage.tsx:83` (pages/main/recap.ts:90-97) | 에이전트 실행의 분류·Contexa 결과·기존 4곳 `runs[agent].classification, business.D/A~C2` | `ux/pages/simulate/agent/ResultPage.tsx:142`, `:145-147` | 있음 | 새 출처는 AgentRunView.proof |

### A-1

- 옛 제목: 에이전트에게 맡길 업무를 선택하세요
- 옛 화면: `pages/main/AgentChoosePage.tsx` (키 `main.A-1.title`)
- 새 위치: 1단계(AI 에이전트 위임 탭) = /simulate/agent · `ux/pages/simulate/agent/PickPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| A-1 | pages/main/AgentChoosePage.tsx:39-46 (→ components/main/ChoiceCards.tsx:65-70) | 열린 에이전트 사례 목록(카드 하나씩) `liveConfig.agentCases[].key` | ux/pages/simulate/agent/PickPage.tsx:51-53, :79 | 있음 | 새 화면은 키를 배지로 보임(옛 화면은 data-choice 속성뿐) |
| A-1 | pages/main/AgentChoosePage.tsx:43 (→ components/main/ChoiceCards.tsx:79) | 사례 제목 `liveConfig.agentCases[].title[lang]` (알려진 5건은 static:i18n/ko.json `choose.agent.{key}.title`) | ux/pages/simulate/agent/PickPage.tsx:95 | 있음 | 새 화면은 `agentCase.title[lang]`(/api/agent-cases/{key})을 그림. 옛 사전 제목('위임 기간이 끝난 요청' 등)은 ux에서 안 씀 |

### 6-1

- 옛 제목: 에이전트가 주간 보고서를 다시 실행합니다
- 옛 화면: `pages/main/AgentRequestPage.tsx` (키 `main.6-1.title`)
- 새 위치: 2단계 = /simulate/agent/T5/review · `ux/pages/simulate/agent/ReviewPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 6-1 | pages/main/AgentRequestPage.tsx:92 (→ components/main/MainScreen.tsx:180) | 보내는 쪽 칩 `agentCase.sender` | — | 없음 | 2단계에는 고정 배지 'AI 에이전트 위임 남용'(ux/pages/simulate/agent/ReviewPage.tsx:132-134)만 있음 |
| 6-1 | pages/main/DelegationParts.tsx:59 (pages/main/AgentRequestPage.tsx:102) | 위임자 `agentCase.protagonist` | ux/pages/simulate/agent/ReviewPage.tsx:152 (→ ux/simulate/AgentParts.tsx:41) | 있음 |  |
| 6-1 | pages/main/DelegationParts.tsx:60 | 에이전트 `agentCase.agentTitle[lang]` | ux/pages/simulate/agent/ReviewPage.tsx:153 | 있음 |  |
| 6-1 | pages/main/DelegationParts.tsx:61 | 작업 대상 자원(사슬) `delegation.resources[]` | ux/pages/simulate/agent/ReviewPage.tsx:154; ux/simulate/AgentParts.tsx:108-112 | 있음 | 사슬에는 첫 자원만, 전부는 위임 범위 배지에 보임 |
| 6-1 | pages/main/DelegationParts.tsx:61 | 자원이 없을 때 대신 보인 `delegation.project` | — | 없음 | 새 사슬은 '—'(ux/pages/simulate/agent/ReviewPage.tsx:154) |
| 6-1 | pages/main/AgentRequestPage.tsx:115 | 위임 목표 `delegation.summary[lang]` | ux/simulate/AgentParts.tsx:100 (ux/pages/simulate/agent/ReviewPage.tsx:156) | 있음 |  |
| 6-1 | pages/main/AgentRequestPage.tsx:121 (pages/main/agentGroup.ts:36-50) | 위임 기간 `delegation.validFromMinutes`·`validUntilMinutes`·`status`(REVOKED) | ux/simulate/AgentParts.tsx:130-136 | 있음 | 시작·끝 중 하나라도 null이면 '—'(옛 '…부터'·'기간 없음' 문구 없음). 철회는 상태 배지로 보임 |
| 6-1 | pages/main/AgentRequestPage.tsx:128-146 | 방문자가 바꾼 위임 값 `delegationChoice.quantity·period·operations` (주소 값, `liveConfig.delegationEdit` 목록) | ux/simulate/AgentParts.tsx:95-96, :113, :123, :137 (ux/pages/simulate/agent/ReviewPage.tsx:156) | 있음 | 바뀐 칸에 '변경됨' 배지와 포털이 바꿔 돌려준 값이 보임. 바꾼 값을 늘어놓는 문장은 없음 |
| 6-1 | pages/main/AgentRequestPage.tsx:179 | 오늘 남은 실제 실행 수 `liveConfig.liveTicketsLeft`({{n}}) | — | 없음 | ux/pages/simulate/agent/ReviewPage.tsx:220은 다른 필드(`remainingAgentToday`·`dailyAgentRuns`, 방문자당 값) |
| 6-1 | pages/main/AgentRequestPage.tsx:167-169 | 실제 실행이 다 나간 상태 `liveConfig.liveTicketsLeft === 0` | ux/pages/simulate/agent/ReviewPage.tsx:95-96 (→ ux/ui/Button.tsx:88, :103-104) | 있음 | 버튼 툴팁(title)과 화면낭독 문구(ux-sr-only)로만 나옴. 늘 보이는 글은 아님 |
| 6-1 | pages/main/AgentRequestPage.tsx:185 | 지시 원문 `agentCase.instruction[lang]` | ux/pages/simulate/agent/ReviewPage.tsx:158 (→ ux/simulate/AgentParts.tsx:69) | 있음 |  |
| 6-1 | pages/main/AgentRequestPage.tsx:197-199 | 위임 범위 작업 `delegation.operations[]` | ux/simulate/AgentParts.tsx:103-107 | 있음 |  |
| 6-1 | pages/main/AgentRequestPage.tsx:200 | 위임 범위 자원 `delegation.resources[]` | ux/simulate/AgentParts.tsx:108-112 | 있음 |  |
| 6-1 | pages/main/AgentRequestPage.tsx:208 | 요청당 최대 건수 `delegation.maxItemsPerRequest` | ux/simulate/AgentParts.tsx:119-121 | 있음 |  |
| 6-1 | pages/main/AgentRequestPage.tsx:223-226 | 같은 사례 최근 기록 실행의 요청 주소 `agentRun(recorded.runId).steps[].path` | ux/pages/runs/RunDetailPage.tsx:134-137 (/runs/:runId?step=n) | 다른 위치 | 2단계에는 목록 없음. 기록 실행 링크(ux/pages/simulate/agent/ReviewPage.tsx:231)는 실행이 거절될 때만 보임 |
| 6-1 | pages/main/AgentRequestPage.tsx:224 | 그 요청들의 회사 시각 `agentRun.steps[].companyTime` | — | 없음 | ux/pages/runs/RunDetailPage.tsx:160은 판정 시각(UTC)이고 회사 시각이 아님 |
| 6-1 | pages/main/AgentRequestPage.tsx:234 | 사례 키 `agentCase.key` | ux/pages/simulate/agent/ReviewPage.tsx:135 | 있음 |  |

### 6-2

- 옛 제목: 에이전트 요청에 대한 다섯 보안의 판단
- 옛 화면: `pages/main/AgentConsolePage.tsx` (키 `main.6-2.title`)
- 새 위치: 3단계 = /simulate/agent/:caseKey/live · `ux/pages/simulate/agent/LivePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 6-2 | pages/main/AgentConsolePage.tsx:56 (→ components/main/MainScreen.tsx:180) | 보내는 쪽 칩 `agentCase.sender` | — | 없음 | ux/pages/simulate/agent/LivePage.tsx:74-76은 고정 배지 |
| 6-2 | pages/main/DelegationParts.tsx:59 (pages/main/AgentConsolePage.tsx:70) | 위임자 `agentCase.protagonist` | ux/pages/simulate/agent/ReviewPage.tsx:152 (2단계) | 다른 위치 | 3단계에는 위임자 확인 패널이 뜰 때만 보임(ux/simulate/DelegatorPanel.tsx:48) |
| 6-2 | pages/main/DelegationParts.tsx:60 | 에이전트 `agentCase.agentTitle[lang]` | ux/pages/simulate/agent/LivePage.tsx:195 | 있음 |  |
| 6-2 | pages/main/DelegationParts.tsx:61 | 작업 대상 자원 `delegation.resources[]` | ux/pages/simulate/agent/ReviewPage.tsx:154; ux/simulate/AgentParts.tsx:108-112 (2단계) | 다른 위치 | 3단계에는 없음 |
| 6-2 | pages/main/AgentConsolePage.tsx:59 (→ components/AppHeader.tsx:81) | 진행 중 live 실행 id `liveRun.liveRunId` (상단 LIVE 표시) | — | 없음 | 3단계에는 저장 run id(ux/pages/simulate/agent/LivePage.tsx:78)와 상태 알약만 있음. ux/shell/TopBar.tsx:28은 실행 가능 여부만 보임 |
| 6-2 | pages/main/AgentConsolePage.tsx:73 (→ components/main/SourceBadge.tsx:36) | 실행 run id `useAgentTry.runId` | ux/pages/simulate/agent/LivePage.tsx:78 | 있음 |  |
| 6-2 | pages/main/MeasureNote.tsx:37 (pages/main/AgentConsolePage.tsx:76) | 누구의 실행인지(방문자 본인) `useAgentTry.own` | ux/pages/runs/RunsPage.tsx:120 (/runs) | 다른 위치 | 3단계에는 출처 문구 없음. 판정 기록 목록에 '내 실행'으로 보임 |
| 6-2 | pages/main/MeasureNote.tsx:33 | 상한으로 멈춘 이유 `agentRun.stopReason`(CAP_*) | ux/pages/simulate/agent/LivePage.tsx:205 | 있음 |  |
| 6-2 | pages/main/MeasureNote.tsx:40-43 | 운영자 기록 수와 최근 기록과 같은 결과 수 `agentCase.recorded.runs`·`sameAsLatest` | — | 없음 |  |
| 6-2 | pages/main/AgentTimeline.tsx:54 | 요청 번호 `agentRun.steps[].stepNo` / `liveRun.steps[].stepNo` | ux/simulate/AgentParts.tsx:201 (ux/pages/simulate/agent/LivePage.tsx:173) | 있음 |  |
| 6-2 | pages/main/AgentTimeline.tsx:55 | 요청 주소 `agentRun.steps[].path` | ux/simulate/AgentParts.tsx:203-206 | 있음 | 저장된 실행에서만 보임(옛 화면과 같음) |
| 6-2 | pages/main/AgentTimeline.tsx:66-70 | 요청별 다섯 통제의 답 `steps[].outcomes[c].outcome·rule` / `liveRun.steps[].layers[c].outcome·ruleId` | ux/simulate/AgentParts.tsx:217 (ux/simulate/agentRows.ts:25, :39-44) | 있음 |  |
| 6-2 | pages/main/AgentTimeline.tsx:98-108 | 같은 요청 묶음: 건수·요청 번호 범위·자체 판정 수·모델 호출 수 (`steps[].decision.final_action`·`model_calls`) | ux/pages/simulate/surge/SurgePage.tsx:349 (/simulate/surge, BurstSummary `withVerdict`·`modelCalls`) | 다른 위치 | 3단계는 묶지 않고 행마다 보여서 건수와 번호는 행으로 보임. 판정 수와 호출 수는 버스트 실행일 때만 요청 폭주 화면에 있고, 일반 에이전트 실행에서는 안 보임 |
| 6-2 | pages/main/AgentConsolePage.tsx:85-86 | 위임자 확인 사유 `liveRun.agentConfirmation.trigger` / `agentRun.confirmation.trigger` | ux/simulate/DelegatorPanel.tsx:54-56 (ux/pages/simulate/agent/LivePage.tsx:184) | 있음 | 진행 중인 확인만 보임. 저장된 실행의 사유는 4단계 ux/pages/simulate/agent/ResultPage.tsx:304-305에 있음 |
| 6-2 | pages/main/AgentConsolePage.tsx:105-112 | 판정 기록: 판정이 있는 요청 수와 요청별 Contexa 판정 `steps[].decision.final_action` | ux/pages/runs/RunDetailPage.tsx:112 (/runs/:runId?step=n, `recorded.finalAction`) | 다른 위치 | 3단계의 D 칸은 결과(outcome)를 먼저 보여서 final_action은 결과가 정해지지 않았을 때만 나옴(ux/simulate/agent.ts:62-74). 'n건' 집계는 없음 |
| 6-2 | pages/main/AgentConsolePage.tsx:116-117 | 에이전트 토큰 수 `agentRun.cost.agent.totalTokens` | — | 없음 |  |
| 6-2 | pages/main/AgentConsolePage.tsx:116-118 | 판정 모델 호출 합계 `agentRun.cost.decisions[].calls` | — | 없음 | ux/pages/runs/detailTabs.tsx:471-474는 한 요청의 호출 목록이고 실행 전체 합계가 아님 |
| 6-2 | pages/main/AgentConsolePage.tsx:128 | 에이전트의 답 `agentRun.finalAnswer` | ux/pages/simulate/agent/LivePage.tsx:210 | 있음 | 접힌 상자(details) 안에 있음 |
| 6-2 | pages/main/AgentConsolePage.tsx:59-60, :132 | 실행 상태 `liveRun.status` (진행 중·확인 대기·실패) | ux/pages/simulate/agent/LivePage.tsx:109-115, :131-148 | 있음 |  |

### 6-7

- 옛 제목: Contexa는 요청 1에서 멈췄고, 기존 보안 4곳은 멈추지 못했습니다
- 옛 화면: `pages/main/AgentResultPage.tsx` (키 `main.6-7.title.*`)
- 새 위치: 4단계 = /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 6-7 | pages/main/AgentResultPage.tsx:89; pages/main/AgentResultParts.tsx:46 | Contexa가 처음 멈춘 요청 `proof.controls.D.firstStopStep` (제목 {{step}}과 요약 칸) | ux/pages/simulate/agent/ResultPage.tsx:142, :152 | 있음 | 새 쪽은 firstStop(ux/simulate/agent.ts:141)으로 계산 |
| 6-7 | pages/main/AgentResultPage.tsx:87, :89 | 기존 보안 중 멈추지 못한 곳 수 ({{others}}) `proof.controls[A,B,C1,C2].firstStopStep` | ux/pages/simulate/agent/ResultPage.tsx:145-147 | 있음 | '멈춘 n개·통과 m개' 문장으로 보임 |
| 6-7 | pages/main/AgentResultPage.tsx:91-95 | 다른 곳이 처음 멈춘 요청 ({{step}}, othersStopped) | ux/pages/simulate/agent/ResultPage.tsx:255-257 | 있음 | 가장 이른 요청을 말하는 문장은 없고, 통제별 '처음 멈춘 요청' 표로 보임 |
| 6-7 | pages/main/AgentResultPage.tsx:97; pages/main/AgentResultParts.tsx:38 | 보낸 요청 수 `proof.sent` | ux/pages/simulate/agent/ResultPage.tsx:142, :152, :203 | 있음 |  |
| 6-7 | pages/main/AgentResultPage.tsx:51 | 보내는 쪽 칩 `agentCase.sender` | — | 없음 |  |
| 6-7 | pages/main/AgentResultPage.tsx:66 (→ pages/main/DelegationParts.tsx:59-61) | 위임 사슬 `protagonist`·`agentTitle`·`delegation.resources` | ux/pages/simulate/agent/ReviewPage.tsx:151-155 (2단계) | 다른 위치 | 4단계에는 사슬이 없음 |
| 6-7 | pages/main/AgentResultPage.tsx:69 | 방문자 실행 run id `useAgentTry.runId` | ux/pages/simulate/agent/ResultPage.tsx:172 | 있음 |  |
| 6-7 | pages/main/AgentResultPage.tsx:71 (→ components/main/SnapshotBadge.tsx:21-24) | 기준 실행의 저장 시각과 경과 시간 `agentSnapshot.capturedAt` | — | 없음 | 새 4단계는 실행이 없으면 '결과 없음'(ux/pages/simulate/agent/ResultPage.tsx:71-82)으로 끝나고, 기준 스냅샷으로 대신 보여 주지 않음 |
| 6-7 | pages/main/AgentResultParts.tsx:42 | 업무에 필요한 양 `proof.workNeeds` | ux/pages/simulate/agent/ResultPage.tsx:225-226 | 있음 | null이면 '필요 없음' 대신 일반 설명 문장(:227) |
| 6-7 | pages/main/AgentResultParts.tsx:50 | 위임한 사람에게 확인을 요청했는지 `agentRun.confirmation` / `steps[].outcomes.D.rule` | ux/pages/simulate/agent/ResultPage.tsx:142 (확인 관련 결론), :182 | 있음 |  |
| 6-7 | pages/main/AgentResultParts.tsx:73 | 통제별 처음 멈춘 요청 `proof.controls[c].firstStopStep` | ux/pages/simulate/agent/ResultPage.tsx:255-257 | 있음 |  |
| 6-7 | pages/main/AgentResultParts.tsx:76-81 | 통제별로 나간 것: 문서·항목·고객 기록·권한 변경 `proof.controls[c].documents·items·records·changes` | — | 없음 | 네 값의 합만 보임(ux/pages/simulate/agent/ResultPage.tsx:245, :259) |
| 6-7 | pages/main/AgentResultParts.tsx:83 | 통제별 업무 필요량을 넘은 양 `proof.controls[c].beyondNeed` | ux/pages/simulate/agent/ResultPage.tsx:260 | 있음 |  |
| 6-7 | pages/main/MeasureNote.tsx:37 (pages/main/AgentResultPage.tsx:76) | 누구의 실행인지(본인 / 기준 실행) `own.data` 유무 | ux/pages/runs/RunsPage.tsx:120 | 다른 위치 |  |
| 6-7 | pages/main/MeasureNote.tsx:33 | 상한으로 멈춤 `agentRun.stopReason` | ux/pages/simulate/agent/LivePage.tsx:205 (3단계) | 다른 위치 |  |
| 6-7 | pages/main/MeasureNote.tsx:40-43 | 운영자 기록 수와 같은 결과 수 `recorded.runs`·`sameAsLatest` | — | 없음 |  |

### 6-3

- 옛 제목: 위임 범위와 실제 요청의 차이
- 옛 화면: `pages/main/AgentReasonPage.tsx` (키 `main.6-3.title`)
- 새 위치: 판정 상세 › 판정 근거 = /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 6-3 | pages/main/AgentReasonPage.tsx:78-81 | Contexa가 멈춘 요청 번호(없으면 '모두 전달') `firstStop(agentRun).stepNo` | ux/pages/simulate/agent/ResultPage.tsx:142, :152 (4단계) | 다른 위치 | 판정 상세는 제한 판정이 난 요청을 처음에 열 뿐(ux/pages/runs/RunDetailPage.tsx:52, ux/simulate/person.ts:299-301), 멈춘 요청 번호를 말하지 않음 |
| 6-3 | pages/main/AgentReasonPage.tsx:84 | 보내는 쪽 칩 `agentCase.sender` | — | 없음 |  |
| 6-3 | pages/main/AgentReasonPage.tsx:97, :99 (→ components/main/SourceBadge.tsx:36) | run id와 요청 번호 `agentRun.runId`·`steps[].stepNo` | ux/pages/runs/RunDetailPage.tsx:111, :173 | 있음 |  |
| 6-3 | pages/main/AgentReasonPage.tsx:96-99; pages/main/MeasureNote.tsx:37 | 실행 출처(본인 실행 / 운영자 기록 1회) `useAgentTry.own` | ux/pages/runs/RunsPage.tsx:120 | 다른 위치 | 판정 상세에는 출처 표시 없음 |
| 6-3 | pages/main/AgentReasonPage.tsx:95 (→ components/main/SnapshotBadge.tsx:21-24) | 기준 실행의 저장 시각 `agentSnapshot.capturedAt` | — | 없음 |  |
| 6-3 | pages/main/AgentReasonPage.tsx:107-112 | 엔진이 든 차이(위임자 확인 사유) `confirmation.trigger` / `liveRun.agentConfirmation.trigger` | ux/pages/simulate/agent/ResultPage.tsx:304-305 (4단계); ux/simulate/DelegatorPanel.tsx:54-56 (3단계) | 다른 위치 | 판정 상세에는 없음 |
| 6-3 | pages/main/AgentReasonPage.tsx:116 | Contexa 판정 `steps[n].decision.final_action` | ux/pages/runs/RunDetailPage.tsx:112 | 있음 | `recorded.finalAction` 상태 배지로, 모든 탭에 공통으로 보임 |
| 6-3 | pages/main/AgentReasonPage.tsx:126-134 | 판단 방식: 위임 기록 규칙(D 규칙 AGENT_CONFIRMATION_REQUIRED)·AI 분석·거부 `steps[n].outcomes.D.rule` | ux/pages/runs/detailTabs.tsx:222 (/runs/:runId?tab=controls) | 다른 위치 | 같은 화면의 다른 탭. 4단계 ux/pages/simulate/agent/ResultPage.tsx:155에도 위임자 확인 배지가 있음 |
| 6-3 | pages/main/AgentReasonPage.tsx:131-133 | AI 분석 모델 호출 수 `steps[n].decision.model_calls` | ux/pages/runs/detailTabs.tsx:471-474 (/runs/:runId?tab=response) | 다른 위치 | 수를 말하는 문장은 없고 호출 카드 개수로만 알 수 있음. 응답 원문이 보관되지 않았으면 안 보임(:466-467) |
| 6-3 | pages/main/AgentReasonPage.tsx:150 (→ pages/main/DelegationParts.tsx:59-61) | 위임 사슬 `protagonist`·`agentTitle`·`resources` | ux/pages/simulate/agent/ReviewPage.tsx:151-155 (2단계) | 다른 위치 | 판정 근거 탭의 Delegation 사실에는 agent id와 delegator id(영문 원문)만 있음 |
| 6-3 | pages/main/DelegationParts.tsx:122 | 위임 목표 `delegation.summary[lang]` | ux/simulate/AgentParts.tsx:100 (2단계) | 다른 위치 | Delegation 사실에는 objective 코드만 있음 |
| 6-3 | pages/main/DelegationParts.tsx:90-91 | 위임된 작업과 요청한 작업 `delegation.operations[]` ↔ `steps[n].tool.tool` | ux/pages/runs/detailTabs.tsx:387-394, :405-406 | 있음 | 엔진이 받은 Delegation('allowed …')·Action 사실을 영문 원문으로 보임. 프롬프트 사실이 없으면 이 부분을 그리지 않음(:380-382) |
| 6-3 | pages/main/DelegationParts.tsx:95-96 | 위임 자원과 요청 대상 `delegation.resources[]` ↔ `tool.arguments.projectKey/documentKey/customerKey` (없으면 path) | ux/pages/runs/detailTabs.tsx:387-394, :405-406 | 있음 | Delegation('on …')·Target·TargetScope 사실. 그리는 조건은 E1-66과 같음 |
| 6-3 | pages/main/DelegationParts.tsx:100-101 | 위임 끝 시각과 요청 시각 `run.companyTime + delegation.validUntilMinutes` ↔ `steps[n].companyTime` | ux/pages/runs/detailTabs.tsx:387-394, :405-406 | 있음 | Delegation('expires …')는 상대 시각이고 Time 사실과 함께 보임. 회사 시각 절대값은 아님. 조건은 E1-66과 같음 |
| 6-3 | pages/main/DelegationParts.tsx:100 (pages/main/agentGroup.ts:36-50) | 위임 시작과 철회 `delegation.validFromMinutes`·`status` | ux/simulate/AgentParts.tsx:130-136 (2단계) | 다른 위치 | 엔진의 Delegation 줄에는 시작 시각이 없음(contexa-core/.../tiered/prompt/AgentLineValues.java:168-178) |
| 6-3 | pages/main/DelegationParts.tsx:104-113 | 요청당 최대 건수와 요청 건수 `delegation.maxItemsPerRequest` ↔ `tool.arguments.items` | ux/pages/runs/detailTabs.tsx:387-394, :405-406 | 있음 | Delegation('limits N items per request')·Size 사실. 조건은 E1-66과 같음 |
| 6-3 | pages/main/DelegationParts.tsx:128, :136 | 대조한 요청 번호 `steps[n].stepNo` | ux/pages/runs/RunDetailPage.tsx:173, :176 | 있음 |  |
| 6-3 | pages/main/DelegationParts.tsx:142 | 요청 주소 `steps[n].path` | ux/pages/runs/RunDetailPage.tsx:134-137 | 있음 | 새 쪽 필드는 `anatomy.context.resource.requestPath` |
| 6-3 | pages/main/AgentReasonPage.tsx:164-174 | 같은 요청에 대한 다섯 통제의 답 `steps[n].outcomes[c].outcome·rule` | ux/pages/runs/detailTabs.tsx:203-213 (/runs/:runId?tab=controls) | 다른 위치 | 같은 화면의 '통제별 응답' 탭. 4단계 AgentSteps에도 있음 |
| 6-3 | pages/main/AgentReasonPage.tsx:207 | 정상 짝 사례 키 `agentCase.normalPair` | ux/pages/simulate/agent/ResultPage.tsx:349 (4단계) | 다른 위치 | 새 쪽은 T5일 때만 고정값 'N1'을 쓰고 normalPair를 읽지 않음 |
| 6-3 | pages/main/AgentReasonPage.tsx:210-214 | 정상 짝 기록 실행: 요청 수·기존 넷이 모두 전달한 수·Contexa 전달 수 `agentRun(normalRecorded.runId).steps[]` | — | 없음 |  |
| 6-3 | pages/main/AgentReasonPage.tsx:216 | 정상 짝 실행이 일을 마쳤는지 `normalRun.finalAnswer` 유무 | — | 없음 |  |
| 6-3 | pages/main/AgentReasonPage.tsx:217 (→ components/main/SourceBadge.tsx:36) | 정상 짝 실행 run id `agentCase.normalRecorded.runId` | — | 없음 |  |
| 6-3 | pages/main/MeasureNote.tsx:33 (pages/main/AgentReasonPage.tsx:181) | 상한으로 멈춤 `agentRun.stopReason` | ux/pages/simulate/agent/LivePage.tsx:205 (3단계) | 다른 위치 |  |
| 6-3 | pages/main/MeasureNote.tsx:40-43 | 운영자 기록 수와 같은 결과 수 `recorded.runs`·`sameAsLatest` | — | 없음 |  |

### 6-4

- 옛 제목: 위임한 사람이 승인했고, 그 요청은 한 번만 처리됐습니다
- 옛 화면: `pages/main/AgentConfirmPage.tsx` (키 `main.6-4.title.approved`)
- 새 위치: 4단계 › 위임자 응답 = /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 6-4 | pages/main/AgentConfirmPage.tsx:109 | 확인 결과 갈래(제목): agentConfirmation.stage·decision / run.confirmation.decision / firstStop D rule | ux/pages/simulate/agent/ResultPage.tsx:142, ux/pages/simulate/agent/ResultPage.tsx:314-316 | 있음 | 결론 문장(confirmApproved/Rejected/Asked/stopped/passed)과 '이 실행' 응답으로 보임 |
| 6-4 | pages/main/AgentConfirmPage.tsx:157-159 | 확인 이유 trigger (agentConfirmation.trigger, run.confirmation.trigger) | ux/pages/simulate/agent/ResultPage.tsx:304-306, ux/simulate/DelegatorPanel.tsx:54-56 | 있음 |  |
| 6-4 | pages/main/AgentConfirmPage.tsx:170 | 남은 시간 agentConfirmation.secondsLeft | ux/simulate/DelegatorPanel.tsx:71 | 있음 | DP는 3단계 LivePage(/live, ux/pages/simulate/agent/LivePage.tsx:184)에서만 그려짐. 결과 화면에는 없음 |
| 6-4 | pages/main/AgentConfirmPage.tsx:202-204 | 다시 보낸 요청: resendStatus·resendDeliveredItems / confirmation.resend.httpStatus·deliveredItems | ux/pages/simulate/agent/ResultPage.tsx:293,318-322(문구 ux/pages/simulate/agent/ResultPage.tsx:278-282), ux/simulate/DelegatorPanel.tsx:100-104 | 있음 |  |
| 6-4 | pages/main/AgentConfirmPage.tsx:209-214 | 같은 확인 재사용·다른 요청 HTTP: reuseStatus·otherStatus / confirmation.reuse·other.httpStatus | ux/pages/simulate/agent/ResultPage.tsx:294-295,318-322, ux/simulate/DelegatorPanel.tsx:109,115 | 있음 |  |
| 6-4 | pages/main/AgentConfirmPage.tsx:210,214(→pages/main/AgentConfirmPage.tsx:358) | reuse·other가 2xx일 때 전달 건수: confirmation.reuse·other.deliveredItems | — | 없음 | 새 문구 ux.agentResult.confirm.reuse·other와 DP 문구에 건수 자리가 없음. 설계상 재사용은 거부되므로 보통은 비어 있음 |
| 6-4 | pages/main/AgentConfirmPage.tsx:289-293 | 거부 규칙 코드: reuseRule·otherRule / confirmation.*.ruleId | ux/pages/simulate/agent/ResultPage.tsx:282, ux/simulate/DelegatorPanel.tsx:110,116 | 있음 |  |
| 6-4 | pages/main/AgentConfirmPage.tsx:279 | 인가 기록 번호: agentConfirmation.authorizationId / confirmation.after.authorizationId | — | 없음 |  |
| 6-4 | pages/main/AgentConfirmPage.tsx:240 | 위임 목표 agentCase.delegation.summary | ux/simulate/AgentParts.tsx:100 (ux/pages/simulate/agent/ReviewPage.tsx:156, /simulate/agent/:caseKey/review) | 다른 위치 |  |
| 6-4 | pages/main/AgentConfirmPage.tsx:245-250 | 위임 범위 delegation.operations·resources | ux/simulate/AgentParts.tsx:103-112 (ReviewPage) | 다른 위치 |  |
| 6-4 | pages/main/AgentConfirmPage.tsx:255 | 위임 기간 delegation.validFromMinutes·validUntilMinutes·status | ux/simulate/AgentParts.tsx:130-136 (ReviewPage) | 다른 위치 |  |
| 6-4 | pages/main/AgentConfirmPage.tsx:266 | 확인을 요청한 요청 method·target (없으면 stop.path) | ux/simulate/DelegatorPanel.tsx:63; ux/pages/simulate/agent/ResultPage.tsx:205→ux/simulate/AgentParts.tsx:203-206(표시된 행의 path) | 있음 | 결과 화면에는 method가 없고 path만 있음 |
| 6-4 | pages/main/AgentConfirmPage.tsx:270 | 요청 회사 시각 stop.companyTime | — | 없음 | 에이전트 화면 어디에서도 companyTime을 그리지 않음 |
| 6-4 | pages/main/AgentConfirmPage.tsx:225-228 | 위임 끝 시각과 요청 시각 비교 (run.companyTime+validUntilMinutes, stop.companyTime) | — | 없음 | ReviewPage에는 상대 시각("N시간 전까지")과 '기간 종료' 배지만 있고 실제 시각은 없음 |
| 6-4 | pages/main/AgentConfirmPage.tsx:304 | 답 없는 이유(실시간 stage EXPIRED/ABANDONED/FAILED) | ux/simulate/DelegatorPanel.tsx:124 | 있음 | LivePage에서만 보임 |
| 6-4 | pages/main/AgentConfirmPage.tsx:304 | 답 없는 이유(저장 run.confirmation.reason: NO_CONFIRMATION·EXPIRED…, null이면 NOT_ASKED) | — | 없음 | ux/pages/simulate/agent/ResultPage.tsx:316은 '응답 없음'만 보임 |
| 6-4 | pages/main/AgentConfirmPage.tsx:310-312 | 통과 시 위협/정상 구분 agentCase.classification (위협이면 '공격 통과(미탐)') | ux/pages/runs/RunDetailPage.tsx:100(정답 배지), :103(EvalBadge) (/runs/:runId) | 다른 위치 | ux/pages/simulate/agent/ResultPage.tsx:142는 'passed'만 말함 |
| 6-4 | pages/main/AgentConfirmPage.tsx:316 | 확인 없이 Contexa 거부 (firstStop D rule이 확인 규칙이 아님) | ux/pages/simulate/agent/ResultPage.tsx:142(stopped) | 있음 |  |
| 6-4 | pages/main/AgentConfirmPage.tsx:129,131 | run id | ux/pages/simulate/agent/ResultPage.tsx:172 | 있음 |  |
| 6-4 | pages/main/AgentConfirmPage.tsx:128-131, pages/main/MeasureNote.tsx:37 | 실행 출처(본인 실행 / 운영자 기록 1회) tried.runId와 agentCase.recorded.runId | — | 없음 | 새 결과 화면은 본인 실행(또는 ?run=)만 보이고 출처를 말하지 않음 |
| 6-4 | pages/main/AgentConfirmPage.tsx:126→components/main/SnapshotBadge.tsx:21-24 | 저장 스냅숏 capturedAt (T5-confirm-approve로 대체할 때) | — | 없음 | 새 결과 화면은 스냅숏으로 대체하지 않고 '실행 기록 없음'(ux/pages/simulate/agent/ResultPage.tsx:77)을 보임 |
| 6-4 | pages/main/MeasureNote.tsx:39-44 | 운영자 기록 횟수 recorded.runs, 같은 결과 횟수 recorded.sameAsLatest | — | 없음 | sameAsLatest를 그리는 곳이 없음 |
| 6-4 | pages/main/MeasureNote.tsx:31-35 | 실행 상한 stopReason CAP_* | ux/pages/simulate/agent/LivePage.tsx:205 (/live) | 다른 위치 |  |
| 6-4 | components/main/MainScreen.tsx:180 (pages/main/AgentConfirmPage.tsx:108) | 요청 주체 칩 agentCase.sender→subject | — | 없음 | ux에서 sender·SubjectChip을 그리는 곳이 없음 |

### 6-5

- 옛 제목: 위임 종료 후 요청에 대한 책임자 응답별 결과
- 옛 화면: `pages/main/AgentEndPage.tsx` (키 `main.6-5.title`)
- 새 위치: 4단계 › 위임자 응답 = /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 6-5 | components/main/MainScreen.tsx:180 (pages/main/AgentEndPage.tsx:42) | 요청 주체 칩 agentCase.sender | — | 없음 | 24와 같은 필드 |
| 6-5 | pages/main/DelegationParts.tsx:37,58-62 (pages/main/AgentEndPage.tsx:51) | 위임 사슬 protagonist·agentTitle·delegation.resources(없으면 project) | ux/pages/simulate/agent/ReviewPage.tsx:151-155→ux/simulate/AgentParts.tsx:41; ux/pages/simulate/surge/SurgePage.tsx:166-170 | 다른 위치 | 새 화면은 resources[0] 하나만 보임(옛 화면은 전부 이어 보임) |
| 6-5 | pages/main/AgentEndPage.tsx:77,86 | 책임자의 답(승인·보고) static:AgentEndPage.ANSWERS.decision | ux/pages/simulate/agent/ResultPage.tsx:315(본인 실행 decision), ux/pages/simulate/agent/ResultPage.tsx:326-327(신고 기록) | 있음 | '승인'은 본인 실행이 승인일 때만 보임 |
| 6-5 | pages/main/AgentEndPage.tsx:89-93 | 확인 뒤 상태 run.confirmation.after.status (두 열) | — | 없음 | after.status·statusAfter를 그리는 곳이 없음. 신고 쪽은 고정 문구 reportedValue만 있음 |
| 6-5 | pages/main/AgentEndPage.tsx:100-106→:132-135 | 승인 열 resend·reuse·other의 outcome·httpStatus [스냅숏 T5-confirm-approve] | ux/pages/simulate/agent/ResultPage.tsx:318-322 | 있음 | 출처가 저장 스냅숏에서 방문자 본인 실행으로 바뀜. 본인이 거절했거나 실행 전이면 승인 결과는 안 보임. outcome 낱말 대신 HTTP 상태로 보임 |
| 6-5 | pages/main/AgentEndPage.tsx:100-106→:132-135 | 보고 열 resend·reuse·other [스냅숏 T5-confirm-report] | ux/pages/simulate/agent/ResultPage.tsx:328-332 | 있음 | T5에서만(ux/pages/simulate/agent/ResultPage.tsx:288), 그리고 본인 실행에 확인 단계가 있을 때만(ux/pages/simulate/agent/ResultPage.tsx:182) |
| 6-5 | pages/main/AgentEndPage.tsx:83→components/main/SnapshotBadge.tsx:21-24 | 두 스냅숏 capturedAt | — | 없음 | 신고 기록은 run id만 있음(ux/pages/simulate/agent/ResultPage.tsx:334) |

### 6-6

- 옛 제목: 요청이 한꺼번에 몰릴 때의 대응
- 옛 화면: `pages/main/AgentBurstPage.tsx` + `pages/main/BurstLive.tsx` (키 `main.6-6.title`)
- 새 위치: 요청 급증 대응 = /simulate/surge · `ux/pages/simulate/surge/SurgePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 6-6 | components/main/MainScreen.tsx:180 (pages/main/AgentBurstPage.tsx:29) | 요청 주체 칩 agentCase.sender | — | 없음 | 새 화면에는 위임 사슬(ux/pages/simulate/surge/SurgePage.tsx:166)만 있음 |
| 6-6 | pages/main/BurstLive.tsx:79,88 | 실시간 최대 건수 burst.most와 고를 수 있는 건수 | ux/pages/simulate/surge/SurgePage.tsx:193 | 있음 |  |
| 6-6 | pages/main/BurstLive.tsx:93 | 1회 점수 burst.points, 오늘 남은 에이전트 실행 remainingAgentToday | ux/pages/simulate/surge/SurgePage.tsx:252, ux/pages/simulate/surge/SurgePage.tsx:214 | 있음 | ux/pages/simulate/surge/SurgePage.tsx:214는 dailyAgentRuns가 있을 때만 |
| 6-6 | pages/main/BurstLive.tsx:108 | 보낼 수 없는 이유 liveTicketsLeft≤0 / remainingToday<points | ux/pages/simulate/surge/SurgePage.tsx:137-140 | 있음 | 버튼 비활성 사유로 보임 |
| 6-6 | pages/main/BurstLive.tsx:112-113 | 실행 상태(진행 중·실패) live.status | ux/pages/simulate/surge/SurgePage.tsx:262, ux/pages/simulate/surge/SurgePage.tsx:141-142 | 있음 |  |
| 6-6 | pages/main/BurstLive.tsx:117-120 | 전송 거절(일일 한도·일시 중지·장애) | ux/pages/simulate/surge/SurgePage.tsx:220-225 | 있음 |  |
| 6-6 | pages/main/BurstLive.tsx:138 | 내 실행 run id | ux/pages/simulate/surge/SurgePage.tsx:260 | 있음 |  |
| 6-6 | pages/main/BurstLive.tsx:149-154 | 내 실행 burst.requests·delivered·refused·busy·withVerdict·modelCalls | ux/pages/simulate/surge/SurgePage.tsx:349 (+Counters ux/pages/simulate/surge/SurgePage.tsx:292-305) | 있음 |  |
| 6-6 | pages/main/BurstLive.tsx:149-154 | 내 실행 burst.deliveredAfterFirstStop | — | 없음 | 새 ROWS(ux/pages/simulate/surge/SurgePage.tsx:312)에서 빠짐 |
| 6-6 | pages/main/BurstLive.tsx:155-158 | 내 실행 burst.firstStopStep | — | 없음 |  |
| 6-6 | pages/main/AgentBurstPage.tsx:82 | M41A 측정 요청 수 on.summary.requests | ux/pages/simulate/surge/SurgePage.tsx:350, ux/pages/simulate/surge/SurgePage.tsx:367 | 있음 |  |
| 6-6 | pages/main/AgentBurstPage.tsx:96-101 | M41A 끔·켬 요청·전달·거부·분석 중 거부·자체 판정·모델 호출 | ux/pages/simulate/surge/SurgePage.tsx:350-351 | 있음 | 포털 설정에 burst가 없으면 BurstTab이 측정 비교도 그리지 않음(ux/pages/simulate/surge/SurgePage.tsx:127-129). 옛 화면은 측정을 따로 보였음 |
| 6-6 | pages/main/AgentBurstPage.tsx:96-101 | M41A 끔·켬 deliveredAfterFirstStop | — | 없음 |  |
| 6-6 | pages/main/AgentBurstPage.tsx:104-106 | M41A 끔·켬 firstStopStep | — | 없음 |  |
| 6-6 | pages/main/AgentTimeline.tsx:54-55,69-71,98-108 (pages/main/AgentBurstPage.tsx:113-115) | M41A 켬 실행의 요청별 타임라인(on.run.steps: 경로, 5개 통제 결과, 묶음 건수·자체 판정·모델 호출) | — | 없음 | 스냅숏 run id는 ux/pages/simulate/surge/SurgePage.tsx:375에 CodeChip으로 보이지만 링크가 아님 |
| 6-6 | pages/main/AgentBurstPage.tsx:45 | 다른 몰림 수 | ux/pages/simulate/surge/SurgePage.tsx:388 | 있음 |  |
| 6-6 | pages/main/AgentBurstPage.tsx:82,99-100 | M41T·M41X 켬 요청·전달·분석 중 거부·모델 호출, 끔 모델 호출 | ux/pages/simulate/surge/SurgePage.tsx:405-409 | 있음 |  |
| 6-6 | pages/main/AgentBurstPage.tsx:99-100 | M41T·M41X 끔 요청·전달·분석 중 거부, 끔·켬 거부·자체 판정 | — | 없음 | OtherBursts에는 켬 값과 모델 호출만 있음 |
| 6-6 | pages/main/AgentBurstPage.tsx:99-100,104-106 | M41T·M41X 끔·켬 deliveredAfterFirstStop·firstStopStep | — | 없음 |  |
| 6-6 | pages/main/AgentBurstPage.tsx:84→components/main/SnapshotBadge.tsx:21-24 | 세 몰림 켬 스냅숏 capturedAt | — | 없음 | 새 화면에는 M41A run id 두 개만 있음(ux/pages/simulate/surge/SurgePage.tsx:375) |

### 1-2

- 옛 제목: 이 데모에서 확인할 여섯 가지
- 옛 화면: `pages/main/IntroMapPage.tsx` (키 `main.1-2.title`)
- 새 위치: AI 판정 엔진 › 판정 근거 사실 = /engine?tab=facts · `ux/pages/engine/EnginePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 1-2 | pages/main/IntroMapPage.tsx:48-51 (문구 33, 그림 83) | `benchmark.cases[key=S13].cells.D.{right,counted}` | ux/pages/validation/ScenariosTab.tsx:228-229 | 다른 위치 | /validation?tab=scenarios&case=S13 상세 패널. /engine?tab=facts에는 벤치마크 값이 없음 |
| 1-2 | pages/main/IntroMapPage.tsx:53-56 (33, 83) | `benchmark.cases[key=S13T].cells.D.{right,counted}` | ux/pages/validation/ScenariosTab.tsx:228-229 | 다른 위치 | /validation?tab=scenarios&case=S13T |
| 1-2 | pages/main/IntroMapPage.tsx:57-60 (33, 83) | `benchmark.cases[key=S16].cells.D.{right,counted}` | ux/pages/validation/ScenariosTab.tsx:228-229 | 다른 위치 | /validation?tab=scenarios&case=S16 |
| 1-2 | pages/main/IntroMapPage.tsx:63 (그림 83) | `benchmark.scope.runs` | ux/pages/validation/ValidationPage.tsx:192 | 다른 위치 | /validation 요약 탭(기본 탭). /compare?tab=runs ux/pages/compare/ComparePage.tsx:351에도 있음 |

### 3-1

- 옛 제목: 방금 판단이 나오기까지의 일곱 단계
- 옛 화면: `pages/main/EvidenceMapPage.tsx` (키 `main.3-1.title`)
- 새 위치: AI 판정 엔진 › 판정 흐름 = /engine?tab=flow · `ux/pages/engine/EnginePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 3-1 | pages/main/EvidenceMapPage.tsx:78 (pages/main/evidence.ts:135-142, 그림 152) | 학습 단계: `anatomy.figures.{baselineBefore,workProfileObservations,workProfileWindow}` | ux/pages/engine/EnginePage.tsx:191-196 (그림 287) | 있음 |  |
| 3-1 | pages/main/EvidenceMapPage.tsx:79,84,93 (factTag 223, 그림 234) | 단계 원문 이름표: `facts.blocks[].facts[label=BaselineStatus · PolicySatisfied/Policy · DeviationsFromBaseline].{factId,label}` (예: B1 BaselineStatus) | ux/pages/runs/detailTabs.tsx:441-442 (PromptTab) | 다른 위치 | /engine?tab=prompt에 있음. 판정 흐름 탭은 응답을 읽지 않고 고정 글자 'BaselineStatus'·'Policy'·'Deviations'만 씀(ux/pages/engine/EnginePage.tsx:198,204,217). factId(B1·F3·F1)가 없음 |
| 3-1 | pages/main/EvidenceMapPage.tsx:70-75,83 (그림 152) | 맥락 단계 회사 기록: `received.businessFacts[code∈NO_APPROVAL·APPROVAL_COVERS·NOT_ASSIGNED].value` | ux/pages/engine/EnginePage.tsx:203 (그림 287) | 있음 | 새 쪽은 거르지 않고 앞의 칩 3개만 보임(서버 순서: 담당 · 승인 · 티켓) |
| 3-1 | pages/main/EvidenceMapPage.tsx:72-74,83 | `received.businessFacts[ACCESS_DAYS_LAST_30].value` (최근 30일 접근 일수) | ux/pages/runs/detailTabs.tsx:443-445 (F4 Assignment 줄 "…on 21 of the last 30 days") | 다른 위치 | 판정 흐름 탭은 `slice(0,3)`으로 잘림. 서버 순서상 5번째(ReplayViews.java:357-374, 반출 요청은 ticket·oncall도 넣음, ContextLookupRules.java:79-83). 이 필드를 그대로 그리는 곳은 /simulate/person/S13/review ux/pages/simulate/person/ReviewPage.tsx:123-125뿐(비교 실행 기준) |
| 3-1 | pages/main/EvidenceMapPage.tsx:87-92 | 비교 단계: `anatomy.figures.departureCount`, `anatomy.juxtaposition.sensitivity` | ux/pages/engine/EnginePage.tsx:210-215 | 있음 | 민감도는 `context.resource.sensitivity`에서 읽음. 서버의 같은 값(AnatomyBuilder.java:144,205)이고 번역 없이 원문 코드로 보임 |
| 3-1 | pages/main/EvidenceMapPage.tsx:96-101 | `anatomy.promptLines.{system,user,total}` | ux/pages/engine/EnginePage.tsx:222-224 | 있음 |  |
| 3-1 | pages/main/EvidenceMapPage.tsx:103-105 | `quality.bundle.version` | ux/pages/engine/EnginePage.tsx:225 (그림 288) | 있음 |  |
| 3-1 | pages/main/EvidenceMapPage.tsx:108-115 (pages/main/evidence.ts:91-106) | LLM 단계: 모델 · 호출 수 · 입력 토큰 · 초 (`interpretation.calls[]`, `interpretation.promptTokens`, `timings.llmLatencyMs`) | ux/pages/engine/EnginePage.tsx:230-235 | 있음 | 새 쪽은 첫 호출의 model을 쓰고, 토큰은 calls[].promptTokens를 화면에서 더함. 마지막 호출 elapsedMs로 대신하는 처리는 없음 |
| 3-1 | pages/main/EvidenceMapPage.tsx:117-119 | `interpretation.recorded.proposedAction` | ux/pages/engine/EnginePage.tsx:236 (그림 288) | 있음 |  |
| 3-1 | pages/main/EvidenceMapPage.tsx:123 | `quality.reasonCodes.length` | ux/pages/engine/EnginePage.tsx:242 | 있음 |  |
| 3-1 | pages/main/EvidenceMapPage.tsx:124-125 | `quality.ribbon.factAccuracy.{matched,total}` | ux/pages/runs/detailTabs.tsx:585-593 (IntegrityTab 검사표의 FACT_ACCURACY 행) | 다른 위치 | /engine?tab=seal. total = matched + mismatched(SealedPromptViews.java:227-228). 흐름 탭 SealCard(ux/pages/engine/EnginePage.tsx:385-391)는 모든 검사의 합계라 다른 값. ux에서 ribbon·factAccuracy 검색 결과 0건 |
| 3-1 | pages/main/EvidenceMapPage.tsx:126 | `interpretation.recorded.applied` | ux/pages/engine/EnginePage.tsx:243-245 | 있음 |  |
| 3-1 | pages/main/EvidenceMapPage.tsx:127 | `stepResults[0].layers[control=D].httpStatus` | ux/pages/runs/detailTabs.tsx:108 | 다른 위치 | /runs/:runId?tab=summary(controls 탭 ux/pages/runs/detailTabs.tsx:214에도 있음). 판정 흐름 탭에는 없음 |
| 3-1 | pages/main/EvidenceMapPage.tsx:129 | `interpretation.recorded.finalAction` | ux/pages/engine/EnginePage.tsx:247 (그림 288), 272 | 있음 |  |
| 3-1 | pages/main/EvidenceMapPage.tsx:132 | 학습 반영 건수 `anatomy.learning.newBehaviourDocuments.length` | ux/pages/engine/EnginePage.tsx:252-257 | 있음 | 새 쪽은 다른 필드인 `figures.baselineAfter − baselineBefore`로 계산. 문서 목록은 /runs/:id?tab=learning ux/pages/runs/detailTabs.tsx:638-646 |
| 3-1 | pages/main/EvidenceMapPage.tsx:133-135, 168 | `quality.seal.packageHash` (짧게) | ux/pages/engine/EnginePage.tsx:258, 378 | 있음 |  |
| 3-1 | pages/main/EvidenceMapPage.tsx:169, 211 (components/main/SourceBadge.tsx:35) | runId | ux/pages/engine/EnginePage.tsx:92 | 있음 | 머리줄의 CodeChip이라 모든 탭에 보임 |
| 3-1 | pages/main/EvidenceMapPage.tsx:170-173 | `quality.seal.capturedAt` | ux/pages/engine/EnginePage.tsx:382 | 있음 |  |
| 3-1 | pages/main/EvidenceMapPage.tsx:184-185 | 내려받은 기록의 SHA-256 (`downloadRunRecord()` 결과) | ux/pages/runs/detailTabs.tsx:547-551 | 다른 위치 | /engine?tab=seal(IntegrityTab). 흐름 탭 SealCard에는 내려받기가 없음 |
| 3-1 | pages/main/EvidenceMapPage.tsx:189-195 → pages/main/ProofPanel.tsx:321-328 | 이 실행의 학습 누적: `learning.template.baselineUpdateCount → learning.atRunEnd.baselineUpdateCount`, 더한 수 | ux/pages/engine/EnginePage.tsx:339 (수 321, 표시 322-324) | 있음 | `figures.baselineBefore/After`는 서버의 같은 필드(AnatomyBuilder.java:248-249) |
| 3-1 | pages/main/EvidenceMapPage.tsx:52,196-203 → pages/main/ProofPanel.tsx:269,321-328 | 정상 업무 5건 측정 실행: `measured[A6T].middleRun` runId와 그 실행의 before→after | ux/pages/engine/EnginePage.tsx:340-345 (runId 316, 수 321) | 있음 |  |
| 3-1 | pages/main/EvidenceMapPage.tsx:53,200 | 그 측정 실행의 직원 이름: `labOptions.employees[cases[A6T].conditions.employee]` (person.* / displayName) | — | 없음 | 새 문구 `ux.engine.learning.other` = "비교 · 정상 업무 측정 실행"에 이름이 들어가지 않음 |
| 3-1 | pages/main/EvidenceMapPage.tsx:193, 209-210 | 실행 출처(내 실행 / 측정 실행) `evidence.own` | ux/pages/engine/EnginePage.tsx:91 | 있음 | 대신 쓰는 실행이 다름. 옛 쪽은 `benchmark.cases[S13].runIds`의 마지막(pages/main/evidence.ts:25-28), 새 쪽은 `hook.attacker.runId`(공개 녹화 실행) |

### 3-2

- 옛 제목: 입력이 프롬프트의 어느 줄이 됐는가
- 옛 화면: `pages/main/EvidencePromptPage.tsx` (키 `main.3-2.title`)
- 새 위치: AI 판정 엔진 › 판정 프롬프트 = /engine?tab=prompt · `ux/pages/engine/EnginePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 3-2 | pages/main/EvidencePromptPage.tsx:59,62 (그림 103) | 평소 패턴 카드: `anatomy.figures.{baselineBefore,workProfileObservations,workProfileWindow}` | ux/pages/runs/detailTabs.tsx:443-445 (B1 BaselineStatus "49 learned requests", Evidence "window 7 days … observations 21") | 있음 | 값이 프롬프트 원문 줄로만 보임. 같은 필드는 /engine?tab=flow ux/pages/engine/EnginePage.tsx:191-196. 고정 자료에서 49 · 21 · 7일이 일치함 |
| 3-2 | pages/main/EvidencePromptPage.tsx:64 (그림 103) | 요청 시각 `received.companyTime` | ux/pages/runs/detailTabs.tsx:443-445 (R2 Time "Wed 14:20") | 있음 | 원문 줄로만 보임. "수요일 14:20" 같은 평이한 표현은 /simulate/person/S13/review(ux/simulate/person.ts:146 → ux/pages/simulate/person/ReviewPage.tsx:112, 비교 실행 기준) |
| 3-2 | pages/main/EvidencePromptPage.tsx:65 | 프로젝트 `labOptions.cases[S13].requests[0].project` | ux/pages/runs/detailTabs.tsx:443-445 (R5 TargetScope "projectKey=HX-310") | 있음 | 원문 줄로만 보임. 같은 필드는 ux에서 승인 있는 사례의 해제 사유(ux/pages/simulate/person/LivePage.tsx:332)에만 있음 |
| 3-2 | pages/main/EvidencePromptPage.tsx:66 | 건수 `labOptions.cases[S13].requests[0].items` | ux/pages/runs/detailTabs.tsx:443-445 (R6 Size "480 items") | 있음 | 원문 줄로만 보임. 같은 필드는 ux/pages/simulate/person/ReviewPage.tsx:94의 제목 |
| 3-2 | pages/main/EvidencePromptPage.tsx:68-74 (그림 103) | 회사 기록 승인 · 담당 `received.businessFacts[NO_APPROVAL·APPROVAL_COVERS·NOT_ASSIGNED]` | ux/pages/engine/EnginePage.tsx:203 | 다른 위치 | /engine?tab=flow의 칩. v21 프롬프트 줄에는 승인 유무를 적은 줄이 없음(F3 Policy는 규정 문장, facts-attacker 고정 자료 기준) |
| 3-2 | pages/main/EvidencePromptPage.tsx:68-74 (그림 103) | `received.businessFacts[ACCESS_DAYS_LAST_30].value` | ux/pages/runs/detailTabs.tsx:443-445 (F4 Assignment "21 of the last 30 days") | 있음 | 원문 줄로만 보임. 같은 값을 엔진 쪽 조회로 얻은 것 |
| 3-2 | pages/main/EvidencePromptPage.tsx:75-80 (그림 103) | 민감도 `received.sensitivity` | ux/pages/runs/detailTabs.tsx:443-445 (R7 ResourceClass "sensitivity HIGH") | 있음 | 원문 줄로만 보임. 같은 값의 필드는 /engine?tab=flow ux/pages/engine/EnginePage.tsx:214 |
| 3-2 | pages/main/EvidencePromptPage.tsx:54-57,110-114 | 평소 시각 · 기기 · 반출 최대 `received.usual.{accessHour,device,size}.values` | ux/pages/runs/detailTabs.tsx:443-445 (UsualHours · UsualDevices · UsualExportSize 줄) | 있음 | 서버가 이 줄에서 베껴 만든 값(api/anatomy.ts:329). 같은 필드는 /engine?tab=facts ux/pages/runs/detailTabs.tsx:304 |
| 3-2 | pages/main/EvidencePromptPage.tsx:123-126 | 입력 묶음별 프롬프트 줄 번호 `facts.blocks[].facts[].line` | ux/pages/runs/detailTabs.tsx:440 | 있음 | 새 쪽은 엔진 블록별로 묶음. 옛 쪽의 입력 네 묶음 분류는 없음 |
| 3-2 | pages/main/EvidencePromptPage.tsx:135, 140 | `anatomy.promptLines.user`, `.system` | ux/pages/runs/detailTabs.tsx:427 | 있음 |  |
| 3-2 | pages/main/EvidencePromptPage.tsx:144-145 | `facts.available` / `facts.reason` | ux/pages/runs/detailTabs.tsx:431-432 | 있음 |  |
| 3-2 | pages/main/EvidencePromptPage.tsx:158-161 | 프롬프트 줄 `facts.blocks[].facts[].{line,factId,label,value}` | ux/pages/runs/detailTabs.tsx:440-445 | 있음 | 라벨은 번역 이름(fact.label.*)으로 보이고, 영어 원문 라벨은 사전에 없을 때만 보임. 옛 쪽은 고른 라벨만, 새 쪽은 모든 줄을 보임 |
| 3-2 | pages/main/EvidencePromptPage.tsx:163-165 | 줄 출처 등급 `facts.blocks[].facts[].source` (HOST · LEARNED · COMPUTED · INFERRED · UNTRUSTED) | — | 없음 |  |
| 3-2 | pages/main/EvidencePromptPage.tsx:173-177 (components/main/SourceBadge.tsx:35) | runId (SourceBadge) | ux/pages/engine/EnginePage.tsx:92 | 있음 |  |
| 3-2 | pages/main/EvidencePromptPage.tsx:174-175 | 실행 출처 `evidence.own` | ux/pages/engine/EnginePage.tsx:91 | 있음 | 대신 쓰는 실행이 다름(27번과 같음) |

### 3-3

- 옛 제목: LLM이 답한 원문과, 그 답이 판정이 되기까지
- 옛 화면: `pages/main/EvidenceVerdictPage.tsx` (키 `main.3-3.title`)
- 새 위치: 판정 상세 › 모델 응답 원문 = /runs/:runId?tab=response · `ux/pages/runs/detailTabs.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 3-3 | pages/main/VerdictCard.tsx:62, :64 | 판정과 원래 코드: `recorded.finalAction ?? proposedAction` | ux/pages/runs/RunDetailPage.tsx:112 | 있음 |  |
| 3-3 | pages/main/VerdictCard.tsx:66-71 | 제안 판정을 그대로 적용했는지 바꿨는지: `recorded.proposedAction` vs `finalAction` | ux/pages/runs/detailTabs.tsx:92-93 (?tab=summary); ux/pages/engine/EnginePage.tsx:236 (/engine?tab=flow) | 다른 위치 |  |
| 3-3 | pages/main/VerdictCard.tsx:129 | 위험 점수·신뢰도: `recorded.riskScore`, `recorded.confidence` | ux/pages/runs/RunDetailPage.tsx:146-147 | 있음 |  |
| 3-3 | pages/main/VerdictCard.tsx:139-142 | 값 출처(모델이 낸 값 / 내지 않음): `recorded.fieldProvenance.*` | — | 없음 |  |
| 3-3 | pages/main/VerdictCard.tsx:102 | AI 판단 요약: `recorded.reasoning` | ux/pages/runs/detailTabs.tsx:334-337 (?tab=evidence) | 다른 위치 | 응답 원문 탭에는 기록된 요약 줄이 없음(원문 안에만 있음) |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:63-67 → pages/main/VerdictCard.tsx:215-221, :238-242 | 근거 코드와 인용한 사실 줄: `quality.reasonCodes[]` + `facts.blocks[].facts[]` | ux/pages/runs/detailTabs.tsx:269-278 (?tab=evidence) | 다른 위치 | /engine?tab=facts에도 같은 부품 |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:77-82 → pages/main/CheckCounts.tsx:20-21 | 검사 4종의 일치/불일치/확인 불가: `quality.inspection.checks[SEAL_INTEGRITY, FACT_ACCURACY, DECISION_FACT_MATCH, REASON_MATCH].{matched,mismatched,unverifiable}` | ux/pages/runs/detailTabs.tsx:588-592 (?tab=integrity) | 다른 위치 | 새것은 모든 검사를 보여 줌. ux/pages/engine/EnginePage.tsx:386-391은 합계만 |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:88 | 불리한 조건 충족 수: `anatomy.juxtaposition.{adverseMet,adverseChecked}` | — | 없음 |  |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:98-100 | 적용 시점: `recorded.applied` | ux/pages/runs/RunDetailPage.tsx:155 | 있음 | 판정 시간(totalAnalysisMs)이 있을 때만 보임 |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:101-102 | Contexa의 HTTP 상태와 나간 건수: `stepResult.layers[D].httpStatus`, `.evidence.deliveredItems` | ux/pages/runs/detailTabs.tsx:106, :108 (?tab=summary) | 다른 위치 |  |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:106 | 평소 행동 패턴에 더한 건수: `anatomy.learning.newBehaviourDocuments.length` | ux/pages/runs/detailTabs.tsx:640-644 (?tab=learning) | 다른 위치 | 더한 기록을 한 줄씩 보여 줌. 수는 figures 기반 :626 |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:110, :113 | 봉인 해시(줄임)와 봉인 시각: `quality.seal.{packageHash,capturedAt}` | ux/pages/runs/detailTabs.tsx:532, :535 (?tab=integrity); ux/pages/engine/EnginePage.tsx:378, :382 | 다른 위치 |  |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:124 | 모델 이름: `anatomy.interpretation.calls[-1].model` | ux/pages/runs/detailTabs.tsx:477 | 있음 | `exchanges.calls[].model`로 읽음 |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:126 | 호출 수: `calls.length` | ux/pages/runs/detailTabs.tsx:471-474 | 있음 | 호출마다 "모델 호출 n" 카드. ux/pages/engine/EnginePage.tsx:232에는 수로 보임 |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:128-131 | 입력·출력 토큰: `interpretation.promptTokens`, `completionTokens` | ux/simulate/DecisionProgress.tsx:101-104 (/simulate/person/:caseKey/live) | 다른 위치 | ux/pages/engine/EnginePage.tsx:233은 입력만 보여 줌 |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:133-137 | 모델 시간: `timings.llmLatencyMs ?? calls[-1].elapsedMs` | ux/pages/engine/EnginePage.tsx:234 (/engine?tab=flow) | 다른 위치 |  |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:147 | 모델 응답 원문: `calls[-1].answer` | ux/pages/runs/detailTabs.tsx:484 | 있음 | `exchanges.calls[].answer`. 보존 기간이 지나면 안내만 나옴(:467) |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:156 → pages/main/Hypotheses.tsx:48-55, :68, :80 | 가설 이름·평가·찬성/반대 사실: `quality.hypotheses[]` | ux/pages/runs/detailTabs.tsx:348-360 (?tab=evidence) | 다른 위치 |  |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:157-161 → components/main/SourceBadge.tsx:36 | run id | ux/pages/runs/RunDetailPage.tsx:111 | 있음 |  |
| 3-3 | pages/main/EvidenceVerdictPage.tsx:158-159 | 내 실행인지 측정 실행인지: `useEvidenceRun.own` | ux/pages/engine/EnginePage.tsx:91 (/engine); ux/pages/runs/RunsPage.tsx:120 | 다른 위치 | 판정 상세에는 출처 표시가 없음 |

### 7-1

- 옛 제목: 규칙을 켜도 공격과 정상 업무가 똑같이 지나갑니다
- 옛 화면: `pages/main/RuleSwitchPage.tsx` (키 `main.7-1.title.blind`)
- 새 위치: 탐지 방식 비교 › 임계값 규칙 적용 = /compare?tab=rule · `ux/pages/compare/ComparePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 7-1 | `pages/main/RuleSwitchPage.tsx:80` (값 조립 60-64) | 규칙 임계값 `/api/settings` threshold.nightStart · nightEnd · volumeLimit | `ux/pages/compare/ComparePage.tsx:137-143` | 있음 | 새 쪽은 dormantWindowDays도 함께 보임 |
| 7-1 | `pages/main/RuleSwitchPage.tsx:103` | 공격 실행(S13)의 규칙 결과: journey runs[].business.C1(켬) / .B(끔) | `ux/pages/compare/ComparePage.tsx:238-241` (공격 행 160) | 있음 | 새 쪽은 `/api/runs/{id}/score` business[C1\|B].result에 반출 건수를 더해 보임. 방문자 실행이 없으면 공개 기록 실행을 씀. PASSED_AFTER_CHECK는 EvalBadge에서 normal로 합쳐짐 |
| 7-1 | `pages/main/RuleSwitchPage.tsx:106` | 정상 실행(S13T)의 규칙 결과: runs[].business.C1 / .B | `ux/pages/compare/ComparePage.tsx:238-241` (정상 행 161) | 있음 | 옛 "켜도 꺼도 결과가 같습니다" 문장(:118)은 없음. 스위치를 끄면 B 결과가 같은 칸에 보임 |
| 7-1 | `pages/main/RuleSwitchPage.tsx:112`, `:115` | Contexa 판단과 반출 건수(공격·정상): runs[].engineAction, exposedItems | `ux/pages/compare/ComparePage.tsx:248-252` | 있음 | 새 쪽은 verdicts[].score.finalAction(decisionOf)과 business.D.exposedItems를 읽음 |
| 7-1 | `pages/main/RuleSwitchPage.tsx:122-123` | 두 실행의 실행 ID: runs[].runId | `ux/pages/compare/ComparePage.tsx:228` | 있음 |  |
| 7-1 | `pages/main/RuleSwitchPage.tsx:80`(제목), `:120` | 제목 판정(C1이 공격 MISSED · 정상 PASSED, 즉 두 요청을 구분 못 함). business.C1에서 나온 판정 | `ux/pages/compare/ComparePage.tsx:170` | 있음 | 옛 3갈래(dilemma / blind / plain)가 새 2갈래(same / differs)로 바뀜 |

### 7-2

- 옛 제목: 조건 하나를 바꿨을 때의 판단 변화
- 옛 화면: `pages/main/ChangePage.tsx` (키 `main.7-2.title`)
- 새 위치: 탐지 방식 비교 › 조건 변경 실험 = /compare?tab=change · `ux/pages/compare/ComparePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 7-2 | `pages/main/ChangePage.tsx:229`, `:233` | 바꿀 조건 3종의 현재값 → 바꿀 값: lab options cases[S13].conditions.timeSlot(→timeSlots[].representativeTime) · items · device, 반대 슬롯 시각, options.items 최솟값, 반대 기기 | `ux/pages/simulate/policy/ComposeTab.tsx:153`, `:172`, `:226-230` (/simulate/policy?tab=compose). 최솟값만은 `ux/pages/compare/ComparePage.tsx:187` (/compare?tab=rule) | 다른 위치 | /compare?tab=change(`ux/pages/compare/ComparePage.tsx:299`)에는 바꾼 조건의 이름만 있고 값이 없음 |
| 7-2 | `pages/main/ChangePage.tsx:261` → `pages/main/consoleParts.tsx:73-81`, `:99-113` | 다섯 통제 레인: live steps[1].layers[통제].outcome · deliveredItems · httpStatus · elapsedMs, D는 decision.finalAction · totalAnalysisMs | `ux/pages/simulate/policy/ComposeTab.tsx:409-417`(결과 배지만). `ux/pages/runs/detailTabs.tsx:203-219`(판정·HTTP·건수·시간), `:99-101`(분석 시간) = /runs/:runId | 다른 위치 | 조건 변경 화면에는 HTTP·건수·시간이 없고, 실행 상세에서만 보임 |
| 7-2 | `pages/main/consoleParts.tsx:93` (ChangePage:195에서 넘김) | Contexa 판단 대기 시간: liveAnalysis.decisionWait.waitedMs | `ux/pages/simulate/person/LivePage.tsx:214-215` (/simulate/person/:caseKey/live) | 다른 위치 | 사람 시뮬레이션 실행에서만 보임. 조건 변경 실행(ComposeTab)에는 없음. 진행 중에만 보이는 값 |
| 7-2 | `pages/main/ChangePage.tsx:273-299` | 프롬프트에서 달라진 줄: `/api/lab/runs/{id}/delta` steps[1].changed[].label / before[] / after[] | — | 없음 | 아래 "없음" 참조 |
| 7-2 | `pages/main/ChangePage.tsx:304-307` | 비교한 나머지 같은 줄 수: delta steps[1].unchangedLines | — | 없음 | 아래 "없음" 참조 |
| 7-2 | `pages/main/ChangePage.tsx:325-339` | 바꾸기 전/후 통제별 결과(C1·C2): 전 = journey runs[S13].business 또는 benchmark cases[S13].runResults[runId], 후 = journey 실행 business 또는 layers outcome + deliveredItems | `ux/pages/simulate/policy/ComposeTab.tsx:504-518` | 다른 위치 | 새 쪽은 `/api/runs/{id}/versus` before/now.business · outcomes를 다섯 통제 모두 보임. 기준 실행은 서버의 referenceRunId(최근 설계대로 보낸 실행). 칸 안의 통제별 반출 건수와 "정답 없음" 표시는 없음 |
| 7-2 | `pages/main/ChangePage.tsx:326-336` (D 행) | Contexa 전/후 판단과 반출 건수: engineAction, exposedItems | `ux/pages/simulate/policy/ComposeTab.tsx:525-535` | 다른 위치 | versus before/now.engineAction · exposedItems |
| 7-2 | `pages/main/ChangePage.tsx:342-345` | Contexa 위험도 전 → 후: anatomy(실행,1).interpretation.recorded.riskScore | `ux/pages/runs/RunDetailPage.tsx:146-147` (/runs/:runId) | 다른 위치 | 실행마다 따로만 보이고, 전·후를 나란히 놓은 곳은 없음 |
| 7-2 | `pages/main/ChangePage.tsx:348-357` | 비교에 쓴 두 실행 ID: baseRunId, view.runId | `ux/pages/simulate/policy/ComposeTab.tsx:547` | 다른 위치 |  |
| 7-2 | `pages/main/ChangePage.tsx:360` | S13이 규칙 사각 묶음에 속함: benchmark.suites[RULE_BLIND].cases ∋ S13 (blindOne 문장) | `ux/pages/validation/ScenariosTab.tsx:41-44`, `:80-81`, `:105-108` (/validation?tab=scenarios) | 다른 위치 | 묶음 제목 "규칙이 미리 모르는 시나리오" 아래에 S13 줄로 보임 |
| 7-2 | `pages/main/ChangePage.tsx:155-159` → `pages/main/consoleParts.tsx:65` | C1 레인 부제의 임계값: threshold.nightStart · nightEnd · volumeLimit | `ux/pages/compare/ComparePage.tsx:137-143` (/compare?tab=rule) | 다른 위치 | change 탭에는 없음 |

### 7-3

- 옛 제목: 반복 측정에서 Contexa가 놓친 공격은 2회, 막은 정상 업무는 0회입니다
- 옛 화면: `pages/main/RunsPage.tsx` (키 `main.7-3.title` 계열)
- 새 위치: 시나리오 검증 › 통제별 = /validation?tab=summary·controls · `ux/pages/validation/ValidationPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 7-3 | `pages/main/RunsPage.tsx:93` | 제목의 수: benchmark controls[D].missed, controls[D].falseBlock.hits | `ux/pages/validation/ValidationPage.tsx:163`, `:173`, `:227-230` | 있음 | 옛 keepsBoth 제목 문장(:91)은 없음. 수는 그대로 보임 |
| 7-3 | `pages/main/RunsPage.tsx:98` | 상황 수 · 반복 수 · 실행 수: scope.cases, sentPerCase(scope.fewest/mostRunsPerCase 또는 protocols[].repeat), scope.runs | `ux/pages/validation/ValidationPage.tsx:186-193` | 있음 | 반복 수는 79번 줄의 성격 안내에도 있음 |
| 7-3 | `pages/main/RunsPage.tsx:100-106` | 정답 없는 상황 수 · 실행 수: caseCounts.UNCERTAIN, scope.otherRuns | `ux/pages/validation/ValidationPage.tsx:180`, `:190` | 있음 |  |
| 7-3 | `pages/main/RunsPage.tsx:116-117` | 공격 · 정상 실행 수: scope.attackRuns, scope.normalRuns | `ux/pages/validation/ValidationPage.tsx:160`, `:171`, `:203-204` | 있음 |  |
| 7-3 | `pages/main/RunsPage.tsx:151-154` | 통제별(C1·C2·D) 놓친 공격 · 막은 정상 업무: controls[].missed, falseBlock.hits | `ux/pages/validation/ValidationPage.tsx:227-230` (요약), `:552` (통제별) | 있음 | 새 쪽은 A·B도 함께 보임 |
| 7-3 | `pages/main/RunsPage.tsx:133-147` | 실행별 점: cases[].runResults[runId][C1\|C2\|D], THREAT / NORMAL로 나눔 | `ux/pages/compare/ComparePage.tsx:378-393` (/compare?tab=runs), `ux/pages/validation/ScenariosTab.tsx:118-126` (/validation?tab=scenarios) | 다른 위치 | 요약·통제별 탭에는 결과별 합계 막대(`ux/pages/validation/ValidationPage.tsx:215-224`)만 있음. PASSED_AFTER_CHECK 점은 옛 'partly' 색과 이름에서 새 'normal'로 합쳐짐(합계는 막대의 'checked' 칸에 남음) |
| 7-3 | `pages/main/RunsPage.tsx:170` | Contexa가 일부 반출 뒤 차단한 수: controls[D].partlyStopped | `ux/pages/validation/ValidationPage.tsx:241-243`, `:553` | 있음 |  |
| 7-3 | `pages/main/RunsPage.tsx:170` | Contexa가 추가 인증을 요구한 수: controls[D].friction.hits | `ux/pages/validation/ValidationPage.tsx:174`, `:554` | 있음 |  |
| 7-3 | `pages/main/RunsPage.tsx:180` | 측정 완료 날짜: scope.protocols[-1].finishedAt | `ux/pages/compare/ComparePage.tsx:418` | 다른 위치 | /validation에는 다른 필드인 spec.firstRunAt~lastRunAt(`ux/pages/validation/ValidationPage.tsx:75-76`)만 있음 |
| 7-3 | `pages/main/RunsPage.tsx:176` | 측정 묶음 ID: scope.protocols[-1].protocolId (배지에 마우스를 올리면 보임) | `ux/pages/compare/ComparePage.tsx:419`, `ux/pages/validation/OtherTabs.tsx:345-347` (/validation?tab=method) | 다른 위치 |  |

### 8-1

- 옛 제목: 오늘 직접 확인한 세 가지
- 옛 화면: `pages/main/SummaryPage.tsx` (키 `main.8-1.title`)
- 새 위치: 4단계 진행 표시 · 판정 이력(내 실행) = 4단계 진행 표시 · /runs · `ux/simulate/FlowFrame.tsx`, `ux/pages/runs/RunsPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 8-1 | `pages/main/SummaryPage.tsx:134-137` | 경험별 예상 적중 `journey.predictions[].engineSameStop, experience` | `ux/pages/simulate/person/ResultPage.tsx:196-201`, `ux/pages/simulate/agent/ResultPage.tsx:161-165` | 있음 | 한 화면 모음 대신 각 4단계 결과 화면에 나뉘어 보임 |
| 8-1 | `pages/main/SummaryPage.tsx:147-148` | 내부자 실행 결과·나간 문서 수 `runs[S16].business.D, exposedItems` | `ux/pages/simulate/person/ResultPage.tsx:170`, `:279`, `ux/pages/runs/RunsPage.tsx:367`, `:472` | 있음 |  |
| 8-1 | `pages/main/SummaryPage.tsx:154` | 업무 에이전트 실행 결과 `runs[agent THREAT].business.D` | `ux/pages/simulate/agent/ResultPage.tsx:142`, `ux/pages/runs/RunsPage.tsx:367` | 있음 |  |
| 8-1 | `pages/main/SummaryPage.tsx:170` (값 :84) | 공격(또는 에이전트) 요청에서 Contexa가 내준 건수 `runs[S13/agent].exposedItems` | `ux/pages/simulate/person/ResultPage.tsx:278`, `ux/pages/runs/RunsPage.tsx:472` | 있음 |  |
| 8-1 | `pages/main/SummaryPage.tsx:89→173` | 기존 보안 B가 내준 건수 `stepResult(attackRun,1).layers[B].evidence.deliveredItems` | `ux/pages/simulate/person/ResultPage.tsx:278`(business.B), `ux/pages/runs/detailTabs.tsx:215` | 있음 | detailTabs는 옛 화면과 같은 필드 |
| 8-1 | `pages/main/SummaryPage.tsx:93→components/main/SourceBadge.tsx:36` | 출처 실행 ID `runs[..].runId` | `ux/pages/simulate/person/ResultPage.tsx:216`, `ux/pages/runs/RunsPage.tsx:117` | 있음 |  |
| 8-1 | `pages/main/SummaryPage.tsx:170` (값 :98-99) | Contexa 오차단 hits/total `benchmark.controls[D].falseBlock` | `ux/pages/validation/ValidationPage.tsx:549`, `:173` | 다른 위치 | /validation(controls·summary 탭) |
| 8-1 | `pages/main/SummaryPage.tsx:103-104→173` | 고정 규칙 C1 오차단 hits/total `benchmark.controls[C1].falseBlock` | `ux/pages/validation/ValidationPage.tsx:549`, `ux/pages/compare/ComparePage.tsx:400` | 다른 위치 |  |
| 8-1 | `pages/main/SummaryPage.tsx:109→components/main/SourceBadge.tsx:42` | 측정 횟수 `benchmark.scope.runs` | `ux/pages/validation/ValidationPage.tsx:192`, `ux/pages/compare/ComparePage.tsx:351` | 다른 위치 |  |
| 8-1 | `pages/main/SummaryPage.tsx:170` (값 :116-117) | 근거 일치 hits/total `promptQuality.reasonMatch` | `ux/pages/validation/QualityTab.tsx:484`, `:490` | 다른 위치 | /validation?tab=quality |

### 8-2 · O-adopt

- 옛 제목: 우리 시스템에 도입하는 방법 · 도입하면 누구에게 무엇이 달라질까요?
- 옛 화면: `pages/main/NextPage.tsx` (키 `main.8-2.title`), `pages/AdoptPage.tsx` (키 `space.r7.adopt.change.title`)
- 새 위치: 도입 · 연동 가이드 = /adopt · `ux/pages/adopt/AdoptPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| 8-2 · O-adopt | `pages/main/OpsStrip.tsx:21` | 실측 판단 수 `benchmark.engine.decisions` (main.ops.title {{n}}) | `ux/pages/validation/ValidationPage.tsx:194` (/validation 요약), `ux/pages/validation/OtherTabs.tsx:410` (/validation?tab=method) | 다른 위치 | /adopt에는 없음 |
| 8-2 · O-adopt | `pages/main/OpsStrip.tsx:42` | 판정 분포 `benchmark.engine.actions.{ALLOW,CHALLENGE,ESCALATE,BLOCK}` | — | 없음 | /metrics(ux/pages/metrics/MetricsPage.tsx:174,326)는 출처가 다름. /api/stats `engineActions`(데모 자체 판정) |
| 8-2 · O-adopt | `pages/main/OpsStrip.tsx:63`, `pages/main/NextPage.tsx:31` | 판단 시간 `benchmark.engine.analysisP50Ms`·`analysisP95Ms` (OpsStrip 시간 칸, main.8-2.adopt.code {{p50}}) | `ux/pages/validation/QualityTab.tsx:234-238` (/validation?tab=quality), `ux/pages/validation/OtherTabs.tsx:395-397,415-419` (?tab=method) | 다른 위치 | /adopt에는 안내 링크만 있음(ux/pages/adopt/AdoptPage.tsx:214-217). /adopt 관찰 모드 탭의 중앙값(315)은 출처가 stats `decisionTime.p50Ms`로 다름 |
| 8-2 · O-adopt | `pages/main/OpsStrip.tsx:71`, `pages/main/NextPage.tsx:32` | 판단당 비용 `benchmark.engine.costPerDecisionUsd` (OpsStrip 비용 칸, adopt.code {{cost}}) | `ux/pages/validation/QualityTab.tsx:242-246`, `ux/pages/validation/OtherTabs.tsx:403-405` | 다른 위치 | /adopt 214-217이 "판정 품질 탭에 있다"고 연결함 |
| 8-2 · O-adopt | `pages/main/OpsStrip.tsx:78-79` | 판단 못 한 요청 `benchmark.engine.unresolved` / `decisions` | — | 없음 | 비슷한 `unresolvedRuns`(ux/pages/validation/OtherTabs.tsx:289 "판정 실패 n회")는 실행 단위라 다른 값 |
| 8-2 · O-adopt | `pages/main/NextPage.tsx:42` | 벤치마크 범위 `benchmark.scope.cases`·`scope.runs` (main.8-2.benchmark.line) | `ux/pages/validation/ValidationPage.tsx:186-192` (/validation 요약) | 다른 위치 |  |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:125-127` (그림 145-146) | 역할별 효과 문구(space.r7.adopt.data.what / employee.what / admin.what) | `ux/pages/adopt/AdoptPage.tsx:237,242,256` | 있음 | 연동 절차 탭 "역할별 도입 효과" 카드 |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:109-113` | 직원 경험 횟수 `benchmark.controls[D].falseBlock.total`·`falseBlock.hits`·`friction.hits` | `ux/pages/adopt/AdoptPage.tsx:245-249` | 있음 |  |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:92` | 행동 기록 보관 `settings.retention.behaviorDays` (data.kept {{behavior}}) | `ux/pages/adopt/AdoptPage.tsx:358→379` | 있음 | 보관·감사 탭 "이 데모" 열. null이면 "응답에 없음"으로 보임 |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:90,93` | 원래 기록 보관 `settings.retention.promptOriginalDays` ({{original}}) | `ux/pages/adopt/AdoptPage.tsx:384` | 있음 | 표 아래 문장 |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:102` | 봉인 보관 `settings.sealedEvidence.cleanPeriodDays` (data.seal {{days}}) | `ux/pages/adopt/AdoptPage.tsx:356→379` | 있음 | "검사 이상 없는 봉인 보관" 행 |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:103` | 표본 비율 `settings.sealedEvidence.samplePercent` ({{percent}}) | `ux/pages/adopt/AdoptPage.tsx:354→379` | 있음 | 옛 이름표는 "판단의 n% 자동 검사", 새 이름표는 "봉인 표본 요청의 n%"이고 389줄에 "봉인한 것 모두 검사"가 있음. 이름표가 바뀜 |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:174` (값 24,28,32-33) | 붙이는 코드 static:AdoptPage.STEP_CODE.attach (`ai.ctxa:spring-boot-starter-contexa:0.1.0`, `@EnableAISecurity`, `@Protectable(sync = true)`, `@PostMapping("/api/projects/{id}/exports")`) | `ux/pages/adopt/AdoptPage.tsx:174-175,195` (값 ux/pages/adopt/adopt.ts:27,30,34-35) | 있음 | 한 덩어리가 두 덩어리로 나뉨. 줄은 같음. sync 설명은 194 |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:176-177,186,225` | 외부 주소 static: QUICKSTART·REPOSITORY·LEGACY·DOCS | `ux/pages/adopt/AdoptPage.tsx:51,206-210,404-414` (ux/pages/adopt/adopt.ts:18-21) | 있음 | 이동 링크지만 주소 값도 대조함. 4개 모두 같음 |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:236` | 관찰 모드 설정 static:STEP_CODE.observe (`contexa.security.zerotrust.mode: SHADOW`) | `ux/pages/adopt/AdoptPage.tsx:195,276` (ux/pages/adopt/adopt.ts:39-42) | 있음 |  |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:253-256` | 적용 모드 값 `mode: ENFORCE` (space.r7.adopt.on.body 안 코드) | `ux/pages/adopt/AdoptPage.tsx:281-282` (ux/pages/adopt/adopt.ts:43-46) | 있음 |  |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:239-244` | 데모 판정 수 `stats.engineDecisions`, `stats.engineActions.BLOCK`·`CHALLENGE`·`ESCALATE` | `ux/pages/adopt/AdoptPage.tsx:297-308` | 있음 | engineDecisions가 없으면 decisionTime.decisions로 대신함(269) |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:217-220` | 집계 기간 `stats.runs.firstAt`·`lastAt` | `ux/pages/adopt/AdoptPage.tsx:320-326` | 있음 |  |
| 8-2 · O-adopt | `pages/AdoptPage.tsx:206-208,258` | 지금 모드 `settings.engine.effectiveMode` | `ux/pages/adopt/AdoptPage.tsx:283-286` | 있음 |  |

### M-learn

- 옛 제목: 03:17의 자료 내보내기, 이상한 일일까요?
- 옛 화면: `pages/intro/LearnWhyPage.tsx` (키 `screen.3-0.title`)
- 새 위치: AI 판정 엔진 › 행위 기준선 = /engine?tab=baseline · `ux/pages/engine/EnginePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| M-learn | pages/intro/LearnWhyPage.tsx:40 | 요청 시각 `labOptions.timeSlots[slot=A3.conditions.timeSlot].representativeTime` (제목 {{clock}}, 03:17) | ux/pages/runs/detailTabs.tsx:305 (/engine?tab=facts, /runs/:id?tab=evidence) | 다른 위치 | 기준선 탭에는 없음. 증거 탭 "행위 기준선 대비 판정" 표(287)의 accessHour 행 `received.usualVsNow[].now`로만 보임. 필드가 다르고, 기본 기준 실행이 S13(오후)이라 03:17이 아님. 대표 시각 자체는 ux/simulate/labConditions.ts:102(정책 조합 조건 문구)에만 있음 |
| M-learn | pages/intro/LearnWhyPage.tsx:63 | 시각별 학습 건수 `baseline.learned.hours` (24칸 막대) | ux/pages/engine/EnginePage.tsx:526-531 | 있음 | /engine?tab=baseline. 기본 기준 실행 S13이라 엔지니어 K의 기준선이 나옴. 옛 화면은 관리자 A(A3) |
| M-learn | pages/intro/LearnWhyPage.tsx:63 | 막대 위 요청 시각 표시("이 요청")와 평소 시각 대비 | ux/pages/runs/detailTabs.tsx:304-313 (/engine?tab=facts, /runs/:id?tab=evidence) | 다른 위치 | 기준선 탭 막대에는 요청 시각 표시가 없음. 증거 탭이 평소 값, 지금 값, 평소 안/밖 배지로 보임 |
| M-learn | pages/intro/LearnWhyPage.tsx:67-68 | 학습 요청 총수 `baseline.learned.requests` ({{n}}) | ux/pages/engine/EnginePage.tsx:516 | 있음 | 기준선 탭 부제 |
| M-learn | pages/intro/LearnWhyPage.tsx:66-68 | 요청 시각의 학습 건수 `baseline.learned.hours[hour]` ({{at}}, "0건" 문장) | ux/pages/engine/EnginePage.tsx:527, 530 | 있음 | 간접적으로만 보임: 시각별 막대의 title과 sr-only 값. 요청 시각과 잇는 문장은 없음 |

### M-learned

- 옛 제목: Contexa가 관리자 A에 대해 배운 것
- 옛 화면: `pages/intro/LearnedPage.tsx` (키 `screen.3-1.title`)
- 새 위치: 같은 탭 = /engine?tab=baseline · `ux/pages/engine/EnginePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| M-learned | pages/intro/LearnedPage.tsx:196 | 직원 이름 `person.{labOptions.employees[].key}` (없으면 `baseline.displayName`) ({{name}}) | ux/pages/engine/EnginePage.tsx:512 | 있음 | `ux.person.{baseline.employeeKey}`. 기본 S13이라 "엔지니어 K"가 나오고, 관리자 A는 ?run=<A3 실행>일 때만 나옴. 기획안의 새 제목 "(관리자 A)"와 어긋남 |
| M-learned | pages/intro/LearnedPage.tsx:216, 100 | `baseline.learned.requests` (차트 제목 {{n}}, 창의 {{learned}}) | ux/pages/engine/EnginePage.tsx:516 | 있음 |  |
| M-learned | pages/intro/LearnedPage.tsx:218 | `baseline.learned.hours` | ux/pages/engine/EnginePage.tsx:526-531 | 있음 |  |
| M-learned | pages/intro/LearnedPage.tsx:59 | 학습 기간 `baseline.taught.from` · `taught.to` | ux/pages/engine/EnginePage.tsx:518-519 | 있음 | 표기가 월/일에서 YYYY-MM-DD(UTC)로 바뀜 |
| M-learned | pages/intro/LearnedPage.tsx:64-66 | 장소 `baseline.learned.networks` | ux/pages/engine/EnginePage.tsx:554 | 있음 |  |
| M-learned | pages/intro/LearnedPage.tsx:65 | 사무실 네트워크 표시 `labOptions.employees[].officeNetwork` | — | 없음 | 네트워크 값만 보이고 "사무실 네트워크" 표시는 없음 |
| M-learned | pages/intro/LearnedPage.tsx:72-74 | 기기 `baseline.learned.devices` | ux/pages/engine/EnginePage.tsx:556 | 있음 | OS 낱말 대신 원래 코드로 보임 |
| M-learned | pages/intro/LearnedPage.tsx:79 (51-53) | 한 일 종류 `baseline.taught.reads/downloads/exports` (>0) | ux/pages/engine/EnginePage.tsx:559-563 | 있음 | 종류 대신 건수로 보임 |
| M-learned | pages/intro/LearnedPage.tsx:79 (54) | 프로젝트 `baseline.taught.projects` (키 목록) | — | 없음 |  |
| M-learned | pages/intro/LearnedPage.tsx:98 | 보낸 학습 요청 수 `baseline.sent` | ux/pages/engine/EnginePage.tsx:517 | 있음 |  |
| M-learned | pages/intro/LearnedPage.tsx:99 | 통과 수 `baseline.allowed` | — | 없음 | 새 문구 "보낸 {{sent}}건 중 허용된 것"에는 learned 수만 들어감 |
| M-learned | pages/intro/LearnedPage.tsx:114 | `baseline.hours.personalBaselineStatus` | — | 없음 | 후보는 있으나 확인 안 함 (아래 참고) |
| M-learned | pages/intro/LearnedPage.tsx:119-121 | `baseline.hours.roleScopeState` (+PROVISIONAL 안내) | — | 없음 | 후보는 있으나 확인 안 함 (아래 참고) |
| M-learned | pages/intro/LearnedPage.tsx:127 | `baseline.hours.normalAccessHours` | — | 없음 | 후보는 있으나 확인 안 함 (아래 참고) |
| M-learned | pages/intro/LearnedPage.tsx:131 | `baseline.hours.observedHours` | ux/pages/runs/detailTabs.tsx:304 (/engine?tab=facts) | 다른 위치 | accessHour 평소 값은 포털 BeforeSend.java가 ObservedHours 줄(v20이면 UsualHours)에서 만듦. 기준 실행의 값이고, 템플릿 최근 판정의 값은 아님 |
| M-learned | pages/intro/LearnedPage.tsx:150-162 | 학습 요청 표 `baseline.requests[]` (no, companyTime, path, items, finalAction, identityCheckPassed) | — | 없음 |  |

### M-how

- 옛 제목: Contexa는 요청마다 이렇게 판단합니다
- 옛 화면: `pages/intro/HowPage.tsx` (키 `screen.3-2.title`)
- 새 위치: AI 판정 엔진 › 판정 흐름 = /engine?tab=flow · `ux/pages/engine/EnginePage.tsx`
- 참고: 옛 화면(HowPage.tsx)은 포털 훅이 없고 고정 안내 문구와 이동 버튼뿐이라 사실이 없습니다(D1 묶음 보고).

### M-stack

- 옛 제목: 같은 조회를 다섯 번 보내면?
- 옛 화면: `pages/try/StackPage.tsx` (키 `screen.3-3.title`)
- 새 위치: 요청 급증 대응 = /simulate/surge?tab=repeat · `ux/pages/simulate/surge/SurgePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| M-stack | pages/try/StackPage.tsx:95 | 요청 칸 수 labOptions cases[A6T·A6].requests.length | ux/pages/simulate/surge/SurgePage.tsx:537 (ux/pages/simulate/surge/SurgePage.tsx:437-438) | 있음 |  |
| M-stack | pages/try/StackPage.tsx:96-100 | 정상 업무 칸의 요청별 판정 anatomy.interpretation.recorded.finalAction | ux/pages/simulate/surge/SurgePage.tsx:540 (ux/pages/simulate/surge/SurgePage.tsx:508-511) | 있음 |  |
| M-stack | pages/try/StackPage.tsx:101-102 | 앞선 판정으로 막힘 stepResult.layers[D].evidence.timing=PRIOR_DECISION | ux/pages/simulate/surge/SurgePage.tsx:544 (ux/pages/simulate/surge/SurgePage.tsx:513-514) | 있음 |  |
| M-stack | pages/try/StackPage.tsx:102 (pages/try/StackPage.tsx:45-46) | 판정이 없을 때 D 결과(DELIVERED·STOPPED·HELD·CUT·BROKEN·UNRESOLVED) stepResult.layers[D].outcome | ux/pages/runs/detailTabs.tsx:208 (/runs/:runId?tab=controls&step=n, 링크 ux/pages/simulate/surge/SurgePage.tsx:528) | 다른 위치 | 칸에는 '판정 없음'(ux/pages/simulate/surge/SurgePage.tsx:515)만. 정상·공격 두 줄 모두 해당 |
| M-stack | pages/try/StackPage.tsx:102 (pages/try/StackPage.tsx:63) | 실시간 칸 live.steps[].layers.D.outcome | ux/pages/simulate/surge/SurgePage.tsx:540, ux/pages/simulate/surge/SurgePage.tsx:544 (ux/pages/simulate/surge/SurgePage.tsx:503-506) | 있음 | 결과 낱말 대신 판정 배지로 보이고, HELD 등은 '답을 기다리는 중' |
| M-stack | pages/try/StackPage.tsx:96-102 (pages/try/StackPage.tsx:179-182) | 공격 칸(측정 middleRun)의 판정·앞선 판정 | ux/pages/simulate/surge/SurgePage.tsx:465→ux/pages/simulate/surge/SurgePage.tsx:540,544 | 있음 |  |
| M-stack | pages/try/StackPage.tsx:111 (pages/try/StackPage.tsx:267,189) | 학습한 요청 수 figures.baselineBefore→baselineAfter (정상·공격) | ux/pages/simulate/surge/SurgePage.tsx:549-556 | 있음 |  |
| M-stack | pages/try/StackPage.tsx:276 (pages/try/StackPage.tsx:194-196) | 시작 학습 상태 n (리셋 줄) figures.baselineBefore | ux/pages/simulate/surge/SurgePage.tsx:551-553(from) | 있음 | 숫자만 있음. "매번 같은 학습 상태에서 시작하고 끝나면 지운다"는 문장은 없음 |
| M-stack | pages/try/StackPage.tsx:211-219,273 | 기록 출처(이번 내 실행 / 전에 보낸 기록) | ux/pages/simulate/surge/SurgePage.tsx:527 | 있음 |  |
| M-stack | pages/try/StackPage.tsx:256-262→components/StateScreen.tsx:101,105 | 대기 순번·남은 대기 시간 queuePosition·queueWaitSeconds | — | 없음 | grep하면 agent·person LivePage에만 있음 |
| M-stack | pages/try/StackPage.tsx:246 (guide pages/try/StackPage.tsx:205) | 실행 실패·만료 (live.status FAILED·EXPIRED) | — | 없음 | RepeatTab에 실패 안내가 없음 |
| M-stack | pages/try/StackPage.tsx:246,263 | 진행 중 상태(QUEUED·STARTING·RUNNING…) | ux/pages/simulate/surge/SurgePage.tsx:449-450, ux/pages/simulate/surge/SurgePage.tsx:505 | 있음 | 버튼 비활성 사유와 대기 칸으로 보임 |
| M-stack | pages/try/StackPage.tsx:281-289 | 전송 거절(일일 한도·일시 중지·장애) | ux/pages/simulate/surge/SurgePage.tsx:480 | 있음 |  |

### M-learnafter

- 옛 제목: 무엇을 배우고, 무엇은 배우지 않을까요?
- 옛 화면: `pages/try/LearnAfterPage.tsx` (키 `screen.3-4.title`)
- 새 위치: AI 판정 엔진 › 행위 기준선 = /engine (기준선) · `ux/pages/engine/EnginePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| M-learnafter | pages/try/LearnAfterPage.tsx:140 (122) | 허용 줄: A6T 실행의 `figures.baselineBefore→After` | ux/pages/engine/EnginePage.tsx:321 (340-345 "비교 · 정상 업무 측정 실행") | 있음 | 실제로는 flow 탭에 있음. 측정 middleRun만 쓰고 방문자 본인의 A6T 실행은 안 씀 |
| M-learnafter | pages/try/LearnAfterPage.tsx:140 | 추가 인증 통과 줄: A3T 실행(본인 실행 또는 `measured.resumed`)의 `figures` | ux/simulate/CompareView.tsx:217-218 (/simulate/person/S13/result?tab=compare), ux/pages/runs/detailTabs.tsx:624 (/runs/:id?tab=learning) | 다른 위치 | 엔진 화면에는 없음. `measured.resumed`를 쓰는 곳은 0곳. S13T 실행이 인증 통과 실행이라는 보장은 없음 |
| M-learnafter | pages/try/LearnAfterPage.tsx:140 | 막힌 요청 줄: A3 실행의 `figures` | ux/pages/engine/EnginePage.tsx:321 (339 "이 실행"), ux/pages/engine/EnginePage.tsx:582-583 (기준선 탭) | 있음 | A3 대신 기준 실행 S13 |

### M-timing

- 옛 제목: 응답 전에 막을까, 다음 요청부터 막을까?
- 옛 화면: `pages/try/TimingPage.tsx`, `pages/try/timing/*Screen.tsx` (키 `screen.4-0.title`)
- 새 위치: AI 판정 엔진 › 판정 흐름 = /engine?tab=flow · `ux/pages/engine/EnginePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| M-timing | pages/try/timing/ConceptScreen.tsx:80-86 | 응답 전 차단 줄 `measured(A3).list[middleRun]`의 analysisMs, responseMs, exposedItems | ux/pages/engine/EnginePage.tsx:421-423 (sync 줄) | 있음 | /engine?tab=flow. 중앙값 1건의 값이 측정 범위(min~max)와 측정 횟수로 바뀜 |
| M-timing | pages/try/timing/ConceptScreen.tsx:97-101 | 다음 요청부터 차단 줄 `measured(A3A).list[middleRun]`의 responseMs, exposedItems, analysisMs | ux/pages/engine/EnginePage.tsx:421-423 (async 줄) | 있음 | 25와 같음 |
| M-timing | pages/try/timing/ResendScreen.tsx:103 | 각 실행의 반출 건수 `stepResult.layers[D].evidence.deliveredItems` | ux/pages/runs/detailTabs.tsx:106, 215 (/runs/:id?tab=summary·controls) | 다른 위치 | 엔진 카드에는 측정 범위만 있음 (ux/pages/engine/EnginePage.tsx:423) |
| M-timing | pages/try/timing/ResendScreen.tsx:107 | 응답 시간 `layers[D].evidence.responseMs` | ux/pages/runs/detailTabs.tsx:217-218 | 다른 위치 | 엔진 카드에는 범위만 있음 (ux/pages/engine/EnginePage.tsx:421) |
| M-timing | pages/try/timing/ResendScreen.tsx:112 | 판정 `layers[D].verdict` (+unresolved) | ux/pages/runs/detailTabs.tsx:91, ux/pages/runs/RunDetailPage.tsx:112 | 다른 위치 | 적용 시점 카드에는 판정이 없음 |
| M-timing | pages/try/timing/ResendScreen.tsx:116 | 판단 시간 `anatomy.interpretation.timings.totalAnalysisMs` | ux/pages/runs/detailTabs.tsx:99-100, ux/pages/runs/RunDetailPage.tsx:152-153 | 다른 위치 | 엔진 카드에는 범위만 있음 (ux/pages/engine/EnginePage.tsx:422) |
| M-timing | pages/try/timing/ResendScreen.tsx:117 | 적용 시점 `layers[D].evidence.timing` | ux/pages/runs/detailTabs.tsx:98 (`recorded.applied`) | 다른 위치 | 카드의 줄 이름은 고정 문구. ux/pages/engine/EnginePage.tsx:243-245는 S13 기준 실행만 보임 |
| M-timing | pages/try/timing/ResendScreen.tsx:123 | 다음 요청 결과 (step 2 `layers[D].outcome`) | ux/pages/runs/detailTabs.tsx:204-208, 215 (/runs/<A3A>?tab=controls&step=2) | 다른 위치 |  |
| M-timing | pages/try/timing/CompareScreen.tsx:84 (128) | 결과 낱말 `measured(A3·A3A·A3T·A3TA).results/allSame` (+제목 선택) | — | 없음 | 실행 한 건의 결과는 ux/pages/runs/RunDetailPage.tsx:103 EvalBadge로만 보임 |
| M-timing | pages/try/timing/CompareScreen.tsx:76, pages/try/timing/WhenScreen.tsx:85 | 공격 반출 범위 `measured(A3·A3A).exposedItems` | ux/pages/engine/EnginePage.tsx:423 | 있음 | 같은 필드 |
| M-timing | pages/try/timing/CompareScreen.tsx:79, pages/try/timing/WhenScreen.tsx:83 | 정상 업무 응답 범위 `measured(A3T).responseMs` (동기 방식의 대가), `measured(A3TA).responseMs` | — | 없음 | 적용 시점 카드는 A3, A3A만 보임 |

### M-follow

- 옛 제목: 판단마다 다음에 무슨 일이 생길까요?
- 옛 화면: `pages/try/FollowPage.tsx` (키 `screen.2-6.title`)
- 새 위치: AI 판정 엔진 › 판정 흐름 = /engine?tab=flow · `ux/pages/engine/EnginePage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| M-follow | pages/try/FollowPage.tsx:88, 91 | 유지 시간 `engineActions[ALLOW·CHALLENGE·ESCALATE·BLOCK].ttlSeconds` | ux/pages/engine/EnginePage.tsx:469-471 | 있음 | /engine?tab=flow |
| M-follow | pages/try/FollowPage.tsx:97, 100 | 판정 수 `stats.engineActions[v]` | ux/pages/engine/EnginePage.tsx:478 | 있음 | 합계가 0보다 클 때만 보임 |
| M-follow | pages/try/FollowPage.tsx:98 | 보류 시간 뒤 차단 수 `stats.blockedAfterReview` | ux/pages/metrics/MetricsPage.tsx:356 (/metrics) | 다른 위치 |  |
| M-follow | pages/try/ReleaseRecord.tsx:52-55, 77-79 | 시연용 강제 차단 `latestRelease.forcedAction` | — | 없음 |  |
| M-follow | pages/try/ReleaseRecord.tsx:65, 71 | 해제 단계 시각 `release.blocked_at·code_requested_at·verified_at·requested_at·approved_at·reissue_sent_at` (+날짜) | — | 없음 | Recovery.tsx에는 단계 표시만 있고 시각은 없음 |
| M-follow | pages/try/ReleaseRecord.tsx:82/87, 93, 97 | `release.block_record.reasoning·mfaVerified·unblockReason` | ux/simulate/Recovery.tsx:304, 307, 309 (/simulate/person/:key/live) | 다른 위치 | 방문자 본인이 실시간으로 해제할 때만 보임(LiveRelease.block). 저장된 최근 해제 기록이 아님 |
| M-follow | pages/try/ReleaseRecord.tsx:107-111 | 다시 보낸 요청 `release.reissue_status·reissue_delivered` | ux/simulate/Recovery.tsx:327-331 | 다른 위치 | 41과 같음 (reissueStatus, reissueDeliveredItems) |
| M-follow | pages/try/ReleaseRecord.tsx:120-123 | 학습 수 `learning.template/atRunEnd.baselineUpdateCount` | ux/pages/runs/detailTabs.tsx:624 (/runs/:id?tab=learning) | 다른 위치 | figures.baselineBefore/After로 보임. 최근 해제 실행으로 가는 링크는 ux에 없음 |
| M-follow | pages/try/ReleaseRecord.tsx:135 | 학습 기록 `learning.newBehaviourDocuments[].content` 첫 줄 | ux/pages/runs/detailTabs.tsx:642-643 | 다른 위치 | 원문 첫 줄이 아니라 action, requestPath, timestamp만 보임. 43과 같은 링크 문제 |
| M-follow | pages/try/ReleaseRecord.tsx:144 (components/main/SourceBadge.tsx:36) | 해제 실행 배지 `latestRelease.runId` | — | 없음 |  |

### M-approaches

- 옛 제목: 다섯 보안 방식은 무엇을 보고, 무엇을 못 볼까요?
- 옛 화면: `pages/intro/ApproachesPage.tsx` (키 `screen.5-0.title`)
- 새 위치: 탐지 방식 비교 = /compare · `ux/pages/compare/ComparePage.tsx` (제목은 ReviewPage에서도 보임)

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| M-approaches | `components/inside/ApproachSettings.tsx:56-57` (ApproachesPage:108) | A 설정: `/api/settings` waf.image, waf.ruleSet | `ux/pages/validation/ValidationPage.tsx:772-773` (그리는 줄 851-856, /validation?tab=controls 통제 상세) | 다른 위치 | /compare와 ReviewPage에는 없음 |
| M-approaches | `components/inside/ApproachSettings.tsx:63-73` | B 설정: permission.roleRules (개수와 목록) | `ux/pages/validation/ValidationPage.tsx:778-784` | 다른 위치 |  |
| M-approaches | `components/inside/ApproachSettings.tsx:80-92` | C1 설정: threshold.nightStart · nightEnd · volumeLimit · dormantWindowDays | `ux/pages/compare/ComparePage.tsx:137-143` | 있음 | `ux/pages/validation/ValidationPage.tsx:790-797`에도 있음 |
| M-approaches | `components/inside/ApproachSettings.tsx:98-105` | C2 설정: businessRecord.exportPolicyKey · assignedExportLimit · ticketAndOncallExempt · historyWindowDays · exportHistoryWindowDays | `ux/pages/validation/ValidationPage.tsx:801-808` | 다른 위치 |  |
| M-approaches | `components/inside/ApproachSettings.tsx:107-120` | C2 접근 정책: businessRecord.accessPolicies[].policyKey · accountManagerExempt · assignedExempt · recentWorkDays | `ux/pages/validation/ValidationPage.tsx:810-822` | 다른 위치 |  |
| M-approaches | `components/inside/ApproachSettings.tsx:128-135` | D 모델: engine.layer1Model · layer2Model (없으면 chatModel) | `ux/pages/validation/ValidationPage.tsx:826-834` | 다른 위치 |  |
| M-approaches | `components/inside/ApproachSettings.tsx:136-145` | D 모드: engine.effectiveMode | `ux/pages/validation/ValidationPage.tsx:835-842` | 다른 위치 |  |
| M-approaches | `components/inside/ApproachSettings.tsx:146-149` | D 응답 검사 조건 수: engine.inspectorConditions | `ux/pages/validation/ValidationPage.tsx:843-846` | 다른 위치 |  |

### L-entrance

- 옛 제목: 조건 하나를 바꾸면 판단이 달라질까요?
- 옛 화면: `pages/lab/LabEntrancePage.tsx` (키 `lab.r7.entrance.title`)
- 새 위치: 정책 시뮬레이터 › 조건 구성 · 실행 = /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| L-entrance | pages/lab/LabEntrancePage.tsx:71 | LiveConfig.remainingToday | ux/pages/simulate/policy/ComposeTab.tsx:365 | 있음 | dailyRuns와 함께 표시 |
| L-entrance | pages/lab/LabEntrancePage.tsx:61 | static:labPlace.ts.LAB_WALK(WALK_STEPS) 단계 목록 | ux/pages/simulate/policy/ComposeTab.tsx:100,135,221,331,390,477 | 있음 | 고정 안내에 가까움. 새 화면은 카드 번호 1~6(실행 진행 카드 추가) |

### L-case

- 옛 제목: 어떤 상황으로 해 볼까요?
- 옛 화면: `pages/lab/LabCasePage.tsx` (키 `lab.r7.case.title`)
- 새 위치: 1단계 = /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| L-case | pages/lab/LabCasePage.tsx:116 | LabOptions.cases[].key, .title(시나리오 목록) | ux/pages/simulate/policy/ComposeTab.tsx:120 | 있음 | 옛 화면은 쉬운 이름(lab.r7.case.name.*), 새 화면은 key · 서버 title |
| L-case | pages/lab/LabCasePage.tsx:113,140 | LabCase.classification THREAT/NORMAL(목록 묶음, "미리 정한 처리") | ux/pages/simulate/policy/ComposeTab.tsx:115 | 있음 | 드롭다운 묶음 이름으로만 보임. 고른 뒤 보이는 카드는 없음 |
| L-case | pages/lab/LabCasePage.tsx:113,140 | LabCase.classification이 THREAT·NORMAL이 아닌 경우(UNCERTAIN, "미리 정하지 않은 상황") | ux/pages/validation/ScenariosTab.tsx:188 (/validation?tab=scenarios&case=) | 다른 위치 | ux/pages/simulate/policy/ComposeTab.tsx:117은 THREAT가 아닌 것을 모두 "정답이 정상 업무" 묶음에 넣음. S07·S08 같은 UNCERTAIN이 잘못 표시됨 |
| L-case | pages/lab/LabCasePage.tsx:129 | 고른 시나리오 이름(LabCase.key/title) | ux/pages/simulate/policy/ComposeTab.tsx:120 | 있음 | 고른 항목으로 보임 |
| L-case | pages/lab/LabCasePage.tsx:25 | LabOptions.employees[key=conditions.employee].displayName, .role | - | 없음 | 이름은 ux/pages/simulate/person/ReviewPage.tsx:112에서 S13·S13T·S16만 보임. 역할은 어디에도 없음 |
| L-case | pages/lab/LabCasePage.tsx:48-51(145) | BenchmarkCase.cells.D.right / .counted | ux/pages/validation/ScenariosTab.tsx:228 | 다른 위치 | 검증 › 시나리오 상세 창 |

### L-change

- 옛 제목: 무엇을 바꿔 볼까요?
- 옛 화면: `pages/lab/LabChangePage.tsx` (키 `lab.r7.change.title`)
- 새 위치: 2단계 = /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| L-change | pages/lab/LabChangePage.tsx:84 | 원래 상황 이름(LabCase.key/title) | ux/pages/simulate/policy/ComposeTab.tsx:120 | 있음 |  |
| L-change | pages/lab/LabChangePage.tsx:92 | employees[].displayName · role | - | 없음 | G-07과 같음 |
| L-change | pages/lab/LabChangePage.tsx:104 | LabCase.conditions.timeSlot/place/device/items/approval 원래 값(+timeSlots[].representativeTime) | ux/pages/simulate/policy/ComposeTab.tsx:153 | 있음 | "조건 · 원래 값" 드롭다운 항목 안 |
| L-change | pages/lab/LabChangePage.tsx:104 | 요청이 여러 개인 시나리오의 conditions.items 원래 값 | - | 없음 | 새 화면은 바꿀 수 있는 조건만 나열(STEPS_FIXED라 items 빠짐) |
| L-change | pages/lab/LabChangePage.tsx:121 | 바꿀 수 있는 조건 목록(static:labPlace.ts.ONE_CHANGE ∩ changeable) | ux/pages/simulate/policy/ComposeTab.tsx:153 | 있음 |  |
| L-change | pages/lab/LabChangePage.tsx:147-149 | 새 값 선택지(LabOptions.timeSlots/items, static place/device/approval) | ux/pages/simulate/policy/ComposeTab.tsx:172 | 있음 | 원래 값은 선택지에서 빠지고 G-11에 표시 |
| L-change | pages/lab/LabChangePage.tsx:159 | LabCase.requests.length(요청 n개, n/total의 total) | - | 없음 | ux/pages/simulate/policy/ComposeTab.tsx:139는 "여러 개"라는 사실만, 개수 n 없음 |

### L-before

- 옛 제목: 보내기 전에 무엇이 달라졌을까요?
- 옛 화면: `pages/lab/LabBeforePage.tsx` (키 `lab.r7.before.title`)
- 새 위치: 3단계 = /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| L-before | pages/lab/LabBeforePage.tsx:147-151 | 바꾼 조건 이름·전→후(LabCase.conditions[key], 바꾼 값) | ux/pages/simulate/policy/ComposeTab.tsx:226-230 | 있음 |  |
| L-before | pages/lab/LabBeforePage.tsx:37 | BeforeSendView.departureCount(설계대로/바꾼 뒤) | ux/pages/simulate/policy/ComposeTab.tsx:211(→260) | 있음 |  |
| L-before | pages/lab/LabBeforePage.tsx:39 | BeforeSendView.companyAdverseCount | ux/pages/simulate/policy/ComposeTab.tsx:212(→260) | 있음 |  |
| L-before | pages/lab/LabBeforePage.tsx:43 | 최소 대응 규칙 해당 여부(minimumRules.applies / boundary.applies / modelJudges) | ux/pages/simulate/policy/ComposeTab.tsx:213(→260) | 있음 |  |
| L-before | pages/lab/LabBeforePage.tsx:21,43 | 충족된 규칙 이름(minimumRules.rules[].code, met=true) | - | 없음 | 새 화면은 "해당"만 보이고 어느 규칙인지는 없음 |
| L-before | pages/lab/LabBeforePage.tsx:189 | 두 기록의 판정 기준 버전 차이(modelJudges 다름) | ux/pages/simulate/policy/ComposeTab.tsx:271 | 있음 |  |
| L-before | pages/lab/LabBeforePage.tsx:191 | 비교 기록 없음(comparison=null) | ux/pages/simulate/policy/ComposeTab.tsx:237,270 | 있음 |  |
| L-before | pages/lab/LabBeforePage.tsx:192 | 미리 정한 처리(classification, 바꾼 경우 정답 없음) | ux/pages/simulate/policy/ComposeTab.tsx:115,457-462 | 있음 | "바꾼 상황엔 정답 없음" 문장은 없음. 결과 칸이 채점 대신 답 배지로 보이는 것으로만 드러남 |

### L-send

- 옛 제목: 이 요청은 공격일까요, 정상 업무일까요?
- 옛 화면: `pages/lab/LabSendPage.tsx` (키 `lab.r7.send.title`)
- 새 위치: 4단계 = /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| L-send | pages/lab/LabSendPage.tsx:152-154 | 보낼 요청(시나리오 + 바꾼 조건) | ux/pages/simulate/policy/ComposeTab.tsx:120,226-230 | 있음 | 같은 탭 안 1·3단계 |
| L-send | pages/lab/LabSendPage.tsx:169 | 예상 선택지(static:LabSendPage.CALLS ATTACK/NORMAL/UNSURE) | ux/pages/simulate/policy/ComposeTab.tsx:347 | 있음 | 힌트 문구(고정)는 빠짐 |
| L-send | pages/lab/LabSendPage.tsx:177-181 | 전송 거절 종류(useLiveSend refusal) | ux/pages/simulate/policy/ComposeTab.tsx:369-376 | 있음 |  |
| L-send | pages/lab/LabSendPage.tsx:255-259 | LiveRunView.queuePosition, .queueWaitSeconds | - | 없음 | ux/pages/simulate/person/LivePage.tsx:226은 사람 흐름 실행에만 해당 |
| L-send | pages/lab/LabSendPage.tsx:271-287 | steps[].layers[통제].outcome(통제별 답) | ux/pages/simulate/policy/ComposeTab.tsx:414 | 있음 | 판정 배지로 표시 |
| L-send | pages/lab/LabSendPage.tsx:271-287 (pages/try/steps/LiveRunBar.tsx:119-161) | layers[].elapsedMs(초), layers[].deliveredItems, steps[].streams.delivered/total | - | 없음 | Contexa를 지난 반출 합계만 6단계 exposedItems로 보임 |
| L-send | pages/lab/LabSendPage.tsx:279 | Contexa 판정(useLiveAnalysis decision.finalAction) | ux/pages/simulate/policy/ComposeTab.tsx:531 | 있음 | 실행이 끝난 뒤에만 보임(Versus now.engineAction) |
| L-send | pages/lab/LabSendPage.tsx:284 | decisionWait.remainingSeconds | - | 없음 |  |
| L-send | pages/lab/LabSendPage.tsx:267 | 요청 번호 n(steps[].stepNo) | ux/pages/simulate/policy/ComposeTab.tsx:411 | 있음 | total은 G-15 |
| L-send | pages/lab/LabSendPage.tsx:311 | 진행 중인 신원 확인(challenge.stage/secondsLeft/code/attempts) | ux/pages/simulate/policy/ComposeTab.tsx:424 (ux/simulate/Recovery.tsx:74,88-92) | 있음 |  |
| L-send | pages/lab/LabSendPage.tsx:304-308 | 끝난 확인 결과 challenge.stage = NO_MAILBOX·ABANDONED | - | 없음 | ux/simulate/Recovery.tsx:51이 null을 돌려줌. DONE·CANCELLED·EXPIRED·FAILED는 보임 |

### L-result

- 옛 제목: 아직 결과가 없습니다
- 옛 화면: `pages/lab/LabResultPage.tsx` (키 `p1.result.empty`)
- 새 위치: 5단계 = /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| L-result | pages/lab/LabResultPage.tsx:176-181(→190) | Versus.before/now.engineAction(Contexa 판단 전→후, contexaChanged) | ux/pages/simulate/policy/ComposeTab.tsx:525-531 | 있음 |  |
| L-result | pages/lab/LabResultPage.tsx:176 (38-44) | Versus.changedConditions(바뀐 조건 이름·개수) | - | 없음 | 주소에 담긴 바꾼 조건만 3단계 부제(ux/pages/simulate/policy/ComposeTab.tsx:226)에 보임 |
| L-result | pages/lab/LabResultPage.tsx:218 | RecentLabRun.call | ux/pages/compare/ComparePage.tsx:301 (/compare?tab=change) | 다른 위치 | 정책 탭은 고른 라디오 상태만 남고, 새로고침하면 사라짐 |
| L-result | pages/lab/LabResultPage.tsx:222 | RecentLabRun.callRight | - | 없음 |  |
| L-result | pages/lab/LabResultPage.tsx:228 | 미리 정한 처리(RecentLabRun.designed + classification) | ux/pages/simulate/policy/ComposeTab.tsx:115,459 | 있음 | 묶음 이름과 채점 배지로 보임 |
| L-result | pages/lab/LabResultPage.tsx:247,249 | VersusSide.business[통제] / outcomes[통제](양쪽) | ux/pages/simulate/policy/ComposeTab.tsx:510,513 | 있음 |  |
| L-result | pages/lab/LabResultPage.tsx:251 | Versus.changedControls | ux/pages/simulate/policy/ComposeTab.tsx:514 | 있음 |  |
| L-result | pages/lab/LabResultPage.tsx:260 | VersusSide.exposedItems | ux/pages/simulate/policy/ComposeTab.tsx:532-535 | 있음 | 이전 값도 함께 보임 |
| L-result | pages/lab/LabResultPage.tsx:236,247 | 내 직전 실행과의 비교(against=직전 lab 실행) | ux/pages/compare/ComparePage.tsx:303 → /runs/:id | 다른 위치 | 새 6단계는 항상 referenceRunId(설계대로)와 비교(ux/pages/simulate/policy/ComposeTab.tsx:470) |
| L-result | pages/lab/LabResultPage.tsx:262 | LabDelta(available/reason/steps[].passed·notCompared·notLookedUp·sameAsBase) | - | 없음 |  |
| L-result | pages/lab/LabResultPage.tsx:264 (components/assessment/AssessPanel.tsx:102-115,150-170) | 평가 창: LabOptions.assessmentReasons, 판정된 단계, PeerAssessments(assessments/assessors/verdicts/reasons/delayHours) | - | 없음 | ux/pages/validation/OtherTabs.tsx:459-461은 전체 합계만 |

### L-rules

- 옛 제목: 규칙을 조이면 무엇이 막히고, 풀면 무엇이 지나갈까요?
- 옛 화면: `pages/lab/LabRulesPage.tsx` (키 `lab.r7.rules.title`)
- 새 위치: 정책 시뮬레이터 › 임계값 조정 = /simulate/policy?tab=threshold · `ux/pages/simulate/policy/PolicyPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| L-rules | pages/lab/LabRulesPage.tsx:184 | 통제 C1/C2(static:LabRulesPage.KNOBS) | ux/pages/simulate/policy/PolicyPage.tsx:179 | 있음 |  |
| L-rules | pages/lab/LabRulesPage.tsx:200 | 통제별 설정 목록(static KNOBS) | ux/pages/simulate/policy/PolicyPage.tsx:190 | 있음 |  |
| L-rules | pages/lab/LabRulesPage.tsx:207,233 | 기본값 RuleDefaults.settings[knob] / assignedLimit | ux/pages/simulate/policy/PolicyPage.tsx:204,232,238,339 | 있음 | 켜고 끄는 설정은 비고 칸의 "기본값과 같음"으로 보임 |
| L-rules | pages/lab/LabRulesPage.tsx:214,225 | 고른 값(RuleSettings[knob]) | ux/pages/simulate/policy/PolicyPage.tsx:212,226-228,234,251 | 있음 |  |
| L-rules | pages/lab/LabRulesPage.tsx:247-248 | RuleTally.attacks / normals(분모) | ux/pages/simulate/policy/PolicyPage.tsx:383,399 (+295-296) | 있음 | 범위 문장은 cases 분류로 센 수 |
| L-rules | pages/lab/LabRulesPage.tsx:84-85(269) | tallies[통제].attacksStopped/attacks, normalsBlocked/normals | ux/pages/simulate/policy/PolicyPage.tsx:383,399 | 있음 | 새 화면은 C1·C2 둘 다 표시 |
| L-rules | pages/lab/LabRulesPage.tsx:273 | tallies.D(Contexa 기록) | ux/pages/simulate/policy/PolicyPage.tsx:383,399 | 있음 |  |
| L-rules | pages/lab/LabRulesPage.tsx:265 | 기본값/바꾼 값 여부(행 이름) | ux/pages/simulate/policy/PolicyPage.tsx:339-340 | 있음 |  |
| L-rules | pages/lab/LabRulesPage.tsx:280 | tallies.D.normalsChecked | ux/pages/simulate/policy/PolicyPage.tsx:335 | 있음 |  |
| L-rules | pages/lab/LabRulesPage.tsx:284 | RuleTally.undecided | ux/pages/simulate/policy/PolicyPage.tsx:408 | 있음 |  |
| L-rules | pages/lab/LabRulesPage.tsx:296 | RuleChange.scenario → RuleCase.title | ux/pages/simulate/policy/PolicyPage.tsx:279-280 | 있음 | key도 함께 보임 |
| L-rules | pages/lab/LabRulesPage.tsx:298 | RuleChange.now | ux/pages/simulate/policy/PolicyPage.tsx:283 | 있음 | null(알 수 없음)도 "이제 허용"으로 보임 |
| L-rules | pages/lab/LabRulesPage.tsx:298 | RuleChange.before | - | 없음 | 참/거짓이면 now의 반대로 추론할 수는 있음 |
| L-rules | pages/lab/LabRulesPage.tsx:311 | 바뀐 상황 수(changed.length) | ux/pages/simulate/policy/PolicyPage.tsx:270 | 있음 |  |
| L-rules | pages/lab/LabRulesPage.tsx:287 | 바뀐 상황 0개(changed 비어 있음) | - | 없음 | ux/pages/simulate/policy/PolicyPage.tsx:266은 1개 이상일 때만 그림 |
| L-rules | pages/lab/LabRulesPage.tsx:153-155 | RuleCasesView.cases.length, recordedFrom, recordedTo | ux/pages/simulate/policy/PolicyPage.tsx:294-298 | 있음 | 시각이 날짜만 남음(slice 0,10) |

### L-agent

- 옛 제목: 에이전트의 요청도 같은 토큰으로 옵니다. 맡긴 일 밖이면 어떻게 될까요?
- 옛 화면: `pages/lab/LabAgentPage.tsx` (키 `labAgent.title`)
- 새 위치: 정책 시뮬레이터 › 에이전트 정책 = /simulate/policy?tab=agent · `ux/pages/simulate/policy/AgentPolicyTab.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| L-agent | pages/lab/LabAgentPage.tsx:56 | 요청 경로 세 가지(static:LabAgentPage.PATHS) | ux/pages/simulate/policy/AgentPolicyTab.tsx:114 | 있음 | 설명 문장 대신 짧은 이름 |
| L-agent | pages/lab/LabAgentPage.tsx:97 | LiveConfig.agentCases[].title | ux/pages/simulate/agent/PickPage.tsx:95 (/simulate/agent) | 다른 위치 |  |
| L-agent | pages/lab/LabAgentPage.tsx:96 | AgentCaseView.sender(사례별 주체 칩) | - | 없음 |  |
| L-agent | pages/lab/LabAgentPage.tsx:99 | 사례별 AgentCaseView.delegation.summary | ux/pages/simulate/agent/ReviewPage.tsx:156 → ux/simulate/AgentParts.tsx:100 | 다른 위치 |  |
| L-agent | pages/lab/LabAgentPage.tsx:101-107 | AgentCaseView.recorded 있음/없음 | ux/pages/simulate/agent/ReviewPage.tsx:230-233, ux/pages/simulate/agent/LivePage.tsx:119-123 | 다른 위치 | 거절되거나 실패했을 때만 링크로 보임 |
| L-agent | pages/lab/LabAgentPage.tsx:74-75 | LiveConfig.remainingAgentToday, dailyAgentRuns | ux/pages/simulate/agent/ReviewPage.tsx:220 | 다른 위치 |  |
| L-agent | pages/lab/LabAgentPage.tsx:76 | LiveConfig.agentRunPoints | - | 없음 |  |
| L-agent | pages/lab/AgentMenuPanel.tsx:61(96) | AgentMenuListing.cases[].title | ux/pages/simulate/policy/AgentPolicyTab.tsx:162 | 있음 |  |
| L-agent | pages/lab/AgentMenuPanel.tsx:80 | AgentMenuListing.paths | ux/pages/simulate/policy/AgentPolicyTab.tsx:173 | 있음 |  |
| L-agent | pages/lab/AgentMenuPanel.tsx:82 | menu.items(조합별 저장 답 유무) | ux/pages/simulate/policy/AgentPolicyTab.tsx:205 | 있음 | 고른 뒤에만 "아직 없음"으로 보임 |
| L-agent | pages/lab/AgentMenuPanel.tsx:128 | AgentMenuAnswer.caseView.title | ux/pages/simulate/policy/AgentPolicyTab.tsx:162 (위임 변경은 61 key만) | 있음 |  |
| L-agent | pages/lab/AgentMenuPanel.tsx:129 | caseView.delegation.summary | ux/pages/simulate/policy/AgentPolicyTab.tsx:226 → ux/simulate/AgentParts.tsx:100 | 있음 | 위임 변경 답에만 있고, 메뉴 답에는 없음 |
| L-agent | pages/lab/AgentMenuPanel.tsx:133 | AgentMenuAnswer.ranAt | ux/pages/simulate/policy/AgentPolicyTab.tsx:222 | 있음 | 상대 시간이 절대 UTC 시각으로 바뀜 |
| L-agent | pages/lab/AgentMenuPanel.tsx:135 | AgentMenuAnswer.stale | ux/pages/simulate/policy/AgentPolicyTab.tsx:223 | 있음 |  |
| L-agent | pages/lab/AgentMenuPanel.tsx:155, pages/main/AgentResultParts.tsx:46 | proof.controls.D.firstStopStep(막았나·몇 번째 요청) | ux/pages/simulate/policy/AgentPolicyTab.tsx:215-216 | 있음 | 결론 문장으로 보임 |
| L-agent | pages/main/AgentResultParts.tsx:38 | proof.sent | ux/pages/simulate/policy/AgentPolicyTab.tsx:217 (+ux/simulate/AgentParts.tsx:201 행) | 있음 | proof.sent 대신 steps 수 |
| L-agent | pages/main/AgentResultParts.tsx:42 | proof.workNeeds | - | 없음 | ux/pages/simulate/agent/ResultPage.tsx:226은 흐름 실행에만 해당 |
| L-agent | pages/main/AgentResultParts.tsx:50 | 위임자 확인 요청 여부(run.confirmation / D rule) | ux/pages/simulate/policy/AgentPolicyTab.tsx:215 | 있음 | confirm* 결론 문장 |
| L-agent | pages/main/AgentResultParts.tsx:73 | proof.controls[통제].firstStopStep | ux/simulate/AgentParts.tsx:217 (ux/pages/simulate/policy/AgentPolicyTab.tsx:228) | 있음 | 요청별 칸에서 첫 차단을 읽을 수 있음 |
| L-agent | pages/main/AgentResultParts.tsx:76-81 | proof.controls[통제].documents/items/records/changes | - | 없음 | 표에는 D 건수 열만 있음(ux/simulate/AgentParts.tsx:227). ux/pages/simulate/agent/ResultPage.tsx:245는 흐름 실행에만 해당 |
| L-agent | pages/main/AgentResultParts.tsx:83 | proof.controls[통제].beyondNeed | - | 없음 | ux/pages/simulate/agent/ResultPage.tsx:260은 흐름 실행에만 해당 |
| L-agent | pages/main/AgentTimeline.tsx:54-55,70 | steps[].stepNo, path, outcomes[통제](outcome·rule) | ux/simulate/AgentParts.tsx:201-217 | 있음 |  |
| L-agent | pages/main/AgentTimeline.tsx:98-108 | 반복 요청 묶음 요약(count, withVerdict, decision.model_calls 합) | - | 없음 | SurgePage는 몰아치기 사례 전용 |
| L-agent | pages/lab/DelegationEditPanel.tsx:80 | DelegationEdit.quantities | ux/pages/simulate/policy/AgentPolicyTab.tsx:73 | 있음 |  |
| L-agent | pages/lab/DelegationEditPanel.tsx:88 | DelegationEdit.periods | ux/pages/simulate/policy/AgentPolicyTab.tsx:88 | 있음 |  |
| L-agent | pages/lab/DelegationEditPanel.tsx:95 | DelegationEdit.operations | ux/pages/simulate/policy/AgentPolicyTab.tsx:103 | 있음 |  |
| L-agent | pages/lab/DelegationEditPanel.tsx:109 | 요청 경로 선택지(static 3개) | ux/pages/simulate/policy/AgentPolicyTab.tsx:114 | 있음 |  |
| L-agent | pages/lab/DelegationEditPanel.tsx:24 | static:DelegationEditPanel.OWN(40/VALID/READ_EXPORT/OAUTH2_DELEGATED) 처음 선택 | ux/pages/simulate/policy/AgentPolicyTab.tsx:37-39,34 | 있음 | 포털 목록 첫 값(DelegationChoice.java:27-29)과 같음 |
| L-agent | pages/lab/DelegationEditPanel.tsx:70 | 위임 변경 사례의 AgentCaseView.instruction | ux/pages/simulate/agent/ReviewPage.tsx:158 (ux/pages/simulate/policy/AgentPolicyTab.tsx:123 링크로 이동) | 다른 위치 |  |
| L-agent | pages/lab/DelegationEditPanel.tsx:129 | LiveConfig.liveTicketsLeft | - | 없음 | ux/pages/simulate/agent/ReviewPage.tsx:95, ux/pages/simulate/surge/SurgePage.tsx:137은 0일 때 이유 문구로만 씀 |

### B-summary

- 옛 제목: 기존 보안이 모두 놓친 공격, Contexa는 막았을까요?
- 옛 화면: `pages/benchmark/BenchSummaryPage.tsx` (키 `bench.chart.summary.title`)
- 새 위치: 시나리오 검증 › 요약 = /validation?tab=summary · `ux/pages/validation/ValidationPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| B-summary | pages/benchmark/BenchSummaryPage.tsx:53 | `benchmark.scope.cases`, `caseCounts.THREAT/NORMAL/UNCERTAIN`, 시나리오당 횟수(`scope.fewestRunsPerCase/mostRunsPerCase`, 옛 포털은 `scope.protocols[].repeat`), `scope.runs` | ux/pages/validation/ValidationPage.tsx:186 | 있음 | 범위 한 줄 |
| B-summary | pages/benchmark/BenchSummaryPage.tsx:64 | `engine.decisions` | ux/pages/validation/ValidationPage.tsx:194 | 있음 |  |
| B-summary | pages/benchmark/BenchSummaryPage.tsx:70 | `blindSpot.pairs.length` (짝 수) | ux/pages/validation/ValidationPage.tsx:251 | 있음 | 카드 부제로 옮김 |
| B-summary | pages/benchmark/charts/ProofLines.tsx:19 | 기준1 `blindSpot.totals.attackAllPassed / attackRuns` | ux/pages/validation/ValidationPage.tsx:258-261 (301에서 그림) | 있음 |  |
| B-summary | pages/benchmark/charts/ProofLines.tsx:20 | 기준2 `totals.normalAllPassed / normalRuns` | ux/pages/validation/ValidationPage.tsx:265-268 | 있음 |  |
| B-summary | pages/benchmark/charts/ProofLines.tsx:23-29 | 기준3 `totals.contexaStopped, contexaFullyStopped, attackAllPassed, contexaPassed, normalAllPassed` | ux/pages/validation/ValidationPage.tsx:272-278 | 있음 |  |
| B-summary | pages/benchmark/charts/ProofLines.tsx:35-39 | 기준4 `engine.agreement.asAnswered/modelAnswered/held` | ux/pages/validation/ValidationPage.tsx:283-287 | 있음 |  |
| B-summary | pages/benchmark/charts/ProofLines.tsx:44 (훅 pages/benchmark/benchData.tsx:44) | 기준5 근거 일치 `decision-quality quality.reasonMatch.hits/total`(없으면 `prompt-quality reasonMatch`) | ux/pages/validation/ValidationPage.tsx:293 (훅 ux/validation/hooks.ts:57) | 있음 | 훅 순서도 같음 |
| B-summary | pages/benchmark/charts/PairBars.tsx:66-68 | 짝 묶음 `blindSpot.pairs[].group` | ux/pages/validation/ValidationPage.tsx:381-383 | 있음 |  |
| B-summary | pages/benchmark/charts/PairBars.tsx:43 | 짝 줄의 시나리오 이름 (`attacks[]/normals[].key` → `cases[].title`) | ux/pages/validation/ValidationPage.tsx:354 | 있음 | 새 화면은 키도 함께 |
| B-summary | pages/benchmark/charts/PairBars.tsx:45 (pages/benchmark/charts/RunCells.tsx:80-93) | 실행별 점 `blindSpot.*[].passedRuns[].runId/result` | ux/pages/validation/ValidationPage.tsx:356-359 (ux/pages/validation/ValidationParts.tsx:80-91) | 있음 | 단 아래 12행 |
| B-summary | pages/benchmark/charts/RunCells.tsx:17, 89 | 점별 결과 중 `PASSED_AFTER_CHECK`(추가 인증 뒤 허용) 구분 | — | 없음 | 새 점은 PASSED와 같은 모양·같은 낱말 |
| B-summary | pages/benchmark/charts/PairBars.tsx:47 | `allPassed / runs` | ux/pages/validation/ValidationPage.tsx:361 | 있음 |  |
| B-summary | pages/benchmark/charts/PairBars.tsx:48 | Contexa 결과별 횟수 `blindSpot.*[].contexa{result:n}` | ux/pages/validation/ValidationPage.tsx:362 | 있음 | 개수에서는 PASSED_AFTER_CHECK가 따로 보임 |
| B-summary | pages/benchmark/charts/PairBars.tsx:50-54 | 함께 쓰는 정상 업무 `blindSpot.sharedNormals[]` | ux/pages/validation/ValidationPage.tsx:364-366 | 있음 |  |
| B-summary | pages/benchmark/charts/PairBars.tsx:84-90 | 짝 없는 공격 (`attacks[]` 중 pairs에 없는 것) | ux/pages/validation/ValidationPage.tsx:394-403 | 있음 |  |
| B-summary | pages/benchmark/BlindSpotProof.tsx:53-57 | 표: `blindSpot.attacks[]/normals[].key`·`allPassed/runs`·`contexa` | ux/pages/validation/ValidationPage.tsx:436-440 | 있음 | 새 표는 이름 대신 키만 |
| B-summary | pages/benchmark/BlindSpotProof.tsx:79-84 | `engine.agreement.asAnswered/modelAnswered/technical/held` 줄 | ux/pages/validation/QualityTab.tsx:314-319 (/validation?tab=quality) | 다른 위치 | 요약 탭의 대체 표(ProofTables)에는 없음 |
| B-summary | pages/benchmark/BlindSpotProof.tsx:88 | `prompt-quality reasonMatch.hits/total` 줄 | ux/pages/validation/QualityTab.tsx:324 (/validation?tab=quality) | 다른 위치 | 위와 같음 |

### B-approaches

- 옛 제목: 다섯 보안은 공격을 얼마나 막고, 정상 업무를 얼마나 막았을까요?
- 옛 화면: `pages/benchmark/BenchApproachesPage.tsx` (키 `bench.chart.approaches.title`)
- 새 위치: 시나리오 검증 › 통제별 = /validation?tab=controls · `ux/pages/validation/ValidationPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| B-approaches | pages/benchmark/BenchApproachesPage.tsx:70-74; pages/benchmark/BenchScreen.tsx:487-489 | 시나리오 묶음 `suites[].suite` (선택지·고른 묶음 이름) | ux/pages/validation/ValidationPage.tsx:489-493 | 있음 |  |
| B-approaches | pages/benchmark/BenchApproachesPage.tsx:82; pages/benchmark/charts/RateScatter.tsx:180-184, 192 | 통제별 공격 막음 `controls[]`(또는 `suites[].controls[]`)`.stoppedAny.{hits,total,rate,low,high,preliminary}` | ux/pages/validation/ValidationPage.tsx:545-546 (ux/pages/validation/ValidationParts.tsx:134-143) | 있음 |  |
| B-approaches | pages/benchmark/BenchApproachesPage.tsx:81; pages/benchmark/charts/RateScatter.tsx:192 | 통제별 오탐 `controls[].falseBlock.{hits,total,rate,low,high,preliminary}` | ux/pages/validation/ValidationPage.tsx:549-550 | 있음 |  |
| B-approaches | pages/benchmark/BenchApproachesPage.tsx:93-96 | 세는 기준 `controls[D].stoppedAny.total`, `falseBlock.total` | ux/pages/validation/ValidationPage.tsx:503-506 | 있음 | 카드 부제 |
| B-approaches | pages/benchmark/BenchApproachesPage.tsx:101-106 | `controls[D].stoppedAny.hits/total` + `judgmentTiming.STATIC_REFUSAL` | ux/pages/validation/ValidationPage.tsx:567-572 | 있음 |  |
| B-approaches | pages/benchmark/BenchApproachesPage.tsx:116 | 세 질문 답 `conclusions.{mostStopped,mostFalseBlock,cleanMostStopped}.controls[]` | ux/pages/validation/ValidationPage.tsx:589-593 | 있음 |  |
| B-approaches | pages/benchmark/BenchApproachesPage.tsx:120 | 세 질문 값 `conclusions.*.hits/total` | ux/pages/validation/ValidationPage.tsx:597-600 | 있음 |  |
| B-approaches | pages/benchmark/BenchScreen.tsx:461, 465, 512 | 통제별 세 점수 `controls[].stopped/stoppedAny/notBlocked .hits/total·preliminary` | ux/pages/validation/ValidationPage.tsx:649 | 있음 | 요약·통제별 '자세히' 창 |
| B-approaches | pages/benchmark/BenchScreen.tsx:462-464 | 추가 인증 `controls[].friction.hits` | ux/pages/validation/ValidationPage.tsx:650-654 | 있음 |  |
| B-approaches | pages/benchmark/BenchScreen.tsx:551-554 | 고른 통제(?control=) 세 점수·범위 `{stopped,stoppedAny,notBlocked}.{hits,total,low,high,preliminary}` | ux/pages/validation/ValidationPage.tsx:713-720 | 있음 |  |
| B-approaches | pages/benchmark/BenchScreen.tsx:560-567 | 고른 통제의 틀린 것 `missed, partlyStopped, falseBlock.hits, attackUnresolved, normalUnresolved` | ux/pages/validation/ValidationPage.tsx:725-733 | 있음 |  |
| B-approaches | components/inside/ApproachSettings.tsx:56-148 | `/api/settings` 통제 설정: `waf.image/ruleSet`, `permission.roleRules[]`, `threshold.nightStart/nightEnd/volumeLimit/dormantWindowDays`, `businessRecord.exportPolicyKey/assignedExportLimit/ticketAndOncallExempt/historyWindowDays/exportHistoryWindowDays/accessPolicies[]`, `engine.layer1Model/layer2Model/chatModel/effectiveMode/inspectorConditions` | ux/pages/validation/ValidationPage.tsx:769-856 | 있음 | 항목이 하나씩 같음 |

### B-cases · B-case

- 옛 제목: 상황마다 누가 제대로 처리했을까요?
- 옛 화면: `pages/benchmark/BenchCasesPage.tsx` (키 `bench.r7.cases.title`) + 시나리오 창 `pages/benchmark/BenchScreen.tsx`
- 새 위치: 시나리오 검증 › 시나리오별 = /validation?tab=scenarios · `ux/pages/validation/ScenariosTab.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| B-cases · B-case | pages/benchmark/BenchCasesPage.tsx:40-46 | `caseCounts.THREAT/NORMAL/UNCERTAIN`, `contexaWrongCases.THREAT/NORMAL` | ux/pages/validation/ScenariosTab.tsx:64-70 | 있음 |  |
| B-cases · B-case | pages/benchmark/charts/CaseMap.tsx:47-58, 83 | 묶음 `suites[].suite/cases[]`, 종류 묶음 `cases[].classification` | ux/pages/validation/ScenariosTab.tsx:40-50, 80-82 | 있음 | 새 화면은 묶음별 개수도 |
| B-cases · B-case | pages/benchmark/charts/CaseMap.tsx:71 | 시나리오 이름 `cases[].title` | ux/pages/validation/ScenariosTab.tsx:105 | 있음 | 키(108)도 |
| B-cases · B-case | pages/benchmark/charts/CaseMap.tsx:66 | 정답 배지 `cases[].classification` | ux/pages/validation/ScenariosTab.tsx:109-113 | 있음 |  |
| B-cases · B-case | pages/benchmark/charts/CaseMap.tsx:136-137 (19-24) | 통제별 실행별 점 `cases[].runResults{runId:{control:result}}` | ux/pages/validation/ScenariosTab.tsx:118-127 | 있음 | 단 아래 37행 |
| B-cases · B-case | pages/benchmark/charts/RunCells.tsx:17, 89 | 점별 결과 중 `PASSED_AFTER_CHECK` 구분 | — | 없음 | 12행과 같은 원인 |
| B-cases · B-case | pages/benchmark/charts/CaseMap.tsx:60, 77 | 틀린 것만 보기 `cases[].contexaWrong` | ux/pages/validation/ScenariosTab.tsx:52, 73-77 | 있음 | ?wrong=1 |
| B-cases · B-case | pages/benchmark/BenchScreen.tsx:169 | 창 제목 시나리오 이름 `cases[].title` | ux/pages/validation/ScenariosTab.tsx:165 (140, 148에서 그림) | 있음 | ?case= |
| B-cases · B-case | pages/benchmark/BenchScreen.tsx:643-645 | 해야 할 처리 (`cases[].classification` → 막음/통과/없음) | ux/pages/validation/ScenariosTab.tsx:187-189 | 있음 |  |
| B-cases · B-case | pages/benchmark/BenchScreen.tsx:646-659 | 맞다고 치는 처리 `/api/cases cases[].allowedActions[]` (+ESCALATE면 보류 안내) | ux/pages/validation/ScenariosTab.tsx:190-202 | 있음 |  |
| B-cases · B-case | pages/benchmark/BenchScreen.tsx:661 | 이유 `/api/cases cases[].rationale[lang]` | ux/pages/validation/ScenariosTab.tsx:204 | 있음 |  |
| B-cases · B-case | pages/benchmark/BenchScreen.tsx:666 | 반론 `/api/cases cases[].counterpoint[lang]` | ux/pages/validation/ScenariosTab.tsx:209 | 있음 |  |
| B-cases · B-case | pages/benchmark/BenchScreen.tsx:675-684 | 통제별 `cases[].cells[control].right/counted/state` | ux/pages/validation/ScenariosTab.tsx:220-230 | 있음 |  |
| B-cases · B-case | pages/benchmark/BenchScreen.tsx:692 | 보낸 실행 수 `cases[].runs` | ux/pages/validation/ScenariosTab.tsx:239 | 있음 |  |
| B-cases · B-case | pages/benchmark/BenchScreen.tsx:695-702 | 실행 ID `cases[].runIds[]` | ux/pages/validation/ScenariosTab.tsx:241-245 | 있음 |  |

### B-judgment

- 옛 제목: Contexa가 받은 공격 23회는 어떻게 끝났을까요?
- 옛 화면: `pages/benchmark/BenchJudgmentPage.tsx` (키 `bench.r7.judgment.title`)
- 새 위치: 시나리오 검증 › 판정 품질 = /validation?tab=quality · `ux/pages/validation/QualityTab.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:130 | 공격 실행 수 `scope.attackRuns` (제목) | ux/pages/validation/QualityTab.tsx:135 | 있음 | 카드 제목 |
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:148-155 (pages/benchmark/charts/StackBar.tsx:135) | 끝난 방식별 `judgmentTiming.{STATIC_REFUSAL,BEFORE_RESPONSE,NEXT_REQUEST,JUDGED_ALLOW,OTHER}` | ux/pages/validation/QualityTab.tsx:124-130, 139-143 (ux/ui/Content.tsx:125) | 있음 |  |
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:84 | 그 밖 횟수 `judgmentTiming.OTHER` | ux/pages/validation/QualityTab.tsx:147 | 있음 |  |
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:91-96 | 그 밖 실행 `judgmentOthers[].caseKey/steps[].{stepNo,action,applied,applicable,source}/result/exposedItems` | ux/pages/validation/QualityTab.tsx:152-157 | 있음 |  |
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:164 | `judgmentTiming.NEXT_REQUEST` 안내 | ux/pages/validation/QualityTab.tsx:164 | 있음 |  |
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:165 | `judgmentTiming.JUDGED_ALLOW` 안내 | ux/pages/validation/QualityTab.tsx:165 | 있음 |  |
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:170-181, 191 | `riskJudged.runs/stopped/kinds{}` (kinds 없으면 runs/stopped) | ux/pages/validation/QualityTab.tsx:168-178 | 있음 |  |
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:185 | `riskJudged.notStopped[]` | ux/pages/validation/QualityTab.tsx:182 | 있음 |  |
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:198-201 | `judgmentExposure{kind:items}` | ux/pages/validation/QualityTab.tsx:188-191 | 있음 |  |
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:209 | `engine.analysisMeasured` | ux/pages/validation/QualityTab.tsx:199 | 있음 |  |
| B-judgment | pages/benchmark/charts/Histogram.tsx:68, 71 | `engine.analysisBins[].fromMs/toMs/decisions` | ux/pages/validation/QualityTab.tsx:211-227 | 있음 |  |
| B-judgment | pages/benchmark/charts/Histogram.tsx:61-62, 81; pages/benchmark/BenchJudgmentPage.tsx:220-224 | `engine.analysisP50Ms/analysisP95Ms` | ux/pages/validation/QualityTab.tsx:234-240 | 있음 | 옛 막대 위 ▼ 표시(소수 둘째 자리)는 없고 한 줄로만 |
| B-judgment | pages/benchmark/BenchJudgmentPage.tsx:228-236 | `engine.costPerDecisionUsd, tokensPerDecision, modelCallsPerDecision` | ux/pages/validation/QualityTab.tsx:244-251 | 있음 |  |

### B-reasoning

- 옛 제목: AI의 판단을 믿을 수 있을까요?
- 옛 화면: `pages/benchmark/BenchReasoningPage.tsx` (키 `bench.chart.reasoning.title`)
- 새 위치: 시나리오 검증 › 판정 품질 = /validation?tab=quality · `ux/pages/validation/QualityTab.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| B-reasoning | pages/benchmark/BenchReasoningPage.tsx:78 | `scope.runs`, `engine.decisions` | ux/pages/validation/QualityTab.tsx:282 | 있음 |  |
| B-reasoning | pages/benchmark/BenchReasoningPage.tsx:88 | `engine.reasoning.mostLikely{truth:{H1..H5,SEVERAL,NONE}}` | ux/pages/validation/QualityTab.tsx:288-296 | 있음 | 0건인 설명은 새 막대에서 빠짐(옛 표는 0도 보임) |
| B-reasoning | pages/benchmark/BenchReasoningPage.tsx:99-108 | `mostLikely.THREAT.H1` + `reasoning.mostLikelyActions.THREAT.H1{action:n}` | ux/pages/validation/QualityTab.tsx:302-309 | 있음 |  |
| B-reasoning | pages/benchmark/BenchReasoningPage.tsx:114-119 | `engine.agreement.asAnswered/modelAnswered/technical/held` | ux/pages/validation/QualityTab.tsx:314-319 | 있음 |  |
| B-reasoning | pages/benchmark/BenchReasoningPage.tsx:123 | 근거 일치 `reasonMatch.hits/total` | ux/pages/validation/QualityTab.tsx:324 | 있음 |  |
| B-reasoning | pages/benchmark/BenchReasoningPage.tsx:125 | `reasoning.retried` | ux/pages/validation/QualityTab.tsx:327 | 있음 |  |
| B-reasoning | pages/benchmark/BenchReasoningPage.tsx:130-134 | `reasoning.flips{"from->to":n}` | ux/pages/validation/QualityTab.tsx:332-336 | 있음 |  |
| B-reasoning | pages/benchmark/BenchReasoningPage.tsx:158, 160 | `reasoning.topRetryReasons[].reason/decisions` | ux/pages/validation/QualityTab.tsx:356, 359 | 있음 |  |

### B-limits

- 옛 제목: Contexa는 무엇을 놓쳤을까요?
- 옛 화면: `pages/benchmark/BenchLimitsPage.tsx` (키 `bench.r7.limits.title`) + 방법 창 `pages/benchmark/BenchScreen.tsx`
- 새 위치: 시나리오 검증 › 한계 · 방법 = /validation?tab=limits·method · `ux/pages/validation/OtherTabs.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| B-limits | pages/benchmark/BenchLimitsPage.tsx:57 | 매번 통과시킨 공격 수 `missedEveryRunCases[]` | ux/pages/validation/OtherTabs.tsx:193-196 | 있음 | 새 화면은 이름도 |
| B-limits | pages/benchmark/charts/WrongCases.tsx:40 | Contexa가 틀린 위협·정상 시나리오 이름 (`cases[]` 중 `contexaWrong`, classification별) | ux/pages/validation/OtherTabs.tsx:153 | 있음 |  |
| B-limits | pages/benchmark/charts/WrongCases.tsx:41-47 | Contexa 실행별 점 `cases[].runResults{runId:{D}}` | ux/pages/validation/OtherTabs.tsx:155-161 | 있음 | 단 아래 71행 |
| B-limits | pages/benchmark/charts/RunCells.tsx:17, 89 | 점별 결과 중 `PASSED_AFTER_CHECK` 구분 (정상 업무 쪽) | — | 없음 | 12행과 같은 원인 |
| B-limits | pages/benchmark/charts/WrongCases.tsx:53 | 모델이 쓴 이유 `wrongRuns[].reasoning` | ux/pages/validation/OtherTabs.tsx:165 | 있음 |  |
| B-limits | pages/benchmark/charts/WrongCases.tsx:61 | 그 실행의 반출 `wrongRuns[].exposedItems` (위협만) | ux/pages/validation/OtherTabs.tsx:171 | 있음 |  |
| B-limits | pages/benchmark/BenchLimitsPage.tsx:77, 81, 85 | `controls[D].stopped`, `stoppedAny`(hits/total), `exposedItems` | ux/pages/validation/OtherTabs.tsx:208, 212, 216 | 있음 |  |
| B-limits | pages/benchmark/BenchLimitsPage.tsx:90 | `judgmentTiming.STATIC_REFUSAL` | ux/pages/validation/OtherTabs.tsx:221 | 있음 |  |
| B-limits | pages/benchmark/BenchLimitsPage.tsx:95-98 | `judgmentTiming.NEXT_REQUEST/JUDGED_ALLOW` | ux/pages/validation/OtherTabs.tsx:224-227 | 있음 |  |
| B-limits | pages/benchmark/BenchLimitsPage.tsx:102-111 | `judgmentTiming.OTHER`, `judgmentOthers[].caseKey/result` | ux/pages/validation/OtherTabs.tsx:231-239 | 있음 |  |
| B-limits | pages/benchmark/BenchLimitsPage.tsx:122 | `spec.promptBundles[]` (-v21 여부로 설명 한계 두 줄을 고름) | ux/pages/validation/OtherTabs.tsx:247 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:242-249 | 범위 `spec.firstRunAt/lastRunAt, scope.cases, scope.runs, 시나리오당 횟수, unresolvedRuns` | ux/pages/validation/OtherTabs.tsx:283-290 | 있음 | ?tab=method |
| B-limits | pages/benchmark/BenchScreen.tsx:278-281 | 기간 `spec.firstRunAt ~ lastRunAt` | ux/pages/validation/OtherTabs.tsx:313 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:287 | `spec.chatModel` | ux/pages/validation/OtherTabs.tsx:318 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:293 | `spec.settingHash`(12자) | ux/pages/validation/OtherTabs.tsx:324 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:299 | `spec.ruleVersion`(12자) | ux/pages/validation/OtherTabs.tsx:330 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:306 | `spec.codeCommit · spec.engineVersion` | ux/pages/validation/OtherTabs.tsx:337 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:313-317 | `scope.protocols[].protocolId` | ux/pages/validation/OtherTabs.tsx:344-348 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:435-441 | 다른 설정 `specs[].settingHash/firstRunAt/protocolRuns` | ux/pages/validation/OtherTabs.tsx:370-381 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:334-336 | `engine.analysisP50Ms` | ux/pages/validation/OtherTabs.tsx:395-397 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:341 | `engine.costPerDecisionUsd` | ux/pages/validation/OtherTabs.tsx:403-405 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:345 | `engine.decisions` | ux/pages/validation/OtherTabs.tsx:410 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:349-356 | `engine.analysisP95Ms, tokensPerDecision, modelCallsPerDecision` | ux/pages/validation/OtherTabs.tsx:415-425 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:358-361 | `engine.priceSource` | ux/pages/validation/OtherTabs.tsx:428-435 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:374-377 | `observations.liveRuns/labRuns` | ux/pages/validation/OtherTabs.tsx:446-449 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:380-384 | `observations.predictions.hits/total/rate` | ux/pages/validation/OtherTabs.tsx:452-456 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:387-390 | `observations.assessments/assessors` | ux/pages/validation/OtherTabs.tsx:459-462 | 있음 |  |
| B-limits | pages/benchmark/BenchScreen.tsx:398-400 | 공정성 안내 `notices[]` | ux/pages/validation/OtherTabs.tsx:469-471 | 있음 |  |

### B-agent

- 옛 제목: 에이전트의 요청에서 Contexa는 얼마나 막았을까요?
- 옛 화면: `pages/benchmark/BenchAgentPage.tsx` (키 `bench.agent.title`)
- 새 위치: 시나리오 검증 › 에이전트 = /validation?tab=agent · `ux/pages/validation/OtherTabs.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| B-agent | pages/benchmark/BenchAgentPage.tsx:41-45 | `agent.total.existingMissed/contexaStopped/contexaShare` | ux/pages/validation/OtherTabs.tsx:38-42 | 있음 |  |
| B-agent | pages/benchmark/BenchAgentPage.tsx:48-53 | `agent.scope.runs/cases/from/to` | ux/pages/validation/OtherTabs.tsx:45-50 | 있음 |  |
| B-agent | pages/benchmark/BenchAgentPage.tsx:73-74, 143-148 | 경로별 `byPath[].path, runs, attacks, existingMissed, contexaStopped, normals, falseBlocks` | ux/pages/validation/OtherTabs.tsx:67-75 | 있음 | 경로 이름은 SubjectChip 대신 사전 라벨 |
| B-agent | pages/benchmark/BenchAgentPage.tsx:78-81 | 합계 줄 `total.*` | ux/pages/validation/OtherTabs.tsx:67 (path ALL) | 있음 |  |
| B-agent | pages/benchmark/BenchAgentPage.tsx:86-89 | `total.falseBlocks/normals` | ux/pages/validation/OtherTabs.tsx:83 | 있음 |  |
| B-agent | pages/benchmark/BenchAgentPage.tsx:92-95 | `variation.differing/cells` | ux/pages/validation/OtherTabs.tsx:86-89 | 있음 |  |
| B-agent | pages/benchmark/BenchAgentPage.tsx:100-108 | 몰림 요청 (useBurstSnapshots) `bursts[].on.summary.requests, off.summary.modelCalls, on.summary.modelCalls` | ux/pages/validation/OtherTabs.tsx:93-102 | 있음 |  |
| B-agent | pages/benchmark/BenchAgentPage.tsx:112, 115 | `contexaMissed[]` 수와 목록 | ux/pages/validation/OtherTabs.tsx:106-108 | 있음 |  |
| B-agent | pages/benchmark/BenchAgentPage.tsx:118, 120 | `notMeasured[]` 수와 목록 | ux/pages/validation/OtherTabs.tsx:111-113 | 있음 |  |

### O-videos

- 옛 제목: 화면별 미리보기 영상
- 옛 화면: `pages/GuidesPage.tsx` (키 `guides.title`)
- 새 위치: 제품 투어 = /tour · `ux/pages/tour/TourPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| O-videos | `pages/GuidesPage.tsx:48,70-71,96` | 영상 목록(매니페스트 id)과 제목 static:components/guide/guides.json.<id>.title | `ux/pages/tour/TourPage.tsx:50-58,86,122` | 있음 | 옛 화면은 지금 영상을 하나도 안 보였음(아래 참고 1). 새 제목 키는 console·agent만 있음(72-76) |
| O-videos | `pages/GuidesPage.tsx:98` | 길이 `durationSec` (guides.length) | `ux/pages/tour/TourPage.tsx:88` | 있음 |  |
| O-videos | `pages/GuidesPage.tsx:99` | 끝까지 봄 표시(localStorage `contexa.guide.watched`) | `ux/pages/tour/TourPage.tsx:94-97` | 있음 | 같은 키(ux/pages/tour/guideWatched.ts:8) |
| O-videos | `pages/GuidesPage.tsx:101-113` | 다루는 화면 목록 static:guides.json.<id>.screens (이름·링크) | — | 없음 | 이동 링크 성격. 옛 주소는 없어짐 |
| O-videos | `pages/GuidesPage.tsx:68` | 묶음 머리글 guides.group.S/H/A/C (static guides.json, route.json track) | — | 없음 | 분류 머리글이라 사실성이 약함 |
| O-videos | `components/guide/GuideWindow.tsx:31` | 녹화 날짜 `recordedAt`, 화면 판 `screens` (guide.recorded) | `ux/pages/tour/TourPage.tsx:89,122` | 있음 |  |
| O-videos | `components/guide/GuidePlayer.tsx:73` | 영상 파일 `file` | `ux/pages/tour/TourPage.tsx:127` | 있음 |  |
| O-videos | `components/guide/GuidePlayer.tsx:46,82-91` | 자막 트랙 `captions`·`captionsNarrow` (언어별) | `ux/pages/tour/TourPage.tsx:113,135-144` | 있음 | 옛 화면의 자막 띠(106-108) 대신 새 화면은 브라우저 기본 자막을 씀 |
| O-videos | `components/guide/GuidePlayer.tsx:95-102,122-136` | 장면 `scenes[].start`, 대본 문구 static:guides.json.<id>.scenes | `ux/pages/tour/TourPage.tsx:146-174` (시각 168, 문구 169) | 있음 | 키가 `ux.tour.scene.<id>.*`로 바뀌었고 console·agent 키만 있음 |

### O-privacy

- 옛 제목: 개인정보 안내
- 옛 화면: `pages/PolicyPage.tsx` + `content/policies.ts` (옛 /privacy)
- 새 위치: 개인정보 처리방침 = /privacy · `ux/pages/privacy/PrivacyPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| O-privacy | `content/policies.ts:27` (그림 pages/PolicyPage.tsx:35) | 이름·이메일·계정 불필요, 외부 분석 도구 없음 | `ux/pages/privacy/PrivacyPage.tsx:37` | 있음 |  |
| O-privacy | `content/policies.ts:28,52-54` (그림 35,76) | 그룹 처음 연 횟수: 날짜별 익명 건수, 누가 열었는지 안 남김, 30일 | `ux/pages/privacy/PrivacyPage.tsx:103` | 있음 | 새 화면에서는 "지금 화면이 보내지 않는 옛 기록"으로 표현이 바뀜 |
| O-privacy | `content/policies.ts:29` | 모델에 방문자 정보 안 들어감 | `ux/pages/privacy/PrivacyPage.tsx:38` | 있음 |  |
| O-privacy | `content/policies.ts:37-39` (그림 71,76) | 방문자 식별자: 목적(이어 보기·하루 한도), 보관(마지막 방문 뒤 30일, 기록 식별자도 지움) | `ux/pages/privacy/PrivacyPage.tsx:48-50` (visitor 행) | 있음 |  |
| O-privacy | `content/policies.ts:42-44` | 진행 위치: 방문자 식별자와 함께 삭제 | `ux/pages/privacy/PrivacyPage.tsx:103` | 있음 | 새 화면에서는 "옛 기록"으로 표현됨 |
| O-privacy | `content/policies.ts:42` | 진행 위치 세부 항목(경로, 그룹, 단계, 확인한 차이, 처음 연 그룹) | — | 없음 | "보내기 전 결과 예상"만 expected 행(48-50)에 있음 |
| O-privacy | `content/policies.ts:47-49` | 실험실 결과 예상: 목적(내 예상 보이기), 보관(실행 기록과 같음, 식별자만 지움) | `ux/pages/privacy/PrivacyPage.tsx:48-50` (expected 행) | 있음 | 정책 시뮬레이터 예상으로 이름이 바뀜 |
| O-privacy | `content/policies.ts:47-49` | 판단 평가(보낸 요청, 고른 답과 이유, 시각): 다른 방문자에게 건수로만 보임, 보관 | — | 없음 | ux/pages/validation/OtherTabs.tsx:459-461의 평가 건수는 정책 문장이 아님 |
| O-privacy | `content/policies.ts:56` | 하루 한도 기록: 목적, 7일 | `ux/pages/privacy/PrivacyPage.tsx:48-50` (quota) | 있음 |  |
| O-privacy | `content/policies.ts:57-61` | 접속 주소 해시: 목적, 7일 | `ux/pages/privacy/PrivacyPage.tsx:48-50` (address) | 있음 |  |
| O-privacy | `content/policies.ts:68` (그림 71,76) | 쿠키 `SC_VISITOR`: 역할, 30일 | `ux/pages/privacy/PrivacyPage.tsx:67,71-72` | 있음 | "처음 받은 뒤 30일"로 바뀜 |
| O-privacy | `content/policies.ts:69` | 쿠키 `XSRF-TOKEN`: 역할, 브라우저 닫을 때까지 | `ux/pages/privacy/PrivacyPage.tsx:67,71-72` | 있음 |  |
| O-privacy | `content/policies.ts:75` | 자동 삭제 매일 03:30 UTC | `ux/pages/privacy/PrivacyPage.tsx:100` | 있음 |  |
| O-privacy | `content/policies.ts:76` | 이해 확인 문항: 문항 건수 30일 | `ux/pages/privacy/PrivacyPage.tsx:103` | 있음 | 항목 이름은 있음. 기간은 "익명 건수 30일"에 묶여 있어 모호함 |
| O-privacy | `content/policies.ts:76` | 결과 공유 카드: 마지막 공유 뒤 90일 | `ux/pages/privacy/PrivacyPage.tsx:103` | 있음 |  |
| O-privacy | `content/policies.ts:76` | 상황별 예측: 방문자 식별자와 함께 삭제 | — | 없음 | external.old 나열에 빠져 있음 |
| O-privacy | `content/policies.ts:77` | Cloudflare Turnstile은 직접 보낼 때만 씀 | `ux/pages/privacy/PrivacyPage.tsx:101` | 있음 |  |
| O-privacy | `content/policies.ts:77` | 언어 모델 호출 시 방문자 정보 안 보냄 | `ux/pages/privacy/PrivacyPage.tsx:102` | 있음 |  |

### O-replay

- 옛 제목: 저장된 실제 기록으로 봅니다
- 옛 화면: `pages/ReplayPage.tsx` (키 `space.r7.replay.title`)
- 새 위치: 판정 이력 › 공개 녹화 실행 = /runs (공개 녹화 실행) · `ux/pages/runs/RunsPage.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| O-replay | `pages/ReplayPage.tsx:115` | 장면 구분(공격/정상 업무) `replay.scenes[].kind` | `ux/pages/runs/RunsPage.tsx:115`, `ux/pages/metrics/MetricsPage.tsx:502` | 있음 | 판정 이력에서는 실행의 시나리오 제목으로 구분 |
| O-replay | `pages/ReplayPage.tsx:116` | 장면 상황 문장 `replay.scenes[].sentence[lang]` | — | 없음 |  |
| O-replay | `pages/ReplayPage.tsx:331` | Contexa 판정 `runScore.verdicts[step1].score.finalAction` | `ux/pages/runs/RunsPage.tsx:127` (패널 :434) | 있음 | 새 화면은 판정이 난 요청을 기준으로 보임 |
| O-replay | `pages/ReplayPage.tsx:334` | 통제별 채점 결과 `runScore.business[c].result` | `ux/pages/runs/RunsPage.tsx:367`(D), `:140`(기존 통제가 막은 수 n/4) | 있음 | 기존 통제는 낱말 대신 개수 요약 |
| O-replay | `pages/ReplayPage.tsx:333` | 위협 실행에서 놓친 통제 강조 `runScore.correct[c]=false`(THREAT) | `ux/pages/runs/RunsPage.tsx:471` | 있음 | 위협 실행에서 반출이 0보다 크면 빨강 |
| O-replay | `pages/ReplayPage.tsx:333` | 정상 실행에서 기존 통제가 잘못 막은 표시 `runScore.correct[A~C2]=false`(NORMAL) | — | 없음 | D만 EvalBadge의 falsePositive로 보임(:367) |
| O-replay | `pages/ReplayPage.tsx:141→229-230`, `:174` | 반복 일치 수 `replay.scenes[].repetitions, agreeing` | `ux/pages/metrics/MetricsPage.tsx:509` | 다른 위치 | /metrics(stats.agreement.recordings). /start에는 hook의 measurement가 보임(HomePage:264-267) |
| O-replay | `pages/ReplayPage.tsx:209` | 녹화 시각 `replay.scenes[].recordedAt` | `ux/pages/runs/RunsPage.tsx:100`, `:423`, `ux/pages/metrics/MetricsPage.tsx:515` | 있음 |  |
| O-replay | `pages/ReplayPage.tsx:206`, `:215` | 지금 측정에 속하는지와 그 측정 날짜 `measured(case).list[runId].startedAt` | — | 없음 |  |
| O-replay | `pages/ReplayPage.tsx:125` | 요청 수(1보다 클 때) `runScore.executedSteps` | `ux/pages/runs/RunsPage.tsx:427` | 있음 |  |
| O-replay | `pages/ReplayPage.tsx:121` | 정답 분류 `runScore.truth.classification` | `ux/pages/runs/RunDetailPage.tsx:100` | 있음 | 판정 이력 › 판정 상세 |
| O-replay | `pages/ReplayPage.tsx:296` | 통제별 내보낸 건수 `runScore.business[c].exposedItems` | `ux/pages/runs/RunsPage.tsx:472` | 있음 |  |
| O-replay | `pages/ReplayPage.tsx:153-156→229-230` | 반복 측정 수·같은 결과 수 `measured.runs, results[result]` | `ux/pages/validation/ScenariosTab.tsx:222-229`, `:239` | 다른 위치 | /validation?tab=scenarios. "같은 결과 수" 대신 맞은 수/센 수와 실행별 점으로 보임 |
| O-replay | `pages/ReplayPage.tsx:157→226` | 추가 인증 뒤 통과 수 `measured.results.PASSED_AFTER_CHECK` | — | 없음 | 통제별 전체 집계만 있음(ValidationPage:554) |

### O-detail

- 옛 제목: (모달)
- 옛 화면: `components/detail/DecisionDetail.tsx` + 탭 7개 (`detail.r7.title`)
- 새 위치: 판정 이력 › 판정 상세 = /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx`

| 번호 | 옛 화면(파일) | 사실(응답 필드) | 새 위치(파일:줄) | 판정 | 메모 |
|---|---|---|---|---|---|
| O-detail | components/detail/DecisionDetail.tsx:50 | 상황 이름 `runScore.title[lang]`(+`scenarioKey`) | ux/pages/runs/RunDetailPage.tsx:113 | 있음 | 머리. 새 쪽은 `bench.r7.caseName` 쉬운 이름 대신 저장된 제목을 씀 |
| O-detail | components/detail/DecisionDetail.tsx:54 | 사람/에이전트 여부 `agentRun`(있음/404) | ux/pages/runs/RunDetailPage.tsx:106 | 있음 | 머리. 에이전트일 때만 뱃지, 사람은 표시 없음 |
| O-detail | components/detail/DecisionDetail.tsx:54 | 에이전트 주체 종류 `agentRun.sender`(위임·자율·세션) | — | 없음 | 머리. 새 쪽은 "AI 에이전트 요청" 한 가지로만 보임 |
| O-detail | components/detail/DecisionDetail.tsx:115 | 요청 번호/전체 `step`, `runScore.executedSteps` | ux/pages/runs/RunDetailPage.tsx:176 | 있음 | 머리(`detail.r7.request`) |
| O-detail | components/detail/TabFrame.tsx:47 | 실행 ID `runId` | ux/pages/runs/RunDetailPage.tsx:111 | 있음 | 요약 탭 출처 줄 → 새 제목 |
| O-detail | components/detail/TabFrame.tsx:49 | 판정 기록 시각 `runScore.verdicts[step].decidedAt` | ux/pages/runs/RunDetailPage.tsx:160 | 있음 | 요약 탭 출처 줄 |
| O-detail | components/detail/SummaryTab.tsx:98 | 판정 `anatomy.interpretation.recorded.finalAction`+`unresolved` | ux/pages/runs/RunDetailPage.tsx:112, ux/pages/runs/detailTabs.tsx:91 | 있음 | 여러 탭(요약·과정 components/detail/ProcessTab.tsx:89) |
| O-detail | components/detail/SummaryTab.tsx:48 | 판정 없는 이유 `anatomy.truth.verdict.source` | ux/pages/runs/detailTabs.tsx:81 | 있음 | 요약. PRIOR/STATIC/그 밖 세 문장으로 |
| O-detail | components/detail/SummaryTab.tsx:56 | 앱 거절 `stepResult.layers[D].httpStatus`·`ruleId` | ux/pages/runs/detailTabs.tsx:81 (+통제 탭 :214, :222) | 있음 | 요약. signIn 문장은 HTTP만, 통제 탭에 둘 다 |
| O-detail | components/detail/SummaryTab.tsx:105 | 적용 시점 `truth.verdict.score.applied ?? recorded.applied` | ux/pages/runs/detailTabs.tsx:98, ux/pages/runs/RunDetailPage.tsx:155 | 있음 | 요약. 새 쪽은 `recorded.applied`만 읽고 NEXT_REQUEST가 아니면 모두 "응답 전 적용"(NONE 구분 없음) |
| O-detail | components/detail/SummaryTab.tsx:105 (값 :67) | 보내는 도중 적용 `stepResult.layers[D].evidence.timing=MID_RESPONSE` | — | 없음 | 요약 |
| O-detail | components/detail/SummaryTab.tsx:107 | 판정 시간 `interpretation.timings.totalAnalysisMs` | ux/pages/runs/detailTabs.tsx:100, ux/pages/runs/RunDetailPage.tsx:153 | 있음 | 요약 |
| O-detail | components/detail/SummaryTab.tsx:114 | 나간 항목 수 `stepResult.layers[D].evidence.deliveredItems` | ux/pages/runs/detailTabs.tsx:106 (+:215) | 있음 | 요약 |
| O-detail | components/detail/SummaryTab.tsx:91 | 학습 전후 `figures.baselineBefore`/`baselineAfter` | ux/pages/runs/detailTabs.tsx:113, :624 | 있음 | 여러 탭(components/detail/ProcessTab.tsx:104). "학습 안 함" 이유는 고정 문구라 뺌 |
| O-detail | components/detail/SummaryTab.tsx:130 | 정답 분류 `truth.classification` | ux/pages/runs/detailTabs.tsx:119, ux/pages/runs/RunDetailPage.tsx:100 | 있음 | 여러 탭(components/detail/AnswerTab.tsx:49) |
| O-detail | components/detail/SummaryTab.tsx:131 | 채점 결과 `truth.verdict.score.result` | ux/pages/runs/detailTabs.tsx:130 | 있음 | 요약. 새 쪽은 `runScore.verdicts[step].score.result` |
| O-detail | components/detail/SummaryTab.tsx:136 | 정답 출처 `truth.truthSource` | — | 없음 | 여러 탭(components/detail/AnswerTab.tsx:31) |
| O-detail | components/detail/SummaryTab.tsx:174 | 정해진 사유 문장 `recorded.reasoningCode` | ux/pages/runs/detailTabs.tsx:140 | 있음 | 요약(근거 탭 :336에도) |
| O-detail | components/detail/SummaryTab.tsx:195 | 추가 인증 결과 `anatomy.recovery.challenge.reason`/`answered` | — | 없음 | 여러 탭(components/detail/ProcessTab.tsx:94) |
| O-detail | components/detail/SummaryTab.tsx:205 | 기술 실패 `recorded.failureType`·`fallbackCategory` | ux/pages/runs/detailTabs.tsx:84 | 있음 | 요약 |
| O-detail | components/detail/ProcessTab.tsx:52 | 요청 종류 `anatomy.operation` | ux/pages/runs/RunDetailPage.tsx:139 (경로가 있으면 :136) | 있음 | 과정. 경로가 있으면 method+path로 대신함 |
| O-detail | components/detail/ProcessTab.tsx:57 | 평소와 다른 항목 수 `figures.departureCount` | ux/pages/engine/EnginePage.tsx:212 | 다른 위치 | 과정. /engine?run=&tab=flow, 1단계만 |
| O-detail | components/detail/ProcessTab.tsx:61 | 회사 기록 줄 수 `juxtaposition.companyFacts.length` | — | 없음 | 과정 |
| O-detail | components/detail/ProcessTab.tsx:65 | 과거 판정 문서 수 `context.rag.ragAuthorizedDocumentCount` | — | 없음 | 과정 |
| O-detail | components/detail/ProcessTab.tsx:68 | 프롬프트 만든 시간 `timings.promptBuildMs` | — | 없음 | 과정 |
| O-detail | components/detail/ProcessTab.tsx:70 | 프롬프트 줄 수 `promptLines.total` | ux/pages/runs/detailTabs.tsx:427 | 있음 | 과정 |
| O-detail | components/detail/ProcessTab.tsx:75 | AI 응답 시간 `timings.llmLatencyMs` | ux/pages/engine/EnginePage.tsx:234 | 다른 위치 | 과정. /engine?run=&tab=flow, 1단계만 |
| O-detail | components/detail/ProcessTab.tsx:76 | 심층 분석 여부 `timings.events[type=LAYER2_COMPLETE]` | — | 없음 | 과정 |
| O-detail | components/detail/ProcessTab.tsx:83 | 제안 판정 `recorded.proposedAction` | ux/pages/runs/detailTabs.tsx:93 | 있음 | 과정 |
| O-detail | components/detail/ProcessTab.tsx:99 | 차단 풀기 요청 `anatomy.recovery.release` | — | 없음 | 과정 |
| O-detail | components/inside/Comparison.tsx:182 | 평소와 다른 항목·평소 값·이번 값 `received.usualVsNow[].dimension/now`, `received.usual[dim].values` | ux/pages/runs/detailTabs.tsx:302 | 있음 | 받은 입력. 새 쪽은 모든 행 |
| O-detail | components/detail/ReceivedTab.tsx:88 | 다른/같은/비교 못한 항목 `received.usualVsNow[].inUsual` | ux/pages/runs/detailTabs.tsx:307 | 있음 | 받은 입력(:88-90 → 행마다 표시) |
| O-detail | components/inside/Comparison.tsx:198 | 회사 기록 걸림 `received.companyAdverse[policysatisfied].values`, `company.approvalRequired`, `businessFacts[NO_APPROVAL]` | — | 없음 | 받은 입력. 엔진 흐름 탭 칩은 걸림 표시가 없음 |
| O-detail | components/detail/ReceivedTab.tsx:91 | 결재 불필요 `received.company.approvalRequired=false`+`businessFacts NO_APPROVAL` | — | 없음 | 받은 입력 |
| O-detail | components/detail/RulesTab.tsx:124 | 데모 추가 인증 집계 `teasers[CHALLENGE_OUTCOMES].values.total/outcomes` | — | 없음 | 규칙(:131-142 결과별) |
| O-detail | components/detail/RulesTab.tsx:133 | 통과 뒤 이어진 수 `CHALLENGE_OUTCOMES.values.resumed` | ux/simulate/Recovery.tsx:141 | 다른 위치 | 규칙. /simulate/person/:key/live, 추가 인증을 통과했을 때만 |
| O-detail | components/detail/RulesTab.tsx:92 | 받은 규칙 줄과 충족 표시 `exchanges.calls[].systemPrompt` 줄, `received.minimumRules.rules[].met` | — | 없음 | 규칙(:93-97) |
| O-detail | components/detail/RulesTab.tsx:86 | 원문 없음 사유 `exchanges.missing` | ux/pages/runs/detailTabs.tsx:467 | 있음 | 여러 탭(components/detail/OriginalTab.tsx:98) |
| O-detail | components/detail/PromptTab.tsx:120 | 사실 없음 사유 `runFacts.reason` | ux/pages/runs/detailTabs.tsx:432 | 있음 | 프롬프트 |
| O-detail | components/detail/PromptTab.tsx:213 | 공식 검사 리본 `quality.ribbon.withSource/facts`, `factAccuracy.matched/total`, `contradictions`, `unknown` | — | 없음 | 프롬프트(:213-241) |
| O-detail | components/detail/PromptTab.tsx:250 | 불리 조건 `juxtaposition.adverseChecked/adverseMet`, `coreAdverseLabels[met].label` | — | 없음 | 프롬프트(:250-254) |
| O-detail | components/detail/PromptTab.tsx:141 | 프롬프트 블록 `runFacts.blocks[].block` | ux/pages/runs/detailTabs.tsx:436 | 있음 | 프롬프트 |
| O-detail | components/detail/PromptTab.tsx:300 | 사실 이름·값 `blocks[].facts[].label/value` | ux/pages/runs/detailTabs.tsx:442, :444 | 있음 | 프롬프트(값 :308). 새 쪽은 줄 번호·factId도 보임 |
| O-detail | components/detail/PromptTab.tsx:301 | 사실 출처 등급 `facts[].source` | — | 없음 | 프롬프트 |
| O-detail | components/detail/PromptTab.tsx:312 | 근거 충분도 `facts[].sufficiency.grade/causes/cautions` | — | 없음 | 프롬프트 |
| O-detail | components/detail/PromptTab.tsx:356 | 다른 번들 비교 `otherBundle.lines.*`, `current/other.bundle.version`·`runId`·`systemPromptLines`·`userPrompt` | — | 없음 | 프롬프트(:356-392) |
| O-detail | components/detail/AnswerTab.tsx:41 | 상황 정의 해시 `truth.scenarioSha256` | — | 없음 | 정답 |
| O-detail | components/detail/AnswerTab.tsx:54 | 맞는 판정 `truth.allowedEngineActions` | ux/pages/runs/detailTabs.tsx:124 | 있음 | 정답 |
| O-detail | components/detail/AnswerTab.tsx:68 | 정답 이유 `truth.rationale[lang]` | ux/pages/runs/detailTabs.tsx:149 | 있음 | 정답 |
| O-detail | components/detail/AnswerTab.tsx:82 | 반론 `truth.counterpoint[lang]` | ux/pages/runs/detailTabs.tsx:155 | 있음 | 정답 |
| O-detail | components/detail/AnswerTab.tsx:89 | 상황 업무 결과 `truth.business.result` | ux/pages/runs/RunDetailPage.tsx:103 | 있음 | 정답. `runScore.business.D.result` 뱃지. PASSED_AFTER_CHECK는 PASSED와 같게, UNRESOLVED·NOT_SCORED는 뱃지 없음 |
| O-detail | components/detail/AnswerTab.tsx:92 | 나간 자료 수 `truth.business.exposedItems` | ux/pages/runs/RunsPage.tsx:472 | 다른 위치 | 정답. /runs에서 행을 고른 오른쪽 패널(`runScore.business[D]`) |
| O-detail | components/detail/OriginalTab.tsx:133 | AI 사유 원문 `recorded.reasoning` | ux/pages/runs/detailTabs.tsx:141 | 있음 | 원본(근거 탭 :337에도) |
| O-detail | components/detail/OriginalTab.tsx:145 | 위험도·확신도 `recorded.riskScore/confidence` | ux/pages/runs/RunDetailPage.tsx:147 | 있음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:159 | 공격 기법 `recorded.mitre` | — | 없음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:166 | 인용 증거 종류 `recorded.evidenceRefs` | — | 없음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:172 | 근거 코드·개수 `quality.reasonCodes[].code` | ux/pages/runs/detailTabs.tsx:256, :278 | 있음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:184 | 심층 분석 사유 `timings.events[LAYER2_COMPLETE].reasoning` | — | 없음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:193 | 호출 번호·모델 `exchanges.calls[].callNo/model` | ux/pages/runs/detailTabs.tsx:474, :477 | 있음 | 원본(번호는 :115) |
| O-detail | components/detail/OriginalTab.tsx:197 | 입력 토큰 `interpretation.calls[].promptTokens` | ux/pages/engine/EnginePage.tsx:233 | 다른 위치 | 원본. 1단계 모든 호출의 합만 |
| O-detail | components/detail/OriginalTab.tsx:198 | 출력 토큰 `interpretation.calls[].completionTokens` | — | 없음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:202 | 호출별 걸린 시간 `interpretation.calls[].elapsedMs` | — | 없음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:207 | 원문 물리 줄 수 `promptLines.systemPhysical/userPhysical` | — | 없음 | 원본. 내용 줄 수(system/user)는 :427에 있음 |
| O-detail | components/detail/OriginalTab.tsx:215 | 호출 실패 `interpretation.calls[].success/failure` | — | 없음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:220 | AI 답 원문 `exchanges.calls[].answer` | ux/pages/runs/detailTabs.tsx:484 | 있음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:220 | 보낸 규칙 원문 `exchanges.calls[].systemPrompt` | — | 없음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:220 | 보낸 상황 원문 `exchanges.calls[].userPrompt` | — | 없음 | 원본. 프롬프트 탭에는 사실 줄만 있음 |
| O-detail | components/detail/OriginalTab.tsx:220 | 제공자 응답 본문 `exchanges.calls[].providerResponse` | ux/pages/runs/detailTabs.tsx:490 | 있음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:277 | 품질 없음 사유 `quality.reason` | ux/pages/runs/detailTabs.tsx:259 | 있음 | 원본. 근거 코드가 없을 때만 |
| O-detail | components/detail/OriginalTab.tsx:286 | 번들 버전 `quality.bundle.version` | ux/pages/runs/detailTabs.tsx:537 (+:428) | 있음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:286 | 번들 해시·선택 출처 `quality.bundle.hash/selectionSource` | — | 없음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:299 | 봉인 ID `quality.seal.packageId` | ux/pages/runs/detailTabs.tsx:528 | 있음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:313 | 봉인 대조 수 `inspection.checks[SEAL_INTEGRITY].matched/mismatched/unverifiable` | ux/pages/runs/detailTabs.tsx:588 | 있음 | 원본(새 쪽은 검사 표 :588-592) |
| O-detail | components/detail/OriginalTab.tsx:331 | 공식 검사 판정·검사기 버전·시각 `inspection.verdict/inspectorVersion/inspectedAt` | ux/pages/runs/detailTabs.tsx:565, :568 | 있음 | 원본(:336, :340) |
| O-detail | components/detail/OriginalTab.tsx:345 | 어긋난/확인 못한 검사 이름 `inspection.checks[].code`(mismatched·unverifiable) | ux/pages/runs/detailTabs.tsx:588 | 있음 | 원본(:361). 새 쪽은 개수 표 |
| O-detail | components/detail/OriginalTab.tsx:352 | 어긋난 줄 상세 `checks[].mismatches[].factId/entry/line/expected/actual/reason` | — | 없음 | 원본 |
| O-detail | components/detail/OriginalTab.tsx:241 | 내려받은 기록 SHA-256 (`downloadRunRecord`, 브라우저 계산) | ux/pages/runs/detailTabs.tsx:549 | 있음 | 원본 |

## 3. 없음 목록

"확인한 새 위치"는 기획안 11절의 새 위치와 그 파일입니다. 하위 점검은 그 파일을 열고 `ux/` 전체를 필드 이름으로 찾았습니다. 찾은 낱말과 비슷한 곳은 메모에 있습니다.

| 번호 | 사실(응답 필드) | 옛 화면(파일:줄) | 확인한 새 위치 | 메모 |
|---|---|---|---|---|
| 2-1 · 4-1 · 5-1 | 승인 목적 `APPROVAL.purpose` | `pages/main/RequestPage.tsx:259→127` | /simulate/person/S13/review · `ux/pages/simulate/person/ReviewPage.tsx` | 고정 응답 세 사례 모두 APPROVAL 사실이 없음. 옛 화면에서도 실제로 그려진 적 없는 갈래 |
| 2-2 · 4-2 · 5-2 | 승인 목적 `businessFacts[APPROVAL_COVERS].value` | `pages/main/ConsolePage.tsx:397` (pages/main/consoleData.ts:150-155) | /simulate/person/S13/live · `ux/pages/simulate/person/LivePage.tsx` | ux.biz.APPROVAL_COVERS 문구에 {{value}}가 없음 |
| 2-2 · 4-2 · 5-2 | `benchmark.cases[key].engineActions` (판단 n건 모두 차단 등) | `pages/main/ConsolePage.tsx:433` (:561-569) | /simulate/person/S13/live · `ux/pages/simulate/person/LivePage.tsx` | ux에는 전체 stats.engineActions만 있음 |
| 2-2 · 4-2 · 5-2 | `stages[LAYER1_START·LAYER*_COMPLETE].atMs` (+n.nn초) | `pages/main/ConsolePage.tsx:249→447` | /simulate/person/S13/live · `ux/pages/simulate/person/LivePage.tsx` | 새 model 행은 stage.elapsedMs를 그림(ux/simulate/DecisionProgress.tsx:95) |
| 2-2 · 4-2 · 5-2 | 2차 분석: `stages[LAYER2_START]`, 1차 `LAYER1_COMPLETE.action/riskScore/confidence` | `pages/main/consoleData.ts:239-257`→`pages/main/ConsolePage.tsx:448` | /simulate/person/S13/live · `ux/pages/simulate/person/LivePage.tsx` | ux/simulate/DecisionProgress.tsx:58은 마지막 패스 하나만 그림 |
| 2-2 · 4-2 · 5-2 | 호출별 `anatomy.interpretation.calls[].callNo/elapsedMs/promptTokens/completionTokens` | `pages/main/consoleData.ts:302-307`→`pages/main/ConsolePage.tsx:236,448` | /simulate/person/S13/live · `ux/pages/simulate/person/LivePage.tsx` | 호출 번호만 ux/pages/runs/detailTabs.tsx:474에 있음 |
| 2-2 · 4-2 · 5-2 | `challenge.codeRequestedMs/verifiedMs/reissueSentMs/reissueDoneMs/reissueOutcome` | `components/RecoveryFlow.tsx:24-27,33,39-42→55,57` | /simulate/person/S13/live · `ux/pages/simulate/person/LivePage.tsx` |  |
| 2-2 · 4-2 · 5-2 | `release.secondsLeft` | `components/show/ReleasePanel.tsx:96` | /simulate/person/S13/live · `ux/pages/simulate/person/LivePage.tsx` | ReleaseCard에 남은 시간 표시가 없음 |
| 2-2 · 4-2 · 5-2 | 해제 사유의 승인 목적 `facts[APPROVAL].purpose` | `pages/main/ConsolePage.tsx:549` | /simulate/person/S13/live · `ux/pages/simulate/person/LivePage.tsx` | reasonApproval 문구에 목적이 없음 |
| 2-3 | `responses[c].sentAt` | `pages/main/ProofPanel.tsx:118` | /simulate/person/S13/result · `ux/pages/simulate/person/ResultPage.tsx` |  |
| 2-3 | `responses[c].excerpt` (응답 원문 앞부분) | `pages/main/ProofPanel.tsx:121` | /simulate/person/S13/result · `ux/pages/simulate/person/ResultPage.tsx` | ResponseTab은 모델 응답이라 다른 것 |
| 2-4 | 평소 최대 대비 배수: `received.sizeRatio.times` | pages/main/AttackReasonPage.tsx:164 | /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx` | 아래 "없음" 참조 |
| 4-3 | `inputChanges[].key/before/now` + 바뀐 줄 수 | `pages/main/DiffPage.tsx:132-138,172-181` | /simulate/person/S13T/result?tab=compare · `ux/simulate/CompareView.tsx` | ux/pages/simulate/policy/ComposeTab.tsx:539-541은 다른 실행 쌍의 비교 |
| 4-4 | 출장 도시 `labCase.facts[TRAVEL].city` | `pages/main/CheckPage.tsx:127,157` | /simulate/person/S13T/result · `ux/pages/simulate/person/ResultPage.tsx` |  |
| 4-4 | 저장된 추가 인증 시각 `recovery.challenge.challenged_at/code_requested_at/verified_at/reissue_sent_at` | `pages/main/RequestSteps.tsx:157,172-174` | /simulate/person/S13T/result · `ux/pages/simulate/person/ResultPage.tsx` |  |
| 4-4 | 저장된 `recovery.challenge.reissue_delivered/reissue_status` | `pages/main/RequestSteps.tsx:162-168` | /simulate/person/S13T/result · `ux/pages/simulate/person/ResultPage.tsx` |  |
| 5-2 | 저장된 재전송 `anatomy(n).recovery.challenge.reissue_delivered/reissue_status` | `pages/main/RequestSteps.tsx:97-104` (pages/main/consoleData.ts:48-49) | /simulate/person/S16/live · `ux/pages/simulate/person/LivePage.tsx` | 진행 중 값만 ux/simulate/Recovery.tsx:133-137에 있음 |
| 5-3 | 판정이 엮은 서로 다른 인용 사실 수 n: `quality.reasonCodes[].fact`의 서로 다른 개수 | pages/main/InsidePage.tsx:114-115, :120 | /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx` | 개별 인용 사실은 ux/pages/runs/detailTabs.tsx:269-272에 보임. 수 n 자체는 그리지 않음(256은 코드 수) |
| 5-3 | 값 출처(모델이 내지 않음): `recorded.fieldProvenance.{riskScore,confidence}` | pages/main/VerdictCard.tsx:139-142 | /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx` | 아래 "없음" 참조 |
| 6-1 | 보내는 쪽 칩 `agentCase.sender` | pages/main/AgentRequestPage.tsx:92 (→ components/main/MainScreen.tsx:180) | /simulate/agent/T5/review · `ux/pages/simulate/agent/ReviewPage.tsx` | 2단계에는 고정 배지 'AI 에이전트 위임 남용'(ux/pages/simulate/agent/ReviewPage.tsx:132-134)만 있음 |
| 6-1 | 자원이 없을 때 대신 보인 `delegation.project` | pages/main/DelegationParts.tsx:61 | /simulate/agent/T5/review · `ux/pages/simulate/agent/ReviewPage.tsx` | 새 사슬은 '—'(ux/pages/simulate/agent/ReviewPage.tsx:154) |
| 6-1 | 오늘 남은 실제 실행 수 `liveConfig.liveTicketsLeft`({{n}}) | pages/main/AgentRequestPage.tsx:179 | /simulate/agent/T5/review · `ux/pages/simulate/agent/ReviewPage.tsx` | ux/pages/simulate/agent/ReviewPage.tsx:220은 다른 필드(`remainingAgentToday`·`dailyAgentRuns`, 방문자당 값) |
| 6-1 | 그 요청들의 회사 시각 `agentRun.steps[].companyTime` | pages/main/AgentRequestPage.tsx:224 | /simulate/agent/T5/review · `ux/pages/simulate/agent/ReviewPage.tsx` | ux/pages/runs/RunDetailPage.tsx:160은 판정 시각(UTC)이고 회사 시각이 아님 |
| 6-2 | 보내는 쪽 칩 `agentCase.sender` | pages/main/AgentConsolePage.tsx:56 (→ components/main/MainScreen.tsx:180) | /simulate/agent/:caseKey/live · `ux/pages/simulate/agent/LivePage.tsx` | ux/pages/simulate/agent/LivePage.tsx:74-76은 고정 배지 |
| 6-2 | 진행 중 live 실행 id `liveRun.liveRunId` (상단 LIVE 표시) | pages/main/AgentConsolePage.tsx:59 (→ components/AppHeader.tsx:81) | /simulate/agent/:caseKey/live · `ux/pages/simulate/agent/LivePage.tsx` | 3단계에는 저장 run id(ux/pages/simulate/agent/LivePage.tsx:78)와 상태 알약만 있음. ux/shell/TopBar.tsx:28은 실행 가능 여부만 보임 |
| 6-2 | 운영자 기록 수와 최근 기록과 같은 결과 수 `agentCase.recorded.runs`·`sameAsLatest` | pages/main/MeasureNote.tsx:40-43 | /simulate/agent/:caseKey/live · `ux/pages/simulate/agent/LivePage.tsx` |  |
| 6-2 | 에이전트 토큰 수 `agentRun.cost.agent.totalTokens` | pages/main/AgentConsolePage.tsx:116-117 | /simulate/agent/:caseKey/live · `ux/pages/simulate/agent/LivePage.tsx` |  |
| 6-2 | 판정 모델 호출 합계 `agentRun.cost.decisions[].calls` | pages/main/AgentConsolePage.tsx:116-118 | /simulate/agent/:caseKey/live · `ux/pages/simulate/agent/LivePage.tsx` | ux/pages/runs/detailTabs.tsx:471-474는 한 요청의 호출 목록이고 실행 전체 합계가 아님 |
| 6-7 | 보내는 쪽 칩 `agentCase.sender` | pages/main/AgentResultPage.tsx:51 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx` |  |
| 6-7 | 기준 실행의 저장 시각과 경과 시간 `agentSnapshot.capturedAt` | pages/main/AgentResultPage.tsx:71 (→ components/main/SnapshotBadge.tsx:21-24) | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx` | 새 4단계는 실행이 없으면 '결과 없음'(ux/pages/simulate/agent/ResultPage.tsx:71-82)으로 끝나고, 기준 스냅샷으로 대신 보여 주지 않음 |
| 6-7 | 통제별로 나간 것: 문서·항목·고객 기록·권한 변경 `proof.controls[c].documents·items·records·changes` | pages/main/AgentResultParts.tsx:76-81 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx` | 네 값의 합만 보임(ux/pages/simulate/agent/ResultPage.tsx:245, :259) |
| 6-7 | 운영자 기록 수와 같은 결과 수 `recorded.runs`·`sameAsLatest` | pages/main/MeasureNote.tsx:40-43 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx` |  |
| 6-3 | 보내는 쪽 칩 `agentCase.sender` | pages/main/AgentReasonPage.tsx:84 | /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx` |  |
| 6-3 | 기준 실행의 저장 시각 `agentSnapshot.capturedAt` | pages/main/AgentReasonPage.tsx:95 (→ components/main/SnapshotBadge.tsx:21-24) | /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx` |  |
| 6-3 | 정상 짝 기록 실행: 요청 수·기존 넷이 모두 전달한 수·Contexa 전달 수 `agentRun(normalRecorded.runId).steps[]` | pages/main/AgentReasonPage.tsx:210-214 | /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx` |  |
| 6-3 | 정상 짝 실행이 일을 마쳤는지 `normalRun.finalAnswer` 유무 | pages/main/AgentReasonPage.tsx:216 | /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx` |  |
| 6-3 | 정상 짝 실행 run id `agentCase.normalRecorded.runId` | pages/main/AgentReasonPage.tsx:217 (→ components/main/SourceBadge.tsx:36) | /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx` |  |
| 6-3 | 운영자 기록 수와 같은 결과 수 `recorded.runs`·`sameAsLatest` | pages/main/MeasureNote.tsx:40-43 | /runs/:runId?tab=evidence · `ux/pages/runs/detailTabs.tsx` |  |
| 6-4 | reuse·other가 2xx일 때 전달 건수: confirmation.reuse·other.deliveredItems | pages/main/AgentConfirmPage.tsx:210,214(→pages/main/AgentConfirmPage.tsx:358) | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | 새 문구 ux.agentResult.confirm.reuse·other와 DP 문구에 건수 자리가 없음. 설계상 재사용은 거부되므로 보통은 비어 있음 |
| 6-4 | 인가 기록 번호: agentConfirmation.authorizationId / confirmation.after.authorizationId | pages/main/AgentConfirmPage.tsx:279 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` |  |
| 6-4 | 요청 회사 시각 stop.companyTime | pages/main/AgentConfirmPage.tsx:270 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | 에이전트 화면 어디에서도 companyTime을 그리지 않음 |
| 6-4 | 위임 끝 시각과 요청 시각 비교 (run.companyTime+validUntilMinutes, stop.companyTime) | pages/main/AgentConfirmPage.tsx:225-228 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | ReviewPage에는 상대 시각("N시간 전까지")과 '기간 종료' 배지만 있고 실제 시각은 없음 |
| 6-4 | 답 없는 이유(저장 run.confirmation.reason: NO_CONFIRMATION·EXPIRED…, null이면 NOT_ASKED) | pages/main/AgentConfirmPage.tsx:304 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | ux/pages/simulate/agent/ResultPage.tsx:316은 '응답 없음'만 보임 |
| 6-4 | 실행 출처(본인 실행 / 운영자 기록 1회) tried.runId와 agentCase.recorded.runId | pages/main/AgentConfirmPage.tsx:128-131, pages/main/MeasureNote.tsx:37 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | 새 결과 화면은 본인 실행(또는 ?run=)만 보이고 출처를 말하지 않음 |
| 6-4 | 저장 스냅숏 capturedAt (T5-confirm-approve로 대체할 때) | pages/main/AgentConfirmPage.tsx:126→components/main/SnapshotBadge.tsx:21-24 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | 새 결과 화면은 스냅숏으로 대체하지 않고 '실행 기록 없음'(ux/pages/simulate/agent/ResultPage.tsx:77)을 보임 |
| 6-4 | 운영자 기록 횟수 recorded.runs, 같은 결과 횟수 recorded.sameAsLatest | pages/main/MeasureNote.tsx:39-44 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | sameAsLatest를 그리는 곳이 없음 |
| 6-4 | 요청 주체 칩 agentCase.sender→subject | components/main/MainScreen.tsx:180 (pages/main/AgentConfirmPage.tsx:108) | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | ux에서 sender·SubjectChip을 그리는 곳이 없음 |
| 6-5 | 요청 주체 칩 agentCase.sender | components/main/MainScreen.tsx:180 (pages/main/AgentEndPage.tsx:42) | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | 24와 같은 필드 |
| 6-5 | 확인 뒤 상태 run.confirmation.after.status (두 열) | pages/main/AgentEndPage.tsx:89-93 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | after.status·statusAfter를 그리는 곳이 없음. 신고 쪽은 고정 문구 reportedValue만 있음 |
| 6-5 | 두 스냅숏 capturedAt | pages/main/AgentEndPage.tsx:83→components/main/SnapshotBadge.tsx:21-24 | /simulate/agent/:caseKey/result · `ux/pages/simulate/agent/ResultPage.tsx`, `ux/simulate/DelegatorPanel.tsx` | 신고 기록은 run id만 있음(ux/pages/simulate/agent/ResultPage.tsx:334) |
| 6-6 | 요청 주체 칩 agentCase.sender | components/main/MainScreen.tsx:180 (pages/main/AgentBurstPage.tsx:29) | /simulate/surge · `ux/pages/simulate/surge/SurgePage.tsx` | 새 화면에는 위임 사슬(ux/pages/simulate/surge/SurgePage.tsx:166)만 있음 |
| 6-6 | 내 실행 burst.deliveredAfterFirstStop | pages/main/BurstLive.tsx:149-154 | /simulate/surge · `ux/pages/simulate/surge/SurgePage.tsx` | 새 ROWS(ux/pages/simulate/surge/SurgePage.tsx:312)에서 빠짐 |
| 6-6 | 내 실행 burst.firstStopStep | pages/main/BurstLive.tsx:155-158 | /simulate/surge · `ux/pages/simulate/surge/SurgePage.tsx` |  |
| 6-6 | M41A 끔·켬 deliveredAfterFirstStop | pages/main/AgentBurstPage.tsx:96-101 | /simulate/surge · `ux/pages/simulate/surge/SurgePage.tsx` |  |
| 6-6 | M41A 끔·켬 firstStopStep | pages/main/AgentBurstPage.tsx:104-106 | /simulate/surge · `ux/pages/simulate/surge/SurgePage.tsx` |  |
| 6-6 | M41A 켬 실행의 요청별 타임라인(on.run.steps: 경로, 5개 통제 결과, 묶음 건수·자체 판정·모델 호출) | pages/main/AgentTimeline.tsx:54-55,69-71,98-108 (pages/main/AgentBurstPage.tsx:113-115) | /simulate/surge · `ux/pages/simulate/surge/SurgePage.tsx` | 스냅숏 run id는 ux/pages/simulate/surge/SurgePage.tsx:375에 CodeChip으로 보이지만 링크가 아님 |
| 6-6 | M41T·M41X 끔 요청·전달·분석 중 거부, 끔·켬 거부·자체 판정 | pages/main/AgentBurstPage.tsx:99-100 | /simulate/surge · `ux/pages/simulate/surge/SurgePage.tsx` | OtherBursts에는 켬 값과 모델 호출만 있음 |
| 6-6 | M41T·M41X 끔·켬 deliveredAfterFirstStop·firstStopStep | pages/main/AgentBurstPage.tsx:99-100,104-106 | /simulate/surge · `ux/pages/simulate/surge/SurgePage.tsx` |  |
| 6-6 | 세 몰림 켬 스냅숏 capturedAt | pages/main/AgentBurstPage.tsx:84→components/main/SnapshotBadge.tsx:21-24 | /simulate/surge · `ux/pages/simulate/surge/SurgePage.tsx` | 새 화면에는 M41A run id 두 개만 있음(ux/pages/simulate/surge/SurgePage.tsx:375) |
| 3-1 | 그 측정 실행의 직원 이름: `labOptions.employees[cases[A6T].conditions.employee]` (person.* / displayName) | pages/main/EvidenceMapPage.tsx:53,200 | /engine?tab=flow · `ux/pages/engine/EnginePage.tsx` | 새 문구 `ux.engine.learning.other` = "비교 · 정상 업무 측정 실행"에 이름이 들어가지 않음 |
| 3-2 | 줄 출처 등급 `facts.blocks[].facts[].source` (HOST · LEARNED · COMPUTED · INFERRED · UNTRUSTED) | pages/main/EvidencePromptPage.tsx:163-165 | /engine?tab=prompt · `ux/pages/engine/EnginePage.tsx` |  |
| 3-3 | 값 출처(모델이 낸 값 / 내지 않음): `recorded.fieldProvenance.*` | pages/main/VerdictCard.tsx:139-142 | /runs/:runId?tab=response · `ux/pages/runs/detailTabs.tsx` |  |
| 3-3 | 불리한 조건 충족 수: `anatomy.juxtaposition.{adverseMet,adverseChecked}` | pages/main/EvidenceVerdictPage.tsx:88 | /runs/:runId?tab=response · `ux/pages/runs/detailTabs.tsx` |  |
| 7-2 | 프롬프트에서 달라진 줄: `/api/lab/runs/{id}/delta` steps[1].changed[].label / before[] / after[] | `pages/main/ChangePage.tsx:273-299` | /compare?tab=change · `ux/pages/compare/ComparePage.tsx` | 아래 "없음" 참조 |
| 7-2 | 비교한 나머지 같은 줄 수: delta steps[1].unchangedLines | `pages/main/ChangePage.tsx:304-307` | /compare?tab=change · `ux/pages/compare/ComparePage.tsx` | 아래 "없음" 참조 |
| 8-2 · O-adopt | 판정 분포 `benchmark.engine.actions.{ALLOW,CHALLENGE,ESCALATE,BLOCK}` | `pages/main/OpsStrip.tsx:42` | /adopt · `ux/pages/adopt/AdoptPage.tsx` | /metrics(ux/pages/metrics/MetricsPage.tsx:174,326)는 출처가 다름. /api/stats `engineActions`(데모 자체 판정) |
| 8-2 · O-adopt | 판단 못 한 요청 `benchmark.engine.unresolved` / `decisions` | `pages/main/OpsStrip.tsx:78-79` | /adopt · `ux/pages/adopt/AdoptPage.tsx` | 비슷한 `unresolvedRuns`(ux/pages/validation/OtherTabs.tsx:289 "판정 실패 n회")는 실행 단위라 다른 값 |
| M-learned | 사무실 네트워크 표시 `labOptions.employees[].officeNetwork` | pages/intro/LearnedPage.tsx:65 | /engine?tab=baseline · `ux/pages/engine/EnginePage.tsx` | 네트워크 값만 보이고 "사무실 네트워크" 표시는 없음 |
| M-learned | 프로젝트 `baseline.taught.projects` (키 목록) | pages/intro/LearnedPage.tsx:79 (54) | /engine?tab=baseline · `ux/pages/engine/EnginePage.tsx` |  |
| M-learned | 통과 수 `baseline.allowed` | pages/intro/LearnedPage.tsx:99 | /engine?tab=baseline · `ux/pages/engine/EnginePage.tsx` | 새 문구 "보낸 {{sent}}건 중 허용된 것"에는 learned 수만 들어감 |
| M-learned | `baseline.hours.personalBaselineStatus` | pages/intro/LearnedPage.tsx:114 | /engine?tab=baseline · `ux/pages/engine/EnginePage.tsx` | 후보는 있으나 확인 안 함 (아래 참고) |
| M-learned | `baseline.hours.roleScopeState` (+PROVISIONAL 안내) | pages/intro/LearnedPage.tsx:119-121 | /engine?tab=baseline · `ux/pages/engine/EnginePage.tsx` | 후보는 있으나 확인 안 함 (아래 참고) |
| M-learned | `baseline.hours.normalAccessHours` | pages/intro/LearnedPage.tsx:127 | /engine?tab=baseline · `ux/pages/engine/EnginePage.tsx` | 후보는 있으나 확인 안 함 (아래 참고) |
| M-learned | 학습 요청 표 `baseline.requests[]` (no, companyTime, path, items, finalAction, identityCheckPassed) | pages/intro/LearnedPage.tsx:150-162 | /engine?tab=baseline · `ux/pages/engine/EnginePage.tsx` |  |
| M-stack | 대기 순번·남은 대기 시간 queuePosition·queueWaitSeconds | pages/try/StackPage.tsx:256-262→components/StateScreen.tsx:101,105 | /simulate/surge?tab=repeat · `ux/pages/simulate/surge/SurgePage.tsx` | grep하면 agent·person LivePage에만 있음 |
| M-stack | 실행 실패·만료 (live.status FAILED·EXPIRED) | pages/try/StackPage.tsx:246 (guide pages/try/StackPage.tsx:205) | /simulate/surge?tab=repeat · `ux/pages/simulate/surge/SurgePage.tsx` | RepeatTab에 실패 안내가 없음 |
| M-timing | 결과 낱말 `measured(A3·A3A·A3T·A3TA).results/allSame` (+제목 선택) | pages/try/timing/CompareScreen.tsx:84 (128) | /engine?tab=flow · `ux/pages/engine/EnginePage.tsx` | 실행 한 건의 결과는 ux/pages/runs/RunDetailPage.tsx:103 EvalBadge로만 보임 |
| M-timing | 정상 업무 응답 범위 `measured(A3T).responseMs` (동기 방식의 대가), `measured(A3TA).responseMs` | pages/try/timing/CompareScreen.tsx:79, pages/try/timing/WhenScreen.tsx:83 | /engine?tab=flow · `ux/pages/engine/EnginePage.tsx` | 적용 시점 카드는 A3, A3A만 보임 |
| M-follow | 시연용 강제 차단 `latestRelease.forcedAction` | pages/try/ReleaseRecord.tsx:52-55, 77-79 | /engine?tab=flow · `ux/pages/engine/EnginePage.tsx` |  |
| M-follow | 해제 단계 시각 `release.blocked_at·code_requested_at·verified_at·requested_at·approved_at·reissue_sent_at` (+날짜) | pages/try/ReleaseRecord.tsx:65, 71 | /engine?tab=flow · `ux/pages/engine/EnginePage.tsx` | Recovery.tsx에는 단계 표시만 있고 시각은 없음 |
| M-follow | 해제 실행 배지 `latestRelease.runId` | pages/try/ReleaseRecord.tsx:144 (components/main/SourceBadge.tsx:36) | /engine?tab=flow · `ux/pages/engine/EnginePage.tsx` |  |
| L-case | LabOptions.employees[key=conditions.employee].displayName, .role | pages/lab/LabCasePage.tsx:25 | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` | 이름은 ux/pages/simulate/person/ReviewPage.tsx:112에서 S13·S13T·S16만 보임. 역할은 어디에도 없음 |
| L-change | employees[].displayName · role | pages/lab/LabChangePage.tsx:92 | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` | G-07과 같음 |
| L-change | 요청이 여러 개인 시나리오의 conditions.items 원래 값 | pages/lab/LabChangePage.tsx:104 | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` | 새 화면은 바꿀 수 있는 조건만 나열(STEPS_FIXED라 items 빠짐) |
| L-change | LabCase.requests.length(요청 n개, n/total의 total) | pages/lab/LabChangePage.tsx:159 | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` | ux/pages/simulate/policy/ComposeTab.tsx:139는 "여러 개"라는 사실만, 개수 n 없음 |
| L-before | 충족된 규칙 이름(minimumRules.rules[].code, met=true) | pages/lab/LabBeforePage.tsx:21,43 | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` | 새 화면은 "해당"만 보이고 어느 규칙인지는 없음 |
| L-send | LiveRunView.queuePosition, .queueWaitSeconds | pages/lab/LabSendPage.tsx:255-259 | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` | ux/pages/simulate/person/LivePage.tsx:226은 사람 흐름 실행에만 해당 |
| L-send | layers[].elapsedMs(초), layers[].deliveredItems, steps[].streams.delivered/total | pages/lab/LabSendPage.tsx:271-287 (pages/try/steps/LiveRunBar.tsx:119-161) | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` | Contexa를 지난 반출 합계만 6단계 exposedItems로 보임 |
| L-send | decisionWait.remainingSeconds | pages/lab/LabSendPage.tsx:284 | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` |  |
| L-send | 끝난 확인 결과 challenge.stage = NO_MAILBOX·ABANDONED | pages/lab/LabSendPage.tsx:304-308 | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` | ux/simulate/Recovery.tsx:51이 null을 돌려줌. DONE·CANCELLED·EXPIRED·FAILED는 보임 |
| L-result | Versus.changedConditions(바뀐 조건 이름·개수) | pages/lab/LabResultPage.tsx:176 (38-44) | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` | 주소에 담긴 바꾼 조건만 3단계 부제(ux/pages/simulate/policy/ComposeTab.tsx:226)에 보임 |
| L-result | RecentLabRun.callRight | pages/lab/LabResultPage.tsx:222 | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` |  |
| L-result | LabDelta(available/reason/steps[].passed·notCompared·notLookedUp·sameAsBase) | pages/lab/LabResultPage.tsx:262 | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` |  |
| L-result | 평가 창: LabOptions.assessmentReasons, 판정된 단계, PeerAssessments(assessments/assessors/verdicts/reasons/delayHours) | pages/lab/LabResultPage.tsx:264 (components/assessment/AssessPanel.tsx:102-115,150-170) | /simulate/policy?tab=compose · `ux/pages/simulate/policy/ComposeTab.tsx` | ux/pages/validation/OtherTabs.tsx:459-461은 전체 합계만 |
| L-rules | RuleChange.before | pages/lab/LabRulesPage.tsx:298 | /simulate/policy?tab=threshold · `ux/pages/simulate/policy/PolicyPage.tsx` | 참/거짓이면 now의 반대로 추론할 수는 있음 |
| L-rules | 바뀐 상황 0개(changed 비어 있음) | pages/lab/LabRulesPage.tsx:287 | /simulate/policy?tab=threshold · `ux/pages/simulate/policy/PolicyPage.tsx` | ux/pages/simulate/policy/PolicyPage.tsx:266은 1개 이상일 때만 그림 |
| L-agent | AgentCaseView.sender(사례별 주체 칩) | pages/lab/LabAgentPage.tsx:96 | /simulate/policy?tab=agent · `ux/pages/simulate/policy/AgentPolicyTab.tsx` |  |
| L-agent | LiveConfig.agentRunPoints | pages/lab/LabAgentPage.tsx:76 | /simulate/policy?tab=agent · `ux/pages/simulate/policy/AgentPolicyTab.tsx` |  |
| L-agent | proof.workNeeds | pages/main/AgentResultParts.tsx:42 | /simulate/policy?tab=agent · `ux/pages/simulate/policy/AgentPolicyTab.tsx` | ux/pages/simulate/agent/ResultPage.tsx:226은 흐름 실행에만 해당 |
| L-agent | proof.controls[통제].documents/items/records/changes | pages/main/AgentResultParts.tsx:76-81 | /simulate/policy?tab=agent · `ux/pages/simulate/policy/AgentPolicyTab.tsx` | 표에는 D 건수 열만 있음(ux/simulate/AgentParts.tsx:227). ux/pages/simulate/agent/ResultPage.tsx:245는 흐름 실행에만 해당 |
| L-agent | proof.controls[통제].beyondNeed | pages/main/AgentResultParts.tsx:83 | /simulate/policy?tab=agent · `ux/pages/simulate/policy/AgentPolicyTab.tsx` | ux/pages/simulate/agent/ResultPage.tsx:260은 흐름 실행에만 해당 |
| L-agent | 반복 요청 묶음 요약(count, withVerdict, decision.model_calls 합) | pages/main/AgentTimeline.tsx:98-108 | /simulate/policy?tab=agent · `ux/pages/simulate/policy/AgentPolicyTab.tsx` | SurgePage는 몰아치기 사례 전용 |
| L-agent | LiveConfig.liveTicketsLeft | pages/lab/DelegationEditPanel.tsx:129 | /simulate/policy?tab=agent · `ux/pages/simulate/policy/AgentPolicyTab.tsx` | ux/pages/simulate/agent/ReviewPage.tsx:95, ux/pages/simulate/surge/SurgePage.tsx:137은 0일 때 이유 문구로만 씀 |
| B-summary | 점별 결과 중 `PASSED_AFTER_CHECK`(추가 인증 뒤 허용) 구분 | pages/benchmark/charts/RunCells.tsx:17, 89 | /validation?tab=summary · `ux/pages/validation/ValidationPage.tsx` | 새 점은 PASSED와 같은 모양·같은 낱말 |
| B-cases · B-case | 점별 결과 중 `PASSED_AFTER_CHECK` 구분 | pages/benchmark/charts/RunCells.tsx:17, 89 | /validation?tab=scenarios · `ux/pages/validation/ScenariosTab.tsx` | 12행과 같은 원인 |
| B-limits | 점별 결과 중 `PASSED_AFTER_CHECK` 구분 (정상 업무 쪽) | pages/benchmark/charts/RunCells.tsx:17, 89 | /validation?tab=limits·method · `ux/pages/validation/OtherTabs.tsx` | 12행과 같은 원인 |
| O-videos | 다루는 화면 목록 static:guides.json.<id>.screens (이름·링크) | `pages/GuidesPage.tsx:101-113` | /tour · `ux/pages/tour/TourPage.tsx` | 이동 링크 성격. 옛 주소는 없어짐 |
| O-videos | 묶음 머리글 guides.group.S/H/A/C (static guides.json, route.json track) | `pages/GuidesPage.tsx:68` | /tour · `ux/pages/tour/TourPage.tsx` | 분류 머리글이라 사실성이 약함 |
| O-privacy | 진행 위치 세부 항목(경로, 그룹, 단계, 확인한 차이, 처음 연 그룹) | `content/policies.ts:42` | /privacy · `ux/pages/privacy/PrivacyPage.tsx` | "보내기 전 결과 예상"만 expected 행(48-50)에 있음 |
| O-privacy | 판단 평가(보낸 요청, 고른 답과 이유, 시각): 다른 방문자에게 건수로만 보임, 보관 | `content/policies.ts:47-49` | /privacy · `ux/pages/privacy/PrivacyPage.tsx` | ux/pages/validation/OtherTabs.tsx:459-461의 평가 건수는 정책 문장이 아님 |
| O-privacy | 상황별 예측: 방문자 식별자와 함께 삭제 | `content/policies.ts:76` | /privacy · `ux/pages/privacy/PrivacyPage.tsx` | external.old 나열에 빠져 있음 |
| O-replay | 장면 상황 문장 `replay.scenes[].sentence[lang]` | `pages/ReplayPage.tsx:116` | /runs (공개 녹화 실행) · `ux/pages/runs/RunsPage.tsx` |  |
| O-replay | 정상 실행에서 기존 통제가 잘못 막은 표시 `runScore.correct[A~C2]=false`(NORMAL) | `pages/ReplayPage.tsx:333` | /runs (공개 녹화 실행) · `ux/pages/runs/RunsPage.tsx` | D만 EvalBadge의 falsePositive로 보임(:367) |
| O-replay | 지금 측정에 속하는지와 그 측정 날짜 `measured(case).list[runId].startedAt` | `pages/ReplayPage.tsx:206`, `:215` | /runs (공개 녹화 실행) · `ux/pages/runs/RunsPage.tsx` |  |
| O-replay | 추가 인증 뒤 통과 수 `measured.results.PASSED_AFTER_CHECK` | `pages/ReplayPage.tsx:157→226` | /runs (공개 녹화 실행) · `ux/pages/runs/RunsPage.tsx` | 통제별 전체 집계만 있음(ValidationPage:554) |
| O-detail | 에이전트 주체 종류 `agentRun.sender`(위임·자율·세션) | components/detail/DecisionDetail.tsx:54 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 머리. 새 쪽은 "AI 에이전트 요청" 한 가지로만 보임 |
| O-detail | 보내는 도중 적용 `stepResult.layers[D].evidence.timing=MID_RESPONSE` | components/detail/SummaryTab.tsx:105 (값 :67) | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 요약 |
| O-detail | 정답 출처 `truth.truthSource` | components/detail/SummaryTab.tsx:136 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 여러 탭(components/detail/AnswerTab.tsx:31) |
| O-detail | 추가 인증 결과 `anatomy.recovery.challenge.reason`/`answered` | components/detail/SummaryTab.tsx:195 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 여러 탭(components/detail/ProcessTab.tsx:94) |
| O-detail | 회사 기록 줄 수 `juxtaposition.companyFacts.length` | components/detail/ProcessTab.tsx:61 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 과정 |
| O-detail | 과거 판정 문서 수 `context.rag.ragAuthorizedDocumentCount` | components/detail/ProcessTab.tsx:65 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 과정 |
| O-detail | 프롬프트 만든 시간 `timings.promptBuildMs` | components/detail/ProcessTab.tsx:68 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 과정 |
| O-detail | 심층 분석 여부 `timings.events[type=LAYER2_COMPLETE]` | components/detail/ProcessTab.tsx:76 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 과정 |
| O-detail | 차단 풀기 요청 `anatomy.recovery.release` | components/detail/ProcessTab.tsx:99 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 과정 |
| O-detail | 회사 기록 걸림 `received.companyAdverse[policysatisfied].values`, `company.approvalRequired`, `businessFacts[NO_APPROVAL]` | components/inside/Comparison.tsx:198 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 받은 입력. 엔진 흐름 탭 칩은 걸림 표시가 없음 |
| O-detail | 결재 불필요 `received.company.approvalRequired=false`+`businessFacts NO_APPROVAL` | components/detail/ReceivedTab.tsx:91 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 받은 입력 |
| O-detail | 데모 추가 인증 집계 `teasers[CHALLENGE_OUTCOMES].values.total/outcomes` | components/detail/RulesTab.tsx:124 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 규칙(:131-142 결과별) |
| O-detail | 받은 규칙 줄과 충족 표시 `exchanges.calls[].systemPrompt` 줄, `received.minimumRules.rules[].met` | components/detail/RulesTab.tsx:92 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 규칙(:93-97) |
| O-detail | 공식 검사 리본 `quality.ribbon.withSource/facts`, `factAccuracy.matched/total`, `contradictions`, `unknown` | components/detail/PromptTab.tsx:213 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 프롬프트(:213-241) |
| O-detail | 불리 조건 `juxtaposition.adverseChecked/adverseMet`, `coreAdverseLabels[met].label` | components/detail/PromptTab.tsx:250 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 프롬프트(:250-254) |
| O-detail | 사실 출처 등급 `facts[].source` | components/detail/PromptTab.tsx:301 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 프롬프트 |
| O-detail | 근거 충분도 `facts[].sufficiency.grade/causes/cautions` | components/detail/PromptTab.tsx:312 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 프롬프트 |
| O-detail | 다른 번들 비교 `otherBundle.lines.*`, `current/other.bundle.version`·`runId`·`systemPromptLines`·`userPrompt` | components/detail/PromptTab.tsx:356 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 프롬프트(:356-392) |
| O-detail | 상황 정의 해시 `truth.scenarioSha256` | components/detail/AnswerTab.tsx:41 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 정답 |
| O-detail | 공격 기법 `recorded.mitre` | components/detail/OriginalTab.tsx:159 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본 |
| O-detail | 인용 증거 종류 `recorded.evidenceRefs` | components/detail/OriginalTab.tsx:166 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본 |
| O-detail | 심층 분석 사유 `timings.events[LAYER2_COMPLETE].reasoning` | components/detail/OriginalTab.tsx:184 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본 |
| O-detail | 출력 토큰 `interpretation.calls[].completionTokens` | components/detail/OriginalTab.tsx:198 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본 |
| O-detail | 호출별 걸린 시간 `interpretation.calls[].elapsedMs` | components/detail/OriginalTab.tsx:202 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본 |
| O-detail | 원문 물리 줄 수 `promptLines.systemPhysical/userPhysical` | components/detail/OriginalTab.tsx:207 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본. 내용 줄 수(system/user)는 :427에 있음 |
| O-detail | 호출 실패 `interpretation.calls[].success/failure` | components/detail/OriginalTab.tsx:215 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본 |
| O-detail | 보낸 규칙 원문 `exchanges.calls[].systemPrompt` | components/detail/OriginalTab.tsx:220 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본 |
| O-detail | 보낸 상황 원문 `exchanges.calls[].userPrompt` | components/detail/OriginalTab.tsx:220 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본. 프롬프트 탭에는 사실 줄만 있음 |
| O-detail | 번들 해시·선택 출처 `quality.bundle.hash/selectionSource` | components/detail/OriginalTab.tsx:286 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본 |
| O-detail | 어긋난 줄 상세 `checks[].mismatches[].factId/entry/line/expected/actual/reason` | components/detail/OriginalTab.tsx:352 | /runs/:runId · `ux/pages/runs/RunDetailPage.tsx`, `ux/pages/runs/detailTabs.tsx` | 원본 |

## 4. 확인 못 한 행

- 없습니다. 59행 모두 옛 화면을 찾았고 대조했습니다.

## 5. 함께 본 점

판정과 별도로, 대조하다가 본 차이입니다. 모두 줄을 열어 확인했습니다.

- 4-4는 옛 화면과 새 위치의 사례가 다릅니다. 옛 `pages/main/CheckPage.tsx:28`은 `CHECK_CASE = 'S14'`(출장 엔지니어, 요청 3개)를 그리고, 새 위치 /simulate/person/S13T/result는 S13T(요청 1개)를 그립니다. 4-4 판정은 같은 필드를 그리는지로 했습니다. S14 실행은 /simulate/policy?tab=compose와 /runs/:runId에서만 볼 수 있습니다.
- M-learn · M-learned: 기준선 탭(`ux/pages/engine/EnginePage.tsx:496-512`)은 기준 실행의 사례(`MAIN = 'S13'`, `EnginePage.tsx:52-59`)의 직원 기준선을 보입니다. 그래서 기본으로 S13의 직원이 나오고, 옛 화면과 기획안 새 제목의 "관리자 A"(A3)는 `?run=`으로 A3 실행을 줄 때만 나옵니다.
- 실행별 점에서 "추가 인증 뒤 허용"(`PASSED_AFTER_CHECK`)이 "허용"과 구분되지 않습니다. `ux/simulate/person.ts:231-233`의 `evalOf`가 둘을 `normal`로 합칩니다(B-summary · B-cases · B-limits · O-replay의 없음 항목).
- 정책 시뮬레이터 시나리오 목록(`ux/pages/simulate/policy/ComposeTab.tsx:114-117`)은 THREAT가 아닌 시나리오를 모두 정상 업무 묶음에 넣습니다. 정답이 정해지지 않은(UNCERTAIN) 시나리오도 정상 업무로 보입니다(L-case G-05).
- 기획안 새 제목 중 화면에 그대로 보이지 않는 것: "위임자 승인 · 요청 1회 처리"는 `ko.json`에 없습니다. "동일 요청 60건 동시 유입"은 `ux.surge.case.M41A`(ko.json:6600)로 있지만 `SurgePage.tsx:404`의 다른 몰림 표에서만 쓰여 M41A 자체에는 그려지지 않습니다. "판정 흐름 7단계"는 `EnginePage.tsx:265-267`의 `ux-sr-only` 제목이라 눈에 보이지 않습니다.
- 여러 행에 걸친 같은 빈자리: 에이전트 요청의 주체 칩(`agentCase.sender`, 6-1 · 6-2 · 6-7 · 6-3 · 6-4 · 6-5 · 6-6 · L-agent · O-detail), 운영자 기록 수와 같은 결과 수(`recorded.runs` · `sameAsLatest`), 기준 스냅숏 저장 시각(`capturedAt`), 저장된 최근 해제 기록(`api/follow.ts:44`의 `/api/follow/release`를 `ux/`에서 읽지 않음).
- 제품 투어(`ux/pages/tour/TourPage.tsx:72-76`)의 영상 제목 · 장면 키는 console · agent 두 영상에만 있습니다. 다른 영상이 녹화되면 제목 자리에 id가 보입니다(O-videos 하위 점검 보고).
