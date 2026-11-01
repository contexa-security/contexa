# UC-5 사실 되살림 · A4 묶음 (AI 판정 엔진 · 탐지 방식 비교 · 도입 가이드)

- 날짜: 2026-11-01
- 범위: `uc5-facts-draft.md` 3절 "없음 목록"의 3-1, 3-2, M-learned, M-timing, M-follow, 7-2, 8-2 · O-adopt 행(18개). M-timing의 "제목 선택"은 따로 한 줄로 나눠 19줄입니다.
- 경로 기준: `contexa-showcase/web/src`. 옛 줄은 모두 열어 보고, 새 화면(`ux/`)에서 같은 값이나 같은 값을 담은 다른 필드를 그리는 곳이 없음을 grep으로 다시 확인했습니다.
- 새 낱말: `ux.engine.*` 38개, `ux.compareMenu.mine.*` 5개, `ux.adopt.measured.*` 3개를 `ux_keys_locked.py`로 더했습니다(키 파일: 스크래치 `i8/uc5/A4-keys.json`, 46개 · 기존 키 변경 0).

| 번호 | 사실 | 옛 줄(열어 본 file:line) | 판정 | 새 위치(file:line) 또는 이유 |
|---|---|---|---|---|
| 3-1 | 정상 업무 측정 실행(A6T)의 직원 이름 `labOptions.employees[cases[A6T].conditions.employee]` | `pages/main/EvidenceMapPage.tsx:53, 200` | 되살림 | `ux/pages/engine/EnginePage.tsx:359-364` (/engine?tab=flow "기준선 학습 범위" 둘째 줄 이름표 "비교 · 관리자 A의 정상 업무 측정 실행". A6T 주인공은 adm-a) |
| 3-2 | 프롬프트 줄 출처 등급 `facts.blocks[].facts[].source` | `pages/main/EvidencePromptPage.tsx:163-165` | 되살림 안 함(파일 밖) | /engine?tab=prompt는 `ux/pages/engine/EnginePage.tsx:141`에서 `ux/pages/runs/detailTabs.tsx`의 `PromptTab`을 그대로 그립니다. 출처 등급은 각 줄 옆(`detailTabs.tsx` PromptTab의 줄 `<li>`)에 있어야 하고, 같은 필드가 O-detail 행(`components/detail/PromptTab.tsx:301`)으로 같은 부품에 걸려 있습니다. 엔진 화면에 따로 그리면 그쪽이 고쳐진 뒤 두 번 보이므로, `detailTabs.tsx` PromptTab에 더하는 것이 맞습니다(이 묶음 파일 밖) |
| 7-2 | 프롬프트에서 달라진 줄 `/api/lab/runs/{id}/delta` steps[1].changed[].label · before[] · after[] | `pages/main/ChangePage.tsx:273-299` | 되살림 | `ux/pages/compare/ComparePage.tsx:301, 321-368` (/compare?tab=change 표의 "바꾼 조건" 칸 아래 "프롬프트에서 달라진 줄 자세히". 열 때 델타를 읽음. 서버 순서 그대로, `- 이름: 전` / `+ 이름: 후`. 비교하지 않은 경우는 reason · notCompared 코드를 그대로 보임) |
| 7-2 | 비교한 나머지 같은 줄 수 delta steps[1].unchangedLines | `pages/main/ChangePage.tsx:302-307` | 되살림 | `ux/pages/compare/ComparePage.tsx:360-364` (같은 "자세히" 안. 값이 없으면 줄을 뺌) |
| 8-2 · O-adopt | 판정 분포 `benchmark.engine.actions.{ALLOW,CHALLENGE,ESCALATE,BLOCK}` | `pages/main/OpsStrip.tsx:39-42` | 되살림 | `ux/pages/adopt/AdoptPage.tsx:219, 235-263` (/adopt 연동 절차 탭 "문서 · 저장소" 카드의 판정당 비용 안내 아래 "시나리오 검증 실측 판정 n건 자세히". 응답에 있는 판정만, 옛 순서대로) |
| 8-2 · O-adopt | 판정 실패 `benchmark.engine.unresolved` / `decisions` | `pages/main/OpsStrip.tsx:77-79` | 되살림 | `ux/pages/adopt/AdoptPage.tsx:254-257` (같은 "자세히"의 "판정 실패 n건 / m건". 검증 화면의 `attackUnresolved` · `normalUnresolved`는 실행 단위라 다른 값) |
| M-learned | 사무실 네트워크 `labOptions.employees[].officeNetwork` | `pages/intro/LearnedPage.tsx:65, 220` | 되살림 | `ux/pages/engine/EnginePage.tsx:670-671` (/engine?tab=baseline 키-값 "사무실 네트워크". 화면에서 맞대어 고르지 않고 값을 그대로 보임) |
| M-learned | 학습시킨 프로젝트 `baseline.taught.projects` | `pages/intro/LearnedPage.tsx:54, 79` | 되살림 | `ux/pages/engine/EnginePage.tsx:682-687` (키-값 "학습시킨 프로젝트" · "HX-310 50건". 응답의 건수도 함께) |
| M-learned | 허용 수 `baseline.allowed` | `pages/intro/LearnedPage.tsx:96-101` | 되살림 | `ux/pages/engine/EnginePage.tsx:696-705` ("학습 요청 n건 자세히" 첫 줄: 보낸 · 허용 · 기준선에 학습 건수) |
| M-learned | `baseline.hours.personalBaselineStatus` | `pages/intro/LearnedPage.tsx:114` | 되살림 | `ux/pages/engine/EnginePage.tsx:738-745` ("최근 판정에서 본 학습 상태 자세히", 엔진이 쓴 코드 그대로) |
| M-learned | `baseline.hours.roleScopeState` (+PROVISIONAL 안내) | `pages/intro/LearnedPage.tsx:119-122` | 되살림 | `ux/pages/engine/EnginePage.tsx:746-752` (코드 그대로, PROVISIONAL이면 "업무 범위 학습이 아직 적어 이 상태만으로는 판정하지 않음") |
| M-learned | `baseline.hours.normalAccessHours` | `pages/intro/LearnedPage.tsx:127` | 되살림 | `ux/pages/engine/EnginePage.tsx:753-754` ("자주 본 시각"). 같은 기록의 `observedHours`(초안 판정 "다른 위치", 기준 실행 값이라 실제로는 다른 기록)와 그 판정의 실행 링크(`hours.runId`)도 함께 보임(755-763) |
| M-learned | 학습 요청 표 `baseline.requests[]` (no, companyTime, path, items, finalAction, identityCheckPassed) | `pages/intro/LearnedPage.tsx:150-163` | 되살림 | `ux/pages/engine/EnginePage.tsx:696-737` ("학습 요청 n건 자세히" 안 표: 번호 · 시각(세계 표준시) · 요청 경로 원문 · 건수 · 판정 배지 + "추가 인증 통과") |
| M-timing | 결과 낱말 `measured(A3·A3A·A3T·A3TA).results` / `allSame` | `pages/try/timing/CompareScreen.tsx:71, 84` | 되살림 | `ux/pages/engine/EnginePage.tsx:455-465` (/engine?tab=flow "판정 적용 시점" 각 줄 끝에 서버가 센 결과별 평가 배지 + 횟수. 결과가 둘 이상이면 모두 보여 allSame도 드러남) |
| M-timing | 제목 선택(tradeOffHolds: 네 결과가 맞으면 "두 방식은 장단점이 다릅니다") | `pages/try/timing/CompareScreen.tsx:31-45, 128` | 사실 아님 | 응답 값이 아니라 화면이 네 결과를 보고 고른 문장(화면 쪽 판정). 결과 값 자체는 위 줄에서 되살림 |
| M-timing | 정상 업무 응답 범위 `measured(A3T).responseMs`, `measured(A3TA).responseMs` | `pages/try/timing/CompareScreen.tsx:78-79`, `pages/try/timing/WhenScreen.tsx:83` | 되살림 | `ux/pages/engine/EnginePage.tsx:436-437, 485-493` (같은 카드에 "정상 업무" 묶음: 동기 · 비동기 줄마다 응답 · 판정 · 반출 · 측정 횟수 · 결과. 측정이 없으면 묶음을 뺌) |
| M-follow | 시연용 강제 차단 `latestRelease.forcedAction` | `pages/try/ReleaseRecord.tsx:52-56` | 되살림 | `ux/pages/engine/EnginePage.tsx:574-579` (/engine?tab=flow "판정별 후속 조치" 카드의 "최근 실제 해제 기록 자세히": "시연용 강제 판정 · BLOCK" + "차단 뒤의 해제 과정은 엔진이 실제로 처리한 기록". `/api/follow/release`를 기존 `useLatestRelease`로 읽음) |
| M-follow | 해제 단계 시각 `release.blocked_at · code_requested_at · verified_at · requested_at · approved_at · reissue_sent_at` (+날짜) | `pages/try/ReleaseRecord.tsx:59-71` | 되살림 | `ux/pages/engine/EnginePage.tsx:580-596` (여섯 단계와 `formatUtc` 시각(날짜 포함, 세계 표준시), 없으면 "—". 분 단위로 보이고 원래 값 전체는 `<time title>`에 있음. 옛 화면은 초까지 보였음) |
| M-follow | 해제 실행 배지 `latestRelease.runId` | `pages/try/ReleaseRecord.tsx:143-145` | 되살림 | `ux/pages/engine/EnginePage.tsx:597-599` ("이 해제 실행 · run-…" 링크 → /runs/:runId, 둘째 요청 이후면 `?step=`) |

판정 집계: 되살림 17 · 사실 아님 1 · 이미 있음 0 · 해당 없음 0 · 되살림 안 함(파일 밖) 1.

## 함께 본 점

- 기준선 탭의 사람: `ux/pages/engine/EnginePage.tsx:137`이 `score.data?.scenarioKey ?? MAIN`(`MAIN = 'S13'`, 39줄)의 직원 기준선을 보입니다. 기본 실행(공개 녹화 S13)에서는 "엔지니어 K"가 나오고, 기획안 새 제목의 "관리자 A"는 `?run=`으로 A3 계열 실행을 줄 때만 나옵니다. 기본값은 바꾸지 않았습니다.
- 3-2(출처 등급)는 이 묶음 파일 밖(`ux/pages/runs/detailTabs.tsx` PromptTab)에서 되살려야 엔진 화면에도 함께 보입니다. O-detail 행의 같은 필드와 한 번에 처리하는 것이 맞습니다.
- 7-2의 옛 화면은 바꾼 조건과 관련된 줄과 그 밖의 줄을 화면 쪽 목록(`pages/main/mainCases.ts:144-160`)으로 나눠 접었습니다. 새 쪽은 나누지 않고 서버 순서대로 모두 보입니다.

## 실행한 검사 (contexa-showcase/web)

| 검사 | 결과 |
|---|---|
| `npx tsc -p tsconfig.app.json --noEmit --incremental false` | 이 묶음 파일 오류 0. 종료 코드 2는 다른 에이전트가 고치는 중인 파일(`ux/pages/runs/detailTabs.tsx` 7건, `ux/pages/simulate/policy/AgentPolicyTab.tsx` 2건)의 오류 |
| `npx eslint src/ux/pages/engine src/ux/pages/compare src/ux/pages/adopt` | 통과(0) |
| `npx stylelint` Engine · Compare · Adopt `.module.css` | 통과(0) |
| `npx vitest run src/ux/pages/engine src/ux/pages/compare src/ux/pages/adopt src/ux/ux-wording.test.ts` | 4파일 78개 통과(engine 11 · compare 5 · adopt 9 · wording 53). 새 테스트 8개: engine 6(3-1 이름, M-timing 정상 업무 · 결과, 정상 업무 측정 없음, M-follow 해제 기록, 해제 기록 없음, M-learned 다섯 사실), compare 1(7-2 달라진 줄 · 같은 줄 수 · 비교 없음 사유), adopt 1(8-2 판정 분포 · 판정 실패) |
| `python -I ux_keys_locked.py A4-keys.json --check` | ko · en 모두 0 added · 0 changed(46개 반영 확인) |
