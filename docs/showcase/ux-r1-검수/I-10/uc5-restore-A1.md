# UC-5 사실 되살림 A1 — 판정 상세와 판정 이력

- 날짜: 2026-11-01
- 범위: 초안 `uc5-facts-draft.md` 3절 "없음 목록" 가운데 O-detail(30) · 2-4(1) · 3-3(2) · 5-3(2) · 6-3(6) · O-replay(4), 모두 45개
- 방법: 옛 줄을 하나씩 열어 방문자에게 보인 데이터 값인지 확인하고, `src/ux` 전체를 필드 이름으로 다시 찾아 새 화면에 없음을 확인한 뒤 되살렸습니다.
- 경로 기준: 옛 줄은 `contexa-showcase/web/src/`, 새 위치는 `contexa-showcase/web/src/ux/pages/runs/`(`detailTabs.tsx`, `RunDetailPage.tsx`, `RunsPage.tsx`)와 `src/ux/runs/runLog.ts`입니다.
- 집계: 되살림 44 · 해당 없음 1 · 사실 아님 0 · 이미 있음 0

| 번호 | 사실 | 옛 줄(열어 본 file:line) | 판정 | 새 위치(file:line) 또는 이유 |
|---|---|---|---|---|
| O-detail · 1 | 에이전트 주체 종류 `agentRun.sender`(위임 · 단독 · 세션) | components/detail/DecisionDetail.tsx:38-42, :54 | 되살림 | RunDetailPage.tsx:98-104, :118 머리 배지 "AI 에이전트 요청 · 위임 에이전트"(모르는 값은 기록 그대로) |
| O-detail · 2 | 보내는 도중 적용 `layers[D].evidence.timing=MID_RESPONSE` | components/detail/SummaryTab.tsx:66-69, :104-106 | 되살림 | detailTabs.tsx:91, :118 요약 "적용 · 판정 시간"(detailWords.ts `appliedKey`) |
| O-detail · 3 | 정답 출처 `truth.truthSource` | components/detail/SummaryTab.tsx:136 | 되살림 | detailTabs.tsx:149-150 요약 "정답 출처" |
| O-detail · 4 | 추가 인증 결과 `recovery.challenge.reason`/`answered` | components/detail/SummaryTab.tsx:192-200 | 되살림 | detailTabs.tsx:228-237 요약 "판정 과정 › 후속 처리" |
| O-detail · 5 | 업무 컨텍스트 줄 수 `juxtaposition.companyFacts.length` | components/detail/ProcessTab.tsx:58-61 | 되살림 | detailTabs.tsx:218-219 판정 과정, :610 판정 근거 업무 컨텍스트 머리(원문 줄 :626-639) |
| O-detail · 6 | 과거 판정 문서 수 `context.rag.ragAuthorizedDocumentCount` | components/detail/ProcessTab.tsx:45, :62-65 | 되살림 | detailTabs.tsx:220-221 판정 과정 "찾은 과거 기록" |
| O-detail · 7 | 프롬프트 만든 시간 `timings.promptBuildMs` | components/detail/ProcessTab.tsx:66-68 | 되살림 | detailTabs.tsx:222-223 판정 과정 |
| O-detail · 8 | 심층 분석 여부 `timings.events[LAYER2_COMPLETE]` | components/detail/ProcessTab.tsx:44, :76 | 되살림 | detailTabs.tsx:226-227 판정 과정 "2차 분석"(LAYER1/LAYER2 완료 사건 기준, 사건 없으면 —) |
| O-detail · 9 | 차단 풀기 요청 `recovery.release` | components/detail/ProcessTab.tsx:98-99 | 되살림 | detailTabs.tsx:234-235 판정 과정 "후속 처리" |
| O-detail · 10 | 회사 기록 걸림 `companyAdverse[policysatisfied]`, `company.approvalRequired`, `businessFacts[NO_APPROVAL]` | components/inside/Comparison.tsx:198 (:284-306) | 되살림 | detailTabs.tsx:437, :573-642 판정 근거 "판정 엔진이 받은 업무 컨텍스트"(걸린 줄에 "불리 조건" 표시) |
| O-detail · 11 | 결재 불필요 `company.approvalRequired=false` + `NO_APPROVAL` | components/detail/ReceivedTab.tsx:77-79, :91 | 되살림 | detailTabs.tsx:625 같은 업무 컨텍스트 아래 한 줄 |
| O-detail · 12 | 데모 추가 인증 집계 `teasers[CHALLENGE_OUTCOMES].total/outcomes/resumed` | components/detail/RulesTab.tsx:73, :119-149 | 되살림 | detailTabs.tsx:239-257 판정 과정 아래 접힌 목록(포털 집계 그대로, 모르는 결과는 기록 이름) |
| O-detail · 13 | 받은 규칙 줄과 충족 표시 `systemPrompt` 줄 + `received.minimumRules.rules[].met` | components/detail/RulesTab.tsx:43-52, :92-97 | 되살림 | detailTabs.tsx:699, :798-855 판정 프롬프트 "최소 판정 규칙"(보낸 줄 원문 · 최소 판정 · 충족). 쉬운 말 풀이는 정적 사전이라 옮기지 않고, 규칙 줄 전체는 응답 원문 탭의 시스템 프롬프트 원문(:958-968)에 있음 |
| O-detail · 14 | 공식 검사 리본 `ribbon.withSource/facts`, `factAccuracy`, `contradictions`, `unknown` | components/detail/PromptTab.tsx:213-241 | 되살림 | detailTabs.tsx:656, :736-791 판정 프롬프트 "프롬프트 검사 수치"(null은 "검사 전") |
| O-detail · 15 | 불리 조건 `adverseChecked/adverseMet`, `coreAdverseLabels[met].label` | components/detail/PromptTab.tsx:248-255 | 되살림 | detailTabs.tsx:774-787 같은 검사 수치(검사한 조건이 0이면 옛 화면처럼 줄 없음) |
| O-detail · 16 | 사실 출처 등급 `facts[].source` | components/detail/PromptTab.tsx:301 | 되살림 | detailTabs.tsx:680-683 사실 줄마다 이름 아래 |
| O-detail · 17 | 근거 충분도 `facts[].sufficiency.grade/causes/cautions` | components/detail/PromptTab.tsx:310-314 | 되살림 | detailTabs.tsx:689-691(`sufficiencyWords` :709-731) 값 아래 |
| O-detail · 18 | 다른 번들 비교 `otherBundle.lines`, 양쪽 `bundle.version` · `runId` · `systemPromptLines` · `userPrompt` | components/detail/PromptTab.tsx:343-397 | 되살림 | detailTabs.tsx:700, :862-918 판정 프롬프트 "다른 번들로 보낸 같은 시나리오"(포털이 없다고 하면 안 보임) |
| O-detail · 19 | 상황 정의 해시 `truth.scenarioSha256` | components/detail/AnswerTab.tsx:35-43 | 되살림 | detailTabs.tsx:151-154 요약(값 전체) |
| O-detail · 20 | 공격 기법 `recorded.mitre` | components/detail/OriginalTab.tsx:155-161 | 되살림 | detailTabs.tsx:1020-1021 응답 원문 "기록된 판정 값" |
| O-detail · 21 | 인용 증거 종류 `recorded.evidenceRefs` | components/detail/OriginalTab.tsx:163-168 | 되살림 | detailTabs.tsx:1022-1023 같은 표(기록된 코드 그대로) |
| O-detail · 22 | 심층 분석 사유 `events[LAYER2_COMPLETE].reasoning` | components/detail/OriginalTab.tsx:72-73, :180-186 | 되살림 | detailTabs.tsx:1068-1073 같은 카드 "2차 분석 사유(원문)" |
| O-detail · 23 | 출력 토큰 `interpretation.calls[].completionTokens` | components/detail/OriginalTab.tsx:195-199 | 되살림 | detailTabs.tsx:1082-1131 응답 원문 "모델 호출 기록" 표(:1113). 같은 표에 입력 토큰도 호출별로 둠 |
| O-detail · 24 | 호출별 걸린 시간 `interpretation.calls[].elapsedMs` | components/detail/OriginalTab.tsx:200-203 | 되살림 | detailTabs.tsx:1114-1118 같은 표 |
| O-detail · 25 | 원문 물리 줄 수 `promptLines.systemPhysical/userPhysical` | components/detail/OriginalTab.tsx:205-209 | 되살림 | detailTabs.tsx:963, :974 마지막 호출의 시스템 · 상황 프롬프트 접힘 제목 |
| O-detail · 26 | 호출 실패 `interpretation.calls[].success/failure` | components/detail/OriginalTab.tsx:211-218 | 되살림 | detailTabs.tsx:1119-1127 같은 표 "결과" |
| O-detail · 27 | 보낸 규칙 원문 `exchanges.calls[].systemPrompt` | components/detail/OriginalTab.tsx:40-41, :219-221 | 되살림 | detailTabs.tsx:958-968 호출 카드 안 접힌 원문 |
| O-detail · 28 | 보낸 상황 원문 `exchanges.calls[].userPrompt` | components/detail/OriginalTab.tsx:42-43, :219-221 | 되살림 | detailTabs.tsx:969-979 호출 카드 안 접힌 원문 |
| O-detail · 29 | 번들 해시 · 선택 출처 `quality.bundle.hash/selectionSource` | components/detail/OriginalTab.tsx:284-288 | 되살림 | detailTabs.tsx:1175-1186 무결성 검증 봉인 표(해시 전체) |
| O-detail · 30 | 어긋난 줄 상세 `checks[].mismatches[].factId/entry/line/expected/actual/reason` | components/detail/OriginalTab.tsx:347-358 | 되살림 | detailTabs.tsx:1247, :1261-1302 무결성 검증 "어긋난 줄" 표 |
| 2-4 · 1 | 평소 최대 대비 배수 `received.sizeRatio.times`(+ `items`, `usualLargest`) | pages/main/AttackReasonPage.tsx:86-91, :163-164 | 되살림 | detailTabs.tsx:428-436 판정 근거, 기준선 표 아래 |
| 3-3 · 1 | 값 출처 `recorded.fieldProvenance.*` | pages/main/VerdictCard.tsx:139-142 | 되살림 | detailTabs.tsx:1003-1075 응답 원문 "기록된 판정 값"(항목 · 기록된 값 · 값 출처) |
| 3-3 · 2 | 불리한 조건 충족 수 `juxtaposition.adverseMet/adverseChecked` | pages/main/EvidenceVerdictPage.tsx:86-90 | 되살림 | detailTabs.tsx:774-787 판정 프롬프트 검사 수치(O-detail · 15와 한 곳). 프롬프트에 든 조건이라 프롬프트 탭이 맞는 탭 |
| 5-3 · 1 | 판정이 엮은 서로 다른 인용 사실 수 n(`reasonCodes[].fact` 서로 다른 수) | pages/main/InsidePage.tsx:114-115, :120 | 되살림 | detailTabs.tsx:349, :358-361 판정 근거 카드 부제 "인용한 서로 다른 사실 n개" |
| 5-3 · 2 | 값 출처(모델이 내지 않음) `fieldProvenance.{riskScore,confidence}` | pages/main/VerdictCard.tsx:139-142 | 되살림 | detailTabs.tsx:1003-1075 3-3 · 1과 같은 표(같은 판정 상세의 응답 원문 탭, 한 곳에 둠) |
| 6-3 · 1 | 보내는 쪽 칩 `sender` | pages/main/AgentReasonPage.tsx:47, :84 | 되살림 | RunDetailPage.tsx:98-104, :118(O-detail · 1과 같은 값, 실행 기록의 sender) |
| 6-3 · 2 | 기준 실행의 저장 시각 `agentSnapshot.capturedAt` | pages/main/AgentReasonPage.tsx:54-58, :95 (components/main/SnapshotBadge.tsx:13-26) | 해당 없음 | 방문자 실행도 운영자 기록도 없을 때 저장 사본 파일이 대신 서던 대체 화면의 값입니다. 판정 상세(/runs/:runId)는 언제나 실행 ID로 DB의 실행을 읽고 저장 사본을 대신 보이지 않으므로 이 값이 설 자리가 없습니다 |
| 6-3 · 3 | 정상 짝 기록 실행: 요청 수 · 기존 넷 모두 전달 수 · Contexa 전달 수 | pages/main/AgentReasonPage.tsx:201-214 | 되살림 | detailTabs.tsx:390, :533-566 판정 근거 "같은 위임 범위의 정상 업무"(실행의 단계 결과 코드로 셈, detailWords.ts `pairCounts`) |
| 6-3 · 4 | 정상 짝 실행이 일을 마쳤는지 `finalAnswer` 유무 | pages/main/AgentReasonPage.tsx:216 | 되살림 | detailTabs.tsx:561-562 같은 곳 |
| 6-3 · 5 | 정상 짝 실행 run id `normalRecorded.runId` | pages/main/AgentReasonPage.tsx:217 | 되살림 | detailTabs.tsx:549-554 같은 곳(그 실행의 판정 상세로 가는 링크) |
| 6-3 · 6 | 운영자 기록 수와 같은 결과 수 `recorded.runs` · `sameAsLatest` | pages/main/MeasureNote.tsx:38-43 | 되살림 | RunDetailPage.tsx:121-128 시나리오 코드 옆 머리 배지 "운영자 기록 n회 · 최근 기록과 같은 결과 m회" |
| O-replay · 1 | 장면 상황 문장 `replay.scenes[].sentence[lang]` | pages/ReplayPage.tsx:113-117 | 되살림 | runLog.ts:20-21, :80(행에 실음) → RunsPage.tsx:421-426 오른쪽 패널 "상황" |
| O-replay · 2 | 정상 실행에서 기존 통제가 잘못 막은 표시 `correct[A~C2]=false` | pages/ReplayPage.tsx:326-339 | 되살림 | RunsPage.tsx:470-486 패널 통제마다 서버 채점 배지(HALTED → "오탐", MISSED → "미탐") |
| O-replay · 3 | 지금 측정에 속하는지와 그 측정 날짜 `measured(case).list[runId].startedAt` | pages/ReplayPage.tsx:186-216 | 되살림 | RunsPage.tsx:495, :508-550 패널 "현재 측정 › 이 실행"(포함 · 시작 시각 / 포함되지 않음) |
| O-replay · 4 | 추가 인증 뒤 통과 수 `measured.results.PASSED_AFTER_CHECK` | pages/ReplayPage.tsx:146-160, :225-226 | 되살림 | RunsPage.tsx:524-538 패널 "현재 측정 › 측정 횟수 · 결과별 횟수"(포털 집계 그대로) |

## 덧붙임

- 판정 과정 카드에는 옛 과정 탭에 같이 있던 모델 응답 시간(`timings.llmLatencyMs`, 초안 판정 "다른 위치")도 함께 두었습니다. 호출별 입력 토큰(초안 "다른 위치", 합계만 있음)도 호출 표에 있습니다.
- 새 낱말 143개(`ux.detail.*` 133 · `ux.runs.*` 10)를 `ux_keys_locked.py`로 넣었습니다. 금지어 점검(glossary.json banned)은 0건입니다. 옛 키(`adverse.*`, `subject.*`, `detail.r7.*`)는 지울 목록에 있어 쓰지 않았습니다.
- 정상 짝의 세 수와 서로 다른 인용 사실 수는 포털 값 목록을 화면에서 센 수입니다(옛 화면과 같은 방식). 판정 값이나 결론을 화면이 만들지는 않습니다.

## 점검(contexa-showcase/web에서)

| 점검 | 결과 |
|---|---|
| `npx tsc -p tsconfig.app.json --noEmit --incremental false` | 통과(오류 0) |
| `npx eslint src/ux/pages/runs src/ux/runs` | 통과(경고 0) |
| `npx stylelint src/ux/pages/runs/Detail.module.css src/ux/pages/runs/Runs.module.css` | 통과 |
| `npx vitest run src/ux/pages/runs src/ux/runs src/ux/ux-wording.test.ts` | 3 파일 81개 통과(runs.test.tsx 27개 중 새로 12개) |
