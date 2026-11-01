# UC-5 사실 되살림 · A3 묶음(에이전트 위임 흐름 · 요청 급증)

- 날짜: 2026-11-01 · 결정 DEC-82 · 규칙 P-8
- 맡은 행: 6-1 · 6-2 · 6-7 · 6-4 · 6-5 · 6-6 · M-stack, 그리고 기획안 11절 제목 둘(6-4 "위임자 승인 · 요청 1회 처리", 6-6 "동일 요청 60건 동시 유입").
- 근거: `uc5-facts-draft.md` 3절 "없음 목록"과 2절 행별 표. 항목마다 옛 줄을 열어 방문자에게 보인 값인지 확인했고, `ux/` 전체를 필드 이름으로 다시 찾아 새 화면이 그리지 않음을 확인했습니다.
- 경로 기준: `contexa-showcase/web/src`. 옛 화면은 `pages/` · `components/`, 새 화면은 `ux/`입니다.
- 배치: 단계 화면(2 · 3 · 4단계)에서 결과를 바꾸는 사실만 본문에 두고, 나머지는 관련 요소 옆의 접힌 "자세히"(`<details className={styles.more}>`)에 두었습니다. 요청 주체와 운영자 기록 수는 화면마다 시나리오 옆에 한 번만 둡니다(2 · 3단계는 머리줄, 4단계는 실행 ID 옆 목록).
- 판정 수: 되살림 36 · 이미 있음 0 · 사실 아님 0 · 해당 없음 3 (모두 39행)

| 번호 | 사실 | 옛 줄(열어 본 file:line) | 판정 | 새 위치(file:line) 또는 이유 |
|---|---|---|---|---|
| 6-1 | 요청 주체 `agentCase.sender` | pages/main/AgentRequestPage.tsx:92 → components/main/MainScreen.tsx:180 | 되살림 | ux/pages/simulate/agent/ReviewPage.tsx:144 (→ ux/simulate/AgentParts.tsx:21, :34; 낱말 ux/simulate/agent.ts:151) |
| 6-1 | 자원이 없을 때 사슬에 보인 `delegation.project` | pages/main/DelegationParts.tsx:61 | 되살림 | ux/pages/simulate/agent/ReviewPage.tsx:163 (→ ux/simulate/agent.ts:140: 자원을 모두 잇고, 없으면 project, 그것도 없으면 "—") |
| 6-1 | 오늘 남은 실제 실행 `liveConfig.liveTicketsLeft` | pages/main/AgentRequestPage.tsx:178-179 | 되살림 | ux/pages/simulate/agent/ReviewPage.tsx:247-249 (실행 버튼 아래 "자세히") |
| 6-1 | 같은 시나리오 최근 운영자 기록 실행의 요청 회사 시각 `agentRun(recorded.runId).steps[].companyTime` (요청 주소와 함께) | pages/main/AgentRequestPage.tsx:215-226 | 되살림 | ux/pages/simulate/agent/ReviewPage.tsx:170-181 (지시 원문 아래 "자세히", 기록 실행이 있을 때만) |
| 6-2 | 요청 주체 `agentCase.sender` | pages/main/AgentConsolePage.tsx:56 → components/main/MainScreen.tsx:180 | 되살림 | ux/pages/simulate/agent/LivePage.tsx:78 |
| 6-2 | 진행 중 실시간 실행 ID `liveRun.liveRunId` (상단 LIVE 표시) | pages/main/AgentConsolePage.tsx:59 → components/AppHeader.tsx:81 | 되살림 | ux/pages/simulate/agent/LivePage.tsx:212-221 (에이전트 작업 칸 "자세히") |
| 6-2 | 운영자 기록 수와 최근 기록과 같은 결과 수 `recorded.runs` · `sameAsLatest` | pages/main/MeasureNote.tsx:40-43 (pages/main/AgentConsolePage.tsx:76) | 되살림 | ux/pages/simulate/agent/LivePage.tsx:78 (→ ux/simulate/AgentParts.tsx:34; ux/simulate/agent.ts:160) |
| 6-2 | 에이전트 토큰 수 `cost.agent.totalTokens` | pages/main/AgentConsolePage.tsx:51, :116-117 | 되살림 | ux/pages/simulate/agent/LivePage.tsx:225-226 |
| 6-2 | 판정 모델 호출 합계 `cost.decisions[].calls` | pages/main/AgentConsolePage.tsx:50, :116-118 | 되살림 | ux/pages/simulate/agent/LivePage.tsx:227-235 (합계와 모델별 호출 수) |
| 6-7 | 요청 주체 `agentCase.sender` | pages/main/AgentResultPage.tsx:51 → components/main/MainScreen.tsx:180 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:194-195 |
| 6-7 | 기준 실행의 저장 시각 `agentSnapshot.capturedAt` | pages/main/AgentResultPage.tsx:42, :71 → components/main/SnapshotBadge.tsx:21-24 | 해당 없음 | 새 4단계는 기준 스냅숏으로 대신 보여 주지 않습니다. 주소의 실행이나 방문자 최근 실행만 읽고(ux/pages/simulate/agent/ResultPage.tsx:71-73), 없으면 "실행 기록 없음"으로 끝납니다(:82-94). 스냅숏을 그리지 않으므로 그 저장 시각도 보일 자리가 없습니다 |
| 6-7 | 통제별로 나간 문서 · 항목 · 고객 기록 · 권한 변경 `proof.controls[c].documents · items · records · changes` | pages/main/AgentResultParts.tsx:76-81 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:303-331 (통제별 결과 카드 "자세히" 표. 본문 표의 "내준 자료"는 네 값의 합) |
| 6-7 | 운영자 기록 수와 같은 결과 수 `recorded.runs` · `sameAsLatest` | pages/main/MeasureNote.tsx:40-43 (pages/main/AgentResultPage.tsx:76) | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:196-197 |
| 6-4 | 같은 확인 재사용 · 다른 요청이 2xx일 때 전달 건수 `confirmation.reuse · other.deliveredItems` | pages/main/AgentConfirmPage.tsx:210, :214 → :357-358 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:343-349, :386-387 (2xx면 "HTTP 200 · n건", 그 밖에는 지금처럼 HTTP 상태와 규칙 코드) |
| 6-4 | 인가 기록 번호 `confirmation.after.authorizationId` | pages/main/AgentConfirmPage.tsx:88, :277-279 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:454-457 (위임자 응답 카드 "자세히") |
| 6-4 | 확인을 요구한 요청의 회사 시각 `steps[n].companyTime` | pages/main/AgentConfirmPage.tsx:87, :269-270 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:446-447 (확인 단계 `confirmation.stepNo`의 요청) |
| 6-4 | 위임 끝 시각과 요청 시각 (`run.companyTime` + `validUntilMinutes`, 요청의 `companyTime`) | pages/main/AgentConfirmPage.tsx:86, :223-228 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:446-449 (위임은 실행이 쓴 `run.delegation`, 없으면 시나리오의 위임. 계산은 옛 plusMinutes와 같음, ux/simulate/agent.ts:171) |
| 6-4 | 답이 없는 이유 `confirmation.reason` | pages/main/AgentConfirmPage.tsx:302-305 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:413-421 ("응답 없음" 아래. 값은 포털 그대로: EXPIRED · ABANDONED · NO_CONFIRMATION은 낱말, 그 밖은 코드, 없으면 "—") |
| 6-4 | 실행 출처(내 실행 / 저장된 실행) | pages/main/AgentConfirmPage.tsx:127-132; pages/main/MeasureNote.tsx:37 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:186-191 (실행 ID 옆 배지. 방문자 journey의 실행 목록에 그 ID가 있으면 "내 실행") |
| 6-4 | 저장 스냅숏 `T5-confirm-approve`의 저장 시각 `capturedAt` | pages/main/AgentConfirmPage.tsx:63-66, :125-126 → components/main/SnapshotBadge.tsx:21-24 | 해당 없음 | 6-7과 같은 이유입니다. 새 결과 화면은 실행이 없을 때 이 스냅숏으로 대신하지 않습니다(ux/pages/simulate/agent/ResultPage.tsx:82-94) |
| 6-4 | 운영자 기록 수와 같은 결과 수 `recorded.runs` · `sameAsLatest` | pages/main/MeasureNote.tsx:39-44 (pages/main/AgentConfirmPage.tsx:317) | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:196-197 (6-7과 같은 화면이라 한 번) |
| 6-4 | 요청 주체 `agentCase.sender` | pages/main/AgentConfirmPage.tsx:108 → components/main/MainScreen.tsx:180 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:194-195 (한 번) |
| 6-4 | 기획안 11절 제목 "위임자 승인 · 요청 1회 처리" | pages/main/AgentConfirmPage.tsx:72-75, :109 (`main.6-4.title.approved`) | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:402-404 (위임자 응답 카드, 이 실행의 `confirmation.decision`이 APPROVE일 때. 옛 화면과 같은 조건) |
| 6-5 | 요청 주체 `agentCase.sender` | pages/main/AgentEndPage.tsx:42 → components/main/MainScreen.tsx:180 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:194-195 (같은 화면, 한 번) |
| 6-5 | 확인 뒤 상태 `confirmation.after.status` (두 열) | pages/main/AgentEndPage.tsx:88-98 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:450-453(이 실행), :460-463(신고한 실제 기록) |
| 6-5 | 신고 스냅숏 `T5-confirm-report`의 저장 시각 `capturedAt` | pages/main/AgentEndPage.tsx:22, :83 → components/main/SnapshotBadge.tsx:21-24 | 되살림 | ux/pages/simulate/agent/ResultPage.tsx:464-467 (그 실행 ID를 보이는 신고 열과 같은 카드 "자세히") |
| 6-5 | 승인 스냅숏 `T5-confirm-approve`의 저장 시각 `capturedAt` | pages/main/AgentEndPage.tsx:21, :83 → components/main/SnapshotBadge.tsx:21-24 | 해당 없음 | 새 결과의 승인 쪽 열("이 실행")은 방문자 본인 실행이나 주소의 실행이고, 이 스냅숏을 읽지 않습니다(ux/pages/simulate/agent/ResultPage.tsx:71-73). 보이지 않는 실행의 저장 시각입니다 |
| 6-6 | 요청 주체 `agentCase.sender` | pages/main/AgentBurstPage.tsx:29 → components/main/MainScreen.tsx:180 | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:167-169 (급증 시나리오 자신의 sender) |
| 6-6 | 내 실행 `burst.deliveredAfterFirstStop` | pages/main/BurstLive.tsx:149-154 (pages/main/burstRows.ts:14) | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:324, :362 |
| 6-6 | 내 실행 `burst.firstStopStep` | pages/main/BurstLive.tsx:155-158 | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:325, :362 (null이면 "멈추지 않음") |
| 6-6 | M41A 끔 · 켬 `deliveredAfterFirstStop` | pages/main/AgentBurstPage.tsx:96-101 | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:363-364 |
| 6-6 | M41A 끔 · 켬 `firstStopStep` | pages/main/AgentBurstPage.tsx:103-107 | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:363-364 |
| 6-6 | M41A 켬 실행의 요청별 응답(경로, 5개 통제 결과, 자체 판정 · 모델 호출) | pages/main/AgentBurstPage.tsx:110-116 → pages/main/AgentTimeline.tsx:54-55, :66-70, :98-108 | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:421-426 ("자세히" 표. ux/simulate/AgentParts.tsx:237, :283-297; ux/simulate/agentRows.ts:50-51). 연속한 같은 요청을 한 줄로 접던 묶음은 다시 만들지 않았습니다. 요청마다 자체 판정과 모델 호출을 그대로 보여, 묶음의 건수 · 판정 수 · 호출 수가 행에서 읽힙니다 |
| 6-6 | M41T · M41X 끔의 보낸 요청 · 전달 · 분석 중 거부, 끔 · 켬의 거부 · 자체 판정 | pages/main/AgentBurstPage.tsx:96-101 | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:436-449 (다른 급증 측정마다 같은 표, :329-371) |
| 6-6 | M41T · M41X 끔 · 켬 `deliveredAfterFirstStop` · `firstStopStep` | pages/main/AgentBurstPage.tsx:96-107 | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:445 (→ :324-325, :363-364) |
| 6-6 | 세 급증 켬 스냅숏의 저장 시각 `capturedAt` | pages/main/AgentBurstPage.tsx:84 → components/main/SnapshotBadge.tsx:21-24 | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:374-381 (출처 줄), :420(M41A), :446(M41T · M41X) |
| 6-6 | 기획안 11절 제목 "동일 요청 60건 동시 유입" | pages/main/AgentBurstPage.tsx:72-74 (`main.6-6.case.M41A`) | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:396-400 (판정 통합 결과의 측정 제목, 이미 있던 키 `ux.surge.case.M41A`) |
| M-stack | 대기 순번 · 남은 대기 시간 `queuePosition` · `queueWaitSeconds` | pages/try/StackPage.tsx:256-262 → components/StateScreen.tsx:101, :105 | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:491-496 (있던 키 `ux.live.queued` · `ux.live.queuedWait`) |
| M-stack | 실행 실패 · 만료 `live.status` FAILED · EXPIRED | pages/try/StackPage.tsx:143, :204-205 (→ :246) | 되살림 | ux/pages/simulate/surge/SurgePage.tsx:497 (있던 키 `ux.live.failed`) |

## 함께 둔 점

- 새 사전 키 47개(`ux.agent.` · `ux.agentReview.` · `ux.agentLive.` · `ux.agentResult.` · `ux.surge.`)는 `ux_keys_locked.py`로만 넣었습니다(ko · en 47개씩 추가, 바뀐 키 0).
- 다른 급증 측정 표를 측정마다 전체 행 표로 바꾸어, 그 표에서 쓰던 `ux.surge.col.callsOnOff`는 더 쓰지 않습니다. 사전 파일은 직접 고치지 않았으므로 키는 남아 있습니다.
- `AgentParts.tsx`의 기존 내보내기와 속성은 그대로이고, `AgentSteps`에 선택 속성 `decisions`만 더했습니다(정책 시뮬레이터 `AgentPolicyTab.tsx`는 그대로 동작).
- 실시간 위임자 확인 패널(DelegatorPanel)의 재사용 · 다른 요청 전달 건수는 포털의 `LiveAgentConfirmation`에 그 필드가 없어 그리지 않습니다. 옛 화면은 이 경우 0을 넣어 보였습니다(pages/main/AgentConfirmPage.tsx:93-94). 저장된 실행의 값은 4단계에 있습니다.

## 실행한 검사 (`contexa-showcase/web`)

| 검사 | 결과 |
|---|---|
| `npx tsc -p tsconfig.app.json --noEmit --incremental false` | 맡은 파일 오류 0. 다른 묶음이 고치는 중인 `ux/pages/runs/detailTabs.tsx` · `ux/pages/simulate/policy/ComposeTab.tsx`에 오류가 있음(맡은 파일 밖) |
| `npx eslint` (맡은 파일 전부) | 통과 |
| `npx stylelint src/ux/simulate/Agent.module.css` | 통과 |
| `npx vitest run src/ux/pages/simulate/agent src/ux/pages/simulate/surge src/ux/ux-wording.test.ts` | 3파일 89개 통과(agent 26 · surge 10 · 문구 53). 되살린 사실의 새 시험 10개(agent 7 · surge 3) |
