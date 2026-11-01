# UC-5 사실 되살림 · A2 사람 위협 흐름(2~4단계)

- 날짜: 2026-11-01 · 결정 DEC-82 · 규칙 P-8
- 맡은 행: 2-1·4-1·5-1, 2-2·4-2·5-2, 5-2, 2-3, 4-3, 4-4 (uc5-facts-draft.md 3절 "없음" 16개 + 2절에서 다시 본 1개)
- 경로 기준: `contexa-showcase/web/src`. 옛 줄은 모두 열어 본 줄입니다.

| 번호 | 사실 | 옛 줄(열어 본 file:line) | 판정 | 새 위치(file:line) 또는 이유 |
|---|---|---|---|---|
| 2-1·4-1·5-1 | 승인 목적 `APPROVAL.purpose`(최대 건수 · 승인자와 한 줄) | `pages/main/RequestPage.tsx:205`, `:257-263` | 해당 없음 | 사람 흐름의 세 시나리오 정의에 APPROVAL 사실이 없음: `showcase-portal/src/main/resources/scenarios/S13.json`·`S13T.json` facts 빈 목록, `S16.json`은 DOCUMENT만(`ux/test/fixtures/lab-options.test.json`도 같음). 옛 화면도 이 갈래는 그린 적 없고 "승인 기록 없음"만 그림(그 사실은 아래 마지막 행) |
| 2-2·4-2·5-2 | 승인 목적 `businessFacts[APPROVAL_COVERS].value` | `pages/main/consoleData.ts:140-160` (→ `pages/main/ConsolePage.tsx:386-397`) | 해당 없음 | 세 시나리오의 업무 조회는 NO_APPROVAL(S13·S13T) 또는 승인 코드 없음(S16): fixtures `before-S13`·`before-S13T`·`before-S16`·`received-attacker`·`received-owner`. APPROVAL_COVERS가 오는 시나리오(A3T·S02·S11·S12 등)는 사람 흐름에 없음 |
| 2-2·4-2·5-2 | 같은 시나리오 측정 횟수와 Contexa 판정 수 `benchmark.cases[key].runs`·`engineActions` | `pages/main/ConsolePage.tsx:430-434`, `:556-570` (`consoleData.ts:61-73`) | 되살림 | `ux/pages/simulate/person/LivePage.tsx:138-139`→`:264`, `ux/simulate/DecisionProgress.tsx:268-283` ("자세히 · 엔진 기록") |
| 2-2·4-2·5-2 | 엔진 이벤트 시각 `stages[LAYER1_START·LAYER*_COMPLETE].atMs` | `pages/main/ConsolePage.tsx:240-252` (`atSeconds`, `consoleData.ts:317-319`) | 되살림 | `ux/simulate/DecisionProgress.tsx:187`→`:221-248` |
| 2-2·4-2·5-2 | 2차 분석 `stages[LAYER2_START]`과 1차 `LAYER1_COMPLETE.action/riskScore/confidence` | `pages/main/consoleData.ts:185-191`, `:239-257` | 되살림 | `ux/simulate/DecisionProgress.tsx:209`, `:214-237` (LAYER2_ 이벤트가 있을 때만 "1차"라고 부름) |
| 2-2·4-2·5-2 | 호출별 `interpretation.calls[].callNo/elapsedMs/promptTokens/completionTokens` | `pages/main/consoleData.ts:279-312` → `ConsolePage.tsx:232-236` | 되살림 | `ux/simulate/DecisionProgress.tsx:249-267` |
| 2-2·4-2·5-2 | 추가 인증 단계 시간 `challenge.codeRequestedMs/verifiedMs/reissueSentMs/reissueDoneMs/reissueOutcome` | `components/RecoveryFlow.tsx:18-44` (← `components/LiveChallenge.tsx:32-33` ← `pages/main/ConsolePage.tsx:477`) | 되살림 | `ux/simulate/Recovery.tsx:148`→`:181-202` (통과 뒤 "자세히 · 추가 인증 요구 뒤 경과") |
| 2-2·4-2·5-2 | 해제 코드 남은 시간 `release.secondsLeft` | `components/show/ReleasePanel.tsx:94-98` | 되살림 | `ux/simulate/Recovery.tsx:323-330` (BLOCKED·CODE_SHOWN, 행동에 걸린 시간이라 주 화면) |
| 2-2·4-2·5-2 | 해제 사유 기본값의 승인 목적 `facts[APPROVAL].purpose` | `pages/main/ConsolePage.tsx:538-553` | 해당 없음 | 첫 행과 같은 이유: 세 시나리오에 APPROVAL이 없어 옛 화면도 `main.release.reasonPlain`만 채움. 새 화면도 같은 갈래(`LivePage.tsx` releaseReason) |
| 2-3 | 통제별 응답 보낸 시각 `responses[c].sentAt` | `pages/main/ProofPanel.tsx:57`, `:111-125` (← `pages/main/ResultPage.tsx:73`) | 되살림 | `ux/pages/simulate/person/ResultPage.tsx:310`→`:319-370` ("자세히 · 통제별 응답 원문", 요청 줄 · HTTP와 함께) |
| 2-3 | 통제별 응답 원문 앞부분 `responses[c].excerpt` | `pages/main/ProofPanel.tsx:121` | 되살림 | `ux/pages/simulate/person/ResultPage.tsx:357-364` |
| 4-3 | 엔진 입력에서 다른 줄 `inputChanges[].key/before/now`와 줄 수 | `pages/main/DiffPage.tsx:89`, `:132-138`, `:172-181` | 되살림 | `ux/simulate/CompareView.tsx:73`→`:196`, `:257-312` ("자세히 · 엔진 입력에서 다른 줄 n개") |
| 4-4 | 출장 도시 `labCase.facts[TRAVEL].city` | `pages/main/CheckPage.tsx:28`, `:126-127`, `:157` | 해당 없음 | 옛 4-4는 S14를 그림(`CheckPage.tsx:28`), 새 위치는 S13T. S13T 정의에 TRAVEL 없음(`S13T.json` facts 빈 목록, 업무 조회 NETWORK_OFFICE) |
| 4-4 | 저장된 추가 인증 시각 `recovery.challenge.challenged_at/code_requested_at/verified_at/reissue_sent_at` | `pages/main/RequestSteps.tsx:130-186` (← `CheckPage.tsx:218`) | 되살림 | `ux/pages/simulate/person/ResultPage.tsx:182` → `ux/simulate/Recovery.tsx:204-265` (S14 전용이 아님: 추가 인증을 통과한 실행이면 모두. 통과 안 한 기록은 옛 화면처럼 그리지 않음) |
| 4-4 | 저장된 재전송 `recovery.challenge.reissue_delivered/reissue_status` | `pages/main/RequestSteps.tsx:160-169` | 되살림 | `ux/simulate/Recovery.tsx:237`, `:251-259` (`ux/simulate/person.ts:305-315` storedResend) |
| 5-2 | 요청별 저장된 재전송 `anatomy(n).recovery.challenge.reissue_delivered/reissue_status` | `pages/main/RequestSteps.tsx:59-63`, `:97-104` (`consoleData.ts:34-55`, ← `ConsolePage.tsx:293`) | 되살림 | `ux/pages/simulate/person/LivePage.tsx:362-366`, `:396-405` (저장 기록으로 읽은 실행에서 그 요청 아래. 실시간 실행은 `Recovery.tsx:130-149` 카드가 보임) |
| 2-1·4-1·5-1 (초안 '있음' 재확인) | 승인 기록 유무 — S16 | `pages/main/RequestPage.tsx:205`, `:257-263` | 되살림 | 초안은 '있음'(NO_APPROVAL 칩)이었으나 `before-S16` 업무 조회에 승인 코드가 없어 S16 검토 화면에는 없었음. `ux/pages/simulate/person/ReviewPage.tsx:71-82`, `:147-152` (업무 컨텍스트에 승인 코드가 없을 때만 "자세히 · 시나리오 정의") |

## 함께 본 점

- 4-4 사례 차이(초안 5절): 옛 4-4는 S14(출장 엔지니어, 요청 3개), 새 위치는 S13T(요청 1개)입니다. S14에만 있는 사실(출장 도시, 출장지 네트워크 198.51.100.0/24, 요청 3개의 이름)은 S13T에 해당하지 않습니다. 지금 `src/ux`에서 S14는 /simulate/policy?tab=compose(시나리오 선택, 조건 목록, 실행), /runs/:runId(판정 근거의 기준선 대비 표에 네트워크 값), /validation?tab=scenarios(측정)에서 보입니다. 출장 도시는 `src/ux` 어디에도 없습니다(업무 사실 NETWORK_TRAVEL의 값이 도시지만, 그 칩은 사람 흐름 세 시나리오와 /engine 흐름 탭의 앞 3개에서만 그려짐). S14 직원은 S13T와 같은 eng-k(`S14.json` protagonist)라 이름은 S13T 검토 화면에 보입니다. 다른 화면은 고치지 않았습니다.
- `src/api/anatomy.ts`의 `StoredCheck`에는 포털이 함께 돌려주는 `challenged_at`·`code_requested_at`·`verified_at`·`reissue_sent_at`(실제 응답 `anatomy-attacker.test.json`에 있음)이 없습니다. 옛 화면처럼 `ux/simulate/Recovery.tsx`의 `TimedCheck`로 넓혀 읽었습니다. API 타입에 넣는 일은 맡은 파일 밖입니다.
- `ux.biz.APPROVAL_COVERS` 문구에 `{{value}}`가 없어, /engine?run=…으로 승인 기록이 있는 실행(A3T 등)을 열면 목적이 안 보입니다. 사람 흐름에는 해당 없고, 고치려면 그 키 문구를 바꿔야 해 범위 밖입니다.
- `ChallengeCard`는 /simulate/policy?tab=compose(ComposeTab)도 씁니다. 통과(DONE) 뒤 접힌 "자세히"가 거기에도 함께 보입니다(덧붙임만, 기존 동작 그대로).

## 실행한 점검 (contexa-showcase/web)

| 점검 | 결과 |
|---|---|
| `npx tsc -p tsconfig.app.json --noEmit --incremental false` | 오류 0 |
| `npx eslint src/ux/pages/simulate/person src/ux/simulate/CompareView.tsx src/ux/simulate/Recovery.tsx src/ux/simulate/DecisionProgress.tsx src/ux/simulate/person.ts` | 오류 0 · 경고 0 |
| `npx stylelint src/ux/simulate/Live.module.css src/ux/simulate/Result.module.css src/ux/simulate/Recovery.module.css src/ux/simulate/Review.module.css` | 통과 |
| `npx vitest run src/ux/pages/simulate/person src/ux/simulate/person.test.ts src/ux/ux-wording.test.ts` | 3파일 94건 통과(flow.test.tsx 34건, 새 테스트 7건) |

- 새 사전 키 35개는 `ux_keys_locked.py`로만 넣었습니다(`ux.live.log.*`, `ux.recovery.times.*`, `ux.recovery.record.more`, `ux.result.responses.*`, `ux.compare.inputs.*`, `ux.review.definition.*`).
- 기존 테스트 하나(진행 단계 상태 목록)는 엔진 기록 목록이 같은 영역에 생겨 `data-state`가 있는 항목만 고르도록 바꿨습니다.
