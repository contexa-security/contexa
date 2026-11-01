# UC-4 옛 동작 대조표

만든 도구: `_tools/ux_uc4_table.py`. 시험 제목에 상태 번호(ST-n)가 붙은 새 화면 시험을 찾는다. 경로는 `contexa-showcase/web` 기준.

| 옛 동작 | 상태(9절) | 새 화면 시험(제목에 상태 번호) |
|---|---|---|
| 사람 확인(턴스타일) | ST-1 사람 확인(Turnstile) 필요 | `src/ux/pages/simulate/person/flow.test.tsx:275` |
| 사람 확인(턴스타일) | ST-2 사람 확인 거절 | `src/ux/pages/simulate/person/flow.test.tsx:220` |
| 하루 할당 거절 · 일시 중지 | ST-3 하루 한도 | `src/ux/pages/simulate/person/flow.test.tsx:220` |
| 하루 할당 거절 · 일시 중지 | ST-4 실행 일시 중지 | `src/ux/pages/simulate/person/flow.test.tsx:220` |
| 하루 할당 거절 · 일시 중지 | ST-21 에이전트 몫 · 동시 실행 상한 | `src/ux/pages/simulate/agent/agent.test.tsx:268` |
| 하루 할당 거절 · 일시 중지 | ST-22 에이전트 하루 한도 | `src/ux/pages/simulate/agent/agent.test.tsx:247` |
| 앞선 실행 대기 뒤 자동 전송 · 대기열 | ST-6 앞선 실행 대기 뒤 자동 전송 | `src/ux/pages/simulate/person/flow.test.tsx:193` · `src/ux/pages/simulate/person/flow.test.tsx:259` |
| 앞선 실행 대기 뒤 자동 전송 · 대기열 | ST-7 대기열 | `src/ux/pages/simulate/person/flow.test.tsx:428` |
| 추가 인증 코드 요청 · 입력 · 취소 · 만료 · 재전송, 차단 해제 | ST-9 추가 인증 · 탈취된 계정(S13) | `src/ux/pages/simulate/person/flow.test.tsx:436` |
| 추가 인증 코드 요청 · 입력 · 취소 · 만료 · 재전송, 차단 해제 | ST-10 추가 인증 · 정상 사용자 · 내부자 | `src/ux/pages/simulate/person/flow.test.tsx:467` |
| 추가 인증 코드 요청 · 입력 · 취소 · 만료 · 재전송, 차단 해제 | ST-11 틀린 코드 · 3회 실패 | `src/ux/pages/simulate/person/flow.test.tsx:467` · `src/ux/pages/simulate/person/flow.test.tsx:608` |
| 추가 인증 코드 요청 · 입력 · 취소 · 만료 · 재전송, 차단 해제 | ST-12 취소 · 만료 | `src/ux/pages/simulate/person/flow.test.tsx:517` |
| 추가 인증 코드 요청 · 입력 · 취소 · 만료 · 재전송, 차단 해제 | ST-13 추가 인증 통과 뒤 재전송 | `src/ux/pages/simulate/person/flow.test.tsx:467` |
| 추가 인증 코드 요청 · 입력 · 취소 · 만료 · 재전송, 차단 해제 | ST-14 차단 해제 · 탈취된 계정 | `src/ux/pages/simulate/person/flow.test.tsx:635` |
| 추가 인증 코드 요청 · 입력 · 취소 · 만료 · 재전송, 차단 해제 | ST-15 차단 해제 · 정상 사용자 | `src/ux/pages/simulate/person/flow.test.tsx:548` |
| 위임자 확인 승인 · 거절 · 응답 없이 끝남(신고는 저장된 실행으로 보임, DEC-26) | ST-24 위임자 확인 요청 | `src/ux/pages/simulate/agent/agent.test.tsx:314` |
| 위임자 확인 승인 · 거절 · 응답 없이 끝남(신고는 저장된 실행으로 보임, DEC-26) | ST-25 위임자 응답 뒤 | `src/ux/pages/simulate/agent/agent.test.tsx:314` · `src/ux/pages/simulate/agent/agent.test.tsx:352` |
| 위임자 확인 승인 · 거절 · 응답 없이 끝남(신고는 저장된 실행으로 보임, DEC-26) | ST-26 위임자 응답 없이 끝남 | `src/ux/pages/simulate/agent/agent.test.tsx:383` |
| 실행 실패 · 만료 · 판정 없음 | ST-16 실행 실패 · 만료 | `src/ux/pages/simulate/agent/agent.test.tsx:405` · `src/ux/pages/simulate/person/flow.test.tsx:411` |
| 실행 실패 · 만료 · 판정 없음 | ST-17 판정 실패(판정 없음) | `src/ux/pages/simulate/person/flow.test.tsx:663` |
| 위임자 신고 | DEC-26: 방문자는 승인 · 거절로 답하고, 신고는 저장된 실제 실행(T5-confirm-report)으로 보인다 | `src/ux/pages/simulate/agent/agent.test.tsx:425` |

제목에 없는 상태: 없음
