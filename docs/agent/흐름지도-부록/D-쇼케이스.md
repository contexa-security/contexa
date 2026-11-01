# 흐름 지도 D: 쇼케이스 전체 (A6-1, A7-1, A7-2, A7-3 대상)

이 부록은 [흐름 지도](../흐름지도.md)의 영역별 상세입니다. 본문 9절에 직접 대조한 줄이 있고, 나머지 줄은 이 기록 기준입니다.

작성: 2026-10-21. 기준: `E:/projects/contexa` 작업 트리의 현재 디스크 파일(읽기만). 줄 번호는 이 시점 파일 기준입니다.

경로 약어(모두 `E:/projects/contexa/` 아래):

| 약어 | 실제 경로 |
|---|---|
| `PT/` | `contexa-showcase/showcase-portal/src/main/java/io/contexa/showcase/portal/` |
| `PR/` | `contexa-showcase/showcase-portal/src/main/resources/` |
| `PTT/` | `contexa-showcase/showcase-portal/src/test/java/io/contexa/showcase/portal/` |
| `BZ/` | `contexa-showcase/showcase-business/src/main/java/io/contexa/showcase/business/` |
| `BR/` | `contexa-showcase/showcase-business/src/main/resources/db/migration/work/` |
| `DX/` | `contexa-showcase/showcase-workload-contexa/src/main/java/io/contexa/showcase/workload/contexa/` |
| `DR/` | `contexa-showcase/showcase-workload-contexa/src/main/resources/` |
| `PL/` | `contexa-showcase/showcase-workload-plain/src/main/java/io/contexa/showcase/workload/plain/` |
| `PLR/` | `contexa-showcase/showcase-workload-plain/src/main/resources/` |
| `INF/` | `contexa-showcase/infra/` |
| `WEB/` | `contexa-showcase/web/src/` |
| `WE2E/` | `contexa-showcase/web/e2e/` |
| `CORE/` | `contexa-core/src/main/java/io/contexa/contexacore/` |
| `DOC/` | `docs/` |

---

## 1. 핵심 원리 (방문자 버튼 → 다섯 보안 → 엔진 판정 → 포털 기록 → 화면)

1. 방문자가 요청 화면에서 예상을 고르고 '보내기'를 누르면 웹이 예상을 `POST /api/journey`로 저장한 뒤 `POST /api/live/runs {scenario}`를 보냅니다 (`WEB/pages/main/RequestPage.tsx:68-75`, `WEB/hooks/useLiveSend.ts:63`, `PT/live/LiveController.java:128-146`).
2. 관문(방문자 쿠키, 하루 한도, Turnstile, 템플릿 유무)을 통과하면 `LiveRuns`가 대기열에서 꺼내 `RunOrchestrator.run(사례, 강제판정, 응답자=LiveRun, 듣는이=LiveRun)`을 부릅니다 (`PT/live/LiveController.java:142`, `PT/live/LiveGate.java:95`, `PT/live/LiveRuns.java:244`).
3. 실행 하나는 새 주체 하나입니다: `run-<hex>`, 사용자명 `v<hex>-<주인공>`, 회사 시각(사례의 시간대), 기기(평소 또는 NEW_DEVICE), 주소(사무실 /24 안 임의 호스트, 외부, 출장지)를 만듭니다 (`PT/orchestrator/RunOrchestrator.java:148-171`, `:763-772`, `:835-838`).
4. 업무 앱(B 인스턴스)에 서명된 내부 API로 계정과 실행 사실(티켓·승인·당번·출장·문서)을 넣고, D에는 엔진 주체를 만들며 주인공의 학습 템플릿을 복제합니다 (`RunOrchestrator.java:174-205`, `PT/orchestrator/WorkloadAdmin.java:82-104`, `PL/internal/PlainInternalController.java:63-81`, `DX/internal/ContexaInternalController.java:133-148`).
5. 다섯 보안에 각자 로그인합니다: A·B·C1·C2는 `/api/login`, D는 `/api/mfa/login` 뒤 데모 메일함의 일회용 코드로 2단계를 끝냅니다 (`RunOrchestrator.java:211-220`, `PT/orchestrator/ControlSession.java:82-117`).
6. 단계마다 같은 요청을 다섯 곳에 동시에 보내고, 요청마다 UUID 요청 ID·회사 시각·주소·기기·조직·테넌트를 HMAC 서명 헤더로 싣습니다 (`RunOrchestrator.java:382-402`, `ControlSession.java:344-351`, `BZ/client/WorkloadClient.java:190-198`).
7. 업무 앱 필터가 서명을 확인해 엔진이 읽는 요청 속성(관측 시각·조직·테넌트·요청 ID)과 주소·UA를 바꿔 끼우고, 모든 요청에서 `x-showcase-`·`x-contexa-`·`x-simulated-` 헤더와 X-Forwarded-For 등을 숨깁니다 (`BZ/internal/InternalContextFilter.java:46-54`, `BZ/internal/InternalContextRequest.java:20`, `:30-47`, `BZ/internal/InternalContextHeaders.java:22-23`).
8. B는 역할 규칙(RBAC)만, C1은 RBAC 뒤 고정 임계 규칙, C2는 RBAC 뒤 업무 기록 규칙으로 판정해 `rule_decision_log`에 남기고, A는 B 앞의 Coraza WAF(CRS 기본값)입니다 (`PL/security/ControlAuthorizationManager.java:79-83`, `BR/V2__virtual_company.sql:189-202`, `INF/compose.stack.yml:76-86`).
9. D는 같은 업무 코드를 `@Protectable` 메서드로 감싸 엔진이 판정합니다(동기 내보내기·권한 부여는 응답 전, 나머지는 다음 요청부터). 엔진 맥락에는 `BusinessFrictionProvider`가 C2와 같은 조회기로 업무 DB 사실을 넣습니다 (`DX/business/ContexaBusinessOperations.java:43-85`, `DX/context/BusinessFrictionProvider.java:61-95`, `DX/ContexaWorkloadConfiguration.java:132-135`).
10. D는 결정 기록(엔진 표 `ai_security_decision_observation`), 분석 이벤트(메모리, 요청 ID 키), 모델 호출, 수신 시각을 `/internal/decisions/{요청ID}`로 내줍니다 (`DX/internal/ContexaInternalController.java:59-62`, `:179-183`, `DX/observation/DecisionRecords.java:38-44`, `DX/observation/AnalysisEventRecorder.java:34`, `:113-120`).
11. 포털은 각 보안의 응답을 `run_arm_result`에, D 판정을 종료 이벤트(DECISION_APPLIED·ANALYSIS_ERROR)까지 기다려 `run_decision`에, 모델 교환·추가 인증·차단 해제를 각 표에 남깁니다 (`RunOrchestrator.java:404-441`, `:261-273`, `:468-506`, `PT/orchestrator/RunStore.java:68`, `:118`, `:144`, `:193`, `:258-285`).
12. D가 추가 인증(401)을 내면 응답자가 처리합니다: 녹화·측정은 정상 사례와 `actor: OWNER`(내부자)만 메일함 코드로 통과하고 외부 공격자는 포기, 라이브는 방문자가 버튼으로 진행합니다 (`RunOrchestrator.java:426-438`, `PT/orchestrator/ChallengeResponder.java:49-82`, `PT/live/LiveRun.java:435-439`).
13. 실행이 끝나면 봉인 점검, 학습 변화, 판정 해부(`run_decision_anatomy`), 업무 증거, 실행 명세를 저장하고 실행이 만든 계정·사실을 지웁니다 (`RunOrchestrator.java:293-345`, `PT/anatomy/AnatomyStore.java:192`).
14. 화면은 실행 중 `/api/live/runs/current`(250ms~1초 폴링)와 `/api/live/runs/current/analysis`로 다섯 레인과 판정을 그리고, 끝나면 `/api/runs/{runId}/steps/{n}/{result,anatomy,received,facts,quality}`로 저장 기록을 읽습니다 (`WEB/api/queries.ts:120-157`, `WEB/pages/try/steps/tryRun.ts:21-42`, `:93-114`, `PT/live/LiveController.java:167-171`, `:294-330`).
15. 화면의 문장은 사전 키, 값은 서버 기록이며, 값 옆 출처 배지(방금 실행·반복 기록·다른 설정)가 판단 근거 보기 창(7개 탭)을 엽니다 (`WEB/components/main/SourceBadge.tsx:5-45`, `WEB/components/detail/useDetail.ts:8-16`, `WEB/components/detail/DecisionDetail.tsx:156-172`).

---

## 2. 구성 표

| 구성 요소 | 위치 | 역할 | 포트·설정 |
|---|---|---|---|
| A 방화벽 | `INF/compose.stack.yml:76-86` | OWASP Coraza + CRS 기본값, B 앞단(B로 전달) | 내부망 8080, `BACKEND: workload-plain-b:19181` (`:80-81`). 포털 주소 `SHOWCASE_PORTAL_CONTROLS_A: http://waf:8080/` (`:110`) |
| B 로그인 인증 | `PL/`, `PLR/application.yml` | 같은 업무 앱 + RBAC만 (`ControlAuthorizationManager.java:79-82` default 분기). 업무 DB 스키마 이전·가상 회사 생성 담당 (`PLR/application.yml:52-56`, `INF/compose.stack.yml:38-39`) | `127.0.0.1:19181` (`PLR/application.yml:31`, `:34`), `showcase.control=B` (`:51`) |
| C1 고정 규칙 | 같은 실행 파일 | RBAC + `ThresholdRules`(밤·건수) (`ControlAuthorizationManager.java:80`) | `SHOWCASE_CONTROL: C1` (`INF/compose.stack.yml:57`) |
| C2 승인 기록 규칙 | 같은 실행 파일 | RBAC + `ContextLookupRules`(업무 DB 조회) (`ControlAuthorizationManager.java:81`) | `SHOWCASE_CONTROL: C2` (`INF/compose.stack.yml:69`) |
| D Contexa | `DX/`, `DR/application.yml` | 같은 업무 앱 + `@EnableAISecurity(FULL)`, ENFORCE (`DX/ContexaWorkloadApplication.java:18-20`, `DR/application.yml:63`) | `127.0.0.1:19182` (`DR/application.yml:124`, `:127`), 프롬프트 묶음 `2026.10.20-v21.8` (`:67-68`), Layer1 `gpt-6-luna`·Layer2 `gpt-6.1-sol` (`:72-76`), 기본 채팅 모델 `gpt-5-nano` (`:41`), DB: vector(`:7`)·engine(`:56`)·work(`:146-150`) |
| showcase-business (공용 모듈) | `BZ/` | 업무 API(`BusinessController`), 업무 DB, 서명 맥락 필터, 조회기(`JdbcBusinessContextLookup`), 실행 등록(`RunRegistry`), 내부 API 가드 | `@EnableShowcaseBusiness` → `BZ/BusinessConfiguration.java:70-73`(조회기), `:101-105`(가드, 순서 +2); `@EnableShowcaseInternalContext` → `BZ/internal/InternalContextConfiguration.java:31`(순서 +1) |
| 포털 | `PT/`, `PR/application.yml` | 오케스트레이터, 방문자 API(`/api/**`), 운영 API(`/ops/**`), 웹 정적 파일 | 방문자 `127.0.0.1:19180` (`PR/application.yml:26-27`), 운영 포트 `showcase.portal.ops.port` 기본 주소 127.0.0.1 (`PT/ops/OpsPortConfiguration.java:28-39`, 운영형 19190 `INF/compose.stack.yml:119-120`). 다섯 주소 `showcase.portal.controls.{a,b,c1,c2,d}` (`PT/orchestrator/ControlEndpoints.java:15-41`), 라이브는 `showcase.live.enabled=true`일 때만 (`PT/orchestrator/OrchestrationConfiguration.java:144`) |
| 웹 | `WEB/` | 방문자 SPA. 포털이 `static/index.html`로 제공 | `PT/web/SinglePageApplicationConfiguration.java:17-27` |
| PostgreSQL | `INF/compose.yml:7-27`, `INF/postgres/init/01-databases.sql:5-7` | DB 4개: showcase_portal, showcase_work(업무), showcase_engine(엔진), showcase_vector(벡터) | 개발 `127.0.0.1:46432` (`INF/compose.yml:19`) |
| 운영형 묶음 | `INF/compose.stack.yml:1-3`, `:124-132` | 포털만 포트 공개, 나머지는 `internal: true` 망. D는 LLM 호출용 egress 망도 붙음(`:102`) | 이미지 기본 `SHOWCASE_BIND_ADDRESS=0.0.0.0` (`INF/docker/showcase.Dockerfile:33`) |
| 서명 키 | `INF/compose.stack.yml:7-9` | 포털↔워크로드 HMAC 키(`HmacSHA256`, `BZ/internal/InternalContextSigner.java:17`, `:32-53`) | 시각 차 60초 초과면 무시 (`BZ/internal/InternalContextConfiguration.java:18`, `InternalContextFilter.java:64-69`) |

### 2.1 업무 API (모든 보안 공통, `BZ/work/BusinessController.java`)

| 작업(`BZ/work/BusinessOperation.java:7-38`) | 경로 | 줄 | D 보호(`ContexaBusinessOperations.java`) |
|---|---|---|---|
| PROJECT_LIST | `GET /api/projects` | `:55` | 없음 (`:38-41`) |
| DOCUMENT_READ | `GET /api/documents/{key}` | `:60` | 비동기 READ (`:43-47`) |
| DOCUMENT_DOWNLOAD | `GET /api/documents/{key}/download` | `:67` | 비동기 READ (`:49-53`) |
| EXPORT | `POST /api/projects/{p}/exports?items=N` | `:78` | 동기 EXPORT (`:55-59`) |
| EXPORT_ASYNC | `POST /api/projects/{p}/exports/async?items=N` | `:86` | 비동기 EXPORT (`:67-71`) |
| EXPORT_STREAM | `GET /api/projects/{p}/exports/stream?items=N` | `:94` | 비동기 EXPORT (`:61-65`) |
| ROLE_GRANT | `POST /api/admin/role-grants?project&grantee&responsibility` | `:108` | 동기 ADMIN, privileged (`:79-85`) |
| CUSTOMER_READ | `GET /api/customers/{key}` | `:119` | 비동기 READ (`:73-77`) |

- 업무 요청 객체는 서명 맥락이 있으면 회사 시각·실행 ID·요청 ID를 쓰고, 없으면 실제 시계와 null을 씁니다 (`BZ/work/BusinessRequest.java:22-28`).

### 2.2 업무 DB 스키마 (`BR/`)

| 표 | 정의 | 뜻 | 실행이 넣는가 |
|---|---|---|---|
| role, employee | `V1__work_foundation.sql:2-16`, email·office_network `V2:14-16` | 역할·직원 | 아니오(생성기) |
| project, project_assignment | `V2:18-37` | 프로젝트, 담당(책임·기간) | 아니오 |
| document | `V2:39-53`, run_id·author `V5__run_documents.sql:5-9` | 문서(유형·민감도·본문) | DOCUMENT 사실 (`BZ/run/RunRegistry.java:79`) |
| customer | `V2:55-63` | 고객과 담당 영업 | 아니오 |
| device, access_history | `V2:65-82` | 기기, 일별 접근 수 | 아니오 |
| run_principal | `V2:85-94` | 실행 주체 ↔ 직원 (employee_key FK) | 예 (`RunRegistry.java:26-34`) |
| itsm_ticket | `V2:97-115` | 티켓(INCIDENT·CHANGE, 기간·상태) | TICKET (`RunRegistry.java:40`) |
| oncall_roster | `V2:117-128` | 당번 | ONCALL (`:94`) |
| approval | `V2:130-146`, approved_at `V6:20` | 승인(목적·최대 건수·기간) | APPROVAL (`:53`) |
| scripted_activity | `V2:149-157`, client_ip `V8` | 주인공의 평소 업무(템플릿 학습 재생용) | 아니오 |
| plain_user | `V2:160-164` | A·B·C1·C2 로그인 계정 | 예 (`PlainInternalController.java:68-72`) |
| export_job | `V2:167-186`, company_at `V9` | 내보내기 결과(전달 건수) | 업무 결과 |
| rule_decision_log | `V2:189-205` | B·C1·C2 판정과 사실 | 판정 기록 |
| travel_plan | `V3__travel_plan.sql:3-16` | 출장(도시·망) | TRAVEL (`RunRegistry.java:68`) |
| role_grant | `V4__role_grant.sql:3-14` | 권한 부여 결과 | 업무 결과 |
| company_policy | `V6__company_policy.sql:4-19`, `V7__access_policy.sql:7-11` | 반출·접근 승인 규정(담당 한도 500 등) | 아니오 |
| (없음) 위임 기록 | - | 업무 DB에 위임·에이전트 표는 없음 (V1~V9 전체 확인) | - |

- 실행 정리는 run_id로 위 표의 실행 행을 지웁니다 (`RunRegistry.java:119-131`).

### 2.3 계정·로그인·MFA 코드가 만들어지는 경로

| 단계 | 경로 | 근거 |
|---|---|---|
| plain 계정 | 포털 → B `POST /internal/runs/{runId}/principals` → `run_principal` + `plain_user` | `WorkloadAdmin.java:82-86`, `PlainInternalController.java:63-74` |
| plain 로그인 조건 | `plain_user` ⋈ `run_principal` ⋈ `employee` (역할 = 직원 역할) | `PL/security/PlainUserDetailsService.java:26-31` |
| D 엔진 계정 | 포털 → D `POST /internal/runs/{runId}/principals` → `run_principal` 등록 + 엔진 `users`·`user_groups`(승인자면 ROLE_ADMIN) + 템플릿 복제 | `WorkloadAdmin.java:102-104`, `ContexaInternalController.java:133-148`, `DX/principal/RunPrincipalService.java:53-79` |
| D 2단계 | MFA 필요 인자 1개, 1차 restLogin, 2차 이메일 OTT | `DX/security/ContexaWorkloadSecurityConfiguration.java:33-36` |
| MFA 코드 | 엔진이 메일을 보내면 `DemoInboxEmailService`가 메모리에 받는 사람별 최신 코드만 둠 | `DX/inbox/DemoInboxEmailService.java:42-53`, 빈 `ContexaWorkloadSecurityConfiguration.java:41-44` |
| 코드 읽기 | 포털 → D `GET /internal/inbox/{recipient}` (꺼내면 지움) | `WorkloadAdmin.java:118-125`, `ContexaInternalController.java:174-177` |
| `/internal/**` 보호 | 서명 맥락 없으면 403 `INTERNAL_SIGNATURE_REQUIRED` | `BZ/internal/InternalApiGuardFilter.java:28-37` (Spring Security는 permitAll: `PL/security/PlainSecurityConfiguration.java:94`) |
| 실행 끝 | 엔진 주체·업무 실행 행 삭제 | `RunOrchestrator.java:606-621`, `:332-345` |

---

## 3. 화면별 데이터 표

화면 유형: 정의는 `DOC/showcase/화면재편-기획안.md:144-152`(T0 테스트 안내, T1 부분 표지, T2 비교, T3 예측, T4 실행, T5 결과, T6 이유, T7 설명, T8 부분 정리). 지금 본 흐름의 쓰임은 `DOC/showcase/최종화면-구현계획.md:42-62`와 `WEB/journey/route.json:2-40`대로 T0 그룹 표지, T1 시작, T3 요청+예상+보내기, T4 실시간 콘솔, T5 결과·차이·판단, T6 결과와 이유, T7 설명, T8 정리입니다. T2는 지금 route.json에 쓰이지 않습니다(`route.json:2-40` 확인). 타입 선언은 `WEB/journey/journey.ts:15`.

출처 약어: **정의**=사례 JSON(`PR/scenarios`), **업무DB**=업무 DB 조회, **실행**=실행 기록(포털 `run`·`run_arm_result`, 라이브 메모리 `LiveRun`), **판정**=D 판정 기록(`run_decision`, D `/internal/decisions`), **해부**=판정 해부(`run_decision_anatomy`), **봉인**=D 봉인 패키지(`/internal/decisions/{id}/prompt-facts`), **측정**=벤치마크 측정 기록, **사전**=`WEB/i18n/*.json`.

| 화면(번호·유형) | 컴포넌트 | 부르는 API | 쓰는 응답 필드 | 출처 |
|---|---|---|---|---|
| 1-1 T1 | `WEB/pages/try/HookPage.tsx` | `GET /api/hook` (`PT/hook/HookController.java:17`), `GET /api/lab/options` | 훅 열(HookColumn) 세부는 미확인 | 측정(훅 슬롯 S13·S13T, `PT/hook/HookStore.java:20-21`) |
| 1-2 T7 | `WEB/pages/main/IntroMapPage.tsx` | `GET /api/benchmark` (`IntroMapPage.tsx:39`) | cases[].runs·results | 측정 + 사전(`group.*`, 주제 묶음 `:10-20`) |
| 2-0·3-0·4-0·5-0·6-0 T0 | `WEB/pages/try/BriefingPage.tsx:89-136` | `GET /api/visitor`, `GET /api/journey` (`:92-93`) | runs[](RecapLine: scenarioKey, lab, engineAction, exposedItems, business{A..D}) (`:44-82`) | 실행(방문자 실행 채점, `PT/journey/JourneyViews.java:255-267`) + 사전 `cover.{그룹}.*` |
| 2-1·4-1·5-1 T3 | `WEB/pages/main/RequestPage.tsx` (role attacker·owner·insider) | `GET /api/lab/options`(`:45`), `GET /api/live/before/{사례}?step=1`(`:48`), `GET /api/runs/{runId}/steps/1/anatomy`(`:50`), `GET /api/settings`(`:46`), `POST /api/journey`, `POST /api/live/runs` | labCase.conditions·facts(APPROVAL·DOCUMENT 제목)·requests[0](items, project, target, document) (`:185-247`); employee.officeNetwork(`:204`); comparison.companyTime(`:102`), usualVsNow[authenticationType](`:65-66`); anatomy.context.resource.httpMethod·requestPath(`:64`, `:117-119`); businessRecord.assignedExportLimit(`:105`) | 정의(조건·사실·요청), 업무DB(담당 여부: `PT/lab/LabController.java:144-146`), 해부(같은 사례의 최근 실제 실행: `PT/live/LiveController.java:373-389`), 공개 설정 |
| 2-2·4-2·5-2 T4 | `WEB/pages/main/ConsolePage.tsx` (+ `consoleParts.tsx` Lane·CompareStrip, 여러 요청이면 `RequestSteps.tsx` StepRow `ConsolePage.tsx:290-306`) | `GET /api/live/runs/current`(폴링), `GET /api/live/runs/current/analysis?step`, 끝나면 `/api/runs/{id}/steps/N/{result,anatomy,received}`, `GET /api/live/before`, `/api/benchmark`, `/api/settings`(C1 임계), `/api/teasers`(CHALLENGE_OUTCOMES); 버튼 `POST /api/live/runs/current/{code,answer,cancel,abandon,release-start,release-request,release-approve,next}` | View.steps[].layers{A,B,C1,C2,D}{outcome,httpStatus,deliveredItems,elapsedMs,ruleId}, challenge, release, status (`PT/live/LiveRun.java:101`, `:116`, `:131-164`); AnalysisView.stages[]{type,atMs,action,layer,riskScore}, decision{finalAction,riskScore,applied,reason,adverseLabels,totalAnalysisMs} (`LiveController.java:246-287`); received.usualVsNow·businessFacts·sensitivity(`WEB/pages/main/consoleData.ts:105-164`); anatomy.interpretation.calls·recovery.challenge | 실행(라이브 메모리 → `run_arm_result`), 판정(D 기록·이벤트), 해부, 측정(대기 시간 추정 `DecisionWaits`) |
| 2-3 T6 | `WEB/pages/main/ResultPage.tsx` (S13 고정 `:44`) | 실행 보기, `/anatomy`, `/received`, `GET /api/live/baseline/{직원}`, `GET /api/engine/actions` (`:45-52`) | recorded.finalAction(`:53`, `:76`), D.deliveredItems(`:77`), usualVsNow[device/accessHour/network].inUsual(`:84-96`), sizeRatio·businessFacts[ITEMS](`:97-103`), departureCount(`:112`), C2 레인 deliveredItems(`:105-106`), ESCALATE ttlSeconds(`:114`) | 실행, 해부, 템플릿 기준선 카드(`LiveController.java:406-428`) |
| 3-1·3-2·3-3 T7 | `EvidenceMapPage`·`EvidencePromptPage`·`EvidenceVerdictPage` | `useEvidenceRun()` = 방문자 실행 없으면 측정 마지막 run (`WEB/pages/main/evidence.ts:17-33`): `/anatomy`, `/received`, `/facts`, `/quality`, `/result`; 3-1은 `/api/cases/A6T/measured`(`EvidenceMapPage.tsx:30`, `:51`) | 봉인 사실 줄, reasonCodes, hypotheses, 해부 calls | 봉인, 해부, 측정 |
| 4-3 T5 | `WEB/pages/main/DiffPage.tsx` | `GET /api/runs/{정상}/steps/1/input-changes?against={공격}`(`:89`), `/api/journey`, `/api/benchmark`, `/api/lab/options` | 입력 차이 줄 | 해부 두 개 비교 |
| 4-4 T4 | `WEB/pages/main/CheckPage.tsx` (S14 `:28`) | `/api/lab/options`, `/api/live/before/S14`, `/api/journey`, `/api/teasers`, `/api/benchmark`, 라이브 보내기 (`:56-70`) | StepRow·CheckRecord(anatomy.recovery.challenge, `WEB/pages/main/RequestSteps.tsx:145-170`) | 실행, 해부 |
| 5-3 T5 | `WEB/pages/main/InsidePage.tsx` (S16, 정상 짝 S16T) | `useEvidenceRun(S16)`, `GET /api/runs/{id}/score`, `/anatomy`, `/facts`, `/quality`, `/steps/N/result`, `/api/benchmark` (`:70-85`) | score.verdicts(판정한 요청), business.D.exposedItems(`:124`); recorded.finalAction·applied(`:108-126`); quality.reasonCodes[].fact(엮은 사실 수 `:113`), quality.hypotheses(`:166`); benchmark cases[S16,S16T].results·runs, scope.protocols.finishedAt, suites[RULE_BLIND] | 실행 채점, 해부, 봉인(가설·근거 코드: `PT/anatomy/SealedPromptViews.java:161-207`), 측정 |
| 6-1 T7 | `RuleSwitchPage.tsx` | `/api/journey`, `/api/settings` | 방문자 두 실행의 레인 결과 | 실행 |
| 6-2 T4 | `ChangePage.tsx` | `POST /api/lab/runs`, 라이브 실행·분석, `GET /api/lab/runs/{id}/delta`, `/anatomy` 전·후, `/api/benchmark`, `/api/settings` | 바뀐 프롬프트 줄 | 실행, 해부 |
| 6-3 T5 | `RunsPage.tsx` | `/api/benchmark` (`:67`) | 사례별 반복 결과 | 측정 |
| 7-1·7-2 T8 | `SummaryPage.tsx`, `NextPage.tsx` | `/api/benchmark`, `/api/journey`, `/result`, `/api/benchmark/prompt-quality` (SummaryPage); `/api/benchmark` (NextPage `:16`) | 세부 미확인 | 측정, 실행 |
| 판단 근거 보기 창 | `WEB/components/detail/DecisionDetail.tsx` (탭 `useDetail.ts:8-16`) | summary: `/steps/N/result`, `/score`; received: `/received`; process·answer: `/anatomy`; prompt: `/facts`, `/quality`, `/other-bundle`; rules: `/exchanges`, `/received`, `/api/teasers`; original: `/exchanges`, `/quality` (각 탭 파일의 use* 호출) | 탭별 | 실행·판정·해부·봉인·모델 교환(`run_model_exchange`) |

### 3.1 role 확장 방식 (내부자 추가 때 쓴 방식)

- 역할은 `type Role = 'attacker' | 'owner' | 'insider'` 하나로 정의하고, 역할마다 사례·주소·화면 번호·체험 키를 표로 둡니다 (`WEB/pages/main/mainCases.ts:13-39`).
- 같은 컴포넌트를 `role` 속성으로 재사용합니다: `App.tsx`가 경로별로 `role="insider"`를 넘깁니다 (`WEB/App.tsx:103-106`).
- 화면 안의 역할 분기: 요청 행 강조(`RequestPage.tsx:196-197`, `:207`, `:225`), 계정 문구 키 `main.request.account.{role}` (`:196`, 사전 `ko.json:4680-4682`), 메일함 보유(`ConsolePage.tsx:75`), 차단 해제는 owner만(`:98`, `:499`), 공격자 자동 코드·해제 시도(`:122-150`, `:492`).
- 요청이 여러 건이면 레인 대신 요청별 행(`ConsolePage.tsx:79`, `:290-306`).

### 3.2 사전(i18n) 키 구조

- 한·영 각 5,301개, 평평한 점 표기 키입니다(최상위 키 수 = 잎 키 수, `WEB/i18n/ko.json`·`en.json` 집계). IN-7 당시 기록은 4,968개(`DOC/showcase/최종화면-구현계획.md:326`).
- 주요 갈래: `main.{번호}.*`(화면 문장, 예: 5-1 3개·5-3 18개), `cover.{그룹}.{question,do,check,try,learn,past.*}`, `group.{n}`·`group.tab.{n}`(`ko.json:4501-4506`, `:5212`), `main.request.*`, `main.console.*`, `main.lane.*`(`:4749-4759`), `main.verdict.*`, `main.result.*`, `badge.{run,repeated,other}`(`:5019-5021`), `person.{직원키}`(adm-a, eng-k만), `control.{A..D}.name`(`:16-22`), `dim.*`, `fact.*`, `detail.*`.
- 사전은 본 흐름용 first와 나머지 rest로 나뉘어 로드됩니다 (`WEB/i18n/index.ts:14-28`, `contexa-showcase/web/dictionarySplit.ts:6-12`). 새 글자는 부분 글꼴 재생성이 필요합니다 (`contexa-showcase/web/scripts/font-subset.py`, `contexa-showcase/web/fontCoverage.test.ts:5-8`).

### 3.3 출처 배지와 판단 근거 보기 창

- 배지 3종: `run`(방금 실제 실행), `repeated`(같은 상황 N회 실행 기록), `other`(다른 설정의 기록). runId가 있으면 버튼이 되어 `detail.show(runId, step)`으로 창을 엽니다 (`WEB/components/main/SourceBadge.tsx:10`, `:23-45`). 사용처: Console·Check·Change·Diff·Evidence 3종·Inside·IntroMap·Result·RuleSwitch·Runs·Summary·ReleaseRecord.
- 창은 모든 화면에 한 번 붙고 주소 `/run/:runId/detail?step=&tab=`도 있습니다 (`DecisionDetail.tsx:22-25`, `DetailAddress.tsx:5-25`).

---

## 4. 사례 JSON 형식과 목록 요약

### 4.1 위치와 형식

- 본 사례: `PR/scenarios/*.json` 41개, `classpath*:scenarios/*.json`으로 읽고 키 중복이면 시작 실패, 정규형 SHA-256을 함께 둡니다 (`PT/scenario/ScenarioCatalog.java:38-50`, `:66-77`).
- 녹화 쌍: `PR/pairs/{A1,A3,A5,A6,A8}.json` 5개(쌍 = 공격 장면 + 정상 장면, `PT/replay/PairDefinition.java:14-26`). A7 쌍 파일은 없습니다.
- 변형 사례: `PR/reactivity/variants/*.json` 15개(INS-V1·V2 포함), `POST /ops/variant-runs/{key}`로만 실행 (`PT/ops/OpsController.java:210`, `:225`).
- 최상위 필드 (`PT/scenario/ScenarioDefinition.java:26-40`): `key`, `version`, `title{ko,en}`, `protagonist`(직원 키), `template`(학습 템플릿 복제 여부), `timeSlot`, `device`(USUAL·NEW `:71-73`), `pace`(PACED·RAPID `:87-89`), `facts[]`, `steps[]`, `oracle`, `network`(OFFICE·EXTERNAL·TRAVEL, 생략 시 OFFICE `:79-85`), `frozenOn`, `suite`(RULE_BLIND·NORMAL_COMBINATION `:47`, `:55`).
- `facts[]` (`:104-107`): `kind` = TICKET·APPROVAL·ONCALL·TRAVEL·DOCUMENT(`:96-98`), 그 밖 ticketKind, approver, project, purpose, maxItems, validFrom/UntilOffset, status, team, city, country, network, `document{source,type,sensitivity,author,updatedOn,title,summary,body}`(`:124-125`), recordedAtOffset. 오케스트레이터가 키 `TCK-·APR-·ONC-·TRV-·DOC-<hex>-<n>`으로 업무 DB에 넣습니다 (`RunOrchestrator.java:785-818`). 엔진에는 문서의 영어 요약이 '작성자의 믿지 않는 글'로 갑니다 (`ScenarioDefinition.java:117-123`, `RunOrchestrator.java:795-797`).
- `steps[]` (`:162-168`): `operation`, `document{project,type,position,fact}`(`:132`), `project`, `customer`, `items`, `offsetSeconds`, `expected{A,B,C1,C2}`(ALLOW·DENY, D는 없음), `claimedTicket`, `grantee`, `responsibility`, `visitorSends`, `body`, `headers`, `requestIdOf`, `newSession`. 경로 변환은 `RunOrchestrator.java:630-643`. 서명 헤더·User-Agent를 headers에 넣으면 거부 (`:700-730`, `WorkloadClient.java:228-231`).
- `oracle` (`:210-232`): `classification`(NORMAL·THREAT·UNCERTAIN), `allowedEngineActions`, `rationale{ko,en}`, `counterpoint{ko,en}`, `actor`(값 `OWNER`만 정의, `:214`). 정답은 엔진에 주지 않습니다(`:201-203`). `/api/lab/options`는 oracle 중 classification만, `/api/cases`는 rationale·counterpoint까지 주고 actor는 어느 쪽에도 주지 않습니다 (`LabController.java:121-155`, `PT/scenario/CasesController.java:160-166`).
- 실제 사용 빈도(41개 집계): 최상위 network 3, suite 16, oracle.actor 2(S16, S18); 단계 키 visitorSends 2, claimedTicket 2, grantee 2, customer 15; body·headers·requestIdOf·newSession은 본 사례 단계에서 0.

### 4.2 사례 목록 (41개: 주인공 eng-k 21, adm-a 20 / 정답 THREAT 21, NORMAL 18, UNCERTAIN 2)

| 키 | 제목(ko) | 주인공 | 묶음 | 정답 | 단계 |
|---|---|---|---|---|---|
| A1 | 새 기기·회사 밖 네트워크에서 쓰는 계정 | eng-k | - | THREAT | READ×2 (EXTERNAL) |
| A1T | 등록된 출장지에서의 정상 접속 | eng-k | - | NORMAL | READ×2 (TRAVEL) |
| A3 | 내부자 대량 반출 | adm-a | - | THREAT | EXPORT GB-500 4,831 |
| A3A | 내부자 대량 반출(비동기식 판정) | adm-a | - | THREAT | EXPORT_ASYNC + DOWNLOAD |
| A3S | 내부자 대량 반출(스트림) | adm-a | - | THREAT | EXPORT_STREAM + DOWNLOAD |
| A3ST | 승인된 프로젝트 이관(스트림) | adm-a | - | NORMAL | EXPORT_STREAM (APPROVAL) |
| A3T | 승인된 프로젝트 이관 | adm-a | - | NORMAL | EXPORT (APPROVAL) |
| A3TA | 승인된 프로젝트 이관(비동기식 판정) | adm-a | - | NORMAL | EXPORT_ASYNC (APPROVAL) |
| A5 | 승인 없는 권한 부여 | adm-a | - | THREAT | ROLE_GRANT |
| A5T | 승인된 변경 티켓에 따른 권한 부여 | adm-a | - | NORMAL | ROLE_GRANT (TICKET) |
| A6 | 담당이 아닌 고객 레코드 연속 조회 | adm-a | - | THREAT | CUSTOMER_READ×5 |
| A6T | 장애 대응 티켓 범위 안의 고객 일괄 확인 | adm-a | - | NORMAL | CUSTOMER_READ×5 (TICKET) |
| A8 | 없는 장애 티켓을 대며 반출 | adm-a | - | THREAT | EXPORT 300 (claimedTicket) |
| A8T | 당번 중 실제 장애 티켓으로 반출 | adm-a | - | NORMAL | EXPORT 300 (TICKET, ONCALL) |
| K2 | 처음 쓰는 기기에서 담당 도면 열기 | eng-k | RULE_BLIND | NORMAL | READ |
| R1 | 역할 밖 요청(권한 검사가 막는 표본) | eng-k | - | THREAT | CUSTOMER_READ×2 (template false) |
| S01 | 담당 업무의 정상 반복 | eng-k | - | NORMAL | READ×2 + EXPORT 20 |
| S02 | 승인된 대량 처리 | adm-a | - | NORMAL | EXPORT 400 (APPROVAL) |
| S03 | 승인된 예외·긴급 작업 | eng-k | - | NORMAL | READ + EXPORT (TICKET) |
| S04 | 탈취된 정상 계정의 탐색 | eng-k | - | THREAT | LIST + READ×2 + EXPORT |
| S05 | 넓은 권한의 업무 범위 이탈 | adm-a | - | THREAT | CUSTOMER_READ×3 |
| S06 | 낮은 속도의 누적 자료 수집 | eng-k | - | THREAT | READ×4 + EXPORT |
| S07 | 정당성 근거가 부족한 예외 | eng-k | - | UNCERTAIN | READ + EXPORT (TICKET) |
| S08 | 신규 사용자·부족한 기준선 | eng-k | - | UNCERTAIN | READ×2 (template false) |
| S09 | 낮은 신뢰도 내용의 판단 유도 | adm-a | - | THREAT | READ + EXPORT (DOCUMENT) |
| S09C | 낮은 신뢰도 내용의 판단 유도 · 대조 | adm-a | - | THREAT | READ + EXPORT (DOCUMENT) |
| S10 | 기록은 정상, 행동만 이상한 새벽 내려받기 | eng-k | RULE_BLIND | THREAT | DOWNLOAD×6 |
| S11 | 승인 범위를 나눠 넘기는 반복 반출 | adm-a | RULE_BLIND | THREAT | EXPORT 480×5 (APPROVAL) |
| S11T | 승인 범위 안에서 나눠 하는 반복 반출 | adm-a | NORMAL_COMBINATION | NORMAL | EXPORT 480×5 (APPROVAL) |
| S12 | 요청 뒤에 기록된 승인 | adm-a | RULE_BLIND | THREAT | EXPORT 300 (APPROVAL) |
| S13 | 담당 범위 안에서 평소의 20배 넘게 반출 | eng-k | RULE_BLIND | THREAT | EXPORT HX-310 480 (NEW 기기) |
| S13T | 담당 범위 안의 큰 반출, 평소 기기 | eng-k | RULE_BLIND | NORMAL | EXPORT HX-310 480 |
| S14 | 출장지에서 새 노트북으로 하는 새벽 정상 업무 | eng-k | NORMAL_COMBINATION | NORMAL | READ×2 + EXPORT (TRAVEL) |
| S15 | 내부 등급 운영 문서로 하는 평소 업무 | adm-a | NORMAL_COMBINATION | NORMAL | READ×2 + EXPORT |
| S16 | 담당 프로젝트 안의 영업 기밀 문서 수집 | eng-k | RULE_BLIND | THREAT, actor OWNER | DOWNLOAD×3 (DOCUMENT×3) |
| S16T | 담당 프로젝트 안의 설계 문서 내려받기 | eng-k | RULE_BLIND | NORMAL | DOWNLOAD×3 (DOCUMENT×3) |
| S17 | 퇴근 뒤 처음 보는 기기로 담당 범위 안 300건 반출 | eng-k | RULE_BLIND | THREAT | EXPORT 300 |
| S17T | 퇴근 뒤 평소 PC로 하는 담당 범위 안 300건 반출 | eng-k | RULE_BLIND | NORMAL | EXPORT 300 |
| S18 | 담당 프로젝트 폴더의 인사 문서 수집 | eng-k | RULE_BLIND | THREAT, actor OWNER | DOWNLOAD×3 (DOCUMENT×3) |
| S19 | 처음 보는 기기로 담당 설계 문서를 몇 초 간격으로 연달아 내려받기 | eng-k | RULE_BLIND | THREAT | DOWNLOAD×3, RAPID |
| S19T | 평소 PC로 담당 설계 문서를 몇 초 간격으로 연달아 내려받기 | eng-k | RULE_BLIND | NORMAL | DOWNLOAD×3, RAPID |

- 근거: 각 파일의 `key`·`protagonist`·`suite`·`oracle` 값을 직접 집계했습니다(`PR/scenarios/*.json`). 목록 자체는 시험이 고정합니다 (`PTT/orchestrator/OrchestratorUnitTest.java:40-43`).
- 주인공은 `CompanyBlueprint`의 두 사람입니다: adm-a(관리자 A), eng-k(설계 엔지니어 K, 담당 HX-310) (`BZ/company/CompanyBlueprint.java:20`, `:23`, `:41`). 템플릿이 있는 사람 = `scripted_activity`가 있는 직원 (`PlainInternalController.java:107-111`).
- 본 흐름이 쓰는 사례: 공격 S13, 정상 S13T, 내부자 S16(정상 짝 S16T), 4-4 S14 (`WEB/pages/main/mainCases.ts:15-18`, `CheckPage.tsx:28`, `PT/journey/JourneyViews.java:37`, `PT/hook/HookStore.java:21`).
- 벤치마크 묶음: 어떤 suite 문자열이든 사례 묶음으로 따로 셉니다 (`PT/benchmark/BenchmarkService.java:399-408`). 사각지대 집계는 RULE_BLIND만 특별 취급 (`PT/benchmark/BenchmarkView.java:118`).

---

## 5. 그룹 하나를 추가할 때 바꿀 곳 (IN-7 기록과 대조)

| 영역 | 파일:줄 | 바꿀 내용 | IN-7 기록 대조 |
|---|---|---|---|
| 웹 경로 | `WEB/journey/route.json:31-40` | 새 그룹 행 추가, 뒤 그룹의 number·act 이동, 유형(T0~T8) 지정 | 5-0~5-3 추가, 옛 5→6, 6→7 (`최종화면-구현계획.md:326`) 일치 |
| 웹 그룹 수 | `WEB/journey/journey.ts:11`(Act), `:21`(GROUPS), `:117`(skipTarget이 GROUPS.length 사용) | 그룹 범위 늘림 | 일치(7그룹) |
| 웹 라우터 | `WEB/App.tsx:90-111` | 새 주소 → BriefingPage/RequestPage/ConsolePage/새 화면, 옛 주소 Navigate | `/compare/inside` → `/insider/reason` (`:111`) 일치 |
| 첫 화면 미리 읽기 | `WEB/firstScreens.ts:15-40`(주소→코드 표, 내부자 `:30-33`) | 새 주소 추가 | IN-6 바꿀 곳에 있음 |
| 역할·사례 | `WEB/pages/main/mainCases.ts:13`, `:15`, `:21-25`, `:28-32`, `:35-39`; `WEB/api/journey.ts:45`(experience 'E1'·'E2'·'E3') | Role 값, MAIN_CASES, 경로, 번호, 체험 키 | 내부자 역할 추가 일치 |
| 요청·콘솔 분기 | `RequestPage.tsx:196-225`, `ConsolePage.tsx:75`, `:98`, `:122-150`, `:492`, `:499` | 새 역할의 행 강조·메일함·해제 동작 | 일치 |
| 표지·주제 카드 | `WEB/pages/try/BriefingPage.tsx:44-82`(그룹 3·5·6의 지난 주제 줄), `:133`(ThemePair 그룹 2·5); `WEB/components/main/themes.ts:2-5` | 그룹 번호와 지난 줄 규칙 | ThemePair 2·5 그룹 일치 |
| 지도 | `WEB/pages/main/IntroMapPage.tsx:10`(TOPICS), `:14-17`(THEME_GROUPS), `:20`(AFTER) | 주제·그룹 묶음 | 일치 |
| 상단 그룹 탭 | `WEB/components/AppHeader.tsx:105`, `:117` | `GROUPS`와 `group.tab.{n}` 키 사용(코드 변경 없음, 사전만) | - |
| 사전 | `WEB/i18n/ko.json`·`en.json`: `group.{n}`(`ko.json:4501-4506`, `:5212`), `group.tab.{n}`, `cover.{n}.*`, `main.{번호}.*` | 새 키 추가, 뒤 그룹 키 번호 이동, 한·영 키 수 같게 | 키 이동 기록 일치 |
| 글꼴 | `contexa-showcase/web/scripts/font-subset.py`, `contexa-showcase/web/fontCoverage.test.ts:5-8` | 새 글자면 부분 글꼴 재생성 | '새 글자 8개' 재생성 기록 일치 |
| 웹 시험 | `WEB/journey/journey.test.ts:23`(그룹·주소 수), `:58-64`(표지 수); `WEB/pages/try/BriefingPage.test.tsx:137-145`; `IntroMapPage.test.tsx`; `RequestPage.test.tsx`; `InsidePage.test.tsx`; `WEB/firstScreens.test.ts` | 수·번호·문장 | 웹 단위 시험 265건 기록 |
| e2e | `WE2E/portal/mainFlow.spec.ts:105-109`(CONSOLES), `:410-430`(그룹 걷기); `WE2E/portal/keyboard.spec.ts:328`(마지막 '7-2') | 새 번호·주소 | mainFlow·keyboard 수정 기록 일치 |
| 자동 검사 | `WE2E/main-audit.mjs:39`(route.json 읽음), `:143-149`(보내기 전 빈 상태 문구 목록) | 새 화면의 빈 상태 키 추가 | '5-3 빈 상태 목록에 더함' 기록 일치 (`:148`) |
| 포털 여정 범위 | `PT/journey/JourneyViews.java:48`(LAST_PART), `:232`(범위 검사) | 그룹 수 | 7 일치 |
| 포털 체험 사례 | `PT/journey/JourneyViews.java:37`(EXPERIENCE_CASES), `:245`, `:271` | E4 등 새 체험 키와 사례 | E3=S16 일치 |
| Flyway | 새 `PR/db/migration/portal/V30__...sql`(마지막은 `V29__decision_quality_publication.sql`), 본보기 `V28__journey_insider_group.sql:4-6` | 제약 해제 → 이동할 그룹 `act+1` → 범위 제약 다시 | V28 일치 |
| 포털 시험 | `PTT/journey/JourneyIntegrationTest.java:76-80`; `PTT/hook/HookViewsTest.java`; `PTT/live/LiveRunTest.java:209-224`; `PTT/orchestrator/OrchestratorUnitTest.java:40-43`(사례 목록), `:366-376` | 범위·사례 | 기록의 시험 이름과 일치 |
| 훅·막 끝 카드 | `PT/hook/HookStore.java:20-21`, `PT/journey/ActEndCards.java:27` | 주제 사례가 바뀌면 | 훅 S13·S13T 일치. ACT_CASES는 A3 계열 그대로 둔다는 기록과 코드(`:27` A3·A3T·A6T·A3A) 일치 |
| 사례 | `PR/scenarios/새키.json` + `OrchestratorUnitTest.java:40-43` | 새 사례 정의와 목록 고정 시험 | S16·S16T 추가 일치 |

---

## 6. 업무 에이전트 데모에 쓸 수 있는 것과 새로 필요한 것

| 항목(작업 ID) | 지금 있는 것(파일:줄) | 새로 필요한 것 |
|---|---|---|
| 점검 사례 정의 (A6-1) | 사례 JSON 형식·정답·counterpoint·suite (`ScenarioDefinition.java:26-40`, `:210-232`); 규칙 보안 기대값 `expected{A,B,C1,C2}`와 실측 대조 `rulesAsExpected` (`RunOrchestrator.java:821-832`); 측정 실행 `/ops/runs/{key}?repeat`, `/ops/protocol` (`OpsController.java:505-527`); suite별 집계 (`BenchmarkService.java:399-408`) | 위임 사실 종류(예: `kind: DELEGATION`)를 `Fact`(`ScenarioDefinition.java:96-107`)와 `RunOrchestrator.facts`(`:785-818`)에 추가; 에이전트 사례 묶음 이름(예: AGENT); 정상·범위 밖·목표 다른 자원·기간 뒤·평소와 다른 양 5종 사례 파일; 목록 시험 갱신 (`OrchestratorUnitTest.java:40-43`) |
| 정답의 행위자 (A6-1, A7-3) | `oracle.actor` 값 `OWNER`(내부자, 메일함 보유) (`ScenarioDefinition.java:205-232`) | 에이전트·위임 행위자 값(예: AGENT)과 그 값에 따른 응답자 동작 |
| 위임 기록 저장 (A7-1) | 업무 DB에 위임 표 없음(`BR/V1`~`V9`). 실행 사실 표의 본보기: run_id 열을 가진 `itsm_ticket`·`approval` (`BR/V2__virtual_company.sql:97-146`), 넣기·지우기 `RunRegistry.java:36-100`, `:119-131`, 사실 묶음 `BZ/run/RunFacts.java:12`, 포털 호출 `WorkloadAdmin.java:89-91` | 새 Flyway `BR/V10__...sql`(위임자, 에이전트, 목표, 허용 작업·자원, 기간, 상태, run_id); `RunFacts.Delegation`; `RunRegistry` insert·delete; P2 설계의 이름 후보 `automation_delegation` (`DOC/showcase/P2-설계.md:20`) |
| 위임 공급자 (A7-1) | 코어 SPI `DelegationContextProvider extends ContextEnricher`(표지 인터페이스, `CORE/autonomous/context/enricher/DelegationContextProvider.java:20`), 자동 수집 `contexa-autoconfigure/src/main/java/io/contexa/autoconfigure/core/autonomous/CoreAutonomousAutoConfiguration.java:242`, 호출 `CORE/autonomous/context/DefaultCanonicalSecurityContextProvider.java:1056`, 채울 칸 `CanonicalSecurityContext.Delegation`(delegated, agentId, objectiveId, allowedOperations, allowedResources, expiresAt 등 `CORE/autonomous/context/CanonicalSecurityContext.java:291-307`). 넣을 자리의 본보기: `BusinessFrictionProvider` 빈 등록 `DX/ContexaWorkloadConfiguration.java:132-135`, 조회기 `BZ/context/BusinessContextLookup.java:20-62`, 구현 `BZ/context/JdbcBusinessContextLookup.java` | D에 `@Bean` 위임 공급자(같은 설정 클래스), `BusinessContextLookup`에 위임 조회 메서드와 JDBC 구현(기록용 `RecordingBusinessContextLookup` 포함 여부 결정), 봉인 사실 원천 검사에 위임 줄 추가(`DX/context/ShowcaseFactSourceVerifier.java:24-31`) |
| 헤더로 위임 전달 | 코어 브리지의 기본 헤더 `X-Contexa-Delegated`, `X-Contexa-Agent-Id` (`contexa-common/src/main/java/io/contexa/contexacommon/security/bridge/BridgeProperties.java:266-267`) | 쇼케이스는 `x-contexa-` 헤더를 모든 요청에서 숨기므로(`InternalContextRequest.java:20`, `:86-100`) 이 길은 못 씀 → 공급자 경로 |
| 에이전트 주체(계정) (A7-2) | 실행 하나 = 주인공 주체 하나 (`RunOrchestrator.java:150`, `:189`, `:205`); 실행 중 두 번째 주체 본보기 = 승인자 (`RunOrchestrator.java:222-223`, `:334-341`, `RunPrincipalService.java:71-78`); plain 로그인은 직원 행 필요 (`PlainUserDetailsService.java:26-31`, `run_principal.employee_key` FK `V2:88`) | 에이전트 주체 생성(직원 행 재사용인지 새 표인지 결정), 엔진 그룹 매핑(`DX/policy/EngineRbacSeeder` engineGroup), 위임자·에이전트 두 주체의 정리 |
| 에이전트 기준선 (A7-2) | 템플릿 = 주인공의 `scripted_activity`를 실제 요청으로 재생해 학습 (`PT/template/TemplateLearner.java:37-44`); 템플릿 없으면 실행 거부 (`RunOrchestrator.java:177-180`, `LiveGate.java:95`) | 에이전트용 평소 활동(또는 `template:false`); 10.3절 3항(에이전트 활동은 에이전트·위임별 기준선만) 반영 |
| 호출 순서 고정 (A7-2) | 단계 = 정의된 순서·간격(`steps[].offsetSeconds`, `pace`), 다섯 곳 동시 전송 (`RunOrchestrator.java:229-292`, `:382-402`) | 단계마다 보내는 주체(위임자/에이전트)를 정하는 칸(지금 Step에 없음, `ScenarioDefinition.java:162-168`) |
| 다섯 보안 비교 (A7-2) | A(WAF)·B·C1·C2·D 그대로 (`ControlAuthorizationManager.java:79-83`, `ControlEndpoints.java:35-41`) | C2가 위임 기록을 보지 않는다면 그대로(기대값만 정의). 위임을 C2 규칙에 넣을지는 공정성 결정 필요 |
| 업무 API (A7-2) | 7종 작업 (`BusinessController.java:55-120`), D 보호 범주 (`ContexaBusinessOperations.java:43-85`) | 기획안 예시('보고서용 자료 정리')는 기존 READ·DOWNLOAD·EXPORT로 표현 가능. 새 작업이 필요한지는 사례 설계에서 결정 |
| 외부 에이전트 연결 (A7-2) | 업무 API는 서명 없는 요청도 처리(엔진 입력만 잃음, `InternalApiGuardFilter.java:13-16`) | 연동 방식 미정(기획안 10.3절 5항). 7절의 세 걸림돌 해소 방법 필요 |
| 추가 인증 → 위임자 확인 (A7-3) | 녹화 응답자: 정상·OWNER만 메일함 코드 (`ChallengeResponder.java:49-82`); 라이브: 공격자는 NO_MAILBOX (`LiveRun.java:435-439`); 차단 해제는 관리자 승인 흐름 (`ChallengeResponder.java:19-25`, `RunOrchestrator.java:432-438`, `PT/orchestrator/RunApprover.java`) | 위임자 확인(승인·거절) 응답 경로. 코어 화면 AC-1~AC-3(`DOC/agent/Agent보안-화면설계.md` 2절)과 구현 A5-2 SPI에 맞춘 포털 응답자·라이브 버튼 |
| 요청 화면 (A7-3) | `RequestPage` 행 구성: 정의·직원·최근 실행 해부·공개 설정에서 값 (`RequestPage.tsx:173-250`) | 위임 기록 행(목표·허용 작업·자원·기간)과 '에이전트가 쓴 글' 칸; `/api/lab/options`에 위임 사실이 실리면(`LabController.java:132`) 재사용 가능 |
| 콘솔 (A7-3) | role 재사용, 여러 요청이면 요청별 행 (`ConsolePage.tsx:79`, `:290-306`, `RequestSteps.tsx:44-58`), 다음 요청부터 적용 표시 (`RequestSteps.tsx:107-109`) | role `agent` 추가, 위임과 실제 요청의 차이 줄 |
| 판정·근거 (A7-3) | 5-3 방식: 판정 카드, 가설(봉인 hypotheses), 근거 코드가 가리키는 사실 줄 (`InsidePage.tsx:108-126`, `:166`, `SealedPromptViews.java:161-207`); 사실 낱말에 'Delegation' 라벨 있음 (`WEB/components/facts/factWords.ts:91`, `WEB/domain/reasons.ts:19`, `WEB/components/detail/OriginalTab.tsx:26`) | 위임 사실 줄의 화면 낱말·사전 키 |
| 주체 칩 (A7-3) | 없음. D 결정 기록에도 에이전트 칸 없음 (`DecisionRecords.java:24-29`) | 칩 부품과 값 출처(판정 기록 또는 봉인 사실의 위임 칸) |
| 재현·비용 (A6-2, A7-3) | 봉인 재생 `/ops/replays` (bundle·runId·step, 최대 80 단계, 운영 포트만) (`PT/ops/ReplayOpsController.java:39`, `:44`, `:71`, `:82-108`); D Layer2는 sol (`DR/application.yml:75-76`) | 에이전트 사례의 ESCALATE가 Layer2(sol)를 부를 수 있음 → 기획안 8.4대로 사전 승인 필요 |
| 그룹·여정 (A7-3) | 5절 목록 전부 | 새 그룹이면 5절 전부 갱신 + Flyway V30 |

---

## 7. 기획안 5.4절 주장 확인표

| 주장 | 코드 확인 | 결과 |
|---|---|---|
| 사례 41개 | `PR/scenarios/*.json` 41개, 시험 목록 41개 (`OrchestratorUnitTest.java:40-43`) | 맞음 (녹화 쌍 5개·변형 15개는 별도) |
| 주인공 eng-k 21, adm-a 20 | 파일별 `protagonist` 집계: eng-k 21, adm-a 20 | 맞음 |
| 에이전트·위임 주체 사례 없음 | 주인공 두 사람뿐, 사실 종류에 위임 없음 (`ScenarioDefinition.java:96-98`, `RunOrchestrator.java:785-818`), 쇼케이스 코드에 위임 표·공급자 없음(Grep 결과 웹 낱말 3곳뿐) | 맞음 |
| A7 쌍은 설계만, 첫 공개 범위 밖 | 설계 행 `DOC/showcase/P2-설계.md:20`; 결정 `DOC/showcase/승인대기.md:30`('A2·A4·A7 설계만'), `:223`('첫 공개 범위 밖'); `PR/pairs`·`PR/scenarios`에 A7 없음 | 맞음 |
| Q-12가 2026-10-17에 고쳐짐 | 문서상 결정 `DOC/showcase/승인대기.md:140`((나) W2-9, (다) W2-1) | 문서 기준 맞음. 코어 코드 수정 여부는 이 영역에서 확인 안 함(미확인) |
| 업무 앱은 `x-contexa-` 헤더를 모든 요청에서 숨김 | `InternalContextRequest.java:20`, `:86-100`; 서명 여부와 무관하게 감쌈 (`InternalContextFilter.java:54`) | 맞음 |
| 위임 정보는 업무 DB 공급자로 넣어야 함 | 헤더 길(`BridgeProperties.java:266-267`)이 숨겨짐 + 코어 SPI 있음(`DelegationContextProvider.java:20`) | 맞음(근거 있는 결론) |
| 걸림돌 ① 계정·로그인: 새 주체는 서명된 내부 API로만, MFA 코드도 그쪽으로만 | 계정 생성 `PlainInternalController.java:63-74`, `ContexaInternalController.java:133-148`; 서명 없으면 403 (`InternalApiGuardFilter.java:28-37`); plain 로그인은 run_principal·직원 행 필요 (`PlainUserDetailsService.java:26-31`); D는 OTT 필수 (`ContexaWorkloadSecurityConfiguration.java:33-36`), 코드는 메모리 메일함에만 있고 `/internal/inbox`로만 읽힘 (`DemoInboxEmailService.java:42-53`, `ContexaInternalController.java:174-177`) | 맞음. 보충: 실행 계정은 실행 끝에 지워짐 (`RunOrchestrator.java:332-345`) |
| 걸림돌 ② 네트워크: 127.0.0.1 바인딩, 운영형은 내부망 | `PLR/application.yml:31`, `DR/application.yml:124`, `PR/application.yml:26`; 운영형은 포트 공개가 포털뿐이고 나머지는 `internal: true` 망 (`INF/compose.stack.yml:1-3`, `:124-132`) | 맞음. 보충: 이미지 기본 바인딩은 0.0.0.0(`showcase.Dockerfile:33`)이지만 내부망 안; D는 egress 망에도 붙음(`compose.stack.yml:102`, 공개 포트 없음) |
| 걸림돌 ③ 엔진 입력: 서명 맥락 없으면 IP·UA·시각이 실제 값 | IP: `InternalContextRequest.java:30-31`; UA: `:44-47`, `:102-104`; 엔진 속성(관측 시각·조직·테넌트·요청 ID)은 서명 맥락이 있을 때만 (`InternalContextFilter.java:47-53`); 업무 시각은 실제 시계 (`BusinessRequest.java:28`); 엔진 관측 시각 추출은 속성 없으면 null (`CORE/autonomous/utils/RequestInfoExtractor.java:282-294`) | IP·UA·업무 시각은 맞음. 엔진이 관측 시각 null을 무엇으로 채우는지는 미확인. 보충: run_principal에 없는 주체는 업무 사실이 아예 안 들어감 (`BusinessFrictionProvider.java:77-80`) |

---

## 8. 미확인 목록

1. 관측 시각 속성이 없을 때 엔진이 쓰는 시각(코어 `RequestInfoExtractor.extractObservedAt`는 null 반환까지만 확인, `:282-294`).
2. Q-12 (나)(다)를 고쳤다는 코어 변경(W2-9, W2-1)의 실제 코드.
3. D(contexa-iam 포함)에서 실행 주체 생성 외의 가입·계정 생성 화면이나 API가 열려 있는지.
4. `CanonicalSecurityContext.Delegation` 값이 프롬프트·봉인 사실·결정 기록에 어떻게 실리는지(코어 영역). D 결정 기록 조회(`DecisionRecords.java:38-44`)는 위임 칸을 읽지 않음.
5. 1-1 HookPage, 7-1 SummaryPage, 7-2 NextPage가 쓰는 응답 필드의 세부.
6. `LiveGate`의 Turnstile·한도·할당 검사 세부(이 지도는 거절 사유 매핑 `LiveController.java:438-456`까지만 확인).
7. 개발 실행(compose.stack 밖)에서 포털의 A 주소 설정 출처(`showcase.portal.controls.a` 값은 compose.stack과 시험에서만 확인).
8. 외부 에이전트 연동 방식(기획안 10.3절 5항: 사용자가 따로 정함)과 그에 따른 서명 맥락 처리.
9. 에이전트 주체를 업무 DB의 직원 행으로 둘지 새 표로 둘지, C2 규칙이 위임 기록을 읽을지(공정성) — 결정이 필요한 항목.

