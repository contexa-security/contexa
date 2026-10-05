# Contexa Showcase 구현 계획 (기획안 v5 기준)

- 작성일: 2026-10-04
- 문서 상태: 승인됨(2026-10-04). Phase 게이트 진행 중
- 대상: `contexa-showcase` 모듈 전체(포털, 업무 대조군, 웹, 인프라)
- 관련 문서: 같은 폴더의 `ADR.md`, `연결계약.md`, `실행명세.md`, `P{n}-검수.md`

## Context

- 목적: 데모 사이트에서 직접 체험하게 해 Contexa의 정체성·가치·차별점을 빠르고 정확하게 각인시킨다. 글로벌 보안 담당자가 모든 수행 과정과 결과를 신뢰할 수 있어야 한다.
- 기존 두 데모(`contexa/contexa-demo`, `contexa-enterprise/contexa-demo`)는 제품으로서 실패했다. 새 데모는 구조와 화면을 새로 만들고, 검증된 기능과 코드만 가져다 쓴다.
- 기준 문서는 기획안 v5 덱(https://claude.ai/artifact/QkExnZME3q152MxzFPVPjK, 44장)이다. 최상위 원칙은 "부담은 0, 깊이는 끝까지"다.
- 진행 방식(사용자 지시):
  - Phase별로 진행한다.
  - Phase마다 프론트·백엔드·DB를 검증·검수할 수 있도록 계획서와 검수 기록을 보존한다.
  - 현재 Phase가 검수를 통과해야 다음 Phase로 넘어간다.
- 계획의 근거: 코드 조사 3건(엔진 확장점, 재사용 코드, 빌드 관례)과 설계 검토 1건. 2절에 요약했다.

## 1. 결정한 값 (사용자 위임, 2026-10-04)
| 항목 | 값 |
|---|---|
| 동시 실시간 체험 인원 | 50명. 51번째부터 대기열. P4 부하 시험을 통과해야 확정 |
| 1인 하루 실시간 실행 | 10회(새 조합만 차감). GitHub·Google 로그인 시 30회. 저장된 실제 기록 보기는 무제한 |
| 크레딧 하루 배분 | 월 예산 ÷ 그 달의 일수. 80%에서 경보, 100%에서 다음 실행부터 실시간 정지 후 기록으로 안내. 이월 없음. 월 예산 금액은 P1 실측으로 산정 |
| 방문자 공간 | 생성 5초 이내, 수명 30분, 무활동 15분이면 정리 |
| 조건 조합 | 직원 2 × 시각 4 × 건수 4 × 티켓 3 × 기기 2 = 192 |
| 녹화 반복 | 재생 칸마다 5회 실행하고 "5회 중 k회 일치"를 기록 |
| 첫 공개 범위 | 데모 트랙 1~4 + R1 + 안전·개인정보 기준 |
| 첫 공개 목표일 | 2027-01-25(월). P0~P6 합계 약 15주. 게이트 통과에 따라 조정 |
| 보관 기간 | 측정 이벤트 13개월(익명), 로그인 계정 12개월 무활동 시 삭제, 공유 카드 90일, 전환 이메일 처리 후 12개월, 방문자 공간과 실행 주체는 정리 즉시 삭제, 조합 실행 기록은 엔진·모델·템플릿·규칙 버전이 바뀌면 폐기 후 재녹화 |
| 도메인 | `demo.ctxa.ai`. 지금은 엔터프라이즈 데모가 쓰고 있어 P6에서 미리보기를 거친 뒤 전환 |
| 비공개 미리보기 | 보안 전문가 10명 |
| LLM | 채팅은 gpt-5-nano로 시작하고, P1 실측(비용, 일관성, fallback 비율) 뒤 고정한다. 임베딩은 OpenAI 1024차원. 둘 다 실행 명세에 기록 |
| 시간대 | 가상 기업 시간대를 컨테이너 TZ로 고정(기본 UTC, P0 ADR에서 확정)하고 실행 명세에 기록 |

## 2. 코드로 확인한 엔진 사실과 v5 대비 조정
| 주제 | 사실(근거) | 계획에서의 처리 |
|---|---|---|
| 업무 맥락 주입 | `ContextEnricher` 계열 provider 7종과 `ResourceContextRegistry`. verified/claimed 라벨은 없음 | D에서 provider를 구현하고, 출처는 텍스트 라벨로 표시 |
| 판정 ID | 응답 헤더 없음. `ai_security_decision_observation.request_id`. `RequestInfoExtractor`는 클라이언트의 `X-Request-ID`를 그대로 받음 | 오케스트레이터만 UUID를 부여한다. workload는 내부망에만 둔다 |
| 분석 생략 | 현재 action이 PENDING이 아니면 분석하지 않음(`ZeroTrustEventListener.shouldSkipPublishing`). ALLOW는 15초, BLOCK은 영구, CHALLENGE는 30분 동안 사용자 단위로 남음 | **격리 단위를 실행 1회로 한다.** 실행마다 템플릿에서 새 주체를 복제한다 |
| 조직·tenant | 조직 기준선, ESCALATE 보호창(`org|path`, 10건 이상이고 50% 넘으면 fallback), RAG 조직 검색, work-profile tenant가 요청 metadata의 `organizationId`/`tenantId`에서 나옴. 요청 속성 `ctxa.context.organizationId`/`tenantId`로 지정 가능 | 실행마다 고유한 org/tenant를 준다. 템플릿의 조직 기준선·벡터 문서도 함께 복제 |
| 기준선 | ENFORCE의 ALLOW, MFA 성공, 관리자 override에서만 학습. 갱신 20회 이상이면 확립. work-profile은 7일/30일 창, 3건·2일 필요. 미래 관측은 버림. `ZoneId.systemDefault()` | 템플릿은 실제 요청 재생으로 학습하고, `observedAt`으로 과거 분포를 만든다. 학습 이력이 7일을 넘기 전에 템플릿을 다시 만든다. TZ 고정 |
| 복제와 삭제 | `BaselineDataStore`(get/save)와 `SecurityContextDataStore`(get/add)는 공개 SPI 빈. 삭제 API는 없음. standalone 메모리 맵은 무제한이고 기준선 캐시는 10만 건 상한 | 복제는 SPI로 한다(코어 변경 없음). 템플릿 원본은 showcase DB에 보관하고 기동 시 복원한다. 삭제는 코어 C-1로 해결(2026-10-05 반영: `UserEngineStatePurger`, 계정 삭제 시 자동 정리) |
| 실행 모드 | `contexa.infrastructure.mode`, 기본 standalone. distributed는 Redis, Kafka, Redisson이 필요 | D는 standalone을 명시한다. 포털은 Redis 없이 DB만 쓴다 |
| 시각 | Clock 빈 없음. 요청 속성 `ctxa.context.observedAt`이 이벤트 시각 | 시각 조건을 실시간 실행에도 연다(v5보다 확장) |
| CHALLENGE | API 요청에만 401 JSON, 일반 요청은 302. 원래 요청은 재개되지 않음. OTT 코드는 `EmailService`(`@ConditionalOnMissingBean`)로 발송 | 오케스트레이터는 `Accept: application/json`을 보낸다. 데모 inbox용 EmailService로 코드를 화면에 전달하고, MFA 성공 뒤 원래 요청을 15초 안에 재발행한다. 재분석 여부를 기록한다 |
| 로그인 | D는 MFA DSL `restLogin`(JSON). D는 엔진 `users` 테이블을 씀 | 실행마다 엔진 users와 B/C 사용자를 만들고 지운다(provisioning) |
| ESCALATE | 검토자 승인 API 없음. 423을 반복하다가 검토 시간(5분) 안에 해결이 없으면 BLOCK으로 승격(P0에서 승격이 사라진 결함을 발견해 코어 수정, ADR-18) | v5의 '검토 승인 경로' 탭은 뺀다. 실제 423 → BLOCK 기록을 보여준다 |
| 응답 도중 차단 | 코어 `BlockableServletOutputStream`. 현재 상태가 PENDING_ANALYSIS일 때만 래핑(기록 없음·만료도 PENDING), BLOCK일 때만 중단. sync에서는 발동하지 않음 | async 스트리밍 엔드포인트를 따로 만든다. 20회 분포를 기록한다 |
| 기술적 fallback | 분석이 실패하면 CHALLENGE로 기록(`ColdPathEventProcessor`). gpt-5-nano는 `FALSE_AUTHORIZED_RAG_CLAIM`에 자주 걸린다는 기록이 있음 | P0~P1의 선행 과제다. fallback 비율 2% 이하를 게이트로 둔다. `technicalFallbackApplied`가 붙은 실행은 '미결·기술 장애'로 분류한다 |
| 비용 훅 | `BaseAdvisor`가 엔진의 모든 채팅 호출에 적용되고 `event.userId`를 받음. 임베딩은 대상이 아님 | advisor는 측정만 한다. 예산 거절은 실행 시작 전 front gate에서 한다. 분석 도중 막으면 fallback이 생기기 때문이다. 임베딩 비용은 따로 잰다 |
| Zero Trust 모드 | 관리 화면(DB)에 저장한 값이 프로퍼티보다 우선 | 실행 시점의 효력 모드를 읽어 실행 명세에 기록한다 |

## 3. 아키텍처

### 3.1 모듈 (OSS 저장소 `E:/projects/contexa/contexa-showcase/`)
| 모듈 | 종류 | 역할 |
|---|---|---|
| `showcase-business` | java-library, Contexa 의존 없음 | 업무 도메인, JDBC, 업무 API 컨트롤러, `BusinessContextLookup`, HMAC 내부 헤더 필터 |
| `showcase-workload-plain` | Boot 앱, Contexa 의존 없음 | 대조군 B(RBAC). C1은 `/c1/**`, C2는 `/c2/**`. A는 이 앱 앞단의 Coraza+CRS 컨테이너 |
| `showcase-workload-contexa` | Boot 앱 + `spring-boot-starter-contexa` | 대조군 D. ENFORCE, standalone. provider, observer, advisor, 템플릿 학습·복제·정리, 데모 inbox EmailService. B와 같은 RBAC 정책을 둔다 |
| `showcase-portal` | Boot 앱, Contexa 의존 없음 | 방문자 API와 정적 웹. 아래 구성 요소를 포함 |
| `web/` | Gradle 프로젝트 아님 | React + TS + Vite. portal 빌드가 node 플러그인으로 빌드해 static에 넣는다 |
| `infra/` | | compose(pgvector pg16, Coraza+CRS, 앱 3개), 시크릿 파일, drain 스크립트 |

`showcase-portal`에 들어가는 구성 요소:
- Orchestrator, Visitor Space Manager, Result & Replay Store, Cost Governor(front gate), Evidence Collector, Execution Stats
- 공유 카드, Turnstile, OAuth2, 이메일 전환

공통 규칙
- 앱 이름은 `showcase-*`로 짓는다. `contexa-` 접두사는 FAIL_FAST를 일으킨다.
- 모든 모듈에 `contexa-demo/build.gradle`의 배포 제외 블록을 넣는다.
- 루트 `Dockerfile`의 COPY 줄을 함께 고친다.
- 기존 OSS `contexa-demo`는 첫 공개를 통과한 뒤 사용자 승인을 받아 제거한다.
- **CI**: `.github/workflows/showcase.yml`을 새로 만든다(pgvector, Node 22, Playwright). OSS `ci.yml`에서는 Docker가 필요한 showcase 테스트를 `Assumptions`로 건너뛴다.

### 3.2 프론트엔드 (`web/`)
- **스택**
  - React, TypeScript strict, Vite
  - TanStack Query, React Router
  - i18next(KO/EN 같은 키)
  - Framer Motion(reduced-motion 존중)
  - 직접 만든 SVG 시각화
- **디자인 토큰**: `tokens.css`/`tokens.ts`. 토큰 밖의 값은 stylelint로 금지한다. 웹폰트는 자체 호스팅하고 대체 스택을 명시한다.
- **화면**: 첫 화면, 판정 비교, 제어와 복귀, 조건 탐색, 끝 화면, 라이브러리, 수행 통계, 도입하기, 정책 문서. 룰 챌린지와 벤치마크는 P7 이후.
- **공통 컴포넌트**: VerdictChip, LayerCard, EvidenceDrawer, ReplayBadge, Stepper, StateScreen(6종), CombinationGrid, AnalysisTimeline, StreamMeter.
- **다국어 원칙**: LLM 판단 이유(reasoning)는 번역하지 않는다. 화면의 근거 한 줄은 구조화된 요인(담당 여부, 평소 대비 배수, 시간대)을 사전으로 현지화해 만든다. reasoning 원문은 '엔진 원문' 표시와 함께 '자세히'에 둔다.
- **이식할 개념**
  - OSS `http.js`: CSRF 처리. origin 허용 목록을 추가한다.
  - OSS `observation-stream.js`
  - 엔터프라이즈 `zero-trust-demo.js` 820~917행: 스트림 차단 감지
  - 엔터프라이즈 `_step5_judgment.html`: 판정 카드 필드

### 3.3 백엔드 핵심 흐름
- **실행 1회 = 새 주체**
  1. 오케스트레이터가 실행을 시작한다.
  2. D에 템플릿 복제를 요청한다: 기준선, work-profile, 조직 기준선, 벡터 문서를 run 고유의 userId·org·tenant로 복제한다.
  3. 엔진 users와 B/C 사용자를 provisioning한다.
  4. 각 대조군에 로그인한다: B/C는 폼 또는 JSON, D는 `restLogin`. 대조군마다 쿠키 저장소를 따로 둔다.
  5. 요청 순서를 실행한다.
  6. Evidence Collector가 4가지 증거(엔진 결정, 적용 시점, HTTP 응답, 업무 결과)를 묶는다.
  7. 주체를 정리한다.
- **내부 서명 헤더**
  - HMAC 서명 헤더 `X-Showcase-Run`, `-ObservedAt`, `-ClientIp`, `-Device`, `-Org`, `-Tenant`를 쓴다.
  - `showcase-business`의 필터가 서명을 검증한 뒤 요청 속성(`ctxa.context.observedAt`/`organizationId`/`tenantId`, `contexa.requestId`)과 원격 주소를 적용한다.
  - IP는 템플릿과 같은 /24 대역 안에서 준다.
  - 서명이 없거나 틀리면 무시하고 기록한다.
- **`BusinessContextLookup`**
  - 함수: `ticketCovers`, `oncallHas`, `projectAssigned`, `approvalExists`, `historyDays`
  - 공간 오버레이를 반영한다.
  - C2의 AuthorizationManager와 D의 provider가 같은 빈을 쓴다.
- **대조군 구성 정의**: A = WAF + B 경로. scoring contract에 대조군별 구성을 명시한다.

### 3.4 DB (PostgreSQL 16 + pgvector)
- **Flyway 범위**: `showcase_portal`, `showcase_work`에만 V1부터 적용한다. 엔진 스키마(`showcase_engine`)는 core가 생성한다.
- **`showcase_portal`**
  - visitor(서명 쿠키 ID 해시, 원문 IP 없음), visitor_daily_quota, account
  - space, run(주체 ID, 템플릿·엔진·모델·규칙 버전), run_arm_result, evidence_link
  - scenario_catalog, combination(유일 키에 버전 포함)
  - replay_record, replay_step, execution_spec
  - prediction, share_card, event(동의한 방문자만), cost_ledger, contact_request, stats_rollup
  - engine_template(템플릿 원본 직렬화)
- **`showcase_work`**
  - employee, role, project, assignment, document, customer
  - export_job, approval, itsm_ticket, oncall_roster, access_history, device
  - space_fact_override, rule_decision_log, 대조군 B/C 사용자 테이블
  - OSS 시드 V7, V13, V28을 이식한다.

### 3.5 코어 변경 제안 (각각 착수 전 설계 승인 필요)
- **C-1 (반영 완료, 2026-10-05)**: 사용자 단위 엔진 상태 삭제 API(`UserEngineStatePurger`, `코어수정-P1.md`).
  - 대상: 기준선, work-profile, action, 벡터 문서, MFA 키, 무제한 JVM 맵(ESCALATE 보호창, analysis event store) 정리.
  - 미승인 시 대안이었던 주기적 drain과 재기동은 필요 없어졌다.
- **선행 조사(P0)**: gpt-5-nano의 `FALSE_AUTHORIZED_RAG_CLAIM` 다발과 `MODEL_UNAVAILABLE` 오분류의 원인. 엔진 수정이 필요하면 별도로 승인받는다.
- **범위 밖(기록만)**: 원래 요청 재개, ESCALATE 검토 승인 API, verified/claimed 라벨, 판정 ID 응답 헤더, `X-Request-ID` 신뢰 경계.

## 4. 계획서 보존과 Phase 게이트 운영
- **P0 첫 작업**: 이 계획서를 `E:/projects/contexa/docs/showcase/2026-10-04-01-contexa-showcase-구현계획.md`로 보존한다. 같은 폴더에 다음 문서를 만든다.
  - `ADR.md`(결정 기록)
  - `연결계약.md`
  - `실행명세.md`(스키마와 해시 규칙)
  - `P{n}-검수.md`
  - 커밋 여부는 사용자가 정한다.
- **검수 기록 형식**: 항목마다 ID(`P{n}-FE|BE|DB|SEC|PRV|OPS-xx`), 측정 가능한 기준, 방법(명령이나 시나리오), 결과(PASS/FAIL), 증거 경로, 날짜를 적는다.
  - 증거 산출물은 저장소 밖 `E:/projects/.contexa-verify/showcase/P{n}/`에 둔다.
- **게이트 통과 조건**
  - 모든 항목이 PASS여야 한다.
  - 실서버 실행 확인이 있어야 한다. 단위 테스트만으로는 통과로 보지 않는다.
  - 사용자 승인이 있어야 다음 Phase를 시작한다.
  - FAIL이 하나라도 있으면 같은 Phase 안에서 고치고 다시 검수한다.
- **공통 규칙**
  - 영어 주석과 로그, error 로그만, FQCN 금지, CRLF 유지, `checkJavaStyle` 통과.
  - AGENTS.md를 따른다: 하드코딩 대체 금지, 실제 흐름 우회 금지, 데이터 날조 금지.
  - 운영 빌드에 fixture 데이터 0.
  - Redis를 쓰는 기존 테스트는 격리 인스턴스로 돌린다.

## 5. Phase별 계획

### P0 기반, 결정 기록, 연결 계약 (약 1.5주)
**작업**
- 계획서를 보존한다.
- **ADR**: 엔진 모드, 복제 방식(SPI), 격리 키 체계(run 단위 userId·org·tenant·IP 대역), 대조군 구성 정의, 임베딩 모델, TZ, 앱 이름, 빌드 포함 방식, 공유 엔진으로 바꾸는 근거(이전 데모 README의 "설치당 1인 독점" 결론과 비교).
- **실행 명세 스키마와 해시 규칙**: 커밋, 엔진 버전, 효력 모드, 엔드포인트 보호 설정, 모델(채팅·임베딩), 프롬프트 해시, 템플릿 ID, 규칙 버전, TZ.
- **연결 계약 6가지를 실행 가능한 probe 테스트로 만든다.**
  1. 로그인과 OTT inbox
  2. `observedAt`
  3. org/tenant 속성과 run 격리
  4. 재발행
  5. ESCALATE 423 계약과 검토 시간 뒤 BLOCK 승격(코어 수정 뒤, ADR-18)
  6. async 스트림 래핑
- **선행 조사**: gpt-5-nano fallback 원인. 엔터프라이즈 `deploy-demo.yml`과 운영 서버 현황.
- **골격**: 모듈 5개와 web, `showcase.yml`, compose(127.0.0.1:46432).
- **FE**: 스캐폴드, lint/stylelint/test, Playwright+axe, i18n, 디자인 토큰, 공통 컴포넌트 기초, 판정 비교 화면 완성 시안(개발 전용 `/design`, 고정 데이터).
- **DB**: portal·work Flyway V1(최소 스키마).
- **운영형 컨테이너(2026-10-04 보강)**: 로컬 검수와 오라클 클라우드 운영을 같은 형태로 맞춘다.
  - 앱 3개의 Docker 이미지(멀티스테이지, linux/amd64)를 만든다.
  - 운영형 compose(내부 네트워크, 포털만 노출)로 로컬에서 기동한다.
  - 이후 모든 Phase의 실서버 검수는 이 스택에서 한다.
  - 대조군 D 이미지에는 엔진 수치 연산 라이브러리의 linux-x86_64 네이티브만 넣는다(현재 jar 878MB의 대부분이 다른 플랫폼 네이티브).

**검수 항목**
| ID | 기준 |
|---|---|
| P0-DOC-01 | ADR, 실행명세, 연결계약 문서가 있고, 각 결정에 코드 근거(파일:줄)가 있다 |
| P0-BE-01 | probe 테스트 6개 통과(예: 서명 헤더로 넣은 `organizationId`·`observedAt`이 observer가 받은 이벤트에 그대로 있다) |
| P0-BE-02 | 새 모듈 build 통과(스타일 검사 포함). OSS `ci.yml`의 결과 변화 없음. publish 목록에 showcase 산출물 0 |
| P0-BE-03 | clean clone에서 `showcase.yml`과 같은 명령이 통과한다 |
| P0-BE-04 | 앱 3개가 기동되고 health가 UP이다(실서버) |
| P0-DB-01 | 빈 DB에 Flyway V1 적용 후 validate 통과. 엔진 스키마는 core만 생성한다 |
| P0-FE-01 | lint, stylelint(토큰 밖의 값 0), test, build가 오류 0 |
| P0-FE-02 | 시안 1440/768/390에서 axe serious·critical 0, 대비 AA, 영어 문구가 30% 늘어나도 넘침 0 |
| P0-OPS-01 | 앱 3개의 linux/amd64 이미지가 빌드되고, 운영형 compose로 기동해 health UP. 호스트에 열린 포트는 포털 하나뿐 |
| P0-OPS-02 | 대조군 D 이미지에 다른 플랫폼의 nd4j/openblas 네이티브 jar가 0개 |

### P1 가상 기업, 다섯 대조군, 실행 주체 (약 3주)
**작업**
- **업무 데이터**: 업무 스키마와 조직 생성기(시드 고정, 120명, 6개 역할). 쌍둥이 정상 요청에 필요한 승인·티켓 데이터를 넣는다.
- **대조군 구현**
  - 업무 API: 문서 조회, sync 내보내기, async 대량 스트림, 고객 조회, 다운로드
  - `BusinessContextLookup`
  - B, C1, C2, D, 그리고 A(Coraza+CRS)
  - D의 provider·observer(MITRE 저장 수정)·advisor(측정만)
- **템플릿 학습**
  - 시나리오 주인공의 정상 활동을 실제 요청으로 재생한다(`observedAt`으로 과거 분포).
  - 확립된 상태를 SPI로 읽어 `engine_template`에 저장하고, 기동 시 복원한다.
  - 7일 안에 다시 학습하는 작업을 자동화한다.
- **실행 주체**: 복제 primitive, provisioning과 정리(C-1 공개 삭제 API), 오케스트레이터 v0, Evidence Collector, front gate 기초.
- **실측**: 판정 1건과 로그인 이벤트의 LLM 호출 수, 토큰, 시간(p50/p95), 임베딩 비용, 템플릿 학습 비용. 이를 바탕으로 월 예산과 하루 배분을 확정한다.
- **개인정보 데이터 목록과 보존 정책 문서**: P2에서 투표를 수집하기 전에 정한다.

**검수 항목**
| ID | 기준 |
|---|---|
| P1-BE-01 | D의 capability가 모두 READY다. B/C 실행물에 `io.contexa` 빈이 0개다 |
| P1-BE-02 | RBAC parity: 역할 × 엔드포인트 30건 이상에서 B와 D의 정적 인가 결과가 같다 |
| P1-BE-03 | S01~S09에서 A·B·C1·C2 결과가 구성상 예상과 일치하고 결정적이다 |
| P1-BE-04 | C2와 D가 같은 `BusinessContextLookup` 빈을 호출한다 |
| P1-BE-05 | 서명이 없거나 위조된 헤더, 외부의 `X-Request-ID`는 무시된다 |
| P1-BE-06 | 주인공마다 updateCount ≥ 20, 관측 ≥ 3, daysCovered ≥ 2. 복제 10건이 템플릿과 필드 단위로 같다 |
| P1-BE-07 | D 실행 100%가 observation 행(request_id 일치)을 남긴다. 50회 중 fallback 비율 ≤ 2% |
| P1-BE-08 | 대표 쌍마다 10회 실행해 일치율을 보고한다. 80% 미만인 쌍은 시나리오를 다시 설계한다 |
| P1-BE-09 | 격리 스모크 T1~T7 통과(7절) |
| P1-DB-01 | 같은 시드로 두 번 생성하면 데이터 해시가 같다. 업무 스키마 제약 시험 통과 |
| P1-OPS-01 | 실측 보고가 있고 월 예산이 확정된다 |
| P1-PRV-01 | 데이터 목록과 보존 정책 문서가 있다 |

FE: 개발 전용 실행 결과 뷰어로 확인한다.

### P2 빠른 입문 (약 2주)
**작업 순서**
1. **녹화 전 동결**: C1/C2 규칙의 공정성을 검토하고 동결한다(git hash 기록). R1 scoring contract(대조군 구성, 채점 계약, 가설)를 동결하고 해시를 기록한다. 공개는 P5에서 한다.
2. **녹화 하네스**: 8쌍(A1~A8) × 5개 대조군 × 5회를 실행한다. 칸마다 새 주체를 쓰고, replay_record와 execution_spec에 "5회 중 k회 일치"를 남긴다.
3. **BE**: 재생 API, 예측 API, 실행 명세 API, 재생 기록과 실행 명세 일치 검사(빌드 태스크와 기동 시).
4. **FE**
   - 첫 화면(질문, 투표, 건너뛰기)
   - 화면 1(결과 줄, 5개 층 카드, Contexa 근거 한 줄, 증거 사슬 서랍)
   - 쌍둥이 자동 이어 재생
   - 진행 표시, 재생 배지, KO/EN, 모바일, 로딩·오류 상태, 상징 모션

**검수 항목**
| ID | 기준 |
|---|---|
| P2-BE-01 | 녹화 칸 전부가 필수 명세 필드 null 0, 원본 observation 행 존재, 해시 재계산 일치 |
| P2-BE-02 | 동결된 규칙과 계약의 해시가 실행 명세와 일치한다 |
| P2-FE-01 | 화면 텍스트와 기록 JSON을 칸 전체에서 대조하는 snapshot 테스트 통과(화면이 기록과 다른 값을 보여주지 않는다) |
| P2-FE-02 | KO와 EN 각각 첫 화면 → 투표 → 화면 1 → 쌍둥이를 완주한다(Chromium과 WebKit, 360px 포함) |
| P2-FE-03 | 4G 기준 LCP ≤ 2.5초, 첫 결과까지 60초 이내, 초기 JS 250KB(gzip) 이하 |
| P2-FE-04 | axe serious·critical 0, 키보드만으로 완주, i18n 누락 키 0, 방문자 화면에 기획 내부 용어 0 |
| P2-FE-05 | P0 시안과 시각 회귀 차이가 허용치 이내 |
| P2-DB-01 | 투표 테이블에 원문 IP 컬럼이 없다. 예측은 방문자당 장면마다 한 번, 위조된 서명 쿠키는 거부 |

### P3 제어와 복귀, 응답 도중 차단 (약 2주)
**작업**
- **추가 확인 흐름**: `Accept: application/json` → 401 `MFA_CHALLENGE_REQUIRED` → OTT 요청 → 데모 inbox로 코드를 화면에 전달 → 방문자 입력 → 같은 쿠키 저장소로 D에 전달 → 15초 안에 원래 요청 재발행.
- **분석 타임라인**: 관측 이벤트 시각에서 단계별 ms를 계산한다.
- **응답 도중 차단**: async 스트리밍 엔드포인트, 마커 감지, 노출량(건수·초).
- **ESCALATE**: 423 → BLOCK 실제 기록(코어 수정 뒤, ADR-18).
- **상태 화면 6종**.
- 직접 해보기는 개발용 단일 공간에서 검수하고, 공개는 P4에서 연다.

**검수 항목**
| ID | 기준 |
|---|---|
| P3-BE-01 | 실제 OTT 왕복 E2E 통과. 재발행 응답 200. 재분석 여부와 소요 시간 기록(코어 수정 뒤 재발행 요청은 MFA가 남긴 ALLOW로 통과, ADR-18) |
| P3-BE-02 | 스트림 20회의 차단 지점 분포를 기록한다. BLOCK이 아닌데 차단으로 표시된 경우 0 |
| P3-BE-03 | 타임라인 ms가 저장된 이벤트 시각에서 계산한 값과 차이 0 |
| P3-FE-01 | 추가 확인 완주, 취소·만료·복귀 실패 화면 각각 확인 |
| P3-FE-02 | 차단 장면의 막대, 카운터, 노출량 표시 확인 |
| P3-DB-01 | 단계별 증거가 결정 ID로 끊김 없이 이어진다. 운영 빌드에 fixture 0 |

### P4 실시간 체험 기반 (약 3주)
**작업**
- **Visitor Space Manager**: 포털 세션, 업무 오버레이, 수명과 무활동 정리, 동시 50명, 대기열. 실행마다 새 주체(P1 primitive)를 쓰고 끝나면 정리한다.
- **Cost Governor(front gate)**
  - Turnstile: 엔터프라이즈 코드 수정판. fail-closed, hostname·action 검증.
  - 서명 쿠키, 신뢰 프록시 기반 IP 제한, 1인 한도, 하루 배분 원장, 조합 결과 재사용(키에 버전 포함).
- **화면 3**: 업무 사실 패널, 5개 층 결과, 조합 격자, 실시간 시각 조건.
- **직접 해보기 공개**.

**검수 항목**
| ID | 기준 |
|---|---|
| P4-BE-01 | 동시 50개 생성에서 p95 ≤ 5초. 51번째는 대기열로 안내 |
| P4-BE-02 | 50개 동시 혼합 부하에서 격리 T1~T8 통과, 프롬프트 누출 0 |
| P4-BE-03 | 11번째(로그인 시 31번째) 새 조합은 429 또는 저장 기록으로 응답. 쿠키를 지워도 IP 제한 동작 |
| P4-BE-04 | 예산 80%에서 경보, 100%에서 다음 실행부터 실시간 중지. 같은 조합의 두 번째 방문은 LLM 호출 0 |
| P4-SEC-01 | Turnstile 장애 시 차단, 운영 프로필에서 테스트 키면 기동 실패, 변조 쿠키 거부 |
| P4-FE-01 | 칸 선택 → 실행 → 격자 갱신, 기록 칸에 일시 표시, 한도와 '잠시 쉼' 화면 |
| P4-DB-01 | combination 키 유일, 정리 뒤 잔여 행 0 |

### P5 마무리 영역, 신뢰, 안전, 개인정보, R1 공개 (약 2주)
**작업**
- **FE**: 끝 화면, 공유 카드, 라이브러리(8군, W1, 제조 업종), 도입하기, 수행 통계, 쿠키 동의, 정책 문서.
- **BE**: OG 이미지, 통계 집계, OAuth2, 이메일 전환(OTP 수정판, 프록시 IP 처리), 동의 기반 이벤트, 보관 삭제 잡.
- **W1 녹화**.
- **R1 공개**: P2에서 동결한 계약과 표본 해시를 공개한다.

**검수 항목**
| ID | 기준 |
|---|---|
| P5-SEC-01~07 | 덱 37쪽의 완료 기준 7가지가 각각 자동 시험으로 통과 |
| P5-PRV-01 | 동의 전 분석용 네트워크 요청 0, 공유 카드와 URL에 PII 0 |
| P5-PRV-02 | 보관 잡을 돌린 뒤 DB 건수 검증 |
| P5-BE-01 | 통계가 원천 run 집계와 일치하고 실행 명세가 표시된다 |
| P5-FE-01 | 전체 동선 E2E, 라이브러리 전 장면 재생, Lighthouse 접근성 ≥ 95·성능 ≥ 90 |
| P5-R1-01 | 공개한 R1 해시가 P2에서 동결한 해시와 같다 |

### P6 첫 공개 (약 1.5주)
**순서**
1. 운영 배포와 모니터링(헬스, 크레딧 경보)
2. 위협 모델 점검
3. 비공개 미리보기 10명
4. 30초 영상
5. 룰 공정성 최종 검증
6. 도메인 전환: 엔터프라이즈 `deploy-demo.yml` 교체는 사용자 승인 후
7. 기존 OSS `contexa-demo` 제거 제안

**검수 항목**
| ID | 기준 |
|---|---|
| P6-OPS-01 | 운영 환경에서 전체 E2E 통과(KO/EN, 데스크톱/모바일) |
| P6-OPS-02 | 도메인 전환 롤백 리허설 10분 이내 |
| P6-SEC-01 | 외부에서 포트 스캔 시 443만 열림. workload와 `/contexa/admin` 외부 접근 불가 |
| P6-RV-01 | 미리보기 10명 중 8명 이상이 기존 보안과 Contexa의 차이를 설명할 수 있다 |
| P6-OPS-03 | 부하와 격리 시험 재실행 통과, 효력 모드가 실행 명세와 일치 |

### P7 이후 (첫 공개 뒤)
- **R2**: 벤치마크 하네스와 첫 보고서(40쌍)
- **R3**: 룰 챌린지, 리더보드, 반례 제출
- **R4**: 표본 확장

각각 별도 Phase로 진행하며, 같은 게이트 규칙을 따른다.

## 6. 재사용 자산 매핑
| 자산(경로) | 쓰는 곳 | 수정 사항 |
|---|---|---|
| OSS `work/*/service/impl/Contexa*`, `Baseline*`, `Abstract*` | business, workload | 승인 결합 정리, 모듈 분리 |
| OSS `platform/context/*` | D provider | 역할·action 하드코딩 제거, `BusinessContextLookup` 연결 |
| OSS `observation/*`(`ModelBoundaryObservationAdvisor`, `NativeAnalysisObserver`, `JsonProviderBodySanitizer`, `JdbcNativeDecisionQuery`) | 타임라인, 증거 | 스트리밍 관측, MITRE 저장, 타임존 |
| OSS `entry/*` | 이메일 전환 | 프록시 IP 처리 |
| OSS `lab/scenarios/S01~S09`, 시드 `V7`/`V13`/`V28` | 시나리오, 업무 시드 | 형식 확장 |
| 엔터프라이즈 `AttackContextComposer`, `AttackPresetCatalog` | 조건 데이터 | 서명된 내부 헤더 전용 |
| 엔터프라이즈 `TurnstileVerificationService` | 봇 차단 | fail-closed, hostname/action 검증 |
| 엔터프라이즈 `zero-trust-demo.js` 스트림 리더, `_step5_judgment.html` | 차단 장면, 판정 카드 | React로 이식 |
| core `BaselineDataStore`, `SecurityContextDataStore` SPI | 템플릿 저장·복제 | 삭제는 C-1(`UserEngineStatePurger`) |

## 7. 격리 시험 (P1 스모크, P4 50개 동시)
| ID | 시험 |
|---|---|
| T1 | 실행 X에서 ESCALATE를 15건 이상 낸 뒤, 실행 Y에서 ESCALATE_PROTECTION 이벤트 0건 |
| T2 | X의 이상 ALLOW가 Y와 템플릿의 기준선 해시를 바꾸지 않는다 |
| T3 | X의 BLOCK이 Y의 새 판정에 영향이 없다 |
| T4 | X의 로그인 실패 5회가 Y의 실패 카운터에 반영되지 않는다 |
| T5 | advisor로 프롬프트를 스캔했을 때 Y의 프롬프트에 X의 ID나 문서가 0건 |
| T6 | 복제 주체와 템플릿의 프롬프트 컨텍스트가 같다(ID와 시각만 정규화) |
| T7 | 같은 조합을 새 주체로 돌린 결과와, 다른 실행 10회 뒤에 돌린 결과의 컨텍스트가 같다 |
| T8 | 만료 뒤 엔진 키, 사용자 행, 오버레이가 0건 남는다 |

## 8. 리스크
- **gpt-5-nano**: fallback과 낮은 일치율이 나오면 P1 게이트에서 모델 교체나 시나리오 재설계를 사용자와 결정한다.
- **C-1**: 반영 완료(2026-10-05). 정리 단계 실패는 결과와 error 로그로 남으므로, 오케스트레이터가 실패를 감지해 재시도한다.
- **50명 동시 처리**: LLM 동시성, Tomcat 스레드, DB 풀이 한계가 될 수 있다. P4에서 측정하고, 필요하면 D를 수평 확장하거나(standalone이라 템플릿을 인스턴스마다 복원) 인원을 하향한다.
- **템플릿 유효기간(7일)**: 자동 재학습이 실패하면 판정이 변한다. 템플릿 나이를 실행 명세에 기록하고, 7일을 넘으면 실시간 실행을 중지한다.
- **첫 공개 범위**: 범위가 넓어 일정 위험이 있다. 게이트마다 범위를 다시 확인한다.

## 9. 검증 (end-to-end)
- Phase마다 검수 표의 명령과 실서버 시나리오를 그대로 실행하고, `docs/showcase/P{n}-검수.md`에 결과와 증거 경로를 기록한다. 사용자 승인 뒤 다음 Phase로 넘어간다.
- 최종(P6)
  - 운영 환경에서 Playwright 전체 동선(KO/EN, Chromium/WebKit, 데스크톱/모바일)을 돌린다.
  - 부하 50명과 T1~T8, 안전 7가지, 개인정보 시험, 재생 기록과 실행 명세 일치 검사를 모두 통과해야 한다.

## 변경 이력
- 2026-10-04 P0 정정(사용자 승인 전, P0 검수에서 함께 보고): ESCALATE 동작, 응답 감싸기 조건, probe 5 내용, P3 ESCALATE 장면과 P3-BE-01 기준. 근거는 `ADR.md` ADR-17과 `연결계약.md` 7절.
- 2026-10-05 P0 승인과 코어 수정 반영: F, A, F-2, F-1, C-1을 공용 결함으로 판정해 코어에서 고쳤다. ESCALATE 장면은 원래 계획(423 → BLOCK)으로 돌아가고, MFA 뒤 재발행은 재분석 없이 통과하며, 실행 주체 정리는 공개 삭제 API로 한다. 근거는 `코어수정-P1.md`, `ADR.md` ADR-18.
