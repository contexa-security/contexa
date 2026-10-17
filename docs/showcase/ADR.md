# Contexa Showcase 결정 기록 (ADR)

- 작성일: 2026-10-04
- 문서 상태: P0에서 작성. 결정을 바꾸면 새 항목을 추가하고, 이전 항목에는 '대체됨'을 표시한다.
- 근거 표기: `파일:줄`. 경로 약어는 다음과 같다.
  - core = `contexa-core/src/main/java/io/contexa/contexacore`
  - auto = `contexa-autoconfigure/src/main/java/io/contexa/autoconfigure`
  - common = `contexa-common/src/main/java/io/contexa/contexacommon`
  - identity = `contexa-identity/src/main/java/io/contexa/contexaidentity`
  - iam = `contexa-iam/src/main/java/io/contexa/contexaiam`
  - 문서(모두 `docs/showcase/`): 계획 = `프롬프트-최종-구현계획.md`, 사전 = `프롬프트-v20-사전.md`, 버전관리 = `프롬프트-버전관리-설계.md`, 재설계 = `프롬프트-검사기-재설계.md`, P{n} 검수 = `프롬프트-P{n}-검수.md`, 승인대기 = `승인대기.md`

## ADR-01 저장소와 모듈 구조
- **결정**: OSS 저장소 `contexa-showcase/` 아래에 다섯 단위를 둔다.
  - `showcase-business`: 공유 라이브러리
  - `showcase-workload-plain`: 대조군 A의 백엔드, B, C1, C2
  - `showcase-workload-contexa`: 대조군 D
  - `showcase-portal`: 방문자 포털
  - `web/`: Gradle 프로젝트가 아니다.
- **Gradle 경로**: `:showcase-*`처럼 평평하게 두고 `projectDir`로 위치를 지정한다(`settings.gradle`). 중간 프로젝트가 생기지 않아, 루트 `subprojects{}`가 빈 프로젝트에 publishing을 주입하는 일이 없다.
- **배포 제외**: 모든 모듈에 `contexa-demo/build.gradle`과 같은 블록을 둔다.
- **루트 `Dockerfile`**: 네 모듈의 `build.gradle` COPY 줄을 추가했다.
- **근거**: 공정성(설계 검토). B/C 실행물에 Contexa jar가 섞이지 않게 하려고 plain과 contexa를 별도 실행물로 나눴다.

## ADR-02 애플리케이션 이름
- **결정**: `showcase-portal`, `showcase-workload-plain`, `showcase-workload-contexa`.
- **근거**: 앱 이름이 `contexa-`로 시작하면 capability 진단이 AUTO 모드에서 기동을 실패시킨다(빌드 관례 조사, `ContexaCapabilityAutoConfigurationTest`).

## ADR-03 엔진 실행 모드: standalone
- **결정**: 대조군 D는 `contexa.infrastructure.mode: standalone`으로 둔다. 포털은 Redis를 쓰지 않는다.
- **근거**
  - `auto/core/autonomous/CoreAutonomousAutoConfiguration.java:532`, `:562`, `:584`, `:613`: standalone과 distributed에 따라 `BaselineDataStore`와 `SecurityContextDataStore` 구현이 갈린다.
  - distributed는 Redis, Kafka, Redisson이 필요하다(설계 검토, `CoreInfrastructureAutoConfiguration`).
  - Redis 키에는 tenant가 없다.
- **영향**: 재기동하면 메모리 상태가 사라진다. 그래서 학습 템플릿 원본을 포털 DB에 보관하고 기동 시 복원한다(ADR-06).

## ADR-04 격리 단위: 실행 1회
- **결정**: 실행 1회마다 템플릿에서 새 주체(사용자 ID)를 복제해 쓰고, 끝나면 정리한다.
- **근거**: `core/autonomous/event/listener/ZeroTrustEventListener.java:88`, `:147`. 현재 action이 PENDING이 아니면 분석을 생략한다(`shouldSkipPublishing`). ALLOW는 15초, BLOCK은 영구, CHALLENGE는 30분 동안 사용자 단위로 남는다(엔진 조사). 같은 주체로 반복하면 앞선 실행이 뒤 결과를 오염시킨다.

## ADR-05 격리 키 체계
- **사용자 ID**: `v{runHex}-{employeeKey}`.
- **조직·tenant**: 실행마다 고유한 값을 요청 속성 `ctxa.context.organizationId`, `ctxa.context.tenantId`로 준다.
  - 근거: `common/security/context/OfficialContextField.java:24`(TENANT_ID), `:25`(ORGANIZATION_ID), `:53`(접두사 `ctxa.context.`).
- **시각**: 요청 속성 `ctxa.context.observedAt`(엔진 조사: `ZeroTrustEventPublisher`가 이벤트 시각으로 사용).
- **IP**: 템플릿과 같은 /24 대역 안에서 실행마다 다른 주소를 준다. 엔진의 네트워크 정규화가 /24 기준이기 때문이다(설계 검토).
- **전달 방식**: 포털이 HMAC으로 서명한 내부 헤더를 보내고, `showcase-business`의 필터가 서명을 검증한 뒤 요청 속성으로 옮긴다. 서명이 없거나 틀리면 무시한다.
- **판정 ID**: 오케스트레이터가 UUID를 부여한다. workload는 외부에 노출하지 않는다. 엔진이 클라이언트의 `X-Request-ID`를 그대로 받기 때문이다(설계 검토, `RequestInfoExtractor.extractRequestId`).

## ADR-06 학습 상태 복제와 삭제
- **복제**: 공개 SPI `BaselineDataStore`, `SecurityContextDataStore`를 쓴다(코어 변경 없음).
  - 근거: `core/autonomous/baseline/store/BaselineDataStore.java:20`, `core/autonomous/store/SecurityContextDataStore.java:21`. 둘 다 `@ConditionalOnMissingBean`이다(ADR-03 근거 줄).
- **템플릿 원본**: 포털 DB `engine_template`에 보관하고 기동 시 복원한다.
- **삭제**: 두 SPI 모두 삭제 API가 없다. 코어 변경 C-1(사용자 단위 삭제 API)을 P1에서 승인받는다. 미승인 시 D를 주기적으로 drain하고 재기동한다.

## ADR-07 대조군 구성 정의
| 대조군 | 구성 |
|---|---|
| A | Coraza WAF + OWASP CRS 컨테이너가 B 앞단에 선다. A 열의 결과는 "WAF + B 경로"다 |
| B | Spring Security 인증 + 역할 기반 인가(RBAC) |
| C1 | B + `AuthorizationManager` 임계값 룰(시각, 건수, 무접근 기간) |
| C2 | B + `AuthorizationManager` 맥락 조회 룰. `BusinessContextLookup`을 쓴다 |
| D | 같은 RBAC 정책 + Contexa(ENFORCE). provider가 `BusinessContextLookup`을 쓴다 |

- 공정성 규칙: C2와 D는 같은 조회 빈을 쓴다. RBAC 정책이 B와 D에서 같은지 parity 테스트로 확인한다. 구성 정의는 P2에서 scoring contract에 동결한다.

## ADR-08 모델
- **채팅**: `gpt-5-nano`로 시작한다(`SHOWCASE_CHAT_MODEL`). P1 실측(비용, 일관성, fallback 비율) 뒤 고정한다.
- **임베딩**: `text-embedding-3-small`, 1024차원(`SHOWCASE_EMBEDDING_MODEL`, `SHOWCASE_EMBEDDING_DIMENSIONS`).
- 둘 다 실행 명세에 기록한다.

## ADR-09 시간대
- **결정**: 가상 기업과 모든 실행물은 UTC로 운영한다.
  - JVM: `-Duser.timezone=UTC`
  - Postgres 컨테이너: `TZ=UTC`, `PGTZ=UTC`
- **화면 표기**: 장면의 시각은 "회사 시각(UTC)"으로 표기한다.
- **근거**: work-profile 수집기가 `ZoneId.systemDefault()`를 쓴다(설계 검토, `DefaultProtectableWorkProfileCollector`). 컨테이너마다 시간대가 다르면 같은 요청도 판정이 달라진다.

## ADR-10 데이터베이스 배치
- **결정(DB 4개, 같은 pgvector 인스턴스)**
  | DB | 소유 | 내용 |
  |---|---|---|
  | `showcase_portal` | 포털(Flyway) | 방문자, 실행, 기록, 실행 명세 |
  | `showcase_work` | plain(Flyway) | 가상 기업 업무 데이터. 모든 대조군의 공통 원천 |
  | `showcase_engine` | Contexa core(`db/schema.sql`) | D의 `contexa.datasource`. 엔진 메타데이터 |
  | `showcase_vector` | Spring AI pgvector | D의 `spring.datasource`. 벡터 스토어(`initialize-schema: true`) |
- D는 업무 데이터를 `showcase-business`의 별도 work datasource로 읽는다(P1).
- **근거**
  - 엔진의 decision strategy는 VectorStore 빈이 있어야 생긴다(`auto/capability/CapabilityRequirementResolver.java:177`, `:218`). VectorStore는 Spring AI pgvector 스타터(`spring-ai-starter-vector-store-pgvector`)가 `spring.datasource`로 만든다. 라이브러리(`spring-ai-pgvector-store`)만으로는 빈이 생기지 않는다(P0 실측: 처음 기동에서 `ProcessingStrategy` 누락).
  - Contexa는 `contexa.datasource`와 `spring.datasource`가 같은 DB면 기동을 거부한다(P0 실측: `contexa.datasource must not share spring.datasource unless ... allow-shared-application-datasource=true ...`). 그래서 벡터 스토어용 앱 DB를 따로 둔다.
  - 엔진 스키마는 core가 만든다(P0 실측 로그: `OSS schema provenance verified ... tables=133`).

## ADR-11 공유 엔진으로 바꾸는 근거
- **이전 판단**: 이전 OSS 데모(Runtime Lab) README는 "설치당 한 참여자 독점 임대"로 결론 냈다. 사용자 단위 엔진 상태가 참여자 사이에 섞이는 것을 막기 위해서였다.
- **이번 설계에서 그 위험을 막는 방법**
  1. 실행마다 새 주체를 쓴다(ADR-04). 사용자 키 상태(action, 기준선, work-profile, 벡터 문서)가 섞이지 않는다.
  2. 사용자 키가 아닌 공유 상태(조직 기준선, RAG 조직 검색, ESCALATE 보호창, work-profile tenant)는 실행마다 다른 org/tenant 속성으로 분리한다(ADR-05).
  3. IP 실패 카운터는 실행마다 다른 IP로 분리한다.
  4. 격리 시험 T1~T8(계획서 7절)로 P1(스모크)과 P4(50개 동시)에서 확인한다. 하나라도 실패하면 공유 엔진 설계를 다시 검토한다.

## ADR-12 선행 조사: gpt-5-nano fallback (결정됨: A+F, 2026-10-05 코어 반영, ADR-18)
- **사실(코드 근거)**
  - 보안 판정 응답의 `reasoning` 문장이 정해진 RAG 문장과 정확히 같은데, 프롬프트에 `RagRelevance: NO_DOCUMENTS`와 `RagAuthorizedDocumentCount: 0`이 있으면 계약 위반 `FALSE_AUTHORIZED_RAG_CLAIM`이 된다(`SecurityDecisionRawOutputContractInspector`:88-92, 296-301).
  - 프롬프트의 정해진 문장 규칙 중 ALLOW용은 RAG가 같은 리소스에 있을 때의 문장뿐이다(`SecurityDecisionPromptSections`:2276-2285). 같은 프롬프트에서 낮은 위험 경계는 ALLOW를 요구한다. 그래서 모델이 하나뿐인 ALLOW 문장을 베끼고, 같은 프롬프트로 재시도해도 다시 위반한다.
  - 판정(ALLOW) 자체는 대개 맞는데, 문장 하나 때문에 기술적 fallback(CHALLENGE)이 된다.
  - fallback 사유가 `MODEL_UNAVAILABLE`로 기록되는 것은 분류 기본값 분기의 버그다(`LLMExecutionStep`:249-260). `VALIDATION_FAILED`를 무시한다.
  - 관련 커밋: 문장 규칙 `c3978ac8`, 계약 검사 `29a1877f`.
- **데모에 미치는 영향**: ALLOW 학습(템플릿)과 녹화가 망가진다. P1 게이트 "fallback 비율 2% 이하"를 통과하지 못할 가능성이 크다.
- **선택지**
  - A: RAG가 없을 때의 ALLOW 문장 규칙을 추가한다. 원인을 제거하지만 코어 프롬프트 계약과 PQA 해시가 바뀐다.
  - F: 분류를 고쳐 `PROMPT_CONTRACT_VIOLATION`으로 기록한다. 관측만 정확해진다.
  - E: 모델이나 reasoning-effort를 바꾼다.
  - 위 셋은 모두 코어나 운영 결정이다.
- **결정**: 사용자가 A+F를 승인했다(공용 결함일 때만 코어 수정 원칙). 둘 다 공용 결함으로 판정해 코어에 반영했다(`코어수정-P1.md`).

## ADR-13 배포 현황과 전환 경로 (P6)
- **현재**
  - `demo.ctxa.ai`는 엔터프라이즈 `contexa-demo`(9081)가 서비스한다.
  - `contexa-enterprise/.github/workflows/deploy-demo.yml`은 main push 때 빌드하고 `ghcr.io/<owner>/contexa-demo:latest` 이미지를 올린다. 배포는 `workflow_dispatch`일 때만 한다(SSH로 `/opt/contexa`에서 `docker compose up`, 이어서 nginx reload).
  - 서버 compose와 nginx 설정은 저장소 밖에 있다.
- **전환 절차(P6, 사용자 승인 후)**
  1. 워크플로의 빌드 대상과 이미지를 바꾸고, 롤백용 SHA 태그를 추가한다.
  2. 서버 compose에 새 서비스, DB, Coraza를 추가하고 비밀값을 넣는다. 롤백을 위해 기존 데모는 남겨 둔다.
  3. nginx upstream을 새 포털로 바꾼다.
  4. passkey rp-id, Turnstile 호스트, OAuth2 redirect URI, trusted-proxies를 설정한다.
  5. 헬스 실패 시 배포를 실패 처리한다.

## ADR-14 배포 대상과 이미지 (2026-10-04 보강)
- **결정**
  - 운영 환경은 오라클 클라우드 유료 VM이다(사용자 확인. 사양 제약은 없다고 함).
  - 이미지 플랫폼은 linux/amd64다.
  - 로컬 검수도 같은 이미지와 운영형 compose(내부 네트워크, 포털만 노출)로 한다.
- **플랫폼 근거**: 기존 배포 워크플로(`contexa-enterprise/.github/workflows/deploy-demo.yml:15`, `:71`)는 `ubuntu-latest`(x86_64)에서 플랫폼 지정 없이 `docker build`하고, 그 이미지가 운영 서버에서 돌고 있다.
- **이미지 슬림화**
  - `contexa-common/build.gradle:21`이 `nd4j-native-platform`을 가져온다. 이 의존이 모든 OS의 네이티브 라이브러리를 담아 대조군 D jar가 878MB가 됐다(Windows, macOS, Android, armhf 등 각 수십 MB).
  - 데모 모듈 빌드에서만 `*-platform` 묶음을 빼고 빌드 플랫폼의 classifier만 넣는다. 코어 변경은 없다.
  - Docker 빌드는 linux-x86_64, 로컬 Windows 실행은 windows-x86_64를 쓴다.

## ADR-15 내부 컨텍스트 신뢰 경계 (P0 확정)
- **결정**
  - 엔진 입력(회사 시각, 조직, tenant, 판정 ID, IP, 기기)은 포털이 HMAC-SHA256으로 서명한 내부 헤더로만 바꾼다.
  - workload는 모든 필터보다 앞에서 서명을 검증하고, 맞으면 엔진의 요청 속성과 요청 뷰(원격 주소, User-Agent)에 반영한다.
  - 엔진이 그대로 믿는 클라이언트 헤더(`X-Request-ID`, `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, `X-Contexa-*`, `X-Simulated-*`)는 서명과 관계없이 숨긴다.
  - 서명 시각 허용 차이는 60초, 키는 32바이트 이상이며 없으면 기동하지 않는다.
- **근거**: common `security/network/ClientIpResolver.java:52`, `:80`(신뢰 프록시가 없으면 원격 주소), core `autonomous/utils/RequestInfoExtractor.java:321-332`(판정 ID는 속성, 없으면 클라이언트 헤더). 상세 규칙과 probe는 `연결계약.md`.

## ADR-16 대조군 D의 인증 구성 (P0 확정)
- **결정**
  - `restLogin`(JSON) + 이메일 OTT 1요소, 세션 상태. 인가는 엔진 정책 관리자에 맡긴다.
  - OTT 코드는 엔진이 만들고 검증하며, 발송만 데모 수신함(`DemoInboxEmailService`)으로 바꾼다.
  - CSRF는 끈다. workload는 오케스트레이터만 부르는 내부 API이고 브라우저가 닿지 않는다. 대조군 B도 같은 조건으로 둔다(공정성).
- **근거**: 엔진 기본 구성은 폼 로그인이다(`contexa-autoconfigure/.../ai/AiSecurityConfiguration.java:79-128`). `EmailService`는 `@ConditionalOnMissingBean`이다(`.../identity/IdentityServiceAutoConfiguration.java:60`).
- **사실**: 새 주체는 로그인할 때 항상 MFA를 거친다(분석 기록이 없으면 CHALLENGE). 그래서 실행마다 오케스트레이터가 OTT를 수신함으로 처리한다(probe 1).

## ADR-17 계획 정정: ESCALATE와 응답 감싸기 (P0, ESCALATE와 재발행 부분은 ADR-18로 대체됨)
- 계획서 2절의 "ESCALATE는 5분 뒤 BLOCK으로 승격"은 실제 동작이 아니다. 423을 반복하다가 5분 뒤 PENDING_ANALYSIS로 돌아간다(발견 F-1, `연결계약.md` 7절).
  - P3의 ESCALATE 장면은 "423, 재시도 안내, 5분 뒤 재분석"으로 바꾼다.
  - probe 5는 "ESCALATE → BLOCK" 대신 "423 계약과 상태 유지"를 고정한다.
- 응답 감싸기 조건은 "action이 없거나 PENDING"이 아니라 "현재 상태가 PENDING_ANALYSIS"다. 기록이 없거나 만료되면 PENDING_ANALYSIS로 읽히므로 실질은 같다(identity `security/zerotrust/ZeroTrustAccessControlFilter.java:147`).
- MFA 뒤 재발행 요청은 다시 분석된다(발견 F-2). P3의 재발행 장면은 재분석 결과를 그대로 기록하고 보여 준다.

## ADR-18 코어 수정 반영 (2026-10-05)
- **배경**: P0 검수 결정. 코어는 공용이므로 데모 사정으로 바꾸지 않고, 공용 결함일 때만 고친다. F, A, F-2, F-1, C-1을 모두 공용 결함으로 판정해 고쳤다(`코어수정-P1.md`).
- **데모 영향**
  - ESCALATE 장면은 원래 계획대로 "423 → 검토 시간(5분) 안에 해결이 없으면 BLOCK"을 실제 기록으로 보여 준다(ADR-17의 ESCALATE 정정을 대체).
  - MFA를 통과한 뒤 다시 보낸 요청은 MFA가 남긴 ALLOW로 통과한다. 재분석 비용이 들지 않는다(ADR-17의 재발행 정정을 대체).
  - 실행 주체 정리는 공개 API(`UserManagementService.deleteUser` 또는 `UserEngineStatePurger.purge`)로 한다. D를 주기적으로 비우고 재기동하는 대안은 필요 없다(ADR-06의 삭제 부분 해소).
  - 위험 낮은 정상 요청의 기술 장애는 실측 20건 중 0건이다. P1-BE-07(50회 중 2% 이하)은 P1 실측으로 다시 확인한다.
- **측정 도구**: `LiveDecisionMeasurementTest`(`liveLlmTest` 태스크, 실제 모델 호출, 비용 발생)와 `SlowContractProbeTest`(`slowContractTest` 태스크)를 기본 시험에서 분리해 두었다.

## ADR-19 가상 기업 (P1, 2026-10-05)
- **업종**: 제조(설계 도면)를 기본 세계로 둔다. 덱의 주 장면이 모두 "설계 문서", "도면", "설계 엔지니어"이고 직원 120명 중 60명이 설계 엔지니어다(덱 9~12, 26쪽). 덱은 기본 세계의 업종을 정하지 않았다(승인대기 Q-01).
- **회사 이름**: 정하지 않는다. 덱 화면은 "관리자 A", "엔지니어 K"만 쓴다. 이메일은 `@showcase.invalid`다(승인대기 Q-02).
- **역할**(덱 26쪽 인원): `ENGINEER` 60, `SALES` 20, `PM` 12, `PARTNER` 12, `FINANCE` 10, `ADMIN` 6.
- **주인공**: 관리자 A(`adm-a`, ADMIN), 엔지니어 K(`eng-k`, ENGINEER). 평소 활동은 생성기가 정한다(근무일 낮 시간, 담당 프로젝트, 평소 기기 하나, 사무실 /24 대역).
- **결정성**: 생성기는 `(seed, anchorDate, generatorVersion)`만으로 같은 행을 만든다. 날짜는 모두 기준일(anchor) 상대값이다. 생성 결과의 SHA-256을 `company_generation`에 기록한다(P1-DB-01).
- **회사 달력**: 실행의 회사 날짜는 기준일이다. 템플릿 학습 이력은 기준일 전 6일 동안의 근무일에 둔다. work-profile 창이 이벤트 시각 기준이므로(ADR-25), 회사 날짜를 벽시계와 맞출 필요가 없다.
- **시각 구간**(덱 13쪽 4구간, 경계는 덱에 없음): 새벽 00:00-05:59(대표 03:17), 아침 06:00-11:59(09:40), 오후 12:00-17:59(14:20), 저녁 18:00-23:59(20:30). 실행은 대표 시각을 쓴다(승인대기 Q-05).

## ADR-20 대조군 실행 구성 (P1, ADR-01 보강)
- **결정**: plain 실행물 하나를 B, C1, C2 세 인스턴스로 띄운다. 인스턴스마다 `SHOWCASE_CONTROL`(B, C1, C2)이 인가 규칙을 고른다. A는 Coraza+CRS 컨테이너가 B 인스턴스 앞에 선다.
- **이유**
  - 세 대조군이 같은 경로(`/api/**`)를 쓰므로 오케스트레이터는 대조군마다 주소만 바꾼다. 계획서의 경로 접두사(`/c1/**`, `/c2/**`) 방식은 같은 컨트롤러를 접두사마다 다시 등록하거나 요청 경로를 바꿔 써야 한다.
  - 대조군끼리 메모리 상태와 로그가 섞이지 않는다.
- **공유하는 것**: 업무 DB(`showcase_work`), plain 사용자 테이블, 업무 API 코드, `BusinessContextLookup`.
- **A 구성**: `ghcr.io/coreruleset/coraza-crs:caddy-alpine`(digest를 compose에 고정), CRS 기본값(paranoia 1, inbound anomaly 5, 차단 모드). 덱 7쪽의 "IP 허용 목록 · 속도 제한"은 P1에 넣지 않는다(승인대기 Q-03).

## ADR-21 업무 API와 보호 방식 (P1)
| 동작 | 경로 | D 보호 |
|---|---|---|
| 프로젝트 목록 | `GET /api/projects` | 없음(RBAC만) |
| 문서 조회(도면 열기 포함) | `GET /api/documents/{documentKey}` | `@Protectable`(비동기) |
| 문서 다운로드 | `GET /api/documents/{documentKey}/download` | `@Protectable`(비동기) |
| 내보내기 | `POST /api/projects/{projectKey}/exports?items=N` | `@Protectable(sync = true)` |
| 내보내기 스트림 | `GET /api/projects/{projectKey}/exports/stream?items=N` | `@Protectable`(비동기, PENDING이면 응답 감싸기) |
| 고객 조회 | `GET /api/customers/{customerKey}` | `@Protectable`(비동기) |
- 판정에 쓰는 요청 값(건수, 프로젝트)은 경로와 쿼리에 둔다. 서명이 쿼리까지 덮으므로(연결계약 3절) 바꿀 수 없고, 룰 대조군의 요청 인가도 본문을 읽지 않고 판단한다.
- 컨트롤러와 업무 구현은 `showcase-business`에 있고, D는 같은 연산을 `@Protectable` 메서드로 감싼 구현을 쓴다. 엔진의 개인 RAG는 `@Protectable` 메서드 이름을 resourceId로 쓰므로, 메서드 이름을 바꾸면 템플릿을 다시 만든다.
- 업무 결과는 "자료가 전달되었는가"다(덱 24쪽). 내보내기는 응답의 manifest(문서 키 목록과 SHA-256)와 `export_job` 행이 근거다.

## ADR-22 룰 대조군 C1·C2 (P1 초안, P2에서 공정성 검토 후 동결)
- **C1 임계값 룰**(덱 7쪽: 시각 · 건수 · 무접근 기간)
  - `C1-NIGHT`: 회사 시각 22:00-05:59의 대량 작업(내보내기, 스트림, 다운로드)을 막는다.
  - `C1-VOLUME`: 내보내기와 스트림의 건수가 500을 넘으면 막는다(덱 18쪽 예시의 500과 같다).
  - `C1-DORMANT`: 요청자가 최근 30일 동안 그 프로젝트에 접근한 날이 없으면 그 프로젝트 자료(조회, 다운로드, 내보내기, 스트림)를 막는다.
- **C2 맥락 조회 룰**(덱 18쪽 조회 함수: ticket.covers, oncall.has, project.assigned, approval.exists, history.days)
  - 대량 작업: `approval.exists(건수 포함)` 또는 `ticket.covers and oncall.has` 또는 `project.assigned and 건수 ≤ 500`이면 허용, 아니면 막는다.
  - 단건 자료(조회, 다운로드): `project.assigned` 또는 `ticket.covers` 또는 `history.days(90일) > 0`이면 허용.
  - 고객 조회: 요청자가 그 고객의 담당자이거나 `ticket.covers`이면 허용.
- 모든 룰 판단은 `rule_decision_log`에 규칙 ID, 결과, 조회한 사실과 함께 남긴다.
- 값은 초안이다. P2 녹화 전에 공정성 검토를 거쳐 동결하고 해시를 실행 명세 `ruleVersion`에 넣는다(승인대기 Q-04).
- **P2 추가(2026-10-05, 쌍 A1·A8, 같은 초안 지위)**
  - 조회 함수 2개를 조회 계획(`LookupPlan`)에 넣어 C2와 D가 똑같이 읽는다: `network.context`(요청 주소가 회사 사무실 네트워크인지, 요청자의 등록된 출장 네트워크인지, 둘 다 아닌지)는 모든 자료 연산, `claimed.ticket`(요청에 적힌 티켓 번호가 업무 DB에 요청자의 것으로 있고 요청을 덮는지)은 티켓 번호를 적은 대량 작업에만.
  - `C2-EXTERNAL-NETWORK`: 회사 사무실도 등록된 출장지도 아닌 네트워크에서 온 자료 요청을 막는다.
  - `C2-FALSE-CLAIM`: 요청에 적힌 티켓이 업무 DB로 확인되지 않으면 막는다. 확인된 티켓도 그 자체로 허용하지 않고, 기존 허용 조건(승인, 티켓+당번, 담당+건수)을 그대로 따른다.
  - 대조군 A(WAF)에는 IP 허용 목록을 두지 않는다(ADR-20, 승인대기 Q-03). 사무실 대역 허용 목록을 둘지는 Q-21에서 묻는다.

## ADR-23 학습 템플릿과 실행 주체 복제 (P1, ADR-06 구체화)
- **학습**: 덱 26쪽 원칙 1(이력은 엔진의 수집 경로로 넣는다)대로, 템플릿 사용자로 실제 로그인하고 업무 요청을 보내 엔진이 학습하게 한다. 서명 헤더로 회사 시각을 기준일 전 6일의 근무 시간에 둔다.
  - 요청 수: 주인공마다 4개 이상의 날짜에 24건(기준선 확립 `updateCount ≥ 20`, work-profile 품질 STRONG 조건).
  - 간격: 각 요청의 판정 기록이 생긴 뒤 16초를 기다린다(ALLOW 15초가 같은 문맥의 다음 분석을 생략시키기 때문).
  - 학습은 ENFORCE의 ALLOW에서만 일어난다. CHALLENGE, ESCALATE, BLOCK이 나오면 그 템플릿 후보를 버리고 새 템플릿 사용자로 다시 학습한다(최대 3회). MFA로 넘기면 학습 시각이 벽시계가 되어 시간 분포가 망가지기 때문이다.
- **스냅샷**(공개 SPI로 읽음): 사용자 기준선, 조직 기준선, work-profile 관측, 권한 범위 상태와 role-scope 관측(`RoleScopeCollector.inspectStoredHistory`), 권한 변경 관측, 개인 행동 벡터 문서. 포털 DB `engine_template`에 JSON으로 둔다.
- **복제**(실행마다): 실행 사용자를 템플릿 사용자와 같은 그룹으로 만들고, 스냅샷의 키를 실행 사용자·조직·tenant로 바꿔 같은 SPI로 넣는다. 벡터 문서는 엔진 공개 빈 `UnifiedVectorService.storeDocuments`로 넣는다(임베딩을 다시 계산하지만 문서 수십 건이라 비용이 작다. 엔진 테이블을 SQL로 직접 쓰지 않는다).
  - 판정 상태, MFA 상태, 세션 상태는 복제하지 않는다. 새 주체는 PENDING_ANALYSIS로 시작해야 한다.
- **정리**: `UserEngineStatePurger.purge(username)` 뒤 사용자 행을 지운다. `deleteUser`는 `@Protectable`이라 시스템 인증과 불필요한 분석 이벤트가 생기므로 쓰지 않는다(C-1에서 정한 "엔진 밖에서 지우는 호스트" 경로).
  - 남는 것: 실행 조직의 조직 기준선과 실행 tenant의 role-scope 관측. 사용자 키가 아니라 정리 API 대상이 아니다(승인대기 Q-06).
- **템플릿 수명**: 엔진·모델·프롬프트·업무 API 시그니처가 바뀌면 다시 만든다. 벽시계에 묶인 것은 행동 문서 보존(기본 90일)뿐이므로, D는 `contexa.rag.etl.behavior.retention-days`를 400으로 두고 템플릿 나이를 실행 명세에 기록한다.

## ADR-24 workload 내부 API (P1)
- 오케스트레이터만 부르는 관리용 API를 `/internal/**`에 둔다: 실행 주체 생성·정리, 템플릿 스냅샷 내보내기, 판정 기록 조회, 데모 수신함.
- `/internal/**`는 서명된 내부 컨텍스트가 있을 때만 받는다(서명이 없거나 틀리면 403). 업무 API는 연결계약 4절대로 서명이 없어도 처리하되 엔진 입력만 바꾸지 않는다.
- workload는 내부망에만 있고(ADR-14), 내부 API는 그 안에서도 서명으로 한 번 더 막는다.

## ADR-25 계획 정정: 엔진 조사 결과 (P1, 2026-10-05)
- work-profile의 7일/30일 창은 현재 이벤트 시각(observedAt) 기준이다(core `autonomous/context/collector/DefaultProtectableWorkProfileCollector.java:95-131`). 계획서 2절의 "학습 이력이 7일을 넘기 전에 템플릿을 다시 만든다"는 맞지 않는다. 실행의 회사 시각이 템플릿 이력 뒤 7일 안이면 된다.
- work-profile 관측은 ALLOW에서만이 아니라 LLM이 분석한 요청마다 쌓인다. RBAC가 거부한 요청만 빠진다(같은 파일 `:846-854`). 기준선(`BaselineVector`)만 ALLOW에서 학습한다.
- 보안 판정 경로의 advisor에는 `event.userId`가 없다. 실행 연결은 advisor context `contexa.llm.observation`의 `requestId`(오케스트레이터 UUID)로 한다(core `std/pipeline/step/LLMExecutionStep.java:452-462`).
- 엔진 스키마는 `contexa-iam` 리소스 `db/schema.sql`이 만든다(auto `identity/IamSeedDataAutoConfiguration.java:62`). ADR-10의 "core가 만든다"를 이렇게 읽는다.
- D의 URL 인가는 맞는 정책이 없으면 허용이 기본이다(`no_matching_url_policy_decision` 기본 PERMIT). B와 같은 RBAC를 위해 업무 경로 끝에 거부 정책을 둔다(P1-BE-02 parity로 확인).
- 판정 기록 `ai_security_decision_observation`의 시각 컬럼은 시간대 없는 `TIMESTAMP`이고 D JVM 시간대로 쓴다. ADR-09(UTC)를 전제로 UTC로 읽는다.

## ADR-32 체험 우선: 첫 화면이 곧 실제 실행 (2026-10-06, 사용자 결정)
- **결정**: 방문자가 가장 먼저 하는 일은 버튼을 직접 눌러 실제 요청을 보내는 것이다. 다섯 보안 방식의 응답은 도착하는 대로 화면에 나타난다.
  - 순서: 장면 1 공격자 → 장면 2 진짜 담당자(같은 요청, 장애 티켓만 다름) → 두 장면 비교 → 조건 바꿔 보내기.
  - 설계와 검수 항목: `체험우선-설계.md`.
- **바뀌는 것**
  - v5의 "질문에 투표 → 녹화 재생" 첫 동선을 버린다. 녹화 재생(`/replay`, `/end`)은 "다른 장면"에서만 들어간다.
  - "조건 바꿔 보기"(`/explore`)와 "직접 해보기"(`/try`)는 첫 화면의 "조건 바꿔 보내기"로 합친다. 옛 경로는 첫 화면으로 보낸다.
  - 기록 재사용을 끈다. 버튼을 누를 때마다 실제로 실행하고, 한도(1인 하루 10회)에서 차감한다. P4-BE-04의 "같은 조합의 두 번째 방문은 LLM 호출 0"은 이 결정으로 폐기한다.
  - 실행을 시작할 수 없을 때(한도, 일시 중지, 템플릿 없음)만 같은 조건의 저장된 실제 실행을 "다른 방문자의 실제 실행 기록"이라고 밝혀 보여 준다(`LiveGate.Refused.fallback`).
- **API**
  - `LiveRun.LayerView`에 나간 자료 건수와 걸린 시간을 더했다.
  - `GET /api/live/runs/current/result`: 끝난 실행의 전체 결과(근거 서랍용)
  - `POST /api/live/runs/current/abandon`: 공격자가 본인 확인을 포기
- **판정 품질**: 엔진이 위협을 통과시키는 문제(승인대기 Q-14)는 데모 구현이 끝난 뒤 프롬프트 구성부터 본다(모델 비교 안 함). 그때까지 화면은 실제 결과를 그대로 보여 준다(예: "둘 다 맞힌 곳: 없음").

## ADR-33 세 막 화면과 방문자가 보내는 두 번째 요청 (2026-10-06)
- **결정**: 첫 화면(`/`)을 화면설계서의 세 막(`ShowPage`)으로 바꾼다. 흐름은 시작 → 막 1 공격자 → 막 2 진짜 직원 → 막 3 붙이는 법이다.
  - 공격자 장면의 "다시 시도하기"는 실제 두 번째 요청이다. 같은 실행 주체(같은 세션·계정)로 GB-500 도면 1건 내려받기를 다섯 방식에 보낸다. 잠김 화면은 이 요청에 대한 Contexa의 실제 응답(403·401·423)에서만 나온다.
  - 화면 효과로 잠김을 연출하지 않는다. 엔진이 허용하면 "다시 보낸 요청도 통과시켰습니다"를 그대로 보여 준다.
- **서버**
  - 시나리오 단계에 `visitorSends`를 추가했다. 실시간 실행은 이 단계 앞에서 방문자를 기다린다(상태 `AWAITING`, 120초). 녹화 실행은 기다리지 않고 바로 보낸다.
  - A3S를 버전 2로 올렸다. 두 번째 단계는 `DOCUMENT_DOWNLOAD` GB-500 DRAWING 1번이다. 기대값은 A·B 허용, C1(야간 반출)·C2(담당·티켓·이력 없음) 거부다.
  - `POST /api/live/runs/current/next`: 기다리는 단계를 보낸다. `abandon`은 그 단계 없이 실행을 끝낸다.
  - `GET /api/live/runs/current/analysis?step=N`, `GET /api/live/runs/current/result?step=N`: 단계별로 조회한다.
- **정합성 장치**
  - `web/src/domain/show.test.ts`: 화면 상수(03:17, GB-500, 4,831건, 승인자 pm-11, 5,000건까지)를 시나리오 원본 A3S·A3ST.json과 대조한다.
  - `web/sourceExcerpts.test.ts`: 막 3에 보여 주는 코드가 workload 소스와 한 줄씩 같은지 대조한다.
  - `web/e2e/portal/experience.spec.ts`: 실서버에서 세 막을 실제로 실행하고, 각 방식의 건수·HTTP 상태와 판정 시각(+ms)을 화면과 API 원본으로 대조한다(E-1).
- **색**: 색 바탕 위 글자는 `--color-signal-ink`(어두운 테마는 짙은 글자)로 쓴다. 어두운 테마의 붉은색을 `#f4676b`로 올려 Contexa 칸 바탕에서도 대비 4.5 이상을 맞췄다. 글자가 있는 요소의 등장 효과는 투명도 없이 위치·크기만 움직인다.
- **남은 것**: BLOCK 해제 흐름(본인 확인 → 사유를 적은 해제 요청 → 관리자 승인, 코어 `ZeroTrustUnblockController`·`BlockedUserService`), 장면 4(규칙의 한계), 근거 서랍 개편, 위협 카드, 통계 성적표.

## ADR-34 차단(BLOCK) 해제 흐름과 실행별 보안 담당자 (2026-10-06, 사용자 질문에 따라)
- **결정**: Contexa가 계정을 차단(403 `ACCOUNT_BLOCKED`)하면, 실행은 방문자가 해제를 요청하기를 기다린다(상태 `BLOCKED`, 단계마다 120초). 모든 단계는 엔진의 실제 엔드포인트를 그대로 부른다.
  1. 본인 확인 시작(`initiate-block-mfa`)
  2. 일반 요청 한 번으로 엔진이 확인을 시작하면 일회용 코드 발송, 데모 메일함의 코드로 확인(`/login/mfa-ott`)
  3. 사유를 적어 해제 요청(`unblock-request`)
  4. 실행의 보안 담당자가 관리자 API로 요청을 읽고(`GET /contexa/admin/api/blacklist`) 승인(`POST .../{id}/resolve`, `resolvedAction=ALLOW`)
  5. 원래 요청 재발행. 승인 직후 권한 캐시(최대 5초) 때문에 403이면 2초 간격으로 4번까지 다시 보낸다.
- **보안 담당자**: 가상 회사 IT 관리 부서의 Administrator B(adm-b)다. 실행마다 해제를 요청할 때만 만들고(엔진 `ROLE_ADMIN` 직접 부여), 실행과 함께 지운다. 비밀번호는 포털만 안다. 방문자는 승인 버튼만 누르고, 포털은 그 실행 자신의 요청 하나만 승인한다.
- **공격자**: 위협 시나리오에서는 본인 확인이든 해제든 코드가 직원의 메일함으로 실제로 발송되고, 실행은 그 코드를 끝까지 내주지 않는다(`NO_MAILBOX`). 화면에서만 숨기던 것을 서버 규칙으로 바꿨다. 방문자가 API를 직접 불러도 공격자 실행에서는 코드를 받을 수 없다.
- **녹화**: 녹화 실행은 해제를 요청하지 않는다(`ReleaseTrace.notAsked`). 차단은 엔진이 남긴 그대로 기록된다.
- **확인 수단**: 엔진이 지금 공격에 BLOCK을 내지 않으므로(Q-14), 개발 전용 강제 판정이 BLOCK도 받도록 넓혔다. 강제 BLOCK은 엔진 집행과 같은 순서로 판정 저장 → 차단 표식 → 차단 기록을 남긴다(사유 "Development-only forced decision"). 강제 판정이 켜진 동안은 녹화와 공개를 거부한다(기존 규칙).
- **API**: `POST /api/live/runs/current/release-start`, `/release-request {reason}`, `/release-approve`. 코드 입력은 `/answer`를 함께 쓴다. 방문자가 떠나면(`abandon`) 실행은 남은 방문자 단계를 더 기다리지 않는다.
- **화면**
  - 직원 장면: 해제 패널(차단 → 코드 → 사유 → "보안 담당자 화면" → 승인), 결론 "업무 복귀 · 차단에서 N초"
  - 공격자 장면: 잠김 화면의 "차단 해제 요청해 보기" → "해제하려면 본인 확인이 필요합니다"
- **같은 작업에서 고친 코어 결함**: K-1 관리 화면 접근 권한(`코어수정-P1.md` K-1)


## ADR-35 진행 위치와 날짜별 익명 건수 (2026-10-08, ADR-27 개정, 사용자 위임 결정 12·16)

- 배경: ADR-27(2026-10-05)은 방문자 부담을 없애려고 동의 배너와 측정 이벤트를 범위에서 뺐고, 개인정보 안내는 '이용 흐름을 재는 측정을 쓰지 않음'이라고 적었다. 화면 설계서 v2.3은 이해 확인 문항별 정답률(결정 12)과 막별 도달 수(결정 16), 새로고침해도 이어지는 진행 위치(작업 14)를 요구한다.
- 결정
  - 진행 위치는 체험 기능이다. 방문자 해시와 함께 `visitor_journey`에 두고, 방문자 식별자와 같은 30일 뒤 함께 지운다.
  - 문항 정답과 막 도착은 날짜·지표·항목·값·건수만 가진 `anonymous_tally`로 센다. 방문자 해시, 주소, 쿠키 값은 없다. 같은 방문자를 두 번 세지 않도록 진행 위치가 '이미 센 막'과 '이미 센 답'을 기억한다.
  - 문항의 정답은 서버에 두고 서버가 채점한다(`/api/quiz`).
  - 외부 분석 도구, 동의 배너, 개별 이벤트 기록은 여전히 쓰지 않는다(ADR-27 유지).
  - 개인정보 안내와 데이터 목록을 같은 날 고쳤다(`policies.ts`, `개인정보-데이터목록.md`).
- 검증: `JourneyIntegrationTest`(한 번만 셈, 집계 표의 열은 날짜·지표·항목·값·건수뿐), `RetentionIntegrationTest`(30일 뒤 삭제, 진행 위치는 방문자와 함께 삭제), `policies.test.ts`.

## ADR-36 화면 설계서 v2.3의 구현 구조 (2026-10-08, 사용자 위임 "가장 최적인 것을 너가 결정해서 진행하라")

- 배경: 화면 설계서 v2.3(훅과 네 막, 개념 경로, 실험실, 판정 자세히 보기, 벤치마크)을 S0~S12로 구현했다. 단계마다 정한 구조를 한곳에 남긴다. 세부와 이유는 구현계획서 15.3이다.
- 결정
  - 주소가 곧 자리다: 단계·창·보기마다 주소가 있어 새로고침·뒤로 가기·공유가 같은 자리로 온다. 판정 자세히 보기는 어느 화면 위에서든 `?modal=detail&detailRun=&detailStep=&detailTab=`로 여는 창이고, 옛 주소는 새 주소로 넘긴다.
  - 화면 틀 하나: 모든 경로 화면은 `RouteScreen`의 같은 순서(위치 띠 → 머리글 → 본문 → 펼침 칩 줄 → 방금 본 것 → 행동 영역)를 쓴다. 다음 버튼의 이름은 위치 띠의 다음 단계 이름이며, 원천 문구가 따로 있으면 그 문구가 가리키는 화면에서만 쓴다.
  - 화면은 세지 않는다: 결론 문장 코드, 정답 대비, 집계, 실험실 비교(바꾼 조건 포함), 예고 카드 숫자와 사실 조건은 포털이 계산해 준다. 웹 소스의 측정 숫자 상수는 시험으로 막는다.
  - 방문자의 실행은 저장 기록으로도 그린다: 포털은 현재 실행을 메모리에만 두므로, 체험 단계는 현재 실행이 없으면 여정의 최신 완료 실행을 저장된 단계 결과·판정 해부로 그린다(`tryRun.ts`). 해부 기록은 판정의 토큰 합계를 서버가 계산해 준다.
  - 첫 로드는 방문자 언어 하나: 사전은 언어별 묶음이고, 첫 HTML의 작은 스크립트가 앱과 같은 규칙으로 언어를 골라 그 사전만 미리 받는다(`languagePreload.ts`).
- 결과: S12 종합 검수 C-1~C-19 중 C-1(사람 시험)은 사용자, C-13은 첫 화면·API 기준 안·체험 화면 LCP 미달(Q-56), 나머지 PASS(`S12-검수.md`).

## ADR-37 판정 프롬프트 v20 형식: 사전·블록·결측 표기·사실 ID (2026-10-10 W0-5 확정, 2026-10-15까지 보강)
- **결정**
  - 모델이 받는 모든 줄은 v20 사전에 등록된 항목으로만 만든다. 항목마다 뜻, 원천 경로, 값 형식, 결측 표기, 판정에서의 쓰임, 블록, 출처 등급을 정한다(계획:63-64, 원칙 2 계획:89-91).
  - 블록은 시스템 둘(판정 규칙, 출력 계약)과 사용자 일곱(USER BASELINE, SESSION, REQUEST, DECISION FACTS, PAST RECORDS, UNKNOWN, UNTRUSTED TEXT)이다. Layer2 2차에서만 SECOND PASS를 덧붙인다. 순서는 바뀌는 주기 순이고, 바뀌지 않는 것이 앞에 와서 제공자 캐시 접두사가 된다(사전:11, 사전:29-42, 계획:399).
  - 출처 등급은 host, learned, computed, inferred, untrusted 다섯이다(사전:45-53).
  - 결측은 세 종류다. not-integrated와 unavailable-now는 줄을 쓰지 않고 UNKNOWN 블록에 이름과 종류로 적는다. not-applicable은 줄을 쓰지 않는다. UNKNOWN은 일치도 불일치도 아니다(사전:65-73, 계획:630).
  - 근거 코드가 인용하는 줄에는 사실 ID를 붙인다. 판정 사실은 `F`, 기준선·세션·요청·과거 기록은 `B`·`S`·`R`·`P`(P3-추가-12), Unknown 줄이 모르는 사실마다 주는 ID는 `U`(N-UID-1, Q-87)다. ID는 그 프롬프트 안에서 블록 안에 그린 순서로 붙는다(사전:79-83, 계획:631).
  - 한 사실은 한 줄, 한 이름, 한 출처, 한 어휘, 한 시계로 쓴다(계획:100, 사전:87). 목록 값의 순서는 입력 순서가 아니라 정한 규칙을 따른다(사전:88-92).
  - 사실을 담은 항목은 빼지 않는다. 빼기는 항목마다 결정한 것만 했다: Q-61·Q-73(W3-5), Q-79(W3-19), Q-84와 P3-추가-36(지시 문장만), `TrustedSignal`(Q-78 요청 4, R4-T)(계획:130-134, 승인대기:1090-1091·1098·1100·1159·1177).
  - 설계 정본은 사전 문서다(계획:624). 실행 정본은 코드 사전(번들 요소 B2)이고, DB 행은 시작 때 쓰는 사본이다(계획:409).
- **이유**
  - v19 판정은 `ApprovalMissing` 한 값에 거의 따라갔다. 공격 중 그 값이 false인 79단계의 정답은 5%였다(계획:5).
  - 지시 3·4: 의미 없거나 틀리거나 출처가 없는 줄이 하나도 없어야 하고, 프롬프트 구성이 모델의 추론을 방해해서는 안 된다(계획:22-23).
  - W0-5의 설계 확정은 사용자 위임으로 했다(사전:3, 승인대기:698-699). 원칙 14의 빼기는 위임 밖이라 항목마다 따로 정했다(승인대기:700).
- **영향**
  - 코드: 블록 `core/autonomous/context/prompt/PromptBlock.java:26-35`, 출처 등급 `PromptSourceGrade.java:19-30`, 결측 종류와 `U` 접두사 `PromptUnknownKind.java:25-33`.
  - 사전이나 렌더가 바뀌면 새 번들 이름으로 고정한다(ADR-39). 프롬프트 검수기의 계약은 이 사전이다(ADR-43).
  - 사전 8절(검사기 계약 v2 구조, 사전:374-395)은 ADR-44에 따라 쓰지 않는다(계획:73, 계획:251).

## ADR-38 v19 형식 유지와 롤백 대상 (2026-10-10 계획 v3, 버전관리 결정 2)
- **결정**
  - P1·P2는 v19 형식을 유지하고 값만 바로잡는다. v20 번들은 P3부터 둔다(계획:264-266).
  - v19·v20 번들을 한 빌드에 싣는다. 빌드 기본은 v19이고, 빌드에 남길 이전 번들은 하나다(계획:119, 계획:250, 버전관리:492).
  - 전환 일정: P7까지 v19가 ACTIVE다. v20은 P3부터 AVAILABLE, P6~P7에 SHADOW다. P8에서 게이트·롤백 리허설·승인 뒤 v20이 CANARY → ACTIVE가 되고, v19는 DEPRECATED로 남아 롤백 대상이 된다(계획:254, 계획:616). v19를 RETIRED로 내릴 시점은 사용자가 정한다(계획:616). P8 결과: 관문 미달(2절 17개 중 A2·C5 미달)로 전환하지 않았다(아래 P8 결과).
  - 출력 계약 v3와 고정 근거 문장 폐지는 v20 번들에만 적용한다. v19 번들은 그대로다(P4 검수:52·89·95).
- **이유**
  - 판정 변화가 어디서 왔는지 따로 보려는 것이다. 값의 뜻을 바로잡은 효과(P1·P2)와 구성을 바꾼 효과(P3·P4)를 따로 잰다(계획:273).
  - 롤백은 빌드에 있는 번들로의 실제 전환이다. 빌드에 없는 번들은 롤백 대상이 될 수 없다(계획:119, 버전관리:97).
- **현재(2026-10-16)**
  - 빌드 기본 번들은 v19 레이아웃이고, 실행할 수 있는 번들은 둘이다(`core/autonomous/tiered/prompt/SecurityDecisionPromptBundles.java:55-62`). 이름은 `2026.10.16-v19.19`와 `2026.10.16-v20.23`이다(`SecurityDecisionStandardPromptTemplate.java:58`, `:108`).
  - v20.23 매니페스트의 롤백 대상은 v19.19다(`contexa-core/src/main/resources/prompt-bundles/manifests/cortex.security-decision/2026.10.16-v20.23.json:77`). 쇼케이스 D에서 v20.23은 SHADOW 릴리스다(P6-변경-19, P6 검수:325).
- **P8 결과**
  - ACTIVE가 된 v20 번들 이름·해시: 없다. P8 관문 미달(A2 정상 업무 본인 확인 25/75, C5 주입 변화 1/7)로 v20을 ACTIVE로 바꾸지 않았다. 측정·공개한 번들은 `2026.10.16-v20.24`(bundleHash `5e75a42543778f2367635001a97174cbe5b890c43bc50a318e50cb9dca23a06e`)다
  - CANARY·ACTIVE 전환 시각과 v19 DEPRECATED 전환: 없다. 레지스트리는 재빌드 첫 등록 그대로다(v19.20 ACTIVE, v20.24 AVAILABLE, v20.23 SHADOW). 전환은 사용자 결정 뒤다
  - 롤백 리허설 결과(W6-10, W8-3): 하지 않았다. 리허설은 전환 절차(연쇄 c)의 앞 단계라, 관문 미달로 연쇄 c를 시작하지 않았다

## ADR-39 프롬프트 번들과 매니페스트 (2026-10-10 W0-10 확정, W1-18 v19 번들화, 2026-10-14 R4-B9)
- **결정**
  - 버전 단위는 번들이고 정체성은 내용 해시다. 한 글자라도 바뀌면 새 번들이다(계획:117, 버전관리:93-94).
  - 요소는 B1~B11이다: B1 시스템 글, B2 사전, B3 렌더러(골든 렌더 다이제스트), B4 출력 계약, B5 최소 대응 규칙, B6 응답 검사 규칙, B7 과거 기록, B8 예산, B9 검사기 계약, B10 어휘, B11 2차 분석(B3에 포함)(버전관리:105-117).
  - 번들 해시는 요소 해시 열한 개를 B1~B11 순서로 이은 글의 SHA-256이다. 글 요소는 줄바꿈을 LF로 바꾼 뒤 해시한다. 내용을 해시하지 않는 요소는 상태 표지(ABSENT, UNVERSIONED, INCLUDED)를 해시해 상태도 정체성에 든다(`core/std/components/prompt/bundle/PromptBundleHashes.java:31-32`, `:50-53`, `:63-68`, `:70-86`, `PromptBundleElementState.java:22-27`).
  - 매니페스트의 다른 칸(골든 입력, 부모, 변경 요약, 문제 ID, 작성자, 고정일, 어휘, 롤백 대상, 모델 프로필)은 번들을 설명할 뿐 해시에 들지 않는다(`PromptBundleManifest.java:21-39`). 매니페스트를 읽을 때 선언한 해시가 요소 해시와 다르면 실패하고, 같은 이름에 다른 해시가 둘이면 실패한다(`PromptBundleManifest.java:50-54`, `PromptBundleCatalog.java:33-35`, `:46-53`).
  - 고정 절차: 번들 시험이 코드에서 매니페스트를 계산해 `build/prompt-bundles/manifests`에 쓰고, 출하 매니페스트와 요소가 다르면 새 버전 이름을 요구한다(`contexa-core/src/test/java/io/contexa/contexacore/autonomous/tiered/prompt/SecurityDecisionPromptBundleTest.java:139-173`). 고정 도구가 그 매니페스트에 손 칸(부모, 문제 ID, 고정일, 쓰는 어휘와 읽는 어휘, 롤백 대상)을 채워 출하 위치에 둔다(P5 검수:796, P6 검수:211, `scratchpad/p5/bundle_p5_freeze.py:1-2`). 고정 도구는 작업 폴더 스크립트이고 레포에 없다. 손 칸은 위의 설명 칸이라 해시에 들지 않는다.
  - 이름은 `YYYY.MM.DD-vNN`이고, 같은 날 다른 내용이면 `.2`, `.3`을 붙인다. 출력 계약 버전은 `CORTEX_PROMPT_CONTRACT_V3`다(버전관리:509-510).
  - 모델 프로필은 번들 밖에 둔다. 실행 구성은 '번들 × 모델 프로필'이다(버전관리:119, 버전관리:495).
  - B9(검사기 계약)는 ABSENT 표지로 바꿨다. v19·v20이 함께 쓰는 요소라 두 번들을 새 버전(v19.10, v20.12)으로 고정했다(R4-B9, Q-78 요청 2, Q-83: 계획:120, 계획:473, 버전관리:662-664, 승인대기:1096).
- **이유**
  - 계획 전의 버전 정체성은 글과 무관했다. 디스크립터 해시는 메타 12필드의 해시라, 글이 바뀌어도 메타가 같으면 해시가 같았다(PV-1, 버전관리:48, 계획:181).
  - 지시 11·12: 프롬프트는 버전관리가 필요하고, 기본 버전관리는 OSS가 맡는다(계획:30-31).
  - 검수 결과는 판정 출력에 영향이 없고 결과마다 검수기 판을 남기므로, 검사기 계약을 번들에 묶을 이유가 없다(재설계:200-201).
- **영향**
  - 지금 빌드의 v20.23 매니페스트: B9 ABSENT(`contexa-core/src/main/resources/prompt-bundles/manifests/cortex.security-decision/2026.10.16-v20.23.json:46-49`). B9가 두 번들의 요소가 아님을 시험이 지킨다(`SecurityDecisionPromptBundleTest.java:120-130`).
  - 옛 매니페스트는 렌더 코드가 없는 기록으로 남고 고를 수 없다(버전관리:523).
  - P8에 ACTIVE가 된 번들의 해시: 없다(전환하지 않음). 측정한 v20 번들 해시는 `5e75a4254377…`다

## ADR-40 번들 선택기, 레지스트리 수명주기, 활성화 게이트 (2026-10-10 버전관리 결정 1~13, 2026-10-12 W3-16, 2026-10-16 W6-8~W6-10)
- **결정**
  - 실행할 번들을 고르는 곳은 선택 SPI `PromptBundleSelector` 하나다. OSS가 설정 구현(`contexa.security.tiered.prompt-bundle.active`)과 레지스트리 구현을 둔다. 쓸 구현은 `contexa.security.tiered.prompt-bundle.selector`(기본 `configuration`, 또는 `registry`)로 고른다(계획:253, P3-변경-22 P3 검수:2962, `core/properties/TieredStrategyProperties.java:44-58`).
  - 한 이벤트는 한 번들로 그린다. Layer2·2차 분석은 1차 프롬프트의 번들을 쓴다(P3-변경-23, P3 검수:2963). 고른 번들이 빌드에 없으면 기본 번들로 그리고 error 로그를 남긴다(버전관리:526).
  - 상태 어휘 정본은 AVAILABLE, SHADOW, CANARY, ACTIVE, DEPRECATED, RETIRED와 이벤트 KILL_SWITCH다. 기존 어휘는 대응표로 읽기 호환이다(결정 1: 버전관리:491, 승인대기:679, `core/std/components/prompt/bundle/PromptBundleState.java:39-55`, `:71`). 앞으로 가는 전이는 단계를 건너뛰지 않는다(AVAILABLE → SHADOW → CANARY → ACTIVE). DEPRECATED에서는 CANARY와 RETIRED로만 가고, RETIRED에서는 갈 곳이 없다(`core/std/components/prompt/governance/PromptGovernanceReleaseGateService.java:676-686`).
  - 게이트 증거는 그 번들 해시로 만든 실행의 평가만 받는다. 다른 번들의 평가로는 CANARY·ACTIVE로 갈 수 없다(W6-8, P6 검수:136, 게이트 `:427-431`, `:914-919`). 재지 않은 게이트 값은 `NOT_VERIFIED`로 둔다(계획:585, 게이트 `:393-396`).
  - ACTIVE로 가려면 TEVV 게이트가 `READY_FOR_PRODUCTION`이고, 주입 게이트가 실패가 아니고, 지연·비용 게이트가 실패가 아니고, 경험 평가가 통과해야 한다. 모델 호환·예산·토큰 계산·캐시·압축 정책과 롤백 대상도 선언되어 있어야 한다(게이트 `:449-484`).
  - 섀도는 기본 꺼짐(0%)이고, 켜면 비율과 하루 호출 상한을 설정으로 둔다(결정 3: 버전관리:493, `TieredStrategyProperties.java:64`, `:67`). 섀도는 판정 뒤 비동기로 후보 번들을 따로 봉인하고 집행·학습하지 않는다(P6-변경-6·11, P6 검수:312·317).
  - 롤백은 매니페스트의 롤백 대상 가운데 하나로 바로 바꾼다. 조건은 원래 번들이 실행 중임, 대상이 빌드에 있음, 대상이 롤백 대상으로 선언되어 있음, 어휘 호환, 대상이 레지스트리에 있음, 정책 세트다. OSS에는 정책 세트가 없어 구현이 없으면 '해당 없음'을 원장에 적는다(P6-변경-7, P6 검수:159-163, `iam/admin/promptquality/governance/PromptBundleRollbackService.java:66-88`).
  - OSS 버전관리는 기본 켬이고 속성 하나(`contexa.prompt.governance.enabled`)로 켜고 끈다(결정 11: 버전관리:501, `auto/iam/admin/PromptGovernanceAutoConfiguration.java:64`).
- **이유**
  - 평가 원장이 늘 '경험 증거 MISSING, TEVV NOT_READY'로 다시 쓰였고(PV-5), 후보 릴리스가 재지 않은 주입·지연·비용을 'PASSED'로 썼다(PV-16)(버전관리:52·62).
  - 지시 12: 엔터프라이즈 버전관리 코드를 OSS로 그대로 옮긴 뒤 결함을 고친다(계획:31, 계획:76).
- **영향**
  - 검증 호스트에서 시작 등록 평가(해시 없음)로 카나리를 요청하면 422 `EVALUATION_NOT_FOR_BUNDLE_HASH`였고, 평가를 같은 번들 해시로 바꾸자 그 막힘이 사라졌다. 최종 트리에서 자기 해시 평가의 카나리 전이는 200이었다(P6 검수:222, :294).
  - 엔터프라이즈가 OSS 게이트를 부르게 바꾸는 일은 최종 구현 계획 뒤로 미뤘다(P3-변경-84, 계획:585).
  - P8 게이트 증거(평가 원장 행, 측정 프로토콜)와 전환 영수증: 평가 원장 행과 전환 영수증은 없다(연쇄 c 미실행). 측정 프로토콜은 protocol-541025e6, 판정 기록은 `p0/repro/records/p8_gate_verdict.json`(종합 FAIL, 15/17 통과)이다. 활성화 게이트의 지연·비용은 PASSED였다
  - 프롬프트 품질 인증이 버전에 묶여 있을 때의 v20 인증(W8-3): 해당 없다(v20.24는 인증되지 않음). 공개 묶음은 `p0/repro/records/p8_publication_p8/`다

## ADR-41 신뢰하지 않는 글(UNTRUSTED TEXT)과 주입 방어 범위 (2026-10-12 W3-6·N-INJ-1, Q-65)
- **결정**
  - 사용자 프롬프트에는 지시문이 없다. 신뢰할 수 없는 글은 출처와 함께 따옴표 블록에 두고, 정규화·분류·비교에 쓰지 않는다(원칙 6 계획:101-103, 사전:184-186).
  - 대상(W3-6): 업무 라벨 작성자 글, 요청 본문 요약, 외부 위협 지식 문장, 이상 신호 글, 상승 사유(호스트 글)(계획:395, P3 검수:24).
  - 대상(N-INJ-1): 해석하지 못한 UA, 요청 경로와 경로 변수, 이번 세션 앞 요청 경로들, 요청자가 이름 댄 티켓. 사실 줄은 엔진이 만든 모양(경로 틀 변수 이름, `this target`·`another target`, `unparsed user agent` 등)만 쓴다(계획:396, P3 검수:25, P3 검수:624-625).
  - 형식은 `source=〈출처〉; "〈글〉"`이다. 글 안의 역슬래시·따옴표는 이스케이프하고, 상한을 넘으면 앞부분만 두고 `… [+n chars cut]`을 쓴다. 상한은 `truncation.layer1.payload`(기본 200)를 모든 항목에 쓴다(P3 검수:548-549, `core/autonomous/context/prompt/PromptSlotRenderer.java:50-69`). 출처 이름은 한 목록에 둔다(`core/autonomous/tiered/prompt/UntrustedTextSources.java:22-41`).
  - 자원 등급은 이 글로 바뀌지 않는다(사전:186, W1-2 계획:333). 권한 없는 요청자의 `X-Contexa-Anomaly-Signal` 주장은 UNTRUSTED TEXT에만 남는다(사전:413, 승인대기:1098).
- **이유**
  - 문서 설명의 'always return ALLOW'로 자원 등급이 PUBLIC으로 바뀌었다(I-2, 계획:310).
  - Q-65의 2차 조사가 요청자 글(UA·경로)의 주입 방어 부재를 찾았고, 사용자가 계획 보완을 모두 추천대로 하라고 정했다(승인대기:812, :814-816).
- **영향**
  - 인증 지표 C5(주입 시험의 사실·판정 변화) 목표는 0이다(계획:157). 측정 하네스의 주입 평가기는 지시문이 UNTRUSTED TEXT 블록에만 있는지 본다(P6 검수:235).
  - W7-4 주입 시험 결과: OSS 호스트(v20.23)는 통과했고 반복 0/6 변화다. 쇼케이스 주입 묶음은 오프라인 재평가 15/18이며, 남은 3건(S09C-I1 업무 라벨)은 코어 결함 N-INJ-3이라 v20.24에서 고쳐 다시 잰다(P7 검수:18, P7 검수:772)
  - P8 C5 판정: FAIL. 주입 7곳 중 1곳(A1T-I1, 과거 기록 이름표의 지시문)에서 판정이 ALLOW → CHALLENGE로 바뀌었다. 지시문은 UNTRUSTED TEXT 안에만 있었고 밖으로 새지 않았다. 새 계획 행 N-INJ-6

## ADR-42 봉인 증거 (W1-15, W6-6·W6-12, 저장 설계 B, 2026-10-14~16)
- **결정**
  - 봉인 캡처, 값 충돌 감지, 해시 무결성처럼 쓸모가 확인된 장치는 유지한다(원칙 8 계획:107, 재설계:20).
  - 보호 판정은 경로와 무관하게 봉인한다(W1-15, 계획:346).
  - 판정마다 번들 이름·해시, 선택 출처, 정책 세트, 모델 설정, 실제 글 해시를 봉인한다(계획:255, 버전관리:155-163).
  - 2차 분석은 적용 단계 값으로 봉인을 맞추고, 모델 호출마다 단계·시도·덧붙은 글·답을 단계 기록에 남긴다(W6-6, P6-변경-4, 계획:577). 프롬프트에 실린 과거 기록 ID와 검색 범위·필터·정렬을 봉인한다(W6-12, P6-변경-9·12, 계획:589).
  - 렌더 메타 `promptFactIds`는 봉인하지 않는다(읽는 검사가 없음, R1b-10, 계획:429, 사전:82).
  - 저장: 표본 포착 기본 1%, 활성 번들·검수기·사전 버전이 바뀐 뒤 1,000건 전수(R4-S6, Q-80 B6), 보존 기본 90일(D-C, R4-S4), 문제없는 묶음은 30일(R4-S5)이다. 쇼케이스는 100% 포착, 90일이다(계획:477·479·481, 승인대기:1101, `core/verification/evidence/VersionChangeCaptureSampling.java:14`, `:16`, `core/verification/evidence/SealedEvidencePackageAssembler.java:52`, `core/verification/inspection/PromptInspectionCleanPackageRetentionScheduler.java:37`).
- **이유**
  - 스트리밍 반출 판정 581건이 봉인되지 않았다(V-14, 계획:198).
  - 2차로 넘어간 판정은 프롬프트 원문은 1차 것, 판정·해시는 2차 것으로 봉인되고 2차 프롬프트가 버려졌다(W0-8, 계획:577).
  - 2026-10-13 실측 묶음 한 건 117.7KB 가운데 칸 합계의 84%가 읽지 않거나 중복이었다(계획:969).
- **영향**
  - 인증 지표 T2(봉인·재현 가능한 보호 판정) 목표는 100%다(계획:159). P6 관문에서 단계 기록 120/120, 실린 ID·검색 범위 120/120이었다(P6 검수:283·285).
  - P8 T2 판정: PASS. 모델 판정 441/441이 봉인됐다(측정 250, 묶음 191), 봉인 실패 사유 0

## ADR-43 프롬프트 검수기와 판 규칙 (2026-10-12 Q-77·Q-78, 2026-10-13 R1b)
- **결정**
  - 품질 보증은 문제를 고치는 장치가 아니라 프롬프트의 문제를 정확하게 짚어 내고 검수하는 장치다. 산출물은 발견(어느 블록·항목·사실 ID의 줄이, 어떤 봉인 원천과 비교해, 어떻게 틀렸는가)과 그 수·추세다. 프롬프트를 바꾸거나 판정을 막지 않는다(Q-78 원칙 승인대기:1013-1016, 재설계:8-14, 계획:71-72).
  - 형식은 12지표와 다르다. JSON 규칙 계약이 없고, 계약은 v20 사전이며 검사는 코드다(Q-77 결정 승인대기:999-1003, 재설계:29, 재설계:147-153).
  - 검사: `SEAL_INTEGRITY`, `BUNDLE_TRACE`, `DICTIONARY_CONTRACT`, `DECISION_FACT_MATCH`, `FACT_ACCURACY`, `UNKNOWN_DECLARED`, `PAST_RECORD_NOTATION`(재설계:157-165), 더한 것 `SAME_FACT`(R1b-8, 계획:427), `REASON_MATCH`(W4-8, 계획:539), `SOURCE_TRUTH`(W6-7, 계획:584). 코드: `core/verification/inspection/SealIntegrityCheck.java:36`, `UnknownDeclaredCheck.java:48`, `SourceTruthCheck.java:31`, `iam/admin/promptquality/inspection/BundleTraceCheck.java:24` 등.
  - 판정은 FAIL(불일치 하나라도), INCOMPLETE(불일치 없고 확인 불가 있음), PASS, NOT_APPLICABLE(v19 글), ERROR다. 확인할 수 없는 것은 사유와 함께 따로 두고 통과로 세지 않는다(재설계:12, 재설계:175-196, `core/verification/inspection/PromptInspectionVerdict.java:19-30`).
  - 판 규칙: 검수기는 번들에 묶지 않는다. 결과마다 검수기·사전·레이아웃 버전을 남기고, 검사가 찾는 것이 바뀌면 판(`prompt-inspector/N`)을 올린다(계획:120, 계획:256, 재설계:198-201). 판 올림과 이유는 한 곳에 적는다(R1b-7, `core/verification/inspection/PromptInspectorVersions.java:21-30`). 다른 번들의 사전으로 봉인된 묶음은 이 빌드의 사전으로 읽지 않는다(판 13·14, `PromptInspectorVersions.java:53`, `:55`).
  - 자동 검수는 판정과 떨어진 스케줄러가 하고 모델을 부르지 않는다(W6-3이 R2로 끝남, 계획:573, 승인대기:1020).
- **이유**
  - 공식 검사기는 실행 0회였고, 3,134건에 돌리면 인증 가능 13.0%, 6개 지표는 변별력 0, 판정 정답률과 관계가 없었다(계획:54).
  - 사용자 결정: 지표 코드 12개가 실질적 효용가치가 없으면 유지할 필요가 없다(Q-77, 승인대기:993).
- **영향**
  - 지금 판은 19다(N-SRC-1: UNKNOWN 줄이 밝힌 원천 사실을 결측 표기로 셈, `PromptInspectorVersions.java:67`, 계획:581).
  - 판을 올리면 옛 봉인을 다시 검수한다(P6 검수:258).
  - P8 W8-1 봉인 검수 결과(판, 표본, FAIL·INCOMPLETE 수): 검수기 판 20, 측정·묶음 봉인 441건 전수(미검수 0). INCOMPLETE 440(확인 불가 항목 있음), FAIL 1(실험실 변형 실행 run-9fb2fd58774d의 봉인, 측정 봉인 아님). 측정 봉인 250건은 어긋남 0

## ADR-44 옛 품질 보증 걷어 내기: 12지표 검사기·결정적 재생·점수표·결함 주입 (2026-10-12 Q-78, 2026-10-13 Q-83 확정, 2026-10-14 엔터프라이즈 이연)
- **결정**
  - 12지표 검사기 v20 이식(W3-15)을 보류하고(Q-77), 품질 보증을 전면 재설계한다. 반드시 필요하고 재사용이 유효한 것만 남기고, 호환을 위해 남기지 않는다(Q-78, 승인대기:1007-1009).
  - 검사기 계약 v1·v2는 만들지 않고 걷어 낸다(계획:73, 계획:120). 결정적 재생(v19 전용 재생·점수표)과 결함 주입 권한 모델도 걷어 낸다(계획:107).
  - 걷어 낼 범위는 재설계서 2.3·부록 A에 13절 보강을 더한 것이다. 계획 행 변경: W6-1·W6-2는 측정 하네스 지표, W6-4 행 삭제, 결정 D-A 거둠(Q-83, 승인대기:1095-1096, :1102).
  - 판정 경로의 검증 고리(결함 주입, 공식 보수, 합성 사용자·세션, 탐침 능력 머리글과 신뢰 이상 신호의 BLOCK 강제, 검증 모델 재정의 키, 자원 URL 재정의, 흔적 키)를 뺐다(R4-L1~L6, 계획:454-459).
  - 엔터프라이즈를 고치는 부분과 엔터프라이즈와 한 빌드여야 하는 걷어 내기(R4-C3~C10·R4-R 남은 부분, R4-I1~I4, R4-AC1·AC2, R4-DB1~DB3, R4-M, R4-E1~E7, R6-1)는 최종 구현 계획 뒤로 미룬다(v3.5 계획:13, P3-변경-84 P3 검수:3030).
- **이유**
  - 산출물은 발견이어야 한다. 품질 보증 안에서 고치는 역할(공식 결함 보수, 문제 → 조치 → 실행 중 규칙의 OSS 부분)은 목적 밖이다(승인대기:1017).
  - 사용자 결정 원문: "호환을 위해 남겨둘 필요까지 없다. contexa 는 OSS 이기 때문에 많은 사용자들에게 오픈되어 있다. 혼란스러운 코드와 기능을 남길 필요가 없다"(승인대기:1007).
- **영향**
  - 이연 동안 옛 코드가 트리에 남는다: `core/verification/replay/DeterministicReplayService.java:32`, `core/verification/adjudication/SealedEvidencePromptScorecard.java:24`, 계약 자원 `contexa-core/src/main/resources/pqa/final-prompt-metric-contracts.json`. 둘을 부르는 곳은 iam 옛 런타임 증거 서비스(`iam/admin/promptquality/official/application/DefaultRuntimeEvidenceReplayService.java:8`, `DefaultRuntimeEvidencePromptScorecardService.java:9`)와 자동 설정(`auto/iam/admin/PqaOfficialInspectionAutoConfiguration.java:354`)뿐이고, 판정 경로(`core/autonomous`)에는 없다(코드 검색). 이 둘은 R4-I1·R4-AC1과 함께 지운다(계획:450, :463, :467).
  - 엔터프라이즈 관리 DB 기동은 깨진 채 두고, 엔터프라이즈 본 소스 컴파일만 지킨다(계획:979).
  - 공개 규약의 '추가만, 기존 이름은 읽기 호환'(계획:968) 원칙에서 이 걷어 내기는 예외다. 지운 이름은 ADR-47 표 2에 적는다.
  - 이연한 걷어 내기의 시기와 결과: 최종 구현 계획 뒤 엔터프라이즈 단계로 이연한 그대로다(P3-변경-84). P8까지 하지 않았다

## ADR-45 최소 대응 규칙 (2026-10-10 Q-60, 2026-10-15 N-P3-1·Q-87, 2026-10-16 N-CONF-1)
- **결정**
  - 규칙은 P1 신원 신호 조합, P2 새 기기·네트워크의 반출, P3 규정 미충족, L1 학습 승격이다(Q-60 승인대기:663·692, 사전:349-355, 계획:747-752).
  - 규칙은 시스템 프롬프트에 사실 이름으로 쓰고, 응답 검사기가 같은 구조화 사실로 위반을 확인한다. 코드는 판정을 미리 정하지 않는다. MinimumAction 줄은 사용자 프롬프트에 넣지 않는다(계획:754, 계획:529, 원칙 3 계획:93-96).
  - 요구 대응: P1·P2는 CHALLENGE 이상, P3는 ESCALATE 이상이다. 본인 확인은 빠진 기록을 채우지 못한다(N-P3-1, Q-87 승인대기:1210, 계획:536, 계획:751). 대응은 약한 것부터 ALLOW < CHALLENGE < ESCALATE < BLOCK이고, 걸린 규칙의 요구 대응보다 약하면 위반이다(사전:359, `core/autonomous/context/decision/MinimumActionRules.java:42`, `:122-123`).
  - P3 요구 대응 설정은 CHALLENGE·ESCALATE만 받고, 그 밖의 값은 시작 오류다(N-CONF-1, P5 검수:703, `MinimumActionRules.java:77-89`, `core/properties/SecurityZeroTrustProperties.java:245-251`).
  - '설명됨'은 그 작업을 덮는 유효한 승인·티켓과 출장과 일치하는 네트워크뿐이다. 당번만으로는 설명이 아니고, 기준선이 없으면 차이는 '모름'이다(재검토 B2: 계획:759, 사전:357). P1은 설명 안 된 차이로 센다(P4-변경-6, P4 검수:868).
  - 집행 방식 기본은 관측(OBSERVE)이다. 기록과 실제 판정을 대조한 뒤 집행으로 바꾼다. 쇼케이스 D는 P4 관문 뒤 집행(ENFORCE)이다(계획:756, P4 검수:863, `SecurityZeroTrustProperties.java:224`).
- **이유**
  - 측정 기록에 대 보면 공격 반응 실행이 67/90에서 90/90이 되고, 정상 업무의 본인 확인은 늘지 않았다(계획:745).
  - P3를 CHALLENGE로 두면 본인 확인 성공이 승인을 대신했다(Q-87, 승인대기:1210).
  - BLOCK 요구는 응답 검사기의 결정적 근거 요구와 충돌해 늘 기술 대체가 되었다(N-CONF-1, 계획:560).
- **영향**
  - 인증 지표 A5(모델 자체 최소 대응 준수) 목표 95%(하한 90%)(계획:152). P6 관문 A5 51/51, 최소 대응 위반 0(P6 검수:274, :288).
  - 문서 정정 대상: 사전 6절 표의 P3 설정 칸 '(CHALLENGE·ESCALATE·BLOCK만, 그 밖의 값은 ESCALATE)'(사전:353)는 N-CONF-1 앞의 문구다.
  - P8 A5와 최소 대응 위반 수: A5 95/95(첫 판정 기준, 하한 96.1%). 응답 검사기의 MINIMUM_ACTION_VIOLATION 재시도 0, 최종 위반 0

## ADR-46 출력 계약 v3: 구조화 출력과 근거 코드 (2026-10-10 Q-57 결정 2·6, 2026-10-14 W4-2·W4-3)
- **결정**
  - 응답은 `action`, `reasonCodes`(1~5개, 코드와 사실 ID), `reason`(200자 이내)이다. 감사용 `riskScore`·`confidence`·`mitre`는 null을 허용하고 판정·검사에 쓰지 않는다(사전:264-291, 승인대기:677, `core/autonomous/tiered/prompt/SecurityDecisionOutputContract.java:33-39`).
  - 구조화 출력(JSON 스키마 strict)으로 강제한다. 지원하지 않는 제공자에게는 같은 스키마를 시스템 글 끝에 글로 두고, 형식 오류면 무엇이 틀렸는지 알려 한 번 재시도한다(Q-57 결정 6, 승인대기:668, 사전:289-292, `SecurityDecisionOutputContract.java:240`, `:252`).
  - 근거 코드는 53개이고 코드마다 인용할 사실과 유효 조건이 있다(사전:19, `SecurityDecisionOutputContract.java:63`). 응답 검사기와 검수기 `REASON_MATCH`는 같은 함수 `SecurityDecisionFactChecks.reasonFindings`로 본다(사전:298).
  - 고정 근거 문장 규칙과 코드의 근거 덮어쓰기를 없애고 근거 코드·사실 ID·모델 문장으로 대체한다(Q-57 결정 2, 승인대기:664, P4 검수:83·95).
  - 이 계약은 v20 번들에만 적용한다. 공급자에 보내는 스키마에는 `maxLength`를 빼고 200자는 응답 처리기가 지킨다(P4-변경-2, P4 검수:49·52). Anthropic 요청에서는 그 공급자가 받지 않는 키워드를 뺀다(P4 검수:68).
- **이유**
  - 출력 형식이 글로만 정해져 형식 오류 4건·재시도 171건이 났고(R4 지표 '지금', 계획:147), 근거의 97%가 고정 문장이었다(T1 지표 '지금', 계획:158).
- **영향**
  - 인증 지표 R4(형식 오류 0), T1(근거 코드와 사실 ID가 있는 판정 100%), C3(근거 코드와 사실의 일치 100%)(계획:147, 계획:155, 계획:158).
  - P8 R4·T1·C3 판정: R4 0건(파서 실패 0, 형식 사유 재시도 0. 의미 사유 재시도 REASON_CODE_MISMATCH 5는 값만 공개), T1 250/250, C3 641/641(근거 줄), 모두 PASS

## ADR-47 공개 규약 변경: 더한 이름과 읽기 호환 (2026-10-10~16, 계획 12절)
- **결정**
  - 공개 규약(공식 필드, 표준 필드)은 추가만 하고 기존 이름은 읽기 호환으로 둔다(계획:968).
  - 공식 필드 `actionFamily`·`resourceCategory`를 더하고, 접두 없는 힌트는 읽기 호환으로 둔다(재검토 결정 C, 승인대기:673, W2-11 계획:375).
  - 예외: 옛 품질 보증 코드는 호환 없이 걷어 낸다(ADR-44).
- **확인 방법**: 기준 커밋 `03026656`과 지금 작업 트리를 비교했다(`git diff 03026656`). 더한 시점은 계획 행과 검수 문서로 대조했다.
- **표 1. 더한 이름**

  | 이름 | 위치 | 더한 작업 | 읽기 호환 |
  |---|---|---|---|
  | `OfficialContextSlot.RESOURCE` | `common/security/context/OfficialContextSlot.java:25` | W2-11(P2 검수:964·979) | 기존 칸 그대로, 지운 칸 없음 |
  | `OfficialContextField.ACTION_FAMILY`(`actionFamily`) | `common/security/context/OfficialContextField.java:54` | W2-11(계획:375, P2 검수:32·964) | 읽을 때 `ctxa.context.actionFamily`를 먼저, 없으면 접두 없는 `actionFamily`를 읽는다(`OfficialContextField.java:81-94`) |
  | `OfficialContextField.RESOURCE_CATEGORY`(`resourceCategory`) | `OfficialContextField.java:56` | W2-11(같음) | 같음 |
  | `OfficialContextField.NETWORK_ZONE`(`networkZone`, LOCATION 칸) | `OfficialContextField.java:39` | W2-4(P2 검수:18·279·282) | 같음. 공식 필드 열거형과 칸 열거형에서 지운 값 없음(기준 커밋 대비 지워진 줄은 끝 값의 `;`를 `,`로 바꾼 줄뿐) |
  | `RequestSecurityContextAttributes.Field.RESOURCE_AUTHOR_TEXT`(`ctxa.context.resourceAuthorText`) | `common/security/context/RequestSecurityContextAttributes.java:42` | W2-6(P2 검수:20·325·328) | 접두 속성을 먼저, 없으면 접두 없는 별칭을 읽는다(`:68-77`). 지운 필드 없음 |
  | `RequestSecurityContextAttributes.Field.REQUEST_ITEMS`(`ctxa.context.requestItems`) | `RequestSecurityContextAttributes.java:44` | W2-6(P2 검수:20·324·328) | 같음 |
  | `@Protectable`의 `category`·`sensitivity`·`actions`·`privileged`·`exportSensitive` | `common/annotation/Protectable.java:82`, `:88`, `:94`, `:97`, `:100` | W2-11(P2 검수:32·979) | 기본값은 모두 '선언 없음'이다. 기존 속성 `ownerField`·`verificationRequired`·`sync`는 그대로다(`:48`, `:59`, `:75`). 기준 커밋 대비 추가 25줄, 삭제 0줄 |
  | 표준 컨텍스트 최상위: `dataConflicts`, `requestObservedAt`, `decisionFacts` | `core/autonomous/context/CanonicalSecurityContext.java:88`, `:94`, `:97` | W1-14(P1 검수:27), W2-5(P2 검수:19) | 이 파일은 기준 커밋 대비 추가 297줄, 삭제 0줄이다 |
  | `Session.authenticationTime`·`challengeVerifiedAt`·`recentMfaElsewhereAt` | `CanonicalSecurityContext.java:131`, `:136`, `:138` | W1-4(계획:335, P1 검수:208), W1-5(P1 검수:305·308) | 같음 |
  | `Actor.accountCreatedAt` | `CanonicalSecurityContext.java:113` | W1-10(P1 검수:694) | 같음 |
  | `Location.networkZone`, `Location.movement`와 `Movement` | `CanonicalSecurityContext.java:196`, `:198`, `:209` | W2-4(P2 검수:18), W2-13(계획:377, P2 검수:34) | 같음 |
  | `Resource.authorText`·`requestedItems`·`resourceClass`·`resourceCategory`·`pathFamily`·`actionFamilySource` | `CanonicalSecurityContext.java:229`, `:231`, `:237`, `:242`, `:245`, `:249` | W2-6(P2 검수:20), W2-10(P2 검수:31), W2-2(P2 검수:16), W2-1(P2 검수:91) | 같음 |
  | `SessionNarrativeProfile.sessionDecisionHistory`·`sessionDecisions` | `CanonicalSecurityContext.java:381`, `:384` | W1-11 세션 판정 이력(P1 검수:24·755). `sessionDecisions`를 더한 행은 대조하지 못했다(2026-10-11 커밋 `0305f038`에는 있음) | 같음 |
  | `SessionNarrativeProfile.sessionDeviceChange`·`sessionNetworkChange` | `CanonicalSecurityContext.java:394`, `:396` | W2-14(P2 검수:35) | 같음 |
  | `WorkProfile.baselineView` | `CanonicalSecurityContext.java:426` | W2-3·P2-보정-9(P2 검수:17·38) | 같음 |
  | `FrictionProfile`의 구조화 기록(승인·티켓·당번·출장·담당·접근 이력·회사 규정)과 `checkedRecordKinds` | `CanonicalSecurityContext.java:521-539`, `:548-670` | W2-6(P2 검수:20), P2-보정-3(P2 검수:25) | 같음 |
  | 그 밖의 표준 필드: `failedLoginWindowMinutes`, `untrustedAnomalySignalClaim`, `methodExecutionOutcome`·`methodExecutionFailure`, `decisionTime`·`privilegedAuthoritySignals`, 위임 `expiresAt`, 브리지 `evidenceStates`, `sessionAgeBasis`, `userRequestsLastHour`, 거부 범위 비교 칸 셋, `peerCount` | `CanonicalSecurityContext.java:141`, `:183`, `:272`, `:274`, `:276`, `:279`, `:302`, `:325`, `:370`, `:389`, `:458-462`, `:464` | W3-12(P3 검수:992), W1-1(P1 검수:47), W1-6(P1 검수:396·410), W1-14(P1 검수:900-902), W1-10(P1 검수:688), W5-10(P5 검수:420·510) | 같음 |
  | `SecurityEvent.getLocalTimestamp()` | `common/domain/SecurityEvent.java:66` | W1-7(P1 검수:20) | 새 메서드. `timestamp` 타입 변경은 표 2 |
  | 브리지 `amrKeys`(기본 `amr`), 클레임 목록의 `challengeVerifiedAt` | `common/security/bridge/BridgeProperties.java:83`, `:87` | W1-4(계획:335, P1 검수:17), W1-5(P1 검수:322) | 새 키와 기존 목록에 더한 값 |
  | 설정 `contexa.security.tiered.prompt-bundle.active`·`.selector`·`.shadow.*` | `core/properties/TieredStrategyProperties.java:52`, `:55`, `:58` | W3-16(P3-변경-22), W6-9(P6-변경-6) | 새 접두사(기준 커밋에 없음) |
  | 설정 `contexa.security.tiered.prompt-runtime.budget-enforcement` | `TieredStrategyProperties.java:105` | W3-7(계획:397, P3-변경-6) | 새 속성 |
  | 설정 `contexa.security.zerotrust.minimum-action.*`, `contexa.security.zerotrust.baseline.promotion.*` | `core/properties/SecurityZeroTrustProperties.java:94`, `:140` | W4-4·N-P3-1(사전:349-355), W5-1(사전:355) | 새 접두사(기준 커밋에 없음) |
  | 설정 `contexa.prompt.governance.enabled` | `auto/iam/admin/PromptGovernanceAutoConfiguration.java:64` | W1-20(c), 결정 11(버전관리:501) | 새 속성, 기본 켬 |
  | 설정 `contexa.prompt-inspection.*` | `auto/iam/admin/PromptInspectionProperties.java:12` | W3-15R R2(승인대기:1032) | 새 접두사 |
  | 설정 `contexa.pqa.oss.sealed-evidence.sample-percent`·`.full-capture-after-change`·`.retention.period`·`.retention.clean-period` | `auto/iam/admin/PqaOssSealedEvidenceCaptureProperties.java:28`, `:31`, `:97`, `:99` | R4-S6·R4-S4·R4-S5(계획:477·479·481) | 기존 접두사에 더함. 이 파일은 기준 커밋 대비 삭제 0줄 |

- **표 2. 바꾸거나 지운 이름(읽기 호환이 아님)**

  | 이름 | 전(기준 커밋) | 지금 | 근거 | 호환 |
  |---|---|---|---|---|
  | `SecurityEvent.timestamp` | `LocalDateTime` | `Instant`(`common/domain/SecurityEvent.java:45`, Lombok `@Data` `:31`) | W1-7 '이벤트 시각을 `Instant`로'(계획:338, P1 검수:20) | `getTimestamp()` 반환 타입이 바뀌어 소스·바이너리 호환이 아니다. 엔터프라이즈 4곳을 함께 고쳤다(P1-변경-6 ⑥, P1 검수:1426). 벽시계 값은 `getLocalTimestamp()`로 읽는다 |
  | 브리지 인증 시각 키 기본값 `contexa.bridge.authentication.security-context.auth-time-keys` | `issuedAt`·`iat` 포함 | 둘을 뺌(`BridgeProperties.java:82`) | W1-4 '`iat`는 인증 시각으로 쓰지 않는다'(계획:335) | 기본값 변경. 키 이름은 그대로이고 호스트가 설정으로 다시 넣을 수 있다 |
  | 이벤트 메타데이터 별칭 `requestRateMultiplier`(최근 요청 수) | 기준 커밋 `DefaultCanonicalSecurityContextProvider.java:611`이 읽음 | 읽지 않음(`core/autonomous/context/DefaultCanonicalSecurityContextProvider.java:653`) | W2-9 '`requestRateMultiplier` 별칭을 없앤다'(계획:373, P2 검수:30) | 지운 별칭 |
  | 위임 승인의 이벤트 메타데이터 키 | `approvalRequired`(업무 승인과 같은 키) | `delegationApprovalRequired`(`core/autonomous/event/publisher/ZeroTrustEventPublisher.java:606`, 읽기 `DefaultCanonicalSecurityContextProvider.java:857-858`). 업무 승인은 `approvalRequired`만(`ZeroTrustEventPublisher.java:639`) | W2-9 키 분리(S-3, 계획:373, P2 검수:30) | 이벤트 메타데이터 키를 나눔. 브리지 위임 해석이 호스트에서 읽는 키 이름(`approvalRequired`, `requiresApproval`)은 그대로다(`BridgeProperties.java:167`) |
  | 설정 `contexa.security.tiered.prompt-runtime.lineage-capture-mode` | 기준 커밋 `TieredStrategyProperties.java:65` | 없음 | R4-C11 검증 계보 모드 걷어 냄(계획:453) | 지운 설정(ADR-44 예외) |
  | SPI `PromptEvidenceMetadataProvider`(코어 `verification/capture`) | 기준 커밋에 있음(공개 인터페이스) | 파일 삭제 | R4-C1b 메타 공급자 SPI 걷어 냄(계획:442) | 지운 SPI(ADR-44 예외) |
  | 판정 경로의 검증 키: 메타 `pqaReferencePrompt`, 신뢰 이상 신호 BLOCK 강제 `applyTrustedConfirmedMaliciousConstraint` 등 | 기준 커밋 `SecurityDecisionPromptSections.java:765`, `AbstractTieredStrategy.java:1827` | 본 코드에 없음 | R4-L1·R4-L2·R4-L6(계획:454-455, :459) | 지운 이름(ADR-44 예외). 이연한 옛 실행기에는 일부 키가 남아 있다(예: `core/verification/runtime/OfficialVerificationRuntimeEvidenceSupport.java:73`) |
  | 설정 `contexa.security.tiered.prompt-runtime.user-prompt-format` | 기준 커밋에 없음 | 없음 | W3-2에서 두고 W3-16 선택기로 대신해 지움(버전관리:528) | 계획 안에서 생기고 없어져 기존 이름이 아니다 |

- **영향**
  - 공식 필드·요청 속성·`@Protectable`·표준 컨텍스트에서는 기존 이름을 지우거나 바꾸지 않았다(표 1. 요청 속성·`@Protectable`·표준 컨텍스트는 기준 커밋 대비 삭제 줄 0, 공식 필드 두 열거형은 끝 값의 `;` → `,` 바꿈만).
  - 표 2의 앞 넷은 계획 행이 정한 정정이다(W1-4, W1-7, W2-9). 원칙 '추가만'(계획:968)과 달라 이 ADR에 남긴다. 그다음 셋은 ADR-44의 예외이고, 마지막 하나는 기존 이름이 아니다.
  - contexa-docs의 공개 규약 문서 반영(W8-4): P8 단계 끝에 반영했다(대상 13개, `p8/docs/p8_docs.py`, P8-변경-35)
