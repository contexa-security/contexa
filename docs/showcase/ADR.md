# Contexa Showcase 결정 기록 (ADR)

- 작성일: 2026-10-04
- 문서 상태: P0에서 작성. 결정을 바꾸면 새 항목을 추가하고, 이전 항목에는 '대체됨'을 표시한다.
- 근거 표기: `파일:줄`. 경로 약어는 다음과 같다.
  - core = `contexa-core/src/main/java/io/contexa/contexacore`
  - auto = `contexa-autoconfigure/src/main/java/io/contexa/autoconfigure`
  - common = `contexa-common/src/main/java/io/contexa/contexacommon`
  - identity = `contexa-identity/src/main/java/io/contexa/contexaidentity`

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
