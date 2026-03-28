# 2026-03-28 v1.0 - Cortex 실전 리허설 테스트 절차서

## 1. 문서 성격

이 문서는 단위 테스트나 고정 fixture 기반 시뮬레이션 문서가 아니다.
이 문서는 `bridge_example` 고객 애플리케이션, `localhost:10000` SaaS, 실제 브라우저 요청, 실제 세션 재사용, 실제 보호 리소스 접근, 실제 SaaS ingest와 pull-back 경로를 기준으로 Contexa Cortex의 전 과정을 리허설하는 절차서다.

이 문서의 목표는 하나다.

- 정상 사용자는 업무를 계속 수행할 수 있어야 한다.
- 정상 사용자의 세션을 탈취한 공격자는 민감 요청 시 plain `200 OK`로 통과하면 안 된다.
- 브릿지, 컨텍스트, 축약, 표준 프롬프트, LLM 추론, 판정, SaaS ingest, SaaS 학습 결과 재공급까지 모든 과정이 코드 기준으로 끊김 없이 이어져야 한다.
- 결과는 로그 감상 수준이 아니라, 브라우저 응답, 서버 로그, DB 기록, SaaS API 기록, 재공급된 신호까지 증거로 남아야 한다.

## 2. 금지 사항

이번 리허설에서는 아래를 금지한다.

- 임의 fixture 데이터로 정상 사용자와 공격자를 만들어 결과를 조작하는 것
- LLM 판정 결과를 수동으로 삽입하는 것
- SaaS 응답을 하드코딩된 stub로 대체해 성공처럼 보이게 하는 것
- "원래 BLOCK이 나와야 한다"는 기대만 쓰고 실제 응답 코드와 DB 기록을 확인하지 않는 것
- 컨텍스트 축약이 잘 되었는지 확인하지 않고 결과만 보는 것

허용되는 것은 실제 제품 직전 환경에서의 설정과 배포뿐이다.

- 로컬 포트만 다를 수 있다.
- 브라우저는 실제 브라우저를 사용한다.
- 서버는 실제 Spring Boot 앱을 띄운다.
- 세션 탈취는 실제 `JSESSIONID` 재사용으로 재현한다.

## 3. 최상위 합격 기준

이번 리허설의 최상위 합격 기준은 다음 네 가지를 동시에 만족하는 것이다.

1. 정상 사용자가 `GET /api/customers/export`를 호출할 때 보호 흐름이 과도하게 방해하지 않고 정상 응답을 낸다.
2. 같은 정상 사용자의 세션을 다른 브라우저 또는 다른 User-Agent로 재사용해 `GET /api/customers/export`를 호출했을 때 plain `200 OK`가 나오지 않는다.
3. 해당 요청에 대한 브릿지 해석, canonical context, prompt metadata, omission/completeness, LLM 판정, enforcement 결과가 모두 추적 가능하게 남는다.
4. 고객 앱이 SaaS로 decision/prompt context audit/threat related signal을 보내고, SaaS가 이를 적재하며, SaaS에서 다시 baseline seed / threat intelligence / threat knowledge / runtime policy가 고객으로 재공급되는 루프가 확인된다.

## 4. 이 문서에서 확인하는 표준 기준

### 4.1 NIST/ISO 기준

이번 리허설은 아래를 확인한다.

- 프롬프트가 단순 문자열이 아니라 버전, 해시, completeness, omitted sections를 가진 관리 대상인지
- 실행된 프롬프트가 나중에 registry/reconciliation에서 추적 가능한지
- prompt telemetry가 SaaS에 전달되어 audit 가능한지

### 4.2 OWASP 기준

이번 리허설은 아래를 확인한다.

- retrieved context와 bridge context가 명령이 아니라 evidence로 취급되는지
- 컨텍스트가 누락되거나 차단된 경우 그대로 audit payload에 남는지
- 민감 요청에서 동기식 판정이 작동해 hijacked session을 그대로 통과시키지 않는지

### 4.3 벤더 공통 기준

이번 리허설은 아래를 확인한다.

- system/user prompt 구조가 유지되는지
- context가 원본 의미를 보존한 채 축약되어 prompt에 실리는지
- prompt metadata와 hashes가 생성되는지
- LLM 결과가 downstream에 구조화된 payload로 전달되는지

## 5. 테스트 토폴로지

### 5.1 고객 앱

- 애플리케이션: `D:/bridge_example`
- 메인 클래스: [BridgeExampleApplication.java](D:/bridge_example/src/main/java/io/contexa/bridge_example/BridgeExampleApplication.java)
- 포트: `9090`
- 설정 파일: [application.yml](D:/bridge_example/src/main/resources/application.yml)

### 5.2 SaaS 앱

- 엔터프라이즈 애플리케이션 저장소: `D:/contexa-enterprise`
- SaaS 런타임 API 컨트롤러: `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/api/SaasRuntimeApiController.java`
- 이번 리허설 기준 포트: `10000`
- 중요: 현재 소스에는 SaaS 앱 포트가 `10000`으로 고정되어 있지 않다. 반드시 기동 시 `--server.port=10000`을 명시해야 한다.

### 5.3 OAuth2 토큰 엔드포인트

- 소스 기준 기본 토큰 엔드포인트: [IdentityOAuth2AutoConfiguration.java](D:/contexa/contexa-autoconfigure/src/main/java/io/contexa/autoconfigure/identity/IdentityOAuth2AutoConfiguration.java)
- token endpoint: `/oauth2/token`
- 따라서 이번 로컬 SaaS의 현실적 token URI는 `http://localhost:10000/oauth2/token`이다.

## 6. 코드 기준 핵심 경로 맵

### 6.1 고객 브릿지와 로그인

- 로그인 필터: [LegacyAuthFilter.java](D:/bridge_example/src/main/java/io/contexa/bridge_example/legacy/filter/LegacyAuthFilter.java)
- 보호 API: [ProtectedCustomerController.java](D:/bridge_example/src/main/java/io/contexa/bridge_example/controller/ProtectedCustomerController.java)
- 실제 테스트 계정 제공자: `D:/bridge_example/src/main/java/io/contexa/bridge_example/legacy/service/LegacyUserService.java`
- 로그인 화면: `D:/bridge_example/src/main/resources/templates/legacy-login.html`
- 대시보드: `D:/bridge_example/src/main/resources/templates/legacy-dashboard.html`

### 6.2 동기식 보호 판정 경로

- 메서드 인터셉터: [AuthorizationManagerMethodInterceptor.java](D:/contexa/contexa-iam/src/main/java/io/contexa/contexaiam/security/xacml/pep/AuthorizationManagerMethodInterceptor.java)
- 거부 예외: [ZeroTrustAccessDeniedException.java](D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/execution/ZeroTrustAccessDeniedException.java)

핵심 사실:

- `@Protectable(sync = true)` 경로는 요청 중간에 즉시 판정된다.
- `BLOCK`이면 `403`
- `CHALLENGE`이면 `401`
- `ESCALATE`이면 `423`
- pending/timeout 계열은 상황에 따라 `408` 또는 action status가 나온다.

### 6.3 세션 탈취 재현 근거

- context binding hash 유틸: [SessionFingerprintUtil.java](D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/utils/SessionFingerprintUtil.java)

핵심 사실:

- context binding hash는 `sessionId + ip + userAgent` 조합으로 생성된다.
- 따라서 같은 `JSESSIONID`를 다른 브라우저 또는 다른 User-Agent로 재사용하면 같은 세션이라도 다른 context binding으로 들어간다.
- 이것이 이번 세션 탈취 리허설의 현실적 재현 방식이다.

### 6.4 브릿지와 이벤트 payload

- 요청 추출기: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/utils/RequestInfoExtractor.java`
- 이벤트 발행기: [ZeroTrustEventPublisher.java](D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/event/publisher/ZeroTrustEventPublisher.java)
- 관련 테스트: `D:/contexa/contexa-core/src/test/java/io/contexa/contexacore/autonomous/event/publisher/ZeroTrustEventPublisherTest.java`
- 대표 테스트 메서드: `shouldIncludeBridgeMetadataInAuthorizationEventPayload`

### 6.5 컨텍스트 조립과 의미 보존 축약

- canonical provider: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/context/DefaultCanonicalSecurityContextProvider.java`
- prompt context composer: [PromptContextComposer.java](D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/context/PromptContextComposer.java)
- prompt sections / omission / completeness: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/tiered/template/SecurityDecisionPromptSections.java`
- prompt execution metadata: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/std/components/prompt/PromptExecutionMetadata.java`

### 6.6 SaaS forwarding과 prompt context audit

- decision payload mapper: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/mapper/SecurityDecisionForwardingPayloadMapper.java`
- prompt context audit mapper: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/mapper/PromptContextAuditPayloadMapper.java`
- forwarding handler: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/handler/handler/SaasForwardingHandler.java`

### 6.7 SaaS ingest와 모니터링

- runtime API controller: `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/api/SaasRuntimeApiController.java`
- decision ingestion: `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/runtime/SecurityDecisionIngestionService.java`
- prompt context audit ingestion: `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/prompt/PromptContextAuditIngestionService.java`

### 6.8 SaaS에서 다시 고객으로 돌아오는 루프

- baseline seed scheduler: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasBaselineSeedPullScheduler.java`
- threat signal scheduler: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatSignalPullScheduler.java`
- threat knowledge pack scheduler: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatKnowledgePackPullScheduler.java`
- threat runtime policy scheduler: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatKnowledgeRuntimePolicyPullScheduler.java`
- baseline seed service: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasBaselineSeedService.java`
- threat intelligence service: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatIntelligenceService.java`
- threat knowledge pack service: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatKnowledgePackService.java`
- threat runtime policy service: `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatKnowledgeRuntimePolicyService.java`

중요:

- 현재 소스가 제공하는 것은 `실시간 SaaS hot-path 제어`가 아니라 `scheduler 기반 pull + local cache + runtime use`이다.
- 따라서 이번 리허설은 SaaS가 현재 요청을 실시간으로 가로채는지 테스트하는 것이 아니라, 고객 앱이 SaaS 학습 결과를 주기적 pull 뒤 실제 판정에 반영하는지 확인하는 것이다.

## 7. 사전 게이트

이번 리허설은 아래 사전 게이트를 통과해야만 시작할 수 있다.

### 7.1 bridge_example 사전 코드 확인

확인할 테스트:

- [BridgeExampleApplicationTests.java](D:/bridge_example/src/test/java/io/contexa/bridge_example/BridgeExampleApplicationTests.java)
  - `applicationShouldDeclareSandboxAiSecurity`
  - `legacyAuthenticationShouldInvokeExplicitContexaHandoff`

의미:

- 고객 앱이 `@EnableAISecurity(mode = SecurityMode.SANDBOX)`로 뜨는지
- `LegacyAuthFilter`가 실제로 `ContexaAuthBridge.handoff(...)`를 호출하는지

실행:

```powershell
cd D:\bridge_example
./gradlew test --tests io.contexa.bridge_example.BridgeExampleApplicationTests --warning-mode all --no-daemon
```

합격:

- 두 테스트가 모두 green

불합격 의미:

- 고객 앱 로그인 후 브릿지 handoff가 실제로 발생하지 않을 수 있다.
- 이 상태에서는 이후 전 과정 리허설을 시작하면 안 된다.

### 7.2 bridge_example SaaS 연동 설정 확인

현재 [application.yml](D:/bridge_example/src/main/resources/application.yml)에는 `contexa.saas.*` 설정이 없다.
따라서 리허설 전에 반드시 bridge_example에 SaaS forwarding 설정을 추가해야 한다.

필수 항목은 [SaasForwardingProperties.java](D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/properties/SaasForwardingProperties.java) 의 `validate()` 기준으로 맞춘다.

필수 최소 항목:

- `contexa.saas.enabled=true`
- `contexa.saas.endpoint=http://localhost:10000`
- `contexa.saas.pseudonymization-secret=<실제 값>`
- `contexa.saas.global-correlation-secret=<실제 값>`
- `contexa.saas.oauth2.enabled=true`
- `contexa.saas.oauth2.registration-id=<실제 값>`
- `contexa.saas.oauth2.token-uri=http://localhost:10000/oauth2/token`
- `contexa.saas.oauth2.client-id=<실제 값>`
- `contexa.saas.oauth2.client-secret=<실제 값>`
- OAuth2 scope에 최소 `saas.xai.decision.ingest` 포함

이번 리허설에서 추가로 켜야 하는 feature flags:

- `decision-feedback`
- `baseline-signal`
- `threat-intelligence`
- `threat-outcome`
- `threat-knowledge`
- `performance-telemetry`
- `prompt-context-audit`

합격:

- 고객 앱 기동 시 SaaS forwarding properties validation 예외가 없다.

불합격 의미:

- decision, audit, baseline, threat 관련 어느 단계도 실제 SaaS로 연결되지 않는다.

### 7.3 SaaS 앱 기동 조건 확인

SaaS 앱은 반드시 `localhost:10000`으로 띄운다.
현재 소스에 고정 포트가 없으므로 반드시 기동 시 지정한다.

예:

```powershell
cd D:\contexa-enterprise
./gradlew :contexa-iam-enterprise:bootRun --args="--server.port=10000" --warning-mode all --no-daemon
```

또는 실제 실행 메인 클래스를 사용하는 방식으로 동일 포트를 맞춘다.

합격:

- `http://localhost:10000`에서 SaaS 앱이 기동
- OAuth2 token endpoint가 `http://localhost:10000/oauth2/token`로 살아 있음

## 8. 실전 리허설 절차

## 8.1 T-01 정상 사용자 로그인과 baseline warm-up

### 성격

- 실환경 브라우저 테스트
- 고객 앱 런타임 테스트

### 목적

- 정상 사용자가 브릿지 handoff와 보호 흐름을 거쳐 정상적으로 진입하는지 확인한다.
- 이후 hijack와 비교할 정상 baseline을 만든다.

### 대상 소스

- [LegacyAuthFilter.java](D:/bridge_example/src/main/java/io/contexa/bridge_example/legacy/filter/LegacyAuthFilter.java)
- [ProtectedCustomerController.java](D:/bridge_example/src/main/java/io/contexa/bridge_example/controller/ProtectedCustomerController.java)

### 테스트 계정

실제 로그인 화면과 서비스 정의를 기준으로 아래 계정 중 하나를 사용한다.

- `kim_manager / manager123`
- `lee_analyst / analyst123`

권장:

- 민감 export까지 자연스럽게 이어가기 위해 `kim_manager / manager123`

### 수행 절차

1. 브라우저 A를 새 프로필로 연다.
2. `http://localhost:9090/legacy/login` 접속
3. `kim_manager / manager123` 로그인
4. 대시보드 진입 확인
5. 대시보드에서 고객 목록 버튼 또는 `GET /api/customers`를 3회 정도 호출
6. 이어서 `GET /api/customers/export`를 1회 호출

### 기대 결과

- 로그인 성공
- 고객 목록이 정상 조회됨
- export 요청이 plain `200 OK`로 허용될 가능성이 높음

### 관찰 포인트

- 브라우저 Network 탭
- 고객 앱 로그
- `JSESSIONID` 값
- `User-Agent`

### 합격 기준

- 정상 사용자의 baseline path가 실제로 동작한다.
- 민감 export 이전까지 브릿지와 protectable path가 살아 있다.

### 실패 의미

- 정상 사용자가 애초에 제품 경로를 타지 못하면 hijack 검증도 무의미하다.

## 8.2 T-02 정상 사용자 보호 결과 추적

### 성격

- 서버 관찰 테스트
- 컨텍스트/프롬프트 추적성 검증

### 목적

- 정상 요청이 들어왔을 때 브릿지, canonical context, prompt metadata가 실제로 생성되는지 확인한다.

### 대상 소스

- [ZeroTrustEventPublisher.java](D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/event/publisher/ZeroTrustEventPublisher.java)
- [PromptContextComposer.java](D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/context/PromptContextComposer.java)
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/std/components/prompt/PromptExecutionMetadata.java`

### 관련 테스트 소스

- `D:/contexa/contexa-core/src/test/java/io/contexa/contexacore/autonomous/event/publisher/ZeroTrustEventPublisherTest.java`
  - `shouldIncludeBridgeMetadataInAuthorizationEventPayload`
- `D:/contexa/contexa-core/src/test/java/io/contexa/contexacore/autonomous/context/PromptContextComposerTest.java`
  - `composeShouldRenderCoverageIdentityResourceAndDelegationSections`
- `D:/contexa/contexa-core/src/test/java/io/contexa/contexacore/std/components/prompt/PromptGeneratorTest.java`
  - `generatePromptShouldAttachGovernanceMetadata`
- `D:/contexa/contexa-core/src/test/java/io/contexa/contexacore/autonomous/tiered/prompt/SecurityDecisionStandardPromptTemplateTest.java`
  - `generatePromptShouldUseGovernedStandardTemplate`

### 런타임 확인 항목

확인해야 할 값:

- `bridgeCoverageLevel`
- `bridgeCoverageSummary`
- `bridgeAuthenticationSource`
- `requestPath`
- `httpMethod`
- `authenticationAssurance`
- prompt `promptKey`
- prompt `promptVersion`
- prompt `promptHash`
- `omittedSections`
- `promptEvidenceCompleteness`

### 합격 기준

- 정상 요청에 대해 bridge metadata와 prompt metadata가 실제로 생성된다.
- omitted sections가 있다면 그대로 남고, 없다면 빈 상태로 명확히 보인다.

### 실패 의미

- 이후 SaaS로 보내는 payload와 governance comparison의 근거가 붕괴된다.

## 8.3 T-03 세션 탈취 재현

### 성격

- 실환경 공격 재현 테스트
- 브라우저 기반 session hijack 재현

### 목적

- 정상 사용자의 세션만 복제해도 보호 자원이 그대로 열리는지, 아니면 context-binding 차이로 재분석이 일어나는지 확인한다.

### 대상 소스

- [SessionFingerprintUtil.java](D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/utils/SessionFingerprintUtil.java)
- [ProtectedCustomerController.java](D:/bridge_example/src/main/java/io/contexa/bridge_example/controller/ProtectedCustomerController.java)

### 수행 절차

1. T-01에서 로그인한 브라우저 A의 `JSESSIONID`를 확인한다.
2. 브라우저 B를 다른 브라우저 또는 다른 프로필로 연다.
3. 브라우저 B의 User-Agent가 브라우저 A와 다르다는 것을 확인한다.
4. 브라우저 B에 브라우저 A의 `JSESSIONID`를 주입한다.
5. 브라우저 B에서 바로 `GET /api/customers/export`를 호출한다.

권장 방식:

- 실제 브라우저 개발자 도구로 cookie를 주입한다.
- 또는 curl/Postman을 사용하되 반드시 브라우저 A와 다른 `User-Agent`를 쓴다.

예시:

```powershell
curl -i "http://localhost:9090/api/customers/export" -H "Cookie: JSESSIONID=<복제한값>" -H "User-Agent: Attack-Browser/1.0"
```

### 기대 결과

코드 기준으로 보장되는 것은 아래다.

- 같은 세션이라도 다른 User-Agent이면 다른 context binding hash가 만들어질 수 있다.
- `@Protectable(sync = true)`인 `/api/customers/export`는 즉시 판정 경로를 탄다.
- 따라서 hijacked export는 plain `200 OK`가 아니어야 한다.

강한 합격:

- `401 CHALLENGE`
- 또는 `403 BLOCK`

조건부 합격:

- `423 ESCALATE`
- 또는 pending analysis 계열 응답

실패:

- hijacked export가 plain `200 OK`

### 실패 의미

- 기존 세션 기반 보안이 못 넘는 산을 Cortex가 넘지 못한 것이다.
- 이번 리허설의 핵심 실패다.

## 8.4 T-04 민감 요청 동기 판정 확인

### 성격

- enforcement 검증

### 목적

- `/api/customers/export`가 실제로 synchronous protectable path를 타는지 확인한다.

### 대상 소스

- [ProtectedCustomerController.java](D:/bridge_example/src/main/java/io/contexa/bridge_example/controller/ProtectedCustomerController.java)
- [AuthorizationManagerMethodInterceptor.java](D:/contexa/contexa-iam/src/main/java/io/contexa/contexaiam/security/xacml/pep/AuthorizationManagerMethodInterceptor.java)
- [ZeroTrustAccessDeniedException.java](D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/execution/ZeroTrustAccessDeniedException.java)

### 확인 포인트

- `/api/customers/export`는 `@Protectable(sync = true)`
- hijacked request에서 `401/403/423/408` 중 하나가 나오는지
- controller body가 실행되기 전에 판정이 발생하는지

### 합격 기준

- 민감 export가 동기 보호를 거친다.
- hijacked request가 controller plain success로 빠지지 않는다.

## 8.5 T-05 컨텍스트 원본 의미 보존과 축약 검증

### 성격

- 품질 검증
- 원본 의미 보존 검증

### 목적

- LLM에 전달된 컨텍스트가 원본을 훼손하지 않으면서도 prompt window에 맞게 요약되었는지 확인한다.

### 대상 소스

- [PromptContextComposer.java](D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/context/PromptContextComposer.java)
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/tiered/template/SecurityDecisionPromptSections.java`
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/std/components/prompt/PromptExecutionMetadata.java`
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/mapper/PromptContextAuditPayloadMapper.java`

### 관련 테스트 소스

- `D:/contexa/contexa-core/src/test/java/io/contexa/contexacore/autonomous/saas/mapper/PromptContextAuditPayloadMapperTest.java`
  - `mapBuildsAuditPayloadFromAuthorizedPromptContext`
  - `mapIncludesAllowedAndDeniedContextItemsWithoutCollapsingThem`
  - `mapUsesContextFingerprintInAuditId`
  - `mapNormalizesDeniedReasonOrderForStableFingerprint`

### 런타임 확인 절차

1. 정상 export 1회, hijacked export 1회를 수행한다.
2. 고객 앱 로그 또는 SaaS audit ingest payload에서 아래를 확인한다.
   - 포함된 context item
   - denied context item
   - provenance
   - purpose
   - authorization
   - prompt safety
   - omitted sections
   - completeness
3. 원본 사실이 사라지지 않았는지 수동 검토한다.

핵심 질문:

- bridge에서 수집한 인증/권한/위임 사실이 사라졌는가
- denied item이 allowed item으로 뭉개졌는가
- omission이 숨겨졌는가
- LLM이 읽을 수 있는 section 이름과 의미가 유지되는가

### 합격 기준

- allowed와 denied가 섞여 지워지지 않는다.
- provenance가 남는다.
- omission/completeness가 보인다.
- 축약 후에도 session hijack의 핵심 의미가 사라지지 않는다.

### 실패 의미

- LLM이 잘못 판단해도 원인을 추적할 수 없게 된다.

## 8.6 T-06 SaaS ingest 실전 검증

### 성격

- 고객 -> SaaS 통합 검증

### 목적

- 고객 앱이 decision, prompt context audit, baseline signal, threat outcome을 실제로 SaaS로 보내고, SaaS가 이를 받는지 확인한다.

### 대상 소스

- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/mapper/SecurityDecisionForwardingPayloadMapper.java`
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/handler/handler/SaasForwardingHandler.java`
- `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/api/SaasRuntimeApiController.java`
- `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/runtime/SecurityDecisionIngestionService.java`
- `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/prompt/PromptContextAuditIngestionService.java`

### 관련 테스트 소스

- `D:/contexa-enterprise/contexa-core-enterprise/src/test/java/io/contexa/contexacoreenterprise/operations/SaasRuntimeApiControllerTest.java`
  - `xaiDecisionIngestionReturnsAcceptedReceipt`
  - `promptContextAuditIngestionReturnsAcceptedReceipt`
  - `baselineSeedUsesRuntimeBindingTenant`
  - `threatSignalsUsesRuntimeBindingTenant`
  - `threatOutcomeIngestionReturnsAcceptedReceipt`
  - `threatKnowledgePackUsesRuntimeBindingTenant`
  - `threatRuntimePolicyUsesRuntimeBindingTenant`

### 런타임 확인 절차

1. hijacked export 요청이 발생한 뒤 SaaS 로그를 확인한다.
2. decision ingest endpoint hit 여부를 확인한다.
3. prompt context audit ingest endpoint hit 여부를 확인한다.
4. 필요 시 DB에서 아래 테이블을 조회한다.

대상 테이블:

- `security_decision_ingestion_records`
- `prompt_context_audit`
- `xai_analysis_reports`
- `prompt_governance_registry`
- `prompt_governance_eval_ledger`
- `prompt_governance_release_ledger`
- `prompt_governance_rollback_ledger`

예시 질의:

```sql
select * from security_decision_ingestion_records order by created_at desc;
select * from prompt_context_audit order by created_at desc;
select * from xai_analysis_reports order by created_at desc;
```

### 합격 기준

- 고객 앱의 실제 요청이 SaaS ingest로 이어진다.
- decision과 prompt context audit이 DB 또는 projection에 남는다.
- tenant binding이 올바르다.

### 실패 의미

- 고객 앱과 SaaS가 논리적으로만 연결되어 있고 실제 런타임 통합은 끊겨 있다.

## 8.7 T-07 SaaS 거버넌스 모니터링 검증

### 성격

- SaaS control plane 검증

### 목적

- ingest된 결과가 governance, reconciliation, alert, assurance로 이어지는지 확인한다.

### 대상 소스

- `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/prompt/PromptGovernanceRegistryService.java`
- `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/prompt/PromptRuntimeGovernanceReconciliationService.java`
- `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/prompt/PromptRuntimeGovernanceAlertFeedService.java`
- `D:/contexa-enterprise/contexa-core-enterprise/src/main/java/io/contexa/contexacoreenterprise/dashboard/operations/assurance/AiNativeCustomerAssuranceService.java`

### 관련 테스트 소스

- `D:/contexa-enterprise/contexa-core-enterprise/src/test/java/io/contexa/contexacoreenterprise/operations/PromptRuntimeGovernanceReconciliationServiceTest.java`
- `D:/contexa-enterprise/contexa-core-enterprise/src/test/java/io/contexa/contexacoreenterprise/operations/PromptRuntimeGovernanceAlertFeedServiceTest.java`
- `D:/contexa-enterprise/contexa-core-enterprise/src/test/java/io/contexa/contexacoreenterprise/operations/AiNativeCustomerAssuranceServiceTest.java`

### 확인 절차

1. hijacked export 이후 SaaS 운영 화면 또는 DB에서 관련 record를 찾는다.
2. 아래가 일치하는지 본다.
   - runtime telemetry 존재 여부
   - prompt hash / version 비교 결과
   - alert severity
   - operator action
   - assurance 상태
3. prompt runtime 결과와 customer assurance가 서로 다른 말을 하지 않는지 확인한다.

### 합격 기준

- SaaS는 hijacked path의 result를 무시하지 않는다.
- decision ingest와 prompt audit의 사실을 토대로 alert/assurance가 생성된다.

### 실패 의미

- SaaS는 단순 적재 저장소에 머물고 운영 관찰 지점으로 기능하지 못한다.

## 8.8 T-08 SaaS 학습 결과 재공급 검증

### 성격

- 고객 <- SaaS 학습 루프 검증

### 목적

- SaaS에서 쌓인 baseline/threat knowledge가 고객으로 되돌아와 후속 판정에 실제 영향을 주는지 확인한다.

### 대상 소스

- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasBaselineSeedPullScheduler.java`
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatSignalPullScheduler.java`
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatKnowledgePackPullScheduler.java`
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatKnowledgeRuntimePolicyPullScheduler.java`
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatIntelligenceService.java`
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatKnowledgePackService.java`
- `D:/contexa/contexa-core/src/main/java/io/contexa/contexacore/autonomous/saas/SaasThreatKnowledgeRuntimePolicyService.java`

### 관련 테스트 소스

- `D:/contexa/contexa-core/src/test/java/io/contexa/contexacore/autonomous/saas/SaasThreatIntelligenceServiceTest.java`
  - `refreshCachesSignalsAndReturnsPromptLimitedSignalsInPriorityOrder`
  - `promptSignalsAreSuppressedWhenSharingIsDisabled`
  - `buildThreatContextReturnsMatchedSignalsForCurrentEvent`
- `D:/contexa/contexa-core/src/test/java/io/contexa/contexacore/autonomous/saas/SaasThreatKnowledgePackServiceTest.java`
  - `refreshCachesKnowledgePackAndReturnsCurrentSnapshot`
  - `buildThreatKnowledgeContextReturnsComparableCasesForCurrentEvent`
  - `buildThreatKnowledgeContextFailsClosedWhenRuntimePolicyWithdrawsKnowledge`
  - `buildThreatKnowledgeContextFailsClosedWhenRuntimePolicyDisablesRuntimeUsage`
- `D:/contexa/contexa-core/src/test/java/io/contexa/contexacore/autonomous/saas/SaasThreatKnowledgeRuntimePolicyServiceTest.java`
  - `refreshCachesRuntimePolicyAndIndexesApprovedArtifacts`
  - `runtimeIsDeniedWhenKillSwitchIsActive`

### 확인 절차

1. SaaS에 hijacked outcome과 관련 threat signal/knowledge가 적재되도록 유도한다.
2. 고객 앱의 scheduler 주기를 기다리거나 수동으로 refresh를 유도한다.
3. 고객 앱에서 SaaS cache refresh 로그를 확인한다.
4. 이후 동일 또는 유사한 공격 경로를 다시 호출한다.
5. 첫 번째 hijack 시도와 두 번째 hijack 시도의 context/prompt/decision 차이를 비교한다.

### 합격 기준

- 고객 앱이 SaaS에서 baseline seed / threat signal / knowledge / runtime policy를 실제로 받아온다.
- 두 번째 유사 공격에서 prompt context 또는 판단 근거가 풍부해진다.
- 결과가 개선되면 그 개선이 로그와 payload에서 설명 가능하다.

### 실패 의미

- SaaS 학습 루프가 문서상 개념에 머물고 실제 고객 판정 개선으로 이어지지 않는다.

## 9. 필수 수집 증거

리허설이 끝나면 아래 증거를 반드시 수집한다.

1. 정상 사용자 로그인 시점 브라우저 HAR
2. 정상 export 호출 결과
3. hijacked export 호출 결과
4. 고객 앱 로그
5. SaaS 앱 로그
6. decision ingest record
7. prompt context audit record
8. XAI or assurance projection
9. baseline/threat pull 로그
10. 두 번째 재실행 시 결과 비교표

## 10. 최종 판정 규칙

이번 리허설의 최종 판정은 아래 중 하나다.

### 10.1 합격

아래를 모두 만족한다.

- 정상 사용자는 허용된다.
- hijacked export는 plain `200 OK`가 아니다.
- bridge -> context -> prompt -> decision -> SaaS ingest -> monitoring -> feedback loop가 모두 추적된다.
- context 축약이 원본 의미를 잃지 않는다.
- SaaS에서 재공급된 신호가 후속 판정에 반영된다.

### 10.2 조건부 합격

아래와 같다.

- hijacked export가 `401/403`은 아니지만 `423 ESCALATE` 또는 pending analysis로 떨어진다.
- 전체 추적은 되지만 판정 강도가 약하다.
- 이 경우 prompt/knowledge/runtime policy 튜닝 과제로 넘긴다.

### 10.3 실패

아래 중 하나라도 해당하면 실패다.

- hijacked export가 plain `200 OK`
- 브릿지 handoff가 실제로 안 일어남
- prompt metadata가 생성되지 않음
- prompt context audit가 SaaS로 안 감
- decision ingest가 SaaS에 안 남음
- SaaS 재공급 루프가 실제 판정에 영향을 주지 못함
- 축약 과정에서 핵심 의미가 사라짐

## 11. 이 문서를 따라가기 전에 반드시 실행할 코드 기반 사전 확인 명령

### 11.1 bridge_example

```powershell
cd D:\bridge_example
./gradlew test --tests io.contexa.bridge_example.BridgeExampleApplicationTests --warning-mode all --no-daemon
```

### 11.2 core 핵심 계약

```powershell
cd D:\contexa
./gradlew :contexa-core:test --tests io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisherTest --tests io.contexa.contexacore.autonomous.context.PromptContextComposerTest --tests io.contexa.contexacore.std.components.prompt.PromptGeneratorTest --tests io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplateTest --tests io.contexa.contexacore.autonomous.saas.mapper.PromptContextAuditPayloadMapperTest --tests io.contexa.contexacore.autonomous.saas.mapper.SecurityDecisionForwardingPayloadMapperTest --tests io.contexa.contexacore.autonomous.saas.SaasThreatIntelligenceServiceTest --tests io.contexa.contexacore.autonomous.saas.SaasThreatKnowledgePackServiceTest --tests io.contexa.contexacore.autonomous.saas.SaasThreatKnowledgeRuntimePolicyServiceTest --warning-mode all --no-daemon
```

### 11.3 enterprise 핵심 계약

```powershell
cd D:\contexa-enterprise
./gradlew :contexa-core-enterprise:test --tests io.contexa.contexacoreenterprise.operations.SaasRuntimeApiControllerTest --tests io.contexa.contexacoreenterprise.operations.PromptRuntimeGovernanceReconciliationServiceTest --tests io.contexa.contexacoreenterprise.operations.PromptRuntimeGovernanceAlertFeedServiceTest --tests io.contexa.contexacoreenterprise.operations.AiNativeCustomerAssuranceServiceTest --warning-mode all --no-daemon
```

이 세 가지가 먼저 green이어야 브라우저 기반 실전 리허설을 시작할 수 있다.

## 12. 마지막 경고

이번 리허설에서 가장 중요한 것은 "결과가 좋아 보이는가"가 아니라 아래 두 가지다.

- 기존 세션 기반 보안이 놓칠 수 있는 hijacked export를 Cortex가 plain success로 두지 않는가
- 그 판정 근거가 bridge, context, prompt, SaaS 전 구간에서 증거로 남는가

이 둘이 성립하지 않으면 이번 리허설은 실패다.
