package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.sandbox.mfa.ott.SandboxOttCaptureTestConfiguration;
import io.contexa.sandbox.mfa.ott.SandboxOttCodeCapture;
import io.contexa.springbootstartercontexa.SpringBootStarterContexaApplication;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineExecutionContext;
import io.contexa.contexacore.std.pipeline.step.LLMExecutionStep;
import org.mockito.Mockito;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * sandbox full-stack prompt 리플레이 테스트.
 *
 * 중요:
 * - 브라우저 UI를 직접 띄우지 않는다.
 * - 하지만 브라우저가 보내는 것과 동일한 HTTP 요청을 실제 포트로 보낸다.
 * - MFA, 세션 쿠키, 보호 리소스 호출, 비동기 prompt 생성, evidence 조회까지 모두 실경로를 탄다.
 *
 * 즉 이 테스트는 "약속된 객체를 주고받는 게임"이 아니라,
 * starter 앱이 실제 웹 환경에서 생성한 데이터를 그대로 받아 검증하는 용도다.
 */
@SpringBootTest(
        classes = SpringBootStarterContexaApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({
        SandboxPromptTraceTestConfiguration.class,
        SandboxOttCaptureTestConfiguration.class,
        SandboxPromptSeedTestConfiguration.class
})
class SandboxFullStackPromptReplayTest {

    private static final String USERNAME = "sandbox-admin-" +
            UUID.randomUUID().toString().replace("-", "").substring(0, 12).toLowerCase(Locale.ROOT) +
            "@example.com";
    private static final String PASSWORD = "1234";
    private static final String NORMAL_CLIENT_IP = "192.168.1.100";
    private static final String RAW_BROWSER_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
                    "Chrome/120.0.0.0 Safari/537.36";
    private static final String REQUEST_PATH = "/admin/api/security-test/sensitive/resource-001";
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(15);
    private static final Duration TRACE_TIMEOUT = Duration.ofSeconds(20);
    private static final Duration ROUND_REENTRY_GUARD_COOLDOWN = SandboxBenchmarkRuntimeSettings.roundCooldown();
    private static final SandboxPostgresqlSchemaSupport POSTGRESQL_SCHEMA_SUPPORT =
            SandboxPostgresqlSchemaSupport.create();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() { };

    @LocalServerPort
    private int port;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SandboxOttCodeCapture sandboxOttCodeCapture;

    @Autowired
    private SandboxPromptTraceStore sandboxPromptTraceStore;

    @Autowired
    private ZeroTrustActionRepository zeroTrustActionRepository;

    @Autowired
    private SandboxVectorStoreIsolationSupport sandboxVectorStoreIsolationSupport;

    @MockBean(name = "llmExecutionStep")
    private LLMExecutionStep llmExecutionStep;

    private SandboxWebSessionClient webSessionClient;
    private String deviceId;

    @DynamicPropertySource
    static void registerSandboxDatasource(DynamicPropertyRegistry registry) {
        POSTGRESQL_SCHEMA_SUPPORT.register(registry);
        SandboxBenchmarkRuntimeSettings.registerSandboxBenchmarkProperties(registry);
        registry.add("sandbox.prompt.username", () -> USERNAME);
        registry.add("sandbox.prompt.password", () -> PASSWORD);
    }

    @BeforeEach
    void setUp() {
        webSessionClient = new SandboxWebSessionClient("http://127.0.0.1:" + port, HTTP_TIMEOUT);
        sandboxVectorStoreIsolationSupport.prepareCleanReplayRun();
        sandboxOttCodeCapture.clearAll();
        sandboxPromptTraceStore.clearAll();
        configureStableFinalLlmStep();
        deviceId = null;
    }

    @AfterAll
    static void tearDown() {
        SandboxVectorStoreIsolationSupport.cleanupReplayArtifactsInDatabase();
        POSTGRESQL_SCHEMA_SUPPORT.dropQuietly();
    }

    private void configureStableFinalLlmStep() {
        Map<String, Object> stableResponse = new LinkedHashMap<>();
        stableResponse.put("action", "ALLOW");
        stableResponse.put("reasoning",
                "Sandbox full-stack replay stabilizes only the final LLM boundary so context and prompt quality can be verified deterministically.");
        stableResponse.put("riskScore", 0.10d);
        stableResponse.put("confidence", 0.70d);
        stableResponse.put("mitre", "UNKNOWN");

        Mockito.reset(llmExecutionStep);
        Mockito.when(llmExecutionStep.getConfigStep()).thenReturn(PipelineConfiguration.PipelineStep.LLM_EXECUTION);
        Mockito.when(llmExecutionStep.getOrder()).thenReturn(4);
        Mockito.when(llmExecutionStep.canExecute(Mockito.any())).thenReturn(true);
        Mockito.doAnswer(invocation -> {
            PipelineExecutionContext context = invocation.getArgument(1);
            Class<?> targetType = context.getMetadata("aiGenerationType", Class.class);
            if (targetType == null) {
                targetType = context.getMetadata("targetResponseType", Class.class);
            }
            Object responseBody = targetType != null
                    ? objectMapper.convertValue(stableResponse, targetType)
                    : objectMapper.writeValueAsString(stableResponse);

            context.addStepResult(PipelineConfiguration.PipelineStep.LLM_EXECUTION, responseBody);
            context.addMetadata("structuredOutputComplete", targetType != null);
            return reactor.core.publisher.Mono.just(responseBody);
        }).when(llmExecutionStep).execute(Mockito.any(), Mockito.any());
    }

    @Test
    @DisplayName("sandbox full-stack: 실제 웹/MFA/비동기 prompt 경로가 1차→2차→3차 동안 95% 이상 품질을 유지해야 한다")
    void shouldReplayRealWebFlowAndMaintainPromptQualityAboveNinetyFivePercent() throws IOException {
        // 이 테스트는 실브라우저 대신 실제 HTTP를 사용한다.
        // 따라서 실패하면 "UI mock이 틀렸다"가 아니라 실제 starter 웹 경로에서 품질 문제가 발생한 것이다.
        authenticateUsingRealOttMfa();

        String runId = "sandbox-run-" + UUID.randomUUID();

        // 1차: 최초 접근이다. baseline과 RAG가 아직 거의 없으므로 relatedDocuments가 0이어도 자연스럽다.
        // executeProtectedRound는 이제 "PromptGenerationStep 통과"가 아니라 "Layer1 전체 완료" 이후의 trace를 돌려준다.
        // 따라서 이 round가 끝났다는 것은 해당 회차의 vector 저장도 끝났다는 뜻이다.
        ReplayRound firstRound = executeProtectedRound("INITIAL", runId);
        waitForNextRoundWindow();

        // 2차: 1차가 Layer1 전체 완료까지 끝난 뒤 호출되므로, 1차에서 저장된 memory/vector document를 회수하기 시작해야 한다.
        // relatedDocuments가 1 이상으로 올라오지 않으면 "학습이 누적된다"는 전제가 깨진다.
        ReplayRound secondRound = executeProtectedRound("FOLLOW_UP", runId);
        waitForNextRoundWindow();

        // 3차: 2차까지의 누적 결과를 다시 회수해야 한다.
        // 여기서 역행하거나 핵심 컨텍스트가 빠지면 round progression 자체가 불안정하다는 의미다.
        ReplayRound thirdRound = executeProtectedRound("FOLLOW_UP", runId);

        SandboxPromptQualityScorecard firstScorecard = SandboxPromptQualityScorecard.evaluateRound(
                "1차 full-stack prompt 품질",
                objectMapper,
                firstRound.snapshot(),
                firstRound.responseBody(),
                new SandboxPromptQualityScorecard.ExpectedRoundExpectation(
                        firstRound.requestId(),
                        USERNAME,
                        REQUEST_PATH,
                        NORMAL_CLIENT_IP,
                        RAW_BROWSER_USER_AGENT,
                        "BASELINE",
                        "NONE",
                        "INITIAL",
                        0,
                        1,
                        SandboxPromptSessionMode.NEW_SESSION,
                        true,
                        true,
                        true,
                        false,
                        false));

        SandboxPromptQualityScorecard secondScorecard = SandboxPromptQualityScorecard.evaluateRound(
                "2차 full-stack prompt 품질",
                objectMapper,
                secondRound.snapshot(),
                secondRound.responseBody(),
                new SandboxPromptQualityScorecard.ExpectedRoundExpectation(
                        secondRound.requestId(),
                        USERNAME,
                        REQUEST_PATH,
                        NORMAL_CLIENT_IP,
                        RAW_BROWSER_USER_AGENT,
                        "BASELINE",
                        "NONE",
                        "FOLLOW_UP",
                        1,
                        2,
                        SandboxPromptSessionMode.REUSE_SESSION,
                        false,
                        false,
                        false,
                        true,
                        true));

        SandboxPromptQualityScorecard thirdScorecard = SandboxPromptQualityScorecard.evaluateRound(
                "3차 full-stack prompt 품질",
                objectMapper,
                thirdRound.snapshot(),
                thirdRound.responseBody(),
                new SandboxPromptQualityScorecard.ExpectedRoundExpectation(
                        thirdRound.requestId(),
                        USERNAME,
                        REQUEST_PATH,
                        NORMAL_CLIENT_IP,
                        RAW_BROWSER_USER_AGENT,
                        "BASELINE",
                        "NONE",
                        "FOLLOW_UP",
                        2,
                        2,
                        SandboxPromptSessionMode.REUSE_SESSION,
                        false,
                        false,
                        false,
                        true,
                        true));

        // 회차 진행은 단순 count 증가가 아니라, 앞선 라운드 memory가 다음 prompt의 근거로 실제 유입되는지를 보는 지표다.
        SandboxPromptQualityScorecard progressionScorecard = SandboxPromptQualityScorecard.evaluateProgression(
                "회차 누적 품질",
                firstRound.snapshot(),
                secondRound.snapshot(),
                thirdRound.snapshot());

        writeDiagnosticFile("round-1", firstRound, firstScorecard);
        writeDiagnosticFile("round-2", secondRound, secondScorecard);
        writeDiagnosticFile("round-3", thirdRound, thirdScorecard);

        firstScorecard.assertPassRateAtLeast(95.0d);
        secondScorecard.assertPassRateAtLeast(95.0d);
        thirdScorecard.assertPassRateAtLeast(95.0d);
        progressionScorecard.assertPassRateAtLeast(95.0d);
    }

    private void authenticateUsingRealOttMfa() {
        deviceId = UUID.randomUUID().toString();

        // 브라우저 로그인 페이지 초기 진입과 동일하게 세션 쿠키를 먼저 확보한다.
        SandboxHttpResponse loginPageResponse = webSessionClient.get("/customLogin", baseBrowserHeaders(deviceId));
        assertThat(loginPageResponse.status()).isEqualTo(200);

        // 1차 인증은 실제 /admin/mfa/login form 로그인 경로를 그대로 탄다.
        SandboxHttpResponse loginResponse = webSessionClient.postForm(
                "/admin/mfa/login",
                formHeaders(deviceId),
                Map.of(
                        "username", USERNAME,
                        "password", PASSWORD));

        Map<String, Object> loginBody = parseJsonBody(loginResponse);
        assertThat(loginResponse.status()).isEqualTo(200);
        assertThat(text(loginBody.get("status")))
                .as("1차 인증 후 MFA_REQUIRED 계열 상태가 와야 이후 MFA 플로우를 정상 진행할 수 있다.")
                .isIn("MFA_REQUIRED_SELECT_FACTOR", "MFA_REQUIRED", "MFA_CONTINUE");

        String factorType = resolveFactorType(loginBody);

        // factor 선택은 실제 /admin/mfa/select-factor JSON API를 그대로 사용한다.
        SandboxHttpResponse factorSelectionResponse = webSessionClient.postJson(
                "/admin/mfa/select-factor",
                jsonHeaders(deviceId),
                Map.of(
                        "factorType", factorType,
                        "username", USERNAME));

        Map<String, Object> factorSelectionBody = parseJsonBody(factorSelectionResponse);
        assertThat(factorSelectionResponse.status()).isEqualTo(200);

        String ottRequestPageUrl = text(factorSelectionBody.get("nextStepUrl"));
        assertThat(ottRequestPageUrl)
                .as("factor 선택 응답에는 다음 MFA 단계 URL이 있어야 실제 브라우저와 같은 화면 전이를 따라갈 수 있다.")
                .isNotBlank();

        SandboxHttpResponse ottRequestPageResponse = webSessionClient.get(
                toRelativePath(ottRequestPageUrl),
                baseBrowserHeaders(deviceId));
        assertThat(ottRequestPageResponse.status()).isEqualTo(200);

        String ottCodeGenerationUrl = extractFormAction(
                ottRequestPageResponse.body(),
                "ottRequestForm",
                "ott-request-form");
        Map<String, String> requestCodeForm = extractHiddenInputs(
                ottRequestPageResponse.body(),
                "ottRequestForm",
                "ott-request-form");
        requestCodeForm.putIfAbsent("username", USERNAME);

        // OTT 생성은 실제 /admin/mfa/request-ott-code로 요청하고, sandbox capture에서 코드만 읽는다.
        SandboxHttpResponse requestCodeResponse = webSessionClient.postForm(
                toRelativePath(ottCodeGenerationUrl),
                formHeaders(deviceId),
                requestCodeForm);

        assertThat(requestCodeResponse.status())
                .as("OTT code generation은 challenge UI로 redirect 되어야 브라우저와 같은 흐름을 유지한다.")
                .isIn(302, 303);

        String latestOttCode = sandboxOttCodeCapture.awaitLatestCode(USERNAME, Duration.ofSeconds(10));
        assertThat(latestOttCode)
                .as("OTT code capture가 비어 있으면 실 HTTP MFA 흐름을 sandbox에서 재현하지 못한 것이다.")
                .isNotBlank();

        // 최종 OTT 검증도 실제 브라우저와 동일하게 application/x-www-form-urlencoded 로 보낸다.
        String ottVerifyPageUrl = text(requestCodeResponse.headers().getFirst("Location"));
        assertThat(ottVerifyPageUrl)
                .as("OTT code generation 이후 verify page redirect Location이 있어야 한다.")
                .isNotBlank();

        SandboxHttpResponse ottVerifyPageResponse = webSessionClient.get(
                toRelativePath(ottVerifyPageUrl),
                baseBrowserHeaders(deviceId));
        assertThat(ottVerifyPageResponse.status()).isEqualTo(200);

        String ottVerifyUrl = extractFormAction(
                ottVerifyPageResponse.body(),
                "verifyForm",
                "ott-verify-form");
        Map<String, String> verifyForm = extractHiddenInputs(
                ottVerifyPageResponse.body(),
                "verifyForm",
                "ott-verify-form");
        verifyForm.put("token", latestOttCode);

        SandboxHttpResponse verifyResponse = webSessionClient.postForm(
                toRelativePath(ottVerifyUrl),
                formHeaders(deviceId),
                verifyForm);

        Map<String, Object> verifyBody = parseJsonBody(verifyResponse);
        assertThat(verifyResponse.status()).isEqualTo(200);
        assertThat(text(verifyBody.get("status")))
                .as("MFA가 완료되지 않으면 이후 보호 리소스 접근이 브라우저와 다른 조건에서 실행된다.")
                .isEqualTo("MFA_COMPLETED");
    }

    private ReplayRound executeProtectedRound(String phase, String runId) {
        rearmPendingAnalysisForReplayRound(phase);
        sandboxPromptTraceStore.clearAll();

        String requestId = "sandbox-req-" + phase.toLowerCase(Locale.ROOT) + "-" + UUID.randomUUID();
        Map<String, String> requestHeaders = securityTestHeaders(requestId, phase, runId);

        SandboxHttpResponse protectedResponse = webSessionClient.get(REQUEST_PATH, requestHeaders);
        Map<String, Object> responseBody = parseJsonBody(protectedResponse);

        assertThat(protectedResponse.status())
                .as("보호 리소스 호출이 200이 아니면 prompt 품질 이전에 웹 경로 자체가 재현되지 않은 것이다.")
                .isEqualTo(200);

        String effectiveRequestId = text(responseBody.get("requestId"));
        assertThat(effectiveRequestId)
                .as("보호 리소스 응답에는 requestId가 반드시 있어야 event/prompt/evidence를 같은 체인으로 추적할 수 있다.")
                .isNotBlank();

        SandboxPromptTraceSnapshot snapshot = resolvePromptTrace(effectiveRequestId);

        return new ReplayRound(
                effectiveRequestId,
                responseBody,
                snapshot);
    }

    private void rearmPendingAnalysisForReplayRound(String phase) {
        // 제품 의미를 그대로 따른다.
        // 현재 플랫폼은 ZeroTrustAction 이 PENDING_ANALYSIS 일 때만 Layer1 비동기 분석과 prompt 생성 경로를 다시 탄다.
        // 따라서 회차 검증에서는 이전 회차에 저장된 baseline/vector memory 는 유지하고,
        // 현재 사용자 action 상태만 PENDING_ANALYSIS 로 되돌린 뒤 다음 HTTP 요청을 보낸다.
        // 이렇게 해야 1차 -> 2차 -> 3차가 모두 "실제 웹 요청 + 실제 분석 경로"로 재현된다.
        zeroTrustActionRepository.saveActionWithPrevious(USERNAME, ZeroTrustAction.PENDING_ANALYSIS);

        assertThat(zeroTrustActionRepository.getCurrentAction(USERNAME))
                .as("회차 %s 실행 전 현재 action 은 반드시 PENDING_ANALYSIS 여야 다음 보호 리소스 호출이 실제 분석 경로를 다시 탄다.", phase)
                .isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    private void waitForNextRoundWindow() {
        try {
            Thread.sleep(Math.max(
                    SandboxBenchmarkRuntimeSettings.minSafeRoundCooldownMs(),
                    ROUND_REENTRY_GUARD_COOLDOWN.toMillis()));
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for rapid re-entry guard cooldown", interruptedException);
        }
    }

    private SandboxPromptTraceSnapshot resolvePromptTrace(String requestId) {
        try {
            return sandboxPromptTraceStore.await(requestId, TRACE_TIMEOUT);
        } catch (IllegalStateException missingRequestIdTrace) {
            SandboxPromptTraceSnapshot latestSnapshot = sandboxPromptTraceStore.awaitAny(TRACE_TIMEOUT);
            String traceRequestId = extractTraceRequestId(latestSnapshot);
            assertThat(traceRequestId)
                    .as("Layer1 전체 완료 후 확정된 trace의 requestId는 보호 리소스 응답 requestId와 반드시 일치해야 한다.")
                    .isEqualTo(requestId);
            return latestSnapshot;
        }
    }

    private String resolveFactorType(Map<String, Object> loginBody) {
        Object availableFactorsValue = loginBody.get("availableFactors");
        if (availableFactorsValue instanceof List<?> factors) {
            for (Object factor : factors) {
                if (factor instanceof Map<?, ?> factorMap) {
                    Object type = factorMap.get("type");
                    if ("MFA_OTT".equals(String.valueOf(type))) {
                        return "MFA_OTT";
                    }
                }
            }
        }
        return "MFA_OTT";
    }

    private Map<String, String> baseBrowserHeaders(String deviceId) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", MediaType.TEXT_HTML_VALUE);
        headers.put("User-Agent", RAW_BROWSER_USER_AGENT);
        headers.put("X-Device-Id", deviceId);
        return headers;
    }

    private Map<String, String> jsonHeaders(String deviceId) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.put("User-Agent", RAW_BROWSER_USER_AGENT);
        headers.put("X-Device-Id", deviceId);
        return headers;
    }

    private Map<String, String> formHeaders(String deviceId) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.put("User-Agent", RAW_BROWSER_USER_AGENT);
        headers.put("X-Device-Id", deviceId);
        return headers;
    }

    private Map<String, String> authenticatedJsonHeaders() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", MediaType.APPLICATION_JSON_VALUE);
        headers.put("User-Agent", RAW_BROWSER_USER_AGENT);
        headers.put("X-Contexa-Auth-Mode", "cookie");
        headers.put("X-Contexa-Token-Source", "none");
        headers.put("X-Contexa-Auth-Carrier", "SESSION_COOKIE_ONLY");
        headers.put("X-Contexa-Auth-Subject", USERNAME);
        headers.put("X-Contexa-Authorization-Present", "false");
        return headers;
    }

    private Map<String, String> securityTestHeaders(String requestId, String phase, String runId) {
        Map<String, String> headers = authenticatedJsonHeaders();
        headers.put("X-Request-ID", requestId);
        headers.put("X-Forwarded-For", NORMAL_CLIENT_IP);
        headers.put("X-Simulated-User-Agent", RAW_BROWSER_USER_AGENT);
        if (StringUtils.hasText(deviceId)) {
            headers.put("X-Device-Id", deviceId);
        }
        headers.put("X-Contexa-Scenario", "NORMAL_USER");
        headers.put("X-Contexa-Expected-Action", "ALLOW or LOW_RISK");
        headers.put("X-Contexa-Demo-Run-Id", runId);
        headers.put("X-Contexa-Demo-Phase", phase);
        return headers;
    }

    private Map<String, Object> parseJsonBody(SandboxHttpResponse response) {
        try {
            String body = response.body();
            if (!StringUtils.hasText(body)) {
                return Map.of();
            }
            return objectMapper.readValue(body, MAP_TYPE);
        } catch (Exception exception) {
            throw new IllegalStateException("Failed to parse sandbox HTTP response body: " + response.body(), exception);
        }
    }

    private void writeDiagnosticFile(
            String roundLabel,
            ReplayRound round,
            SandboxPromptQualityScorecard scorecard) throws IOException {

        Map<String, Object> diagnostic = new LinkedHashMap<>();
        diagnostic.put("requestId", round.requestId());
        diagnostic.put("response", round.responseBody());
        diagnostic.put("trace", round.snapshot().toDiagnosticMap(objectMapper));
        diagnostic.put("passRatePercent", scorecard.passRatePercent());
        diagnostic.put("failureSummary", scorecard.failureSummary());

        Path reportDirectory = Path.of("build", "reports", "sandbox-fullstack-prompt");
        Files.createDirectories(reportDirectory);
        Files.writeString(
                reportDirectory.resolve(roundLabel + ".json"),
                objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(diagnostic));
    }

    private static String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static String extractTraceRequestId(SandboxPromptTraceSnapshot snapshot) {
        if (snapshot == null || snapshot.event() == null || snapshot.event().getMetadata() == null) {
            return null;
        }
        Object requestId = snapshot.event().getMetadata().get("requestId");
        if (requestId instanceof String text && !text.isBlank()) {
            return text.trim();
        }
        Object correlationId = snapshot.event().getMetadata().get("correlationId");
        if (correlationId instanceof String text && !text.isBlank()) {
            return text.trim();
        }
        return null;
    }

    private static String toRelativePath(String url) {
        if (!StringUtils.hasText(url)) {
            return url;
        }
        if (url.startsWith("http://") || url.startsWith("https://")) {
            URI uri = URI.create(url);
            String path = StringUtils.hasText(uri.getRawPath()) ? uri.getRawPath() : "/";
            return StringUtils.hasText(uri.getRawQuery()) ? path + "?" + uri.getRawQuery() : path;
        }
        return url;
    }

    private static String extractFormAction(String html, String... formIds) {
        assertThat(html)
                .as("렌더링된 HTML이 비어 있으면 브라우저와 같은 form action 추적이 불가능하다.")
                .isNotBlank();

        FormSlice formSlice = locateFormSlice(html, formIds);
        int formStart = formSlice.formStart();
        Object formId = List.of(formIds);
        assertThat(formStart)
                .as("form id=%s 가 HTML에 있어야 실제 브라우저 submit 경로를 재현할 수 있다. htmlSnippet=%s",
                        List.of(formIds),
                        html.substring(0, Math.min(html.length(), 600)))
                .isGreaterThanOrEqualTo(0);

        int actionStart = html.indexOf("action=\"", formStart);
        assertThat(actionStart)
                .as("form id=%s 에 action 속성이 있어야 한다.", formId)
                .isGreaterThanOrEqualTo(0);

        int valueStart = actionStart + "action=\"".length();
        int valueEnd = html.indexOf('"', valueStart);
        assertThat(valueEnd).isGreaterThan(valueStart);
        return html.substring(valueStart, valueEnd);
    }

    private static Map<String, String> extractHiddenInputs(String html, String... formIds) {
        Map<String, String> hiddenInputs = new LinkedHashMap<>();
        if (!StringUtils.hasText(html)) {
            return hiddenInputs;
        }

        FormSlice formSlice = locateFormSlice(html, formIds);
        if (formSlice.formStart() < 0 || formSlice.formEnd() < 0) {
            return hiddenInputs;
        }

        String formHtml = html.substring(formSlice.formStart(), formSlice.formEnd());
        int searchIndex = 0;
        while (searchIndex >= 0) {
            int inputIndex = formHtml.indexOf("<input", searchIndex);
            if (inputIndex < 0) {
                break;
            }

            int tagEnd = formHtml.indexOf('>', inputIndex);
            if (tagEnd < 0) {
                break;
            }

            String inputTag = formHtml.substring(inputIndex, tagEnd + 1);
            if (inputTag.contains("type=\"hidden\"")) {
                String name = extractAttribute(inputTag, "name");
                String value = extractAttribute(inputTag, "value");
                if (StringUtils.hasText(name)) {
                    hiddenInputs.put(name, value == null ? "" : value);
                }
            }
            searchIndex = tagEnd + 1;
        }
        return hiddenInputs;
    }

    private static FormSlice locateFormSlice(String html, String... formIds) {
        if (!StringUtils.hasText(html)) {
            return new FormSlice(-1, -1);
        }

        if (formIds != null) {
            for (String formId : formIds) {
                if (!StringUtils.hasText(formId)) {
                    continue;
                }
                int formIdIndex = html.indexOf("id=\"" + formId + "\"");
                if (formIdIndex >= 0) {
                    int formStart = html.lastIndexOf("<form", formIdIndex);
                    int formEnd = html.indexOf("</form>", formIdIndex);
                    return new FormSlice(formStart >= 0 ? formStart : formIdIndex, formEnd);
                }
            }
        }

        int fallbackFormStart = html.indexOf("<form");
        int fallbackFormEnd = fallbackFormStart >= 0 ? html.indexOf("</form>", fallbackFormStart) : -1;
        return new FormSlice(fallbackFormStart, fallbackFormEnd);
    }

    private static String extractAttribute(String tag, String attributeName) {
        String marker = attributeName + "=\"";
        int start = tag.indexOf(marker);
        if (start < 0) {
            return null;
        }
        int valueStart = start + marker.length();
        int valueEnd = tag.indexOf('"', valueStart);
        if (valueEnd < 0) {
            return null;
        }
        return tag.substring(valueStart, valueEnd);
    }

    private record ReplayRound(
            String requestId,
            Map<String, Object> responseBody,
            SandboxPromptTraceSnapshot snapshot) {
    }

    private record FormSlice(int formStart, int formEnd) {
    }
}
