package io.contexa.sandbox.fullstack.prompt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.sandbox.mfa.ott.SandboxOttCodeCapture;
import org.assertj.core.api.Assertions;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * sandbox full-stack replay 실행기.
 *
 * 이 하네스는 브라우저를 띄우지 않지만, 서버 입장에서는 브라우저와 동일한 HTTP/MFA/세션 흐름을 탄다.
 * 따라서 여기서 회수한 event/sessionCtx/behaviorCtx/relatedDocuments/prompt는 실제 웹 원본이다.
 */
public class SandboxFullStackPromptReplayHarness {

    public static final String DEFAULT_REQUEST_PATH = "/admin/api/security-test/sensitive/resource-001";
    public static final String DEFAULT_CLIENT_IP = "192.168.1.100";
    public static final String DEFAULT_SCENARIO_KEY = "ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE";
    public static final String DEFAULT_EXPERIMENT_GROUP = "WEBCLIENT_FULLSTACK_BEHAVIOR_BENCHMARK";
    public static final String DEFAULT_BROWSER_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) " +
                    "Chrome/120.0.0.0 Safari/537.36";

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() { };

    private final String baseUrl;
    private final Duration httpTimeout;
    private final Duration traceTimeout;
    private final Duration roundCooldown;
    private final ObjectMapper objectMapper;
    private final SandboxOttCodeCapture sandboxOttCodeCapture;
    private final SandboxPromptTraceStore sandboxPromptTraceStore;
    private final ZeroTrustActionRepository zeroTrustActionRepository;
    private final SandboxPromptUserProvisioner sandboxPromptUserProvisioner;
    private final SandboxVectorStoreIsolationSupport sandboxVectorStoreIsolationSupport;

    public SandboxFullStackPromptReplayHarness(
            String baseUrl,
            Duration httpTimeout,
            Duration traceTimeout,
            Duration roundCooldown,
            ObjectMapper objectMapper,
            SandboxOttCodeCapture sandboxOttCodeCapture,
            SandboxPromptTraceStore sandboxPromptTraceStore,
            ZeroTrustActionRepository zeroTrustActionRepository,
            SandboxPromptUserProvisioner sandboxPromptUserProvisioner,
            SandboxVectorStoreIsolationSupport sandboxVectorStoreIsolationSupport) {
        this.baseUrl = baseUrl;
        this.httpTimeout = httpTimeout;
        this.traceTimeout = traceTimeout;
        this.roundCooldown = roundCooldown;
        this.objectMapper = objectMapper;
        this.sandboxOttCodeCapture = sandboxOttCodeCapture;
        this.sandboxPromptTraceStore = sandboxPromptTraceStore;
        this.zeroTrustActionRepository = zeroTrustActionRepository;
        this.sandboxPromptUserProvisioner = sandboxPromptUserProvisioner;
        this.sandboxVectorStoreIsolationSupport = sandboxVectorStoreIsolationSupport;
    }

    public SandboxPromptReplayRun replayThreeRounds(String username, String password, String benchmarkRunId) {
        return replayScenario(
                username,
                password,
                benchmarkRunId,
                withRoundCount(SandboxPromptReplayScenarioCatalog.ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE, 3));
    }

    public SandboxPromptReplayRun replayRounds(
            String username,
            String password,
            String benchmarkRunId,
            int roundCount) {
        return replayScenario(
                username,
                password,
                benchmarkRunId,
                withRoundCount(SandboxPromptReplayScenarioCatalog.ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE, roundCount));
    }

    public SandboxPromptReplayRun replayScenario(
            String username,
            String password,
            String benchmarkRunId,
            SandboxPromptReplayScenario scenario) {
        if (scenario == null) {
            throw new IllegalArgumentException("scenario must not be null");
        }
        if (scenario.roundCount() < 3) {
            throw new IllegalArgumentException("scenario.roundCount must be at least 3");
        }
        sandboxVectorStoreIsolationSupport.prepareCleanReplayRun();
        sandboxPromptUserProvisioner.ensurePromptAdminUser(username, password);
        sandboxOttCodeCapture.clearAll();
        sandboxPromptTraceStore.clearAll();

        SandboxWebSessionClient webSessionClient = new SandboxWebSessionClient(baseUrl, httpTimeout);
        Map<String, String> deviceIdsByAlias = new HashMap<>();
        SandboxPromptRoundPlan initialRoundPlan = scenario.roundPlanForRound(1);
        String initialDeviceId = deviceIdsByAlias.computeIfAbsent(
                initialRoundPlan.deviceAlias(),
                ignored -> UUID.randomUUID().toString());
        authenticateUsingRealOttMfa(webSessionClient, username, password, scenario, initialRoundPlan, initialDeviceId);

        List<SandboxPromptReplayRound> rounds = new java.util.ArrayList<>(scenario.roundCount());
        for (int roundNumber = 1; roundNumber <= scenario.roundCount(); roundNumber++) {
            String phase = roundNumber == 1 ? "INITIAL" : "FOLLOW_UP";
            SandboxPromptRoundPlan roundPlan = scenario.roundPlanForRound(roundNumber);
            if (roundNumber > 1) {
                waitForNextRoundWindow(roundPlan.cooldownBeforeRoundMs());
            }
            rounds.add(executeProtectedRound(
                    webSessionClient,
                    username,
                    deviceIdsByAlias,
                    phase,
                    benchmarkRunId,
                    scenario,
                    roundNumber,
                    roundPlan));
        }

        return new SandboxPromptReplayRun(
                benchmarkRunId,
                username,
                scenario.scenarioKey(),
                scenario.experimentGroup(),
                scenario,
                rounds);
    }

    private void authenticateUsingRealOttMfa(
            SandboxWebSessionClient webSessionClient,
            String username,
            String password,
            SandboxPromptReplayScenario scenario,
            SandboxPromptRoundPlan initialRoundPlan,
            String deviceId) {

        SandboxHttpResponse loginPageResponse = webSessionClient.get(
                "/customLogin",
                baseBrowserHeaders(deviceId, initialRoundPlan));
        Assertions.assertThat(loginPageResponse.status()).isEqualTo(200);

        SandboxHttpResponse loginResponse = webSessionClient.postForm(
                "/admin/mfa/login",
                formHeaders(deviceId, initialRoundPlan),
                Map.of("username", username, "password", password));

        Map<String, Object> loginBody = parseJsonBody(loginResponse);
        Assertions.assertThat(loginResponse.status()).isEqualTo(200);
        Assertions.assertThat(text(loginBody.get("status")))
                .as("1차 인증은 반드시 MFA_REQUIRED 계열 상태를 반환해야 이후 실제 MFA 경로를 탈 수 있다.")
                .isIn("MFA_REQUIRED_SELECT_FACTOR", "MFA_REQUIRED", "MFA_CONTINUE");

        String factorType = resolveFactorType(loginBody);

        SandboxHttpResponse factorSelectionResponse = webSessionClient.postJson(
                "/admin/mfa/select-factor",
                jsonHeaders(deviceId, initialRoundPlan),
                Map.of("factorType", factorType, "username", username));
        Map<String, Object> factorSelectionBody = parseJsonBody(factorSelectionResponse);
        Assertions.assertThat(factorSelectionResponse.status()).isEqualTo(200);

        String ottRequestPageUrl = text(factorSelectionBody.get("nextStepUrl"));
        Assertions.assertThat(ottRequestPageUrl)
                .as("factor 선택 이후 nextStepUrl이 있어야 브라우저와 동일한 다음 화면 이동을 재현할 수 있다.")
                .isNotBlank();

        SandboxHttpResponse ottRequestPageResponse = webSessionClient.get(
                toRelativePath(ottRequestPageUrl),
                baseBrowserHeaders(deviceId, initialRoundPlan));
        Assertions.assertThat(ottRequestPageResponse.status()).isEqualTo(200);

        String ottCodeGenerationUrl = extractFormAction(ottRequestPageResponse.body(), "ottRequestForm", "ott-request-form");
        Map<String, String> requestCodeForm = extractHiddenInputs(
                ottRequestPageResponse.body(),
                "ottRequestForm",
                "ott-request-form");
        requestCodeForm.putIfAbsent("username", username);

        SandboxHttpResponse requestCodeResponse = webSessionClient.postForm(
                toRelativePath(ottCodeGenerationUrl),
                formHeaders(deviceId, initialRoundPlan),
                requestCodeForm);

        Assertions.assertThat(requestCodeResponse.status())
                .as("OTT code generation은 challenge 화면으로 redirect되어야 한다.")
                .isIn(302, 303);

        String latestOttCode = sandboxOttCodeCapture.awaitLatestCode(username, Duration.ofSeconds(10));
        Assertions.assertThat(latestOttCode)
                .as("sandbox OTT capture가 비어 있으면 실제 HTTP MFA 흐름을 재현하지 못한 것이다.")
                .isNotBlank();

        String ottVerifyPageUrl = text(requestCodeResponse.headers().getFirst("Location"));
        Assertions.assertThat(ottVerifyPageUrl).isNotBlank();

        SandboxHttpResponse ottVerifyPageResponse = webSessionClient.get(
                toRelativePath(ottVerifyPageUrl),
                baseBrowserHeaders(deviceId, initialRoundPlan));
        Assertions.assertThat(ottVerifyPageResponse.status()).isEqualTo(200);

        String ottVerifyUrl = extractFormAction(ottVerifyPageResponse.body(), "verifyForm", "ott-verify-form");
        Map<String, String> verifyForm = extractHiddenInputs(
                ottVerifyPageResponse.body(),
                "verifyForm",
                "ott-verify-form");
        verifyForm.put("token", latestOttCode);

        SandboxHttpResponse verifyResponse = webSessionClient.postForm(
                toRelativePath(ottVerifyUrl),
                formHeaders(deviceId, initialRoundPlan),
                verifyForm);

        Map<String, Object> verifyBody = parseJsonBody(verifyResponse);
        Assertions.assertThat(verifyResponse.status()).isEqualTo(200);
        Assertions.assertThat(text(verifyBody.get("status")))
                .as("MFA가 완료되어야 이후 보호 리소스 접근이 실제 인증 세션으로 진행된다.")
                .isEqualTo("MFA_COMPLETED");

    }

    private SandboxPromptReplayRound executeProtectedRound(
            SandboxWebSessionClient webSessionClient,
            String username,
            Map<String, String> deviceIdsByAlias,
            String phase,
            String benchmarkRunId,
            SandboxPromptReplayScenario scenario,
            int roundNumber,
            SandboxPromptRoundPlan roundPlan) {
        rearmPendingAnalysisForReplayRound(username, phase);
        sandboxPromptTraceStore.clearAll();

        String requestPath = roundPlan.requestPath();
        String requestId = "sandbox-req-" + phase.toLowerCase(Locale.ROOT) + "-" + UUID.randomUUID();
        String deviceId = deviceIdsByAlias.computeIfAbsent(roundPlan.deviceAlias(), ignored -> UUID.randomUUID().toString());
        Map<String, String> requestHeaders = securityTestHeaders(
                requestId,
                phase,
                benchmarkRunId,
                username,
                deviceId,
                scenario,
                roundPlan);
        SandboxHttpResponse protectedResponse = webSessionClient.get(requestPath, requestHeaders);
        Map<String, Object> responseBody = parseJsonBody(protectedResponse);

        Assertions.assertThat(protectedResponse.status())
                .as("보호 리소스 접근이 200이 아니면 prompt 품질 이전에 실제 HTTP 경로가 깨진 것이다.")
                .isEqualTo(200);

        String effectiveRequestId = text(responseBody.get("requestId"));
        Assertions.assertThat(effectiveRequestId)
                .as("보호 리소스 응답에는 requestId가 있어야 event/prompt/evidence를 하나의 체인으로 추적할 수 있다.")
                .isNotBlank();

        SandboxPromptTraceSnapshot snapshot = resolvePromptTrace(effectiveRequestId);
        return new SandboxPromptReplayRound(
                phase,
                roundNumber,
                roundPlan,
                effectiveRequestId,
                requestPath,
                roundPlan.clientIp(),
                roundPlan.simulatedUserAgentLabel(),
                deviceId,
                responseBody,
                snapshot);
    }

    private void rearmPendingAnalysisForReplayRound(String username, String phase) {
        // 제품 정책상 LLM 분석은 PENDING_ANALYSIS 상태일 때만 진입한다.
        // 따라서 replay 테스트는 이전 round의 memory는 유지하되 현재 사용자 action만 PENDING으로 되돌린다.
        zeroTrustActionRepository.saveActionWithPrevious(username, ZeroTrustAction.PENDING_ANALYSIS);
        Assertions.assertThat(zeroTrustActionRepository.getCurrentAction(username))
                .as("%s 회차 실행 전 현재 action은 반드시 PENDING_ANALYSIS여야 한다.", phase)
                .isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    private SandboxPromptTraceSnapshot resolvePromptTrace(String requestId) {
        try {
            return sandboxPromptTraceStore.await(requestId, traceTimeout);
        } catch (IllegalStateException missingRequestIdTrace) {
            SandboxPromptTraceSnapshot latestSnapshot = sandboxPromptTraceStore.awaitAny(traceTimeout);
            String traceRequestId = extractTraceRequestId(latestSnapshot);
            Assertions.assertThat(traceRequestId)
                    .as("Layer1 전체 완료 뒤 확정된 trace의 requestId는 보호 리소스 응답 requestId와 일치해야 한다.")
                    .isEqualTo(requestId);
            return latestSnapshot;
        }
    }

    private void waitForNextRoundWindow(long cooldownBeforeRoundMs) {
        try {
            Thread.sleep(Math.max(roundCooldown.toMillis(), cooldownBeforeRoundMs));
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for rapid re-entry guard cooldown", interruptedException);
        }
    }

    private Map<String, String> baseBrowserHeaders(String deviceId, SandboxPromptRoundPlan roundPlan) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", "text/html");
        headers.put("User-Agent", roundPlan.browserUserAgent());
        headers.put("X-Device-Id", deviceId);
        return headers;
    }

    private Map<String, String> jsonHeaders(String deviceId, SandboxPromptRoundPlan roundPlan) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", "application/json");
        headers.put("User-Agent", roundPlan.browserUserAgent());
        headers.put("X-Device-Id", deviceId);
        return headers;
    }

    private Map<String, String> formHeaders(String deviceId, SandboxPromptRoundPlan roundPlan) {
        return jsonHeaders(deviceId, roundPlan);
    }

    private Map<String, String> securityTestHeaders(
            String requestId,
            String phase,
            String benchmarkRunId,
            String username,
            String deviceId,
            SandboxPromptReplayScenario scenario,
            SandboxPromptRoundPlan roundPlan) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Accept", "application/json");
        headers.put("User-Agent", roundPlan.browserUserAgent());
        headers.put("X-Contexa-Auth-Mode", "cookie");
        headers.put("X-Contexa-Token-Source", "none");
        headers.put("X-Contexa-Auth-Carrier", "SESSION_COOKIE_ONLY");
        headers.put("X-Contexa-Auth-Subject", username);
        headers.put("X-Contexa-Authorization-Present", "false");
        headers.put("X-Request-ID", requestId);
        headers.put("X-Forwarded-For", roundPlan.clientIp());
        // 브라우저 정적 페이지도 X-Simulated-User-Agent에 raw UA를 보낸다.
        // benchmark harness도 동일 계약을 따라야 currentUserAgentBrowser/OS가
        // 실제 웹 경로와 같은 방식으로 계산된다.
        headers.put("X-Simulated-User-Agent", roundPlan.browserUserAgent());
        headers.put("X-Device-Id", deviceId);
        headers.put("X-Contexa-Scenario", scenario.scenarioHeader());
        headers.put("X-Contexa-Expected-Action", scenario.expectedActionHeader());
        headers.put("X-Contexa-Demo-Run-Id", benchmarkRunId);
        headers.put("X-Contexa-Demo-Phase", phase);
        headers.put("X-Contexa-Round-Key", roundPlan.roundKey());
        headers.put("X-Contexa-Behavior-Phase", roundPlan.behaviorPhase());
        headers.put("X-Contexa-Anomaly-Signal", roundPlan.anomalySignal());
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

    private String extractTraceRequestId(SandboxPromptTraceSnapshot snapshot) {
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

    private String toRelativePath(String url) {
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

    private String extractFormAction(String html, String... formIds) {
        Assertions.assertThat(html).isNotBlank();
        FormSlice formSlice = locateFormSlice(html, formIds);
        int formStart = formSlice.formStart();
        Assertions.assertThat(formStart).isGreaterThanOrEqualTo(0);

        int actionStart = html.indexOf("action=\"", formStart);
        Assertions.assertThat(actionStart).isGreaterThanOrEqualTo(0);

        int valueStart = actionStart + "action=\"".length();
        int valueEnd = html.indexOf('\"', valueStart);
        Assertions.assertThat(valueEnd).isGreaterThan(valueStart);
        return html.substring(valueStart, valueEnd);
    }

    private Map<String, String> extractHiddenInputs(String html, String... formIds) {
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

    private FormSlice locateFormSlice(String html, String... formIds) {
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

    private String extractAttribute(String tag, String attributeName) {
        String marker = attributeName + "=\"";
        int start = tag.indexOf(marker);
        if (start < 0) {
            return null;
        }
        int valueStart = start + marker.length();
        int valueEnd = tag.indexOf('\"', valueStart);
        if (valueEnd < 0) {
            return null;
        }
        return tag.substring(valueStart, valueEnd);
    }

    private String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private SandboxPromptReplayScenario withRoundCount(
            SandboxPromptReplayScenario scenario,
            int roundCount) {
        if (roundCount < 3) {
            throw new IllegalArgumentException("roundCount must be at least 3");
        }
        if (scenario.roundCount() == roundCount) {
            return scenario;
        }
        java.util.ArrayList<SandboxPromptRoundPlan> roundPlans = new java.util.ArrayList<>(roundCount);
        for (int roundIndex = 1; roundIndex <= roundCount; roundIndex++) {
            SandboxPromptRoundPlan sourcePlan = roundIndex <= scenario.roundCount()
                    ? scenario.roundPlanForRound(roundIndex)
                    : scenario.roundPlanForRound(scenario.roundCount());
            roundPlans.add(new SandboxPromptRoundPlan(
                    "R" + roundIndex,
                    sourcePlan.requestPath(),
                    sourcePlan.clientIp(),
                    sourcePlan.browserUserAgent(),
                    sourcePlan.simulatedUserAgentLabel(),
                    sourcePlan.deviceAlias(),
                    sourcePlan.cooldownBeforeRoundMs(),
                    sourcePlan.behaviorPhase(),
                    sourcePlan.anomalySignal(),
                    sourcePlan.expectationNote(),
                    sourcePlan.semanticMarkers()));
        }
        return new SandboxPromptReplayScenario(
                scenario.scenarioKey(),
                scenario.experimentGroup(),
                scenario.scenarioHeader(),
                scenario.expectedActionHeader(),
                scenario.userProfileKey(),
                scenario.scenarioFamily(),
                roundPlans);
    }

    private record FormSlice(int formStart, int formEnd) {
    }
}
