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
 * sandbox full-stack replay ?????덊떀??
 *
 * ?????β뼯援㏆쭕????紐꾪닓 ???⑥ル츥??????????썹땟?????됱삩? ????? ??嶺뚮Ĳ?됭짆?????⑤㈇??????????⑥ル츥?????? ????怨뺣윞??HTTP/MFA/?癲ル슢??????????????썹땟???
 * ????산뭐??????????????event/sessionCtx/behaviorCtx/relatedDocuments/prompt?????繹먮냱議??????雅?????
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
                SandboxPromptReplayScenarioCatalog.resizeScenario(
                        SandboxPromptReplayScenarioCatalog.ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE,
                        3));
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
                SandboxPromptReplayScenarioCatalog.resizeScenario(
                        SandboxPromptReplayScenarioCatalog.ADMIN_SENSITIVE_BASELINE_THEN_CRITICAL_SURGE,
                        roundCount));
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

        Map<String, String> deviceIdsByAlias = new HashMap<>();
        SandboxWebSessionClient webSessionClient = null;

        List<SandboxPromptReplayRound> rounds = new java.util.ArrayList<>(scenario.roundCount());
        for (int roundNumber = 1; roundNumber <= scenario.roundCount(); roundNumber++) {
            String phase = roundNumber == 1 ? "INITIAL" : "FOLLOW_UP";
            SandboxPromptRoundPlan roundPlan = scenario.roundPlanForRound(roundNumber);
            if (roundNumber > 1) {
                waitForNextRoundWindow(roundPlan.cooldownBeforeRoundMs());
            }
            String deviceId = deviceIdsByAlias.computeIfAbsent(
                    roundPlan.deviceAlias(),
                    ignored -> UUID.randomUUID().toString());
            if (webSessionClient == null || roundPlan.startsNewSession()) {
                preparePendingAnalysisForAuthentication(username, phase);
                webSessionClient = new SandboxWebSessionClient(baseUrl, httpTimeout);
                authenticateUsingRealOttMfa(webSessionClient, username, password, scenario, roundPlan, deviceId);
            }
            rounds.add(executeProtectedRound(
                    webSessionClient,
                    username,
                    deviceId,
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
                .as("1???癲ル슢???먥꼻?? ?熬곣뫖利??レ벁???MFA_REQUIRED ??影??낟??????븐뻤????熬곣뫖利??????ㅿ폑?????ш끽維?????繹먮냱議?MFA ?嚥▲굧???뚪뜮?熬곣벀嫄??????????딅젩.")
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
                .as("factor ????ｋ?????ш끽維??nextStepUrl??????⑥ろ맖?????⑥ル츥?????? ????怨뺣윞?????繹먮굞?????됰Ŧ六????????????????????딅젩.")
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
                .as("OTT code generation?? challenge ???됰Ŧ六?????Β??redirect??嶺뚮슣??땻????嶺뚮㉡???")
                .isIn(302, 303);

        String latestOttCode = sandboxOttCodeCapture.awaitLatestCode(username, Duration.ofSeconds(10));
        Assertions.assertThat(latestOttCode)
                .as("sandbox OTT capture??醫딆쓧? ????猷뱀쟼????繹먮겧嫄х솾????繹먮냱議?HTTP MFA ???????????? ?꿔꺂??쭫?묒쒜????嚥▲굧?????")
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
                .as("MFA??醫딆쓧? ????썹땟???嶺뚮슣??땻?????ш끽維????⑤슢??????잙갭큔?딆뼇???????뗫떔??????繹먮냱議??癲ル슢???먥꼻??癲ル슢???????Β???꿔꺂????紐꾩뗄??嶺뚮㉡???")
                .isEqualTo("MFA_COMPLETED");

    }

    private SandboxPromptReplayRound executeProtectedRound(
            SandboxWebSessionClient webSessionClient,
            String username,
            String deviceId,
            String phase,
            String benchmarkRunId,
            SandboxPromptReplayScenario scenario,
            int roundNumber,
            SandboxPromptRoundPlan roundPlan) {
        rearmPendingAnalysisForReplayRound(username, phase);
        sandboxPromptTraceStore.clearAll();

        String requestPath = roundPlan.requestPath();
        String requestId = "sandbox-req-" + phase.toLowerCase(Locale.ROOT) + "-" + UUID.randomUUID();
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
                .as("??⑤슢??????잙갭큔?딆뼇???????뗫떔???200??????썹땟????ㅷ빊?prompt ???繹먮끏堉?????ㅼ굣??????繹먮냱議?HTTP ?嚥▲굧???뚪뜮?域민쇱?? ?μ떜媛?力?????嚥▲굧?????")
                .isEqualTo(200);

        String effectiveRequestId = text(responseBody.get("requestId"));
        Assertions.assertThat(effectiveRequestId)
                .as("??⑤슢??????잙갭큔?딆뼇??????????????requestId??醫딆쓧? ????⑥ろ맖??event/prompt/evidence?????β뼯援η뙴???꿔꺂????????Β?????ㅻ쿋驪??????????딅젩.")
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
        // ???? ?癲ル슢캉????LLM ???곗뒩泳??? PENDING_ANALYSIS ????븐뻤?????????꿔꺂??????嶺뚮㉡???
        // ????산뭐???replay ?????癲ル슢??蹂?쭍?????ㅼ굣??round??memory????????β뼯源닻?????썹땟???????action??PENDING????Β?????β뼯爰??濚밸Þ????
        zeroTrustActionRepository.saveActionWithPrevious(username, ZeroTrustAction.PENDING_ANALYSIS);
        Assertions.assertThat(zeroTrustActionRepository.getCurrentAction(username))
                .as("%s ??????????덊떀 ??????썹땟??action?? ?熬곣뫖利??レ벁???PENDING_ANALYSIS??????嶺뚮㉡???", phase)
                .isEqualTo(ZeroTrustAction.PENDING_ANALYSIS);
    }

    private void preparePendingAnalysisForAuthentication(String username, String phase) {
        zeroTrustActionRepository.removeAllUserData(username);
        rearmPendingAnalysisForReplayRound(username, phase + "_AUTH");
    }

    private SandboxPromptTraceSnapshot resolvePromptTrace(String requestId) {
        try {
            return sandboxPromptTraceStore.await(requestId, traceTimeout);
        } catch (IllegalStateException missingRequestIdTrace) {
            SandboxPromptTraceSnapshot latestSnapshot = sandboxPromptTraceStore.awaitAny(traceTimeout);
            String traceRequestId = extractTraceRequestId(latestSnapshot);
            Assertions.assertThat(traceRequestId)
                    .as("Layer1 ????썹땟??????썹땟?????癲ル슢캉????trace??requestId????⑤슢??????잙갭큔?딆뼇??????????requestId?? ??濚밸Ŧ遊얕맱????ㅿ폑????嶺뚮㉡???")
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
        // ???⑥ル츥???? ?癲ル슢캉???????볥궙?袁р뵾??????X-Simulated-User-Agent??raw UA????⑤슢?????
        // benchmark harness??????怨뺣윞 ??影??낟???????산뭐???currentUserAgentBrowser/OS??醫딆쓧?
        // ???繹먮냱議????嚥▲굧???뚪뜮?? ??醫딆┻?? ?熬곣뫖?삥납?????Β????影??낟???嶺뚮㉡???
        headers.put("X-Simulated-User-Agent", roundPlan.browserUserAgent());
        headers.put("X-Simulated-User-Agent-Label", roundPlan.simulatedUserAgentLabel());
        headers.put("X-Device-Id", deviceId);
        headers.put("X-Contexa-Observed-At", roundPlan.observedAt().toString());
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
    private record FormSlice(int formStart, int formEnd) {
    }
}
