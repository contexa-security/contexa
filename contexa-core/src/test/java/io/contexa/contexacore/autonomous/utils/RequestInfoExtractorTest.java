package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageLevel;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageReport;
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationEffect;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RequestInfoExtractorTest {

    @Test
    @DisplayName("request attributes previousPath and interval should seed session narrative metadata")
    void extractShouldIncludeAuthMethodAndResourceHintsFromRequestAttributes() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-001");
        request.addHeader("X-Simulated-User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        request.setAttribute("hcad.auth_method", "mfa");
        request.setAttribute("hcad.resource_sensitivity", "HIGH");
        request.setAttribute("hcad.resource_business_label", "Sensitive Security Test Resource resource-001");
        request.setAttribute("hcad.mfa_verified", true);
        request.setAttribute("hcad.previous_path", "/admin/api/security-test/sensitive/resource-000");
        request.setAttribute("hcad.last_request_interval_ms", 4_200L);

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getAuthMethod()).isEqualTo("mfa");
        assertThat(requestInfo.getResourceSensitivity()).isEqualTo("HIGH");
        assertThat(requestInfo.getResourceBusinessLabel()).isEqualTo("Sensitive Security Test Resource resource-001");
        assertThat(requestInfo.getMfaVerified()).isTrue();
        assertThat(requestInfo.getPreviousPath()).isEqualTo("/admin/api/security-test/sensitive/resource-000");
        assertThat(requestInfo.getLastRequestIntervalMs()).isEqualTo(4_200L);
        assertThat(requestInfo.getUserAgent()).contains("Chrome/120");
    }

    @Test
    @DisplayName("bridge stamped request attributes should rehydrate a resolution result when the aggregate object is absent")
    void extractShouldRehydrateBridgeResolutionResultFromStampedRequestAttributes() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/reports/export");
        request.addHeader("X-Request-ID", "req-bridge-fallback");
        request.addHeader("User-Agent", "JUnit");
        request.setRequestedSessionId("session-bridge");
        request.setRemoteAddr("203.0.113.30");
        request.setAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP,
                new AuthenticationStamp("alice", "Alice", "USER", true, "JWT", "HEADER", "HIGH", true, Instant.parse("2026-04-04T01:00:00Z"), "session-bridge", List.of("ROLE_USER"), Map.of("organizationId", "tenant-a")));
        request.setAttribute(BridgeRequestAttributes.AUTHORIZATION_STAMP,
                new AuthorizationStamp("alice", "/reports/export", "GET", AuthorizationEffect.ALLOW, true, List.of("report:export"), "policy-1", null, "HEADER", Instant.parse("2026-04-04T01:00:01Z"), List.of("ROLE_USER"), List.of("REPORT_EXPORT"), Map.of()));
        request.setAttribute(BridgeRequestAttributes.COVERAGE_REPORT,
                new BridgeCoverageReport(BridgeCoverageLevel.AUTHORIZATION_CONTEXT, 85, Set.of(MissingBridgeContext.DELEGATION), "Bridge completeness reached authentication and authorization context for the current request.", List.of("Populate delegated execution metadata when the request acts under delegated scope.")));

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getBridgeResolutionResult()).isNotNull();
        assertThat(requestInfo.getBridgeResolutionResult().authenticationStamp()).isNotNull();
        assertThat(requestInfo.getBridgeResolutionResult().authorizationStamp()).isNotNull();
        assertThat(requestInfo.getBridgeResolutionResult().coverageReport()).isNotNull();
        assertThat(requestInfo.getBridgeResolutionResult().requestContext()).isNotNull();
        assertThat(requestInfo.getBridgeResolutionResult().requestContext().requestUri()).isEqualTo("/reports/export");
        assertThat(requestInfo.getBridgeResolutionResult().requestContext().requestId()).isEqualTo("req-bridge-fallback");
        assertThat(requestInfo.getBridgeResolutionResult().coverageReport().missingContexts()).contains(MissingBridgeContext.DELEGATION);
    }

    @Test
    @DisplayName("observed-at header should populate request info observedAt")
    void extractShouldIncludeObservedAtFromHeaders() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-observed-at");
        request.addHeader("X-Contexa-Observed-At", "2026-02-03T09:15:00+09:00");

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getObservedAt()).isNotNull();
        assertThat(requestInfo.getObservedAt().toString()).isEqualTo("2026-02-03T00:15:00Z");
    }

    @Test
    @DisplayName("prompt budget profile header should flow into request info")
    void extractShouldIncludePromptBudgetProfileFromHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-budget-profile");
        request.addHeader("X-Contexa-Prompt-Budget-Profile", "CORTEX_L1_COMPACT");

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getPromptBudgetProfile()).isEqualTo("CORTEX_L1_COMPACT");
    }

    @Test
    @DisplayName("official verification runtime headers should flow into request info")
    void extractShouldIncludeOfficialVerificationRuntimeHeaders() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/enterprise/verification/runtime/probe/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-ov-runtime");
        request.addHeader("X-Contexa-Official-Verification-Model-Id", "qwen3:8b");
        request.addHeader("X-Contexa-Official-Verification-Temperature", "0.0");
        request.addHeader("X-Contexa-Official-Verification-Top-P", "0.2");
        request.addHeader("X-Contexa-Official-Verification-Seed", "7");
        request.addHeader("X-Contexa-Official-Verification-Max-Tokens", "96");
        request.addHeader("X-Contexa-Official-Verification-Disable-Retries", "true");
        request.addHeader("X-Contexa-Official-Verification-Disable-Ollama-Thinking", "true");

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getOfficialVerificationDecisionBoundaryMode()).isEqualTo("OFFICIAL_VERIFICATION_RUNTIME");
        assertThat(requestInfo.getOfficialVerificationPinnedModelId()).isEqualTo("qwen3:8b");
        assertThat(requestInfo.getOfficialVerificationTemperature()).isEqualTo(0.0d);
        assertThat(requestInfo.getOfficialVerificationTopP()).isEqualTo(0.2d);
        assertThat(requestInfo.getOfficialVerificationSeed()).isEqualTo(7);
        assertThat(requestInfo.getOfficialVerificationMaxTokens()).isEqualTo(96);
        assertThat(requestInfo.getOfficialVerificationDisableRetries()).isTrue();
        assertThat(requestInfo.getOfficialVerificationDisableOllamaThinking()).isTrue();
    }

    @Test
    @DisplayName("official verification runtime attributes should backfill request info when headers are absent")
    void extractShouldIncludeOfficialVerificationRuntimeAttributesWhenHeadersAreMissing() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/enterprise/verification/runtime/probe/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-ov-runtime-attr");
        request.setAttribute("officialVerificationPinnedModelId", "qwen3:8b");
        request.setAttribute("officialVerificationTemperature", "0.0");
        request.setAttribute("officialVerificationTopP", "0.2");
        request.setAttribute("officialVerificationSeed", "7");
        request.setAttribute("officialVerificationMaxTokens", "96");

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getOfficialVerificationDecisionBoundaryMode()).isEqualTo("OFFICIAL_VERIFICATION_RUNTIME");
        assertThat(requestInfo.getOfficialVerificationPinnedModelId()).isEqualTo("qwen3:8b");
        assertThat(requestInfo.getOfficialVerificationTemperature()).isEqualTo(0.0d);
        assertThat(requestInfo.getOfficialVerificationTopP()).isEqualTo(0.2d);
        assertThat(requestInfo.getOfficialVerificationSeed()).isEqualTo(7);
        assertThat(requestInfo.getOfficialVerificationMaxTokens()).isEqualTo(96);
    }
}
