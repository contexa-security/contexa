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
        request.setAttribute("currentResourceFamily", "SENSITIVE");
        request.setAttribute("currentActionFamily", "READ");
        request.setAttribute("expectedResourceFamilies", List.of("SENSITIVE"));
        request.setAttribute("expectedActionFamilies", List.of("READ"));
        request.setAttribute("recentPermissionChanges", List.of("NONE_RECORDED"));
        request.setAttribute("approvalRequired", false);
        request.setAttribute("approvalGranted", false);
        request.setAttribute("approvalMissing", false);
        request.setAttribute("approvalStatus", "NOT_APPLICABLE");
        request.setAttribute("delegated", false);
        request.setAttribute("objectiveDrift", false);
        request.setAttribute("objectiveDriftSummary", "NOT_APPLICABLE: direct user request is not delegated.");

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getAuthMethod()).isEqualTo("mfa");
        assertThat(requestInfo.getResourceSensitivity()).isEqualTo("HIGH");
        assertThat(requestInfo.getResourceBusinessLabel()).isEqualTo("Sensitive Security Test Resource resource-001");
        assertThat(requestInfo.getMfaVerified()).isTrue();
        assertThat(requestInfo.getPreviousPath()).isEqualTo("/admin/api/security-test/sensitive/resource-000");
        assertThat(requestInfo.getLastRequestIntervalMs()).isEqualTo(4_200L);
        assertThat(requestInfo.getUserAgent()).contains("Chrome/120");
        assertThat(requestInfo.getCurrentResourceFamily()).isEqualTo("SENSITIVE");
        assertThat(requestInfo.getCurrentActionFamily()).isEqualTo("READ");
        assertThat(requestInfo.getExpectedResourceFamilies()).containsExactly("SENSITIVE");
        assertThat(requestInfo.getExpectedActionFamilies()).containsExactly("READ");
        assertThat(requestInfo.getRecentPermissionChanges()).containsExactly("NONE_RECORDED");
        assertThat(requestInfo.getApprovalRequired()).isFalse();
        assertThat(requestInfo.getApprovalGranted()).isFalse();
        assertThat(requestInfo.getApprovalMissing()).isFalse();
        assertThat(requestInfo.getApprovalStatus()).isEqualTo("NOT_APPLICABLE");
        assertThat(requestInfo.getDelegated()).isFalse();
        assertThat(requestInfo.getObjectiveDrift()).isFalse();
        assertThat(requestInfo.getObjectiveDriftSummary()).isEqualTo("NOT_APPLICABLE: direct user request is not delegated.");
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
    @DisplayName("generic requested model header should flow into request info")
    void extractShouldIncludeRequestedModelIdFromGenericHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-generic-model");
        request.addHeader("X-Contexa-Model-Id", "qwen2.5:7b");

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getRequestedModelId()).isEqualTo("qwen2.5:7b");
    }

    @Test
    @DisplayName("canonical runtime headers should flow into request info")
    void extractShouldIncludeCanonicalRuntimeHeaders() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-runtime-selection");
        request.addHeader("X-Contexa-Model-Id", "qwen3:8b");
        request.addHeader("X-Contexa-Temperature", "0.0");
        request.addHeader("X-Contexa-Top-P", "0.2");
        request.addHeader("X-Contexa-Seed", "7");
        request.addHeader("X-Contexa-Max-Tokens", "96");
        request.addHeader("X-Contexa-Disable-Retries", "true");
        request.addHeader("X-Contexa-Disable-Ollama-Thinking", "true");

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getDecisionBoundaryMode()).isEqualTo("RUNTIME_MODEL_SELECTION");
        assertThat(requestInfo.getRequestedModelId()).isEqualTo("qwen3:8b");
        assertThat(requestInfo.getRuntimeTemperature()).isEqualTo(0.0d);
        assertThat(requestInfo.getRuntimeTopP()).isEqualTo(0.2d);
        assertThat(requestInfo.getRuntimeSeed()).isEqualTo(7);
        assertThat(requestInfo.getRuntimeMaxTokens()).isEqualTo(96);
        assertThat(requestInfo.getRuntimeDisableRetries()).isTrue();
        assertThat(requestInfo.getRuntimeDisableOllamaThinking()).isTrue();
    }

    @Test
    @DisplayName("canonical runtime attributes should backfill request info when headers are absent")
    void extractShouldIncludeCanonicalRuntimeAttributesWhenHeadersAreMissing() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-runtime-selection-attr");
        request.setAttribute("requestedModelId", "qwen3:8b");
        request.setAttribute("temperature", "0.0");
        request.setAttribute("topP", "0.2");
        request.setAttribute("seed", "7");
        request.setAttribute("maxTokens", "96");
        request.setAttribute("disableRetries", true);
        request.setAttribute("disableOllamaThinking", true);

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getDecisionBoundaryMode()).isEqualTo("RUNTIME_MODEL_SELECTION");
        assertThat(requestInfo.getRequestedModelId()).isEqualTo("qwen3:8b");
        assertThat(requestInfo.getRuntimeTemperature()).isEqualTo(0.0d);
        assertThat(requestInfo.getRuntimeTopP()).isEqualTo(0.2d);
        assertThat(requestInfo.getRuntimeSeed()).isEqualTo(7);
        assertThat(requestInfo.getRuntimeMaxTokens()).isEqualTo(96);
        assertThat(requestInfo.getRuntimeDisableRetries()).isTrue();
        assertThat(requestInfo.getRuntimeDisableOllamaThinking()).isTrue();
    }

    @Test
    @DisplayName("organization scope hints should flow into request info")
    void extractShouldIncludeOrganizationScopeFromGenericRequestAttributes() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-org-scope");
        request.setAttribute("organizationId", "tenant-acme");

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getOrganizationId()).isEqualTo("tenant-acme");
    }
}
