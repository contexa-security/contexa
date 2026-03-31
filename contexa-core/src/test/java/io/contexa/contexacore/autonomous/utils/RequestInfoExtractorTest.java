package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

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
        // Without previousPath/interval, Layer1 session narrative can only describe the current request.
        assertThat(requestInfo.getPreviousPath()).isEqualTo("/admin/api/security-test/sensitive/resource-000");
        assertThat(requestInfo.getLastRequestIntervalMs()).isEqualTo(4_200L);
        assertThat(requestInfo.getUserAgent()).contains("Chrome/120");
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
}