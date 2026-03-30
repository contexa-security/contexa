package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class RequestInfoExtractorTest {

    @Test
    void extractShouldIncludeAuthMethodAndResourceHintsFromRequestAttributes() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/api/security-test/sensitive/resource-001");
        request.addHeader("X-Request-ID", "req-001");
        request.addHeader("X-Simulated-User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        request.setAttribute("hcad.auth_method", "mfa");
        request.setAttribute("hcad.resource_sensitivity", "HIGH");
        request.setAttribute("hcad.resource_business_label", "Sensitive Security Test Resource resource-001");
        request.setAttribute("hcad.mfa_verified", true);

        RequestInfoExtractor.RequestInfo requestInfo =
                RequestInfoExtractor.extract(request, new TieredStrategyProperties().getSecurity());

        assertThat(requestInfo.getAuthMethod()).isEqualTo("mfa");
        assertThat(requestInfo.getResourceSensitivity()).isEqualTo("HIGH");
        assertThat(requestInfo.getResourceBusinessLabel()).isEqualTo("Sensitive Security Test Resource resource-001");
        assertThat(requestInfo.getMfaVerified()).isTrue();
        assertThat(requestInfo.getUserAgent()).contains("Chrome/120");
    }
}
