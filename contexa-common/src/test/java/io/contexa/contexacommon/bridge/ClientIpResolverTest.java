package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.network.ClientIpResolutionPolicy;
import io.contexa.contexacommon.security.network.ClientIpResolver;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIpResolverTest {

    @Test
    void trustedProxyPolicyShouldIgnoreForwardedHeaderWhenTrustedProxyListIsEmpty() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setRemoteAddr("10.0.0.10");
        request.addHeader("X-Forwarded-For", "203.0.113.10");

        String clientIp = ClientIpResolver.resolve(request, ClientIpResolutionPolicy.trustedProxy(List.of()));

        assertThat(clientIp).isEqualTo("10.0.0.10");
    }

    @Test
    void trustedProxyPolicyShouldResolveForwardedHeaderFromTrustedCidr() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setRemoteAddr("10.0.0.10");
        request.addHeader("X-Forwarded-For", "203.0.113.10, 10.0.0.10");

        String clientIp = ClientIpResolver.resolve(
                request,
                ClientIpResolutionPolicy.trustedProxy(List.of("10.0.0.0/24")));

        assertThat(clientIp).isEqualTo("203.0.113.10");
    }

    @Test
    void legacyPolicyShouldPreserveExistingForwardedHeaderCompatibility() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setRemoteAddr("10.0.0.10");
        request.addHeader("X-Forwarded-For", "unknown");
        request.addHeader("X-Real-IP", "203.0.113.20");

        String clientIp = ClientIpResolver.resolve(request, ClientIpResolutionPolicy.legacyForwardedHeaders());

        assertThat(clientIp).isEqualTo("203.0.113.20");
    }
}
