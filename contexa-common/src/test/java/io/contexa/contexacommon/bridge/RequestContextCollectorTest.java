package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextSnapshot;
import io.contexa.contexacommon.security.network.ClientIpResolutionPolicy;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RequestContextCollectorTest {

    @Test
    void defaultCollectorShouldIgnoreForwardedHeaderWhenTrustedProxyIsNotConfigured() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setRemoteAddr("10.0.0.10");
        request.addHeader("X-Forwarded-For", "203.0.113.10, 10.0.0.10");

        RequestContextSnapshot snapshot = new RequestContextCollector().collect(request);

        assertThat(snapshot.clientIp()).isEqualTo("10.0.0.10");
    }

    @Test
    void collectorShouldUseForwardedHeaderWhenRemoteAddressIsTrustedProxy() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setRemoteAddr("10.0.0.10");
        request.addHeader("X-Forwarded-For", "203.0.113.10, 10.0.0.10");

        RequestContextCollector collector = new RequestContextCollector(
                ClientIpResolutionPolicy.trustedProxy(List.of("10.0.0.0/24")));

        RequestContextSnapshot snapshot = collector.collect(request);

        assertThat(snapshot.clientIp()).isEqualTo("203.0.113.10");
    }
}
