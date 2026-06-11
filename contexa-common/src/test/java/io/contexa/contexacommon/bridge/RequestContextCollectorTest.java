/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
