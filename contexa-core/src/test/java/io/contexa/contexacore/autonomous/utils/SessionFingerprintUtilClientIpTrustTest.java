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
package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacore.properties.TieredStrategyProperties;
import io.contexa.contexacore.verification.runtime.OfficialVerificationProbeHeaders;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The context binding hash binds stored zero trust actions to a session context. Its client IP must
 * follow the trusted proxy rule of {@link RequestInfoExtractor}; otherwise a client could rewrite
 * forwarded headers to detach a stored CHALLENGE or ESCALATE action from its context.
 */
class SessionFingerprintUtilClientIpTrustTest {

    private static final String SESSION_ID = "session-binding-1";
    private static final String USER_AGENT = "Mozilla/5.0 Binding";
    private static final String PROXY_IP = "10.0.0.10";
    private static final String CLIENT_IP = "198.51.100.20";
    private static final String SPOOFED_IP = "203.0.113.99";

    private final List<TieredStrategyProperties> bindings = new ArrayList<>();

    @AfterEach
    void unbind() {
        bindings.forEach(SessionFingerprintUtil::unbindClientIpResolution);
    }

    private TieredStrategyProperties bindTrustedProxies(String... trustedProxies) {
        TieredStrategyProperties properties = new TieredStrategyProperties();
        properties.getSecurity().setTrustedProxies(List.of(trustedProxies));
        SessionFingerprintUtil.bindClientIpResolution(properties);
        bindings.add(properties);
        return properties;
    }

    private static MockHttpServletRequest request(String remoteAddr, String forwardedFor) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/orders/42");
        request.setRemoteAddr(remoteAddr);
        request.setRequestedSessionId(SESSION_ID);
        request.addHeader("User-Agent", USER_AGENT);
        if (forwardedFor != null) {
            request.addHeader("X-Forwarded-For", forwardedFor);
            request.addHeader("X-Real-IP", forwardedFor);
        }
        return request;
    }

    private static String expectedHash(String clientIp) {
        return SessionFingerprintUtil.generateContextBindingHash(SESSION_ID, clientIp, USER_AGENT);
    }

    @Test
    @DisplayName("Without trusted proxies a forwarded header cannot change the binding hash")
    void untrustedForwardedHeaderDoesNotChangeHash() {
        String direct = SessionFingerprintUtil.generateContextBindingHash(request(CLIENT_IP, null));
        String spoofed = SessionFingerprintUtil.generateContextBindingHash(request(CLIENT_IP, SPOOFED_IP));

        assertThat(spoofed).isEqualTo(direct).isEqualTo(expectedHash(CLIENT_IP));
        assertThat(SessionFingerprintUtil.extractClientIp(request(CLIENT_IP, SPOOFED_IP))).isEqualTo(CLIENT_IP);
    }

    @Test
    @DisplayName("A peer outside the trusted proxies cannot change the binding hash")
    void peerOutsideTrustedProxiesIsIgnored() {
        bindTrustedProxies("10.0.0.0/8");

        String spoofed = SessionFingerprintUtil.generateContextBindingHash(request("192.0.2.5", SPOOFED_IP));

        assertThat(spoofed).isEqualTo(expectedHash("192.0.2.5"));
    }

    @Test
    @DisplayName("A trusted proxy forwards the client IP into the binding hash")
    void trustedProxyForwardsClientIp() {
        bindTrustedProxies("10.0.0.0/8");

        String hash = SessionFingerprintUtil.generateContextBindingHash(
                request(PROXY_IP, CLIENT_IP + ", " + PROXY_IP));

        assertThat(hash).isEqualTo(expectedHash(CLIENT_IP)).isNotEqualTo(expectedHash(PROXY_IP));
    }

    @Test
    @DisplayName("Disabling trusted proxy validation keeps the legacy forwarded header resolution")
    void disabledValidationKeepsLegacyResolution() {
        TieredStrategyProperties properties = bindTrustedProxies();
        properties.getSecurity().setTrustedProxyValidationEnabled(false);

        String hash = SessionFingerprintUtil.generateContextBindingHash(request(PROXY_IP, CLIENT_IP));

        assertThat(hash).isEqualTo(expectedHash(CLIENT_IP));
    }

    @Test
    @DisplayName("A probe carrying the server issued capability keeps its simulated client IP")
    void serverIssuedProbeKeepsSimulatedClientIp() {
        MockHttpServletRequest request = request(PROXY_IP, CLIENT_IP);
        OfficialVerificationProbeHeaders headers = new OfficialVerificationProbeHeaders();
        headers.setRuntimeOverrideCapability();
        headers.asMap().forEach(request::addHeader);

        assertThat(SessionFingerprintUtil.extractClientIp(request))
                .isEqualTo(RequestInfoExtractor.extractClientIp(request, new TieredStrategyProperties().getSecurity()))
                .isEqualTo(CLIENT_IP);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    @DisplayName("Event publisher, enforcement fallback, filters and authentication handlers agree on one hash")
    void everyCallerComputesTheSameHash(boolean behindTrustedProxy) {
        TieredStrategyProperties properties = behindTrustedProxy
                ? bindTrustedProxies("10.0.0.0/8")
                : bindTrustedProxies();
        String forwardedFor = behindTrustedProxy ? CLIENT_IP : SPOOFED_IP;

        RequestInfoExtractor.RequestInfo requestInfo = RequestInfoExtractor.extract(
                request(PROXY_IP, forwardedFor), properties.getSecurity());
        String filterHash = SessionFingerprintUtil.generateContextBindingHash(request(PROXY_IP, forwardedFor));
        String eventFallbackHash = SessionFingerprintUtil.generateContextBindingHash(
                requestInfo.getSessionId(), requestInfo.getClientIp(), requestInfo.getUserAgent());
        String authenticationEventIp = SessionFingerprintUtil.extractClientIp(request(PROXY_IP, forwardedFor));

        String expectedIp = behindTrustedProxy ? CLIENT_IP : PROXY_IP;
        assertThat(requestInfo.getClientIp()).isEqualTo(expectedIp);
        assertThat(authenticationEventIp).isEqualTo(expectedIp);
        assertThat(requestInfo.getContextBindingHash())
                .isEqualTo(filterHash)
                .isEqualTo(eventFallbackHash)
                .isEqualTo(expectedHash(expectedIp));
    }

    @Test
    @DisplayName("Unbinding an older context keeps the binding of a newer context")
    void unbindKeepsNewerBinding() {
        TieredStrategyProperties older = bindTrustedProxies();
        bindTrustedProxies("10.0.0.0/8");

        SessionFingerprintUtil.unbindClientIpResolution(older);

        assertThat(SessionFingerprintUtil.extractClientIp(request(PROXY_IP, CLIENT_IP))).isEqualTo(CLIENT_IP);
    }
}
