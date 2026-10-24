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

import io.contexa.contexacommon.domain.SecurityEvent;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionFingerprintUtilTest {

    @Mock
    private HttpServletRequest request;

    @Test
    @DisplayName("generateFingerprint for SecurityEvent should generate consistent hash")
    void testSecurityEventFingerprint() {
        SecurityEvent event = mock(SecurityEvent.class);
        when(event.getUserAgent()).thenReturn("Mozilla/5.0");
        when(event.getSourceIp()).thenReturn("192.168.0.1");
        when(event.getLocalTimestamp()).thenReturn(LocalDateTime.of(2026, 6, 15, 14, 0));

        String fp1 = SessionFingerprintUtil.generateFingerprint(event);
        String fp2 = SessionFingerprintUtil.generateFingerprint(event);

        assertThat(fp1).isEqualTo(fp2);
        assertThat(fp1).isNotEqualTo("UNKNOWN");
    }

    @Test
    @DisplayName("generateFingerprint for null SecurityEvent returns UNKNOWN")
    void testSecurityEventFingerprintNull() {
        String fp = SessionFingerprintUtil.generateFingerprint((SecurityEvent) null);
        assertThat(fp).isEqualTo("UNKNOWN");
    }

    @Test
    @DisplayName("generateContextBindingHash returns consistent hash for same input")
    void testContextBindingHash() {
        String h1 = SessionFingerprintUtil.generateContextBindingHash("sess-1", "127.0.0.1", "Agent");
        String h2 = SessionFingerprintUtil.generateContextBindingHash("sess-1", "127.0.0.1", "Agent");

        assertThat(h1).isEqualTo(h2);
    }

    @Test
    @DisplayName("generateContextBindingHash returns different hash if IP changes")
    void testContextBindingHashDifferentIp() {
        String h1 = SessionFingerprintUtil.generateContextBindingHash("sess-1", "127.0.0.1", "Agent");
        String h2 = SessionFingerprintUtil.generateContextBindingHash("sess-1", "10.0.0.1", "Agent");

        assertThat(h1).isNotEqualTo(h2);
    }

    @Test
    @DisplayName("generateContextBindingHash for HttpServletRequest caches hash in attributes")
    void testContextBindingHashCaching() {
        when(request.getRequestedSessionId()).thenReturn("session-xyz");
        when(request.getRemoteAddr()).thenReturn("192.168.1.10");
        when(request.getHeader(anyString())).thenAnswer(invocation ->
                "User-Agent".equals(invocation.getArgument(0)) ? "Mozilla/5.0" : null);
        when(request.getAttribute("contexa.contextBindingHash")).thenReturn(null);

        String hash = SessionFingerprintUtil.generateContextBindingHash(request);

        assertThat(hash).isNotNull();
        verify(request).setAttribute("contexa.contextBindingHash", hash);
    }

    @Test
    @DisplayName("generateNextRequestContextBindingHash follows a session id rotated during the request")
    void nextRequestHashFollowsRotatedSession() {
        HttpSession rotated = mock(HttpSession.class);
        when(rotated.getId()).thenReturn("rotated-session");
        when(request.getSession(false)).thenReturn(rotated);
        when(request.getRemoteAddr()).thenReturn("192.168.1.10");
        when(request.getHeader(anyString())).thenAnswer(invocation ->
                "User-Agent".equals(invocation.getArgument(0)) ? "Mozilla/5.0" : null);

        String next = SessionFingerprintUtil.generateNextRequestContextBindingHash(request);

        assertThat(next).isEqualTo(
                SessionFingerprintUtil.generateContextBindingHash("rotated-session", "192.168.1.10", "Mozilla/5.0"));
        verify(request, never()).getRequestedSessionId();
    }

    @Test
    @DisplayName("generateNextRequestContextBindingHash keeps the requested session id without a session")
    void nextRequestHashKeepsRequestedSessionWithoutSession() {
        when(request.getSession(false)).thenReturn(null);
        when(request.getRequestedSessionId()).thenReturn("session-xyz");
        when(request.getRemoteAddr()).thenReturn("192.168.1.10");
        when(request.getHeader(anyString())).thenAnswer(invocation ->
                "User-Agent".equals(invocation.getArgument(0)) ? "Mozilla/5.0" : null);

        String next = SessionFingerprintUtil.generateNextRequestContextBindingHash(request);

        assertThat(next).isEqualTo(
                SessionFingerprintUtil.generateContextBindingHash("session-xyz", "192.168.1.10", "Mozilla/5.0"));
    }

    @Test
    @DisplayName("A1-11: agents on one network and one user agent get their own context binding")
    void agentsOnOneNetworkGetTheirOwnBinding() {
        try {
            String first = bindingFor("report-client");
            String second = bindingFor("batch-client");
            SecurityContextHolder.clearContext();
            MockHttpServletRequest person = new MockHttpServletRequest();
            person.setRemoteAddr("10.0.0.5");
            person.addHeader("User-Agent", "agent-runtime/1.0");
            person.setRequestedSessionId("session-1");

            assertThat(first).isNotEqualTo(second);
            assertThat(SessionFingerprintUtil.generateContextBindingHash(person))
                    .isEqualTo(SessionFingerprintUtil.generateContextBindingHash("session-1", "10.0.0.5", "agent-runtime/1.0"));
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * A session's security context is loaded on its first read, and loading it computes the binding (the zero trust
     * check of AISessionSecurityContextRepository). The binding read the context to find an agent's session (A1-11),
     * which loaded it again: the people's one-time code request failed with a StackOverflowError (A7-0).
     */
    @Test
    @DisplayName("A1-11: computing the binding while the security context loads does not load it again")
    void bindingWhileTheContextLoadsDoesNotLoadItAgain() {
        MockHttpServletRequest request = agentRequest();
        JwtAuthenticationToken agent = clientToken("report-client");
        AtomicInteger loads = new AtomicInteger();
        try {
            SecurityContextHolder.setDeferredContext(() -> {
                loads.incrementAndGet();
                SessionFingerprintUtil.generateContextBindingHash(request);
                return new SecurityContextImpl(agent);
            });

            String binding = SessionFingerprintUtil.generateContextBindingHash(request);

            assertThat(loads).hasValue(1);
            assertThat(binding).isEqualTo(SessionFingerprintUtil.generateContextBindingHash(agentRequest(), agent))
                    .isNotEqualTo(SessionFingerprintUtil.generateContextBindingHash("session-1", "10.0.0.5",
                            "agent-runtime/1.0"));
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    @DisplayName("A1-11: the binding of a given authentication never reads the security context")
    void bindingOfAGivenAuthenticationDoesNotReadTheContext() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.5");
        request.addHeader("User-Agent", "agent-runtime/1.0");
        try {
            SecurityContextHolder.setDeferredContext(() -> {
                throw new AssertionError("the security context was read");
            });

            assertThat(SessionFingerprintUtil.generateContextBindingHash(request, clientToken("report-client")))
                    .isNotNull();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private static MockHttpServletRequest agentRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.5");
        request.addHeader("User-Agent", "agent-runtime/1.0");
        request.setRequestedSessionId("session-1");
        return request;
    }

    private static JwtAuthenticationToken clientToken(String clientId) {
        Instant now = Instant.now();
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject(clientId).claim("client_id", clientId)
                .claim("jti", "token-1").issuedAt(now).expiresAt(now.plusSeconds(300)).build();
        return new JwtAuthenticationToken(jwt, List.of());
    }

    private static String bindingFor(String clientId) {
        SecurityContextHolder.getContext().setAuthentication(clientToken(clientId));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.5");
        request.addHeader("User-Agent", "agent-runtime/1.0");
        return SessionFingerprintUtil.generateContextBindingHash(request);
    }
}
