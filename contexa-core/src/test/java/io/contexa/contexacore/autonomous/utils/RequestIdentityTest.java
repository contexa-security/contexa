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

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W1-21: the session identifier the engine gives a request. A token (OAuth2) request is identified by the login its
 * token carries (claim sid), with or without an HTTP session; a request whose identity names its sign-in (bridge v2,
 * the session key of an application without sessions) by that sign-in; any other request by its HTTP session. No
 * request attribute of the client names the session (R4-C9: the synthetic session attribute of the verification probes
 * is gone).
 */
class RequestIdentityTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void aTokenRequestIsIdentifiedByTheLoginItsTokenCarries() {
        SecurityContextHolder.getContext().setAuthentication(token("login-1"));

        assertThat(RequestIdentity.sessionId(new MockHttpServletRequest())).isEqualTo("login-1");
    }

    @Test
    void aTokenRequestHoldingAnHttpSessionIsStillIdentifiedByItsLogin() {
        SecurityContextHolder.getContext().setAuthentication(token("login-2"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);

        assertThat(RequestIdentity.sessionId(request)).isEqualTo("login-2");
    }

    @Test
    void aSessionRequestIsIdentifiedByItsHttpSession() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession(true).getId();

        assertThat(RequestIdentity.sessionId(request)).isEqualTo(sessionId);
    }

    @Test
    void aTokenWithoutALoginIdentifierHasNoSessionWithoutAnHttpSession() {
        SecurityContextHolder.getContext().setAuthentication(token(null));

        assertThat(RequestIdentity.sessionId(new MockHttpServletRequest())).isNull();
    }

    private static JwtAuthenticationToken token(String sid) {
        Instant now = Instant.now();
        Jwt.Builder jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice")
                .issuedAt(now).expiresAt(now.plusSeconds(300));
        if (sid != null) {
            jwt.claim("sid", sid);
        }
        return new JwtAuthenticationToken(jwt.build(), List.of());
    }

    @Test
    void anAgentsExchangedTokenHasTheAgentsSessionNotThePersonsLogin() {
        // A1-11: the token carries the person's login (sid) and the agent as the actor.
        Instant now = Instant.now();
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice").claim("sid", "login-1")
                .claim("act", Map.of("sub", "agent-x")).issuedAt(now).expiresAt(now.plusSeconds(300)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));

        String agentSession = RequestIdentity.sessionId(new MockHttpServletRequest());

        assertThat(agentSession).startsWith("agent:sid:").isNotEqualTo("login-1");
    }

    @Test
    void aClientsOwnTokenIsIdentifiedByItsTokenWithinTheClient() {
        Instant now = Instant.now();
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("report-client")
                .claim("client_id", "report-client").claim("jti", "token-1")
                .issuedAt(now).expiresAt(now.plusSeconds(300)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));

        assertThat(RequestIdentity.sessionId(new MockHttpServletRequest())).startsWith("client:jti:");
    }

    @Test
    @DisplayName("갈래 N: 신원의 로그인 구분 값이 서블릿 세션보다 앞선다")
    void theSignInTheIdentityNamesComesBeforeTheServletSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);
        identify(request, ContexaIdentity.Source.RESOLVER, "login-seq-7", null);

        assertThat(RequestIdentity.sessionId(request)).isEqualTo("login-seq-7");
    }

    @Test
    @DisplayName("토큰의 sid가 신원의 로그인 구분 값보다 앞선다")
    void theTokensLoginComesBeforeTheIdentitysSessionKey() {
        JwtAuthenticationToken token = token("login-1");
        SecurityContextHolder.getContext().setAuthentication(token);
        MockHttpServletRequest request = new MockHttpServletRequest();
        identify(request, ContexaIdentity.Source.SPRING_SECURITY, "other-key", token);

        assertThat(RequestIdentity.sessionId(request)).isEqualTo("login-1");
    }

    @Test
    @DisplayName("로그인 구분 값이 없는 신원의 요청은 서블릿 세션을 쓴다")
    void anIdentityWithoutASessionKeyKeepsTheServletSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession(true).getId();
        identify(request, ContexaIdentity.Source.RESOLVER, null, null);

        assertThat(RequestIdentity.sessionId(request)).isEqualTo(sessionId);
    }

    @Test
    @DisplayName("다른 인증에서 해석된 신원의 로그인 구분 값은 지금 인증의 세션이 아니다")
    void theSessionKeyOfAnotherAuthenticationsIdentityIsNotUsed() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("admin", null, List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession(true).getId();
        identify(request, ContexaIdentity.Source.RESOLVER, "legacy-login-7", null);

        assertThat(RequestIdentity.sessionId(request)).isEqualTo(sessionId);
    }

    @Test
    @DisplayName("Spring 로그인이 없는 익명 요청에서는 앱이 알린 신원의 로그인 구분 값을 쓴다")
    void anAnonymousRequestUsesTheSessionKeyTheApplicationNamed() {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        MockHttpServletRequest request = new MockHttpServletRequest();
        identify(request, ContexaIdentity.Source.REQUEST_ATTRIBUTE, "login-seq-8", null);

        assertThat(RequestIdentity.sessionId(request)).isEqualTo("login-seq-8");
    }

    private static void identify(MockHttpServletRequest request, ContexaIdentity.Source source, String sessionKey,
                                 Authentication readFrom) {
        ContexaSubject subject = ContexaSubject.of("kim01", "kim01@seum.example").sessionKey(sessionKey).build();
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY,
                ContexaIdentity.resolved(subject, source, Set.of(), readFrom));
    }
}
