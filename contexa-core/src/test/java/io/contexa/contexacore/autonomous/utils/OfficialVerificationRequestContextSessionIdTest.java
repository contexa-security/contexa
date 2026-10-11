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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * W1-21: the session identifier the engine gives a request. The host's own session comes first; a token (OAuth2)
 * request is identified by the login its token carries (claim sid), with or without an HTTP session; any other request
 * by its HTTP session.
 */
class OfficialVerificationRequestContextSessionIdTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void aTokenRequestIsIdentifiedByTheLoginItsTokenCarries() {
        SecurityContextHolder.getContext().setAuthentication(token("login-1"));

        assertThat(OfficialVerificationRequestContext.resolveSessionId(new MockHttpServletRequest())).isEqualTo("login-1");
    }

    @Test
    void aTokenRequestHoldingAnHttpSessionIsStillIdentifiedByItsLogin() {
        SecurityContextHolder.getContext().setAuthentication(token("login-2"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);

        assertThat(OfficialVerificationRequestContext.resolveSessionId(request)).isEqualTo("login-2");
    }

    @Test
    void aSessionRequestIsIdentifiedByItsHttpSession() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest();
        String sessionId = request.getSession(true).getId();

        assertThat(OfficialVerificationRequestContext.resolveSessionId(request)).isEqualTo(sessionId);
    }

    @Test
    void aTokenWithoutALoginIdentifierHasNoSessionWithoutAnHttpSession() {
        SecurityContextHolder.getContext().setAuthentication(token(null));

        assertThat(OfficialVerificationRequestContext.resolveSessionId(new MockHttpServletRequest())).isNull();
    }

    @Test
    void theHostsSessionComesFirst() {
        SecurityContextHolder.getContext().setAuthentication(token("login-3"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(OfficialVerificationRequestContext.SYNTHETIC_SESSION_ID, "host-session");

        assertThat(OfficialVerificationRequestContext.resolveSessionId(request)).isEqualTo("host-session");
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
}
