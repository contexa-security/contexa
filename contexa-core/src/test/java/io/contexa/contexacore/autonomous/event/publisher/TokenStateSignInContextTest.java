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
package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A sign-in of a token state is decided for the context its client presents next: a bearer call, which is one session
 * with the login its token carries. The login's servlet session, which a step of an MFA flow may have created and a
 * client that keeps no cookies never sends again, is not the context the sign-in is decided for.
 */
class TokenStateSignInContextTest {

    private static final String LOGIN = "login-1";

    private final List<Object> events = new ArrayList<>();
    private final ZeroTrustEventPublisher publisher =
            new ZeroTrustEventPublisher(events::add, new TieredStrategyProperties());
    private final Authentication alice = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static MockHttpServletRequest loginRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/login/mfa-ott");
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("User-Agent", "browser");
        request.setSession(new MockHttpSession(null, "J-4711"));
        return request;
    }

    private static String bearerCallContext() {
        MockHttpServletRequest call = new MockHttpServletRequest("GET", "/api/records/1");
        call.setRemoteAddr("10.0.0.1");
        call.addHeader("User-Agent", "browser");
        Instant now = Instant.now();
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice").claim("sid", LOGIN)
                .issuedAt(now).expiresAt(now.plusSeconds(300)).build();
        return SessionFingerprintUtil.generateContextBindingHash(call, new JwtAuthenticationToken(jwt, List.of()));
    }

    private Map<String, Object> publishedPayload() {
        assertThat(events).hasSize(1);
        return ((ZeroTrustSpringEvent) events.get(0)).getPayload();
    }

    @Test
    @DisplayName("a token-state sign-in is decided for the context of the bearer call that follows it")
    void aTokenStateSignInIsDecidedForTheBearerCall() {
        SecurityContextHolder.getContext().setAuthentication(alice);

        publisher.publishAuthenticationSuccess(alice, loginRequest(),
                Map.of("authenticationType", "MFA", ZeroTrustEventPublisher.TOKEN_SESSION_ID, LOGIN));

        assertThat(publishedPayload()).containsEntry("contextBindingHash", bearerCallContext());
    }

    @Test
    @DisplayName("the login's identifier steers the context and is no fact of the sign-in")
    void theLoginIdentifierIsNoFactOfTheSignIn() {
        SecurityContextHolder.getContext().setAuthentication(alice);

        publisher.publishAuthenticationSuccess(alice, loginRequest(),
                Map.of("authenticationType", "MFA", ZeroTrustEventPublisher.TOKEN_SESSION_ID, LOGIN));

        assertThat(publishedPayload()).doesNotContainKey(ZeroTrustEventPublisher.TOKEN_SESSION_ID)
                .containsEntry("authenticationType", "MFA");
    }

    @Test
    @DisplayName("a session-state sign-in is decided for its servlet session, as before")
    void aSessionStateSignInFollowsItsServletSession() {
        SecurityContextHolder.getContext().setAuthentication(alice);

        publisher.publishAuthenticationSuccess(alice, loginRequest(), Map.of("authenticationType", "MFA"));

        assertThat(publishedPayload()).containsEntry("contextBindingHash",
                SessionFingerprintUtil.generateContextBindingHash("J-4711", "10.0.0.1", "browser"));
    }
}
