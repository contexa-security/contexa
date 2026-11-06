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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The context a person's sign-in is decided for is the one the client presents on its next request. In a token state
 * that request is a bearer call, which is one session with the login its token carries (claim sid), whether or not it
 * carries the servlet session a step of the login may have created. The sign-in is bound to that login, so that the
 * first call is no change of context, for a client that keeps the session cookie and for one that does not.
 */
class TokenStateContextHashTest {

    private static final String LOGIN = "login-1";
    private static final String SERVLET_SESSION = "J-4711";

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static MockHttpServletRequest network(MockHttpServletRequest request) {
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("User-Agent", "browser");
        return request;
    }

    private static MockHttpServletRequest loginRequest(boolean withServletSession) {
        MockHttpServletRequest request = network(new MockHttpServletRequest("POST", "/api/login/mfa-ott"));
        if (withServletSession) {
            request.setSession(new MockHttpSession(null, SERVLET_SESSION));
            request.setRequestedSessionId(SERVLET_SESSION);
        }
        return request;
    }

    private static MockHttpServletRequest bearerCall(String cookieSession) {
        MockHttpServletRequest request = network(new MockHttpServletRequest("GET", "/api/records/1"));
        if (cookieSession != null) {
            request.setRequestedSessionId(cookieSession);
        }
        return request;
    }

    private static Authentication token(String sid) {
        Instant now = Instant.now();
        Jwt.Builder jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice")
                .issuedAt(now).expiresAt(now.plusSeconds(300));
        if (sid != null) {
            jwt.claim("sid", sid);
        }
        return new JwtAuthenticationToken(jwt.build(), List.of());
    }

    private static Authentication loginAuthentication() {
        return UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());
    }

    @ParameterizedTest(name = "the login had a servlet session: {0}")
    @ValueSource(booleans = {false, true})
    @DisplayName("a token-state sign-in and the bearer call after it, which carries no cookie, are bound to the same context")
    void aSignInAndItsCookielessBearerCallAgree(boolean loginHadAServletSession) {
        SecurityContextHolder.getContext().setAuthentication(loginAuthentication());
        String signIn = SessionFingerprintUtil.generateNextRequestContextBindingHash(
                loginRequest(loginHadAServletSession), LOGIN);

        String call = SessionFingerprintUtil.generateContextBindingHash(bearerCall(null), token(LOGIN));

        assertThat(call).isEqualTo(signIn);
    }

    @Test
    @DisplayName("and so are the sign-in and a bearer call that carries the servlet session's cookie")
    void aSignInAndItsBearerCallWithTheCookieAgree() {
        SecurityContextHolder.getContext().setAuthentication(loginAuthentication());
        String signIn = SessionFingerprintUtil.generateNextRequestContextBindingHash(loginRequest(true), LOGIN);

        String call = SessionFingerprintUtil.generateContextBindingHash(bearerCall(SERVLET_SESSION), token(LOGIN));

        assertThat(call).isEqualTo(signIn);
    }

    @Test
    @DisplayName("a bearer call is one context with or without a cookie: the login its token carries is its session")
    void aBearerCallDoesNotDependOnTheCookie() {
        String without = SessionFingerprintUtil.generateContextBindingHash(bearerCall(null), token(LOGIN));
        String with = SessionFingerprintUtil.generateContextBindingHash(bearerCall("any-cookie"), token(LOGIN));

        assertThat(with).isEqualTo(without);
    }

    @Test
    @DisplayName("two logins from one network are two contexts")
    void twoLoginsAreTwoContexts() {
        String first = SessionFingerprintUtil.generateContextBindingHash(bearerCall(null), token("login-1"));
        String second = SessionFingerprintUtil.generateContextBindingHash(bearerCall(null), token("login-2"));

        assertThat(second).isNotEqualTo(first);
    }

    @Test
    @DisplayName("a token that names no login keeps the request's session, as before")
    void aTokenWithoutALoginKeepsTheRequestedSession() {
        String call = SessionFingerprintUtil.generateContextBindingHash(bearerCall(SERVLET_SESSION), token(null));

        assertThat(call).isEqualTo(SessionFingerprintUtil.generateContextBindingHash(SERVLET_SESSION, "10.0.0.1", "browser"));
    }

    @Test
    @DisplayName("a session-state sign-in, which has no token session, follows its servlet session as before")
    void aSessionStateSignInFollowsItsServletSession() {
        SecurityContextHolder.getContext().setAuthentication(loginAuthentication());

        String signIn = SessionFingerprintUtil.generateNextRequestContextBindingHash(loginRequest(true), null);

        assertThat(signIn).isEqualTo(SessionFingerprintUtil.generateContextBindingHash(SERVLET_SESSION, "10.0.0.1", "browser"));
        assertThat(SessionFingerprintUtil.generateNextRequestContextBindingHash(loginRequest(true)))
                .as("the form without a token session is the same").isEqualTo(signIn);
    }
}
