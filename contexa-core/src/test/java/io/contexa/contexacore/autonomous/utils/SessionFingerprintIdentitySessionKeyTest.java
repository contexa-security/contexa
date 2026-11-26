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
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * bridge v2: the session place of the context binding names the sign-in the request's identity names (the session key
 * of an application without sessions), after an agent's session and a token's login and before the servlet session, by
 * the order {@link RequestIdentity#sessionId} names the request's session.
 */
@DisplayName("맥락 해시의 세션 자리는 신원의 로그인 구분 값을 따른다(bridge v2)")
class SessionFingerprintIdentitySessionKeyTest {

    private static final String ADDRESS = "10.0.0.1";
    private static final String BROWSER = "browser";

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("갈래 N: 신원의 로그인 구분 값이 맥락 해시의 세션 자리에 들어간다")
    void theSessionKeyOfTheIdentityIsTheSessionOfTheBinding() {
        MockHttpServletRequest request = request();
        request.setRequestedSessionId("J-1");
        identify(request, ContexaIdentity.Source.RESOLVER, "login-seq-7", null);

        assertThat(SessionFingerprintUtil.generateContextBindingHash(request))
                .isEqualTo(SessionFingerprintUtil.generateContextBindingHash("login-seq-7", ADDRESS, BROWSER));
    }

    @Test
    @DisplayName("같은 주소와 브라우저에서 온 두 로그인은 두 맥락이다")
    void twoSignInsFromOneAddressAndBrowserAreTwoContexts() {
        MockHttpServletRequest first = request();
        identify(first, ContexaIdentity.Source.REQUEST_ATTRIBUTE, "login-seq-1", null);
        MockHttpServletRequest second = request();
        identify(second, ContexaIdentity.Source.REQUEST_ATTRIBUTE, "login-seq-2", null);

        assertThat(SessionFingerprintUtil.generateContextBindingHash(second))
                .isNotEqualTo(SessionFingerprintUtil.generateContextBindingHash(first));
    }

    @Test
    @DisplayName("토큰의 sid가 신원의 로그인 구분 값보다 앞선다")
    void theTokensLoginComesBeforeTheIdentitysSessionKey() {
        JwtAuthenticationToken token = token("login-1");
        MockHttpServletRequest request = request();
        identify(request, ContexaIdentity.Source.SPRING_SECURITY, "other-key", token);

        assertThat(SessionFingerprintUtil.generateContextBindingHash(request, token))
                .isEqualTo(SessionFingerprintUtil.generateContextBindingHash("login-1", ADDRESS, BROWSER));
    }

    @Test
    @DisplayName("보안 문맥을 적재하는 코드가 준 인증으로 해시를 만들 때 신원의 로그인 구분 값을 쓰고 문맥은 읽지 않는다")
    void theBindingOfALoadingContextReadsTheIdentityAndNotTheContext() {
        MockHttpServletRequest request = request();
        identify(request, ContexaIdentity.Source.RESOLVER, "login-seq-7", null);
        SecurityContextHolder.setDeferredContext(() -> {
            throw new AssertionError("the security context was read");
        });

        assertThat(SessionFingerprintUtil.generateContextBindingHash(request, null))
                .isEqualTo(SessionFingerprintUtil.generateContextBindingHash("login-seq-7", ADDRESS, BROWSER));
    }

    @Test
    @DisplayName("다음 요청 해시는 로그인 때 다시 해석한 신원의 로그인 구분 값을 따른다")
    void theNextRequestFollowsTheIdentityReadAgainForTheSignIn() {
        Authentication signedIn = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(signedIn);
        MockHttpServletRequest request = request();
        request.setSession(new MockHttpSession(null, "S-2"));
        identify(request, ContexaIdentity.Source.SPRING_SECURITY, "idp-sid-9", signedIn);

        assertThat(SessionFingerprintUtil.generateNextRequestContextBindingHash(request))
                .isEqualTo(SessionFingerprintUtil.generateContextBindingHash("idp-sid-9", ADDRESS, BROWSER));
    }

    @Test
    @DisplayName("다음 요청 해시는 로그인 전에 만난 다른 신원의 로그인 구분 값을 쓰지 않고 로그인이 남긴 세션을 따른다")
    void theNextRequestIgnoresAnIdentityMetBeforeTheSignIn() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("admin", null, List.of()));
        MockHttpServletRequest request = request();
        request.setSession(new MockHttpSession(null, "S-2"));
        identify(request, ContexaIdentity.Source.RESOLVER, "legacy-login-7", null);

        assertThat(SessionFingerprintUtil.generateNextRequestContextBindingHash(request))
                .isEqualTo(SessionFingerprintUtil.generateContextBindingHash("S-2", ADDRESS, BROWSER));
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setRemoteAddr(ADDRESS);
        request.addHeader("User-Agent", BROWSER);
        return request;
    }

    private static void identify(MockHttpServletRequest request, ContexaIdentity.Source source, String sessionKey,
                                 Authentication readFrom) {
        ContexaSubject subject = ContexaSubject.of("kim01", "kim01@seum.example").sessionKey(sessionKey).build();
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY,
                ContexaIdentity.resolved(subject, source, Set.of(), readFrom));
    }

    private static JwtAuthenticationToken token(String sid) {
        Instant now = Instant.now();
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("alice").claim("sid", sid)
                .issuedAt(now).expiresAt(now.plusSeconds(300)).build();
        return new JwtAuthenticationToken(jwt, List.of());
    }
}
