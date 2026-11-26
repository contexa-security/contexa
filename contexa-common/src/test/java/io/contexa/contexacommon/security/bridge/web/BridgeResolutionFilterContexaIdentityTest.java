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
package io.contexa.contexacommon.security.bridge.web;

import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.security.bridge.BridgeProperties;
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageEvaluator;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R-10 of docs/agent/운영모드-정상화-구현계획.md: where Contexa does not write the application's security context
 * (SANDBOX), the user the bridge resolves is Contexa's own identity of the request, kept in a request attribute; the
 * application's security context stays as the application left it. FULL keeps what it did.
 */
@DisplayName("bridge 신원은 Contexa 전용 요청 범위 신원이다(R-10)")
class BridgeResolutionFilterContexaIdentityTest {

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    /**
     * bridge v2, decision 3 of docs/agent/bridge-v2-연동표준-초안.md: a user object the legacy keeps in its session names
     * no user, whatever its attribute is called; the v1 setting that named the attribute is gone (B6), and the application
     * names its user through its resolver ({@code BridgeResolutionFilterSubjectTest}).
     */
    @Test
    @DisplayName("v2(결정 3): 레거시가 세션에 둔 사용자 객체만으로는 Contexa 신원이 생기지 않고, 앱 보안 문맥도 그대로다")
    void aSessionUserObjectNamesNoUser() throws Exception {
        BridgeProperties properties = properties("SANDBOX");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("loginUser", new LegacyUser("u-100", List.of("ROLE_STAFF")));
        request.setSession(session);

        filter(properties).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(ContexaIdentity.of(request)).isNull();
        assertThat(ContexaIdentity.current(request).getOutcome()).isEqualTo(ContexaIdentity.Outcome.ABSENT);
        assertThat(request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT)).isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication())
                .as("the application's security context is not written")
                .isNull();
    }

    /**
     * bridge v2, decision 3: the flat v1 request attributes ({@code ctxa.auth.*}) name no user any more; the application
     * puts a {@code ContexaSubject} under {@code ctxa.subject} ({@code BridgeResolutionFilterSubjectTest}).
     */
    @Test
    @DisplayName("v2(결정 3): 평평한 옛 요청 속성(ctxa.auth.*)은 더 읽지 않는다")
    void theFlatV1RequestAttributesNameNoUser() throws Exception {
        BridgeProperties properties = properties("SANDBOX");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setAttribute("ctxa.auth.principalId", "bob");
        request.setAttribute("ctxa.auth.authorities", "ROLE_USER");

        filter(properties).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(ContexaIdentity.of(request)).isNull();
        assertThat(ContexaIdentity.current(request).getOutcome()).isEqualTo(ContexaIdentity.Outcome.ABSENT);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("SANDBOX: 이름을 정하지 않은 속성을 훑어 찾은 객체는 사용자로 보지 않고 요청을 그대로 둔다")
    void anObjectOnlyDiscoveredByScanningIsNoUser() throws Exception {
        BridgeProperties properties = properties("SANDBOX");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders/42");
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("cartSummary", new Cart("42"));
        request.setSession(session);
        request.setAttribute("pageInfo", new Cart("7"));

        filter(properties).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(BridgeRequestAttributes.IDENTITY)).isNull();
        assertThat(request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT)).isNull();
        assertThat(ContexaIdentity.of(request)).isNull();
    }

    @Test
    @DisplayName("FULL: Spring 인증이 없는 요청은 지금처럼 해석하지 않는다")
    void fullKeepsWhatItDid() throws Exception {
        BridgeProperties properties = properties("FULL");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("loginUser", new LegacyUser("u-100", List.of("ROLE_STAFF")));
        request.setSession(session);

        filter(properties).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(BridgeRequestAttributes.IDENTITY)).isNull();
        assertThat(request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT)).isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    /**
     * bridge v2, decision 3: at the decision, an object of the application's under one of its own request attributes is
     * not guessed to be the user; a user named later through {@code ctxa.subject} is read
     * ({@code BridgeResolutionFilterSubjectTest}).
     */
    @Test
    @DisplayName("v2(결정 3): 판정 시점에도 앱 고유 요청 속성의 객체를 사용자로 추측하지 않는다")
    void aLateObjectOfTheApplicationIsNotGuessedAtTheDecision() throws Exception {
        BridgeProperties properties = properties("SANDBOX");
        BridgeResolutionFilter filter = filter(properties);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        assertThat(ContexaIdentity.of(request)).isNull();

        request.setAttribute("currentUser", new LegacyUser("carol", List.of("ROLE_USER")));
        filter.resolveAtDecision(request);

        assertThat(ContexaIdentity.of(request)).isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("판정 시점 지연 해석: 필터 뒤에 앱이 만든 Spring 인증으로 도장을 다시 해석한다")
    void aSpringSignInAfterTheFiltersIsResolvedAtTheDecision() throws Exception {
        BridgeProperties properties = properties("SANDBOX");
        BridgeResolutionFilter filter = filter(properties);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        Authentication late = UsernamePasswordAuthenticationToken.authenticated("dave", null,
                AuthorityUtils.createAuthorityList("ROLE_USER"));
        SecurityContextHolder.getContext().setAuthentication(late);

        filter.resolveAtDecision(request);

        BridgeResolutionResult result = (BridgeResolutionResult) request.getAttribute(BridgeRequestAttributes.RESOLUTION_RESULT);
        assertThat(result).isNotNull();
        assertThat(result.authenticationStamp().principalId()).isEqualTo("dave");
        assertThat(result.authenticationStamp().authenticationSource()).isEqualTo("SECURITY_CONTEXT");
        assertThat(ContexaIdentity.of(request)).isSameAs(late);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(late);
    }

    private static BridgeProperties properties(String mode) {
        BridgeProperties properties = new BridgeProperties();
        MockEnvironment environment = new MockEnvironment().withProperty(ContexaOperatingProfile.PROP_MODE, mode);
        properties.setEnvironment(environment);
        return properties;
    }

    /** The stamp resolvers the auto-configuration registers (bridge v2: the Spring Security ones only). */
    private static BridgeResolutionFilter filter(BridgeProperties properties) {
        return new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(new SecurityContextAuthorizationStampResolver()),
                List.of(),
                new BridgeCoverageEvaluator(),
                null,
                new BridgeRuntimeSupport(properties, null),
                null);
    }

    /** A legacy application's user object, kept in its session or request. */
    public static final class LegacyUser {
        private final String userId;
        private final List<String> roles;

        LegacyUser(String userId, List<String> roles) {
            this.userId = userId;
            this.roles = roles;
        }

        public String getUserId() {
            return userId;
        }

        public List<String> getRoles() {
            return roles;
        }
    }

    /** An object of the application's that happens to carry an id; it names no user. */
    public static final class Cart {
        private final String id;

        Cart(String id) {
            this.id = id;
        }

        public String getId() {
            return id;
        }
    }
}
