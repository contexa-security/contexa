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
import io.contexa.contexacommon.security.bridge.identity.IdentityDiagnostics;
import io.contexa.contexacommon.security.bridge.identity.IdentityResolution;
import io.contexa.contexacommon.security.bridge.identity.SubjectStamps;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthenticationStampResolver;
import io.contexa.contexacommon.security.bridge.resolver.SecurityContextAuthorizationStampResolver;
import io.contexa.contexacommon.security.bridge.runtime.BridgeRuntimeSupport;
import io.contexa.contexacommon.security.bridge.sensor.RequestContextCollector;
import io.contexa.contexacommon.security.bridge.stamp.AuthenticationStamp;
import io.contexa.contexacommon.security.bridge.stamp.AuthorizationStamp;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacommon.security.bridge.subject.ContexaAuthentication;
import io.contexa.contexacommon.security.bridge.subject.ContexaDelegation;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubjectResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * bridge v2 step B3: a request the application's Spring Security signed nobody in to is resolved for the user the
 * application named for Contexa alone (its resolver or the request attribute) and for nothing else; the application's
 * security context and session stay as the application left them.
 */
@DisplayName("레거시 연동 표준 v2: 갈래 N 신원이 bridge 출력으로 이어진다")
class BridgeResolutionFilterSubjectTest {

    private static final Instant LOGIN_AT = Instant.parse("2026-11-26T01:00:00Z");

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("SANDBOX: 리졸버가 이름 지은 사용자가 Contexa 신원·스탬프·인가 사실이 되고, 앱 보안 문맥은 비어 있다")
    void theResolversUserBecomesContexasIdentity() throws Exception {
        ContexaSubjectResolver resolver = view -> view.sessionAttribute("loginVO", String.class)
                .map(id -> ContexaSubject.of(id, id + "@seum.example")
                        .authorities(List.of("ROLE_USER", "MENU_ORDERS"))
                        .authentication(ContexaAuthentication.of("PASSWORD").mfa(false).authenticatedAt(LOGIN_AT))
                        .build());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/legacy/orders");
        request.getSession(true).setAttribute("loginVO", "kim01");
        MockFilterChain chain = new MockFilterChain();

        filter(properties("SANDBOX"), resolver).doFilter(request, new MockHttpServletResponse(), chain);

        ContexaIdentity identity = ContexaIdentity.current(request);
        assertThat(identity.getOutcome()).isEqualTo(ContexaIdentity.Outcome.RESOLVED);
        assertThat(identity.getSource()).isEqualTo(ContexaIdentity.Source.RESOLVER);
        Authentication bridged = (Authentication) request.getAttribute(BridgeRequestAttributes.IDENTITY);
        assertThat(bridged.getName()).isEqualTo("kim01");
        assertThat(ContexaIdentity.of(request)).isSameAs(bridged);
        AuthenticationStamp stamp = (AuthenticationStamp) request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP);
        assertThat(stamp.principalId()).isEqualTo("kim01");
        assertThat(stamp.authenticationSource()).isEqualTo(SubjectStamps.RESOLVER_SOURCE);
        assertThat(stamp.attributes()).containsEntry("email", "kim01@seum.example");
        assertThat(stamp.authenticationType()).isEqualTo("PASSWORD");
        assertThat(stamp.mfaCompleted()).isFalse();
        assertThat(stamp.authenticationTime()).isEqualTo(LOGIN_AT);
        AuthorizationStamp authorization = (AuthorizationStamp) request.getAttribute(BridgeRequestAttributes.AUTHORIZATION_STAMP);
        assertThat(authorization.effectiveRoles()).containsExactly("ROLE_USER");
        assertThat(authorization.effectiveAuthorities()).containsExactly("ROLE_USER", "MENU_ORDERS");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isSameAs(request);
    }

    @Test
    @DisplayName("SANDBOX: 레거시가 이름 짓지 않은 세션·요청 속성은 읽지 않는다(흔한 사용자 세션 이름과 Spring 내부 속성 포함)")
    void nothingTheApplicationDidNotNameIsRead() throws Exception {
        BridgeProperties properties = properties("SANDBOX");
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/legacy/orders");
        request.getSession(true).setAttribute("loginUser", new LegacyUser("kim01"));
        request.setAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", new LegacyUser("context"));

        filter(properties, null).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(ContexaIdentity.current(request).getOutcome()).isEqualTo(ContexaIdentity.Outcome.ABSENT);
        assertThat(request.getAttribute(BridgeRequestAttributes.IDENTITY)).isNull();
        assertThat(request.getAttribute(BridgeRequestAttributes.AUTHENTICATION_STAMP)).isNull();
    }

    @Test
    @DisplayName("SANDBOX: 레거시 필터가 요청 속성에 넣은 사용자와 위임이 신원과 위임 스탬프가 된다")
    void theRequestAttributesUserAndDelegation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/legacy/reports");
        request.setAttribute(ContexaSubject.REQUEST_ATTRIBUTE, ContexaSubject.of("kim01", "kim01@seum.example")
                .delegation(ContexaDelegation.of("report-agent").objective("monthly report")
                        .allowedOperations(List.of("READ")).approvalRequired(true).build())
                .build());

        filter(properties("SANDBOX"), null).doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(ContexaIdentity.current(request).getSource()).isEqualTo(ContexaIdentity.Source.REQUEST_ATTRIBUTE);
        assertThat(((Authentication) request.getAttribute(BridgeRequestAttributes.IDENTITY)).getName()).isEqualTo("kim01");
        DelegationStamp delegation = (DelegationStamp) request.getAttribute(BridgeRequestAttributes.DELEGATION_STAMP);
        assertThat(delegation.agentId()).isEqualTo("report-agent");
        assertThat(delegation.delegated()).isTrue();
        assertThat(delegation.objectiveSummary()).isEqualTo("monthly report");
        assertThat(delegation.allowedOperations()).containsExactly("READ");
        assertThat(delegation.approvalRequired()).isTrue();
    }

    @Test
    @DisplayName("리졸버가 실패해도 앱 요청은 그대로 진행하고, Contexa 신원만 없다")
    void aFailingResolverNeverStopsTheRequest() throws Exception {
        ContexaSubjectResolver failing = view -> {
            throw new IllegalStateException("legacy session store is down");
        };
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/legacy/orders");
        MockFilterChain chain = new MockFilterChain();

        filter(properties("SANDBOX"), failing).doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isSameAs(request);
        assertThat(ContexaIdentity.current(request).getOutcome()).isEqualTo(ContexaIdentity.Outcome.FAILED);
        assertThat(request.getAttribute(BridgeRequestAttributes.IDENTITY)).isNull();
    }

    @Test
    @DisplayName("FULL: Contexa 체인이 로그인시키므로 리졸버 사용자를 요청 신원으로 두지 않는다")
    void underFullTheResolverGivesNoRequestIdentity() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");

        filter(properties("FULL"), view -> Optional.of(ContexaSubject.of("kim01", "kim01@seum.example").build()))
                .doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(ContexaIdentity.current(request).getSource()).isEqualTo(ContexaIdentity.Source.RESOLVER);
        assertThat(request.getAttribute(BridgeRequestAttributes.IDENTITY)).isNull();
    }

    @Test
    @DisplayName("결정 시점: 인터셉터가 나중에 요청 속성에 넣은 사용자를 리졸버를 다시 부르지 않고 읽는다")
    void aUserNamedAfterTheFilterIsReadAtTheDecision() throws Exception {
        int[] calls = {0};
        ContexaSubjectResolver nobodyYet = view -> {
            calls[0]++;
            return Optional.empty();
        };
        BridgeResolutionFilter filter = filter(properties("SANDBOX"), nobodyYet);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/legacy/orders");
        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        request.setAttribute(ContexaSubject.REQUEST_ATTRIBUTE, ContexaSubject.of("kim01", "kim01@seum.example").build());

        filter.resolveAtDecision(request);

        assertThat(calls[0]).isEqualTo(1);
        assertThat(ContexaIdentity.current(request).getUserId()).isEqualTo("kim01");
        assertThat(((Authentication) request.getAttribute(BridgeRequestAttributes.IDENTITY)).getName()).isEqualTo("kim01");
    }

    private static BridgeProperties properties(String mode) {
        BridgeProperties properties = new BridgeProperties();
        properties.setEnvironment(new MockEnvironment().withProperty(ContexaOperatingProfile.PROP_MODE, mode));
        return properties;
    }

    private static BridgeResolutionFilter filter(BridgeProperties properties, ContexaSubjectResolver resolver) {
        return new BridgeResolutionFilter(
                properties,
                new RequestContextCollector(),
                List.of(new SecurityContextAuthenticationStampResolver()),
                List.of(new SecurityContextAuthorizationStampResolver()),
                List.of(),
                new BridgeCoverageEvaluator(),
                null,
                new BridgeRuntimeSupport(properties, null),
                null,
                new IdentityResolution(IdentityResolution.Settings.of(properties), resolver, null, null,
                        IdentityResolution.Accounts.NONE, new IdentityDiagnostics()));
    }

    /** A legacy application's user object in its session, which the application did not hand to Contexa. */
    public static final class LegacyUser {
        private final String userId;

        LegacyUser(String userId) {
            this.userId = userId;
        }

        public String getUserId() {
            return userId;
        }
    }
}
