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

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.ContexaIdentity;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageLevel;
import io.contexa.contexacommon.security.bridge.coverage.BridgeCoverageReport;
import io.contexa.contexacommon.security.bridge.coverage.MissingBridgeContext;
import io.contexa.contexacommon.security.bridge.subject.ContexaSubject;
import io.contexa.contexacommon.security.bridge.subject.SubjectProblem;
import io.contexa.contexacommon.security.bridge.web.BridgeResolutionFilter;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.TieredStrategyProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * bridge v2 step B4: the engine's events name their user by the one rule of the request's identity, a sign-in's after
 * the bridge read the request again for it, and say how the bridge identified the user (source, outcome, problems)
 * beside the bridge's coverage keys, which stay.
 */
@DisplayName("엔진 이벤트의 사용자와 bridge 신원 키(bridge v2 B4)")
class ZeroTrustEventPublisherBridgeIdentityTest {

    private final List<Object> events = new ArrayList<>();
    private final ZeroTrustEventPublisher publisher =
            new ZeroTrustEventPublisher(events::add, new TieredStrategyProperties());
    private final Authentication alice = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("로그인 이벤트의 사용자는 bridge가 로그인 때 다시 해석한 신원의 사용자 ID다")
    void aSignInIsDecidedForTheIdentityReadAgainForIt() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY,
                resolved("kim01", ContexaIdentity.Source.RESOLVER, Set.of(), null));
        ContexaIdentity readAgain = resolved("emp-7", ContexaIdentity.Source.SPRING_SECURITY, Set.of(), alice);
        bridgeThatResolvesTheSignInAs(readAgain);

        publisher.publishAuthenticationSuccess(alice, request, Map.of());

        ZeroTrustSpringEvent signIn = published();
        assertThat(signIn.getUserId()).isEqualTo("emp-7");
        assertThat(signIn.getPayload())
                .containsEntry(ZeroTrustEventPublisher.BRIDGE_IDENTITY_SOURCE, "spring-security")
                .containsEntry(ZeroTrustEventPublisher.BRIDGE_IDENTITY_OUTCOME, "RESOLVED");
    }

    /** bridge v2 B5-2, ContexaBridge.signedIn: the user the application named is the identity already. */
    @Test
    @DisplayName("레거시가 알린 로그인은 bridge를 다시 해석하지 않고 요청 신원의 사용자로 한 번만 엔진에 간다")
    void aNamedSignInGoesOnceForTheIdentityOfTheRequestWithoutTheBridge() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/legacy/login");
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY,
                resolved("kim01", ContexaIdentity.Source.REQUEST_ATTRIBUTE, Set.of(), null));
        bridgeThatResolvesTheSignInAs(resolved("someone-else", ContexaIdentity.Source.SPRING_SECURITY, Set.of(), alice));

        publisher.publishNamedSignIn(request, Map.of("authenticationType", "HOST_SIGN_IN"));
        publisher.publishNamedSignIn(request, Map.of("authenticationType", "HOST_SIGN_IN"));

        ZeroTrustSpringEvent signIn = published();
        assertThat(signIn.getUserId()).isEqualTo("kim01");
        assertThat(signIn.getEventType()).isEqualTo(ZeroTrustSpringEvent.TYPE_AUTHENTICATION_SUCCESS);
        assertThat(signIn.getPayload()).containsEntry("authenticationType", "HOST_SIGN_IN");
    }

    @Test
    @DisplayName("신원이 없으면 로그인 이벤트의 사용자는 로그인 인증의 주체이고 요청 이벤트와 같은 이름 규칙을 쓴다")
    void withoutAnIdentityASignInIsNamedByTheOneSubjectRule() {
        Authentication padded = UsernamePasswordAuthenticationToken.authenticated(" alice ", null, List.of());

        publisher.publishAuthenticationSuccess(padded, new MockHttpServletRequest("POST", "/login"), Map.of());

        assertThat(published().getUserId()).isEqualTo("alice");
    }

    @Test
    @DisplayName("앱 고유 principal로 로그인하면 Contexa는 필드를 추측하지 않고 사용자를 정하지 않는다")
    void aSignInOfAnApplicationsOwnPrincipalNamesNoUser() {
        Authentication own = UsernamePasswordAuthenticationToken.authenticated(new LegacyLoginUser("kim01"), null,
                List.of());

        publisher.publishAuthenticationSuccess(own, new MockHttpServletRequest("POST", "/login"), Map.of());

        assertThat(published().getUserId()).isNull();
    }

    @Test
    @DisplayName("요청 이벤트의 사용자는 해석한 신원의 사용자 ID다")
    void aRequestIsDecidedForItsResolvedIdentity() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY,
                resolved("emp-7", ContexaIdentity.Source.SPRING_SECURITY, Set.of(), alice));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ZeroTrustSpringEvent event = publisher.buildRequestAuthorizationEvent(alice, true, null);

        assertThat(event.getUserId()).isEqualTo("emp-7");
    }

    @Test
    @DisplayName("엔진 이벤트에 신원의 출처·결과·문제 이름이 실린다")
    void theEventSaysHowTheBridgeIdentifiedTheUser() {
        ZeroTrustSpringEvent event = requestEventWith(resolved("kim01", ContexaIdentity.Source.RESOLVER,
                Set.of(SubjectProblem.EMAIL_MISSING, SubjectProblem.RESOLVER_SLOW), null));

        assertThat(event.getPayload())
                .containsEntry(ZeroTrustEventPublisher.BRIDGE_IDENTITY_SOURCE, "resolver")
                .containsEntry(ZeroTrustEventPublisher.BRIDGE_IDENTITY_OUTCOME, "RESOLVED")
                .containsEntry(ZeroTrustEventPublisher.BRIDGE_IDENTITY_PROBLEMS, List.of("EMAIL_MISSING", "RESOLVER_SLOW"));
    }

    @Test
    @DisplayName("성립하지 않은 신원은 출처 없이 결과와 문제만 싣는다")
    void anUnresolvedIdentityCarriesNoSource() {
        ZeroTrustSpringEvent event = requestEventWith(ContexaIdentity.unresolved(ContexaIdentity.Outcome.FAILED,
                Set.of(SubjectProblem.RESOLVER_FAILED)));

        assertThat(event.getPayload())
                .doesNotContainKey(ZeroTrustEventPublisher.BRIDGE_IDENTITY_SOURCE)
                .containsEntry(ZeroTrustEventPublisher.BRIDGE_IDENTITY_OUTCOME, "FAILED")
                .containsEntry(ZeroTrustEventPublisher.BRIDGE_IDENTITY_PROBLEMS, List.of("RESOLVER_FAILED"));
    }

    @Test
    @DisplayName("문제가 없는 신원은 문제 목록 키를 싣지 않는다")
    void anIdentityThatBrokeNothingCarriesNoProblems() {
        ZeroTrustSpringEvent event = requestEventWith(
                resolved("kim01", ContexaIdentity.Source.REQUEST_ATTRIBUTE, Set.of(), null));

        assertThat(event.getPayload())
                .containsEntry(ZeroTrustEventPublisher.BRIDGE_IDENTITY_SOURCE, "request-attribute")
                .doesNotContainKey(ZeroTrustEventPublisher.BRIDGE_IDENTITY_PROBLEMS);
    }

    @Test
    @DisplayName("bridge가 보지 않은 요청의 이벤트에는 신원 키가 없다")
    void aRequestTheBridgeHasNotSeenCarriesNoIdentityKeys() {
        RequestContextHolder.setRequestAttributes(
                new ServletRequestAttributes(new MockHttpServletRequest("GET", "/orders")));

        ZeroTrustSpringEvent event = publisher.buildRequestAuthorizationEvent(alice, true, null);

        assertThat(event.getPayload()).doesNotContainKeys(ZeroTrustEventPublisher.BRIDGE_IDENTITY_SOURCE,
                ZeroTrustEventPublisher.BRIDGE_IDENTITY_OUTCOME, ZeroTrustEventPublisher.BRIDGE_IDENTITY_PROBLEMS);
    }

    @Test
    @DisplayName("bridge 수집 범위 키는 신원 키와 함께 그대로 남는다")
    void theCoverageKeysStayBesideTheIdentityKeys() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setAttribute(BridgeRequestAttributes.COVERAGE_REPORT, new BridgeCoverageReport(
                BridgeCoverageLevel.AUTHORIZATION_CONTEXT, 85, Set.of(MissingBridgeContext.DELEGATION),
                "Bridge completeness reached authentication and authorization context for the current request.",
                List.of()));
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY,
                resolved("kim01", ContexaIdentity.Source.RESOLVER, Set.of(), null));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        ZeroTrustSpringEvent event = publisher.buildRequestAuthorizationEvent(alice, true, null);

        assertThat(event.getPayload())
                .containsEntry("bridgeCoverageLevel", BridgeCoverageLevel.AUTHORIZATION_CONTEXT.name())
                .containsEntry("bridgeCoverageScore", 85)
                .containsKey("bridgeMissingContexts")
                .containsEntry(ZeroTrustEventPublisher.BRIDGE_IDENTITY_OUTCOME, "RESOLVED");
    }

    private ZeroTrustSpringEvent requestEventWith(ContexaIdentity identity) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, identity);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return publisher.buildRequestAuthorizationEvent(alice, true, null);
    }

    private ZeroTrustSpringEvent published() {
        assertThat(events).hasSize(1);
        return (ZeroTrustSpringEvent) events.get(0);
    }

    @SuppressWarnings("unchecked")
    private void bridgeThatResolvesTheSignInAs(ContexaIdentity identity) {
        BridgeResolutionFilter bridge = mock(BridgeResolutionFilter.class);
        doAnswer(call -> {
            HttpServletRequest request = call.getArgument(0);
            request.setAttribute(BridgeRequestAttributes.SUBJECT_IDENTITY, identity);
            return null;
        }).when(bridge).resolveSignIn(any(), any());
        ObjectProvider<BridgeResolutionFilter> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(bridge);
        ReflectionTestUtils.setField(publisher, "bridgeResolution", provider);
    }

    private static ContexaIdentity resolved(String userId, ContexaIdentity.Source source, Set<SubjectProblem> problems,
                                            Authentication readFrom) {
        return ContexaIdentity.resolved(ContexaSubject.of(userId, userId + "@seum.example").build(), source, problems,
                readFrom);
    }

    /** A legacy application's own login object, of none of the kinds Spring Security names a user by. */
    private static final class LegacyLoginUser {

        private final String empNo;

        private LegacyLoginUser(String empNo) {
            this.empNo = empNo;
        }

        String getEmpNo() {
            return empNo;
        }
    }
}
