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
package io.contexa.contexaiam.security.xacml.pep.interceptor;

import io.contexa.contexacommon.annotation.Protectable;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService.AsyncProtectableGate;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties.EnforcementMode;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableLlmSuppressionWriter;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRefusalFilter;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.springframework.aop.Pointcut;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * A call in a request that names no user, by operating mode. OBSERVE and DISABLED decide on nobody: the call goes on as a
 * signed-in user's does there, no question goes to the model and nothing is published, and the method policies still
 * decide on what the context holds. SHADOW and ENFORCE refuse it as before. The refusal of the call before its method runs
 * is marked on its request, so that a path no Spring Security chain covers still answers it; what the method itself
 * refuses, and a decision of Contexa that has its own answer, is not.
 */
class ProtectableCallWithoutUserByModeTest {

    private final ProtectableMethodAuthorizationManager policies = mock(ProtectableMethodAuthorizationManager.class);
    private final ProtectableRapidReentryGuard reentryGuard = mock(ProtectableRapidReentryGuard.class);
    private final ZeroTrustEventPublisher events = mock(ZeroTrustEventPublisher.class);
    private final SynchronousProtectableDecisionService decisions = mock(SynchronousProtectableDecisionService.class);
    private final ProtectableLlmSuppressionWriter records = mock(ProtectableLlmSuppressionWriter.class);
    private final MethodInvocation call = mock(MethodInvocation.class);
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() throws Throwable {
        when(call.getMethod()).thenReturn(Work.class.getMethod("decided"));
        when(call.getThis()).thenReturn(new Work());
        when(call.proceed()).thenReturn("done");
        when(reentryGuard.tryAcquire(any(), any(), anyString())).thenReturn(true);
        when(decisions.asyncGate(any(), any())).thenReturn(AsyncProtectableGate.PROCEED);
        SecurityContextHolder.clearContext();
        request = new MockHttpServletRequest("GET", "/h/m/secured");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    private AuthorizationManagerMethodInterceptor interceptor(EnforcementMode mode) {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setMode(mode);
        return interceptor(properties);
    }

    private AuthorizationManagerMethodInterceptor interceptor(SecurityZeroTrustProperties properties) {
        AuthorizationManagerMethodInterceptor created =
                new AuthorizationManagerMethodInterceptor(mock(Pointcut.class), policies, reentryGuard);
        created.setZeroTrustEventPublisher(events);
        created.setSynchronousProtectableDecisionService(decisions);
        created.setProtectableLlmSuppressionWriter(records);
        created.setSecurityZeroTrustProperties(properties);
        return created;
    }

    private static void signedIn(Authentication authentication) {
        SecurityContextHolder.setContext(new SecurityContextImpl(authentication));
    }

    private static Authentication visitor() {
        return new AnonymousAuthenticationToken("key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    }

    private static Authentication user() {
        return UsernamePasswordAuthenticationToken.authenticated("kim", null, List.of());
    }

    private Object marked() {
        return request.getAttribute(ProtectableRefusalFilter.REFUSAL);
    }

    /** The subject the method policies were evaluated for. */
    @SuppressWarnings("unchecked")
    private Authentication subjectOfThePolicies() {
        ArgumentCaptor<Supplier<Authentication>> subject = ArgumentCaptor.forClass(Supplier.class);
        verify(policies).protectable(subject.capture(), eq(call));
        return subject.getValue().get();
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"OBSERVE", "DISABLED"})
    void aVisitorsCallRunsWhereTheModeDecidesOnNobody(EnforcementMode mode) throws Throwable {
        Authentication visitor = visitor();
        signedIn(visitor);

        assertThat(interceptor(mode).invoke(call)).isEqualTo("done");

        verify(call).proceed();
        assertThat(subjectOfThePolicies()).as("the method policies decide on the visitor").isSameAs(visitor);
        verify(reentryGuard, never()).tryAcquire(any(), any(), anyString());
        verifyNoInteractions(decisions, events, records);
        assertThat(marked()).isNull();
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"OBSERVE", "DISABLED"})
    void aRequestWithNoUserRunsWhereTheModeDecidesOnNobody(EnforcementMode mode) throws Throwable {
        assertThat(interceptor(mode).invoke(call)).isEqualTo("done");

        verify(call).proceed();
        assertThat(subjectOfThePolicies()).isNull();
        verifyNoInteractions(decisions, events, records);
        assertThat(marked()).isNull();
    }

    @Test
    void withTheAnalysisSwitchedOffAVisitorsCallRunsToo() throws Throwable {
        SecurityZeroTrustProperties off = new SecurityZeroTrustProperties();
        off.setEnabled(false);
        signedIn(visitor());

        assertThat(interceptor(off).invoke(call)).isEqualTo("done");

        verifyNoInteractions(decisions, events, records);
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"OBSERVE", "DISABLED"})
    void theMethodPoliciesStillRefuseTheVisitor(EnforcementMode mode) throws Throwable {
        signedIn(visitor());
        AuthorizationDeniedException denied = new AuthorizationDeniedException("Access is denied by method policies");
        doThrow(denied).when(policies).protectable(any(), eq(call));

        assertThatThrownBy(() -> interceptor(mode).invoke(call)).isSameAs(denied);

        verify(call, never()).proceed();
        verifyNoInteractions(events, records);
        assertThat(marked()).isSameAs(denied);
    }

    /** A policy that needs a user, on a path where the context holds none at all. */
    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"OBSERVE", "DISABLED"})
    void aPolicyThatNeedsAUserRefusesACallThatHasNone(EnforcementMode mode) throws Throwable {
        AuthenticationCredentialsNotFoundException missing =
                new AuthenticationCredentialsNotFoundException("A method policy needs a user");
        doThrow(missing).when(policies).protectable(any(), eq(call));

        assertThatThrownBy(() -> interceptor(mode).invoke(call)).isSameAs(missing);

        verify(call, never()).proceed();
        verifyNoInteractions(events, records);
        assertThat(marked()).isSameAs(missing);
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"SHADOW", "ENFORCE"})
    void aVisitorStaysRefusedWhereTheModeDecides(EnforcementMode mode) throws Throwable {
        signedIn(visitor());

        Throwable refused = catchThrowable(() -> interceptor(mode).invoke(call));

        assertThat(refused).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        verify(call, never()).proceed();
        verifyNoInteractions(policies, decisions, events);
        assertThat(marked()).as("marked for a path no chain covers").isSameAs(refused);
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"SHADOW", "ENFORCE"})
    void aRequestWithNoUserStaysRefusedWhereTheModeDecides(EnforcementMode mode) throws Throwable {
        Throwable refused = catchThrowable(() -> interceptor(mode).invoke(call));

        assertThat(refused).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        verify(call, never()).proceed();
        verifyNoInteractions(policies, decisions, events);
        assertThat(marked()).isSameAs(refused);
    }

    /** The visitor's context came along to a thread with no request: refused, and there is no request to mark. */
    @Test
    void aVisitorWithoutARequestIsRefusedAsBefore() throws Throwable {
        RequestContextHolder.resetRequestAttributes();
        signedIn(visitor());

        assertThatThrownBy(() -> interceptor(EnforcementMode.ENFORCE).invoke(call))
                .isInstanceOf(AuthenticationCredentialsNotFoundException.class);

        verify(call, never()).proceed();
    }

    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"DISABLED", "ENFORCE"})
    void aRefusalOfTheMethodPoliciesIsMarked(EnforcementMode mode) throws Throwable {
        signedIn(user());
        AuthorizationDeniedException denied = new AuthorizationDeniedException("Access is denied by method policies");
        doThrow(denied).when(policies).protectable(any(), eq(call));

        assertThatThrownBy(() -> interceptor(mode).invoke(call)).isSameAs(denied);

        assertThat(marked()).isSameAs(denied);
    }

    /** The application's own refusal from inside the method (its @PreAuthorize, its code) stays the application's. */
    @ParameterizedTest
    @EnumSource(value = EnforcementMode.class, names = {"DISABLED", "ENFORCE"})
    void whatTheMethodItselfRefusesIsNotMarked(EnforcementMode mode) throws Throwable {
        signedIn(user());
        AuthorizationDeniedException theApplications = new AuthorizationDeniedException("Access Denied");
        when(call.proceed()).thenThrow(theApplications);

        assertThatThrownBy(() -> interceptor(mode).invoke(call)).isSameAs(theApplications);

        assertThat(marked()).isNull();
    }

    /** A decision of the analysis is answered by Contexa's own resolver, with its action and its status. */
    @Test
    void aZeroTrustDecisionIsNotMarked() throws Throwable {
        signedIn(user());
        when(decisions.asyncGate(any(), any())).thenReturn(AsyncProtectableGate.restricted(ZeroTrustAction.BLOCK));

        assertThatThrownBy(() -> interceptor(EnforcementMode.ENFORCE).invoke(call))
                .isInstanceOf(ZeroTrustAccessDeniedException.class);

        verify(call, never()).proceed();
        assertThat(marked()).isNull();
    }

    @Test
    void aSignedInUsersCallIsDecidedAsBefore() throws Throwable {
        Authentication user = user();
        signedIn(user);

        assertThat(interceptor(EnforcementMode.DISABLED).invoke(call)).isEqualTo("done");

        assertThat(subjectOfThePolicies()).isSameAs(user);
        verifyNoInteractions(decisions, events, records);
        assertThat(marked()).isNull();
    }

    public static class Work {

        @Protectable(verificationRequired = false)
        public String decided() {
            return "done";
        }
    }
}
