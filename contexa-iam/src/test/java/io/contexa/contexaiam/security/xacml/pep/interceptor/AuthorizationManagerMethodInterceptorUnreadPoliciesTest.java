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
import io.contexa.contexacommon.annotation.ResourceImportance;
import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacommon.store.ContexaStores;
import io.contexa.contexacommon.store.StoreUnavailableException;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.execution.ZeroTrustAccessDeniedException;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.aop.Pointcut;
import org.springframework.dao.QueryTimeoutException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.CannotCreateTransactionException;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * While the database does not answer, the method policies of a call may hold a DENY nobody can read. A call to a
 * sensitive resource is then refused for this request, as a call without a decision is while the analysis is behind;
 * a call to a general resource goes on, as the operating mode specifies.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthorizationManagerMethodInterceptorUnreadPoliciesTest {

    static class Resources {

        @Protectable(importance = ResourceImportance.SENSITIVE)
        public String sensitive() {
            return "sensitive";
        }

        @Protectable(sensitivity = "RESTRICTED")
        public String restricted() {
            return "restricted";
        }

        @Protectable
        public String general() {
            return "general";
        }

        @Protectable(importance = ResourceImportance.SENSITIVE, sync = true)
        public String sensitiveAndDecidedInPlace() {
            return "sync";
        }
    }

    @Mock
    private Pointcut pointcut;
    @Mock
    private ProtectableMethodAuthorizationManager authorizationManager;
    @Mock
    private ProtectableRapidReentryGuard rapidReentryGuard;
    @Mock
    private ZeroTrustEventPublisher zeroTrustEventPublisher;
    @Mock
    private SynchronousProtectableDecisionService decisions;
    @Mock
    private MethodInvocation invocation;
    @Mock
    private Authentication authentication;

    private AuthorizationManagerMethodInterceptor interceptor;

    @BeforeEach
    void setUp() throws Throwable {
        interceptor = new AuthorizationManagerMethodInterceptor(pointcut, authorizationManager, rapidReentryGuard);
        interceptor.setZeroTrustEventPublisher(zeroTrustEventPublisher);
        interceptor.setSynchronousProtectableDecisionService(decisions);
        SecurityContext context = mock(SecurityContext.class);
        when(context.getAuthentication()).thenReturn(authentication);
        SecurityContextHolder.setContext(context);
        when(rapidReentryGuard.tryAcquire(eq(authentication), eq(invocation), anyString())).thenReturn(true);
        when(decisions.asyncGate(invocation, authentication))
                .thenReturn(SynchronousProtectableDecisionService.AsyncProtectableGate.PROCEED);
        when(invocation.getThis()).thenReturn(new Resources());
        when(invocation.proceed()).thenReturn("ran");
        mode(SecurityZeroTrustProperties.EnforcementMode.ENFORCE);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private void mode(SecurityZeroTrustProperties.EnforcementMode mode) {
        SecurityZeroTrustProperties properties = new SecurityZeroTrustProperties();
        properties.setMode(mode);
        interceptor.setSecurityZeroTrustProperties(properties);
    }

    private void calling(String method) throws Exception {
        Method target = Resources.class.getMethod(method);
        when(invocation.getMethod()).thenReturn(target);
    }

    private void thePoliciesCannotBeRead() {
        doThrow(new CannotCreateTransactionException("no connection"))
                .when(authorizationManager).protectable(any(), eq(invocation));
    }

    private void theCallIsRefusedForItsVerification() throws Throwable {
        assertThatThrownBy(() -> interceptor.invoke(invocation))
                .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                        refused -> assertThat(refused.getAction()).isEqualTo(ZeroTrustAction.CHALLENGE.name()));
        verify(invocation, never()).proceed();
    }

    @Test
    void aSensitiveCallIsRefusedWhileItsPoliciesCannotBeRead() throws Throwable {
        calling("sensitive");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);
        thePoliciesCannotBeRead();

        theCallIsRefusedForItsVerification();
    }

    @Test
    void theRefusedCallIsRecordedAsACheckThatDidNotFinishAndAMethodThatDidNotRun() throws Throwable {
        calling("sensitive");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);
        thePoliciesCannotBeRead();

        theCallIsRefusedForItsVerification();

        verify(zeroTrustEventPublisher).publishUncheckedMethodAuthorization(eq(invocation), eq(authentication),
                eq("CannotCreateTransactionException"), eq(ZeroTrustEventPublisher.METHOD_NOT_RUN), isNull());
    }

    @Test
    void aRefusedCallIsNotCountedAsOneThatWentOn() throws Throwable {
        calling("sensitive");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);
        thePoliciesCannotBeRead();
        ContexaStores stores = new ContexaStores();
        List<ContexaStores.UndecidedCalls> records = new ArrayList<>();
        stores.setRecorder(records::add);
        interceptor.setContexaStores(stores);

        theCallIsRefusedForItsVerification();

        assertThat(records).isEmpty();
    }

    @Test
    void aGeneralCallGoesOnWhileItsPoliciesCannotBeRead() throws Throwable {
        calling("general");
        when(decisions.sensitive(invocation, authentication)).thenReturn(false);
        thePoliciesCannotBeRead();

        assertThat(interceptor.invoke(invocation)).isEqualTo("ran");
    }

    @Test
    void aSensitiveCallWhosePoliciesWereReadGoesOn() throws Throwable {
        calling("sensitive");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);

        assertThat(interceptor.invoke(invocation)).isEqualTo("ran");
    }

    @Test
    void aFailureThatIsNoStoreStaysWhatItWas() throws Throwable {
        calling("sensitive");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);
        doThrow(new IllegalStateException("a bug in a policy"))
                .when(authorizationManager).protectable(any(), eq(invocation));

        assertThatThrownBy(() -> interceptor.invoke(invocation)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void aRealDenialStaysADenial() throws Throwable {
        calling("sensitive");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);
        doThrow(new AuthorizationDeniedException("role cannot read customers"))
                .when(authorizationManager).protectable(any(), eq(invocation));

        assertThatThrownBy(() -> interceptor.invoke(invocation))
                .isInstanceOf(AuthorizationDeniedException.class)
                .isNotInstanceOf(ZeroTrustAccessDeniedException.class);
    }

    @Test
    void aRestrictionInForceAnswersBeforeTheRefusal() throws Throwable {
        calling("sensitive");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);
        thePoliciesCannotBeRead();
        when(decisions.asyncGate(invocation, authentication))
                .thenReturn(SynchronousProtectableDecisionService.AsyncProtectableGate.restricted(ZeroTrustAction.BLOCK));

        assertThatThrownBy(() -> interceptor.invoke(invocation))
                .isInstanceOfSatisfying(ZeroTrustAccessDeniedException.class,
                        refused -> assertThat(refused.getAction()).isEqualTo(ZeroTrustAction.BLOCK.name()));
    }

    @Test
    void anAllowOfTheModelSaysNothingOfAPolicyNobodyRead() throws Throwable {
        calling("sensitiveAndDecidedInPlace");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);
        thePoliciesCannotBeRead();
        SynchronousProtectableDecisionService.SyncDecisionResult allowed =
                mock(SynchronousProtectableDecisionService.SyncDecisionResult.class);
        when(allowed.action()).thenReturn(ZeroTrustAction.ALLOW);
        when(decisions.analyze(invocation, authentication)).thenReturn(allowed);

        theCallIsRefusedForItsVerification();
    }

    @Test
    void aSynchronousDecisionAStoreEndedIsRefusedToo() throws Throwable {
        calling("sensitiveAndDecidedInPlace");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);
        thePoliciesCannotBeRead();
        when(decisions.analyze(invocation, authentication)).thenThrow(new StoreUnavailableException("Redis"));

        theCallIsRefusedForItsVerification();
    }

    @Test
    void aSynchronousCallWhosePoliciesWereReadGoesOnWhenAStoreEndsItsDecision() throws Throwable {
        calling("sensitiveAndDecidedInPlace");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);
        when(decisions.analyze(invocation, authentication)).thenThrow(new StoreUnavailableException("Redis"));

        assertThat(interceptor.invoke(invocation)).isEqualTo("ran");
    }

    @Test
    void whatTheMethodDeclaresAnswersWhenTheFactsOfTheCallCannotBeRead() throws Throwable {
        calling("sensitive");
        when(decisions.sensitive(invocation, authentication)).thenThrow(new QueryTimeoutException("no answer"));
        thePoliciesCannotBeRead();

        theCallIsRefusedForItsVerification();
    }

    @Test
    void aSensitivityWordOnTheMethodCountsAsItsDeclaration() throws Throwable {
        calling("restricted");
        when(decisions.sensitive(invocation, authentication)).thenThrow(new QueryTimeoutException("no answer"));
        thePoliciesCannotBeRead();

        theCallIsRefusedForItsVerification();
    }

    @Test
    void aGeneralMethodGoesOnWhenTheFactsOfTheCallCannotBeRead() throws Throwable {
        calling("general");
        when(decisions.sensitive(invocation, authentication)).thenThrow(new QueryTimeoutException("no answer"));
        thePoliciesCannotBeRead();

        assertThat(interceptor.invoke(invocation)).isEqualTo("ran");
    }

    @Test
    void whereDecisionsAreNotEnforcedNothingIsRefused() throws Throwable {
        calling("sensitive");
        when(decisions.sensitive(invocation, authentication)).thenReturn(true);
        thePoliciesCannotBeRead();
        mode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);

        assertThat(interceptor.invoke(invocation)).isEqualTo("ran");
    }

    @Test
    void withoutTheDecisionServiceTheMethodsDeclarationDecides() throws Throwable {
        calling("sensitive");
        interceptor.setSynchronousProtectableDecisionService(null);
        thePoliciesCannotBeRead();

        theCallIsRefusedForItsVerification();
    }
}
