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

import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacommon.security.bridge.stamp.DelegationStamp;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.DelegatorAuthority;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.Pointcut;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * A1-8 (AG-11c): a delegated agent's call the method policies grant is evaluated again as the person it acts for and
 * refused before any Contexa decision when that person could not make it.
 */
class AuthorizationManagerMethodInterceptorDelegatorTest {

    private final ProtectableMethodAuthorizationManager policies = mock(ProtectableMethodAuthorizationManager.class);
    private final ProtectableRapidReentryGuard reentryGuard = mock(ProtectableRapidReentryGuard.class);
    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final SynchronousProtectableDecisionService decisions = mock(SynchronousProtectableDecisionService.class);
    private final MethodInvocation call = mock(MethodInvocation.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/reports/export");
    private AuthorizationManagerMethodInterceptor interceptor;

    @BeforeEach
    void setUp() throws Throwable {
        interceptor = new AuthorizationManagerMethodInterceptor(mock(Pointcut.class), policies, reentryGuard);
        interceptor.setZeroTrustEventPublisher(publisher);
        interceptor.setSynchronousProtectableDecisionService(decisions);
        interceptor.setDelegatorAuthority(new DelegatorAuthority(delegatorId -> "alice".equals(delegatorId)
                ? Optional.of(UsernamePasswordAuthenticationToken.authenticated("alice", null,
                AuthorityUtils.createAuthorityList("ROLE_USER")))
                : Optional.empty()));
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                "report-bot", null, AuthorityUtils.createAuthorityList("ROLE_ANALYST")));
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, new DelegationStamp("alice", "report-bot",
                true, null, null, null, List.of(), List.of(), null, null, null, null, Map.of()));
        when(call.getMethod()).thenReturn(Reports.class.getMethod("export"));
        when(call.getThis()).thenReturn(new Reports());
        when(call.proceed()).thenReturn("exported");
        when(reentryGuard.tryAcquire(any(), eq(call), anyString())).thenReturn(true);
        // The analyst policy grants the agent's account but not alice.
        doAnswer(invocation -> {
            Supplier<Authentication> caller = invocation.getArgument(0);
            if ("alice".equals(caller.get().getName())) {
                throw new AuthorizationDeniedException("Access is denied by method policies");
            }
            return null;
        }).when(policies).protectable(any(), eq(call));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void aCallTheDelegatorCouldNotMakeIsRefusedBeforeAnyDecision() throws Throwable {
        assertThatThrownBy(() -> interceptor.invoke(call))
                .isInstanceOf(AuthorizationDeniedException.class)
                .hasMessageContaining("delegator alice");

        verify(call, never()).proceed();
        verifyNoInteractions(decisions);
        verify(publisher, never()).publishMethodAuthorization(any(), any(), eq(true), any(), any(), any());
        assertThat(request.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isEqualTo("DENIED");
    }

    @Test
    void shadowModeRecordsTheRefusalAndRunsTheCall() throws Throwable {
        SecurityZeroTrustProperties shadow = new SecurityZeroTrustProperties();
        shadow.setMode(SecurityZeroTrustProperties.EnforcementMode.SHADOW);
        interceptor.setSecurityZeroTrustProperties(shadow);

        assertThat(interceptor.invoke(call)).isEqualTo("exported");
        assertThat(request.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isEqualTo("DENIED");
    }

    @Test
    void anAgentOnItsOwnIsNotCheckedAgainstADelegator() throws Throwable {
        request.setAttribute(BridgeRequestAttributes.DELEGATION_STAMP, new DelegationStamp("report-bot", "report-bot",
                false, null, null, null, List.of(), List.of(), null, null, null, null, Map.of()));

        assertThat(interceptor.invoke(call)).isEqualTo("exported");
        assertThat(request.getAttribute(BridgeRequestAttributes.DELEGATOR_AUTHORITY)).isNull();
    }

    static class Reports {
        public String export() {
            return "exported";
        }
    }
}
