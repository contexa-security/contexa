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
import io.contexa.contexacommon.security.bridge.BridgeRequestAttributes;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexaiam.security.xacml.pep.AuthorizationManagerMethodInterceptor;
import io.contexa.contexaiam.security.xacml.pep.ProtectableMethodAuthorizationManager;
import io.contexa.contexaiam.security.xacml.pep.ProtectableRapidReentryGuard;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.aop.Pointcut;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * R-10 of docs/agent/운영모드-정상화-구현계획.md: a {@code @Protectable} call of a user the bridge resolved for Contexa
 * alone is decided for that user, the method policies' expressions included; a user the application makes known after
 * Contexa's request filters is resolved at the decision; the application's security context is not changed.
 */
@DisplayName("@Protectable은 Contexa 신원으로 판정하고 판정 때 늦은 신원을 해석한다(R-10)")
class AuthorizationManagerMethodInterceptorContexaIdentityTest {

    private final ProtectableMethodAuthorizationManager authorizationManager = mock(ProtectableMethodAuthorizationManager.class);
    private final ProtectableRapidReentryGuard rapidReentryGuard = mock(ProtectableRapidReentryGuard.class);
    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final MethodInvocation invocation = mock(MethodInvocation.class);
    private final Authentication carol = signedIn("carol");
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/orders/export");
    private AuthorizationManagerMethodInterceptor interceptor;

    @BeforeEach
    void setUp() throws Throwable {
        SecurityContextHolder.clearContext();
        interceptor = new AuthorizationManagerMethodInterceptor(mock(Pointcut.class), authorizationManager, rapidReentryGuard);
        interceptor.setZeroTrustEventPublisher(publisher);
        when(invocation.getMethod()).thenReturn(Orders.class.getMethod("export"));
        when(invocation.getThis()).thenReturn(new Orders());
        when(invocation.proceed()).thenReturn("exported");
        when(rapidReentryGuard.tryAcquire(eq(carol), eq(invocation), anyString())).thenReturn(true);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("요청 필터가 둔 bridge 신원으로 메서드 정책과 판정을 한다")
    void theBridgedUserIsDecided() throws Throwable {
        request.setAttribute(BridgeRequestAttributes.IDENTITY, carol);

        assertThat(interceptor.invoke(invocation)).isEqualTo("exported");

        assertThat(policyAuthentication()).isSameAs(carol);
        verify(publisher).publishMethodAuthorization(eq(invocation), eq(carol), eq(true), isNull(),
                eq(ZeroTrustEventPublisher.METHOD_COMPLETED), isNull());
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("요청 필터 뒤에 알려진 사용자는 판정 시점에 해석한다")
    void aLateUserIsResolvedAtTheDecision() throws Throwable {
        interceptor.setIdentityResolution(late -> late.setAttribute(BridgeRequestAttributes.IDENTITY, carol));

        assertThat(interceptor.invoke(invocation)).isEqualTo("exported");

        assertThat(policyAuthentication()).isSameAs(carol);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @DisplayName("해석할 사용자가 없는 요청은 지금처럼 거부한다")
    void anUnresolvedRequestIsRefusedAsBefore() {
        interceptor.setIdentityResolution(late -> { });

        assertThatThrownBy(() -> interceptor.invoke(invocation)).isInstanceOf(AccessDeniedException.class);
    }

    @SuppressWarnings("unchecked")
    private Authentication policyAuthentication() {
        ArgumentCaptor<Supplier<Authentication>> supplier = ArgumentCaptor.forClass(Supplier.class);
        verify(authorizationManager).protectable(supplier.capture(), eq(invocation));
        return supplier.getValue().get();
    }

    private static Authentication signedIn(String name) {
        TestingAuthenticationToken authentication = new TestingAuthenticationToken(name, null, "ROLE_USER");
        authentication.setAuthenticated(true);
        return authentication;
    }

    public static class Orders {
        @Protectable
        public String export() {
            return "exported";
        }
    }
}
