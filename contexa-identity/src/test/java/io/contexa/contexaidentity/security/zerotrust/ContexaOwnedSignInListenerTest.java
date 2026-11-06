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
package io.contexa.contexaidentity.security.zerotrust;

import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.ott.OneTimeTokenAuthenticationFilter;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Where Contexa owns the sign-in, a single-factor login of a flow that keeps Spring Security's own filter and handler
 * (form, one-time code, passkey) goes to the engine from the filter's event. A step of an MFA flow is no sign-in yet: the
 * flow's final success sends it.
 */
class ContexaOwnedSignInListenerTest {

    private final ZeroTrustEventPublisher publisher = mock(ZeroTrustEventPublisher.class);
    private final MfaStateMachineIntegrator mfaFlows = mock(MfaStateMachineIntegrator.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
    private final TestingAuthenticationToken signedIn = new TestingAuthenticationToken("customer", null, "ROLE_USER");

    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
    }

    private void inTheRequest() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @Test
    @DisplayName("a single-factor sign-in is published as an authentication success")
    void aSingleFactorSignInIsPublished() {
        inTheRequest();

        new ContexaOwnedSignInListener(publisher, mfaFlows).onApplicationEvent(
                new InteractiveAuthenticationSuccessEvent(signedIn, UsernamePasswordAuthenticationFilter.class));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> payload = ArgumentCaptor.forClass(Map.class);
        verify(publisher).publishAuthenticationSuccess(eq(signedIn), eq(request), payload.capture());
        assertThat(payload.getValue()).containsEntry("authenticationType", "SINGLE")
                .containsEntry("signedInBy", "UsernamePasswordAuthenticationFilter");
    }

    @Test
    @DisplayName("a factor of an MFA flow of the same person is no sign-in yet")
    void aFactorOfAnMfaFlowIsNoSignInYet() {
        inTheRequest();
        FactorContext underWay = new FactorContext("mfa-session-1", signedIn, MfaState.NONE, "mfa");
        underWay.changeState(MfaState.FACTOR_VERIFICATION_PENDING);
        when(mfaFlows.loadFactorContextFromRequest(request)).thenReturn(underWay);

        new ContexaOwnedSignInListener(publisher, mfaFlows).onApplicationEvent(
                new InteractiveAuthenticationSuccessEvent(signedIn, OneTimeTokenAuthenticationFilter.class));

        verify(publisher, never()).publishAuthenticationSuccess(any(), any(), any());
    }

    @Test
    @DisplayName("an MFA flow left by another person does not hide this one's sign-in")
    void anotherPersonsFlowDoesNotHideIt() {
        inTheRequest();
        FactorContext someoneElses = new FactorContext("mfa-session-2",
                new TestingAuthenticationToken("someone-else", null, "ROLE_USER"), MfaState.NONE, "mfa");
        when(mfaFlows.loadFactorContextFromRequest(request)).thenReturn(someoneElses);

        new ContexaOwnedSignInListener(publisher, mfaFlows).onApplicationEvent(
                new InteractiveAuthenticationSuccessEvent(signedIn, UsernamePasswordAuthenticationFilter.class));

        verify(publisher).publishAuthenticationSuccess(eq(signedIn), eq(request), any());
    }

    @Test
    @DisplayName("a store of MFA flows that cannot be read does not hide the sign-in")
    void anUnreadableFlowStoreDoesNotHideIt() {
        inTheRequest();
        when(mfaFlows.loadFactorContextFromRequest(request)).thenThrow(new IllegalStateException("store down"));

        new ContexaOwnedSignInListener(publisher, mfaFlows).onApplicationEvent(
                new InteractiveAuthenticationSuccessEvent(signedIn, UsernamePasswordAuthenticationFilter.class));

        verify(publisher).publishAuthenticationSuccess(eq(signedIn), eq(request), any());
    }

    @Test
    @DisplayName("a sign-in that cannot be sent is a sign-in all the same")
    void aSignInThatCannotBeSentGoesOn() {
        inTheRequest();
        doThrow(new IllegalStateException("no engine")).when(publisher).publishAuthenticationSuccess(any(), any(), any());

        assertThatCode(() -> new ContexaOwnedSignInListener(publisher, mfaFlows).onApplicationEvent(
                new InteractiveAuthenticationSuccessEvent(signedIn, UsernamePasswordAuthenticationFilter.class)))
                .doesNotThrowAnyException();
    }
}
