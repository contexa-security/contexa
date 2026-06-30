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
package io.contexa.contexaidentity.security.handler;

import io.contexa.contexacommon.properties.MfaSettings;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.service.IBlockedUserRecorder;
import io.contexa.contexacore.hcad.store.HCADDataStore;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UnifiedAuthenticationFailureHandlerTest {

    @Mock
    private AuthResponseWriter responseWriter;

    @Mock
    private MfaStateMachineIntegrator stateMachineIntegrator;

    @Mock
    private MfaSessionRepository sessionRepository;

    @Mock
    private ZeroTrustActionRepository actionRepository;

    @Mock
    private MfaSettings mfaSettings;

    @Mock
    private IBlockedUserRecorder blockedUserRecorder;

    @Mock
    private LoginPolicyHandler loginPolicyHandler;

    @Mock
    private HCADDataStore hcadDataStore;

    private UnifiedAuthenticationFailureHandler handler;

    @BeforeEach
    void setUp() {
        handler = new UnifiedAuthenticationFailureHandler(
                responseWriter,
                stateMachineIntegrator,
                sessionRepository,
                actionRepository,
                mfaSettings,
                blockedUserRecorder,
                null,
                loginPolicyHandler,
                hcadDataStore
        );
    }

    @Test
    void primaryAuthenticationFailureRecordsOnlyHcadFailureCounter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setParameter("username", "admin");
        request.setRemoteAddr("203.0.113.10");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        verify(hcadDataStore).recordLoginFailure(eq("admin"), isNull(), anyLong());
        verify(loginPolicyHandler).onLoginFailure("admin");
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=primary_auth_failed");
    }

    @Test
    void primaryAuthenticationFailureWithoutSubmittedPrincipalDoesNotPoisonHcadCounter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        when(stateMachineIntegrator.loadFactorContextFromRequest(request)).thenReturn(null);

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("bad credentials"));

        verify(hcadDataStore, never()).recordLoginFailure(eq("UnknownUser"), isNull(), anyLong());
        verify(loginPolicyHandler, never()).onLoginFailure("UnknownUser");
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error=primary_auth_failed");
    }
}