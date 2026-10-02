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
package io.contexa.contexaidentity.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.mfa.util.MfaPendingSessionMarker;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import io.contexa.contexaidentity.security.statemachine.enums.MfaState;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaRestAuthenticationFilterTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private RequestMatcher requestMatcher;

    @Mock
    private MfaStateMachineIntegrator stateMachineIntegrator;

    @Mock
    private MfaSessionRepository sessionRepository;

    @Mock
    private PlatformAuthenticationSuccessHandler successHandler;

    @Mock
    private PlatformAuthenticationFailureHandler failureHandler;

    @Mock
    private SecurityContextRepository securityContextRepository;

    private MfaRestAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        when(applicationContext.getBean(MfaStateMachineIntegrator.class)).thenReturn(stateMachineIntegrator);
        when(applicationContext.getBean(MfaSessionRepository.class)).thenReturn(sessionRepository);
        when(sessionRepository.supportsDistributedSync()).thenReturn(false);
        when(stateMachineIntegrator.getCurrentState(anyString())).thenReturn(MfaState.NONE);

        AuthContextProperties properties = new AuthContextProperties();
        properties.getMfa().setMinimumDelayMs(0L);
        filter = new MfaRestAuthenticationFilter(authenticationManager, applicationContext, properties, requestMatcher);
        filter.setSuccessHandler(successHandler);
        filter.setFailureHandler(failureHandler);
        filter.setSecurityContextRepository(securityContextRepository);
    }

    @Test
    @DisplayName("Primary REST authentication marks the session before the SecurityContext is saved")
    void marksSessionBeforeSavingContext() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/mfa/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated("user", null, List.of());
        filter.setFlowTypeName("mfa_api");
        AtomicReference<String> markerAtSave = new AtomicReference<>();
        doAnswer(invocation -> {
            markerAtSave.set(MfaPendingSessionMarker.getPendingFlowTypeName(request));
            return null;
        }).when(securityContextRepository).saveContext(any(), eq(request), eq(response));

        filter.successfulAuthentication(request, response, new MockFilterChain(), authentication);

        assertThat(markerAtSave.get()).isEqualTo("mfa_api");
        assertThat(MfaPendingSessionMarker.getPendingFlowTypeName(request)).isEqualTo("mfa_api");
        verify(successHandler).onAuthenticationSuccess(request, response, authentication);
    }
}
