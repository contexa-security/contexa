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

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.mfa.context.FactorContext;
import io.contexa.contexaidentity.security.filter.matcher.MfaUrlMatcher;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.core.validator.MfaContextValidator;
import io.contexa.contexaidentity.security.core.validator.ValidationResult;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

import java.lang.reflect.Field;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

class MfaContinuationFilterPrimaryProofTest {

    private final Authentication primary = UsernamePasswordAuthenticationToken.authenticated("admin", null, List.of());
    private MfaContinuationFilter filter;
    private MfaStateMachineIntegrator stateMachineIntegrator;

    @BeforeEach
    void setUp() throws Exception {
        ApplicationContext applicationContext = mock(ApplicationContext.class);
        AuthUrlProvider authUrlProvider = mock(AuthUrlProvider.class);
        stateMachineIntegrator = mock(MfaStateMachineIntegrator.class);
        when(applicationContext.getBean(AuthUrlProvider.class)).thenReturn(authUrlProvider);
        when(applicationContext.getBean(MfaStateMachineIntegrator.class)).thenReturn(stateMachineIntegrator);
        when(applicationContext.getBean(MfaSessionRepository.class)).thenReturn(mock(MfaSessionRepository.class));
        when(applicationContext.getBean(MfaFlowUrlRegistry.class)).thenReturn(mock(MfaFlowUrlRegistry.class));

        filter = new MfaContinuationFilter(mock(AuthContextProperties.class), mock(AuthResponseWriter.class), applicationContext);
        MfaUrlMatcher urlMatcher = mock(MfaUrlMatcher.class);
        when(urlMatcher.isMfaRequest(any())).thenReturn(false);
        setField(filter, "urlMatcher", urlMatcher);

        AuthUrlProvider flowProvider = mock(AuthUrlProvider.class);
        when(flowProvider.getMfaInProgressUrls()).thenReturn(new LinkedHashSet<>(List.of(
                "/mfa/login", "/login", "/login/rest", "/mfa/login?error", "/logout-page", "/logout",
                "/mfa/select-factor", "/mfa/challenge/ott", "/login/mfa-ott", "/webauthn/authenticate/options")));
        when(flowProvider.getPrimaryLoginPage()).thenReturn("/mfa/login");
        when(flowProvider.getPrimaryFormLoginProcessing()).thenReturn("/login");
        when(flowProvider.getPrimaryRestLoginProcessing()).thenReturn("/login/rest");
        when(flowProvider.getPrimaryLoginFailure()).thenReturn("/mfa/login?error");
        when(flowProvider.getLogoutPage()).thenReturn("/logout-page");
        when(flowProvider.getLogoutProcessingUrl()).thenReturn("/logout");
        filter.initializeUrlMatchers(flowProvider);
        filter.setFlowTypeName("mfa");

        FactorContext factorContext = mock(FactorContext.class);
        when(factorContext.getFlowTypeName()).thenReturn("mfa");
        when(factorContext.getPrimaryAuthentication()).thenReturn(primary);
        when(stateMachineIntegrator.loadFactorContextFromRequest(any())).thenReturn(factorContext);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("A token state exposes the primary proof to an MFA step request")
    void restoresPrimaryProofForMfaStep() throws Exception {
        filter.setRestorePrimaryProof(true);

        assertThat(authenticationSeenBy("/login/mfa-ott")).isSameAs(primary);
    }

    @Test
    @DisplayName("The restored proof is registered for the request, so session management sees no new login")
    void restoredProofIsRegisteredForTheRequest() throws Exception {
        filter.setRestorePrimaryProof(true);
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/webauthn/authenticate/options");
        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            validator.when(() -> MfaContextValidator.validateMfaContext(any())).thenReturn(new ValidationResult());
            filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> {
            });
        }

        assertThat(new RequestAttributeSecurityContextRepository().containsContext(request)).isTrue();
    }

    @Test
    @DisplayName("The passkey registration page never receives the primary proof of a pending MFA")
    void doesNotRestoreForPasskeyRegistration() throws Exception {
        filter.setRestorePrimaryProof(true);

        assertThat(authenticationSeenBy("/webauthn/register")).isNull();
    }

    @Test
    @DisplayName("The primary login URL does not receive the primary proof")
    void doesNotRestoreForPrimaryLogin() throws Exception {
        filter.setRestorePrimaryProof(true);

        assertThat(authenticationSeenBy("/login")).isNull();
    }

    @Test
    @DisplayName("The session state keeps its own login handling and restores nothing")
    void sessionStateRestoresNothing() throws Exception {
        filter.setRestorePrimaryProof(false);

        assertThat(authenticationSeenBy("/login/mfa-ott")).isNull();
    }

    private Authentication authenticationSeenBy(String path) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
        AtomicReference<Authentication> seen = new AtomicReference<>();
        try (MockedStatic<MfaContextValidator> validator = mockStatic(MfaContextValidator.class)) {
            validator.when(() -> MfaContextValidator.validateMfaContext(any())).thenReturn(new ValidationResult());
            filter.doFilter(request, new MockHttpServletResponse(),
                    (req, res) -> seen.set(SecurityContextHolder.getContext().getAuthentication()));
        }
        return seen.get();
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = MfaContinuationFilter.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
