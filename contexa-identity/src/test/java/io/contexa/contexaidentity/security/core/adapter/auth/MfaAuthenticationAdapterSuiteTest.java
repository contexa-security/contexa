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
package io.contexa.contexaidentity.security.core.adapter.auth;

import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.core.dsl.configurer.impl.MfaFormAuthenticationConfigurer;
import io.contexa.contexaidentity.security.core.dsl.configurer.impl.MfaRestAuthenticationConfigurer;
import io.contexa.contexaidentity.security.core.dsl.option.FormOptions;
import io.contexa.contexaidentity.security.core.dsl.option.OttOptions;
import io.contexa.contexaidentity.security.core.dsl.option.PasskeyOptions;
import io.contexa.contexaidentity.security.core.dsl.option.RestOptions;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationFailureHandler;
import io.contexa.contexaidentity.security.handler.PlatformAuthenticationSuccessHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.WebAuthnConfigurer;
import org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MfaAuthenticationAdapterSuiteTest {

    @Mock
    private HttpSecurity httpSecurity;

    @Mock
    private PlatformContext platformContext;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private AuthContextProperties authContextProperties;

    @Mock
    private StateConfig stateConfig;

    @Mock
    private AuthenticationFlowConfig currentFlow;

    @BeforeEach
    void setUp() {
        when(httpSecurity.getSharedObject(PlatformContext.class)).thenReturn(platformContext);
        when(platformContext.applicationContext()).thenReturn(applicationContext);
        when(applicationContext.getBean(AuthContextProperties.class)).thenReturn(authContextProperties);
        when(authContextProperties.getStateType()).thenReturn(StateType.SESSION);
        when(httpSecurity.getSharedObject(AuthenticationFlowConfig.class)).thenReturn(currentFlow);
        when(currentFlow.getStateConfig()).thenReturn(stateConfig);
        when(stateConfig.stateType()).thenReturn(StateType.SESSION);
    }

    @Nested
    @DisplayName("MfaFormAuthenticationAdapter tests")
    class MfaFormAdapterTests {

        private MfaFormAuthenticationAdapter adapter;

        @BeforeEach
        void setUp() {
            adapter = new MfaFormAuthenticationAdapter();
        }

        @Test
        @DisplayName("getId should return 'mfa_form'")
        void getIdReturnsMfaForm() {
            assertThat(adapter.getId()).isEqualTo("mfa_form");
        }

        @Test
        @DisplayName("getOrder should return 100")
        void getOrderReturns100() {
            assertThat(adapter.getOrder()).isEqualTo(100);
        }

        @Test
        @DisplayName("apply should configure MFA Form Login successfully")
        @SuppressWarnings("unchecked")
        void applyConfiguresMfaFormLogin() throws Exception {
            FormOptions options = mock(FormOptions.class);
            when(options.getLoginProcessingUrl()).thenReturn("/mfa/login/form");
            when(options.getUsernameParameter()).thenReturn("mfa-user");
            when(options.getPasswordParameter()).thenReturn("mfa-pass");
            when(options.getEffectiveLoginPage()).thenReturn("/mfa-login-page");
            when(options.getFailureUrl()).thenReturn("/mfa-error");
            when(options.getDefaultSuccessUrl()).thenReturn("/home");
            when(options.isAlwaysUseDefaultSuccessUrl()).thenReturn(true);
            when(options.isPermitAll()).thenReturn(true);

            AuthenticationStepConfig step = new AuthenticationStepConfig();
            step.setType("mfa_form");
            step.getOptions().put(AuthenticationStepConfig.OPTIONS_KEY, options);

            MfaFormAuthenticationConfigurer<HttpSecurity> mockConfigurer = mock(MfaFormAuthenticationConfigurer.class);
            when(mockConfigurer.loginProcessingUrl(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.usernameParameter(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.passwordParameter(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.loginPage(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.failureUrl(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.successUrl(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.successUrl(any(), any(Boolean.class))).thenReturn(mockConfigurer);
            when(mockConfigurer.successHandler(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.failureHandler(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.permitAll(any(Boolean.class))).thenReturn(mockConfigurer);

            doAnswer(invocation -> {
                Customizer<MfaFormAuthenticationConfigurer<HttpSecurity>> customizer = invocation.getArgument(1);
                customizer.customize(mockConfigurer);
                return httpSecurity;
            }).when(httpSecurity).with(any(MfaFormAuthenticationConfigurer.class), any(Customizer.class));

            adapter.apply(httpSecurity, List.of(step), stateConfig);

            verify(mockConfigurer).loginProcessingUrl("/mfa/login/form");
            verify(mockConfigurer).usernameParameter("mfa-user");
            verify(mockConfigurer).passwordParameter("mfa-pass");
            verify(mockConfigurer).loginPage("/mfa-login-page");
            verify(mockConfigurer).failureUrl("/mfa-error");
            verify(mockConfigurer).successUrl("/home", true);
            verify(mockConfigurer).permitAll(true);
        }
    }

    @Nested
    @DisplayName("MfaRestAuthenticationAdapter tests")
    class MfaRestAdapterTests {

        private MfaRestAuthenticationAdapter adapter;

        @BeforeEach
        void setUp() {
            adapter = new MfaRestAuthenticationAdapter();
        }

        @Test
        @DisplayName("getId should return 'mfa_rest'")
        void getIdReturnsMfaRest() {
            assertThat(adapter.getId()).isEqualTo("mfa_rest");
        }

        @Test
        @DisplayName("apply should configure MFA Rest Login successfully")
        @SuppressWarnings("unchecked")
        void applyConfiguresMfaRestLogin() throws Exception {
            RestOptions options = mock(RestOptions.class);
            when(options.getLoginProcessingUrl()).thenReturn("/mfa/login/rest");
            when(options.getSecurityContextRepository()).thenReturn(mock(SecurityContextRepository.class));

            AuthenticationStepConfig step = new AuthenticationStepConfig();
            step.setType("mfa_rest");
            step.getOptions().put(AuthenticationStepConfig.OPTIONS_KEY, options);

            MfaRestAuthenticationConfigurer<HttpSecurity> mockConfigurer = mock(MfaRestAuthenticationConfigurer.class);
            when(mockConfigurer.loginProcessingUrl(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.successHandler(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.failureHandler(any())).thenReturn(mockConfigurer);

            doAnswer(invocation -> {
                Customizer<MfaRestAuthenticationConfigurer<HttpSecurity>> customizer = invocation.getArgument(1);
                customizer.customize(mockConfigurer);
                return httpSecurity;
            }).when(httpSecurity).with(any(MfaRestAuthenticationConfigurer.class), any(Customizer.class));

            adapter.apply(httpSecurity, List.of(step), stateConfig);

            verify(mockConfigurer).loginProcessingUrl("/mfa/login/rest");
        }
    }

    @Nested
    @DisplayName("MfaOttAuthenticationAdapter tests")
    class MfaOttAdapterTests {

        private MfaOttAuthenticationAdapter adapter;

        @BeforeEach
        void setUp() {
            adapter = new MfaOttAuthenticationAdapter();
        }

        @Test
        @DisplayName("getId should return 'mfa_ott'")
        void getIdReturnsMfaOtt() {
            assertThat(adapter.getId()).isEqualTo("mfa_ott");
        }

        @Test
        @DisplayName("getOrder should return 301")
        void getOrderReturns301() {
            assertThat(adapter.getOrder()).isEqualTo(301);
        }

        @Test
        @DisplayName("configureHttpSecurity directly should throw UnsupportedOperationException")
        void configureHttpSecurityThrowsException() {
            OttOptions options = mock(OttOptions.class);
            assertThatThrownBy(() -> adapter.configureHttpSecurity(httpSecurity, options, currentFlow, null, null))
                    .isInstanceOf(UnsupportedOperationException.class)
                    .hasMessageContaining("configureHttpSecurityForOtt instead");
        }

        @Test
        @DisplayName("configureHttpSecurityForOtt should configure OTT login successfully")
        @SuppressWarnings("unchecked")
        void configureHttpSecurityForOttConfiguresOtt() throws Exception {
            OttOptions options = mock(OttOptions.class);
            when(options.getLoginProcessingUrl()).thenReturn("/mfa/login/ott");
            when(options.getDefaultSubmitPageUrl()).thenReturn("/mfa/ott/submit");
            when(options.isShowDefaultSubmitPage()).thenReturn(true);
            when(options.getTokenGeneratingUrl()).thenReturn("/mfa/ott/generate");

            OneTimeTokenGenerationSuccessHandler genHandler = mock(OneTimeTokenGenerationSuccessHandler.class);
            PlatformAuthenticationSuccessHandler successHandler = mock(PlatformAuthenticationSuccessHandler.class);
            PlatformAuthenticationFailureHandler failureHandler = mock(PlatformAuthenticationFailureHandler.class);

            when(applicationContext.getBean(UserDetailsService.class)).thenReturn(mock(UserDetailsService.class));
            when(applicationContext.getBean(OneTimeTokenService.class)).thenReturn(mock(OneTimeTokenService.class));

            OneTimeTokenLoginConfigurer<HttpSecurity> mockConfigurer = mock(OneTimeTokenLoginConfigurer.class);
            when(mockConfigurer.defaultSubmitPageUrl(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.loginProcessingUrl(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.showDefaultSubmitPage(any(Boolean.class))).thenReturn(mockConfigurer);
            when(mockConfigurer.tokenGeneratingUrl(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.tokenService(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.tokenGenerationSuccessHandler(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.generateRequestResolver(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.authenticationProvider(any())).thenReturn(mockConfigurer);

            when(httpSecurity.oneTimeTokenLogin(any(Customizer.class))).thenAnswer(invocation -> {
                Customizer<OneTimeTokenLoginConfigurer<HttpSecurity>> customizer = invocation.getArgument(0);
                customizer.customize(mockConfigurer);
                return httpSecurity;
            });

            adapter.configureHttpSecurityForOtt(httpSecurity, options, genHandler, successHandler, failureHandler);

            verify(mockConfigurer).loginProcessingUrl("/mfa/login/ott");
            verify(mockConfigurer).defaultSubmitPageUrl("/mfa/ott/submit");
            verify(mockConfigurer).showDefaultSubmitPage(true);
            verify(mockConfigurer).tokenGeneratingUrl("/mfa/ott/generate");
        }
    }

    @Nested
    @DisplayName("MfaPasskeyAuthenticationAdapter tests")
    class MfaPasskeyAdapterTests {

        private MfaPasskeyAuthenticationAdapter adapter;

        @BeforeEach
        void setUp() {
            adapter = new MfaPasskeyAuthenticationAdapter();
        }

        @Test
        @DisplayName("getId should return 'mfa_passkey'")
        void getIdReturnsMfaPasskey() {
            assertThat(adapter.getId()).isEqualTo("mfa_passkey");
        }

        @Test
        @DisplayName("getOrder should return 401")
        void getOrderReturns401() {
            assertThat(adapter.getOrder()).isEqualTo(401);
        }

        @Test
        @DisplayName("configureHttpSecurity should configure WebAuthn successfully")
        @SuppressWarnings("unchecked")
        void configureHttpSecurityConfiguresWebAuthn() throws Exception {
            PasskeyOptions options = mock(PasskeyOptions.class);
            when(options.getRpName()).thenReturn("Contexa MFA");
            when(options.getRpId()).thenReturn("localhost");
            when(options.getAllowedOrigins()).thenReturn(Collections.singleton("http://localhost:8080"));

            WebAuthnConfigurer<HttpSecurity> mockConfigurer = mock(WebAuthnConfigurer.class);
            when(mockConfigurer.rpName(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.rpId(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.allowedOrigins(any(Set.class))).thenReturn(mockConfigurer);

            when(httpSecurity.webAuthn(any(Customizer.class))).thenAnswer(invocation -> {
                Customizer<WebAuthnConfigurer<HttpSecurity>> customizer = invocation.getArgument(0);
                customizer.customize(mockConfigurer);
                return httpSecurity;
            });

            adapter.configureHttpSecurity(httpSecurity, options, currentFlow, null, null);

            verify(mockConfigurer).rpName("Contexa MFA");
            verify(mockConfigurer).rpId("localhost");
            verify(mockConfigurer).allowedOrigins(Collections.singleton("http://localhost:8080"));
        }
    }
}
