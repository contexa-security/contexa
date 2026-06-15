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
import org.springframework.context.MessageSource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.WebAuthnConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import io.contexa.contexaidentity.security.core.dsl.configurer.impl.RestAuthenticationConfigurer;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthenticationAdapterTest {

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
    @DisplayName("FormAuthenticationAdapter tests")
    class FormAdapterTests {

        private FormAuthenticationAdapter adapter;

        @BeforeEach
        void setUp() {
            adapter = new FormAuthenticationAdapter();
        }

        @Test
        @DisplayName("getId should return 'form'")
        void getIdReturnsForm() {
            assertThat(adapter.getId()).isEqualTo("form");
        }

        @Test
        @DisplayName("getOrder should return 100")
        void getOrderReturns100() {
            assertThat(adapter.getOrder()).isEqualTo(100);
        }

        @Test
        @DisplayName("apply should configure Form Login successfully")
        @SuppressWarnings("unchecked")
        void applyConfiguresFormLogin() throws Exception {
            FormOptions options = mock(FormOptions.class);
            when(options.getLoginProcessingUrl()).thenReturn("/login/form");
            when(options.getUsernameParameter()).thenReturn("user");
            when(options.getPasswordParameter()).thenReturn("pass");
            when(options.isPermitAll()).thenReturn(true);
            when(options.getLoginPage()).thenReturn("/custom-login");

            AuthenticationStepConfig step = new AuthenticationStepConfig();
            step.setType("form");
            step.getOptions().put(AuthenticationStepConfig.OPTIONS_KEY, options);

            FormLoginConfigurer<HttpSecurity> mockConfigurer = mock(FormLoginConfigurer.class);
            when(mockConfigurer.loginProcessingUrl(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.usernameParameter(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.passwordParameter(any())).thenReturn(mockConfigurer);
            when(mockConfigurer.permitAll()).thenReturn(mockConfigurer);
            when(mockConfigurer.loginPage(any())).thenReturn(mockConfigurer);

            doAnswer(invocation -> {
                Customizer<FormLoginConfigurer<HttpSecurity>> customizer = invocation.getArgument(1);
                customizer.customize(mockConfigurer);
                return httpSecurity;
            }).when(httpSecurity).with(any(FormLoginConfigurer.class), any(Customizer.class));

            adapter.apply(httpSecurity, List.of(step), stateConfig);

            verify(mockConfigurer).loginProcessingUrl("/login/form");
            verify(mockConfigurer).usernameParameter("user");
            verify(mockConfigurer).passwordParameter("pass");
            verify(mockConfigurer).permitAll();
            verify(mockConfigurer).loginPage("/custom-login");
        }
    }

    @Nested
    @DisplayName("RestAuthenticationAdapter tests")
    class RestAdapterTests {

        private RestAuthenticationAdapter adapter;

        @BeforeEach
        void setUp() {
            adapter = new RestAuthenticationAdapter();
        }

        @Test
        @DisplayName("getId should return 'rest'")
        void getIdReturnsRest() {
            assertThat(adapter.getId()).isEqualTo("rest");
        }

        @Test
        @DisplayName("apply should configure Rest Login successfully")
        @SuppressWarnings("unchecked")
        void applyConfiguresRestLogin() throws Exception {
            RestOptions options = mock(RestOptions.class);
            when(options.getLoginProcessingUrl()).thenReturn("/login/rest");
            when(options.getSecurityContextRepository()).thenReturn(mock(SecurityContextRepository.class));

            AuthenticationStepConfig step = new AuthenticationStepConfig();
            step.setType("rest");
            step.getOptions().put(AuthenticationStepConfig.OPTIONS_KEY, options);

            when(applicationContext.getBean(MessageSource.class)).thenReturn(mock(MessageSource.class));
            when(httpSecurity.getSharedObject(ApplicationContext.class)).thenReturn(applicationContext);

            RestAuthenticationConfigurer<HttpSecurity> mockConfigurer = mock(RestAuthenticationConfigurer.class);
            when(mockConfigurer.loginProcessingUrl(any())).thenReturn(mockConfigurer);

            doAnswer(invocation -> {
                Customizer<RestAuthenticationConfigurer<HttpSecurity>> customizer = invocation.getArgument(1);
                customizer.customize(mockConfigurer);
                return httpSecurity;
            }).when(httpSecurity).with(any(RestAuthenticationConfigurer.class), any(Customizer.class));

            adapter.apply(httpSecurity, List.of(step), stateConfig);

            verify(mockConfigurer).loginProcessingUrl("/login/rest");
        }
    }

    @Nested
    @DisplayName("OttAuthenticationAdapter tests")
    class OttAdapterTests {

        private OttAuthenticationAdapter adapter;

        @BeforeEach
        void setUp() {
            adapter = new OttAuthenticationAdapter();
        }

        @Test
        @DisplayName("getId should return 'ott'")
        void getIdReturnsOtt() {
            assertThat(adapter.getId()).isEqualTo("ott");
        }

        @Test
        @DisplayName("getOrder should return 300")
        void getOrderReturns300() {
            assertThat(adapter.getOrder()).isEqualTo(300);
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
            when(options.getLoginProcessingUrl()).thenReturn("/login/ott");
            when(options.getDefaultSubmitPageUrl()).thenReturn("/ott/submit");
            when(options.isShowDefaultSubmitPage()).thenReturn(true);
            when(options.getTokenGeneratingUrl()).thenReturn("/ott/generate");

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

            verify(mockConfigurer).loginProcessingUrl("/login/ott");
            verify(mockConfigurer).defaultSubmitPageUrl("/ott/submit");
            verify(mockConfigurer).showDefaultSubmitPage(true);
            verify(mockConfigurer).tokenGeneratingUrl("/ott/generate");
        }
    }

    @Nested
    @DisplayName("PasskeyAuthenticationAdapter tests")
    class PasskeyAdapterTests {

        private PasskeyAuthenticationAdapter adapter;

        @BeforeEach
        void setUp() {
            adapter = new PasskeyAuthenticationAdapter();
        }

        @Test
        @DisplayName("getId should return 'passkey'")
        void getIdReturnsPasskey() {
            assertThat(adapter.getId()).isEqualTo("passkey");
        }

        @Test
        @DisplayName("getOrder should return 400")
        void getOrderReturns400() {
            assertThat(adapter.getOrder()).isEqualTo(400);
        }

        @Test
        @DisplayName("configureHttpSecurity should configure WebAuthn successfully")
        @SuppressWarnings("unchecked")
        void configureHttpSecurityConfiguresWebAuthn() throws Exception {
            PasskeyOptions options = mock(PasskeyOptions.class);
            when(options.getRpName()).thenReturn("Contexa");
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

            verify(mockConfigurer).rpName("Contexa");
            verify(mockConfigurer).rpId("localhost");
            verify(mockConfigurer).allowedOrigins(Collections.singleton("http://localhost:8080"));
        }
    }
}
