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
package io.contexa.contexaidentity.security.core.adapter.state.session;

import io.contexa.contexacommon.enums.StateType;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.config.AuthenticationStepConfig;
import io.contexa.contexaidentity.security.core.config.StateConfig;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.properties.AuthUrlConfig;
import io.contexa.contexacommon.properties.PrimaryAuthUrls;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SessionStateAdapterTest {

    private SessionStateAdapter adapter;

    @Mock
    private HttpSecurity httpSecurity;

    @Mock
    private PlatformContext platformContext;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private LogoutHandler logoutHandler;

    @Mock
    private AuthContextProperties authContextProperties;

    @BeforeEach
    void setUp() {
        adapter = new SessionStateAdapter();
        when(platformContext.applicationContext()).thenReturn(applicationContext);
        when(applicationContext.getBean("contexaCompositeLogoutHandler", LogoutHandler.class)).thenReturn(logoutHandler);
        when(applicationContext.getBean(AuthContextProperties.class)).thenReturn(authContextProperties);
    }

    @Test
    @DisplayName("getId should return 'session'")
    void getIdReturnsSession() {
        assertThat(adapter.getId()).isEqualTo("session");
    }

    @Test
    @DisplayName("apply with HttpSecurity and PlatformContext should delegate successfully")
    @SuppressWarnings("unchecked")
    void applyDelegatesSuccessfully() throws Exception {
        LogoutConfigurer<HttpSecurity> mockLogoutConfigurer = mock(LogoutConfigurer.class);
        when(mockLogoutConfigurer.logoutUrl(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.logoutSuccessUrl(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.addLogoutHandler(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.invalidateHttpSession(any(Boolean.class))).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.clearAuthentication(any(Boolean.class))).thenReturn(mockLogoutConfigurer);

        doAnswer(invocation -> {
            Customizer<LogoutConfigurer<HttpSecurity>> customizer = invocation.getArgument(0);
            customizer.customize(mockLogoutConfigurer);
            return httpSecurity;
        }).when(httpSecurity).logout(any(Customizer.class));

        adapter.apply(httpSecurity, platformContext);

        verify(mockLogoutConfigurer).logoutUrl("/logout");
        verify(mockLogoutConfigurer).logoutSuccessUrl("/contexa/admin/login");
        verify(mockLogoutConfigurer).addLogoutHandler(logoutHandler);
        verify(httpSecurity).with(any(SessionStateConfigurer.class), any(Customizer.class));
    }

    @Test
    @DisplayName("apply with flowConfig of MFA flow should construct custom logout success URL")
    @SuppressWarnings("unchecked")
    void applyWithMfaFlowConfigConstructsCustomUrls() throws Exception {
        AuthenticationFlowConfig flowConfig = mock(AuthenticationFlowConfig.class);
        when(flowConfig.getUrlPrefix()).thenReturn("/mfa-prefix");
        when(flowConfig.getTypeName()).thenReturn("mfa");
        when(flowConfig.stateCustomizer(SessionStateConfigurer.class)).thenReturn(Customizer.withDefaults());

        AuthUrlConfig authUrlConfig = mock(AuthUrlConfig.class);
        PrimaryAuthUrls primaryAuthUrls = mock(PrimaryAuthUrls.class);
        when(authContextProperties.getUrls()).thenReturn(authUrlConfig);
        when(authUrlConfig.getPrimary()).thenReturn(primaryAuthUrls);
        when(primaryAuthUrls.getFormLoginPage()).thenReturn("/login-page");

        LogoutConfigurer<HttpSecurity> mockLogoutConfigurer = mock(LogoutConfigurer.class);
        when(mockLogoutConfigurer.logoutUrl(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.logoutSuccessUrl(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.addLogoutHandler(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.invalidateHttpSession(any(Boolean.class))).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.clearAuthentication(any(Boolean.class))).thenReturn(mockLogoutConfigurer);

        doAnswer(invocation -> {
            Customizer<LogoutConfigurer<HttpSecurity>> customizer = invocation.getArgument(0);
            customizer.customize(mockLogoutConfigurer);
            return httpSecurity;
        }).when(httpSecurity).logout(any(Customizer.class));

        adapter.apply(httpSecurity, platformContext, flowConfig);

        verify(mockLogoutConfigurer).logoutUrl("/mfa-prefix/logout");
        verify(mockLogoutConfigurer).logoutSuccessUrl("/mfa-prefix/login-page");
        verify(mockLogoutConfigurer).addLogoutHandler(logoutHandler);
        verify(httpSecurity).with(any(SessionStateConfigurer.class), any(Customizer.class));
    }

    @Test
    @DisplayName("the address after a sign-out is given with the defaults, and the state applied after them leaves it")
    @SuppressWarnings("unchecked")
    void theAddressAfterASignOutIsGivenBeforeTheApplicationsSettings() throws Exception {
        Map<Class<?>, Object> shared = new HashMap<>();
        doAnswer(invocation -> {
            shared.put(invocation.getArgument(0), invocation.getArgument(1));
            return null;
        }).when(httpSecurity).setSharedObject(any(Class.class), any());
        when(httpSecurity.getSharedObject(any(Class.class))).thenAnswer(invocation -> shared.get(invocation.getArgument(0)));
        LogoutConfigurer<HttpSecurity> mockLogoutConfigurer = mock(LogoutConfigurer.class);
        when(mockLogoutConfigurer.logoutUrl(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.logoutSuccessUrl(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.addLogoutHandler(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.invalidateHttpSession(any(Boolean.class))).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.clearAuthentication(any(Boolean.class))).thenReturn(mockLogoutConfigurer);
        doAnswer(invocation -> {
            Customizer<LogoutConfigurer<HttpSecurity>> customizer = invocation.getArgument(0);
            customizer.customize(mockLogoutConfigurer);
            return httpSecurity;
        }).when(httpSecurity).logout(any(Customizer.class));

        adapter.applyDefaults(httpSecurity, platformContext, null);

        verify(mockLogoutConfigurer).logoutSuccessUrl("/contexa/admin/login");
        verify(mockLogoutConfigurer, never()).logoutUrl(any());

        // what the application sets comes in between; the state applied after it does not write the address again
        clearInvocations(mockLogoutConfigurer);
        adapter.apply(httpSecurity, platformContext);

        verify(mockLogoutConfigurer).logoutUrl("/logout");
        verify(mockLogoutConfigurer).addLogoutHandler(logoutHandler);
        verify(mockLogoutConfigurer, never()).logoutSuccessUrl(any());
    }

    @Test
    @DisplayName("apply uses the customizer the flow's .session(customizer) gave (A1-10)")
    void applyUsesTheFlowsSessionCustomizer() throws Exception {
        Customizer<SessionStateConfigurer> customizer = session -> { };
        AuthenticationFlowConfig flowConfig = AuthenticationFlowConfig.builder("form_flow")
                .stepConfigs(List.of(new AuthenticationStepConfig("form_flow", "FORM", 100, false)))
                .build()
                .withStateConfig(new StateConfig("session", StateType.SESSION), customizer);

        adapter.apply(httpSecurity, platformContext, flowConfig);

        verify(httpSecurity).with(any(SessionStateConfigurer.class), same(customizer));
    }
}
