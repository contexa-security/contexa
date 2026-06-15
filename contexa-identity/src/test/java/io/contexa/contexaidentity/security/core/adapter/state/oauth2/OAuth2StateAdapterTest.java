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
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import io.contexa.contexacommon.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class OAuth2StateAdapterTest {

    private OAuth2StateAdapter adapter;

    @Mock
    private HttpSecurity httpSecurity;

    @Mock
    private PlatformContext platformContext;

    @Mock
    private ApplicationContext applicationContext;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private JsonAuthResponseWriter jsonAuthResponseWriter;

    @Mock
    private JwtDecoder jwtDecoder;

    @Mock
    private JwtEncoder jwtEncoder;

    @Mock
    private OAuth2AuthorizationService authorizationService;

    @Mock
    private RegisteredClientRepository registeredClientRepository;

    @Mock
    private AuthorizationServerSettings authorizationServerSettings;

    @Mock
    private OAuth2TokenGenerator<?> tokenGenerator;

    @Mock
    private UserRepository userRepository;

    @Mock
    private OAuth2TokenService tokenService;

    @Mock
    private LogoutHandler logoutHandler;

    @Mock
    private AuthResponseWriter responseWriter;

    @BeforeEach
    void setUp() {
        adapter = new OAuth2StateAdapter();
        when(platformContext.applicationContext()).thenReturn(applicationContext);
    }

    @Test
    @DisplayName("getId should return 'oauth2'")
    void getIdReturnsOAuth2() {
        assertThat(adapter.getId()).isEqualTo("oauth2");
    }

    @Test
    @DisplayName("apply with null HttpSecurity should throw NullPointerException")
    void applyWithNullHttpThrowsException() {
        assertThatThrownBy(() -> adapter.apply(null, platformContext))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("HttpSecurity cannot be null");
    }

    @Test
    @DisplayName("apply with null PlatformContext should throw NullPointerException")
    void applyWithNullContextThrowsException() {
        assertThatThrownBy(() -> adapter.apply(httpSecurity, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("PlatformContext cannot be null");
    }

    @Test
    @DisplayName("apply when ObjectMapper is missing should throw IllegalStateException")
    void applyWhenObjectMapperMissingThrowsException() {
        when(applicationContext.getBean(ObjectMapper.class))
                .thenThrow(new NoSuchBeanDefinitionException(ObjectMapper.class));

        assertThatThrownBy(() -> adapter.apply(httpSecurity, platformContext))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Required bean for OAuth2 state configuration not found");
    }

    @Test
    @DisplayName("apply when JwtDecoder is missing should throw IllegalStateException")
    void applyWhenJwtDecoderMissingThrowsException() {
        when(applicationContext.getBean(ObjectMapper.class)).thenReturn(objectMapper);
        when(applicationContext.getBean(JsonAuthResponseWriter.class)).thenReturn(jsonAuthResponseWriter);
        when(applicationContext.getBean(JwtDecoder.class))
                .thenThrow(new NoSuchBeanDefinitionException(JwtDecoder.class));

        assertThatThrownBy(() -> adapter.apply(httpSecurity, platformContext))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JwtDecoder is required for Resource Server mode");
    }

    @Test
    @DisplayName("apply when Authorization Server beans are missing should throw IllegalStateException")
    void applyWhenAuthServerBeansMissingThrowsException() {
        when(applicationContext.getBean(ObjectMapper.class)).thenReturn(objectMapper);
        when(applicationContext.getBean(JsonAuthResponseWriter.class)).thenReturn(jsonAuthResponseWriter);
        when(applicationContext.getBean(JwtDecoder.class)).thenReturn(jwtDecoder);
        when(applicationContext.getBean(JwtEncoder.class))
                .thenThrow(new NoSuchBeanDefinitionException(JwtEncoder.class));

        assertThatThrownBy(() -> adapter.apply(httpSecurity, platformContext))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Authorization Server beans are required");
    }

    @Test
    @DisplayName("apply when all required beans are present should apply successfully")
    @SuppressWarnings("unchecked")
    void applyWithAllBeansSucceeds() throws Exception {
        when(applicationContext.getBean(ObjectMapper.class)).thenReturn(objectMapper);
        when(applicationContext.getBean(JsonAuthResponseWriter.class)).thenReturn(jsonAuthResponseWriter);
        when(applicationContext.getBean(JwtDecoder.class)).thenReturn(jwtDecoder);
        when(applicationContext.getBean(JwtEncoder.class)).thenReturn(jwtEncoder);
        when(applicationContext.getBean(OAuth2AuthorizationService.class)).thenReturn(authorizationService);
        when(applicationContext.getBean(RegisteredClientRepository.class)).thenReturn(registeredClientRepository);
        when(applicationContext.getBean(AuthorizationServerSettings.class)).thenReturn(authorizationServerSettings);
        when(applicationContext.getBean(OAuth2TokenGenerator.class)).thenReturn(tokenGenerator);
        when(applicationContext.getBean(UserRepository.class)).thenReturn(userRepository);
        when(applicationContext.getBean(OAuth2TokenService.class)).thenReturn(tokenService);
        when(applicationContext.getBean("compositeLogoutHandler", LogoutHandler.class)).thenReturn(logoutHandler);
        when(applicationContext.getBean(AuthResponseWriter.class)).thenReturn(responseWriter);

        LogoutConfigurer<HttpSecurity> mockLogoutConfigurer = mock(LogoutConfigurer.class);
        when(mockLogoutConfigurer.logoutRequestMatcher(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.addLogoutHandler(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.logoutSuccessHandler(any())).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.invalidateHttpSession(any(Boolean.class))).thenReturn(mockLogoutConfigurer);
        when(mockLogoutConfigurer.clearAuthentication(any(Boolean.class))).thenReturn(mockLogoutConfigurer);

        doAnswer(invocation -> {
            Customizer<LogoutConfigurer<HttpSecurity>> customizer = invocation.getArgument(0);
            customizer.customize(mockLogoutConfigurer);
            return httpSecurity;
        }).when(httpSecurity).logout(any(Customizer.class));

        adapter.apply(httpSecurity, platformContext);

        verify(httpSecurity).setSharedObject(ObjectMapper.class, objectMapper);
        verify(httpSecurity).setSharedObject(JsonAuthResponseWriter.class, jsonAuthResponseWriter);
        verify(httpSecurity).setSharedObject(JwtDecoder.class, jwtDecoder);
        verify(httpSecurity).setSharedObject(JwtEncoder.class, jwtEncoder);
        verify(httpSecurity).setSharedObject(OAuth2AuthorizationService.class, authorizationService);
        verify(httpSecurity).setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
        verify(httpSecurity).setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
        verify(httpSecurity).setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
        verify(httpSecurity).setSharedObject(UserRepository.class, userRepository);

        verify(httpSecurity).with(any(OAuth2StateConfigurer.class), any(Customizer.class));
    }
}
