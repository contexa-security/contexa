/*
 * Copyright 2026 The Contexa Project
 *
 * Licensed under the Apache License, Version 2.0.
 */
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.OAuth2ServerMode;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2StateModeIsolationTest {

    @Mock
    private HttpSecurity http;
    @Mock
    private PlatformContext platformContext;
    @Mock
    private ApplicationContext applicationContext;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private JsonAuthResponseWriter responseWriter;

    @BeforeEach
    void setUp() {
        when(platformContext.applicationContext()).thenReturn(applicationContext);
        when(applicationContext.getBean(ObjectMapper.class)).thenReturn(objectMapper);
        when(applicationContext.getBean(JsonAuthResponseWriter.class)).thenReturn(responseWriter);
        when(applicationContext.getBean(ObjectMapper.class)).thenReturn(objectMapper);
        when(applicationContext.getBean(JsonAuthResponseWriter.class)).thenReturn(responseWriter);
    }

    @Test
    @SuppressWarnings("unchecked")
    void resourceServerModeDoesNotRequireAuthorizationServerBeans() throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setOauth2ServerMode(OAuth2ServerMode.RESOURCE_SERVER);
        JwtDecoder decoder = mock(JwtDecoder.class);
        when(applicationContext.getBean(AuthContextProperties.class)).thenReturn(properties);
        when(applicationContext.getBean(JwtDecoder.class)).thenReturn(decoder);

        new OAuth2StateAdapter().apply(http, platformContext);

        verify(http).setSharedObject(JwtDecoder.class, decoder);
        verify(applicationContext, never()).getBean(JwtEncoder.class);
        verify(http).with(any(OAuth2StateConfigurer.class), any(Customizer.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void authorizationServerModeDoesNotRequireResourceServerBeans() throws Exception {
        AuthContextProperties properties = new AuthContextProperties();
        properties.setOauth2ServerMode(OAuth2ServerMode.AUTHORIZATION_SERVER);
        JwtEncoder encoder = mock(JwtEncoder.class);
        OAuth2AuthorizationService authorizationService = mock(OAuth2AuthorizationService.class);
        RegisteredClientRepository clientRepository = mock(RegisteredClientRepository.class);
        AuthorizationServerSettings settings = mock(AuthorizationServerSettings.class);
        OAuth2TokenGenerator<?> tokenGenerator = mock(OAuth2TokenGenerator.class);
        UserRepository userRepository = mock(UserRepository.class);
        when(applicationContext.getBean(AuthContextProperties.class)).thenReturn(properties);
        when(applicationContext.getBean(JwtEncoder.class)).thenReturn(encoder);
        when(applicationContext.getBean(OAuth2AuthorizationService.class)).thenReturn(authorizationService);
        when(applicationContext.getBean(RegisteredClientRepository.class)).thenReturn(clientRepository);
        when(applicationContext.getBean(AuthorizationServerSettings.class)).thenReturn(settings);
        when(applicationContext.getBean(OAuth2TokenGenerator.class)).thenReturn(tokenGenerator);
        when(applicationContext.getBean(UserRepository.class)).thenReturn(userRepository);

        new OAuth2StateAdapter().apply(http, platformContext);

        verify(applicationContext, never()).getBean(JwtDecoder.class);
        verify(http).setSharedObject(JwtEncoder.class, encoder);
        verify(http).with(any(OAuth2StateConfigurer.class), any(Customizer.class));
    }
}
