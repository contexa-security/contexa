/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 */
package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.enums.OAuth2ServerMode;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexaidentity.security.core.adapter.StateAdapter;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.handler.logout.OAuth2LogoutSuccessHandler;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.util.Objects;

@Slf4j
public final class OAuth2StateAdapter implements StateAdapter {

    private static final String ID = "oauth2";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void apply(HttpSecurity http, PlatformContext platformCtx) throws Exception {
        Objects.requireNonNull(http, "HttpSecurity cannot be null for OAuth2StateAdapter.apply");
        Objects.requireNonNull(platformCtx, "PlatformContext cannot be null for OAuth2StateAdapter.apply");
        ApplicationContext appContext = Objects.requireNonNull(
                platformCtx.applicationContext(), "ApplicationContext from PlatformContext cannot be null");

        configureSharedInfrastructure(http, appContext);
        OAuth2ServerMode mode = resolveMode(appContext);
        if (mode.includesResourceServer()) {
            configureResourceServer(http, appContext);
        }
        if (mode.includesAuthorizationServer()) {
            configureAuthorizationServer(http, appContext);
            configureLogout(http, appContext);
        }
        configureOptionalTokenService(http, appContext);
        http.with(new OAuth2StateConfigurer(mode), Customizer.withDefaults());
    }

    private void configureSharedInfrastructure(HttpSecurity http, ApplicationContext appContext) {
        try {
            ObjectMapper objectMapper = appContext.getBean(ObjectMapper.class);
            JsonAuthResponseWriter responseWriter = appContext.getBean(JsonAuthResponseWriter.class);
            http.setSharedObject(ObjectMapper.class, objectMapper);
            http.setSharedObject(JsonAuthResponseWriter.class, responseWriter);
        } catch (NoSuchBeanDefinitionException e) {
            throw new IllegalStateException(
                    "Required bean for OAuth2 state configuration not found: " + e.getMessage(), e);
        }
    }

    private OAuth2ServerMode resolveMode(ApplicationContext appContext) {
        try {
            AuthContextProperties properties = appContext.getBean(AuthContextProperties.class);
            return properties != null && properties.getOauth2ServerMode() != null
                    ? properties.getOauth2ServerMode()
                    : OAuth2ServerMode.COMBINED;
        } catch (NoSuchBeanDefinitionException ignored) {
            return OAuth2ServerMode.COMBINED;
        }
    }

    private void configureResourceServer(HttpSecurity http, ApplicationContext appContext) {
        try {
            http.setSharedObject(JwtDecoder.class, appContext.getBean(JwtDecoder.class));
        } catch (NoSuchBeanDefinitionException e) {
            throw new IllegalStateException("JwtDecoder is required for Resource Server mode", e);
        }
    }

    private void configureAuthorizationServer(HttpSecurity http, ApplicationContext appContext) {
        try {
            http.setSharedObject(JwtEncoder.class, appContext.getBean(JwtEncoder.class));
            http.setSharedObject(OAuth2AuthorizationService.class,
                    appContext.getBean(OAuth2AuthorizationService.class));
            http.setSharedObject(RegisteredClientRepository.class,
                    appContext.getBean(RegisteredClientRepository.class));
            http.setSharedObject(AuthorizationServerSettings.class,
                    appContext.getBean(AuthorizationServerSettings.class));
            http.setSharedObject(OAuth2TokenGenerator.class,
                    appContext.getBean(OAuth2TokenGenerator.class));
            http.setSharedObject(UserRepository.class, appContext.getBean(UserRepository.class));
        } catch (NoSuchBeanDefinitionException e) {
            throw new IllegalStateException("Authorization Server beans are required for AUTHORIZATION_SERVER mode", e);
        }
    }

    private void configureOptionalTokenService(HttpSecurity http, ApplicationContext appContext) {
        try {
            http.setSharedObject(TokenService.class, appContext.getBean(OAuth2TokenService.class));
        } catch (NoSuchBeanDefinitionException e) {
            log.debug("OAuth2TokenService is not available for OAuth2 state");
        }
    }

    private void configureLogout(HttpSecurity http, ApplicationContext appContext) throws Exception {
        try {
            LogoutHandler logoutHandler = appContext.getBean("compositeLogoutHandler", LogoutHandler.class);
            AuthResponseWriter responseWriter = appContext.getBean(AuthResponseWriter.class);
            http.setSharedObject(LogoutHandler.class, logoutHandler);
            http.logout(logout -> logout
                    .logoutRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/logout"))
                    .addLogoutHandler(logoutHandler)
                    .logoutSuccessHandler(new OAuth2LogoutSuccessHandler(responseWriter))
                    .invalidateHttpSession(false)
                    .clearAuthentication(true));
        } catch (NoSuchBeanDefinitionException e) {
            log.debug("OAuth2 logout handlers are not available; using the default configuration");
        }
    }
}
