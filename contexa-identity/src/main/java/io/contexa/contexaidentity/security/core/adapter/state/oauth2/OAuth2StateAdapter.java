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
import io.contexa.contexacommon.enums.TokenTransportType;
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
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import io.contexa.contexaidentity.security.core.config.AuthenticationFlowConfig;
import io.contexa.contexaidentity.security.core.mfa.util.MfaFlowTypeUtils;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Slf4j
public final class OAuth2StateAdapter implements StateAdapter {

    private static final String ID = "oauth2";
    private static final String OAUTH2_LOGOUT_SUCCESS_HANDLER = "oauth2LogoutSuccessHandler";
    private static final String TOKEN_PERSISTENCE_MEMORY = "memory";
    private static final AtomicBoolean PAGE_NAVIGATION_LIMIT_REPORTED = new AtomicBoolean();

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
        reportPageNavigationLimit(appContext);
        OAuth2ServerMode mode = resolveMode(appContext);
        if (mode.includesResourceServer()) {
            configureResourceServer(http, appContext);
        }
        if (mode.includesAuthorizationServer()) {
            configureAuthorizationServer(http, appContext);
            configureLogout(http, appContext);
        }
        configureOptionalTokenService(http, appContext);
        // Runs after every authentication adapter and global configurer, so the chain neither reads nor
        // writes the HTTP session regardless of the factor order; this is the Spring stateless default.
        http.setSharedObject(SecurityContextRepository.class, new RequestAttributeSecurityContextRepository());
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

    /**
     * With header transports a page navigation of the browser cannot carry the access token, and with the
     * memory persistence the token is gone after the navigation that ends the generated MFA pages.
     * The combination works for SPAs only, so it is reported once at startup.
     */
    private void reportPageNavigationLimit(ApplicationContext appContext) {
        try {
            AuthContextProperties properties = appContext.getBean(AuthContextProperties.class);
            if (properties != null
                    && properties.getTokenTransportType() != TokenTransportType.COOKIE
                    && TOKEN_PERSISTENCE_MEMORY.equalsIgnoreCase(properties.getTokenPersistence())
                    && PAGE_NAVIGATION_LIMIT_REPORTED.compareAndSet(false, true)) {
                log.error("OAuth2 state with the {} token transport and memory token persistence: browser page "
                                + "navigations carry no access token, so server-rendered pages stay unauthenticated "
                                + "after login. Use the COOKIE transport for server-rendered pages.",
                        properties.getTokenTransportType());
            }
        } catch (NoSuchBeanDefinitionException ignored) {
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
        }
    }

    /**
     * Uses the logout success handler bean. The default handler additionally sends plain browser
     * submissions to the sign-in page of the flow; a handler defined by the application is used as is.
     */
    private LogoutSuccessHandler resolveLogoutSuccessHandler(HttpSecurity http, ApplicationContext appContext) {
        LogoutSuccessHandler handler;
        try {
            handler = appContext.getBean(OAUTH2_LOGOUT_SUCCESS_HANDLER, LogoutSuccessHandler.class);
        } catch (NoSuchBeanDefinitionException e) {
            handler = new OAuth2LogoutSuccessHandler(appContext.getBean(AuthResponseWriter.class));
        }
        if (handler instanceof OAuth2LogoutSuccessHandler defaultHandler) {
            return defaultHandler.withLogoutSuccessUrl(resolveSignInPage(http, appContext));
        }
        return handler;
    }

    private String resolveSignInPage(HttpSecurity http, ApplicationContext appContext) {
        AuthenticationFlowConfig flowConfig = http.getSharedObject(AuthenticationFlowConfig.class);
        if (flowConfig != null && MfaFlowTypeUtils.isMfaFlow(flowConfig.getTypeName())) {
            try {
                AuthUrlProvider provider = appContext.getBean(MfaFlowUrlRegistry.class).getProvider(flowConfig.getTypeName());
                if (provider != null) {
                    return provider.getPrimaryLoginPage();
                }
            } catch (NoSuchBeanDefinitionException ignored) {
            }
        }
        return appContext.getBean(AuthContextProperties.class).getUrls().getPrimary().getFormLoginPage();
    }

    private void configureLogout(HttpSecurity http, ApplicationContext appContext) throws Exception {
        try {
            LogoutHandler logoutHandler = appContext.getBean("compositeLogoutHandler", LogoutHandler.class);
            LogoutSuccessHandler logoutSuccessHandler = resolveLogoutSuccessHandler(http, appContext);
            http.setSharedObject(LogoutHandler.class, logoutHandler);
            // The session only carries MFA progress, CSRF and passkey registration state of the login;
            // ending the login ends it as well.
            http.logout(logout -> logout
                    .logoutRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/logout"))
                    .addLogoutHandler(logoutHandler)
                    .logoutSuccessHandler(logoutSuccessHandler)
                    .invalidateHttpSession(true)
                    .clearAuthentication(true));
        } catch (NoSuchBeanDefinitionException e) {
        }
    }
}
