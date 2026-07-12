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

import io.contexa.contexacommon.enums.OAuth2ServerMode;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.security.AIOAuth2SecurityContextRepository;
import io.contexa.contexacore.security.AIOAuth2ZeroTrustFilter;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationConverter;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.Objects;

@Slf4j
public final class OAuth2StateConfigurer extends AbstractHttpConfigurer<OAuth2StateConfigurer, HttpSecurity> {

    private final OAuth2ServerMode mode;

    public OAuth2StateConfigurer() {
        this(OAuth2ServerMode.COMBINED);
    }

    public OAuth2StateConfigurer(OAuth2ServerMode mode) {
        this.mode = Objects.requireNonNull(mode, "OAuth2 server mode cannot be null");
    }

    public OAuth2ServerMode getMode() {
        return mode;
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        if (mode.includesResourceServer()) {
            configureResourceServer(http);
        }
        if (mode.includesAuthorizationServer()) {
            configureAuthorizationServer(http);
        }
    }

    private void configureResourceServer(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(new OAuth2JwtAuthenticationConverter(http)))
                .authenticationEntryPoint(new OAuth2AuthenticationEntryPoint())
                .accessDeniedHandler(new OAuth2AccessDeniedHandler()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        ApplicationContext appContext = getBuilder().getSharedObject(ApplicationContext.class);
        if (appContext == null) {
            return;
        }
        try {
            AIOAuth2SecurityContextRepository repository = appContext.getBean(AIOAuth2SecurityContextRepository.class);
            http.addFilterAfter(new AIOAuth2ZeroTrustFilter(repository), BearerTokenAuthenticationFilter.class);
        } catch (Exception e) {
            log.warn("OAuth2StateConfigurer: Contexa OAuth2 zero-trust filter is unavailable");
        }
    }

    private void configureAuthorizationServer(HttpSecurity http) throws Exception {
        OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);
        RegisteredClientRepository clientRepository = http.getSharedObject(RegisteredClientRepository.class);
        AuthorizationServerSettings serverSettings = http.getSharedObject(AuthorizationServerSettings.class);
        OAuth2TokenGenerator<?> tokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);
        UserRepository userRepository = http.getSharedObject(UserRepository.class);

        if (authorizationService == null || clientRepository == null) {
            throw new IllegalStateException(
                    "OAuth2AuthorizationService and RegisteredClientRepository are required for AUTHORIZATION_SERVER mode");
        }

        OAuth2AuthorizationServerConfigurer authorizationServer = new OAuth2AuthorizationServerConfigurer();
        ApplicationContext appContext = getBuilder().getSharedObject(ApplicationContext.class);
        http.with(authorizationServer, configurer -> {
            configurer.authorizationService(authorizationService).registeredClientRepository(clientRepository);
            if (serverSettings != null) {
                configurer.authorizationServerSettings(serverSettings);
            }

            TransactionTemplate transactionTemplate = getOptionalBean(
                    appContext, "contexaTransactionTemplate", TransactionTemplate.class);
            if (transactionTemplate != null) {
                if (tokenGenerator == null || userRepository == null) {
                    throw new IllegalStateException(
                            "OAuth2TokenGenerator and UserRepository are required for the authenticated-user grant");
                }
                configurer.tokenEndpoint(endpoint -> endpoint
                        .accessTokenRequestConverter(new AuthenticatedUserGrantAuthenticationConverter())
                        .authenticationProvider(new AuthenticatedUserGrantAuthenticationProvider(
                                authorizationService, tokenGenerator, userRepository, transactionTemplate)));
            }

            configurer.tokenEndpoint(endpoint -> {
                AuthenticationSuccessHandler successHandler = getOptionalBean(
                        appContext, "oauth2TokenSuccessHandler", AuthenticationSuccessHandler.class);
                if (successHandler != null) {
                    endpoint.accessTokenResponseHandler(successHandler);
                }
                AuthenticationFailureHandler failureHandler = getOptionalBean(
                        appContext, "oauth2TokenFailureHandler", AuthenticationFailureHandler.class);
                if (failureHandler != null) {
                    endpoint.errorResponseHandler(failureHandler);
                }
            });
            configurer.oidc(Customizer.withDefaults());
        });

        AuthContextProperties properties = appContext != null
                ? appContext.getBean(AuthContextProperties.class)
                : new AuthContextProperties();
        http.with(new OAuth2CsrfConfigurer(properties.isOauth2Csrf()), Customizer.withDefaults());
    }

    private <T> T getOptionalBean(ApplicationContext context, String name, Class<T> type) {
        if (context == null) {
            return null;
        }
        try {
            return context.getBean(name, type);
        } catch (Exception ignored) {
            return null;
        }
    }
}
