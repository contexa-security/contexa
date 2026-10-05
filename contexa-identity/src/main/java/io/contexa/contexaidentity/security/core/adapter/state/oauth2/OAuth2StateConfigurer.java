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
import io.contexa.contexacommon.enums.TokenTransportType;
import io.contexa.contexaidentity.security.token.service.TokenService;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import io.contexa.contexaidentity.security.utils.JsonAuthResponseWriter;

@Slf4j
public final class OAuth2StateConfigurer extends AbstractHttpConfigurer<OAuth2StateConfigurer, HttpSecurity> {

    private static final String OAUTH2_CSRF_PROPERTY = "contexa.auth.oauth2-csrf";

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
        ApplicationContext appContext = getBuilder().getSharedObject(ApplicationContext.class);
        OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();
        OAuth2CookieTokenSupport cookieTokenSupport = resolveCookieTokenSupport(http, appContext);

        http.oauth2ResourceServer(oauth2 -> {
            oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(new OAuth2JwtAuthenticationConverter(http)))
                    .authenticationEntryPoint(entryPoint)
                    .accessDeniedHandler(new OAuth2AccessDeniedHandler());
            if (cookieTokenSupport != null) {
                // Only the filter reads the cookie. The configurer keeps its header resolver, which also
                // defines the CSRF exemption, so cookie-authenticated requests remain CSRF protected.
                OAuth2AccessTokenResolver tokenResolver = new OAuth2AccessTokenResolver(cookieTokenSupport.tokenService());
                OAuth2CookieTokenFailureHandler failureHandler =
                        new OAuth2CookieTokenFailureHandler(cookieTokenSupport, entryPoint);
                oauth2.withObjectPostProcessor(new ObjectPostProcessor<BearerTokenAuthenticationFilter>() {
                    @Override
                    public <O extends BearerTokenAuthenticationFilter> O postProcess(O filter) {
                        filter.setBearerTokenResolver(tokenResolver);
                        filter.setAuthenticationFailureHandler(failureHandler);
                        return filter;
                    }
                });
            }
        }).sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        if (cookieTokenSupport != null) {
            // The refresh entry point is registered only where this chain also hosts the authorization server.
            String refreshUri = mode.includesAuthorizationServer()
                    ? appContext.getBean(AuthContextProperties.class).getInternal().getRefreshUri()
                    : null;
            http.addFilterBefore(new OAuth2CookieTokenRefreshFilter(cookieTokenSupport, refreshUri),
                    BearerTokenAuthenticationFilter.class);
        }

        if (appContext == null) {
            return;
        }
        try {
            AIOAuth2SecurityContextRepository repository = appContext.getBean(AIOAuth2SecurityContextRepository.class);
            AIOAuth2ZeroTrustFilter zeroTrustFilter = cookieTokenSupport != null
                    ? new AIOAuth2ZeroTrustFilter(repository,
                    new OAuth2CookieTokenFailureHandler(cookieTokenSupport, new BearerTokenAuthenticationEntryPoint()))
                    : new AIOAuth2ZeroTrustFilter(repository);
            http.addFilterAfter(zeroTrustFilter, BearerTokenAuthenticationFilter.class);
        } catch (Exception e) {
            log.error("OAuth2StateConfigurer: Contexa OAuth2 zero-trust filter is unavailable", e);
        }
    }

    /**
     * Returns the cookie token handling when access tokens travel in cookies and the application has not
     * defined its own {@link BearerTokenResolver}; otherwise {@code null}.
     */
    private OAuth2CookieTokenSupport resolveCookieTokenSupport(HttpSecurity http, ApplicationContext appContext) {
        if (appContext == null || appContext.getBeanNamesForType(BearerTokenResolver.class).length > 0) {
            return null;
        }
        AuthContextProperties properties = appContext.getBean(AuthContextProperties.class);
        TokenService tokenService = http.getSharedObject(TokenService.class);
        if (properties.getTokenTransportType() != TokenTransportType.COOKIE || tokenService == null) {
            return null;
        }
        return new OAuth2CookieTokenSupport(tokenService);
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
        http.with(new OAuth2CsrfConfigurer(resolveCsrfEnabled(properties, appContext)), Customizer.withDefaults());

        TokenService tokenService = http.getSharedObject(TokenService.class);
        JsonAuthResponseWriter responseWriter = http.getSharedObject(JsonAuthResponseWriter.class);
        if (tokenService != null && responseWriter != null) {
            // Placed before the bearer token filter, so an expired access token sent along with the
            // refresh request cannot block the renewal.
            http.addFilterBefore(new OAuth2TokenRefreshFilter(properties.getInternal().getRefreshUri(), tokenService,
                    properties.getTokenTransportType(), responseWriter), BearerTokenAuthenticationFilter.class);
        }
    }

    /**
     * CSRF protection follows the transport: tokens sent automatically by the browser in cookies need it,
     * so the cookie transport always enables it and refuses an explicit opt-out.
     */
    private boolean resolveCsrfEnabled(AuthContextProperties properties, ApplicationContext appContext) {
        if (properties.getTokenTransportType() != TokenTransportType.COOKIE) {
            return properties.isOauth2Csrf();
        }
        if (appContext != null && appContext.getEnvironment().containsProperty(OAUTH2_CSRF_PROPERTY)
                && !properties.isOauth2Csrf()) {
            throw new IllegalStateException(OAUTH2_CSRF_PROPERTY + "=false cannot be combined with the COOKIE token "
                    + "transport: the browser sends the token cookies with every request, so CSRF protection is required. "
                    + "Remove the property or use the HEADER transport.");
        }
        return true;
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
