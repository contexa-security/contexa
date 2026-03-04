package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.security.AIOAuth2ZeroTrustFilter;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationConverter;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
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

@Slf4j
public final class OAuth2StateConfigurer extends AbstractHttpConfigurer<OAuth2StateConfigurer, HttpSecurity> {

    @Override
    public void init(HttpSecurity http) throws Exception {
        configureResourceServer(http);
        configureAuthorizationServer(http);
    }

    private void configureResourceServer(HttpSecurity http) throws Exception {
        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {
                    jwt.jwtAuthenticationConverter(new OAuth2JwtAuthenticationConverter(http));
                })
                .authenticationEntryPoint(new OAuth2AuthenticationEntryPoint())
                .accessDeniedHandler(new OAuth2AccessDeniedHandler())
        ).sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        ApplicationContext appContext = getBuilder().getSharedObject(ApplicationContext.class);
        if (appContext != null) {
            try {
                AIOAuth2ZeroTrustFilter zeroTrustFilter = appContext.getBean(AIOAuth2ZeroTrustFilter.class);
                http.addFilterAfter(zeroTrustFilter, BearerTokenAuthenticationFilter.class);
            } catch (Exception e) {
                log.error("OAuth2StateConfigurer: AIOAuth2ZeroTrustFilter not found - Zero Trust will not be applied to OAuth2 requests");
            }
        }
    }

    private void configureAuthorizationServer(HttpSecurity http) throws Exception {
        OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);
        RegisteredClientRepository clientRepository = http.getSharedObject(RegisteredClientRepository.class);
        AuthorizationServerSettings authzServerSettings = http.getSharedObject(AuthorizationServerSettings.class);
        OAuth2TokenGenerator<?> oAuth2TokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);
        UserRepository userRepository = http.getSharedObject(UserRepository.class);

        if (authorizationService == null || clientRepository == null) {
            log.error("OAuth2StateConfigurer: Required beans for Authorization Server not found in SharedObjects.");
            throw new IllegalStateException("OAuth2AuthorizationService and RegisteredClientRepository are required for Authorization Server mode");
        }

        OAuth2AuthorizationServerConfigurer authzServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        ApplicationContext appContext = getBuilder().getSharedObject(ApplicationContext.class);
        http.with(authzServerConfigurer, authzServer -> {
            authzServer
                    .authorizationService(authorizationService)
                    .registeredClientRepository(clientRepository);

            if (authzServerSettings != null) {
                authzServer.authorizationServerSettings(authzServerSettings);
            }


            TransactionTemplate transactionTemplate = null;
            if (appContext != null) {
                try {
                    transactionTemplate = appContext.getBean(TransactionTemplate.class);
                } catch (Exception e) {
                    log.error("OAuth2StateConfigurer: TransactionTemplate not found - authenticated-user grant type will not be available");
                }
            }
            if (transactionTemplate != null) {
                TransactionTemplate finalTransactionTemplate = transactionTemplate;
                authzServer.tokenEndpoint(tokenEndpoint ->
                        tokenEndpoint
                                .accessTokenRequestConverter(new AuthenticatedUserGrantAuthenticationConverter())
                                .authenticationProvider(new AuthenticatedUserGrantAuthenticationProvider(
                                        authorizationService,
                                        oAuth2TokenGenerator,
                                        userRepository,
                                        finalTransactionTemplate))
                );
            }

            authzServer.tokenEndpoint(tokenEndpoint -> {

                if (appContext != null) {
                    try {
                        AuthenticationSuccessHandler successHandler = appContext.getBean("oauth2TokenSuccessHandler", AuthenticationSuccessHandler.class);
                        tokenEndpoint.accessTokenResponseHandler(successHandler);
                    } catch (Exception e) {
                        log.error("OAuth2StateConfigurer: Failed to register OAuth2TokenSuccessHandler: {}", e.getMessage());
                    }

                    try {
                        AuthenticationFailureHandler failureHandler = appContext.getBean("oauth2TokenFailureHandler", AuthenticationFailureHandler.class);
                        tokenEndpoint.errorResponseHandler(failureHandler);
                    } catch (Exception e) {
                        log.error("OAuth2StateConfigurer: Failed to register OAuth2TokenFailureHandler: {}", e.getMessage());
                    }
                }
            });
            authzServer.oidc(Customizer.withDefaults());
        });
        AuthContextProperties properties = appContext.getBean(AuthContextProperties.class);
        http.with(new OAuth2CsrfConfigurer(properties.isOauth2Csrf()), Customizer.withDefaults());
    }
}
