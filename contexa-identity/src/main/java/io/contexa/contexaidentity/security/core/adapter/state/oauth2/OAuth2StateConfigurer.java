package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationConverter;
import io.contexa.contexaidentity.security.core.adapter.state.oauth2.grant.AuthenticatedUserGrantAuthenticationProvider;
import io.contexa.contexaidentity.security.filter.OAuth2PreAuthenticationFilter;
import io.contexa.contexaidentity.security.filter.OAuth2RefreshAuthenticationFilter;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * OAuth2 기반 상태 관리 전략을 HttpSecurity에 적용하는 설정자입니다.
 * OAuth2 Resource Server 및 Authorization Server 필터들을 필터 체인에 등록합니다.
 *
 * <p>이 설정자는 Spring Security의 oauth2ResourceServer() DSL과
 * Spring Authorization Server의 OAuth2AuthorizationServerConfigurer를 활용하여
 * AIDC 프레임워크의 DSL 스타일로 통합합니다.
 */
@Slf4j
public final class OAuth2StateConfigurer extends AbstractHttpConfigurer<OAuth2StateConfigurer, HttpSecurity> {

    public OAuth2StateConfigurer() {
        log.debug("OAuth2StateConfigurer instance created.");
    }

    @Override
    public void init(HttpSecurity http) throws Exception {
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        if (context == null) {
            log.warn("OAuth2StateConfigurer: ApplicationContext not found in HttpSecurity sharedObjects during init. " +
                    "Dependencies will be resolved in configure phase.");
        }
        log.debug("OAuth2StateConfigurer initializing for HttpSecurity (hash: {}).", http.hashCode());
        configureResourceServer(http);
        configureAuthorizationServer(http);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        log.debug("OAuth2StateConfigurer configuring HttpSecurity (hash: {}). Adding OAuth2 filters.", http.hashCode());

        TokenService tokenService = http.getSharedObject(TokenService.class);
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);

        if (tokenService != null) {

            OAuth2PreAuthenticationFilter preAuthFilter = new OAuth2PreAuthenticationFilter(tokenService);
            http.addFilterBefore(postProcess(preAuthFilter), LogoutFilter.class);
            log.debug("OAuth2StateConfigurer: Added OAuth2PreAuthenticationFilter before LogoutFilter.");

            if (context != null) {
                try {
                    LogoutHandler logoutHandler = context.getBean("oauth2LogoutHandler", LogoutHandler.class);
                    AuthResponseWriter responseWriter = context.getBean(AuthResponseWriter.class);

                    OAuth2RefreshAuthenticationFilter refreshFilter =
                            new OAuth2RefreshAuthenticationFilter(tokenService, logoutHandler, responseWriter);
                    http.addFilterBefore(postProcess(refreshFilter), LogoutFilter.class);
                    log.debug("OAuth2StateConfigurer: Added OAuth2RefreshAuthenticationFilter before LogoutFilter.");

                } catch (Exception e) {
                    log.warn("OAuth2StateConfigurer: Failed to register OAuth2RefreshAuthenticationFilter. " +
                            "LogoutHandler or AuthResponseWriter not found: {}", e.getMessage());
                }
            }
        } else {
            log.warn("OAuth2StateConfigurer: TokenService not found in SharedObjects. OAuth2 filters not registered.");
        }


    }

    /**
     * Resource Server 설정 적용
     */
    private void configureResourceServer(HttpSecurity http) throws Exception {

        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {
                    jwt.jwtAuthenticationConverter(new OAuth2JwtAuthenticationConverter());
                })
                .authenticationEntryPoint(new OAuth2AuthenticationEntryPoint())
                .accessDeniedHandler(new OAuth2AccessDeniedHandler())
        );

        log.info("OAuth2StateConfigurer: Resource Server configured with JWT token validation using JwtDecoder Bean.");

    }

    /**
     * Authorization Server 설정 적용
     */
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

        http.with(authzServerConfigurer, authzServer -> {
            authzServer
                    .authorizationService(authorizationService)
                    .registeredClientRepository(clientRepository);

            if (authzServerSettings != null) {
                authzServer.authorizationServerSettings(authzServerSettings);
            }

            // TransactionTemplate 조회
            ApplicationContext appContext = getBuilder().getSharedObject(ApplicationContext.class);
            TransactionTemplate transactionTemplate = null;
            if (appContext != null) {
                try {
                    transactionTemplate = appContext.getBean(TransactionTemplate.class);
                } catch (Exception e) {
                    log.warn("OAuth2StateConfigurer: TransactionTemplate not found - AuthenticatedUserGrantAuthenticationProvider may fail with auto-commit:false");
                }
            }

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

            authzServer.tokenEndpoint(tokenEndpoint -> {

                ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
                if (context != null) {
                    try {
                        AuthenticationSuccessHandler successHandler =
                                context.getBean("oauth2TokenSuccessHandler", AuthenticationSuccessHandler.class);
                        tokenEndpoint.accessTokenResponseHandler(successHandler);
                    } catch (Exception e) {
                        log.debug("OAuth2StateConfigurer: Custom token success handler not found, using default.");
                    }

                    try {
                        AuthenticationFailureHandler failureHandler =
                                context.getBean("oauth2TokenFailureHandler", AuthenticationFailureHandler.class);
                        tokenEndpoint.errorResponseHandler(failureHandler);
                    } catch (Exception e) {
                        log.debug("OAuth2StateConfigurer: Custom token failure handler not found, using default.");
                    }
                }
            });

            // OIDC 지원
            authzServer.oidc(Customizer.withDefaults());
        });

        log.info("OAuth2StateConfigurer: Authorization Server endpoints configured.");
    }
}
