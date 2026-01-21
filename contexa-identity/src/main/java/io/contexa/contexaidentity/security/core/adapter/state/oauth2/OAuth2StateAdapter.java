package io.contexa.contexaidentity.security.core.adapter.state.oauth2;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaidentity.security.core.adapter.StateAdapter;
import io.contexa.contexaidentity.security.core.context.PlatformContext;
import io.contexa.contexaidentity.security.token.service.OAuth2TokenService;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.JsonAuthResponseWriter;
import io.contexa.contexacommon.repository.UserRepository;
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
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
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

        ApplicationContext appContext = Objects.requireNonNull(platformCtx.applicationContext(), "ApplicationContext from PlatformContext cannot be null");

        ObjectMapper objectMapper;
        JsonAuthResponseWriter jsonAuthResponseWriter;
        try {
            objectMapper = appContext.getBean(ObjectMapper.class);
            jsonAuthResponseWriter = appContext.getBean(JsonAuthResponseWriter.class);

            http.setSharedObject(ObjectMapper.class, objectMapper);
            http.setSharedObject(JsonAuthResponseWriter.class, jsonAuthResponseWriter);

        } catch (NoSuchBeanDefinitionException e) {
            log.error("OAuth2StateAdapter [{}]: Required bean ({}) not found in ApplicationContext.",
                    getId(), e.getMessage(), e);
            throw new IllegalStateException("Required bean for OAuth2 state configuration not found: " + e.getMessage(), e);
        }
        configureResourceServer(http, appContext);
        configureAuthorizationServer(http, appContext);
        try {
            OAuth2TokenService tokenService = appContext.getBean(OAuth2TokenService.class);
            http.setSharedObject(TokenService.class, tokenService);
        } catch (NoSuchBeanDefinitionException e) {
            log.warn("OAuth2StateAdapter [{}]: OAuth2TokenService bean not found. " +
                    "Token operations may not be available.", getId());
        }

        configureLogout(http, appContext);

        OAuth2StateConfigurer oauth2StateConfigurer = new OAuth2StateConfigurer();
        http.with(oauth2StateConfigurer, Customizer.withDefaults());

            }

    private void configureResourceServer(HttpSecurity http, ApplicationContext appContext) {
        try {
            JwtDecoder jwtDecoder = appContext.getBean(JwtDecoder.class);
            http.setSharedObject(JwtDecoder.class, jwtDecoder);
                    } catch (NoSuchBeanDefinitionException e) {
            log.error("OAuth2StateAdapter: JwtDecoder bean not found for Resource Server mode. " +
                    "Ensure JwtDecoder is configured in OAuth2AutoConfiguration.", e);
            throw new IllegalStateException("JwtDecoder is required for Resource Server mode", e);
        }
    }

    private void configureAuthorizationServer(HttpSecurity http, ApplicationContext appContext) {
        try {
            JwtEncoder jwtEncoder = appContext.getBean(JwtEncoder.class);
            OAuth2AuthorizationService authorizationService = appContext.getBean(OAuth2AuthorizationService.class);
            RegisteredClientRepository registeredClientRepository = appContext.getBean(RegisteredClientRepository.class);
            AuthorizationServerSettings authorizationServerSettings = appContext.getBean(AuthorizationServerSettings.class);
            OAuth2TokenGenerator<?> tokenGenerator = appContext.getBean(OAuth2TokenGenerator.class);
            UserRepository userRepository = appContext.getBean(UserRepository.class);

            http.setSharedObject(JwtEncoder.class, jwtEncoder);
            http.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
            http.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
            http.setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
            http.setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
            http.setSharedObject(UserRepository.class, userRepository);

                    } catch (NoSuchBeanDefinitionException e) {
            log.error("OAuth2StateAdapter: Required bean for Authorization Server mode not found: {}. " +
                    "Ensure all beans are configured in OAuth2AutoConfiguration.", e.getMessage(), e);
            throw new IllegalStateException("Authorization Server beans are required for AUTHORIZATION_SERVER mode", e);
        }
    }

    private void configureLogout(HttpSecurity http, ApplicationContext appContext) throws Exception {
        try {
            LogoutHandler logoutHandler = appContext.getBean("oauth2LogoutHandler", LogoutHandler.class);
            LogoutSuccessHandler logoutSuccessHandler = appContext.getBean("oauth2LogoutSuccessHandler", LogoutSuccessHandler.class);

            http.setSharedObject(LogoutHandler.class, logoutHandler);
            http.setSharedObject(LogoutSuccessHandler.class, logoutSuccessHandler);

            http.logout(logout -> logout
                    .logoutRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/api/auth/logout"))
                    .addLogoutHandler(logoutHandler)
                    .logoutSuccessHandler(logoutSuccessHandler)
                    .invalidateHttpSession(false) 
                    .clearAuthentication(true)
            );

                    } catch (NoSuchBeanDefinitionException e) {
            log.warn("OAuth2StateAdapter: Logout handlers not found. Using default logout configuration.");
        }
    }
}
