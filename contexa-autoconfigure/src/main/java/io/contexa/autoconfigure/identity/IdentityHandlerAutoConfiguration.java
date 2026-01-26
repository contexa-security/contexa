package io.contexa.autoconfigure.identity;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.*;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.springframework.context.annotation.Bean;


@AutoConfiguration
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnProperty(
    prefix = "contexa.identity.handler",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
public class IdentityHandlerAutoConfiguration {

    public IdentityHandlerAutoConfiguration() {
        
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    public OneTimeTokenCreationSuccessHandler oneTimeTokenCreationSuccessHandler(
            MfaStateMachineIntegrator mfaStateMachineIntegrator,
            AuthUrlProvider authUrlProvider,
            MfaSessionRepository sessionRepository) {
        return new OneTimeTokenCreationSuccessHandler(
            mfaStateMachineIntegrator,
            authUrlProvider,
            sessionRepository
        );
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    public SessionSingleAuthFailureHandler sessionSingleAuthFailureHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties) {
        return new SessionSingleAuthFailureHandler(responseWriter, authContextProperties);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SessionSingleAuthSuccessHandler sessionSingleAuthSuccessHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties) {
        return new SessionSingleAuthSuccessHandler(responseWriter, authContextProperties);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SessionMfaFailureHandler sessionMfaFailureHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties) {
        return new SessionMfaFailureHandler(responseWriter, authContextProperties);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public SessionMfaSuccessHandler sessionMfaSuccessHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties) {
        return new SessionMfaSuccessHandler(responseWriter, authContextProperties);
    }

    

    
    @Bean
    @ConditionalOnMissingBean
    public OAuth2SingleAuthSuccessHandler oauth2SingleAuthSuccessHandler(
            TokenService tokenService,
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties) {
        return new OAuth2SingleAuthSuccessHandler(tokenService, responseWriter, authContextProperties);
    }

    
    @Bean
    @ConditionalOnMissingBean
    public OAuth2SingleAuthFailureHandler oauth2SingleAuthFailureHandler(
            AuthResponseWriter responseWriter) {
        return new OAuth2SingleAuthFailureHandler(responseWriter);
    }
}
