package io.contexa.autoconfigure.identity;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.*;
import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.writer.AuthResponseWriter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

/**
 * Identity Handler AutoConfiguration
 *
 * <p>
 * Contexa Identity의 Handler 관련 자동 구성을 제공합니다.
 * Success/Failure Handler 등을 명시적으로 등록합니다.
 * </p>
 *
 * <h3>등록되는 빈:</h3>
 * <ul>
 *   <li>OTT Handler (1개): OneTimeTokenCreationSuccessHandler</li>
 *   <li>Session Handlers (4개): SessionSingleAuthFailureHandler, SessionSingleAuthSuccessHandler, SessionMfaFailureHandler, SessionMfaSuccessHandler</li>
 *   <li>OAuth2 Handlers (2개): OAuth2SingleAuthSuccessHandler, OAuth2SingleAuthFailureHandler</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * contexa:
 *   identity:
 *     handler:
 *       enabled: true  # (기본값)
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.identity.handler",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
public class IdentityHandlerAutoConfiguration {

    public IdentityHandlerAutoConfiguration() {
        // Handler 관련 빈 등록
    }

    // ========== Level 1: OTT Handler (1개) ==========

    /**
     * 1-1. OneTimeTokenCreationSuccessHandler - OTT 생성 성공 핸들러
     */
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

    // ========== Level 2: Session Handlers (4개) ==========

    /**
     * 2-1. SessionSingleAuthFailureHandler - 단일 인증 실패 핸들러 (세션)
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionSingleAuthFailureHandler sessionSingleAuthFailureHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties) {
        return new SessionSingleAuthFailureHandler(responseWriter, authContextProperties);
    }

    /**
     * 2-2. SessionSingleAuthSuccessHandler - 단일 인증 성공 핸들러 (세션)
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionSingleAuthSuccessHandler sessionSingleAuthSuccessHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties) {
        return new SessionSingleAuthSuccessHandler(responseWriter, authContextProperties);
    }

    /**
     * 2-3. SessionMfaFailureHandler - MFA 실패 핸들러 (세션)
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMfaFailureHandler sessionMfaFailureHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties) {
        return new SessionMfaFailureHandler(responseWriter, authContextProperties);
    }

    /**
     * 2-4. SessionMfaSuccessHandler - MFA 성공 핸들러 (세션)
     */
    @Bean
    @ConditionalOnMissingBean
    public SessionMfaSuccessHandler sessionMfaSuccessHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties) {
        return new SessionMfaSuccessHandler(responseWriter, authContextProperties);
    }

    // ========== Level 3: OAuth2 Handlers (2개) ==========

    /**
     * 3-1. OAuth2SingleAuthSuccessHandler - 단일 인증 성공 핸들러 (OAuth2)
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2SingleAuthSuccessHandler oauth2SingleAuthSuccessHandler(
            TokenService tokenService,
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties) {
        return new OAuth2SingleAuthSuccessHandler(tokenService, responseWriter, authContextProperties);
    }

    /**
     * 3-2. OAuth2SingleAuthFailureHandler - 단일 인증 실패 핸들러 (OAuth2)
     */
    @Bean
    @ConditionalOnMissingBean
    public OAuth2SingleAuthFailureHandler oauth2SingleAuthFailureHandler(
            AuthResponseWriter responseWriter) {
        return new OAuth2SingleAuthFailureHandler(responseWriter);
    }
}
