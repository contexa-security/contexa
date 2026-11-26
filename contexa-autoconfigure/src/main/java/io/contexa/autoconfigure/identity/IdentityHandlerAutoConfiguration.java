/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.*;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import io.contexa.contexacommon.operating.ConditionalOnMode;
import io.contexa.contexacommon.security.HeldBean;
import io.contexa.contexacommon.security.bridge.SecurityMode;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnProperty(prefix = "contexa.identity.handler", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IdentityHandlerAutoConfiguration {

    public IdentityHandlerAutoConfiguration() {
    }

    /**
     * Spring Security's one-time token login of the application takes a {@link OneTimeTokenGenerationSuccessHandler} by type, a sole
     * one even when it is no autowire candidate, and does not start with two. Contexa's is offered by type only where its main
     * chain signs the application's users in and the application has none (R-17 of docs/agent/운영모드-정상화-구현계획.md); elsewhere
     * it is held, and Contexa's flows take it by its name.
     */
    @Bean(name = "contexaOneTimeTokenCreationSuccessHandler")
    @ConditionalOnMode(SecurityMode.FULL)
    @ConditionalOnMissingBean(OneTimeTokenGenerationSuccessHandler.class)
    public OneTimeTokenCreationSuccessHandler oneTimeTokenCreationSuccessHandler(
            MfaStateMachineIntegrator contexaMfaStateMachineIntegrator,
            AuthUrlProvider contexaAuthUrlProvider,
            MfaFlowUrlRegistry contexaMfaFlowUrlRegistry,
            MfaSessionRepository sessionRepository) {
        return new OneTimeTokenCreationSuccessHandler(
                contexaMfaStateMachineIntegrator,
                contexaAuthUrlProvider,
                contexaMfaFlowUrlRegistry,
                sessionRepository);
    }

    @Bean(name = "contexaOneTimeTokenCreationSuccessHandler")
    @ConditionalOnMissingBean(name = "contexaOneTimeTokenCreationSuccessHandler")
    public HeldBean<OneTimeTokenGenerationSuccessHandler> heldOneTimeTokenCreationSuccessHandler(
            MfaStateMachineIntegrator contexaMfaStateMachineIntegrator,
            AuthUrlProvider contexaAuthUrlProvider,
            MfaFlowUrlRegistry contexaMfaFlowUrlRegistry,
            MfaSessionRepository sessionRepository) {
        return new HeldBean<>(new OneTimeTokenCreationSuccessHandler(
                contexaMfaStateMachineIntegrator,
                contexaAuthUrlProvider,
                contexaMfaFlowUrlRegistry,
                sessionRepository));
    }

    @Bean(name = "contexaSessionSingleAuthFailureHandler")
    @ConditionalOnMissingBean
    public SessionSingleAuthFailureHandler sessionSingleAuthFailureHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties,
            @Autowired(required = false) LoginPolicyHandler contexaLoginPolicyHandler) {
        return new SessionSingleAuthFailureHandler(responseWriter, authContextProperties, contexaLoginPolicyHandler);
    }

    @Bean(name = "contexaSessionSingleAuthSuccessHandler")
    @ConditionalOnMissingBean
    public SessionSingleAuthSuccessHandler sessionSingleAuthSuccessHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties,
            @Autowired(required = false) LoginPolicyHandler contexaLoginPolicyHandler,
            ObjectProvider<ZeroTrustEventPublisher> zeroTrustEventPublisher) {
        SessionSingleAuthSuccessHandler handler =
                new SessionSingleAuthSuccessHandler(responseWriter, authContextProperties, contexaLoginPolicyHandler);
        // The completed sign-in goes to the engine, as the application's own sign-in does in mode SANDBOX.
        handler.setZeroTrustEventPublisher(zeroTrustEventPublisher.getIfAvailable());
        return handler;
    }

    @Bean(name = "contexaOauth2SingleAuthSuccessHandler")
    @ConditionalOnMissingBean
    public OAuth2SingleAuthSuccessHandler oauth2SingleAuthSuccessHandler(
            ObjectProvider<TokenService> tokenService,
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties,
            @Autowired(required = false) LoginPolicyHandler contexaLoginPolicyHandler,
            ObjectProvider<ZeroTrustEventPublisher> zeroTrustEventPublisher) {
        // The token service belongs to Contexa's OAuth2 plane, which only a flow on OAuth2 state uses this handler with
        OAuth2SingleAuthSuccessHandler handler = new OAuth2SingleAuthSuccessHandler(tokenService.getIfAvailable(), responseWriter,
                authContextProperties, contexaLoginPolicyHandler);
        // The completed sign-in goes to the engine, as the application's own sign-in does in mode SANDBOX.
        handler.setZeroTrustEventPublisher(zeroTrustEventPublisher.getIfAvailable());
        return handler;
    }

    @Bean(name = "contexaOauth2SingleAuthFailureHandler")
    @ConditionalOnMissingBean
    public OAuth2SingleAuthFailureHandler oauth2SingleAuthFailureHandler(
            AuthResponseWriter responseWriter,
            @Autowired(required = false) LoginPolicyHandler contexaLoginPolicyHandler) {
        return new OAuth2SingleAuthFailureHandler(responseWriter, contexaLoginPolicyHandler);
    }
}
