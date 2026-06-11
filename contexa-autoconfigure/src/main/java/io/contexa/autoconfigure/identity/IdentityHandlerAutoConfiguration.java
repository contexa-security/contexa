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

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.handler.*;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.token.service.TokenService;
import io.contexa.contexaidentity.security.utils.AuthResponseWriter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnProperty(prefix = "contexa.identity.handler", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IdentityHandlerAutoConfiguration {

    public IdentityHandlerAutoConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean
    public OneTimeTokenCreationSuccessHandler oneTimeTokenCreationSuccessHandler(
            MfaStateMachineIntegrator mfaStateMachineIntegrator,
            AuthUrlProvider authUrlProvider,
            MfaFlowUrlRegistry mfaFlowUrlRegistry,
            MfaSessionRepository sessionRepository) {
        return new OneTimeTokenCreationSuccessHandler(
                mfaStateMachineIntegrator,
                authUrlProvider,
                mfaFlowUrlRegistry,
                sessionRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionSingleAuthFailureHandler sessionSingleAuthFailureHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties,
            @Autowired(required = false) io.contexa.contexacommon.security.LoginPolicyHandler loginPolicyHandler) {
        return new SessionSingleAuthFailureHandler(responseWriter, authContextProperties, loginPolicyHandler);
    }

    @Bean
    @ConditionalOnMissingBean
    public SessionSingleAuthSuccessHandler sessionSingleAuthSuccessHandler(
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties,
            @Autowired(required = false) io.contexa.contexacommon.security.LoginPolicyHandler loginPolicyHandler) {
        return new SessionSingleAuthSuccessHandler(responseWriter, authContextProperties, loginPolicyHandler);
    }

    @Bean
    @ConditionalOnMissingBean
    public OAuth2SingleAuthSuccessHandler oauth2SingleAuthSuccessHandler(
            TokenService tokenService,
            AuthResponseWriter responseWriter,
            AuthContextProperties authContextProperties,
            @Autowired(required = false) io.contexa.contexacommon.security.LoginPolicyHandler loginPolicyHandler) {
        return new OAuth2SingleAuthSuccessHandler(tokenService, responseWriter, authContextProperties, loginPolicyHandler);
    }

    @Bean
    @ConditionalOnMissingBean
    public OAuth2SingleAuthFailureHandler oauth2SingleAuthFailureHandler(
            AuthResponseWriter responseWriter,
            @Autowired(required = false) io.contexa.contexacommon.security.LoginPolicyHandler loginPolicyHandler) {
        return new OAuth2SingleAuthFailureHandler(responseWriter, loginPolicyHandler);
    }
}
