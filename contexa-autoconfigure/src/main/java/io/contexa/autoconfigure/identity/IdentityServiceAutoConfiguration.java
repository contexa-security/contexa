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
import io.contexa.contexaidentity.controller.MfaConfigController;
import io.contexa.contexaidentity.security.filter.handler.MfaStateMachineIntegrator;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.service.ott.MagicLinkHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.transaction.support.TransactionTemplate;

@AutoConfiguration
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnProperty(prefix = "contexa.identity.service", name = "enabled", havingValue = "true", matchIfMissing = true)
public class IdentityServiceAutoConfiguration {

    public IdentityServiceAutoConfiguration() {
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthUrlProvider authUrlProvider(AuthContextProperties properties) {
        return new AuthUrlProvider(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public MfaFlowUrlRegistry mfaFlowUrlRegistry(AuthContextProperties properties) {
        return new MfaFlowUrlRegistry(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public EmailService emailService(@Autowired(required = false) JavaMailSender mailSender) {
        return new EmailService(mailSender);
    }

    @Bean
    @ConditionalOnMissingBean(OneTimeTokenService.class)
    public EmailOneTimeTokenService oneTimeTokenService(
            EmailService emailService,
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            // one_time_tokens is JDBC-owned; the shared Contexa transaction manager keeps the boundary explicit.
            @Qualifier("contexaTransactionTemplate") TransactionTemplate transactionTemplate,
            AuthContextProperties authContextProperties) {
        return new EmailOneTimeTokenService(
                emailService,
                jdbcTemplate,
                transactionTemplate,
                authContextProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public MagicLinkHandler magicLinkHandler() {
        return new MagicLinkHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(AuthUrlProvider.class)
    public MfaConfigController mfaConfigController(AuthUrlProvider authUrlProvider,
                                                     MfaFlowUrlRegistry mfaFlowUrlRegistry,
                                                     MfaStateMachineIntegrator stateMachineIntegrator) {
        return new MfaConfigController(authUrlProvider, mfaFlowUrlRegistry, stateMachineIntegrator);
    }
}

