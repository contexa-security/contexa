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

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.service.ott.ContexaOneTimeTokens;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.service.ott.MagicLinkHandler;
import io.contexa.contexaidentity.security.zerotrust.stepup.InMemoryStepUpOptionsStore;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.transaction.support.TransactionTemplate;

@AutoConfiguration
@ConditionalOnBean(PlatformConfig.class)
@ConditionalOnProperty(prefix = "contexa.identity.service", name = "enabled", havingValue = "true", matchIfMissing = true)
@Import(IdentityServiceContexaOwnedConfiguration.class)
public class IdentityServiceAutoConfiguration {

    public IdentityServiceAutoConfiguration() {
    }
    @Bean(name = "contexaAuthUrlProvider")
    @ConditionalOnMissingBean
    public AuthUrlProvider authUrlProvider(AuthContextProperties properties) {
        return new AuthUrlProvider(properties);
    }

    @Bean(name = "contexaMfaFlowUrlRegistry")
    @ConditionalOnMissingBean
    public MfaFlowUrlRegistry mfaFlowUrlRegistry(AuthContextProperties properties) {
        return new MfaFlowUrlRegistry(properties);
    }

    @Bean(name = "contexaEmailService")
    @ConditionalOnMissingBean
    public EmailService emailService(ObjectProvider<JavaMailSender> mailSender, AuthContextProperties mailLimits) {
        // none, or several of the application's: Contexa then does not send mail with the application's sender
        AuthContextProperties.OttSettings ott = mailLimits.getOtt();
        return new EmailService(mailSender.getIfUnique(), ott.getEmailMaxConcurrentSends(), ott.getEmailSendWaitSeconds(),
                ott.getEmailSmtpTimeoutSeconds());
    }

    // Held in a bean that is not a OneTimeTokenService, and not stood aside for the application's own service: the one-time token login of
    // the application takes its OneTimeTokenService by type (and finds a sole bean of that type even when it is no autowire candidate),
    // while Contexa's flows take theirs by this name.
    @Bean(name = "contexaOneTimeTokenService")
    @ConditionalOnMissingBean(name = "contexaOneTimeTokenService")
    public ContexaOneTimeTokens oneTimeTokenService(
            EmailService contexaEmailService,
            @Qualifier("contexaJdbcTemplate") JdbcTemplate jdbcTemplate,
            // ctxa_one_time_tokens is JDBC-owned; the shared Contexa transaction manager keeps the boundary explicit.
            @Qualifier("contexaTransactionTemplate") TransactionTemplate transactionTemplate,
            AuthContextProperties authContextProperties,
            ObjectProvider<StepUpOptionsStore> stepUpOptionsStore,
            BeanFactory beanFactory) {
        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                contexaEmailService,
                jdbcTemplate,
                transactionTemplate,
                authContextProperties,
                authContextProperties.getOtt().isFailOnEmailError(),
                stepUpOptionsStore.getIfAvailable(InMemoryStepUpOptionsStore::new));
        service.setUserStore(() -> ContexaUserStore.of(beanFactory));
        return new ContexaOneTimeTokens(service);
    }

    @Bean(name = "contexaMagicLinkHandler")
    @ConditionalOnMissingBean
    public MagicLinkHandler magicLinkHandler() {
        return new MagicLinkHandler();
    }

}

