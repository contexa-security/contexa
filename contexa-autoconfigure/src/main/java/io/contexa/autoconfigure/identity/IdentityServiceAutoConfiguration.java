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
import org.springframework.boot.ssl.SslBundles;
import org.springframework.core.env.Environment;
import io.contexa.contexacommon.operating.ConditionalOnOwnership;
import io.contexa.contexacommon.operating.ContexaOperatingProfile;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexacommon.security.bridge.SecurityOwnershipMode;
import io.contexa.contexacore.security.ContexaUserStore;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.MfaFlowUrlRegistry;
import io.contexa.contexaidentity.security.service.ott.ContexaOneTimeTokens;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.service.ott.MagicLinkHandler;
import io.contexa.contexaidentity.security.zerotrust.stepup.InMemoryStepUpOptionsStore;
import io.contexa.contexaidentity.security.zerotrust.stepup.StepUpOptionsStore;
import lombok.extern.slf4j.Slf4j;
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

@Slf4j
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
    public EmailService emailService(ObjectProvider<JavaMailSender> mailSender, Environment environment,
                                     ObjectProvider<SslBundles> sslBundles, AuthContextProperties mailLimits) {
        // the application's one sender; none, or several of them where the application signs its users in: Contexa then does
        // not send mail with the application's sender
        JavaMailSender sender = mailSender.getIfUnique();
        if (sender == null && ContexaOperatingProfile.resolve(environment).ownership() == SecurityOwnershipMode.CONTEXA_OWNED) {
            // Contexa signs the users in, and the administrator reaches the console by the code it mails: that must not depend on how
            // many senders the application keeps. None or several of them, and Contexa builds a sender of its own from spring.mail.*,
            // which only the service holds; the application's beans are not touched.
            sender = ContexaMailSenders.fromSettings(environment, sslBundles);
        }
        AuthContextProperties.OttSettings ott = mailLimits.getOtt();
        return new EmailService(sender, ott.getEmailMaxConcurrentSends(), ott.getEmailSendWaitSeconds(),
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
            BeanFactory beanFactory,
            Environment environment) {
        EmailOneTimeTokenService service = new EmailOneTimeTokenService(
                contexaEmailService,
                jdbcTemplate,
                transactionTemplate,
                authContextProperties,
                authContextProperties.getOtt().isFailOnEmailError(),
                stepUpOptionsStore.getIfAvailable(InMemoryStepUpOptionsStore::new));
        service.setUserStore(() -> ContexaUserStore.forSignIn(beanFactory));
        boolean toConsole = codeToConsole(authContextProperties, environment, contexaEmailService.isMailSenderConfigured());
        service.setCodeToConsole(toConsole);
        if (toConsole) {
            log.warn("[Contexa] One-time sign-in codes are written to this log ({}), so a sign-in finishes without a mail "
                            + "server; they are mailed as well where mail is configured. A production start mails them only: "
                            + "start without these profiles and with spring.mail.* set, or set "
                            + "contexa.auth.ott.code-to-console=false.",
                    authContextProperties.getOtt().getCodeToConsole() != null ? "contexa.auth.ott.code-to-console=true"
                            : contexaEmailService.isMailSenderConfigured()
                            ? "profile " + String.join(",", environment.getActiveProfiles()) : "no mail server is configured");
        }
        return new ContexaOneTimeTokens(service);
    }

    /** Says at the start whether the mail server of the codes works, and what to set when it does not. */
    @Bean(name = "contexaOttMailStartupCheck")
    @ConditionalOnMissingBean(name = "contexaOttMailStartupCheck")
    public OttMailStartupCheck ottMailStartupCheck(EmailService contexaEmailService,
                                                   AuthContextProperties authContextProperties,
                                                   Environment environment) {
        return new OttMailStartupCheck(contexaEmailService,
                codeToConsole(authContextProperties, environment, contexaEmailService.isMailSenderConfigured()));
    }

    /** Whether one-time codes go to the log too, by the rule the sign-in pages follow as well. */
    static boolean codeToConsole(AuthContextProperties properties, Environment environment, boolean mailConfigured) {
        return properties.getOtt().writesCodesToConsole(environment.getActiveProfiles(), mailConfigured);
    }

    // Only where Contexa signs the users in: the one-time token login of an application that signs its own users in takes its
    // OneTimeTokenGenerationSuccessHandler by type, and does not start with two of them (with none of its own it would take this one).
    @Bean(name = "contexaMagicLinkHandler")
    @ConditionalOnMissingBean
    @ConditionalOnOwnership(SecurityOwnershipMode.CONTEXA_OWNED)
    public MagicLinkHandler magicLinkHandler() {
        return new MagicLinkHandler();
    }

}

