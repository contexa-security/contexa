package io.contexa.autoconfigure.identity;

import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.service.ott.InMemoryCodeStore;
import io.contexa.contexaidentity.security.service.ott.MagicLinkHandler;
import org.springframework.beans.factory.annotation.Autowired;
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
    public EmailService emailService(@Autowired(required = false) JavaMailSender mailSender) {
        return new EmailService(mailSender);
    }

    @Bean
    @ConditionalOnMissingBean(OneTimeTokenService.class)
    public OneTimeTokenService oneTimeTokenService(
            EmailService emailService,
            JdbcTemplate jdbcTemplate,
            TransactionTemplate transactionTemplate,
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
    public InMemoryCodeStore inMemoryCodeStore() {
        return new InMemoryCodeStore();
    }
}
