package io.contexa.autoconfigure.identity;

import io.contexa.contexaidentity.security.properties.AuthContextProperties;
import io.contexa.contexaidentity.security.service.AuthUrlProvider;
import io.contexa.contexaidentity.security.service.IdentityUserDetailsService;
import io.contexa.contexaidentity.security.service.ott.EmailOneTimeTokenService;
import io.contexa.contexaidentity.security.service.ott.EmailService;
import io.contexa.contexaidentity.security.service.ott.InMemoryCodeStore;
import io.contexa.contexaidentity.security.service.ott.MagicLinkHandler;
import io.contexa.contexacommon.repository.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Identity Service AutoConfiguration
 *
 * <p>
 * Contexa Identity의 Service 관련 자동 구성을 제공합니다.
 * UserDetailsService, URL Provider, OTT 서비스 등을 명시적으로 등록합니다.
 * </p>
 *
 * <h3>등록되는 빈:</h3>
 * <ul>
 *   <li>Core Services (2개): CustomUserDetailsService, AuthUrlProvider</li>
 *   <li>OTT Services (4개): EmailService, EmailOneTimeTokenService, MagicLinkHandler, InMemoryCodeStore</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * contexa:
 *   identity:
 *     service:
 *       enabled: true  # (기본값)
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.identity.service",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
public class IdentityServiceAutoConfiguration {

    public IdentityServiceAutoConfiguration() {
        // Service 관련 빈 등록
    }

    // ========== Level 1: Core Services (2개) ==========

    /**
     * 1-1. CustomUserDetailsService - 사용자 세부 정보 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public IdentityUserDetailsService identityUserDetailsService(
            UserRepository userRepository,
            ModelMapper modelMapper) {
        return new IdentityUserDetailsService(userRepository, modelMapper);
    }

    /**
     * 1-2. AuthUrlProvider - 인증 URL 제공 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthUrlProvider authUrlProvider(AuthContextProperties properties) {
        return new AuthUrlProvider(properties);
    }

    // ========== Level 2: OTT Services (4개) ==========

    /**
     * 2-1. EmailService - 이메일 발송 서비스
     * JavaMailSender가 있을 때만 활성화
     */
    @Bean
    @ConditionalOnBean(JavaMailSender.class)
    @ConditionalOnMissingBean
    public EmailService emailService(JavaMailSender mailSender) {
        return new EmailService(mailSender);
    }

    /**
     * 2-2. EmailOneTimeTokenService - 이메일 기반 OTT 서비스
     * EmailService가 있을 때만 활성화
     */
    @Bean
    @ConditionalOnBean(EmailService.class)
    @ConditionalOnMissingBean
    public EmailOneTimeTokenService emailOneTimeTokenService(
            EmailService emailService,
            JdbcTemplate jdbcTemplate,
            TransactionTemplate transactionTemplate,
            AuthContextProperties authContextProperties) {
        return new EmailOneTimeTokenService(
            emailService,
            jdbcTemplate,
            transactionTemplate,
            authContextProperties
        );
    }

    /**
     * 2-3. MagicLinkHandler - Magic Link 핸들러
     */
    @Bean
    @ConditionalOnMissingBean
    public MagicLinkHandler magicLinkHandler() {
        return new MagicLinkHandler();
    }

    /**
     * 2-4. InMemoryCodeStore - 인메모리 코드 저장소
     */
    @Bean
    @ConditionalOnMissingBean
    public InMemoryCodeStore inMemoryCodeStore() {
        return new InMemoryCodeStore();
    }
}
