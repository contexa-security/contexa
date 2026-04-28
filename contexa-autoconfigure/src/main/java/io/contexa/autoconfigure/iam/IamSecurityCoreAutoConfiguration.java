package io.contexa.autoconfigure.iam;

import io.contexa.contexacore.autonomous.blocking.BlockingSignalBroadcaster;
import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.security.AISecurityContextSupport;
import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexacore.security.AIOAuth2SecurityContextRepository;
import io.contexa.contexacore.security.AIOAuth2ZeroTrustFilter;
import io.contexa.contexacore.security.async.AsyncSecurityContextProvider;
import io.contexa.contexacore.security.session.InMemorySessionIdResolver;
import io.contexa.contexacore.security.session.RedisSessionIdResolver;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.InMemoryZeroTrustSecurityService;
import io.contexa.contexacore.security.zerotrust.RedisZeroTrustSecurityService;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexacore.properties.SecuritySessionProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.core.CustomAuthenticationProvider;
import io.contexa.contexaiam.security.core.LoginAttemptCleanupFilter;
import io.contexa.contexaiam.security.core.LoginAttemptEventListener;
import io.contexa.contexaiam.security.core.LoginAttemptIpUpserter;
import io.contexa.contexaiam.security.core.LoginPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexacommon.repository.LoginAttemptIpRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.security.LoginPolicyHandler;
import org.springframework.lang.Nullable;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
@AutoConfigureAfter(name = {
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration",
        "io.contexa.contexacommon.config.redis.CommonRedisAutoConfiguration"
})
@EnableConfigurationProperties({ SecurityZeroTrustProperties.class, SecuritySessionProperties.class })
public class IamSecurityCoreAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public LoginAttemptIpUpserter loginAttemptIpUpserter(LoginAttemptIpRepository loginAttemptIpRepository) {
        return new LoginAttemptIpUpserter(loginAttemptIpRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public LoginPolicyHandler loginPolicyHandler(UserRepository userRepository,
                                                  LoginAttemptIpRepository loginAttemptIpRepository,
                                                  PasswordPolicyService passwordPolicyService,
                                                  LoginAttemptIpUpserter loginAttemptIpUpserter) {
        return new LoginPolicyService(userRepository, loginAttemptIpRepository,
                passwordPolicyService, loginAttemptIpUpserter);
    }

    @Bean
    @ConditionalOnMissingBean
    public LoginAttemptEventListener loginAttemptEventListener(LoginPolicyHandler loginPolicyHandler) {
        return new LoginAttemptEventListener(loginPolicyHandler);
    }

    /**
     * Explicit registration so the filter's URL pattern, ordering, and name are deterministic
     * rather than inferred by Spring Boot's automatic Filter-bean detection. Wrapping the
     * filter in {@link FilterRegistrationBean} also prevents accidental double registration
     * (the wrapped filter is registered by this bean and skipped by the auto-detection path).
     */
    @Bean
    @ConditionalOnMissingBean(name = "loginAttemptCleanupFilterRegistration")
    public FilterRegistrationBean<LoginAttemptCleanupFilter> loginAttemptCleanupFilterRegistration() {
        FilterRegistrationBean<LoginAttemptCleanupFilter> registration =
                new FilterRegistrationBean<>(new LoginAttemptCleanupFilter());
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.LOWEST_PRECEDENCE);
        registration.setName("loginAttemptCleanupFilter");
        return registration;
    }

    @Bean
    @ConditionalOnMissingBean
    public CustomAuthenticationProvider customAuthenticationProvider(UserDetailsService userDetailsService,
                                                                    PasswordEncoder passwordEncoder,
                                                                    LoginPolicyHandler loginPolicyHandler) {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder, loginPolicyHandler);
    }

    @Bean
    @ConditionalOnMissingBean
    public AISecurityContextSupport aiSecurityContextSupport(
            SecurityZeroTrustProperties securityZeroTrustProperties,
            @Nullable ZeroTrustSecurityService zeroTrustSecurityService,
            @Nullable SessionIdResolver sessionIdResolver) {
        return new AISecurityContextSupport(securityZeroTrustProperties, zeroTrustSecurityService, sessionIdResolver);
    }

    @Bean
    @ConditionalOnMissingBean
    public AISessionSecurityContextRepository aiSessionSecurityContextRepository(
            AISecurityContextSupport aiSecurityContextSupport,
            @Nullable SecurityContextDataStore securityContextDataStore,
            @Nullable AsyncSecurityContextProvider asyncSecurityContextProvider) {
        return new AISessionSecurityContextRepository(
                aiSecurityContextSupport,
                securityContextDataStore,
                asyncSecurityContextProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public AIOAuth2SecurityContextRepository aiOAuth2SecurityContextRepository(
            AISecurityContextSupport aiSecurityContextSupport) {
        return new AIOAuth2SecurityContextRepository(aiSecurityContextSupport);
    }

    @Configuration
    @ConditionalOnProperty(name = "contexa.infrastructure.mode", havingValue = "distributed")
    @ConditionalOnBean(RedisTemplate.class)
    static class DistributedSecurityConfig {

        @Bean
        @ConditionalOnMissingBean(ZeroTrustSecurityService.class)
        public RedisZeroTrustSecurityService zeroTrustSecurityService(
                RedisTemplate<String, Object> redisTemplate,
                ThreatScoreUtil threatScoreUtil,
                SecurityZeroTrustProperties securityZeroTrustProperties,
                ZeroTrustActionRepository actionRedisRepository) {
            return new RedisZeroTrustSecurityService(redisTemplate,
                    threatScoreUtil, securityZeroTrustProperties, actionRedisRepository);
        }

        @Bean
        @ConditionalOnMissingBean(SessionIdResolver.class)
        public RedisSessionIdResolver redisSessionIdResolver(RedisTemplate<String, Object> redisTemplate,
                SecuritySessionProperties securitySessionProperties) {
            return new RedisSessionIdResolver(redisTemplate, securitySessionProperties);
        }
    }

    @Bean
    @ConditionalOnMissingBean(SessionIdResolver.class)
    public SessionIdResolver inMemorySessionIdResolver(SecuritySessionProperties securitySessionProperties) {
        return new InMemorySessionIdResolver(securitySessionProperties);
    }

    @Bean
    @ConditionalOnMissingBean(ZeroTrustSecurityService.class)
    public InMemoryZeroTrustSecurityService inMemoryZeroTrustSecurityService(
            ThreatScoreUtil threatScoreUtil,
            SecurityZeroTrustProperties securityZeroTrustProperties,
            ZeroTrustActionRepository actionRepository,
            @Nullable BlockingSignalBroadcaster blockingSignalBroadcaster) {
        return new InMemoryZeroTrustSecurityService(
                threatScoreUtil, securityZeroTrustProperties, actionRepository, blockingSignalBroadcaster);
    }
}

