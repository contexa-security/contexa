package io.contexa.autoconfigure.iam;

import io.contexa.contexacore.autonomous.repository.ZeroTrustActionRepository;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.security.AIReactiveSecurityContextRepository;
import io.contexa.contexacore.security.session.InMemorySessionIdResolver;
import io.contexa.contexacore.security.session.RedisSessionIdResolver;
import io.contexa.contexacore.security.session.SessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexacore.properties.SecuritySessionProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.core.CustomAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
@EnableConfigurationProperties({ SecurityZeroTrustProperties.class, SecuritySessionProperties.class })
public class IamSecurityCoreAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public CustomAuthenticationProvider customAuthenticationProvider(UserDetailsService userDetailsService,
                                                                    PasswordEncoder passwordEncoder) {
        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder);
    }

    @Bean
    @ConditionalOnMissingBean
    public AIReactiveSecurityContextRepository aiReactiveSecurityContextRepository() {
        return new AIReactiveSecurityContextRepository();
    }

    // --- Distributed mode: Redis-based ZeroTrust and session ---

    @Configuration
    @ConditionalOnBean(RedisTemplate.class)
    static class DistributedSecurityConfig {

        @Bean
        @ConditionalOnMissingBean
        public ZeroTrustSecurityService zeroTrustSecurityService(
                RedisTemplate<String, Object> redisTemplate,
                ThreatScoreUtil threatScoreUtil,
                SecurityZeroTrustProperties securityZeroTrustProperties,
                ZeroTrustActionRepository actionRedisRepository) {
            return new ZeroTrustSecurityService(redisTemplate,
                    threatScoreUtil, securityZeroTrustProperties, actionRedisRepository);
        }

        @Bean
        @ConditionalOnMissingBean(SessionIdResolver.class)
        public RedisSessionIdResolver redisSessionIdResolver(RedisTemplate<String, Object> redisTemplate,
                SecuritySessionProperties securitySessionProperties) {
            return new RedisSessionIdResolver(redisTemplate, securitySessionProperties);
        }
    }

    // --- Standalone mode: In-memory session resolver ---

    @Configuration
    @ConditionalOnMissingBean(RedisTemplate.class)
    static class StandaloneSecurityConfig {

        @Bean
        @ConditionalOnMissingBean(SessionIdResolver.class)
        public SessionIdResolver inMemorySessionIdResolver(SecuritySessionProperties securitySessionProperties) {
            return new InMemorySessionIdResolver(securitySessionProperties);
        }
    }
}
