package io.contexa.autoconfigure.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.utils.ThreatScoreUtil;
import io.contexa.contexacore.security.AIReactiveSecurityContextRepository;
import io.contexa.contexacore.security.session.RedisSessionIdResolver;
import io.contexa.contexacore.security.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexacore.properties.SecuritySessionProperties;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.security.core.CustomAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
@EnableConfigurationProperties({ SecurityZeroTrustProperties.class, SecuritySessionProperties.class })
public class IamSecurityCoreAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustSecurityService zeroTrustSecurityService(
            RedisTemplate<String, Object> redisTemplate,
            ThreatScoreUtil threatScoreUtil,
            ObjectMapper objectMapper,
            SecurityZeroTrustProperties securityZeroTrustProperties) {
        return new ZeroTrustSecurityService(redisTemplate,
                threatScoreUtil, objectMapper, securityZeroTrustProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public CustomAuthenticationProvider customAuthenticationProvider(UserDetailsService userDetailsService) {
        return new CustomAuthenticationProvider(userDetailsService);
    }

    @Bean
    @ConditionalOnMissingBean
    public AIReactiveSecurityContextRepository aiReactiveSecurityContextRepository() {
        return new AIReactiveSecurityContextRepository();
    }

    @Bean
    @ConditionalOnMissingBean
    public RedisSessionIdResolver redisSessionIdResolver(RedisTemplate<String, Object> redisTemplate,
            SecuritySessionProperties securitySessionProperties) {
        return new RedisSessionIdResolver(redisTemplate, securitySessionProperties);
    }
}
