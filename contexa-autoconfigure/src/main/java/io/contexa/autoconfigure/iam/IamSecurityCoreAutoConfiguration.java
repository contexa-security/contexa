package io.contexa.autoconfigure.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.notification.NotificationService;
import io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator;
import io.contexa.contexacore.infra.redis.RedisAtomicOperations;
import io.contexa.contexaiam.security.core.AIReactiveSecurityContextRepository;
import io.contexa.contexaiam.security.core.CustomAuthenticationProvider;
import io.contexa.contexaiam.security.core.session.RedisSessionIdResolver;
import io.contexa.contexaiam.security.core.zerotrust.ZeroTrustSecurityService;
import org.springframework.security.core.userdetails.UserDetailsService;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
public class IamSecurityCoreAutoConfiguration {

    // Security Core Services (3개)
    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustSecurityService zeroTrustSecurityService(
            RedisTemplate<String, Object> redisTemplate,
            ThreatScoreOrchestrator threatScoreOrchestrator,
            RedisAtomicOperations redisAtomicOperations,
            ObjectMapper objectMapper) {
        return new ZeroTrustSecurityService(redisTemplate, threatScoreOrchestrator, redisAtomicOperations, objectMapper);
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
    public RedisSessionIdResolver redisSessionIdResolver(RedisTemplate<String, Object> redisTemplate) {
        return new RedisSessionIdResolver(redisTemplate);
    }
}
