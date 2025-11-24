package io.contexa.autoconfigure.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.orchestrator.ThreatScoreOrchestrator;
import io.contexa.contexacore.infra.redis.RedisAtomicOperations;
import io.contexa.contexacoreenterprise.autonomous.notification.UnifiedNotificationService;
import io.contexa.contexaiam.security.core.AIReactiveSecurityContextRepository;
import io.contexa.contexaiam.security.core.AIReactiveUserDetailsService;
import io.contexa.contexaiam.security.core.CustomAuthenticationProvider;
import io.contexa.contexaiam.security.core.IAMUserDetailsService;
import io.contexa.contexaiam.security.core.session.RedisSessionIdResolver;
import io.contexa.contexaiam.security.core.zerotrust.ZeroTrustSecurityService;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.UserRepository;
import org.modelmapper.ModelMapper;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

@AutoConfiguration
public class IamSecurityCoreAutoConfiguration {

    // Security Core Services (6개)
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
    public IAMUserDetailsService iamUserDetailsService(UserRepository userRepository) {
        return new IAMUserDetailsService(userRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public CustomAuthenticationProvider customAuthenticationProvider(
            AIReactiveUserDetailsService aiReactiveUserDetailsService,
            ModelMapper modelMapper) {
        return new CustomAuthenticationProvider(aiReactiveUserDetailsService, modelMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public AIReactiveUserDetailsService aiReactiveUserDetailsService(
            UserRepository userRepository,
            RedisTemplate<String, Object> redisTemplate,
            UnifiedNotificationService notificationService,
            AuditLogRepository auditLogRepository) {
        return new AIReactiveUserDetailsService(userRepository, redisTemplate, notificationService, auditLogRepository);
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
