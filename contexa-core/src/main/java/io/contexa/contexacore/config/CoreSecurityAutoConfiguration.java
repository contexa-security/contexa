package io.contexa.contexacore.config;

import io.contexa.contexacore.security.UnifiedUserDetailsService;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.properties.SecurityTrustTierProperties;
import io.contexa.contexacommon.properties.SecurityAnomalyDetectionProperties;
import io.contexa.contexacore.autonomous.notification.NotificationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;


@Slf4j
@AutoConfiguration
@EnableConfigurationProperties({
    SecurityTrustTierProperties.class,
    SecurityAnomalyDetectionProperties.class
})
@ConditionalOnProperty(
    prefix = "contexa.core.security",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
public class CoreSecurityAutoConfiguration {

    public CoreSecurityAutoConfiguration() {
        log.info("Core Security AutoConfiguration activated");
    }

    
    @Bean
    @Primary
    @ConditionalOnProperty(
        prefix = "contexa.core.security.unified",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
    )
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UnifiedUserDetailsService unifiedUserDetailsService(
            UserRepository userRepository,
            SecurityTrustTierProperties trustTierProperties,
            SecurityAnomalyDetectionProperties anomalyDetectionProperties,
            @Autowired(required = false) RedisTemplate<String, Object> redisTemplate,
            @Autowired(required = false) NotificationService notificationService,
            AuditLogRepository auditLogRepository) {

        log.info("Registering UnifiedUserDetailsService as @Primary UserDetailsService");

        return new UnifiedUserDetailsService(
                userRepository,
                trustTierProperties,
                anomalyDetectionProperties,
                redisTemplate,
                notificationService,
                auditLogRepository
        );
    }
}
