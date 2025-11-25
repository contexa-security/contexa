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

/**
 * Core Security AutoConfiguration
 *
 * Contexa Core의 핵심 보안 서비스 자동 구성
 *
 * <h3>등록되는 빈:</h3>
 * <ul>
 *   <li>UnifiedUserDetailsService (@Primary) - 통합 UserDetailsService</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * contexa:
 *   core:
 *     security:
 *       enabled: true  # (기본값)
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
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

    /**
     * UnifiedUserDetailsService 등록 (@Primary)
     *
     * Identity와 IAM의 UserDetailsService를 대체하는 통합 서비스
     * - RoleAuthority + PermissionAuthority 권한 모델
     * - Trust Tier 동적 권한 조정 (선택적)
     * - HCAD 이상 탐지 (선택적)
     *
     * 활성화 조건:
     * - contexa.core.security.unified.enabled = true (기본값: true)
     * - UserDetailsService 빈이 없을 때만 등록
     *
     * 비활성화 시 각 모듈의 UserDetailsService가 사용됩니다
     */
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
