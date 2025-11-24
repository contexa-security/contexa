package io.contexa.autoconfigure.identity;

import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.MfaPageGeneratingConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaidentity.security.core.mfa.policy.AIAdaptiveMfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.DefaultMfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.MfaPolicyProvider;
import io.contexa.contexaidentity.security.core.mfa.policy.evaluator.*;
import io.contexa.contexacommon.properties.AuthContextProperties;
import io.contexa.contexaidentity.service.MfaSupportService;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.notification.NotificationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

import java.util.List;

/**
 * Identity MFA AutoConfiguration
 *
 * <p>
 * Contexa Identity의 MFA Policy 관련 자동 구성을 제공합니다.
 * MFA Policy Provider, Policy Evaluator 등을 명시적으로 등록합니다.
 * </p>
 *
 * <h3>등록되는 빈:</h3>
 * <ul>
 *   <li>Policy Providers (2개): DefaultMfaPolicyProvider, AIAdaptiveMfaPolicyProvider (@Primary)</li>
 *   <li>Policy Evaluators (4개): DefaultMfaPolicyEvaluator, AIAdaptivePolicyEvaluator, ZeroTrustPolicyEvaluator, CompositeMfaPolicyEvaluator (@Primary)</li>
 * </ul>
 *
 * <h3>활성화 조건:</h3>
 * <pre>
 * contexa:
 *   identity:
 *     mfa:
 *       enabled: true  # (기본값)
 * </pre>
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.identity.mfa",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
public class IdentityMfaAutoConfiguration {

    public IdentityMfaAutoConfiguration() {
        // MFA Policy 관련 빈 등록
    }

    // ========== Level 1: Policy Evaluators (4개) ==========

    /**
     * 1-1. DefaultMfaPolicyEvaluator - 기본 규칙 기반 정책 평가자
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultMfaPolicyEvaluator defaultMfaPolicyEvaluator(
            UserRepository userRepository,
            ApplicationContext applicationContext) {
        return new DefaultMfaPolicyEvaluator(userRepository, applicationContext);
    }

    /**
     * 1-2. AIAdaptivePolicyEvaluator - AI 기반 적응형 정책 평가자
     * AICoreOperations가 있을 때만 활성화
     */
    @Bean
    @ConditionalOnBean(AICoreOperations.class)
    @ConditionalOnMissingBean
    public AIAdaptivePolicyEvaluator aiAdaptivePolicyEvaluator(
            AICoreOperations aiCoreOperations) {
        return new AIAdaptivePolicyEvaluator(aiCoreOperations);
    }

    /**
     * 1-3. ZeroTrustPolicyEvaluator - Zero Trust 기반 정책 평가자
     * zeroTrustRedisTemplate이 있을 때만 활성화
     */
    @Bean
    @ConditionalOnBean(name = "zeroTrustRedisTemplate")
    @ConditionalOnMissingBean
    public ZeroTrustPolicyEvaluator zeroTrustPolicyEvaluator(
            @Qualifier("zeroTrustRedisTemplate") RedisTemplate<String, Double> redisTemplate,
            @Autowired(required = false) NotificationService notificationService,
            AuditLogRepository auditLogRepository) {
        return new ZeroTrustPolicyEvaluator(redisTemplate, notificationService, auditLogRepository);
    }

    /**
     * 1-4. CompositeMfaPolicyEvaluator - Composite 패턴 평가자 (@Primary)
     * 모든 MfaPolicyEvaluator를 통합 관리
     */
    @Bean
    @ConditionalOnMissingBean
    public CompositeMfaPolicyEvaluator compositeMfaPolicyEvaluator(
            List<MfaPolicyEvaluator> evaluators) {
        return new CompositeMfaPolicyEvaluator(evaluators);
    }

    // ========== Level 2: Policy Providers (2개) ==========

    /**
     * 2-1. DefaultMfaPolicyProvider - 기본 MFA 정책 제공자
     */
    @Bean
    @ConditionalOnMissingBean(name = "defaultMfaPolicyProvider")
    public DefaultMfaPolicyProvider defaultMfaPolicyProvider(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            AuthContextProperties properties,
            MfaPolicyEvaluator policyEvaluator,
            PlatformConfig platformConfig) {
        return new DefaultMfaPolicyProvider(
            userRepository,
            applicationContext,
            properties,
            policyEvaluator,
            platformConfig
        );
    }

    /**
     * 2-2. AIAdaptiveMfaPolicyProvider - AI 적응형 MFA 정책 제공자 (@Primary)
     * AICoreOperations가 있을 때만 활성화
     */
    @Bean
    @ConditionalOnBean(AICoreOperations.class)
    @ConditionalOnMissingBean(name = "aiAdaptiveMfaPolicyProvider")
    public AIAdaptiveMfaPolicyProvider aiAdaptiveMfaPolicyProvider(
            UserRepository userRepository,
            ApplicationContext applicationContext,
            AuthContextProperties properties,
            CompositeMfaPolicyEvaluator compositePolicyEvaluator,
            PlatformConfig platformConfig,
            AICoreOperations aiCoreOperations) {
        return new AIAdaptiveMfaPolicyProvider(
            userRepository,
            applicationContext,
            properties,
            compositePolicyEvaluator,
            platformConfig,
            aiCoreOperations
        );
    }

    // ========== Level 3: MFA Support Components (2개) ==========

    /**
     * 3-1. MfaSupportService - MFA 지원 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public MfaSupportService mfaSupportService(UserRepository userRepository) {
        return new MfaSupportService(userRepository);
    }

    /**
     * 3-2. MfaPageGeneratingConfigurer - MFA 페이지 생성 Configurer
     */
    @Bean
    @ConditionalOnMissingBean
    public MfaPageGeneratingConfigurer mfaPageGeneratingConfigurer(ApplicationContext applicationContext) {
        return new MfaPageGeneratingConfigurer(applicationContext);
    }
}
