package io.contexa.autoconfigure.core.autonomous;

import io.contexa.autoconfigure.core.hcad.CoreHCADAutoConfiguration;
import io.contexa.autoconfigure.properties.ContextaProperties;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.config.SecurityPlaneConfiguration;
import io.contexa.contexacore.autonomous.strategy.DynamicStrategySelector;
import io.contexa.contexacore.autonomous.tiered.TieredEventProcessor;
import io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer;
import io.contexa.contexacore.autonomous.tiered.detection.MaliciousPatternDetector;
import io.contexa.contexacore.autonomous.tiered.feedback.LayerFeedbackService;
import io.contexa.contexacore.autonomous.tiered.routing.AdaptiveTierRouter;
import io.contexa.contexacore.autonomous.tiered.template.Layer1PromptTemplate;
import io.contexa.contexacore.autonomous.tiered.template.Layer2PromptTemplate;
import io.contexa.contexacore.autonomous.tiered.template.Layer3PromptTemplate;
import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.std.rag.processors.ThreatCorrelator;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * Core Autonomous AutoConfiguration
 *
 * Contexa 프레임워크의 Autonomous Security Plane 자동 구성을 제공합니다.
 * @Bean 방식으로 Autonomous 관련 컴포넌트들을 명시적으로 등록합니다.
 *
 * 포함된 Configuration:
 * - SecurityPlaneConfiguration - Security Plane 기본 설정
 *
 * 포함된 컴포넌트 (12개):
 * - 전략 패턴 (1개): DynamicStrategySelector
 * - 템플릿 (3개): Layer1/2/3PromptTemplate
 * - 유틸리티 (8개): TieredEventProcessor, AdaptiveTierRouter, SecurityEventEnricher, LayerFeedbackService, MaliciousPatternDetector
 *
 * 활성화 조건:
 * contexa:
 *   autonomous:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@AutoConfigureAfter(CoreHCADAutoConfiguration.class)
@ConditionalOnProperty(
    prefix = "contexa.autonomous",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties(ContextaProperties.class)
@ConditionalOnClass(name = "io.contexa.contexacore.autonomous.SecurityPlaneAgent")
@Import({
    SecurityPlaneConfiguration.class
})
public class CoreAutonomousAutoConfiguration {

    public CoreAutonomousAutoConfiguration() {
        // @Bean 방식으로 Autonomous 컴포넌트 등록
    }

    // ========== Level 1: 독립적 서비스 (5개) ==========

    /**
     * 1-1. TieredEventProcessor - 계층적 이벤트 처리 프로세서
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.autonomous.tiered.TieredEventProcessor")
    public TieredEventProcessor tieredEventProcessor() {
        return new TieredEventProcessor();
    }

    /**
     * 1-2. SecurityEventEnricher - 보안 이벤트 강화 유틸리티
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher")
    public SecurityEventEnricher securityEventEnricher() {
        return new SecurityEventEnricher();
    }

    /**
     * 1-3. DynamicStrategySelector - 동적 전략 선택기
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.autonomous.strategy.DynamicStrategySelector")
    public DynamicStrategySelector dynamicStrategySelector(
            ThreatCorrelator threatCorrelator) {
        return new DynamicStrategySelector(threatCorrelator);
    }

    /**
     * 1-4. MaliciousPatternDetector - 악성 패턴 탐지기
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.autonomous.tiered.detection.MaliciousPatternDetector")
    public MaliciousPatternDetector maliciousPatternDetector(
            @Qualifier("stringRedisTemplate") RedisTemplate<String, String> stringRedisTemplate) {
        return new MaliciousPatternDetector(stringRedisTemplate);
    }

    /**
     * 1-5. LayerFeedbackService - 계층별 피드백 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.autonomous.tiered.feedback.LayerFeedbackService")
    public LayerFeedbackService layerFeedbackService(
            @Autowired(required = false) UnifiedVectorService unifiedVectorService,
            RedisTemplate<String, Object> redisTemplate,
            FeedbackIntegrationProperties feedbackIntegrationProperties) {
        return new LayerFeedbackService(unifiedVectorService, redisTemplate, feedbackIntegrationProperties);
    }

    // ========== Level 2: Level 1 의존 (4개) ==========

    /**
     * 2-1. Layer1PromptTemplate - Layer 1 프롬프트 템플릿
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.autonomous.tiered.template.Layer1PromptTemplate")
    public Layer1PromptTemplate layer1PromptTemplate(
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher) {
        return new Layer1PromptTemplate(securityEventEnricher);
    }

    /**
     * 2-2. Layer2PromptTemplate - Layer 2 프롬프트 템플릿
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.autonomous.tiered.template.Layer2PromptTemplate")
    public Layer2PromptTemplate layer2PromptTemplate(
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher) {
        return new Layer2PromptTemplate(securityEventEnricher);
    }

    /**
     * 2-3. Layer3PromptTemplate - Layer 3 프롬프트 템플릿
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnClass(name = "io.contexa.contexacore.autonomous.tiered.template.Layer3PromptTemplate")
    public Layer3PromptTemplate layer3PromptTemplate(
            @Autowired(required = false) SecurityEventEnricher securityEventEnricher) {
        return new Layer3PromptTemplate(securityEventEnricher);
    }

}

