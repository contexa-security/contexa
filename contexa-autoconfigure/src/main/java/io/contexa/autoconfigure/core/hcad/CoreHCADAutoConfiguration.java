package io.contexa.autoconfigure.core.hcad;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.tiered.feedback.LayerFeedbackService;
import io.contexa.contexacore.hcad.filter.HCADFilter;
import io.contexa.contexacore.hcad.service.EmbeddingService;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import io.contexa.contexacore.hcad.service.HCADContextExtractor;
import io.contexa.contexacore.hcad.service.HCADVectorIntegrationService;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * Core HCAD AutoConfiguration
 *
 * Contexa 프레임워크의 HCAD 관련 자동 구성을 제공합니다.
 *
 * AI Native 전환:
 * - 삭제된 클래스: HCADSimilarityCalculator, UnifiedThresholdManager, AdaptiveThresholdManager,
 *   FeedbackLoopSystem, HCADFeedbackOrchestrator, HCADBaselineLearningService, DynamicTrustCalculator,
 *   HCADAuthenticationService, ThreatCorrelationService, TimeSeriesCorrelationAnalyzer,
 *   TrustProfileService, ZeroTrustThresholdManager, HCADBaselineCacheService, HCADSessionThreatService,
 *   ZeroTrustDecisionEngine
 * - LLM riskScore 기반 판단으로 전환
 *
 * 활성화 조건:
 * contexa:
 *   hcad:
 *     enabled: true  (기본값)
 *
 * @since 0.1.0-ALPHA
 */
@AutoConfiguration
@ConditionalOnProperty(
    prefix = "contexa.hcad",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true
)
@EnableConfigurationProperties({ContexaProperties.class, HcadProperties.class, FeedbackIntegrationProperties.class})
public class CoreHCADAutoConfiguration {

    public CoreHCADAutoConfiguration() {
        // @Bean 방식으로 HCAD 서비스 등록
    }

    // ========== Level 1: 독립적 서비스 ==========

    /**
     * EmbeddingService - 임베딩 생성 및 캐싱 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public EmbeddingService embeddingService(
            RedisTemplate<String, Object> redisTemplate) {
        return new EmbeddingService(redisTemplate);
    }

    /**
     * HCADContextExtractor - HCAD 컨텍스트 추출 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADContextExtractor hcadContextExtractor(
            RedisTemplate<String, Object> redisTemplate) {
        return new HCADContextExtractor(redisTemplate);
    }

    // ========== Level 2: Level 1 의존 ==========
    // AI Native 전환: FewShotAnomalyDetector 삭제 (완전 규칙 기반 로직 - LLM 무관)

    // ========== Level 3: Level 2 의존 ==========

    /**
     * HCADVectorIntegrationService - HCAD와 Vector Store 통합 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADVectorIntegrationService hcadVectorIntegrationService(
            BehaviorVectorService behaviorVectorService,
            UnifiedVectorService unifiedVectorService,
            RedisTemplate<String, Object> redisTemplate,
            FeedbackIntegrationProperties feedbackIntegrationProperties,
            LayerFeedbackService layerFeedbackService,
            EmbeddingService embeddingService) {
        return new HCADVectorIntegrationService(
            behaviorVectorService, unifiedVectorService, redisTemplate,
            feedbackIntegrationProperties, layerFeedbackService, embeddingService
        );
    }

    // ========== Level 4: Level 3 의존 ==========

    /**
     * HCADAnalysisService - HCAD 분석 서비스
     *
     * AI Native 전환:
     * - HCADBaselineCacheService 제거
     * - LLM riskScore 기반 판단으로 전환
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADAnalysisService hcadAnalysisService(
            HCADContextExtractor hcadContextExtractor) {
        return new HCADAnalysisService(hcadContextExtractor);
    }

    // ========== Level 5: HCADFilter (조건부) ==========

    /**
     * HCADFilter - HCAD 필터
     *
     * AI Native 전환:
     * - LLM riskScore를 Redis에서 조회하여 사용
     * - HCADAuthenticationService 제거
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADFilter hcadFilter(HCADAnalysisService hcadAnalysisService) {
        return new HCADFilter(hcadAnalysisService);
    }
}
