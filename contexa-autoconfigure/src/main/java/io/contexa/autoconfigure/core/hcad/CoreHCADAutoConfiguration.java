package io.contexa.autoconfigure.core.hcad;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.properties.HcadProperties;
import io.contexa.contexacommon.metrics.HCADFeedbackMetrics;
import io.contexa.contexacore.autonomous.config.FeedbackIntegrationProperties;
import io.contexa.contexacore.autonomous.tiered.feedback.LayerFeedbackService;
import io.contexa.contexacore.hcad.engine.ZeroTrustDecisionEngine;
import io.contexa.contexacore.hcad.feedback.FeedbackLoopSystem;
import io.contexa.contexacore.hcad.filter.HCADFilter;
import io.contexa.contexacore.hcad.orchestrator.HCADFeedbackOrchestrator;
import io.contexa.contexacore.hcad.service.*;
import io.contexa.contexacore.hcad.threshold.AdaptiveThresholdManager;
import io.contexa.contexacore.hcad.threshold.UnifiedThresholdManager;
import io.contexa.contexacore.plane.ZeroTrustHotPathOrchestrator;
import io.contexa.contexacore.std.labs.behavior.BehaviorVectorService;
import io.contexa.contexacore.std.rag.processors.AnomalyScoreRanker;
import io.contexa.contexacore.std.rag.processors.ThreatCorrelator;
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
 * @Bean 방식으로 HCAD 서비스들을 명시적으로 등록합니다.
 *
 * 의존성 순서:
 * Level 1 (8개) - 독립적 서비스
 * Level 2 (3개) - Level 1 의존
 * Level 3 (2개) - Level 2 의존
 * Level 4 (2개) - Level 3 의존
 * Level 5 (3개) - Level 4 의존
 * Level 6 (2개) - Level 5 의존
 * Level 7 (1개) - Level 6 의존
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
@EnableConfigurationProperties({ContexaProperties.class, HcadProperties.class})
public class CoreHCADAutoConfiguration {

    public CoreHCADAutoConfiguration() {
        // @Bean 방식으로 21개 HCAD 서비스 등록
    }

    // ========== Level 1: 독립적 서비스 (8개) ==========

    /**
     * 1-1. EmbeddingService - 임베딩 생성 및 캐싱 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public EmbeddingService embeddingService(
            RedisTemplate<String, Object> redisTemplate) {
        return new EmbeddingService(redisTemplate);
    }

    /**
     * 1-2. HCADContextExtractor - HCAD 컨텍스트 추출 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADContextExtractor hcadContextExtractor(
            RedisTemplate<String, Object> redisTemplate) {
        return new HCADContextExtractor(redisTemplate);
    }

    /**
     * 1-3. DynamicTrustCalculator - 동적 신뢰도 계산기
     */
    @Bean
    @ConditionalOnMissingBean
    public DynamicTrustCalculator dynamicTrustCalculator(
            RedisTemplate<String, Object> redisTemplate) {
        return new DynamicTrustCalculator(redisTemplate);
    }

    /**
     * 1-4. TimeSeriesCorrelationAnalyzer - 시계열 상관관계 분석 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public TimeSeriesCorrelationAnalyzer timeSeriesCorrelationAnalyzer(
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
        return new TimeSeriesCorrelationAnalyzer(redisTemplate);
    }

    /**
     * 1-5. HCADAuthenticationService - HCAD 인증 정보 관리 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADAuthenticationService hcadAuthenticationService() {
        return new HCADAuthenticationService();
    }

    /**
     * 1-6. HCADBaselineLearningService - HCAD 기준선 학습 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADBaselineLearningService hcadBaselineLearningService(
            RedisTemplate<String, Object> redisTemplate) {
        return new HCADBaselineLearningService(redisTemplate);
    }

    /**
     * 1-7. TrustProfileService - 신뢰 프로필 관리 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public TrustProfileService trustProfileService(
            RedisTemplate<String, Object> redisTemplate) {
        return new TrustProfileService(redisTemplate);
    }

    /**
     * 1-8. HCADSessionThreatService - 세션 위협 관리 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADSessionThreatService hcadSessionThreatService(
            RedisTemplate<String, Object> redisTemplate) {
        return new HCADSessionThreatService(redisTemplate);
    }

    // ========== Level 2: Level 1 의존 (3개) ==========

    /**
     * 2-1. FewShotAnomalyDetector - Few-Shot 이상 탐지 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public FewShotAnomalyDetector fewShotAnomalyDetector(
            UnifiedVectorService unifiedVectorService) {
        return new FewShotAnomalyDetector(unifiedVectorService);
    }

    /**
     * 2-2. ThreatCorrelationService - 위협 상관관계 분석 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public ThreatCorrelationService threatCorrelationService(
            TimeSeriesCorrelationAnalyzer timeSeriesCorrelationAnalyzer) {
        return new ThreatCorrelationService(timeSeriesCorrelationAnalyzer);
    }

    /**
     * 2-3. ZeroTrustThresholdManager - Zero Trust 임계값 관리 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustThresholdManager zeroTrustThresholdManager(
            TrustProfileService trustProfileService,
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
        return new ZeroTrustThresholdManager(trustProfileService, redisTemplate);
    }

    // ========== Level 3: Level 2 의존 (2개) ==========

    /**
     * 3-1. HCADVectorIntegrationService - HCAD와 Vector Store 통합 서비스
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

    /**
     * 3-2. AdaptiveThresholdManager - 적응형 임계값 관리자
     */
    @Bean
    @ConditionalOnMissingBean
    public AdaptiveThresholdManager adaptiveThresholdManager() {
        return new AdaptiveThresholdManager();
    }

    // ========== Level 4: Level 3 의존 (2개) ==========

    /**
     * 4-1. HCADBaselineCacheService - 기준선 캐시 관리 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADBaselineCacheService hcadBaselineCacheService(
            RedisTemplate<String, Object> redisTemplate,
            HCADVectorIntegrationService hcadVectorIntegrationService) {
        return new HCADBaselineCacheService(redisTemplate, hcadVectorIntegrationService);
    }

    /**
     * 4-2. FeedbackLoopSystem - 피드백 루프 시스템
     */
    @Bean
    @ConditionalOnMissingBean
    public FeedbackLoopSystem feedbackLoopSystem() {
        return new FeedbackLoopSystem();
    }

    // ========== Level 5: Level 4 의존 (3개) ==========

    /**
     * 5-1. HCADSimilarityCalculator - HCAD 유사도 계산 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADSimilarityCalculator hcadSimilarityCalculator(
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            UnifiedVectorService unifiedVectorService,
            ThreatCorrelator threatCorrelator,
            AnomalyScoreRanker anomalyScoreRanker,
            DynamicTrustCalculator dynamicTrustCalculator,
            FewShotAnomalyDetector fewShotAnomalyDetector,
            @Autowired(required = false) ZeroTrustHotPathOrchestrator zeroTrustHotPathOrchestrator,
            @Autowired(required = false) HCADFeedbackMetrics hcadFeedbackMetrics) {
        return new HCADSimilarityCalculator(
            redisTemplate, unifiedVectorService, threatCorrelator, anomalyScoreRanker,
            dynamicTrustCalculator, fewShotAnomalyDetector,
            zeroTrustHotPathOrchestrator, hcadFeedbackMetrics
        );
    }

    /**
     * 5-2. UnifiedThresholdManager - 통합 임계값 관리자
     */
    @Bean
    @ConditionalOnMissingBean
    public UnifiedThresholdManager unifiedThresholdManager(
            AdaptiveThresholdManager adaptiveThresholdManager,
            RedisTemplate<String, Object> redisTemplate) {
        return new UnifiedThresholdManager(adaptiveThresholdManager, redisTemplate);
    }

    /**
     * 5-3. ZeroTrustDecisionEngine - Zero Trust 결정 엔진
     */
    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustDecisionEngine zeroTrustDecisionEngine(
            TrustProfileService trustProfileService,
            ThreatCorrelationService threatCorrelationService,
            ZeroTrustThresholdManager zeroTrustThresholdManager) {
        return new ZeroTrustDecisionEngine(
            trustProfileService, threatCorrelationService, zeroTrustThresholdManager
        );
    }

    // ========== Level 6: Level 5 의존 (2개) ==========

    /**
     * 6-1. HCADAnalysisService - HCAD 분석 서비스
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADAnalysisService hcadAnalysisService(
            HCADContextExtractor hcadContextExtractor,
            HCADBaselineCacheService hcadBaselineCacheService,
            HCADSimilarityCalculator hcadSimilarityCalculator,
            UnifiedThresholdManager unifiedThresholdManager,
            HCADBaselineLearningService hcadBaselineLearningService) {
        return new HCADAnalysisService(
            hcadContextExtractor, hcadBaselineCacheService, hcadSimilarityCalculator,
            unifiedThresholdManager, hcadBaselineLearningService
        );
    }

    /**
     * 6-2. HCADFeedbackOrchestrator - HCAD 피드백 오케스트레이터
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADFeedbackOrchestrator hcadFeedbackOrchestrator(
            HCADVectorIntegrationService hcadVectorIntegrationService,
            @Autowired(required = false) FeedbackLoopSystem feedbackLoopSystem,
            @Autowired(required = false) AdaptiveThresholdManager adaptiveThresholdManager,
            @Autowired(required = false) UnifiedThresholdManager unifiedThresholdManager,
            RedisTemplate<String, Object> redisTemplate) {
        return new HCADFeedbackOrchestrator(
            hcadVectorIntegrationService, feedbackLoopSystem,
            adaptiveThresholdManager, unifiedThresholdManager, redisTemplate
        );
    }

    // ========== Level 7: Level 6 의존 (1개) ==========

    /**
     * 7-1. HCADFilter - HCAD 필터 (조건부 등록, @Component 주석처리됨)
     */
    @Bean
    @ConditionalOnMissingBean
    public HCADFilter hcadFilter(
            HCADAnalysisService hcadAnalysisService,
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate,
            HCADAuthenticationService hcadAuthenticationService) {
        return new HCADFilter(hcadAnalysisService, redisTemplate, hcadAuthenticationService);
    }
}
