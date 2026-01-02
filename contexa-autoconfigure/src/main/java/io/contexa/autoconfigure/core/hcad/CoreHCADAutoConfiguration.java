package io.contexa.autoconfigure.core.hcad;

import io.contexa.autoconfigure.properties.ContexaProperties;
import io.contexa.contexacore.properties.HcadProperties;
// AI Native v4.0: Dead Code 제거
// - EmbeddingService, HCADVectorIntegrationService 삭제
// - BehaviorVectorService import 제거 (미사용)
import io.contexa.contexacore.hcad.filter.HCADFilter;
import io.contexa.contexacore.hcad.service.HCADAnalysisService;
import io.contexa.contexacore.hcad.service.HCADContextExtractor;
import io.contexa.contexacore.hcad.service.BaselineLearningService;
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
// AI Native v4.0: FeedbackIntegrationProperties 제거 (미사용)
@EnableConfigurationProperties({ContexaProperties.class, HcadProperties.class})
public class CoreHCADAutoConfiguration {

    public CoreHCADAutoConfiguration() {
        // @Bean 방식으로 HCAD 서비스 등록
    }

    // ========== Level 1: 독립적 서비스 ==========

    // AI Native v4.0: EmbeddingService 제거
    // - LLM 분석은 텍스트 컨텍스트 기반 (임베딩 불필요)
    // - Hot Path의 규칙 기반 유사도 비교 제거

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

    /**
     * BaselineLearningService - 정상 패턴 학습 서비스
     *
     * AI Native: LLM이 ALLOW 판정한 요청만 학습
     * EMA 기반 점진적 기준선 업데이트
     *
     * Zero Trust 필수 데이터:
     * - normalIpRanges: 정상 IP 대역
     * - normalAccessHours: 정상 접근 시간대
     * - frequentPaths: 자주 접근하는 경로
     */
    @Bean
    @ConditionalOnMissingBean
    public BaselineLearningService baselineLearningService(
            @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
        return new BaselineLearningService(redisTemplate);
    }

    // ========== Level 3: Level 2 의존 ==========

    // AI Native v4.0: HCADVectorIntegrationService 제거
    // - 임베딩 기반 유사도 비교는 LLM 분석에서 사용되지 않음
    // - Cold Path ↔ Hot Path 동기화 불필요 (LLM이 직접 Redis에 저장)

    // ========== Level 4: HCADAnalysisService ==========

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
