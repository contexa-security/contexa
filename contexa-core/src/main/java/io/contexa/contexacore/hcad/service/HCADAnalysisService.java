package io.contexa.contexacore.hcad.service;

// import io.contexa.contexacoreenterprise.dashboard.metrics.evolution.EvolutionMetricsCollector;
// import io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust.HCADFeedbackLoopMetrics;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.threshold.UnifiedThresholdManager;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * HCAD 분석 서비스
 *
 * HCADFilter의 핵심 로직을 추출한 서비스 (Single Source of Truth)
 *
 * 사용처:
 * 1. HCADFilter: 모든 일반 요청 분석 (인증 전 상태)
 * 2. MySecurityConfig 로그인 핸들러: 로그인 시 인증된 사용자로 재계산
 *
 * 설계 목적:
 * - Single Source of Truth: 유사도 계산 로직의 중앙 집중화
 * - DRY 원칙: 코드 중복 제거
 * - Separation of Concerns: 필터는 라우팅, 서비스는 비즈니스 로직
 * - 정확한 userId 매칭: 로그인 시 인증된 사용자로 재계산하여 익명/인증 불일치 해결
 *
 * 성능 목표: 1-5ms (컨텍스트 추출) + 1ms (BaselineVector 조회) + 1-2ms (유사도 계산) = 5-30ms
 *
 * @author contexa
 * @since 3.0.0
 */
@Slf4j
@Service
public class HCADAnalysisService {

    private final HCADContextExtractor contextExtractor;
    private final HCADBaselineCacheService cacheService;
    private final HCADSimilarityCalculator similarityCalculator;
    private final UnifiedThresholdManager unifiedThresholdManager;
    private final HCADBaselineLearningService baselineLearningService;
    // private final Object feedbackMetrics;
    // private final Object evolutionMetricsCollector;

    public HCADAnalysisService(
            HCADContextExtractor contextExtractor,
            HCADBaselineCacheService cacheService,
            HCADSimilarityCalculator similarityCalculator,
            UnifiedThresholdManager unifiedThresholdManager,
            HCADBaselineLearningService baselineLearningService
            // Enterprise metrics - optional
            // @Autowired(required = false) Object feedbackMetrics,
            // @Autowired(required = false) Object evolutionMetricsCollector
    ) {
        this.contextExtractor = contextExtractor;
        this.cacheService = cacheService;
        this.similarityCalculator = similarityCalculator;
        this.unifiedThresholdManager = unifiedThresholdManager;
        this.baselineLearningService = baselineLearningService;
        // this.feedbackMetrics = feedbackMetrics;
        // this.evolutionMetricsCollector = evolutionMetricsCollector;
    }

    /**
     * HCAD 분석 수행
     *
     * HCADFilter와 로그인 핸들러 모두에서 사용
     *
     * 처리 흐름:
     * 1. 컨텍스트 추출 (userId, IP, UserAgent 등)
     * 2. Redis에서 BaselineVector 조회 (사용자별 정상 행동 패턴)
     * 3. RAG 강화 유사도 계산 (다층 신뢰성 검증)
     * 4. 통합 임계값 조회 및 이상 여부 판단
     * 5. HCADAnalysisResult 반환
     *
     * @param request HTTP 요청
     * @param authentication 인증 정보 (인증 전: anonymousUser, 인증 후: 실제 사용자)
     * @return HCAD 분석 결과
     */
    public HCADAnalysisResult analyze(HttpServletRequest request, Authentication authentication) {
        long startTime = System.currentTimeMillis();

        try {
            // 1. 컨텍스트 추출 (1-5ms)
            // HCADContextExtractor가 Authentication 에서 userId를 추출
            // - 인증 전: "anonymous:{IP}"
            // - 인증 후: 실제 username (예: "admin")
            HCADContext context = contextExtractor.extractContext(request, authentication);
            String userId = context.getUserId();

            if (log.isDebugEnabled()) {
                log.debug("[HCADAnalysisService] 컨텍스트 추출 완료: userId={}, path={}, ip={}",
                    userId, context.getRequestPath(), context.getRemoteIp());
            }

            // 2. Redis 에서 기준선 벡터 조회 (1ms)
            // 사용자별 정상 행동 패턴 (384차원 벡터)
            BaselineVector baseline = cacheService.getBaseline(userId);

            // 3. RAG 강화 다층 신뢰성 검증
            // - HCAD 유사도 계산 (현재 요청 vs BaselineVector)
            // - Cold Path AI 진단 결과는 Redis를 통해 비동기로 피드백됨
            // - TrustScore, ThreatType, ThreatEvidence 포함
            HCADSimilarityCalculator.TrustedSimilarityResult finalResult =
                similarityCalculator.calculateRAGEnhancedSimilarity(context, baseline);

            double similarityScore = finalResult.getFinalSimilarity();
            double anomalyScore = 1.0 - similarityScore;

            // 4. 통합 임계값 조회
            // 사용자별 동적 임계값 (정상 사용자는 낮게, 의심 사용자는 높게)
            double currentThreshold = unifiedThresholdManager.getThreshold(userId, context);
            // 버그 수정: anomalyScore > threshold로 판정 (높을수록 이상)
            boolean isAnomaly = anomalyScore > currentThreshold;

            long processingTime = System.currentTimeMillis() - startTime;

            // ===== 메트릭 수집 =====
            // if (feedbackMetrics != null) {
                // 나노초로 변환 (더 정확한 측정)
                // long durationNanos = processingTime * 1_000_000;
                // feedbackMetrics.recordAnalysis(durationNanos, similarityScore, isAnomaly);

                // EventRecorder 인터페이스 호출
                // Map<String, Object> eventMetadata = new HashMap<>();
                // eventMetadata.put("user_id", userId);
                // eventMetadata.put("similarity_score", similarityScore);
                // eventMetadata.put("anomaly_score", anomalyScore);
                // eventMetadata.put("is_anomaly", isAnomaly);
                // eventMetadata.put("duration_nanos", durationNanos);
                // feedbackMetrics.recordEvent("hcad_analysis", eventMetadata);
            // }

            // 📊 Prometheus 메트릭 수집 (Micrometer)
            // if (evolutionMetricsCollector != null) {
                // evolutionMetricsCollector.recordHCADAnalysis(processingTime, anomalyScore, isAnomaly);
            // }

            if (log.isDebugEnabled()) {
                log.debug("[HCADAnalysisService] 분석 완료: userId={}, similarity={}, anomaly={}, threshold={}, time={}ms",
                    userId,
                    String.format("%.3f", similarityScore),
                    String.format("%.3f", anomalyScore),
                    String.format("%.3f", currentThreshold),
                    processingTime);
            }

            // 5. 결과 반환
            return HCADAnalysisResult.builder()
                .userId(userId)
                .similarityScore(similarityScore)
                .trustScore(finalResult.getTrustScore())
                .threatType(finalResult.getThreatType())
                .threatEvidence(finalResult.getThreatEvidence())
                .isAnomaly(isAnomaly)
                .anomalyScore(anomalyScore)
                .threshold(currentThreshold)
                .processingTimeMs(processingTime)
                .context(context)
                .baseline(baseline)
                .build();

        } catch (Exception e) {
            log.error("[HCADAnalysisService] 분석 실패: request={}", request.getRequestURI(), e);

            // Fail-Safe: 에러 발생 시 기본값 반환
            // 보안상 안전한 쪽으로 실패 (isAnomaly=true)
            return HCADAnalysisResult.builder()
                .userId("error")
                .similarityScore(0.0)
                .trustScore(0.0)
                .threatType("ANALYSIS_ERROR")
                .threatEvidence(e.getMessage())
                .isAnomaly(true)
                .anomalyScore(1.0)
                .threshold(0.5)
                .processingTimeMs(System.currentTimeMillis() - startTime)
                .build();
        }
    }

    /**
     * 기준선 업데이트 수행
     *
     * HCADFilter와 로그인 핸들러 모두에서 사용
     *
     * @param result HCAD 분석 결과
     */
    public void updateBaselineIfNeeded(HCADAnalysisResult result) {
        if (result.getBaseline() == null || result.getContext() == null) {
            return;
        }

        double anomalyScore = result.getAnomalyScore();
        double similarityScore = result.getSimilarityScore();
        BaselineVector baseline = result.getBaseline();
        HCADContext context = result.getContext();

        // 학습 단계 판단
        String phase = baselineLearningService.isInBootstrapPhase(baseline) ? "bootstrap" :
                      (baseline.getConfidence() < 0.7 ? "building" : "mature");

        if (baselineLearningService.shouldUpdateBaseline(baseline, anomalyScore, similarityScore, context)) {
            long startTime = System.nanoTime();

            baselineLearningService.updateBaseline(context, baseline, similarityScore);

            long duration = System.nanoTime() - startTime;

            // ===== 메트릭 수집 =====
            // if (feedbackMetrics != null) {
                // feedbackMetrics.recordBaselineUpdate();
                // feedbackMetrics.recordFeedbackProcessing(duration);
            // }

            // 📊 Prometheus 메트릭 수집 (학습 결정)
            // if (evolutionMetricsCollector != null) {
                // evolutionMetricsCollector.recordHCADLearningDecision(
                    // result.getUserId(),
                    // phase,
                    // "updated",
                    // baseline.getConfidence()
                // );
            // }

            log.debug("[HCADAnalysisService] 기준선 업데이트: userId={}, similarity={}",
                result.getUserId(), String.format("%.3f", similarityScore));
        } else {
            // 📊 학습 건너뜀 사유 기록
            // if (evolutionMetricsCollector != null) {
                // 건너뜀 사유 판단 - 통계적 이상치 여부만 확인 가능
                // String decision;
                // if (baselineLearningService.isStatisticalOutlier(anomalyScore, baseline)) {
                    // decision = "skipped_outlier";
                // } else {
                    // 의심스러운 컨텍스트이거나 임계값 미달
                    // decision = "skipped";
                // }

                // evolutionMetricsCollector.recordHCADLearningDecision(
                    // result.getUserId(),
                    // phase,
                    // decision,
                    // baseline.getConfidence()
                // );
            // }
        }
    }

    /**
     * 통계 업데이트 수행 (극도로 제한적)
     *
     * HCADFilter 에서 사용
     *
     * @param result HCAD 분석 결과
     */
    public void updateStatisticsIfNeeded(HCADAnalysisResult result) {
        if (result.getBaseline() == null) {
            return;
        }

        BaselineVector baseline = result.getBaseline();
        double anomalyScore = result.getAnomalyScore();

        if (baselineLearningService.shouldUpdateStatistics(baseline, anomalyScore)) {
            baseline.updateAnomalyStatistics(anomalyScore);
        }
    }
}
