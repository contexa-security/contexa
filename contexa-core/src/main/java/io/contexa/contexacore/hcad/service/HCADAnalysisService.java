package io.contexa.contexacore.hcad.service;

import io.contexa.contexacore.hcad.domain.BaselineVector;
import io.contexa.contexacore.hcad.domain.HCADAnalysisResult;
import io.contexa.contexacore.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.threshold.UnifiedThresholdManager;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

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
@RequiredArgsConstructor
public class HCADAnalysisService {

    private final HCADContextExtractor contextExtractor;
    private final HCADBaselineCacheService cacheService;
    private final HCADSimilarityCalculator similarityCalculator;
    private final UnifiedThresholdManager unifiedThresholdManager;
    private final HCADBaselineLearningService baselineLearningService;

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
            // ✅ 버그 수정: anomalyScore > threshold로 판정 (높을수록 이상)
            boolean isAnomaly = anomalyScore > currentThreshold;

            long processingTime = System.currentTimeMillis() - startTime;

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

        if (baselineLearningService.shouldUpdateBaseline(baseline, anomalyScore, similarityScore, context)) {
            baselineLearningService.updateBaseline(context, baseline, similarityScore);
            log.debug("[HCADAnalysisService] 기준선 업데이트: userId={}, similarity={}",
                result.getUserId(), String.format("%.3f", similarityScore));
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
