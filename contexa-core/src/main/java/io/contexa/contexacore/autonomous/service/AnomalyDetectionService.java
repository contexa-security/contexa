package io.contexa.contexacore.autonomous.service;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.service.HCADVectorIntegrationService;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * 통계 기반 이상 탐지 서비스
 *
 * BaselineVector의 Z-score 기반 통계적 이상 탐지를 중앙에서 관리합니다.
 * 세션 하이재킹 등 급격한 변화와 일반 이상 행동을 구분하여 처리합니다.
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
@RequiredArgsConstructor
public class AnomalyDetectionService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final HCADVectorIntegrationService hcadVectorIntegrationService;

    // Z-score 임계값 (3-시그마 규칙)
    @Value("${security.anomaly.zscore.warning:2.0}")
    private double zscoreWarningThreshold;  // 2 표준편차 = 경고 수준

    @Value("${security.anomaly.zscore.critical:3.0}")
    private double zscoreCriticalThreshold; // 3 표준편차 = 위험 수준

    @Value("${security.anomaly.zscore.extreme:4.0}")
    private double zscoreExtremeThreshold;  // 4 표준편차 = 극단적 이상

    // 급격한 변화 감지 임계값
    @Value("${security.anomaly.rapid-change.threshold:0.4}")
    private double rapidChangeThreshold;    // Trust Score 급격한 변화 기준

    @Value("${security.anomaly.rapid-change.time-window:300}")
    private int rapidChangeTimeWindowSeconds; // 급격한 변화 시간 윈도우 (5분)

    // 세션 하이재킹 탐지 임계값
    @Value("${security.anomaly.hijack.score-delta:0.3}")
    private double hijackScoreDeltaThreshold; // 세션 하이재킹 의심 점수 변화

    @Value("${security.anomaly.hijack.min-zscore:2.5}")
    private double hijackMinZScore;          // 세션 하이재킹 최소 Z-score

    /**
     * AI 분석 결과와 통계를 기반으로 이상 탐지 수행
     *
     * @param event 보안 이벤트
     * @param aiRiskScore AI가 계산한 위험 점수
     * @param processingResult 처리 결과
     * @return 이상 탐지 결과
     */
    public AnomalyDetectionResult detectAnomaly(SecurityEvent event, double aiRiskScore, ProcessingResult processingResult) {
        String userId = event.getUserId();

        try {
            // 1. BaselineVector 조회
            BaselineVector baseline = getBaselineVector(userId);
            if (baseline == null) {
                log.info("[AnomalyDetectionService] No baseline for user {}, creating initial baseline", userId);
                return AnomalyDetectionResult.builder()
                        .isAnomaly(false)
                        .anomalyType(AnomalyType.NONE)
                        .zScore(0.0)
                        .confidence(0.0)
                        .reason("Initial baseline creation")
                        .build();
            }

            // 2. HCADContext 생성 (현재 이벤트 기반)
            HCADContext context = createHCADContext(event);

            // 3. 이상 점수 계산
            double anomalyScore = baseline.calculateAnomalyScore(context);

            // 4. Z-score 계산 (통계적 이상 판단)
            double zScore = baseline.calculateZScore(anomalyScore);

            // 5. 이전 Trust Score 조회 (급격한 변화 감지용)
            TrustScoreHistory history = getTrustScoreHistory(userId);

            // 6. 종합 이상 판단
            AnomalyDetectionResult result = analyzeAnomaly(
                    userId, aiRiskScore, anomalyScore, zScore, history, processingResult
            );

            // 7. 결과 저장 (통계 업데이트)
            if (result.isAnomaly()) {
                saveAnomalyDetection(userId, result);
            }

            // 8. BaselineVector 통계 업데이트
            updateBaselineStatistics(baseline, anomalyScore);

            log.info("[AnomalyDetectionService] Anomaly detection for user {} - zScore: {}, type: {}, isAnomaly: {}",
                    userId, String.format("%.3f", zScore), result.getAnomalyType(), result.isAnomaly());

            return result;

        } catch (Exception e) {
            log.error("[AnomalyDetectionService] Error detecting anomaly for user: {}", userId, e);
            return AnomalyDetectionResult.builder()
                    .isAnomaly(false)
                    .anomalyType(AnomalyType.NONE)
                    .zScore(0.0)
                    .confidence(0.0)
                    .reason("Error in anomaly detection")
                    .build();
        }
    }

    /**
     * 종합 이상 분석
     *
     * AI 위험 점수, 통계적 Z-score, 급격한 변화를 종합하여 판단
     */
    private AnomalyDetectionResult analyzeAnomaly(
            String userId, double aiRiskScore, double anomalyScore,
            double zScore, TrustScoreHistory history, ProcessingResult processingResult) {

        // 1. AI가 안전하다고 판단한 경우 (Cold Path false positive 방지)
        if (aiRiskScore < 0.3 && zScore < zscoreWarningThreshold) {
            return AnomalyDetectionResult.builder()
                    .isAnomaly(false)
                    .anomalyType(AnomalyType.NONE)
                    .zScore(zScore)
                    .confidence(0.9)
                    .aiRiskScore(aiRiskScore)
                    .reason("AI and statistics both indicate normal behavior")
                    .build();
        }

        // 2. 세션 하이재킹 의심 (급격한 변화 + 높은 Z-score)
        if (history != null && history.hasRapidChange(rapidChangeThreshold, rapidChangeTimeWindowSeconds)) {
            if (zScore >= hijackMinZScore && aiRiskScore >= 0.6) {
                return AnomalyDetectionResult.builder()
                        .isAnomaly(true)
                        .anomalyType(AnomalyType.SESSION_HIJACKING)
                        .severity(AnomalySeverity.CRITICAL)
                        .zScore(zScore)
                        .confidence(0.95)
                        .aiRiskScore(aiRiskScore)
                        .scoreDelta(history.getScoreDelta())
                        .reason("Session hijacking suspected - rapid change in behavior pattern")
                        .recommendedAction("Require MFA immediately")
                        .build();
            }
        }

        // 3. 극단적 통계적 이상 (4 표준편차 이상)
        if (zScore >= zscoreExtremeThreshold) {
            return AnomalyDetectionResult.builder()
                    .isAnomaly(true)
                    .anomalyType(AnomalyType.EXTREME_DEVIATION)
                    .severity(AnomalySeverity.CRITICAL)
                    .zScore(zScore)
                    .confidence(0.99)
                    .aiRiskScore(aiRiskScore)
                    .reason("Extreme statistical deviation detected")
                    .recommendedAction("Block access and alert security team")
                    .build();
        }

        // 4. 높은 통계적 이상 (3 표준편차 이상)
        if (zScore >= zscoreCriticalThreshold) {
            // AI도 위험하다고 판단한 경우
            if (aiRiskScore >= 0.7) {
                return AnomalyDetectionResult.builder()
                        .isAnomaly(true)
                        .anomalyType(AnomalyType.HIGH_RISK_ACTIVITY)
                        .severity(AnomalySeverity.HIGH)
                        .zScore(zScore)
                        .confidence(0.9)
                        .aiRiskScore(aiRiskScore)
                        .reason("Both AI and statistics indicate high risk")
                        .recommendedAction("Require additional authentication")
                        .build();
            } else {
                // 통계적으로는 이상이지만 AI는 보통 수준
                return AnomalyDetectionResult.builder()
                        .isAnomaly(true)
                        .anomalyType(AnomalyType.STATISTICAL_ANOMALY)
                        .severity(AnomalySeverity.MEDIUM)
                        .zScore(zScore)
                        .confidence(0.7)
                        .aiRiskScore(aiRiskScore)
                        .reason("Statistical anomaly detected, monitoring required")
                        .recommendedAction("Enhanced monitoring")
                        .build();
            }
        }

        // 5. 경고 수준 이상 (2 표준편차 이상)
        if (zScore >= zscoreWarningThreshold) {
            if (aiRiskScore >= 0.5) {
                return AnomalyDetectionResult.builder()
                        .isAnomaly(true)
                        .anomalyType(AnomalyType.SUSPICIOUS_ACTIVITY)
                        .severity(AnomalySeverity.MEDIUM)
                        .zScore(zScore)
                        .confidence(0.6)
                        .aiRiskScore(aiRiskScore)
                        .reason("Suspicious activity detected")
                        .recommendedAction("Monitor closely")
                        .build();
            }
        }

        // 6. 정상 범위 (이상 없음)
        return AnomalyDetectionResult.builder()
                .isAnomaly(false)
                .anomalyType(AnomalyType.NONE)
                .severity(AnomalySeverity.NONE)
                .zScore(zScore)
                .confidence(0.8)
                .aiRiskScore(aiRiskScore)
                .reason("Within normal behavior range")
                .build();
    }

    /**
     * BaselineVector 조회
     */
    private BaselineVector getBaselineVector(String userId) {
        try {
            String key = ZeroTrustRedisKeys.baselineVector(userId);
            return (BaselineVector) redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            log.error("[AnomalyDetectionService] Failed to get baseline vector for user: {}", userId, e);
            return null;
        }
    }

    /**
     * HCADContext 생성
     */
    private HCADContext createHCADContext(SecurityEvent event) {
        return HCADContext.builder()
                .userId(event.getUserId())
                .timestamp(Instant.now()) // LocalDateTime을 Instant로 변환 필요
                // eventType 필드가 HCADContext에 없으므로 제거
                .remoteIp(event.getSourceIp()) // getIpAddress() -> getSourceIp()
                .userAgent(event.getUserAgent())
                // requestPath와 currentTrustScore 필드가 HCADContext에 정의되어 있음
                .requestPath("/unknown") // SecurityEvent에 requestPath가 없으므로 기본값 사용
                // AI Native: deprecated getConfidenceScore() 제거, metadata에서 추출 또는 기본값
                .currentTrustScore(extractTrustScoreFromMetadata(event))
                .build();
    }

    /**
     * Trust Score 이력 조회
     */
    private TrustScoreHistory getTrustScoreHistory(String userId) {
        try {
            String key = ZeroTrustRedisKeys.trustScoreHistory(userId);
            return (TrustScoreHistory) redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            log.error("[AnomalyDetectionService] Failed to get trust score history for user: {}", userId, e);
            return null;
        }
    }

    /**
     * 이상 탐지 결과 저장
     */
    private void saveAnomalyDetection(String userId, AnomalyDetectionResult result) {
        try {
            String key = ZeroTrustRedisKeys.anomalyDetected(userId);
            Map<String, Object> anomalyData = new HashMap<>();
            anomalyData.put("userId", userId);
            anomalyData.put("anomalyType", result.getAnomalyType());
            anomalyData.put("severity", result.getSeverity());
            anomalyData.put("zScore", result.getZScore());
            anomalyData.put("aiRiskScore", result.getAiRiskScore());
            anomalyData.put("reason", result.getReason());
            anomalyData.put("detectedAt", LocalDateTime.now());

            // TTL 설정 (심각도에 따라 다르게)
            int ttlMinutes = switch (result.getSeverity()) {
                case CRITICAL -> 30;
                case HIGH -> 20;
                case MEDIUM -> 10;
                default -> 5;
            };

            redisTemplate.opsForValue().set(key, anomalyData, Duration.ofMinutes(ttlMinutes));

        } catch (Exception e) {
            log.error("[AnomalyDetectionService] Failed to save anomaly detection for user: {}", userId, e);
        }
    }

    /**
     * AI Native: metadata에서 trustScore 추출
     * deprecated getConfidenceScore() 대체
     */
    private double extractTrustScoreFromMetadata(SecurityEvent event) {
        if (event.getMetadata() != null) {
            // auth.trustScore 또는 authz.trustScore에서 추출
            Object trustScore = event.getMetadata().get("auth.trustScore");
            if (trustScore == null) {
                trustScore = event.getMetadata().get("authz.trustScore");
            }
            if (trustScore instanceof Number) {
                return ((Number) trustScore).doubleValue();
            }
        }
        return 0.5; // 기본값
    }

    /**
     * BaselineVector 통계 업데이트
     */
    private void updateBaselineStatistics(BaselineVector baseline, double anomalyScore) {
        // 이동 평균 방식으로 통계 업데이트
        double alpha = 0.1; // 학습률

        if (baseline.getAnomalyScoreMean() != null) {
            baseline.setAnomalyScoreMean(
                    alpha * anomalyScore + (1 - alpha) * baseline.getAnomalyScoreMean()
            );
        } else {
            baseline.setAnomalyScoreMean(anomalyScore);
        }

        // 표준편차 업데이트 (간단한 근사)
        if (baseline.getAnomalyScoreStdDev() != null) {
            double variance = Math.pow(anomalyScore - baseline.getAnomalyScoreMean(), 2);
            baseline.setAnomalyScoreStdDev(
                    Math.sqrt(alpha * variance + (1 - alpha) * Math.pow(baseline.getAnomalyScoreStdDev(), 2))
            );
        } else {
            baseline.setAnomalyScoreStdDev(0.1); // 초기값
        }

        // Redis에 저장
        try {
            String key = ZeroTrustRedisKeys.baselineVector(baseline.getUserId());
            redisTemplate.opsForValue().set(key, baseline, Duration.ofHours(24));
        } catch (Exception e) {
            log.error("[AnomalyDetectionService] Failed to update baseline statistics", e);
        }
    }

    /**
     * 이상 탐지 결과
     */
    @Data
    @Builder
    public static class AnomalyDetectionResult {
        private boolean isAnomaly;
        private AnomalyType anomalyType;
        private AnomalySeverity severity;
        private double zScore;
        private double confidence;
        private double aiRiskScore;
        private Double scoreDelta;  // Trust Score 변화량
        private String reason;
        private String recommendedAction;
    }

    /**
     * 이상 유형
     */
    public enum AnomalyType {
        NONE,                   // 이상 없음
        SUSPICIOUS_ACTIVITY,    // 의심스러운 활동
        STATISTICAL_ANOMALY,    // 통계적 이상
        HIGH_RISK_ACTIVITY,     // 고위험 활동
        SESSION_HIJACKING,      // 세션 하이재킹 의심
        EXTREME_DEVIATION      // 극단적 편차
    }

    /**
     * 이상 심각도
     */
    public enum AnomalySeverity {
        NONE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /**
     * Trust Score 이력 (내부 클래스)
     */
    @Data
    @Builder
    private static class TrustScoreHistory {
        private String userId;
        private Double previousScore;
        private Double currentScore;
        private LocalDateTime previousUpdateTime;
        private LocalDateTime currentUpdateTime;

        public boolean hasRapidChange(double threshold, int timeWindowSeconds) {
            if (previousScore == null || currentScore == null) {
                return false;
            }

            double scoreDelta = Math.abs(currentScore - previousScore);

            if (previousUpdateTime != null && currentUpdateTime != null) {
                long secondsBetween = Duration.between(previousUpdateTime, currentUpdateTime).getSeconds();
                return scoreDelta >= threshold && secondsBetween <= timeWindowSeconds;
            }

            return scoreDelta >= threshold;
        }

        public double getScoreDelta() {
            if (previousScore == null || currentScore == null) {
                return 0.0;
            }
            return Math.abs(currentScore - previousScore);
        }
    }
}