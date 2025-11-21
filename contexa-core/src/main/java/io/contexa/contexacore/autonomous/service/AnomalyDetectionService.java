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


import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * ?µê³„ ê¸°ë°˜ ?´ìƒ ?ì? ?œë¹„??
 *
 * BaselineVector??Z-score ê¸°ë°˜ ?µê³„???´ìƒ ?ì?ë¥?ì¤‘ì•™?ì„œ ê´€ë¦¬í•©?ˆë‹¤.
 * ?¸ì…˜ ?˜ì´?¬í‚¹ ??ê¸‰ê²©??ë³€?”ì? ?¼ë°˜ ?´ìƒ ?‰ë™??êµ¬ë¶„?˜ì—¬ ì²˜ë¦¬?©ë‹ˆ??
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j

@RequiredArgsConstructor
public class AnomalyDetectionService {

    private final RedisTemplate<String, Object> redisTemplate;
    private final HCADVectorIntegrationService hcadVectorIntegrationService;

    // Z-score ?„ê³„ê°?(3-?œê·¸ë§?ê·œì¹™)
    @Value("${security.anomaly.zscore.warning:2.0}")
    private double zscoreWarningThreshold;  // 2 ?œì??¸ì°¨ = ê²½ê³  ?˜ì?

    @Value("${security.anomaly.zscore.critical:3.0}")
    private double zscoreCriticalThreshold; // 3 ?œì??¸ì°¨ = ?„í—˜ ?˜ì?

    @Value("${security.anomaly.zscore.extreme:4.0}")
    private double zscoreExtremeThreshold;  // 4 ?œì??¸ì°¨ = ê·¹ë‹¨???´ìƒ

    // ê¸‰ê²©??ë³€??ê°ì? ?„ê³„ê°?
    @Value("${security.anomaly.rapid-change.threshold:0.4}")
    private double rapidChangeThreshold;    // Trust Score ê¸‰ê²©??ë³€??ê¸°ì?

    @Value("${security.anomaly.rapid-change.time-window:300}")
    private int rapidChangeTimeWindowSeconds; // ê¸‰ê²©??ë³€???œê°„ ?ˆë„??(5ë¶?

    // ?¸ì…˜ ?˜ì´?¬í‚¹ ?ì? ?„ê³„ê°?
    @Value("${security.anomaly.hijack.score-delta:0.3}")
    private double hijackScoreDeltaThreshold; // ?¸ì…˜ ?˜ì´?¬í‚¹ ?˜ì‹¬ ?ìˆ˜ ë³€??

    @Value("${security.anomaly.hijack.min-zscore:2.5}")
    private double hijackMinZScore;          // ?¸ì…˜ ?˜ì´?¬í‚¹ ìµœì†Œ Z-score

    /**
     * AI ë¶„ì„ ê²°ê³¼?€ ?µê³„ë¥?ê¸°ë°˜?¼ë¡œ ?´ìƒ ?ì? ?˜í–‰
     *
     * @param event ë³´ì•ˆ ?´ë²¤??
     * @param aiRiskScore AIê°€ ê³„ì‚°???„í—˜ ?ìˆ˜
     * @param processingResult ì²˜ë¦¬ ê²°ê³¼
     * @return ?´ìƒ ?ì? ê²°ê³¼
     */
    public AnomalyDetectionResult detectAnomaly(SecurityEvent event, double aiRiskScore, ProcessingResult processingResult) {
        String userId = event.getUserId();

        try {
            // 1. BaselineVector ì¡°íšŒ
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

            // 2. HCADContext ?ì„± (?„ì¬ ?´ë²¤??ê¸°ë°˜)
            HCADContext context = createHCADContext(event);

            // 3. ?´ìƒ ?ìˆ˜ ê³„ì‚°
            double anomalyScore = baseline.calculateAnomalyScore(context);

            // 4. Z-score ê³„ì‚° (?µê³„???´ìƒ ?ë‹¨)
            double zScore = baseline.calculateZScore(anomalyScore);

            // 5. ?´ì „ Trust Score ì¡°íšŒ (ê¸‰ê²©??ë³€??ê°ì???
            TrustScoreHistory history = getTrustScoreHistory(userId);

            // 6. ì¢…í•© ?´ìƒ ?ë‹¨
            AnomalyDetectionResult result = analyzeAnomaly(
                userId, aiRiskScore, anomalyScore, zScore, history, processingResult
            );

            // 7. ê²°ê³¼ ?€??(?µê³„ ?…ë°?´íŠ¸)
            if (result.isAnomaly()) {
                saveAnomalyDetection(userId, result);
            }

            // 8. BaselineVector ?µê³„ ?…ë°?´íŠ¸
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
     * ì¢…í•© ?´ìƒ ë¶„ì„
     *
     * AI ?„í—˜ ?ìˆ˜, ?µê³„??Z-score, ê¸‰ê²©??ë³€?”ë? ì¢…í•©?˜ì—¬ ?ë‹¨
     */
    private AnomalyDetectionResult analyzeAnomaly(
        String userId, double aiRiskScore, double anomalyScore,
        double zScore, TrustScoreHistory history, ProcessingResult processingResult) {

        // 1. AIê°€ ?ˆì „?˜ë‹¤ê³??ë‹¨??ê²½ìš° (Cold Path false positive ë°©ì?)
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

        // 2. ?¸ì…˜ ?˜ì´?¬í‚¹ ?˜ì‹¬ (ê¸‰ê²©??ë³€??+ ?’ì? Z-score)
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

        // 3. ê·¹ë‹¨???µê³„???´ìƒ (4 ?œì??¸ì°¨ ?´ìƒ)
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

        // 4. ?’ì? ?µê³„???´ìƒ (3 ?œì??¸ì°¨ ?´ìƒ)
        if (zScore >= zscoreCriticalThreshold) {
            // AI???„í—˜?˜ë‹¤ê³??ë‹¨??ê²½ìš°
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
                // ?µê³„?ìœ¼ë¡œëŠ” ?´ìƒ?´ì?ë§?AI??ë³´í†µ ?˜ì?
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

        // 5. ê²½ê³  ?˜ì? ?´ìƒ (2 ?œì??¸ì°¨ ?´ìƒ)
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

        // 6. ?•ìƒ ë²”ìœ„ (?´ìƒ ?†ìŒ)
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
     * BaselineVector ì¡°íšŒ
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
     * HCADContext ?ì„±
     */
    private HCADContext createHCADContext(SecurityEvent event) {
        return HCADContext.builder()
            .userId(event.getUserId())
            .timestamp(Instant.now()) // LocalDateTime??Instantë¡?ë³€???„ìš”
            // eventType ?„ë“œê°€ HCADContext???†ìœ¼ë¯€ë¡??œê±°
            .remoteIp(event.getSourceIp()) // getIpAddress() -> getSourceIp()
            .userAgent(event.getUserAgent())
            // requestPath?€ currentTrustScore ?„ë“œê°€ HCADContext???•ì˜?˜ì–´ ?ˆìŒ
            .requestPath("/unknown") // SecurityEvent??requestPathê°€ ?†ìœ¼ë¯€ë¡?ê¸°ë³¸ê°??¬ìš©
            .currentTrustScore(event.getConfidenceScore() != null ? event.getConfidenceScore() : 0.5)
            .build();
    }

    /**
     * Trust Score ?´ë ¥ ì¡°íšŒ
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
     * ?´ìƒ ?ì? ê²°ê³¼ ?€??
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

            // TTL ?¤ì • (?¬ê°?„ì— ?°ë¼ ?¤ë¥´ê²?
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
     * BaselineVector ?µê³„ ?…ë°?´íŠ¸
     */
    private void updateBaselineStatistics(BaselineVector baseline, double anomalyScore) {
        // ?´ë™ ?‰ê·  ë°©ì‹?¼ë¡œ ?µê³„ ?…ë°?´íŠ¸
        double alpha = 0.1; // ?™ìŠµë¥?

        if (baseline.getAnomalyScoreMean() != null) {
            baseline.setAnomalyScoreMean(
                alpha * anomalyScore + (1 - alpha) * baseline.getAnomalyScoreMean()
            );
        } else {
            baseline.setAnomalyScoreMean(anomalyScore);
        }

        // ?œì??¸ì°¨ ?…ë°?´íŠ¸ (ê°„ë‹¨??ê·¼ì‚¬)
        if (baseline.getAnomalyScoreStdDev() != null) {
            double variance = Math.pow(anomalyScore - baseline.getAnomalyScoreMean(), 2);
            baseline.setAnomalyScoreStdDev(
                Math.sqrt(alpha * variance + (1 - alpha) * Math.pow(baseline.getAnomalyScoreStdDev(), 2))
            );
        } else {
            baseline.setAnomalyScoreStdDev(0.1); // ì´ˆê¸°ê°?
        }

        // Redis???€??
        try {
            String key = ZeroTrustRedisKeys.baselineVector(baseline.getUserId());
            redisTemplate.opsForValue().set(key, baseline, Duration.ofHours(24));
        } catch (Exception e) {
            log.error("[AnomalyDetectionService] Failed to update baseline statistics", e);
        }
    }

    /**
     * ?´ìƒ ?ì? ê²°ê³¼
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
        private Double scoreDelta;  // Trust Score ë³€?”ëŸ‰
        private String reason;
        private String recommendedAction;
    }

    /**
     * ?´ìƒ ? í˜•
     */
    public enum AnomalyType {
        NONE,                   // ?´ìƒ ?†ìŒ
        SUSPICIOUS_ACTIVITY,    // ?˜ì‹¬?¤ëŸ¬???œë™
        STATISTICAL_ANOMALY,    // ?µê³„???´ìƒ
        HIGH_RISK_ACTIVITY,     // ê³ ìœ„???œë™
        SESSION_HIJACKING,      // ?¸ì…˜ ?˜ì´?¬í‚¹ ?˜ì‹¬
        EXTREME_DEVIATION      // ê·¹ë‹¨???¸ì°¨
    }

    /**
     * ?´ìƒ ?¬ê°??
     */
    public enum AnomalySeverity {
        NONE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /**
     * Trust Score ?´ë ¥ (?´ë? ?´ë˜??
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
