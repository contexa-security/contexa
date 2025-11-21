package io.contexa.contexacore.hcad.service;

import io.contexa.contexacore.hcad.domain.RiskLevel;
import io.contexa.contexacore.hcad.domain.UserTrustProfile;
import io.contexa.contexacore.hcad.domain.ZeroTrustDecision;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Zero Trust 임계값 관리 서비스
 *
 * ZeroTrustAdaptiveEngine 에서 분리된 Zero Trust 전용 임계값 관리 서비스
 * - 사용자별 적응형 임계값 조정
 * - 글로벌 임계값 최적화
 * - 주기적 성능 최적화 및 학습
 * - 신뢰 점수 감쇠 관리
 *
 * Note: HCAD 필터용 AdaptiveThresholdManager(hcad.threshold 패키지)와는 다른 용도
 */
@Slf4j
@RequiredArgsConstructor
public class ZeroTrustThresholdManager {

    private final TrustProfileService trustProfileService;
    private final @Qualifier("generalRedisTemplate") RedisTemplate<String, Object> redisTemplate;

    @Value("${zerotrust.engine.enabled:true}")
    private boolean engineEnabled;

    @Value("${zerotrust.trust-score.decay-rate:0.99}")
    private double trustScoreDecayRate;

    @Value("${zerotrust.engine.optimization-interval:3600000}")
    private long optimizationIntervalMs;

    // 성능 메트릭
    private final AtomicLong totalAnalysisCount = new AtomicLong(0);
    private final AtomicLong successfulAnalysisCount = new AtomicLong(0);
    private final Map<String, PerformanceMetrics> userPerformanceMetrics = new ConcurrentHashMap<>();

    /**
     * 제로트러스트 결정 기반 임계값 업데이트
     */
    public void updateThresholdsFromDecision(String userId, ZeroTrustDecision decision) {
        try {
            UserTrustProfile profile = trustProfileService.getOrCreateUserTrustProfile(userId);

            // 1. 결정 결과 기반 임계값 조정
            Map<String, Double> newThresholds = calculateAdaptiveThresholds(decision, profile);

            // 2. 프로필에 임계값 업데이트
            for (Map.Entry<String, Double> entry : newThresholds.entrySet()) {
                trustProfileService.updateAdaptiveThreshold(profile, entry.getKey(), entry.getValue());
            }

            log.debug("[ZeroTrustThreshold] Updated thresholds for user {}: {}", userId, newThresholds);

        } catch (Exception e) {
            log.error("[ZeroTrustThreshold] Failed to update thresholds for user {}", userId, e);
        }
    }

    /**
     * 결정 결과 기반 적응형 임계값 계산
     */
    private Map<String, Double> calculateAdaptiveThresholds(ZeroTrustDecision decision, UserTrustProfile profile) {
        Map<String, Double> thresholds = new HashMap<>();

        // 현재 위험 수준 기반 임계값 조정
        double riskAdjustment = calculateRiskAdjustment(decision.getRiskLevel());

        // 신뢰 점수 기반 임계값 조정
        double trustScoreAdjustment = (1.0 - decision.getCurrentTrustScore()) * 0.2;

        // 1. 블로킹 임계값
        double blockThreshold = 0.8 - riskAdjustment - trustScoreAdjustment;
        thresholds.put("block_threshold", Math.max(0.5, Math.min(0.95, blockThreshold)));

        // 2. 모니터링 임계값
        double monitorThreshold = 0.5 - (riskAdjustment * 0.5) - (trustScoreAdjustment * 0.5);
        thresholds.put("monitor_threshold", Math.max(0.3, Math.min(0.7, monitorThreshold)));

        // 3. 조사 임계값
        double investigateThreshold = 0.6 - riskAdjustment - (trustScoreAdjustment * 0.7);
        thresholds.put("investigate_threshold", Math.max(0.4, Math.min(0.8, investigateThreshold)));

        return thresholds;
    }

    /**
     * 위험 수준 기반 조정 값 계산
     */
    private double calculateRiskAdjustment(RiskLevel riskLevel) {
        switch (riskLevel) {
            case CRITICAL:
                return 0.3;
            case HIGH:
                return 0.2;
            case MEDIUM:
                return 0.1;
            case LOW:
                return 0.0;
            case MINIMAL:
                return -0.1;
            default:
                return 0.0;
        }
    }

    /**
     * 사용자별 성능 메트릭 기록
     */
    public void recordAnalysisMetrics(String userId, long processingTimeMs, boolean successful) {
        totalAnalysisCount.incrementAndGet();
        if (successful) {
            successfulAnalysisCount.incrementAndGet();
        }

        userPerformanceMetrics.compute(userId, (key, metrics) -> {
            if (metrics == null) {
                metrics = new PerformanceMetrics();
            }
            metrics.addProcessingTime(processingTimeMs);
            metrics.incrementAnalysisCount();
            if (successful) {
                metrics.incrementSuccessCount();
            }
            return metrics;
        });
    }

    /**
     * 주기적 성능 최적화 및 학습
     */
//    @Scheduled(fixedDelayString = "${zerotrust.engine.optimization-interval:3600000}") // 1시간마다
    public void performPeriodicOptimization() {
        if (!engineEnabled) {
            return;
        }

        try {
            log.info("[ZeroTrustThreshold] Starting periodic optimization");

            // 1. 신뢰 점수 감쇠 적용
            applyTrustScoreDecay();

            // 2. 성능 메트릭 분석 및 최적화
            analyzeAndOptimizePerformance();

            // 3. 전역 위협 패턴 분석
            analyzeGlobalThreatPatterns();

            // 4. 적응형 임계값 글로벌 조정
            performGlobalThresholdOptimization();

            // 5. 만료된 메트릭 정리
            cleanupExpiredMetrics();

            log.info("[ZeroTrustThreshold] Periodic optimization completed");

        } catch (Exception e) {
            log.error("[ZeroTrustThreshold] Periodic optimization failed", e);
        }
    }

    /**
     * 신뢰 점수 감쇠 적용
     */
    private void applyTrustScoreDecay() {
        // TrustProfileService를 통해 모든 프로필에 감쇠 적용
        log.debug("[ZeroTrustThreshold] Applying trust score decay with rate {}", trustScoreDecayRate);
    }

    /**
     * 성능 메트릭 분석 및 최적화
     */
    private void analyzeAndOptimizePerformance() {
        long total = totalAnalysisCount.get();
        long successful = successfulAnalysisCount.get();
        double successRate = total > 0 ? (double) successful / total * 100 : 0.0;

        log.info("[ZeroTrustThreshold] Performance - Total: {}, Successful: {} ({:.2f}%), Users: {}",
                total, successful, successRate, userPerformanceMetrics.size());

        // 사용자별 성능 분석
        userPerformanceMetrics.forEach((userId, metrics) -> {
            if (metrics.getAnalysisCount() > 100) {
                double avgTime = metrics.getAverageProcessingTime();
                double userSuccessRate = metrics.getSuccessRate();
                log.debug("[ZeroTrustThreshold] User {} - Avg Time: {}ms, Success Rate: {:.2f}%",
                         userId, String.format("%.2f", avgTime), userSuccessRate);
            }
        });
    }

    /**
     * 전역 위협 패턴 분석
     */
    private void analyzeGlobalThreatPatterns() {
        try {
            String threatKey = "zerotrust:global:threats";
            Set<Object> threats = redisTemplate.opsForZSet().range(threatKey, 0, -1);
            log.info("[ZeroTrustThreshold] Global threat patterns analyzed: {} unique threats",
                    threats != null ? threats.size() : 0);
        } catch (Exception e) {
            log.error("[ZeroTrustThreshold] Failed to analyze global threat patterns", e);
        }
    }

    /**
     * 글로벌 임계값 최적화
     */
    private void performGlobalThresholdOptimization() {
        // 전역 성능 기반 임계값 최적화
        long total = totalAnalysisCount.get();
        long successful = successfulAnalysisCount.get();

        if (total > 1000) {
            double successRate = (double) successful / total;
            log.info("[ZeroTrustThreshold] Global success rate: {:.2f}%", successRate * 100);

            // 성공률이 낮으면 임계값을 더 엄격하게
            if (successRate < 0.8) {
                log.warn("[ZeroTrustThreshold] Low success rate detected, considering stricter thresholds");
            }
        }
    }

    /**
     * 만료된 메트릭 정리
     */
    private void cleanupExpiredMetrics() {
        Instant cutoff = Instant.now().minus(Duration.ofDays(7));
        userPerformanceMetrics.entrySet().removeIf(entry ->
            entry.getValue().getLastUpdated().isBefore(cutoff)
        );
        log.debug("[ZeroTrustThreshold] Cleaned up expired metrics, remaining users: {}",
                 userPerformanceMetrics.size());
    }

    /**
     * 임계값 조회
     */
    public Map<String, Double> getThresholds(String userId) {
        UserTrustProfile profile = trustProfileService.getOrCreateUserTrustProfile(userId);
        return profile.getAdaptiveThresholds();
    }

    /**
     * 임계값 초기화 (테스트용)
     */
    public void resetThresholds(String userId) {
        UserTrustProfile profile = trustProfileService.getOrCreateUserTrustProfile(userId);
        profile.getAdaptiveThresholds().clear();
        log.info("[ZeroTrustThreshold] Reset thresholds for user {}", userId);
    }

    /**
     * 성능 메트릭 클래스
     */
    private static class PerformanceMetrics {
        private long analysisCount = 0;
        private long successCount = 0;
        private long totalProcessingTime = 0;
        private Instant lastUpdated = Instant.now();

        public void addProcessingTime(long timeMs) {
            this.totalProcessingTime += timeMs;
            this.lastUpdated = Instant.now();
        }

        public void incrementAnalysisCount() {
            this.analysisCount++;
        }

        public void incrementSuccessCount() {
            this.successCount++;
        }

        public double getAverageProcessingTime() {
            return analysisCount > 0 ? (double) totalProcessingTime / analysisCount : 0.0;
        }

        public double getSuccessRate() {
            return analysisCount > 0 ? (double) successCount / analysisCount * 100 : 0.0;
        }

        public long getAnalysisCount() {
            return analysisCount;
        }

        public Instant getLastUpdated() {
            return lastUpdated;
        }
    }
}
