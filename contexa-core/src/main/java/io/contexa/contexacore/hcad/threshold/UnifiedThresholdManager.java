package io.contexa.contexacore.hcad.threshold;

import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.constants.HCADRedisKeys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * 통합 임계값 관리자 (단일 진실 공급원)
 *
 * AdaptiveThresholdManager와 FeedbackLoopSystem의 임계값을 통합 관리하여
 * 충돌을 방지하고 일관성 있는 임계값을 제공합니다.
 *
 * 통합 임계값 = 적응형 임계값 + 피드백 조정값
 *
 * 핵심 기능:
 * 1. 적응형 임계값과 피드백 기반 조정값 통합
 * 2. Redis 키 충돌 방지 및 레거시 키 정리
 * 3. 임계값 캐싱 및 빠른 조회
 * 4. 임계값 변경 이벤트 발행
 * 5. FeedbackLoopSystem과 AdaptiveThresholdManager 간 중재
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@Service
public class UnifiedThresholdManager {

    private final AdaptiveThresholdManager adaptiveManager;
    private final RedisTemplate<String, Object> redisTemplate;
    // Enterprise metrics - optional
    // private Object feedbackMetrics;

    @Autowired
    public UnifiedThresholdManager(
        AdaptiveThresholdManager adaptiveManager,
        RedisTemplate<String, Object> redisTemplate) {
        this.adaptiveManager = adaptiveManager;
        this.redisTemplate = redisTemplate;
    }

    // public void setFeedbackMetrics(Object feedbackMetrics) {
        // this.feedbackMetrics = feedbackMetrics;
    // }

    // 기본 임계값 (폴백용)
    private static final double DEFAULT_THRESHOLD = 0.6;

    // 임계값 범위
    private static final double MIN_THRESHOLD = 0.3;
    private static final double MAX_THRESHOLD = 0.95;

    /**
     * 통합 임계값 조회
     *
     * 1. Redis 캐시에서 통합 임계값 조회
     * 2. 캐시 미스 시 계산 후 캐싱
     * 3. 적응형 임계값 + 피드백 조정값 통합
     *
     * @param userId 사용자 ID
     * @param context HCAD 컨텍스트
     * @return 최종 통합 임계값 (0.3 ~ 0.95)
     */
    public double getThreshold(String userId, HCADContext context) {
        try {
            // 1. 캐시 조회
            String cacheKey = HCADRedisKeys.unifiedThreshold(userId);
            Double cachedThreshold = (Double) redisTemplate.opsForValue().get(cacheKey);

            if (cachedThreshold != null) {
                return cachedThreshold;
            }

            // 2. 통합 임계값 계산
            double unifiedThreshold = calculateUnifiedThreshold(userId, context);

            // 3. 캐싱 (1시간 TTL)
            redisTemplate.opsForValue().set(
                cacheKey,
                unifiedThreshold,
                Duration.ofHours(HCADRedisKeys.TTL_THRESHOLD_UNIFIED_HOURS)
            );

            log.debug("Unified threshold calculated for user {}: {}", userId, unifiedThreshold);
            return unifiedThreshold;

        } catch (Exception e) {
            log.error("Failed to get unified threshold for user: {}", userId, e);
            return DEFAULT_THRESHOLD;
        }
    }

    /**
     * 통합 임계값 계산
     *
     * 적응형 임계값과 피드백 조정값을 통합합니다.
     *
     * @param userId 사용자 ID
     * @param context HCAD 컨텍스트
     * @return 계산된 통합 임계값
     */
    private double calculateUnifiedThreshold(String userId, HCADContext context) {
        // 1. 적응형 임계값 조회
        double adaptiveThreshold = getAdaptiveThreshold(userId, context);

        // 2. 피드백 조정값 조회
        double feedbackAdjustment = getFeedbackAdjustment(userId);

        // 3. 통합 임계값 계산
        double unifiedThreshold = adaptiveThreshold + feedbackAdjustment;

        // 4. 범위 제한
        unifiedThreshold = Math.max(MIN_THRESHOLD, Math.min(MAX_THRESHOLD, unifiedThreshold));

        // ===== 메트릭 수집: 임계값 조정 발생 =====
        // if (feedbackMetrics != null && Math.abs(feedbackAdjustment) > 0.001) {
            // feedbackMetrics.recordThresholdAdjustment();
        // }

        log.debug("Threshold calculation - User: {}, Adaptive: {}, Feedback: {}, Unified: {}",
                 userId, adaptiveThreshold, feedbackAdjustment, unifiedThreshold);

        return unifiedThreshold;
    }

    /**
     * 적응형 임계값 조회
     *
     * AdaptiveThresholdManager 로부터 동적 임계값을 조회합니다.
     *
     * @param userId 사용자 ID
     * @param context HCAD 컨텍스트
     * @return 적응형 임계값
     */
    private double getAdaptiveThreshold(String userId, HCADContext context) {
        try {
            // AdaptiveThresholdManager 에서 임계값 조회
            AdaptiveThresholdManager.ThresholdContext thresholdContext = buildThresholdContext(context);
            AdaptiveThresholdManager.ThresholdConfiguration config = adaptiveManager.getThreshold(userId, thresholdContext);

            return config != null ? config.getAdjustedThreshold() : DEFAULT_THRESHOLD;

        } catch (Exception e) {
            log.warn("Failed to get adaptive threshold for user: {}, using default", userId, e);
            return DEFAULT_THRESHOLD;
        }
    }

    /**
     * 피드백 조정값 조회
     *
     * FeedbackLoopSystem이 학습한 임계값 조정값을 조회합니다.
     *
     * @param userId 사용자 ID
     * @return 피드백 조정값 (-0.2 ~ +0.2)
     */
    private double getFeedbackAdjustment(String userId) {
        try {
            String key = HCADRedisKeys.feedbackThreshold(userId);
            Double adjustment = (Double) redisTemplate.opsForValue().get(key);

            if (adjustment == null) {
                return 0.0; // 조정값 없음
            }

            // 조정값 범위 제한 (-0.2 ~ +0.2)
            return Math.max(-0.2, Math.min(0.2, adjustment));

        } catch (Exception e) {
            log.warn("Failed to get feedback adjustment for user: {}", userId, e);
            return 0.0;
        }
    }

    /**
     * ThresholdContext 생성
     *
     * HCADContext로부터 ThresholdContext를 생성합니다.
     * 개선: AdaptiveThresholdManager.ThresholdContext 사용
     *
     * @param context HCAD 컨텍스트
     * @return ThresholdContext
     */
    private AdaptiveThresholdManager.ThresholdContext buildThresholdContext(HCADContext context) {
        AdaptiveThresholdManager.ThresholdContext thresholdContext =
            new AdaptiveThresholdManager.ThresholdContext();

        thresholdContext.setUserId(context.getUserId());
        thresholdContext.setThreatScore(context.getThreatScore() != null ? context.getThreatScore() : 0.0);

        // Risk level 결정
        if (context.getIsNewDevice() != null && context.getIsNewDevice()) {
            thresholdContext.setRiskLevel(AdaptiveThresholdManager.RiskLevel.HIGH);
        } else if (context.getIsNewLocation() != null && context.getIsNewLocation()) {
            thresholdContext.setRiskLevel(AdaptiveThresholdManager.RiskLevel.MEDIUM);
        } else {
            thresholdContext.setRiskLevel(AdaptiveThresholdManager.RiskLevel.LOW);
        }

        return thresholdContext;
    }

    /**
     * 신호 불일치 StdDev 임계값 조회 (동적, 외부기관 2 요구사항)
     *
     * @param userId 사용자 ID
     * @return StdDev 임계값 (기본: 0.15)
     */
    public double getInconsistencyStdDevThreshold(String userId) {
        try {
            String key = HCADRedisKeys.inconsistencyStdDevThreshold(userId);
            Double threshold = (Double) redisTemplate.opsForValue().get(key);
            return threshold != null ? threshold : 0.15; // 기본값
        } catch (Exception e) {
            log.warn("Failed to get inconsistency stdDev threshold for user {}: {}", userId, e.getMessage());
            return 0.15;
        }
    }

    /**
     * 신호 불일치 Outlier 임계값 조회 (동적, 외부기관 2 요구사항)
     *
     * @param userId 사용자 ID
     * @return Mahalanobis Distance 임계값 (기본: 0.25)
     */
    public double getInconsistencyOutlierThreshold(String userId) {
        try {
            String key = HCADRedisKeys.inconsistencyOutlierThreshold(userId);
            Double threshold = (Double) redisTemplate.opsForValue().get(key);
            return threshold != null ? threshold : 0.25; // 기본값
        } catch (Exception e) {
            log.warn("Failed to get inconsistency outlier threshold for user {}: {}", userId, e.getMessage());
            return 0.25;
        }
    }

    /**
     * 불일치 탐지 결과 기록 (피드백 루프용, 외부기관 2 요구사항)
     *
     * 자동 튜닝:
     * - 100개 탐지마다 자동으로 임계값 재계산
     * - p95 기반 보수적 튜닝
     *
     * @param userId 사용자 ID
     * @param actualStdDev 실제 표준편차
     * @param stdDevThreshold 현재 StdDev 임계값
     * @param actualMahalanobis 실제 Mahalanobis Distance
     * @param outlierThreshold 현재 Outlier 임계값
     */
    public void recordInconsistencyDetection(
            String userId,
            double actualStdDev,
            double stdDevThreshold,
            double actualMahalanobis,
            double outlierThreshold) {

        try {
            // 1. 탐지 이력 저장 (최근 100개)
            String historyKey = HCADRedisKeys.inconsistencyHistory(userId);
            java.util.Map<String, Object> record = java.util.Map.of(
                "timestamp", System.currentTimeMillis(),
                "actualStdDev", actualStdDev,
                "stdDevThreshold", stdDevThreshold,
                "actualMahalanobis", actualMahalanobis,
                "outlierThreshold", outlierThreshold
            );

            redisTemplate.opsForList().leftPush(historyKey, record);
            redisTemplate.opsForList().trim(historyKey, 0, 99); // 최대 100개 유지
            redisTemplate.expire(historyKey, Duration.ofDays(7)); // 7일 TTL

            // 2. 자동 튜닝 트리거 (100개마다)
            Long historySize = redisTemplate.opsForList().size(historyKey);
            if (historySize != null && historySize % 100 == 0) {
                autoTuneInconsistencyThresholds(userId, historyKey);
            }

        } catch (Exception e) {
            log.error("Failed to record inconsistency detection for user {}: {}", userId, e.getMessage());
        }
    }

    /**
     * 자동 임계값 튜닝 (외부기관 2 요구사항)
     *
     * 전략:
     * - p95 기반 임계값 설정 (false positive 5% 허용)
     * - 최소/최대 범위 제한 (stdDev: 0.05~0.5, outlier: 0.1~2.0)
     *
     * @param userId 사용자 ID
     * @param historyKey Redis 히스토리 키
     */
    private void autoTuneInconsistencyThresholds(String userId, String historyKey) {
        try {
            java.util.List<Object> history = redisTemplate.opsForList().range(historyKey, 0, -1);
            if (history == null || history.isEmpty()) {
                return;
            }

            // 1. StdDev 분포 분석
            java.util.List<Double> stdDevs = new java.util.ArrayList<>();
            for (Object obj : history) {
                if (obj instanceof java.util.Map) {
                    java.util.Map<String, Object> record = (java.util.Map<String, Object>) obj;
                    Object stdDev = record.get("actualStdDev");
                    if (stdDev instanceof Number) {
                        stdDevs.add(((Number) stdDev).doubleValue());
                    }
                }
            }

            // 2. p95를 새로운 임계값으로 설정 (false positive 5% 허용)
            if (!stdDevs.isEmpty()) {
                double p95StdDev = calculatePercentile(stdDevs, 0.95);
                p95StdDev = Math.max(0.05, Math.min(0.5, p95StdDev)); // 범위 제한

                String stdDevKey = HCADRedisKeys.inconsistencyStdDevThreshold(userId);
                redisTemplate.opsForValue().set(stdDevKey, p95StdDev, Duration.ofDays(30));

                log.info("[UnifiedThresholdManager] Auto-tuned stdDev threshold for user {}: {}",
                    userId, p95StdDev);
            }

            // 3. Mahalanobis 분포 분석
            java.util.List<Double> mahalanobis = new java.util.ArrayList<>();
            for (Object obj : history) {
                if (obj instanceof java.util.Map) {
                    java.util.Map<String, Object> record = (java.util.Map<String, Object>) obj;
                    Object maha = record.get("actualMahalanobis");
                    if (maha instanceof Number) {
                        mahalanobis.add(((Number) maha).doubleValue());
                    }
                }
            }

            // 4. p95를 새로운 임계값으로 설정
            if (!mahalanobis.isEmpty()) {
                double p95Mahalanobis = calculatePercentile(mahalanobis, 0.95);
                p95Mahalanobis = Math.max(0.1, Math.min(2.0, p95Mahalanobis)); // 범위 제한

                String outlierKey = HCADRedisKeys.inconsistencyOutlierThreshold(userId);
                redisTemplate.opsForValue().set(outlierKey, p95Mahalanobis, Duration.ofDays(30));

                log.info("[UnifiedThresholdManager] Auto-tuned outlier threshold for user {}: {}",
                    userId, p95Mahalanobis);
            }

        } catch (Exception e) {
            log.error("Failed to auto-tune inconsistency thresholds for user {}: {}", userId, e.getMessage());
        }
    }

    /**
     * Percentile 계산
     *
     * @param values 값 목록
     * @param percentile 백분위수 (0.0 ~ 1.0)
     * @return 백분위값
     */
    private double calculatePercentile(java.util.List<Double> values, double percentile) {
        if (values.isEmpty()) {
            return 0.0;
        }

        java.util.List<Double> sorted = new java.util.ArrayList<>(values);
        java.util.Collections.sort(sorted);

        int index = (int) Math.ceil(percentile * sorted.size()) - 1;
        index = Math.max(0, Math.min(sorted.size() - 1, index));

        return sorted.get(index);
    }

    /**
     * 피드백 조정값 설정
     *
     * FeedbackLoopSystem이 학습한 조정값을 저장합니다.
     *
     * @param userId 사용자 ID
     * @param adjustment 조정값 (-0.2 ~ +0.2)
     */
    public void setFeedbackAdjustment(String userId, double adjustment) {
        try {
            // 조정값 범위 제한
            adjustment = Math.max(-0.2, Math.min(0.2, adjustment));

            // Redis에 저장 (7일 TTL)
            String key = HCADRedisKeys.feedbackThreshold(userId);
            redisTemplate.opsForValue().set(
                key,
                adjustment,
                Duration.ofDays(HCADRedisKeys.TTL_THRESHOLD_DAYS)
            );

            // 캐시 무효화 (통합 임계값 재계산 필요)
            invalidateCache(userId);

            // 임계값 변경 이벤트 발행
            publishThresholdUpdateEvent(userId, adjustment);

            log.info("Feedback adjustment set for user {}: {}", userId, adjustment);

        } catch (Exception e) {
            log.error("Failed to set feedback adjustment for user: {}", userId, e);
        }
    }

    /**
     * 캐시 무효화
     *
     * 임계값 변경 시 캐시를 무효화하여 다음 조회 시 재계산합니다.
     *
     * @param userId 사용자 ID
     */
    public void invalidateCache(String userId) {
        try {
            String cacheKey = HCADRedisKeys.unifiedThreshold(userId);
            redisTemplate.delete(cacheKey);

            log.debug("Threshold cache invalidated for user: {}", userId);

        } catch (Exception e) {
            log.warn("Failed to invalidate threshold cache for user: {}", userId, e);
        }
    }

    /**
     * 임계값 업데이트 이벤트 발행
     *
     * Redis Pub/Sub을 통해 임계값 변경을 알립니다.
     *
     * @param userId 사용자 ID
     * @param adjustment 조정값
     */
    private void publishThresholdUpdateEvent(String userId, double adjustment) {
        try {
            String channel = HCADRedisKeys.thresholdUpdateChannel();
            String message = String.format("userId=%s,adjustment=%.3f", userId, adjustment);

            redisTemplate.convertAndSend(channel, message);

            log.debug("Threshold update event published for user: {}", userId);

        } catch (Exception e) {
            log.warn("Failed to publish threshold update event", e);
        }
    }

    /**
     * 임계값 강제 설정 (관리자용)
     *
     * 관리자가 특정 사용자의 임계값을 수동으로 설정합니다.
     *
     * @param userId 사용자 ID
     * @param threshold 임계값 (0.3 ~ 0.95)
     */
    public void forceSetThreshold(String userId, double threshold) {
        try {
            // 범위 제한
            threshold = Math.max(MIN_THRESHOLD, Math.min(MAX_THRESHOLD, threshold));

            // Redis에 직접 저장
            String cacheKey = HCADRedisKeys.unifiedThreshold(userId);
            redisTemplate.opsForValue().set(
                cacheKey,
                threshold,
                Duration.ofDays(1) // 1일간 고정
            );

            log.warn("Threshold forcibly set for user {}: {}", userId, threshold);

        } catch (Exception e) {
            log.error("Failed to force set threshold for user: {}", userId, e);
        }
    }

    /**
     * 임계값 초기화 (관리자용)
     *
     * 특정 사용자의 모든 임계값 관련 데이터를 초기화합니다.
     *
     * @param userId 사용자 ID
     */
    public void resetThreshold(String userId) {
        try {
            // 통합 임계값 캐시 삭제
            redisTemplate.delete(HCADRedisKeys.unifiedThreshold(userId));

            // 피드백 조정값 삭제
            redisTemplate.delete(HCADRedisKeys.feedbackThreshold(userId));

            // 적응형 임계값 프로파일 삭제
            redisTemplate.delete(HCADRedisKeys.thresholdProfile(userId));

            // 레거시 FeedbackLoopSystem 키 삭제
            redisTemplate.delete("threshold:" + userId);

            log.info("Threshold reset for user: {}", userId);

        } catch (Exception e) {
            log.error("Failed to reset threshold for user: {}", userId, e);
        }
    }

    /**
     * 레거시 임계값 마이그레이션
     *
     * FeedbackLoopSystem이 사용하던 "threshold:{userId}" 키의 값을
     * 새로운 피드백 조정값 시스템으로 마이그레이션합니다.
     *
     * @param userId 사용자 ID
     */
    public void migrateLegacyThreshold(String userId) {
        try {
            String legacyKey = "threshold:" + userId;
            Double legacyThreshold = (Double) redisTemplate.opsForValue().get(legacyKey);

            if (legacyThreshold != null) {
                // 레거시 절대 임계값을 조정값으로 변환
                // 기본값 0.6을 기준으로 차이를 조정값으로 저장
                double adjustment = legacyThreshold - DEFAULT_THRESHOLD;
                adjustment = Math.max(-0.2, Math.min(0.2, adjustment));

                setFeedbackAdjustment(userId, adjustment);

                // 레거시 키 삭제
                redisTemplate.delete(legacyKey);

                log.info("Migrated legacy threshold for user {}: {} -> adjustment: {}",
                    userId, legacyThreshold, adjustment);
            }

        } catch (Exception e) {
            log.warn("Failed to migrate legacy threshold for user: {}", userId, e);
        }
    }

    /**
     * FeedbackLoopSystem에서 호출하는 임계값 조정 통합 메서드
     *
     * FeedbackLoopSystem의 학습 결과를 UnifiedThresholdManager를 통해 적용합니다.
     * 이 메서드는 FeedbackLoopSystem.adjustThreshold()를 대체합니다.
     *
     * @param userId 사용자 ID
     * @param isIncrease true면 증가, false면 감소
     * @param delta 조정값 크기
     */
    public void applyFeedbackThresholdAdjustment(String userId, boolean isIncrease, double delta) {
        try {
            // 1. 현재 피드백 조정값 조회
            double currentAdjustment = getFeedbackAdjustment(userId);

            // 2. 새로운 조정값 계산
            double newAdjustment = isIncrease ?
                Math.min(0.2, currentAdjustment + delta) :
                Math.max(-0.2, currentAdjustment - delta);

            // 3. 새로운 조정값 저장 (캐시 무효화 포함)
            setFeedbackAdjustment(userId, newAdjustment);

            // 4. AdaptiveThresholdManager에도 학습 결과 전파
            java.util.Map<String, Object> adjustmentMap = new java.util.HashMap<>();
            adjustmentMap.put("userId", userId);
            if (isIncrease) {
                adjustmentMap.put("increase", delta);
            } else {
                adjustmentMap.put("decrease", delta);
            }
            adaptiveManager.applyLearningFeedback(adjustmentMap);

            log.info("[UnifiedThresholdManager] Feedback adjustment applied: userId={}, isIncrease={}, delta={}, newAdjustment={}",
                userId, isIncrease, delta, newAdjustment);

        } catch (Exception e) {
            log.error("Failed to apply feedback threshold adjustment for user: {}", userId, e);
        }
    }

    /**
     * HCADFeedbackOrchestrator의 학습 결과 통합
     *
     * @param userId 사용자 ID
     * @param learningResult 학습 결과 맵
     */
    public void applyIntegratedLearningResult(String userId, java.util.Map<String, Object> learningResult) {
        try {
            // 1. AdaptiveThresholdManager에 학습 결과 적용
            if (learningResult != null && !learningResult.isEmpty()) {
                adaptiveManager.applyLearningFeedback(learningResult);
            }

            // 2. 통합 임계값 캐시 무효화 (다음 조회 시 재계산)
            invalidateCache(userId);

            log.debug("[UnifiedThresholdManager] Integrated learning result applied for user: {}", userId);

        } catch (Exception e) {
            log.error("Failed to apply integrated learning result for user: {}", userId, e);
        }
    }
}
