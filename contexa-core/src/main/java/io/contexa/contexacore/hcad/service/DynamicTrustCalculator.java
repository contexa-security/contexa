package io.contexa.contexacore.hcad.service;

import io.contexa.contexacore.hcad.constants.HCADRedisKeys;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 동적 신뢰도 계산기
 *
 * HCADFilter의 4-Layer 유사도 계산에서 각 Layer의 신뢰도를
 * 동적으로 계산하여 정확한 유사도 가중 평균을 제공합니다.
 *
 * 핵심 기능:
 * 1. VectorStore 검색 품질 평가 기반 신뢰도 계산
 * 2. 이상도 분석 품질 평가 기반 신뢰도 계산
 * 3. 상관관계 분석 품질 평가 기반 신뢰도 계산
 * 4. 계층별 우선순위 가중치 적용
 *
 * @author AI Security Framework
 * @since 3.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DynamicTrustCalculator {

    private final RedisTemplate<String, Object> redisTemplate;

    // 계층별 기본 신뢰도 (폴백용)
    private static final double DEFAULT_THREAT_TRUST = 0.7;
    private static final double DEFAULT_BASELINE_TRUST = 0.6;
    private static final double DEFAULT_ANOMALY_TRUST = 0.8;
    private static final double DEFAULT_CORRELATION_TRUST = 0.7;

    // 계층별 우선순위 가중치 (총합 = 1.0)
    private static final double THREAT_LAYER_PRIORITY = 0.4;    // 위협 검색이 가장 중요
    private static final double BASELINE_LAYER_PRIORITY = 0.3;  // 기준선 비교가 두번째
    private static final double ANOMALY_LAYER_PRIORITY = 0.2;   // 이상도 분석이 세번째
    private static final double CORRELATION_LAYER_PRIORITY = 0.1; // 상관관계가 마지막

    // 사용자별 정확도 이력 캐시 (메모리 캐시)
    private final Map<String, LayerAccuracyHistory> accuracyCache = new ConcurrentHashMap<>();

    /**
     * 위협 검색 Layer 신뢰도 계산
     *
     * VectorStore 검색 품질과 과거 정확도를 기반으로 동적 신뢰도 계산
     *
     * @param userId 사용자 ID
     * @param threatSearchQuality 검색 품질 (0.0 ~ 1.0)
     * @param isHighRisk 고위험 위협 여부
     * @param isEmpty 검색 결과 없음 여부
     * @return 동적 신뢰도 (0.2 ~ 0.95)
     */
    public double calculateThreatTrust(String userId, double threatSearchQuality,
                                       boolean isHighRisk, boolean isEmpty) {
        try {
            if (isEmpty) {
                // 검색 결과 없음 → 낮은 신뢰도
                return 0.2;
            }

            // 1. 검색 품질 기반 신뢰도
            double qualityTrust = 0.5 + (threatSearchQuality * 0.4); // 0.5 ~ 0.9

            // 2. 위험도 기반 조정
            if (isHighRisk) {
                qualityTrust = Math.min(0.95, qualityTrust + 0.1);
            }

            // 3. 과거 정확도 반영
            double historicalAccuracy = getHistoricalAccuracy(userId, "threat");
            double dynamicTrust = (qualityTrust * 0.7) + (historicalAccuracy * 0.3);

            // 4. 범위 제한
            dynamicTrust = Math.max(0.2, Math.min(0.95, dynamicTrust));

            log.debug("Threat trust calculated - User: {}, Quality: {:.3f}, Historical: {:.3f}, Final: {:.3f}",
                     userId, qualityTrust, historicalAccuracy, dynamicTrust);

            return dynamicTrust;

        } catch (Exception e) {
            log.warn("Failed to calculate threat trust for user: {}, using default", userId, e);
            return DEFAULT_THREAT_TRUST;
        }
    }

    /**
     * 기준선 Layer 신뢰도 계산
     *
     * 기준선 유사도와 기준선 신뢰도를 기반으로 동적 신뢰도 계산
     *
     * @param userId 사용자 ID
     * @param baselineSimilarity 기준선 유사도 (0.0 ~ 1.0)
     * @param baselineConfidence 기준선 자체 신뢰도 (0.0 ~ 1.0)
     * @return 동적 신뢰도 (0.3 ~ 0.95)
     */
    public double calculateBaselineTrust(String userId, double baselineSimilarity,
                                         Double baselineConfidence) {
        try {
            // 1. 기준선 신뢰도가 높을수록 신뢰 (null일 경우 기본값 0.5)
            double confidenceTrust = baselineConfidence != null ? baselineConfidence : 0.5;

            // 2. 유사도 패턴 분석
            double patternTrust;
            if (baselineSimilarity >= 0.9) {
                // 매우 유사 → 높은 신뢰도
                patternTrust = 0.9;
            } else if (baselineSimilarity <= 0.1) {
                // 매우 다름 → 높은 신뢰도 (확실한 이상)
                patternTrust = 0.9;
            } else if (baselineSimilarity >= 0.7 && baselineSimilarity < 0.9) {
                // 중간 유사 → 중간 신뢰도
                patternTrust = 0.7;
            } else if (baselineSimilarity > 0.1 && baselineSimilarity <= 0.3) {
                // 중간 차이 → 중간 신뢰도
                patternTrust = 0.7;
            } else {
                // 애매한 범위 (0.3 ~ 0.7) → 낮은 신뢰도
                patternTrust = 0.5;
            }

            // 3. 과거 정확도 반영
            double historicalAccuracy = getHistoricalAccuracy(userId, "baseline");

            // 4. 가중 평균
            double dynamicTrust = (confidenceTrust * 0.4) + (patternTrust * 0.4) + (historicalAccuracy * 0.2);

            // 5. 범위 제한
            dynamicTrust = Math.max(0.3, Math.min(0.95, dynamicTrust));

            log.debug("Baseline trust calculated - User: {}, Similarity: {:.3f}, Confidence: {:.3f}, Final: {:.3f}",
                     userId, baselineSimilarity, baselineConfidence, dynamicTrust);

            return dynamicTrust;

        } catch (Exception e) {
            log.warn("Failed to calculate baseline trust for user: {}, using default", userId, e);
            return DEFAULT_BASELINE_TRUST;
        }
    }

    /**
     * 이상도 Layer 신뢰도 계산
     *
     * 이상도 분석 품질과 과거 정확도를 기반으로 동적 신뢰도 계산
     *
     * @param userId 사용자 ID
     * @param anomalyScore 이상도 점수 (0.0 ~ 1.0)
     * @param zScore Z-Score 값 (null일 경우 기본값 0.0)
     * @return 동적 신뢰도 (0.5 ~ 0.95)
     */
    public double calculateAnomalyTrust(String userId, double anomalyScore, Double zScore) {
        try {
            // 1. Z-Score 기반 신뢰도 (null일 경우 기본값 0.0 사용)
            double actualZScore = zScore != null ? zScore : 0.0;
            double zScoreTrust;
            if (Math.abs(actualZScore) >= 3.0) {
                // 3-시그마 이상 → 매우 높은 신뢰도
                zScoreTrust = 0.95;
            } else if (Math.abs(actualZScore) >= 2.0) {
                // 2-시그마 이상 → 높은 신뢰도
                zScoreTrust = 0.85;
            } else if (Math.abs(actualZScore) >= 1.0) {
                // 1-시그마 이상 → 중간 신뢰도
                zScoreTrust = 0.7;
            } else {
                // 1-시그마 이하 → 낮은 신뢰도
                zScoreTrust = 0.5;
            }

            // 2. 이상도 점수 일관성 확인
            boolean isConsistent = (anomalyScore > 0.7 && actualZScore > 2.0) ||
                                  (anomalyScore < 0.3 && Math.abs(actualZScore) < 1.0);
            if (!isConsistent) {
                zScoreTrust *= 0.8; // 일관성 없으면 신뢰도 하락
            }

            // 3. 과거 정확도 반영
            double historicalAccuracy = getHistoricalAccuracy(userId, "anomaly");

            // 4. 가중 평균
            double dynamicTrust = (zScoreTrust * 0.7) + (historicalAccuracy * 0.3);

            // 5. 범위 제한
            dynamicTrust = Math.max(0.5, Math.min(0.95, dynamicTrust));

            log.debug("Anomaly trust calculated - User: {}, Score: {:.3f}, Z-Score: {:.2f}, Final: {:.3f}",
                     userId, anomalyScore, actualZScore, dynamicTrust);

            return dynamicTrust;

        } catch (Exception e) {
            log.warn("Failed to calculate anomaly trust for user: {}, using default", userId, e);
            return DEFAULT_ANOMALY_TRUST;
        }
    }

    /**
     * 상관관계 Layer 신뢰도 계산
     *
     * 위협 상관관계 분석 품질을 기반으로 동적 신뢰도 계산
     *
     * @param userId 사용자 ID
     * @param correlationScore 상관관계 점수 (0.0 ~ 1.0)
     * @param correlationCount 상관관계 개수
     * @return 동적 신뢰도 (0.4 ~ 0.9)
     */
    public double calculateCorrelationTrust(String userId, double correlationScore, int correlationCount) {
        try {
            // 1. 상관관계 개수 기반 신뢰도
            double countTrust;
            if (correlationCount >= 5) {
                countTrust = 0.9; // 5개 이상 → 높은 신뢰도
            } else if (correlationCount >= 3) {
                countTrust = 0.7; // 3-4개 → 중간 신뢰도
            } else if (correlationCount >= 1) {
                countTrust = 0.6; // 1-2개 → 낮은 신뢰도
            } else {
                countTrust = 0.4; // 없음 → 매우 낮은 신뢰도
            }

            // 2. 상관관계 점수 반영
            double scoreTrust = 0.4 + (correlationScore * 0.5); // 0.4 ~ 0.9

            // 3. 과거 정확도 반영
            double historicalAccuracy = getHistoricalAccuracy(userId, "correlation");

            // 4. 가중 평균
            double dynamicTrust = (countTrust * 0.4) + (scoreTrust * 0.4) + (historicalAccuracy * 0.2);

            // 5. 범위 제한
            dynamicTrust = Math.max(0.4, Math.min(0.9, dynamicTrust));

            log.debug("Correlation trust calculated - User: {}, Score: {:.3f}, Count: {}, Final: {:.3f}",
                     userId, correlationScore, correlationCount, dynamicTrust);

            return dynamicTrust;

        } catch (Exception e) {
            log.warn("Failed to calculate correlation trust for user: {}, using default", userId, e);
            return DEFAULT_CORRELATION_TRUST;
        }
    }

    /**
     * 계층별 우선순위 가중치 조회
     *
     * 각 Layer의 중요도에 따라 우선순위 가중치를 반환합니다.
     *
     * @param layerName Layer 이름 (threat, baseline, anomaly, correlation)
     * @return 우선순위 가중치 (0.0 ~ 1.0)
     */
    public double getLayerPriority(String layerName) {
        switch (layerName.toLowerCase()) {
            case "threat":
                return THREAT_LAYER_PRIORITY;
            case "baseline":
                return BASELINE_LAYER_PRIORITY;
            case "anomaly":
                return ANOMALY_LAYER_PRIORITY;
            case "correlation":
                return CORRELATION_LAYER_PRIORITY;
            default:
                return 0.25; // 동일 가중치
        }
    }

    /**
     * 과거 정확도 조회
     *
     * Redis에서 사용자별 Layer별 과거 정확도를 조회합니다.
     *
     * @param userId 사용자 ID
     * @param layerName Layer 이름
     * @return 과거 정확도 (0.0 ~ 1.0)
     */
    private double getHistoricalAccuracy(String userId, String layerName) {
        try {
            // 1. 메모리 캐시 조회
            LayerAccuracyHistory history = accuracyCache.get(userId);
            if (history != null) {
                Double accuracy = history.getAccuracy(layerName);
                if (accuracy != null) {
                    return accuracy;
                }
            }

            // 2. Redis 조회
            String key = HCADRedisKeys.modelConfidence(userId);
            Object obj = redisTemplate.opsForHash().get(key, layerName + "_accuracy");

            if (obj instanceof Double) {
                double accuracy = (Double) obj;

                // 메모리 캐시 업데이트
                if (history == null) {
                    history = new LayerAccuracyHistory();
                    accuracyCache.put(userId, history);
                }
                history.setAccuracy(layerName, accuracy);

                return accuracy;
            }

            // 3. 기본값 반환
            return 0.7; // 중립적 정확도

        } catch (Exception e) {
            log.warn("Failed to get historical accuracy for user: {}, layer: {}", userId, layerName, e);
            return 0.7;
        }
    }

    /**
     * 정확도 업데이트
     *
     * 피드백 학습 결과를 기반으로 Layer별 정확도를 업데이트합니다.
     *
     * @param userId 사용자 ID
     * @param layerName Layer 이름
     * @param isCorrect 정확한 판단 여부
     */
    public void updateAccuracy(String userId, String layerName, boolean isCorrect) {
        try {
            // 1. 현재 정확도 조회
            double currentAccuracy = getHistoricalAccuracy(userId, layerName);

            // 2. 지수 이동 평균으로 업데이트
            double alpha = 0.1; // 학습률
            double newAccuracy = isCorrect
                ? currentAccuracy + alpha * (1.0 - currentAccuracy)
                : currentAccuracy - alpha * currentAccuracy;

            // 3. 범위 제한
            newAccuracy = Math.max(0.1, Math.min(0.99, newAccuracy));

            // 4. Redis 저장
            String key = HCADRedisKeys.modelConfidence(userId);
            redisTemplate.opsForHash().put(key, layerName + "_accuracy", newAccuracy);

            // 5. 메모리 캐시 업데이트
            LayerAccuracyHistory history = accuracyCache.computeIfAbsent(userId, k -> new LayerAccuracyHistory());
            history.setAccuracy(layerName, newAccuracy);

            log.debug("Accuracy updated - User: {}, Layer: {}, IsCorrect: {}, New: {:.3f}",
                     userId, layerName, isCorrect, newAccuracy);

        } catch (Exception e) {
            log.error("Failed to update accuracy for user: {}, layer: {}", userId, layerName, e);
        }
    }

    /**
     * Layer별 정확도 이력
     */
    private static class LayerAccuracyHistory {
        private final Map<String, Double> accuracies = new ConcurrentHashMap<>();

        public Double getAccuracy(String layerName) {
            return accuracies.get(layerName);
        }

        public void setAccuracy(String layerName, double accuracy) {
            accuracies.put(layerName, accuracy);
        }
    }
}
