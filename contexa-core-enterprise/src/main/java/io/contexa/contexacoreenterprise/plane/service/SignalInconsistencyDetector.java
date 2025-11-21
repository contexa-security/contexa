package io.contexa.contexacoreenterprise.plane.service;

import io.contexa.contexacoreenterprise.dashboard.metrics.plane.OrthogonalSignalCollector;
import io.contexa.contexacore.hcad.service.HCADSimilarityCalculator.TrustedSimilarityResult;
import io.contexa.contexacore.hcad.threshold.UnifiedThresholdManager;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.math3.linear.*;
import org.apache.commons.math3.stat.correlation.Covariance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SessionCallback;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * 신호 불일치 탐지기 (Signal Inconsistency Detector)
 *
 * 7차원 직교 신호 간 불일치를 Mahalanobis Distance로 탐지합니다.
 *
 * 핵심 기능:
 * 1. Mahalanobis Distance 계산 (공분산 행렬 고려)
 * 2. UnifiedThresholdManager 동적 임계값 조회 ✅
 * 3. 탐지 결과 피드백 루프 기록 → 자동 튜닝 ✅
 *
 * 외부기관 1 피드백 반영:
 * - 직교 신호 부족 문제 해결 (7차원 신호)
 *
 * 외부기관 2 피드백 반영:
 * - 고정 임계값 제거 (stdDev > 0.15, outlier > 0.25)
 * - UnifiedThresholdManager 자동 튜닝 통합 ✅
 *
 * @author contexa
 * @since 3.0
 */
@Slf4j
public class SignalInconsistencyDetector {

    @Autowired
    private UnifiedThresholdManager unifiedThresholdManager;

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    // ===== 설정값 (하드코딩 제거) =====

    /**
     * Chi-Square 임계값 (χ²(7, 0.95) = 14.07)
     * 자유도 7, 신뢰구간 95%
     */
    @Value("${hcad.signal.chi.square.threshold:14.07}")
    private double chiSquareThreshold;

    /**
     * 공분산 행렬 학습을 위한 최소 샘플 수
     */
    @Value("${hcad.signal.covariance.min.samples:30}")
    private int covarianceMinSamples;

    /**
     * 사용자별 신호 히스토리 저장 크기
     */
    @Value("${hcad.signal.history.size:100}")
    private int signalHistorySize;

    // ===== Public Methods =====

    /**
     * 7차원 신호 불일치 탐지
     *
     * @param userId 사용자 ID
     * @param signals 직교 신호 (7차원)
     * @param hcadResult HCAD 분석 결과
     * @return InconsistencyResult (불일치 여부, 상세 정보)
     */
    public InconsistencyResult detectInconsistency(
            String userId,
            OrthogonalSignalCollector.OrthogonalSignals signals,
            TrustedSimilarityResult hcadResult) {

        try {
            // 1. 7차원 벡터 구성
            double[] signalVector = signals.toArray();

            // 2. 평균 및 표준편차 계산
            double mean = calculateMean(signalVector);
            double stdDev = calculateStdDev(signalVector, mean);

            // 3. UnifiedThresholdManager에서 동적 임계값 조회 ✅
            double stdDevThreshold = unifiedThresholdManager.getInconsistencyStdDevThreshold(userId);
            double outlierThreshold = unifiedThresholdManager.getInconsistencyOutlierThreshold(userId);

            // 4. 표준편차 기반 불일치 탐지
            boolean inconsistentByStdDev = stdDev > stdDevThreshold;

            // 5. Mahalanobis Distance (공분산 고려)
            double mahalanobisDistance = calculateMahalanobisDistance(signalVector, userId);
            boolean inconsistentByOutlier = mahalanobisDistance > outlierThreshold;

            // 6. Chi-Square 임계값 (χ²(7, 0.95) = 14.07)
            boolean inconsistentByChiSquare = mahalanobisDistance > chiSquareThreshold;

            // 7. 최종 판정
            boolean isInconsistent = inconsistentByStdDev || inconsistentByOutlier || inconsistentByChiSquare;

            // 8. 피드백 루프에 기록 (자동 튜닝용) ✅
            if (isInconsistent) {
                unifiedThresholdManager.recordInconsistencyDetection(
                        userId,
                        stdDev,
                        stdDevThreshold,
                        mahalanobisDistance,
                        outlierThreshold
                );
            }

            // 9. 신호 히스토리 저장 (공분산 학습용)
            saveSignalHistory(userId, signalVector);

            // 10. 결과 반환
            return InconsistencyResult.builder()
                    .inconsistent(isInconsistent)
                    .stdDev(stdDev)
                    .stdDevThreshold(stdDevThreshold) // 동적 임계값
                    .mahalanobisDistance(mahalanobisDistance)
                    .outlierThreshold(outlierThreshold) // 동적 임계값
                    .chiSquareThreshold(chiSquareThreshold)
                    .inconsistentReasons(buildReasons(inconsistentByStdDev, inconsistentByOutlier, inconsistentByChiSquare))
                    .signalVector(signalVector)
                    .timestamp(LocalDateTime.now())
                    .build();

        } catch (Exception e) {
            log.error("[SignalInconsistency] Failed to detect inconsistency for user {}: {}",
                    userId, e.getMessage());

            // 예외 발생 시 안전한 기본값 반환
            return InconsistencyResult.builder()
                    .inconsistent(false)
                    .stdDev(0.0)
                    .stdDevThreshold(0.15)
                    .mahalanobisDistance(0.0)
                    .outlierThreshold(0.25)
                    .chiSquareThreshold(chiSquareThreshold)
                    .inconsistentReasons(List.of("Error during detection"))
                    .signalVector(signals.toArray())
                    .timestamp(LocalDateTime.now())
                    .build();
        }
    }

    // ===== Private Methods =====

    /**
     * 평균 계산
     */
    private double calculateMean(double[] vector) {
        return Arrays.stream(vector).average().orElse(0.5);
    }

    /**
     * 표준편차 계산
     */
    private double calculateStdDev(double[] vector, double mean) {
        double variance = Arrays.stream(vector)
                .map(v -> Math.pow(v - mean, 2))
                .average()
                .orElse(0.0);

        return Math.sqrt(variance);
    }

    /**
     * Mahalanobis Distance 계산 (공분산 행렬 고려)
     *
     * D = sqrt((x - μ)^T * Σ^-1 * (x - μ))
     *
     * where:
     * - x: 관측 벡터 (7차원)
     * - μ: 평균 벡터
     * - Σ: 공분산 행렬
     * - Σ^-1: 공분산 역행렬
     */
    private double calculateMahalanobisDistance(double[] vector, String userId) {
        try {
            // 1. 사용자별 공분산 행렬 조회
            RealMatrix covMatrix = getUserCovarianceMatrix(userId);

            if (covMatrix == null) {
                // 학습 전: Euclidean Distance로 대체
                log.debug("[Mahalanobis] Covariance matrix not available for user {}, using Euclidean distance",
                        userId);
                return calculateEuclideanDistance(vector);
            }

            // 2. 평균 벡터 조회
            double[] meanVector = getUserMeanVector(userId);

            if (meanVector == null || meanVector.length != vector.length) {
                log.debug("[Mahalanobis] Mean vector not available for user {}, using Euclidean distance",
                        userId);
                return calculateEuclideanDistance(vector);
            }

            // 3. 차이 벡터 계산: (x - μ)
            double[] diff = new double[vector.length];
            for (int i = 0; i < vector.length; i++) {
                diff[i] = vector[i] - meanVector[i];
            }

            // 4. 공분산 역행렬 계산: Σ^-1
            RealMatrix invCovMatrix = new LUDecomposition(covMatrix).getSolver().getInverse();

            // 5. Mahalanobis Distance 계산
            // D = sqrt((x - μ)^T * Σ^-1 * (x - μ))
            RealVector diffVector = new ArrayRealVector(diff);
            RealVector result = invCovMatrix.operate(diffVector);
            double distance = Math.sqrt(diffVector.dotProduct(result));

            return distance;

        } catch (SingularMatrixException e) {
            log.warn("[Mahalanobis] Singular covariance matrix for user {}, using Euclidean distance",
                    userId);
            return calculateEuclideanDistance(vector);
        } catch (Exception e) {
            log.error("[Mahalanobis] Failed to calculate Mahalanobis distance for user {}: {}",
                    userId, e.getMessage());
            return calculateEuclideanDistance(vector);
        }
    }

    /**
     * Euclidean Distance 계산 (Mahalanobis Distance 대체용)
     *
     * D = sqrt(Σ(x_i - mean)^2)
     */
    private double calculateEuclideanDistance(double[] vector) {
        double mean = calculateMean(vector);
        double sumSquares = Arrays.stream(vector)
                .map(v -> Math.pow(v - mean, 2))
                .sum();

        return Math.sqrt(sumSquares);
    }

    /**
     * 사용자별 공분산 행렬 조회
     *
     * Redis 캐시 → 공분산 계산 → 캐시 저장
     */
    private RealMatrix getUserCovarianceMatrix(String userId) {
        if (redisTemplate == null) {
            return null;
        }

        // 1. Redis 캐시 조회
        String cacheKey = "signal:covariance:" + userId;
        Object cached = redisTemplate.opsForValue().get(cacheKey);

        if (cached != null && cached instanceof double[][]) {
            return new Array2DRowRealMatrix((double[][]) cached);
        }

        // 2. 신호 히스토리 조회
        List<double[]> history = getSignalHistory(userId);

        if (history.size() < covarianceMinSamples) {
            log.debug("[Covariance] Insufficient samples for user {}: {} < {}",
                    userId, history.size(), covarianceMinSamples);
            return null;
        }

        // 3. 공분산 행렬 계산
        double[][] historyArray = history.toArray(new double[0][]);
        Covariance covariance = new Covariance(historyArray);
        RealMatrix covMatrix = covariance.getCovarianceMatrix();

        // 4. Redis 캐시 저장 (1시간 TTL)
        redisTemplate.opsForValue().set(cacheKey, covMatrix.getData(), Duration.ofHours(1));

        return covMatrix;
    }

    /**
     * 사용자별 평균 벡터 조회
     */
    private double[] getUserMeanVector(String userId) {
        if (redisTemplate == null) {
            return null;
        }

        // 1. Redis 캐시 조회
        String cacheKey = "signal:mean:" + userId;
        Object cached = redisTemplate.opsForValue().get(cacheKey);

        if (cached != null && cached instanceof double[]) {
            return (double[]) cached;
        }

        // 2. 신호 히스토리 조회
        List<double[]> history = getSignalHistory(userId);

        if (history.isEmpty()) {
            return null;
        }

        // 3. 평균 벡터 계산
        int dimensions = history.get(0).length;
        double[] meanVector = new double[dimensions];

        for (double[] signal : history) {
            for (int i = 0; i < dimensions; i++) {
                meanVector[i] += signal[i];
            }
        }

        for (int i = 0; i < dimensions; i++) {
            meanVector[i] /= history.size();
        }

        // 4. Redis 캐시 저장 (1시간 TTL)
        redisTemplate.opsForValue().set(cacheKey, meanVector, Duration.ofHours(1));

        return meanVector;
    }

    /**
     * 신호 히스토리 조회
     */
    private List<double[]> getSignalHistory(String userId) {
        if (redisTemplate == null) {
            return List.of();
        }

        String key = "signal:history:" + userId;
        List<Object> history = redisTemplate.opsForList().range(key, 0, -1);

        if (history == null) {
            return List.of();
        }

        return history.stream()
                .filter(o -> o instanceof double[])
                .map(o -> (double[]) o)
                .collect(Collectors.toList());
    }

    /**
     * 신호 히스토리 저장 (공분산 학습용)
     */
    /**
     * 신호 히스토리 저장 (공분산 학습용)
     * Redis Pipelining 적용으로 RTT 최소화
     */
    private void saveSignalHistory(String userId, double[] signalVector) {
        if (redisTemplate == null) {
            return;
        }

        String key = "signal:history:" + userId;
        String covKey = "signal:covariance:" + userId;
        String meanKey = "signal:mean:" + userId;

        redisTemplate.executePipelined(new SessionCallback<>() {
            @Override
            public Object execute(RedisOperations operations){
                // 1. 히스토리 추가 (LPUSH)
                operations.opsForList().leftPush(key, signalVector);
                
                // 2. 크기 제한 (LTRIM)
                operations.opsForList().trim(key, 0, signalHistorySize - 1);

                // 3. 만료 시간 설정 (EXPIRE)
                operations.expire(key, Duration.ofDays(7));

                // 4. 캐시 무효화 (DEL)
                operations.delete(covKey);
                operations.delete(meanKey);

                return null;
            }
        });
    }

    /**
     * 불일치 이유 생성
     */
    private List<String> buildReasons(boolean byStdDev, boolean byOutlier, boolean byChiSquare) {
        List<String> reasons = new ArrayList<>();

        if (byStdDev) {
            reasons.add("High standard deviation across signals");
        }

        if (byOutlier) {
            reasons.add("Mahalanobis distance exceeds outlier threshold");
        }

        if (byChiSquare) {
            reasons.add("Chi-square test failed (95% confidence)");
        }

        if (reasons.isEmpty()) {
            reasons.add("Signals consistent");
        }

        return reasons;
    }

    // ===== Inner Classes =====

    /**
     * 불일치 탐지 결과 클래스
     */
    @lombok.Builder
    @lombok.Getter
    public static class InconsistencyResult {
        private final boolean inconsistent;

        // 표준편차 기반
        private final double stdDev;
        private final double stdDevThreshold; // 동적 임계값 ✅

        // Mahalanobis Distance 기반
        private final double mahalanobisDistance;
        private final double outlierThreshold; // 동적 임계값 ✅

        // Chi-Square 기반
        private final double chiSquareThreshold;

        private final List<String> inconsistentReasons;
        private final double[] signalVector;
        private final LocalDateTime timestamp;
    }
}
