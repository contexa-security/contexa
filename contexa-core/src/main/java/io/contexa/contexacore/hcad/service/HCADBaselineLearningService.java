package io.contexa.contexacore.hcad.service;

import io.contexa.contexacore.hcad.constants.HCADRedisKeys;
import io.contexa.contexacommon.hcad.domain.BaselineVector;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * HCAD Baseline 학습 서비스
 *
 * 기준선 벡터의 학습 로직을 담당:
 * - Bootstrap Phase 관리
 * - 적응형 학습률 계산
 * - 통계적 이상치 탐지
 * - 동적 임계값 계산
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class HCADBaselineLearningService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${hcad.threshold.warn:0.7}")
    private double warnThreshold;

    @Value("${hcad.baseline.redis.ttl-days:30}")
    private int baselineTtlDays;

    @Value("${hcad.baseline.min-confidence:0.3}")
    private double minConfidence;

    @Value("${hcad.baseline.bootstrap.enabled:true}")
    private boolean bootstrapEnabled;

    @Value("${hcad.baseline.bootstrap.initial-samples:10}")
    private int bootstrapInitialSamples;

    @Value("${hcad.baseline.bootstrap.max-anomaly-score:0.85}")
    private double bootstrapMaxAnomalyScore;

    @Value("${hcad.baseline.statistical.z-score-threshold:3.0}")
    private double zScoreThreshold;

    @Value("${hcad.baseline.statistical.enabled:true}")
    private boolean statisticalDetectionEnabled;

    @Value("${hcad.baseline.statistical.min-samples:20}")
    private int statisticalMinSamples;

    @Value("${hcad.baseline.statistical.update-interval:10}")
    private int statisticalUpdateInterval;

    @Value("${hcad.baseline.update-alpha:0.1}")
    private double baselineUpdateAlpha;

    /**
     * Z-Score 임계값 조회 (외부에서 사용)
     */
    public double getZScoreThreshold() {
        return zScoreThreshold;
    }

    /**
     * 기준선 업데이트 여부 결정 (최적화된 학습 로직)
     *
     * 1. Bootstrap Phase: 초기 학습 단계 (신규 사용자)
     * 2. Confidence-based Learning: 신뢰도 기반 동적 임계값
     * 3. Statistical Anomaly Detection: 통계적 이상치 탐지
     * 4. Security-First Principle: 보안 우선 원칙 유지
     */
    public boolean shouldUpdateBaseline(BaselineVector baseline, double anomalyScore,
                                       double similarityScore, HCADContext context) {

        // 0. 의심스러운 컨텍스트 필터링 (기준선 오염 방지)
        if (isSuspiciousContext(context)) {
            if (log.isDebugEnabled()) {
                log.debug("[HCAD] Suspicious context detected, skipping baseline update: userId={}, reasons={}",
                    context.getUserId(), getSuspiciousReasons(context));
            }
            return false;
        }

        // 1. Bootstrap Phase (초기 학습 단계)
        if (bootstrapEnabled && isInBootstrapPhase(baseline)) {
            // Bootstrap 단계에서는 더 관대한 임계값 적용
            boolean shouldLearn = anomalyScore < bootstrapMaxAnomalyScore;
            if (shouldLearn) {
                if (log.isDebugEnabled()) {
                    log.debug("[HCAD] Bootstrap learning - userId: {}, updateCount: {}, anomalyScore: {}",
                        context.getUserId(), baseline.getUpdateCount(), String.format("%.3f", anomalyScore));
                }
            }
            return shouldLearn;
        }

        // 2. Confidence-based Dynamic Threshold (신뢰도 기반 동적 임계값)
        double dynamicThreshold = calculateDynamicThreshold(baseline.getConfidence());

        // 3. Statistical Anomaly Detection (통계적 이상치 판단)
        boolean isStatisticalAnomaly = false;
        if (statisticalDetectionEnabled && baseline.getUpdateCount() > bootstrapInitialSamples) {
            isStatisticalAnomaly = isStatisticalOutlier(anomalyScore, baseline);
        }

        // 4. Learning Decision (학습 결정)
        boolean shouldUpdate = false;
        String reason = "";

        if (isStatisticalAnomaly) {
            // 통계적 이상치는 학습하지 않음
            shouldUpdate = false;
            reason = "Statistical outlier detected";
        } else if (anomalyScore < dynamicThreshold) {
            // 동적 임계값 이하면 학습
            shouldUpdate = true;
            reason = String.format("Below dynamic threshold (%.3f)", dynamicThreshold);
        } else if (baseline.getConfidence() < minConfidence && anomalyScore < warnThreshold) {
            // 신뢰도가 낮고 경고 임계값 이하면 학습 (신뢰도 구축)
            shouldUpdate = true;
            reason = "Building confidence";
        }

        if (log.isDebugEnabled()) {
            log.debug("[HCAD] Learning decision - userId: {}, shouldUpdate: {}, reason: {}, "
                + "anomalyScore: {}, dynamicThreshold: {}, confidence: {}, "
                + "updateCount: {}, isStatisticalAnomaly: {}",
                context.getUserId(), shouldUpdate, reason,
                String.format("%.3f", anomalyScore), String.format("%.3f", dynamicThreshold),
                String.format("%.3f", baseline.getConfidence()),
                baseline.getUpdateCount(), isStatisticalAnomaly);
        }

        return shouldUpdate;
    }

    /**
     * Bootstrap 단계 여부 판단
     */
    public boolean isInBootstrapPhase(BaselineVector baseline) {
        return baseline.getUpdateCount() < bootstrapInitialSamples ||
               baseline.getConfidence() < minConfidence;
    }

    /**
     * 신뢰도 기반 동적 임계값 계산
     * 신뢰도가 높을수록 더 엄격한 임계값 적용
     */
    public double calculateDynamicThreshold(double confidence) {
        // Sigmoid 함수를 사용한 부드러운 전환
        // confidence 0 → threshold = warnThreshold
        // confidence 1 → threshold = warnThreshold * 0.7
        double scaleFactor = 0.7 + 0.3 * Math.exp(-5 * confidence);
        return warnThreshold * scaleFactor;
    }

    /**
     * 통계적 이상치 탐지 (Z-score 기반)
     */
    public boolean isStatisticalOutlier(double anomalyScore, BaselineVector baseline) {
        // 1. 충분한 샘플 수 확보 확인
        if (baseline.getUpdateCount() <= statisticalMinSamples) {
            return false; // 데이터 부족
        }

        // 2. 통계 정보 null-safe 검증
        if (baseline.getAnomalyScoreMean() == null || baseline.getAnomalyScoreStdDev() == null) {
            return false; // 통계 정보 부족
        }

        // 3. Z-score 계산 및 이상치 판단
        double zScore = baseline.calculateZScore(anomalyScore);
        if (zScore > zScoreThreshold) {
            if (log.isDebugEnabled()) {
                log.debug("[HCAD] Statistical outlier detected - userId: {}, anomalyScore: {}, zScore: {}, mean: {}, stdDev: {}",
                    baseline.getUserId(),
                    String.format("%.3f", anomalyScore),
                    String.format("%.3f", zScore),
                    String.format("%.3f", baseline.getAnomalyScoreMean()),
                    String.format("%.3f", baseline.getAnomalyScoreStdDev()));
            }
            return true;
        }

        return false;
    }

    /**
     * 기준선 학습 업데이트 (메모리 업데이트 후 Redis 비동기 저장)
     */
    public void updateBaseline(HCADContext context, BaselineVector baseline, double similarityScore) {
        // Adaptive Learning Rate 계산 (confidence 기반)
        double adaptiveLearningRate = calculateAdaptiveLearningRate(baseline.getConfidence());

        // 지수 이동 평균으로 업데이트
        baseline.updateWithContext(context, adaptiveLearningRate);

        if (log.isDebugEnabled()) {
            log.debug("[HCAD] 기준선 학습 완료: userId={}, confidence={}, updateCount={}, learningRate={}",
                context.getUserId(),
                String.format("%.3f", baseline.getConfidence()),
                baseline.getUpdateCount(),
                String.format("%.3f", adaptiveLearningRate));
        }

        // Redis에 비동기 저장 (성능 최적화)
        saveBaselineAsync(baseline);
    }

    /**
     * BaselineVector를 Redis에 비동기 저장
     * <p>
     * 성능 최적화:
     * - 비동기 저장으로 Hot Path 지연 최소화
     * - TTL 30일 설정으로 자동 만료 관리
     * - 저장 실패 시 로깅만 수행 (메모리 캐시는 유지)
     */
    @Async("hcadExecutor")
    public void saveBaselineAsync(BaselineVector baseline) {
        try {
            String key = HCADRedisKeys.baselineVector(baseline.getUserId());
            redisTemplate.opsForValue().set(key, baseline, Duration.ofDays(baselineTtlDays));

            if (log.isDebugEnabled()) {
                log.debug("[HCAD] Baseline saved to Redis (async): userId={}, updateCount={}, confidence={}, ttl={}days",
                    baseline.getUserId(),
                    baseline.getUpdateCount(),
                    String.format("%.3f", baseline.getConfidence()),
                    baselineTtlDays);
            }
        } catch (Exception e) {
            log.error("[HCAD] Failed to save baseline to Redis: userId={}, error={}",
                baseline.getUserId(), e.getMessage(), e);
        }
        CompletableFuture.completedFuture(null);
    }

    /**
     * Adaptive Learning Rate 계산
     * Bootstrap 단계에서는 빠른 학습, 이후 점진적으로 감소
     */
    public double calculateAdaptiveLearningRate(double confidence) {
        // Bootstrap phase: 높은 학습률
        // Mature phase: 낮은 학습률
        if (confidence < minConfidence) {
            return baselineUpdateAlpha * 2.0;  // Bootstrap: 2배 학습률
        } else if (confidence < 0.7) {
            return baselineUpdateAlpha * 1.5;  // Building: 1.5배 학습률
        } else {
            return baselineUpdateAlpha;  // Mature: 기본 학습률
        }
    }

    /**
     * 통계 업데이트 여부 결정 (Z-Score 계산용)
     * 수백만 사용자 성능을 위해 통계 업데이트도 제한
     *
     * 통계 오염 방지: 이상치 발생 시 Z-score 검증을 통해 통계적 이상치는 제외
     */
    public boolean shouldUpdateStatistics(BaselineVector baseline, double anomalyScore) {
        // 1. 부트스트랩 단계: 항상 업데이트 (통계 구축 단계)
        if (baseline.getUpdateCount() < bootstrapInitialSamples) {
            return true;
        }

        // 2. 정기 업데이트: N회마다 (설정 가능)
        if (baseline.getUpdateCount() % statisticalUpdateInterval == 0) {
            return true;
        }

        // 3. 이상 탐지 시: 통계적 이상치가 아닌 경우만 업데이트
        if (anomalyScore >= warnThreshold) {
            // 통계 정보가 충분히 축적된 경우 Z-score 검증
            if (baseline.getUpdateCount() > statisticalMinSamples &&
                baseline.getAnomalyScoreMean() != null &&
                baseline.getAnomalyScoreStdDev() != null) {

                double zScore = baseline.calculateZScore(anomalyScore);
                boolean isStatisticalOutlier = zScore > zScoreThreshold;

                if (log.isDebugEnabled() && isStatisticalOutlier) {
                    log.debug("[HCAD] Skipping statistics update for statistical outlier - userId: {}, anomalyScore: {}, zScore: {}",
                        baseline.getUserId(), String.format("%.3f", anomalyScore), String.format("%.3f", zScore));
                }

                // 통계적 이상치는 통계 업데이트에서 제외 (통계 오염 방지)
                return !isStatisticalOutlier;
            }

            // 통계 정보 부족 시 일단 업데이트 (초기 구축)
            return true;
        }

        return false;
    }

    /**
     * 의심스러운 컨텍스트 판별 (기준선 오염 방지)
     */
    private boolean isSuspiciousContext(HCADContext context) {
        // isNewDevice - 새 디바이스는 의심
        if (context.getIsNewDevice() != null && context.getIsNewDevice()) {
            return true;
        }

        // failedLoginAttempts - 로그인 실패 이력 있으면 의심
        if (context.getFailedLoginAttempts() != null && context.getFailedLoginAttempts() > 0) {
            return true;
        }

        // 비정상적으로 짧은 요청 간격 (봇 의심)
        Long interval = context.getLastRequestInterval();
        if (interval != null && interval < 1000) {
            return true;
        }

        // 의심스러운 경로 패턴
        String path = context.getRequestPath();
        if (path != null && (path.contains("attack") || path.contains("exploit") ||
            path.contains("..") || path.contains("hack"))) {
            return true;
        }

        // localhost IP (내부 테스트 트래픽)
        String ip = context.getRemoteIp();
        if (ip != null && (ip.startsWith("127.") || ip.equals("localhost"))) {
            return true;
        }

        return false;
    }

    /**
     * 의심스러운 이유 문자열 생성 (디버깅용)
     */
    private String getSuspiciousReasons(HCADContext context) {
        List<String> reasons = new ArrayList<>();

        if (context.getIsNewDevice() != null && context.getIsNewDevice()) {
            reasons.add("newDevice");
        }
        if (context.getFailedLoginAttempts() != null && context.getFailedLoginAttempts() > 0) {
            reasons.add("failedLogins=" + context.getFailedLoginAttempts());
        }
        Long interval = context.getLastRequestInterval();
        if (interval != null && interval < 1000) {
            reasons.add("rapidRequest=" + interval + "ms");
        }
        String path = context.getRequestPath();
        if (path != null && (path.contains("attack") || path.contains("exploit") ||
            path.contains("..") || path.contains("hack"))) {
            reasons.add("suspiciousPath=" + path);
        }
        String ip = context.getRemoteIp();
        if (ip != null && (ip.startsWith("127.") || ip.equals("localhost"))) {
            reasons.add("localhostIP");
        }

        return String.join(", ", reasons);
    }
}
