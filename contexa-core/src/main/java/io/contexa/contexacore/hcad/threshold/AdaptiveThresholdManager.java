package io.contexa.contexacore.hcad.threshold;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.contexa.contexacore.hcad.constants.HCADRedisKeys;
import io.contexa.contexacore.hcad.feedback.FeedbackLoopSystem;
import io.contexa.contexacore.hcad.domain.ZeroTrustDecision;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * 적응형 임계값 관리자
 * 시간대, 사용자 패턴, 환경 변화에 따라 동적으로 임계값을 조정
 *
 * 주요 기능:
 * 1. 시간대별 임계값 조정 (업무시간/비업무시간)
 * 2. 사용자별 개인화된 임계값
 * 3. 환경 변화 감지 및 적응
 * 4. 성능 기반 자동 조정
 * 5. 계절성 패턴 반영
 *
 * @author AI3Security
 * @since 3.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdaptiveThresholdManager {

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired(required = false)
    private FeedbackLoopSystem feedbackSystem;

    @Value("${hcad.threshold.base:0.7}")
    private double baseThreshold;

    @Value("${hcad.threshold.min:0.3}")
    private double minThreshold;

    @Value("${hcad.threshold.max:0.95}")
    private double maxThreshold;

    @Value("${hcad.threshold.adjustment.rate:0.01}")
    private double adjustmentRate;

    @Value("${hcad.threshold.sensitivity:1.0}")
    private double sensitivityFactor;

    // 사용자별 임계값 저장소
    private final Map<String, UserThresholdProfile> userProfiles = new ConcurrentHashMap<>();

    // 전역 임계값 프로파일
    private final GlobalThresholdProfile globalProfile = new GlobalThresholdProfile();

    // 환경 컨텍스트
    private final EnvironmentContext environmentContext = new EnvironmentContext();

    // 성능 추적기
    private final PerformanceTracker performanceTracker = new PerformanceTracker();

    /**
     * 사용자의 현재 임계값 조회
     */
    public ThresholdConfiguration getThreshold(String userId, ThresholdContext context) {
        try {
            // 1. 사용자 프로파일 조회 또는 생성
            UserThresholdProfile profile = getUserProfile(userId);

            // 2. 기본 임계값 계산
            double baseValue = calculateBaseThreshold(profile, context);

            // 3. 시간대별 조정
            double timeAdjusted = applyTimeAdjustment(baseValue, context);

            // 4. 위험 수준별 조정
            double riskAdjusted = applyRiskAdjustment(timeAdjusted, context);

            // 5. 계절성 조정
            double seasonalAdjusted = applySeasonalAdjustment(riskAdjusted, context);

            // 6. 환경 요인 조정
            double environmentAdjusted = applyEnvironmentAdjustment(seasonalAdjusted, context);

            // 7. 최종 임계값 정규화
            double finalThreshold = normalize(environmentAdjusted);

            // 8. 구성 객체 생성
            ThresholdConfiguration config = ThresholdConfiguration.builder()
                .userId(userId)
                .baseThreshold(baseValue)
                .adjustedThreshold(finalThreshold)
                .timeFactors(calculateTimeFactors(context))
                .riskFactors(calculateRiskFactors(context))
                .environmentFactors(calculateEnvironmentFactors())
                .confidence(profile.getConfidence())
                .lastUpdated(LocalDateTime.now())
                .build();

            // 9. 프로파일 업데이트
            profile.recordThresholdUsage(finalThreshold, context);

            // 10. Redis에 캐시
            cacheThreshold(userId, config);

            return config;

        } catch (Exception e) {
            log.error("Failed to get adaptive threshold for user: {}", userId, e);
            return getDefaultConfiguration(userId);
        }
    }

    /**
     * 임계값 조정 (피드백 기반)
     */
    public void adjustThreshold(String userId, ThresholdAdjustment adjustment) {
        UserThresholdProfile profile = getUserProfile(userId);

        switch (adjustment.getType()) {
            case INCREASE_SENSITIVITY:
                // 민감도 증가 (임계값 감소)
                profile.adjustBaseThreshold(-adjustment.getDelta());
                log.info("Increased sensitivity for user {}: threshold decreased by {}",
                        userId, adjustment.getDelta());
                break;

            case DECREASE_SENSITIVITY:
                // 민감도 감소 (임계값 증가)
                profile.adjustBaseThreshold(adjustment.getDelta());
                log.info("Decreased sensitivity for user {}: threshold increased by {}",
                        userId, adjustment.getDelta());
                break;

            case RESET_TO_DEFAULT:
                // 기본값으로 리셋
                profile.resetToDefault(baseThreshold);
                log.info("Reset threshold to default for user {}", userId);
                break;

            case OPTIMIZE_FOR_ACCURACY:
                // 정확도 최적화
                optimizeForAccuracy(profile);
                break;

            case OPTIMIZE_FOR_RECALL:
                // 재현율 최적화 (미탐 최소화)
                optimizeForRecall(profile);
                break;
        }

        // Redis에 저장
        saveProfile(userId, profile);
    }
    // ===== Private Methods =====

    private UserThresholdProfile getUserProfile(String userId) {
        return userProfiles.computeIfAbsent(userId, k -> {
            // Redis에서 로드 시도
            UserThresholdProfile cached = loadProfileFromRedis(userId);
            if (cached != null) {
                return cached;
            }

            // 새 프로파일 생성
            return new UserThresholdProfile(userId, baseThreshold);
        });
    }

    private double calculateBaseThreshold(UserThresholdProfile profile, ThresholdContext context) {
        // 사용자의 기본 임계값
        double userBase = profile.getBaseThreshold();

        // 히스토리 기반 조정
        double historyFactor = profile.calculateHistoryFactor();

        // 신뢰도 기반 조정
        double confidenceFactor = profile.getConfidence();

        return userBase * historyFactor * confidenceFactor;
    }

    private double applyTimeAdjustment(double threshold, ThresholdContext context) {
        try {
            // 개선: HCADRedisKeys 사용
            String workHoursKey = HCADRedisKeys.thresholdWorkHours(context.getUserId());
            Map<String, Object> workHours = (Map<String, Object>) redisTemplate.opsForValue().get(workHoursKey);

            LocalTime currentTime = LocalTime.now();
            int hour = currentTime.getHour();
            int dayOfWeek = LocalDateTime.now().getDayOfWeek().getValue();
            double timeWeight = 1.0;

            if (workHours != null && !workHours.isEmpty()) {
                // 학습된 사용자 패턴 사용
                Integer startHour = (Integer) workHours.get("startHour");
                Integer endHour = (Integer) workHours.get("endHour");
                Boolean worksWeekend = (Boolean) workHours.get("worksWeekend");

                if (startHour != null && endHour != null) {
                    if (hour >= startHour && hour <= endHour) {
                        timeWeight = 1.0;
                    } else if (hour > endHour && hour <= 23) {
                        timeWeight = (Double) workHours.getOrDefault("eveningWeight", 0.95);
                    } else if (hour >= 0 && hour < startHour) {
                        timeWeight = (Double) workHours.getOrDefault("nightWeight", 0.85);
                    }
                }

                if (dayOfWeek >= 6 && !Boolean.TRUE.equals(worksWeekend)) {
                    timeWeight *= (Double) workHours.getOrDefault("weekendWeight", 0.9);
                }
            } else {
                // 기본 패턴 (학습 전)
                if (hour >= 9 && hour <= 18) {
                    timeWeight = 1.0;
                } else if (hour >= 19 && hour <= 23) {
                    timeWeight = 0.95;
                } else if (hour >= 0 && hour <= 6) {
                    timeWeight = 0.85;
                } else {
                    timeWeight = 0.98;
                }

                if (dayOfWeek >= 6) {
                    timeWeight *= 0.9;
                }
            }

            return threshold * timeWeight;

        } catch (Exception e) {
            log.error("Failed to apply time-based adjustment", e);
            return threshold * 0.95;
        }
    }

    private double applyRiskAdjustment(double threshold, ThresholdContext context) {
        RiskLevel riskLevel = context.getRiskLevel();

        switch (riskLevel) {
            case CRITICAL:
                return threshold * 0.7; // 매우 엄격
            case HIGH:
                return threshold * 0.85;
            case MEDIUM:
                return threshold * 0.95;
            case LOW:
                return threshold * 1.05;
            default:
                return threshold;
        }
    }

    private double applySeasonalAdjustment(double threshold, ThresholdContext context) {
        try {
            // 개선: HCADRedisKeys 사용
            String seasonalKey = HCADRedisKeys.thresholdSeasonalPatterns();
            Map<String, Object> seasonalPatterns = (Map<String, Object>) redisTemplate.opsForValue().get(seasonalKey);

            int month = LocalDateTime.now().getMonthValue();
            int dayOfMonth = LocalDateTime.now().getDayOfMonth();
            double seasonalFactor = 1.0;

            if (seasonalPatterns != null && !seasonalPatterns.isEmpty()) {
                // 학습된 조직 패턴 사용
                String monthKey = "month_" + month;
                Double monthFactor = (Double) seasonalPatterns.get(monthKey);
                if (monthFactor != null) {
                    seasonalFactor = monthFactor;
                }

                // 특별 기간 처리
                List<Map<String, Object>> specialPeriods = (List<Map<String, Object>>) seasonalPatterns.get("specialPeriods");
                if (specialPeriods != null) {
                    for (Map<String, Object> period : specialPeriods) {
                        Integer startMonth = (Integer) period.get("startMonth");
                        Integer endMonth = (Integer) period.get("endMonth");
                        Integer startDay = (Integer) period.get("startDay");
                        Integer endDay = (Integer) period.get("endDay");
                        Double factor = (Double) period.get("factor");

                        if (isInPeriod(month, dayOfMonth, startMonth, endMonth, startDay, endDay)) {
                            seasonalFactor = factor != null ? factor : seasonalFactor;
                            break;
                        }
                    }
                }
            } else {
                // 기본 계절성 패턴
                if ((month == 12 && dayOfMonth > 20) || (month == 1 && dayOfMonth < 10)) {
                    seasonalFactor = 0.9;
                } else if (month == 7 || month == 8) {
                    seasonalFactor = 0.95;
                } else if ((month == 3 && dayOfMonth > 25) || (month == 9 && dayOfMonth > 25)) {
                    seasonalFactor = 0.92;
                }
            }

            return threshold * seasonalFactor;

        } catch (Exception e) {
            log.error("Failed to apply seasonal adjustment", e);
            return threshold;
        }
    }

    private boolean isInPeriod(int currentMonth, int currentDay, Integer startMonth, Integer endMonth,
                              Integer startDay, Integer endDay) {
        if (startMonth == null || endMonth == null) {
            return false;
        }

        if (startMonth.equals(endMonth)) {
            return currentMonth == startMonth &&
                   (startDay == null || currentDay >= startDay) &&
                   (endDay == null || currentDay <= endDay);
        } else {
            return (currentMonth == startMonth && (startDay == null || currentDay >= startDay)) ||
                   (currentMonth == endMonth && (endDay == null || currentDay <= endDay)) ||
                   (currentMonth > startMonth && currentMonth < endMonth);
        }
    }

    private double applyEnvironmentAdjustment(double threshold, ThresholdContext context) {
        try {
            EnvironmentFactors factors = environmentContext.getFactors();
            double adjustment = 1.0;

            // 시스템 부하 기반 조정 (동적)
            double systemLoad = factors.getSystemLoad();
            if (systemLoad > 0.9) {
                adjustment *= 1.15; // 매우 높은 부하 - 성능 우선
            } else if (systemLoad > 0.8) {
                adjustment *= 1.1;
            } else if (systemLoad > 0.7) {
                adjustment *= 1.05;
            }

            // 최근 공격 빈도 기반 조정 (동적)
            int attackFrequency = factors.getRecentAttackFrequency();
            if (attackFrequency > 50) {
                adjustment *= 0.7; // 매우 높은 공격 빈도 - 보안 우선
            } else if (attackFrequency > 20) {
                adjustment *= 0.8;
            } else if (attackFrequency > 10) {
                adjustment *= 0.85;
            }

            // 네트워크 이상 감지 (동적)
            if (factors.isNetworkAnomaly()) {
                double anomalySeverity = factors.getAnomalySeverity();
                if (anomalySeverity > 0.8) {
                    adjustment *= 0.75;
                } else if (anomalySeverity > 0.5) {
                    adjustment *= 0.85;
                } else {
                    adjustment *= 0.9;
                }
            }

            // 전역 위협 레벨
            String globalThreatLevel = factors.getGlobalThreatLevel();
            if ("CRITICAL".equals(globalThreatLevel)) {
                adjustment *= 0.7;
            } else if ("HIGH".equals(globalThreatLevel)) {
                adjustment *= 0.85;
            } else if ("ELEVATED".equals(globalThreatLevel)) {
                adjustment *= 0.95;
            }

            return threshold * adjustment;

        } catch (Exception e) {
            log.error("Failed to apply environment adjustment", e);
            return threshold * 0.9; // 안전한 기본값 (약간 엄격)
        }
    }

    private double normalize(double threshold) {
        // 민감도 팩터 적용
        threshold *= sensitivityFactor;

        // 최소/최대 범위 적용
        return Math.max(minThreshold, Math.min(maxThreshold, threshold));
    }

    private Map<String, Double> calculateTimeFactors(ThresholdContext context) {
        Map<String, Double> factors = new HashMap<>();
        factors.put("hour_of_day", (double) LocalTime.now().getHour() / 24.0);
        factors.put("day_of_week", (double) LocalDateTime.now().getDayOfWeek().getValue() / 7.0);
        factors.put("is_weekend", LocalDateTime.now().getDayOfWeek().getValue() >= 6 ? 1.0 : 0.0);
        return factors;
    }

    private Map<String, Double> calculateRiskFactors(ThresholdContext context) {
        Map<String, Double> factors = new HashMap<>();
        factors.put("risk_level", context.getRiskLevel().getValue());
        factors.put("threat_score", context.getThreatScore());
        factors.put("anomaly_count", (double) context.getRecentAnomalyCount());
        return factors;
    }

    private Map<String, Double> calculateEnvironmentFactors() {
        EnvironmentFactors env = environmentContext.getFactors();
        Map<String, Double> factors = new HashMap<>();
        factors.put("system_load", env.getSystemLoad());
        factors.put("attack_frequency", (double) env.getRecentAttackFrequency());
        factors.put("network_anomaly", env.isNetworkAnomaly() ? 1.0 : 0.0);
        return factors;
    }

    private void cacheThreshold(String userId, ThresholdConfiguration config) {
        if (redisTemplate != null) {
            // 개선: HCADRedisKeys 사용
            String key = HCADRedisKeys.thresholdConfig(userId);
            redisTemplate.opsForValue().set(key, config, Duration.ofMinutes(5));
        }
    }

    private ThresholdConfiguration getDefaultConfiguration(String userId) {
        return ThresholdConfiguration.builder()
            .userId(userId)
            .baseThreshold(baseThreshold)
            .adjustedThreshold(baseThreshold)
            .confidence(0.5)
            .lastUpdated(LocalDateTime.now())
            .build();
    }

    private void saveProfile(String userId, UserThresholdProfile profile) {
        if (redisTemplate != null) {
            // 개선: HCADRedisKeys 사용
            String key = HCADRedisKeys.thresholdProfile(userId);
            redisTemplate.opsForValue().set(key, profile, Duration.ofDays(30));
        }
    }

    private UserThresholdProfile loadProfileFromRedis(String userId) {
        if (redisTemplate != null) {
            // 개선: HCADRedisKeys 사용
            String key = HCADRedisKeys.thresholdProfile(userId);
            return (UserThresholdProfile) redisTemplate.opsForValue().get(key);
        }
        return null;
    }

    private void broadcastGlobalUpdate() {
        if (redisTemplate != null) {
            redisTemplate.convertAndSend("threshold:global:update", globalProfile);
        }
    }

    private boolean shouldAdjustGlobally(PerformanceMetrics metrics) {
        // F1 스코어가 낮거나 오탐률이 높으면 조정 필요
        return metrics.getF1Score() < 0.7 || metrics.getFalsePositiveRate() > 0.3;
    }

    private void adjustGlobalThresholds(PerformanceMetrics metrics) {
        if (metrics.getFalsePositiveRate() > 0.3) {
            // 오탐이 많으면 임계값 증가
            globalProfile.adjustBase(0.05);
            log.info("Increased global threshold due to high false positive rate");
        } else if (metrics.getFalseNegativeRate() > 0.1) {
            // 미탐이 많으면 임계값 감소
            globalProfile.adjustBase(-0.05);
            log.info("Decreased global threshold due to high false negative rate");
        }
    }

    private boolean shouldAdjustUser(UserThresholdProfile profile, PerformanceMetrics metrics) {
        // 최근 조정 이후 충분한 시간이 지났는지
        Duration timeSinceLastAdjustment = Duration.between(
            profile.getLastAdjustment(), LocalDateTime.now());

        return timeSinceLastAdjustment.toMinutes() > 30 &&
               (profile.needsAdjustment() || metrics.getF1Score() < 0.75);
    }

    private void adjustUserThreshold(String userId, UserThresholdProfile profile,
                                    PerformanceMetrics metrics) {
        double adjustment = calculateOptimalAdjustment(profile, metrics);
        profile.adjustBaseThreshold(adjustment);

        log.info("Adjusted threshold for user {} by {}", userId, adjustment);
        saveProfile(userId, profile);
    }

    private double calculateOptimalAdjustment(UserThresholdProfile profile,
                                             PerformanceMetrics metrics) {
        // 간단한 조정 알고리즘
        double targetF1 = 0.85;
        double currentF1 = metrics.getF1Score();
        double gap = targetF1 - currentF1;

        return gap * adjustmentRate * sensitivityFactor;
    }

    private void optimizeForAccuracy(UserThresholdProfile profile) {
        // 정확도 최적화: 오탐과 미탐의 균형
        profile.setOptimizationMode(OptimizationMode.ACCURACY);
        profile.adjustBaseThreshold(0.0); // 중간값으로 조정
    }

    private void optimizeForRecall(UserThresholdProfile profile) {
        // 재현율 최적화: 미탐 최소화 (임계값 감소)
        profile.setOptimizationMode(OptimizationMode.RECALL);
        profile.adjustBaseThreshold(-0.1);
    }

    private void adaptToEnvironmentChange() {
        // 환경 변화에 대한 전역 적응
        EnvironmentFactors factors = environmentContext.getFactors();

        if (factors.getSystemLoad() > 0.9) {
            // 시스템 과부하 - 임시로 덜 엄격하게
            globalProfile.setTemporaryAdjustment(0.1);
        } else if (factors.getRecentAttackFrequency() > 20) {
            // 공격 증가 - 임시로 더 엄격하게
            globalProfile.setTemporaryAdjustment(-0.15);
        }
    }

    // ===== Inner Classes =====

    public static class ThresholdConfiguration {
        private final String userId;
        private final double baseThreshold;
        private final double adjustedThreshold;
        private final Map<String, Double> timeFactors;
        private final Map<String, Double> riskFactors;
        private final Map<String, Double> environmentFactors;
        private final double confidence;
        private final LocalDateTime lastUpdated;

        private ThresholdConfiguration(Builder builder) {
            this.userId = builder.userId;
            this.baseThreshold = builder.baseThreshold;
            this.adjustedThreshold = builder.adjustedThreshold;
            this.timeFactors = builder.timeFactors;
            this.riskFactors = builder.riskFactors;
            this.environmentFactors = builder.environmentFactors;
            this.confidence = builder.confidence;
            this.lastUpdated = builder.lastUpdated;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String userId;
            private double baseThreshold;
            private double adjustedThreshold;
            private Map<String, Double> timeFactors;
            private Map<String, Double> riskFactors;
            private Map<String, Double> environmentFactors;
            private double confidence;
            private LocalDateTime lastUpdated;

            public Builder userId(String userId) {
                this.userId = userId;
                return this;
            }

            public Builder baseThreshold(double threshold) {
                this.baseThreshold = threshold;
                return this;
            }

            public Builder adjustedThreshold(double threshold) {
                this.adjustedThreshold = threshold;
                return this;
            }

            public Builder timeFactors(Map<String, Double> factors) {
                this.timeFactors = factors;
                return this;
            }

            public Builder riskFactors(Map<String, Double> factors) {
                this.riskFactors = factors;
                return this;
            }

            public Builder environmentFactors(Map<String, Double> factors) {
                this.environmentFactors = factors;
                return this;
            }

            public Builder confidence(double confidence) {
                this.confidence = confidence;
                return this;
            }

            public Builder lastUpdated(LocalDateTime time) {
                this.lastUpdated = time;
                return this;
            }

            public ThresholdConfiguration build() {
                return new ThresholdConfiguration(this);
            }
        }

        // Getters
        public double getAdjustedThreshold() { return adjustedThreshold; }
        public double getConfidence() { return confidence; }
        public double getSimilarityThreshold() { return adjustedThreshold; }
        public double getAdjustmentFactor() { return confidence; }
    }

    public static class ThresholdContext {
        private String userId;
        private RiskLevel riskLevel = RiskLevel.MEDIUM;
        private double threatScore = 0.5;
        private int recentAnomalyCount = 0;
        private boolean isHighRiskPeriod = false;
        private Map<String, Object> additionalContext = new HashMap<>();

        // Getters and setters
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public RiskLevel getRiskLevel() { return riskLevel; }
        public void setRiskLevel(RiskLevel riskLevel) { this.riskLevel = riskLevel; }

        public double getThreatScore() { return threatScore; }
        public void setThreatScore(double threatScore) { this.threatScore = threatScore; }

        public int getRecentAnomalyCount() { return recentAnomalyCount; }
        public void setRecentAnomalyCount(int count) { this.recentAnomalyCount = count; }

        public boolean isHighRiskPeriod() { return isHighRiskPeriod; }
        public void setHighRiskPeriod(boolean highRiskPeriod) { this.isHighRiskPeriod = highRiskPeriod; }

        public Map<String, Object> getAdditionalContext() { return additionalContext; }
        public void setAdditionalContext(Map<String, Object> context) { this.additionalContext = context; }
    }

    public static class ThresholdAdjustment {
        private final AdjustmentType type;
        private final double delta;
        private final String reason;

        public ThresholdAdjustment(AdjustmentType type, double delta, String reason) {
            this.type = type;
            this.delta = delta;
            this.reason = reason;
        }

        public AdjustmentType getType() { return type; }
        public double getDelta() { return delta; }
    }

    public enum AdjustmentType {
        INCREASE_SENSITIVITY,
        DECREASE_SENSITIVITY,
        RESET_TO_DEFAULT,
        OPTIMIZE_FOR_ACCURACY,
        OPTIMIZE_FOR_RECALL
    }

    public enum RiskLevel {
        LOW(0.25),
        MEDIUM(0.5),
        HIGH(0.75),
        CRITICAL(1.0);

        private final double value;

        RiskLevel(double value) {
            this.value = value;
        }

        public double getValue() { return value; }
    }

    private enum OptimizationMode {
        ACCURACY,
        RECALL,
        PRECISION,
        BALANCED
    }

    @NoArgsConstructor(access = AccessLevel.PRIVATE) // Jackson 역직렬화용
    @AllArgsConstructor(access = AccessLevel.PRIVATE) // 내부 생성자용
    @JsonIgnoreProperties(ignoreUnknown = true) // 기존 Redis 데이터 호환성
    private static class UserThresholdProfile {
        private String userId;
        private double baseThreshold;
        private double confidence;
        private LocalDateTime lastAdjustment;
        private List<Double> thresholdHistory;
        private Map<LocalDateTime, Double> performanceHistory;
        private OptimizationMode optimizationMode;
        private int adjustmentCount;

        public UserThresholdProfile(String userId, double baseThreshold) {
            this.userId = userId;
            this.baseThreshold = baseThreshold;
            this.confidence = 0.5;
            this.lastAdjustment = LocalDateTime.now();
            this.thresholdHistory = new ArrayList<>();
            this.performanceHistory = new HashMap<>();
            this.optimizationMode = OptimizationMode.BALANCED;
            this.adjustmentCount = 0;
        }

        public void adjustBaseThreshold(double delta) {
            thresholdHistory.add(baseThreshold);
            baseThreshold = Math.max(0.3, Math.min(0.95, baseThreshold + delta));
            lastAdjustment = LocalDateTime.now();
            adjustmentCount++;
        }

        public void resetToDefault(double defaultValue) {
            thresholdHistory.clear();
            baseThreshold = defaultValue;
            confidence = 0.5;
            adjustmentCount = 0;
        }

        public double calculateHistoryFactor() {
            if (thresholdHistory.isEmpty()) return 1.0;

            // 최근 임계값 변화 추세 분석
            int recentCount = Math.min(10, thresholdHistory.size());
            List<Double> recent = thresholdHistory.subList(
                thresholdHistory.size() - recentCount, thresholdHistory.size());

            double trend = 0.0;
            for (int i = 1; i < recent.size(); i++) {
                trend += recent.get(i) - recent.get(i-1);
            }

            // 추세가 안정적이면 신뢰도 증가
            if (Math.abs(trend) < 0.01) {
                confidence = Math.min(1.0, confidence + 0.01);
                return 1.0;
            }

            // 추세가 불안정하면 신뢰도 감소
            confidence = Math.max(0.3, confidence - 0.01);
            return 1.0 + (trend * 0.1); // 추세 반영
        }

        public boolean needsAdjustment() {
            // 조정이 너무 자주 일어나면 안 됨
            if (adjustmentCount > 10) {
                return false;
            }

            // 신뢰도가 낮으면 조정 필요
            return confidence < 0.6;
        }

        public void recordThresholdUsage(double threshold, ThresholdContext context) {
            // 사용 기록 저장
            performanceHistory.put(LocalDateTime.now(), threshold);

            // 오래된 기록 제거
            LocalDateTime cutoff = LocalDateTime.now().minusDays(7);
            performanceHistory.entrySet().removeIf(e -> e.getKey().isBefore(cutoff));
        }

        public void setOptimizationMode(OptimizationMode mode) {
            this.optimizationMode = mode;
        }

        // Getters
        public double getBaseThreshold() { return baseThreshold; }
        public double getConfidence() { return confidence; }
        public double getConfidenceLevel() { return confidence; }
        public LocalDateTime getLastAdjustment() { return lastAdjustment; }

        // 신뢰도 조정
        public void adjustConfidenceLevel(double delta) {
            this.confidence = Math.max(0.0, Math.min(1.0, this.confidence + delta));
        }

        // 임계값 업데이트
        public void updateBaseThreshold(double newThreshold) {
            thresholdHistory.add(this.baseThreshold);
            this.baseThreshold = Math.max(0.1, Math.min(0.9, newThreshold));
            this.lastAdjustment = LocalDateTime.now();
            this.adjustmentCount++;
        }
    }

    private static class GlobalThresholdProfile {
        private double baseGlobalThreshold = 0.7;
        private double temporaryAdjustment = 0.0;
        private LocalDateTime temporaryUntil;
        private Map<String, Double> categoryThresholds = new HashMap<>();

        public void updateThresholds(Map<String, Double> thresholds) {
            categoryThresholds.putAll(thresholds);
        }

        public void adjustBase(double delta) {
            baseGlobalThreshold = Math.max(0.3, Math.min(0.95, baseGlobalThreshold + delta));
        }

        public void setTemporaryAdjustment(double adjustment) {
            temporaryAdjustment = adjustment;
            temporaryUntil = LocalDateTime.now().plusHours(1);
        }

        public double getEffectiveThreshold() {
            if (temporaryUntil != null && LocalDateTime.now().isBefore(temporaryUntil)) {
                return baseGlobalThreshold + temporaryAdjustment;
            }
            return baseGlobalThreshold;
        }
    }

    private static class EnvironmentContext {
        private EnvironmentFactors currentFactors = new EnvironmentFactors();
        private EnvironmentFactors previousFactors = new EnvironmentFactors();
        private LocalDateTime lastUpdate = LocalDateTime.now();

        public void update() {
            previousFactors = currentFactors;
            currentFactors = collectCurrentFactors();
            lastUpdate = LocalDateTime.now();
        }

        private EnvironmentFactors collectCurrentFactors() {
            EnvironmentFactors factors = new EnvironmentFactors();

            // 시스템 부하 수집 (시뮬레이션)
            factors.setSystemLoad(Math.random() * 0.5 + 0.3);

            // 공격 빈도 수집 (시뮬레이션)
            factors.setRecentAttackFrequency((int)(Math.random() * 20));

            // 네트워크 이상 감지 (시뮬레이션)
            factors.setNetworkAnomaly(Math.random() < 0.1);

            return factors;
        }

        public boolean hasSignificantChange() {
            double loadChange = Math.abs(currentFactors.getSystemLoad() -
                                       previousFactors.getSystemLoad());
            int attackChange = Math.abs(currentFactors.getRecentAttackFrequency() -
                                      previousFactors.getRecentAttackFrequency());

            return loadChange > 0.3 || attackChange > 10 ||
                   currentFactors.isNetworkAnomaly() != previousFactors.isNetworkAnomaly();
        }

        public EnvironmentFactors getFactors() { return currentFactors; }
    }

    private static class EnvironmentFactors {
        private double systemLoad = 0.5;
        private int recentAttackFrequency = 0;
        private boolean networkAnomaly = false;
        private double anomalySeverity = 0.0;
        private String globalThreatLevel = "NORMAL";

        // Getters and setters
        public double getSystemLoad() { return systemLoad; }
        public void setSystemLoad(double load) { this.systemLoad = load; }

        public int getRecentAttackFrequency() { return recentAttackFrequency; }
        public void setRecentAttackFrequency(int frequency) { this.recentAttackFrequency = frequency; }

        public boolean isNetworkAnomaly() { return networkAnomaly; }
        public void setNetworkAnomaly(boolean anomaly) { this.networkAnomaly = anomaly; }

        public double getAnomalySeverity() { return anomalySeverity; }
        public void setAnomalySeverity(double severity) { this.anomalySeverity = severity; }

        public String getGlobalThreatLevel() { return globalThreatLevel; }
        public void setGlobalThreatLevel(String level) { this.globalThreatLevel = level; }
    }

    private static class PerformanceTracker {
        private final List<PerformanceMetrics> metricsHistory = new ArrayList<>();
        private PerformanceMetrics currentMetrics = new PerformanceMetrics();

        public PerformanceMetrics getRecentMetrics() {
            // 시뮬레이션된 메트릭 반환
            currentMetrics = generateSimulatedMetrics();
            metricsHistory.add(currentMetrics);

            // 최대 100개 유지
            if (metricsHistory.size() > 100) {
                metricsHistory.remove(0);
            }

            return currentMetrics;
        }

        private PerformanceMetrics generateSimulatedMetrics() {
            PerformanceMetrics metrics = new PerformanceMetrics();
            metrics.setF1Score(0.75 + Math.random() * 0.2);
            metrics.setFalsePositiveRate(0.1 + Math.random() * 0.3);
            metrics.setFalseNegativeRate(0.05 + Math.random() * 0.1);
            return metrics;
        }
    }

    private static class PerformanceMetrics {
        private double f1Score;
        private double falsePositiveRate;
        private double falseNegativeRate;

        // Getters and setters
        public double getF1Score() { return f1Score; }
        public void setF1Score(double score) { this.f1Score = score; }

        public double getFalsePositiveRate() { return falsePositiveRate; }
        public void setFalsePositiveRate(double rate) { this.falsePositiveRate = rate; }

        public double getFalseNegativeRate() { return falseNegativeRate; }
        public void setFalseNegativeRate(double rate) { this.falseNegativeRate = rate; }
    }

    /**
     * HCADFeedbackOrchestrator 에서 사용하는 메소드들
     */
    public ThresholdConfiguration getThresholdRecommendation(String userId, String layerName) {
        try {
            UserThresholdProfile userProfile = getUserProfile(userId);
            GlobalThresholdProfile globalProfile = getGlobalProfile();

            double baseThreshold = userProfile.getBaseThreshold();
            double adjustedThreshold = calculateDynamicThreshold(userId, new ThresholdContext());

            return ThresholdConfiguration.builder()
                .userId(userId)
                .baseThreshold(baseThreshold)
                .adjustedThreshold(adjustedThreshold)
                .confidence(userProfile.getConfidenceLevel())
                .lastUpdated(LocalDateTime.now())
                .build();

        } catch (Exception e) {
            log.warn("Failed to get threshold recommendation for user: {} layer: {}", userId, layerName, e);
            // 기본값 반환
            return ThresholdConfiguration.builder()
                .userId(userId)
                .baseThreshold(0.5)
                .adjustedThreshold(0.5)
                .confidence(0.7)
                .lastUpdated(LocalDateTime.now())
                .build();
        }
    }

    /**
     * ZeroTrustDecision을 기반으로 임계값 업데이트
     */
    public void updateThresholdsFromDecision(String userId, ZeroTrustDecision decision) {
        try {
            log.debug("Updating thresholds for user: {} based on decision", userId);

            // 결정 결과에 따른 임계값 조정
            double adjustmentFactor = calculateAdjustmentFactor(decision);

            UserThresholdProfile profile = getUserProfile(userId);
            double newThreshold = profile.getBaseThreshold() + adjustmentFactor;

            // 임계값 범위 제한 (0.1 ~ 0.9)
            newThreshold = Math.max(0.1, Math.min(0.9, newThreshold));

            profile.updateBaseThreshold(newThreshold);
            saveProfile(userId, profile);

            log.debug("Updated threshold for user: {} to: {}", userId, newThreshold);

        } catch (Exception e) {
            log.error("Failed to update thresholds from decision for user: {}", userId, e);
        }
    }

    private double calculateAdjustmentFactor(ZeroTrustDecision decision) {
        // 결정 유형에 따른 조정 계수 계산
        switch (decision.getFinalAction()) {
            case ALLOW:
                return decision.getConfidence() > 0.8 ? -0.01 : 0.0; // 신뢰도 높은 허용 시 임계값 약간 낮춤
            case BLOCK:
                return decision.getConfidence() > 0.8 ? 0.02 : 0.01; // 거부 시 임계값 높임
            case MITIGATE:
                return 0.005; // 도전 시 임계값 약간 높임
            default:
                return 0.0;
        }
    }

    public void applyLearningFeedback(Map<String, Object> thresholdAdjustments) {
        try {
            if (thresholdAdjustments == null || thresholdAdjustments.isEmpty()) {
                return;
            }

            String userId = (String) thresholdAdjustments.get("userId");
            if (userId == null) {
                log.warn("No userId provided in threshold adjustments");
                return;
            }

            UserThresholdProfile profile = getUserProfile(userId);

            // 증가 조정
            if (thresholdAdjustments.containsKey("increase")) {
                double increase = ((Number) thresholdAdjustments.get("increase")).doubleValue();
                profile.adjustBaseThreshold(increase);
                log.debug("Applied threshold increase {} for user {}", increase, userId);
            }

            // 감소 조정
            if (thresholdAdjustments.containsKey("decrease")) {
                double decrease = ((Number) thresholdAdjustments.get("decrease")).doubleValue();
                profile.adjustBaseThreshold(-decrease);
                log.debug("Applied threshold decrease {} for user {}", decrease, userId);
            }

            // 유지 (신뢰도 강화)
            if (thresholdAdjustments.containsKey("maintain")) {
                double confidenceBoost = ((Number) thresholdAdjustments.get("maintain")).doubleValue();
                profile.adjustConfidenceLevel(confidenceBoost * 0.1); // 10% 신뢰도 증가
                log.debug("Applied confidence boost {} for user {}", confidenceBoost, userId);
            }

            saveProfile(userId, profile);

        } catch (Exception e) {
            log.error("Failed to apply learning feedback", e);
        }
    }

    /**
     * 글로벌 프로필 조회
     */
    private GlobalThresholdProfile getGlobalProfile() {
        return globalProfile;
    }

    /**
     * 동적 임계값 계산
     */
    private double calculateDynamicThreshold(String userId, ThresholdContext context) {
        try {
            UserThresholdProfile userProfile = getUserProfile(userId);
            double baseThreshold = userProfile.getBaseThreshold();
            double adjustment = 0.0;

            // 위험도에 따른 조정
            if (context.getThreatScore() > 0.7) {
                adjustment -= 0.1; // 임계값 낮춤 (더 민감하게)
            } else if (context.getThreatScore() < 0.3) {
                adjustment += 0.05; // 임계값 높임 (덜 민감하게)
            }

            // 최근 이상 탐지 수에 따른 조정
            if (context.getRecentAnomalyCount() > 5) {
                adjustment -= 0.05;
            }

            return Math.max(0.1, Math.min(0.9, baseThreshold + adjustment));

        } catch (Exception e) {
            log.warn("Failed to calculate dynamic threshold for user: {}", userId, e);
            return 0.5; // 기본값
        }
    }

    /**
     * 임계값 추천 클래스
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ThresholdRecommendation {
        private String userId;
        private String layerName;
        private double recommendedThreshold;
        private double confidence;
        private String reasoning;
        private LocalDateTime timestamp;
    }
}