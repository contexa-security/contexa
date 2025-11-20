package io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust;

import io.contexa.contexacoreenterprise.dashboard.core.AbstractMicrometerMetrics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 사용자 신뢰도 메트릭 수집기
 *
 * Zero Trust 아키텍처에서 사용자의 실시간 신뢰도 점수를 추적하고,
 * 고위험/저위험 사용자 수를 모니터링합니다.
 *
 * 주요 기능:
 * - 사용자별 신뢰도 점수 추적 (0.0-1.0)
 * - 고위험 사용자 감지 (< 0.5)
 * - 저위험 사용자 분류 (>= 0.7)
 * - 평균 신뢰도 점수 계산
 * - 신뢰도 변화 이벤트 추적
 *
 * @author contexa
 * @since 3.0.0
 */
@Slf4j
@Component
public class UserTrustMetrics extends AbstractMicrometerMetrics {

    // ===== 사용자 신뢰도 추적 =====
    private final Map<String, Double> userTrustScores = new ConcurrentHashMap<>();
    private final AtomicInteger monitoredUsersCount = new AtomicInteger(0);
    private final AtomicInteger highRiskUsersCount = new AtomicInteger(0);
    private final AtomicInteger lowRiskUsersCount = new AtomicInteger(0);

    // ===== 메트릭 카운터 =====
    private Counter trustScoreUpdatesCounter;
    private Counter trustScoreDowngradesCounter;
    private Counter trustScoreUpgradesCounter;

    public UserTrustMetrics(MeterRegistry registry) {
        super(registry, "zerotrust.trust");
    }

    @Override
    protected void initializeCounters() {
        // 신뢰도 점수 업데이트 횟수
        trustScoreUpdatesCounter = counterBuilder("score.updates", "Total number of trust score updates")
                .register(meterRegistry);

        // 신뢰도 하락 이벤트
        trustScoreDowngradesCounter = counterBuilder("score.downgrades", "Number of trust score downgrade events")
                .register(meterRegistry);

        // 신뢰도 상승 이벤트
        trustScoreUpgradesCounter = counterBuilder("score.upgrades", "Number of trust score upgrade events")
                .register(meterRegistry);
    }

    @Override
    protected void initializeTimers() {
        // UserTrustMetrics는 타이머 메트릭을 사용하지 않음
    }

    @Override
    protected void initializeGauges() {
        // 모니터링 중인 사용자 수
        Gauge.builder("zerotrust_trust_users_monitored", monitoredUsersCount, AtomicInteger::get)
                .description("Total number of users being monitored for trust score")
                .register(meterRegistry);

        // 고위험 사용자 수 (신뢰도 < 0.5)
        Gauge.builder("zerotrust_trust_users_high_risk", highRiskUsersCount, AtomicInteger::get)
                .description("Number of high-risk users (trust score < 0.5)")
                .register(meterRegistry);

        // 저위험 사용자 수 (신뢰도 >= 0.7)
        Gauge.builder("zerotrust_trust_users_low_risk", lowRiskUsersCount, AtomicInteger::get)
                .description("Number of low-risk users (trust score >= 0.7)")
                .register(meterRegistry);

        // 평균 신뢰도 점수
        Gauge.builder("zerotrust_trust_score_average", this, UserTrustMetrics::calculateAverageTrustScore)
                .description("Average trust score across all monitored users")
                .register(meterRegistry);
    }

    // ===== Public API =====

    /**
     * 사용자 신뢰도 점수 업데이트
     *
     * @param userId 사용자 ID
     * @param newTrustScore 새로운 신뢰도 점수 (0.0-1.0)
     */
    public void updateUserTrustScore(String userId, double newTrustScore) {
        // 점수 범위 검증
        double normalizedScore = Math.min(Math.max(newTrustScore, 0.0), 1.0);

        // 이전 점수 조회
        Double previousScore = userTrustScores.get(userId);
        boolean isNewUser = (previousScore == null);

        // 신뢰도 점수 업데이트
        userTrustScores.put(userId, normalizedScore);
        trustScoreUpdatesCounter.increment();

        // 신규 사용자 추가
        if (isNewUser) {
            monitoredUsersCount.incrementAndGet();
        }

        // 신뢰도 변화 추적
        if (!isNewUser) {
            if (normalizedScore < previousScore) {
                trustScoreDowngradesCounter.increment();
                log.debug("[TrustDowngrade] User: {}, {} -> {}", userId,
                    String.format("%.3f", previousScore), String.format("%.3f", normalizedScore));
            } else if (normalizedScore > previousScore) {
                trustScoreUpgradesCounter.increment();
                log.debug("[TrustUpgrade] User: {}, {} -> {}", userId,
                    String.format("%.3f", previousScore), String.format("%.3f", normalizedScore));
            }
        }

        // 위험 등급 재계산
        recalculateRiskCategories();

        log.debug("[TrustUpdate] User: {}, Score: {}", userId, String.format("%.3f", normalizedScore));
    }

    /**
     * 사용자 신뢰도 점수 조회
     *
     * @param userId 사용자 ID
     * @return 신뢰도 점수 (0.0-1.0), 없으면 null
     */
    public Double getUserTrustScore(String userId) {
        return userTrustScores.get(userId);
    }

    /**
     * 모든 사용자 신뢰도 점수 조회
     *
     * @return 사용자별 신뢰도 점수 맵
     */
    public Map<String, Double> getAllUserTrustScores() {
        return Map.copyOf(userTrustScores);
    }

    /**
     * 평균 신뢰도 점수 계산
     *
     * @return 평균 신뢰도 점수 (0.0-1.0)
     */
    public double calculateAverageTrustScore() {
        if (userTrustScores.isEmpty()) {
            return 1.0; // 사용자가 없으면 기본값 1.0
        }

        double sum = userTrustScores.values().stream()
                .mapToDouble(Double::doubleValue)
                .sum();

        return sum / userTrustScores.size();
    }

    /**
     * 위험 등급별 사용자 수 재계산
     */
    private void recalculateRiskCategories() {
        int highRisk = 0;
        int lowRisk = 0;

        for (double score : userTrustScores.values()) {
            if (score < 0.5) {
                highRisk++;
            } else if (score >= 0.7) {
                lowRisk++;
            }
        }

        highRiskUsersCount.set(highRisk);
        lowRiskUsersCount.set(lowRisk);
    }

    /**
     * 사용자 제거
     *
     * @param userId 사용자 ID
     */
    public void removeUser(String userId) {
        if (userTrustScores.remove(userId) != null) {
            monitoredUsersCount.decrementAndGet();
            recalculateRiskCategories();
            log.debug("[UserRemoved] User: {}", userId);
        }
    }

    // ===== AbstractMicrometerMetrics 구현 =====

    @Override
    public void reset() {
        userTrustScores.clear();
        monitoredUsersCount.set(0);
        highRiskUsersCount.set(0);
        lowRiskUsersCount.set(0);
        log.info("UserTrustMetrics 리셋 완료");
    }

    @Override
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("monitoredUsers", monitoredUsersCount.get());
        stats.put("highRiskUsers", highRiskUsersCount.get());
        stats.put("lowRiskUsers", lowRiskUsersCount.get());
        stats.put("averageTrustScore", calculateAverageTrustScore());
        stats.put("totalUpdates", trustScoreUpdatesCounter != null ? trustScoreUpdatesCounter.count() : 0.0);
        stats.put("downgrades", trustScoreDowngradesCounter != null ? trustScoreDowngradesCounter.count() : 0.0);
        stats.put("upgrades", trustScoreUpgradesCounter != null ? trustScoreUpgradesCounter.count() : 0.0);
        return stats;
    }

    @Override
    public double getHealthScore() {
        // 신뢰도 메트릭 자체의 건강도: 평균 신뢰도 점수 반환
        return calculateAverageTrustScore();
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        metrics.put("monitored_users", (double) monitoredUsersCount.get());
        metrics.put("high_risk_users", (double) highRiskUsersCount.get());
        metrics.put("low_risk_users", (double) lowRiskUsersCount.get());
        metrics.put("average_trust_score", calculateAverageTrustScore());
        return metrics;
    }

    @Override
    public void recordEvent(String eventType, Map<String, Object> metadata) {
        switch (eventType) {
            case "trust_score_update":
                String userId = (String) metadata.get("user_id");
                Double trustScore = metadata.containsKey("trust_score") ?
                    ((Number) metadata.get("trust_score")).doubleValue() : null;

                if (userId != null && trustScore != null) {
                    updateUserTrustScore(userId, trustScore);
                }
                break;

            case "user_removed":
                String removedUserId = (String) metadata.get("user_id");
                if (removedUserId != null) {
                    removeUser(removedUserId);
                }
                break;

            default:
                log.warn("Unknown event type: {}", eventType);
        }
    }
}
