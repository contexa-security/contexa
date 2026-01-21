package io.contexa.contexacoreenterprise.dashboard.metrics.zerotrust;

import io.contexa.contexacoreenterprise.dashboard.core.AbstractMicrometerMetrics;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
public class UserTrustMetrics extends AbstractMicrometerMetrics {

    private final Map<String, Double> userTrustScores = new ConcurrentHashMap<>();
    private final AtomicInteger monitoredUsersCount = new AtomicInteger(0);
    private final AtomicInteger highRiskUsersCount = new AtomicInteger(0);
    private final AtomicInteger lowRiskUsersCount = new AtomicInteger(0);

    private Counter trustScoreUpdatesCounter;
    private Counter trustScoreDowngradesCounter;
    private Counter trustScoreUpgradesCounter;

    public UserTrustMetrics(MeterRegistry registry) {
        super(registry, "zerotrust.trust");
    }

    @Override
    protected void initializeCounters() {
        
        trustScoreUpdatesCounter = counterBuilder("score.updates", "Total number of trust score updates")
                .register(meterRegistry);

        trustScoreDowngradesCounter = counterBuilder("score.downgrades", "Number of trust score downgrade events")
                .register(meterRegistry);

        trustScoreUpgradesCounter = counterBuilder("score.upgrades", "Number of trust score upgrade events")
                .register(meterRegistry);
    }

    @Override
    protected void initializeTimers() {
        
    }

    @Override
    protected void initializeGauges() {
        
        Gauge.builder("zerotrust_trust_users_monitored", monitoredUsersCount, AtomicInteger::get)
                .description("Total number of users being monitored for trust score")
                .register(meterRegistry);

        Gauge.builder("zerotrust_trust_users_high_risk", highRiskUsersCount, AtomicInteger::get)
                .description("Number of high-risk users (trust score < 0.5)")
                .register(meterRegistry);

        Gauge.builder("zerotrust_trust_users_low_risk", lowRiskUsersCount, AtomicInteger::get)
                .description("Number of low-risk users (trust score >= 0.7)")
                .register(meterRegistry);

        Gauge.builder("zerotrust_trust_score_average", this, UserTrustMetrics::calculateAverageTrustScore)
                .description("Average trust score across all monitored users")
                .register(meterRegistry);
    }

    public void updateUserTrustScore(String userId, double newTrustScore) {
        
        double normalizedScore = Math.min(Math.max(newTrustScore, 0.0), 1.0);

        Double previousScore = userTrustScores.get(userId);
        boolean isNewUser = (previousScore == null);

        userTrustScores.put(userId, normalizedScore);
        trustScoreUpdatesCounter.increment();

        if (isNewUser) {
            monitoredUsersCount.incrementAndGet();
        }

        if (!isNewUser) {
            if (normalizedScore < previousScore) {
                trustScoreDowngradesCounter.increment();
                            } else if (normalizedScore > previousScore) {
                trustScoreUpgradesCounter.increment();
                            }
        }

        recalculateRiskCategories();

            }

    public Double getUserTrustScore(String userId) {
        return userTrustScores.get(userId);
    }

    public Map<String, Double> getAllUserTrustScores() {
        return Map.copyOf(userTrustScores);
    }

    public double calculateAverageTrustScore() {
        if (userTrustScores.isEmpty()) {
            return 1.0; 
        }

        double sum = userTrustScores.values().stream()
                .mapToDouble(Double::doubleValue)
                .sum();

        return sum / userTrustScores.size();
    }

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

    public void removeUser(String userId) {
        if (userTrustScores.remove(userId) != null) {
            monitoredUsersCount.decrementAndGet();
            recalculateRiskCategories();
                    }
    }

    @Override
    public void reset() {
        userTrustScores.clear();
        monitoredUsersCount.set(0);
        highRiskUsersCount.set(0);
        lowRiskUsersCount.set(0);
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
