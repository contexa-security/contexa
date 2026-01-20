package io.contexa.contexacoreenterprise.autonomous.metrics;

import com.fasterxml.jackson.core.type.TypeReference;
import io.contexa.contexacommon.cache.ContexaCacheService;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
@ConditionalOnBean(PolicyProposalRepository.class)
public class PolicyUsageMetricsService {

    private static final String CACHE_DOMAIN = "policies";
    private static final String EFFECTIVENESS_CACHE_PREFIX = "policies:effectiveness:";
    private static final TypeReference<Map<String, Object>> EFFECTIVENESS_TYPE = new TypeReference<>() {};

    private final PolicyProposalRepository proposalRepository;
    private final ContexaCacheService cacheService;

    
    private final Map<String, PolicyMetrics> policyMetricsMap = new ConcurrentHashMap<>();

    
    private final Map<String, LocalDateTime> lastUsedMap = new ConcurrentHashMap<>();

    
    public void recordPolicyExecution(String policyId, long executionTimeMs, boolean successful) {
        PolicyMetrics metrics = policyMetricsMap.computeIfAbsent(policyId, k -> new PolicyMetrics(policyId));

        metrics.recordExecution(executionTimeMs, successful);
        lastUsedMap.put(policyId, LocalDateTime.now());

        log.debug("정책 실행 기록: policyId={}, time={}ms, success={}", policyId, executionTimeMs, successful);
    }

    
    public void recordPolicyImpact(String policyId, double impactScore) {
        PolicyMetrics metrics = policyMetricsMap.computeIfAbsent(policyId, k -> new PolicyMetrics(policyId));
        metrics.recordImpact(impactScore);

        log.debug("정책 효과 기록: policyId={}, impact={}", policyId, impactScore);
    }

    
    public PolicyMetrics getPolicyMetrics(String policyId) {
        return policyMetricsMap.getOrDefault(policyId, new PolicyMetrics(policyId));
    }

    
    public Map<String, PolicyMetrics> getAllPolicyMetrics() {
        return new HashMap<>(policyMetricsMap);
    }

    
    public List<PolicyMetrics> findSlowPolicies(long thresholdMs) {
        return policyMetricsMap.values().stream()
            .filter(metrics -> metrics.getAverageExecutionTime() > thresholdMs)
            .sorted((a, b) -> Double.compare(b.getAverageExecutionTime(), a.getAverageExecutionTime()))
            .collect(Collectors.toList());
    }

    
    public List<String> findUnusedPolicies(int unusedDays) {
        LocalDateTime threshold = LocalDateTime.now().minusDays(unusedDays);

        return lastUsedMap.entrySet().stream()
            .filter(entry -> entry.getValue().isBefore(threshold))
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
    }

    
    public List<PolicyMetrics> findHighFailurePolicies(double failureRateThreshold) {
        return policyMetricsMap.values().stream()
            .filter(metrics -> metrics.getFailureRate() > failureRateThreshold)
            .sorted((a, b) -> Double.compare(b.getFailureRate(), a.getFailureRate()))
            .collect(Collectors.toList());
    }

    
    public Map<String, Object> analyzePolicyEffectiveness(String policyId) {
        String cacheKey = EFFECTIVENESS_CACHE_PREFIX + policyId;

        return cacheService.get(
            cacheKey,
            () -> {
                log.debug("정책 효과 분석 (캐시 미스): {}", policyId);

                Map<String, Object> analysis = new HashMap<>();

                PolicyMetrics metrics = getPolicyMetrics(policyId);
                analysis.put("policyId", policyId);
                analysis.put("executionCount", metrics.getExecutionCount());
                analysis.put("successRate", 1.0 - metrics.getFailureRate());
                analysis.put("averageExecutionTime", metrics.getAverageExecutionTime());
                analysis.put("averageImpact", metrics.getAverageImpact());

                
                double effectivenessScore = calculateEffectivenessScore(metrics);
                analysis.put("effectivenessScore", effectivenessScore);

                
                List<String> recommendations = generateRecommendations(metrics, effectivenessScore);
                analysis.put("recommendations", recommendations);

                return analysis;
            },
            EFFECTIVENESS_TYPE,
            CACHE_DOMAIN
        );
    }

    
    public void invalidateEffectivenessCache(String policyId) {
        if (policyId == null) {
            log.info("정책 효과 캐시 전체 무효화");
            cacheService.invalidate(EFFECTIVENESS_CACHE_PREFIX + "*");
        } else {
            log.debug("정책 효과 캐시 무효화: {}", policyId);
            cacheService.invalidate(EFFECTIVENESS_CACHE_PREFIX + policyId);
        }
    }

    
    private double calculateEffectivenessScore(PolicyMetrics metrics) {
        double successWeight = 0.3;
        double impactWeight = 0.4;
        double performanceWeight = 0.3;

        double successScore = 1.0 - metrics.getFailureRate();
        double impactScore = metrics.getAverageImpact();
        double performanceScore = calculatePerformanceScore(metrics.getAverageExecutionTime());

        return (successScore * successWeight) + (impactScore * impactWeight) + (performanceScore * performanceWeight);
    }

    
    private double calculatePerformanceScore(double avgExecutionTime) {
        
        if (avgExecutionTime <= 100) return 1.0;
        if (avgExecutionTime <= 500) return 0.8;
        if (avgExecutionTime <= 1000) return 0.6;
        if (avgExecutionTime <= 5000) return 0.4;
        return 0.2;
    }

    
    private List<String> generateRecommendations(PolicyMetrics metrics, double effectivenessScore) {
        List<String> recommendations = new ArrayList<>();

        if (effectivenessScore < 0.3) {
            recommendations.add("정책 비활성화 고려");
        } else if (effectivenessScore < 0.5) {
            recommendations.add("정책 개선 필요");
        }

        if (metrics.getFailureRate() > 0.3) {
            recommendations.add("높은 실패율 - 조건 검토 필요");
        }

        if (metrics.getAverageExecutionTime() > 1000) {
            recommendations.add("성능 최적화 필요");
        }

        if (metrics.getAverageImpact() < 0.3) {
            recommendations.add("낮은 효과 - 정책 재설계 고려");
        }

        if (metrics.getExecutionCount() < 10) {
            recommendations.add("실행 횟수 부족 - 추가 관찰 필요");
        }

        return recommendations;
    }

    

    public void cleanupOldMetrics() {
        log.info("정책 메트릭 정리 시작");

        LocalDateTime threshold = LocalDateTime.now().minusDays(90);
        int removedCount = 0;

        Iterator<Map.Entry<String, LocalDateTime>> iterator = lastUsedMap.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, LocalDateTime> entry = iterator.next();
            if (entry.getValue().isBefore(threshold)) {
                iterator.remove();
                policyMetricsMap.remove(entry.getKey());
                removedCount++;
            }
        }

        log.info("정책 메트릭 정리 완료: {} 개 제거", removedCount);
    }

    
    public static class PolicyMetrics {
        private final String policyId;
        private final AtomicLong executionCount = new AtomicLong(0);
        private final AtomicLong totalExecutionTime = new AtomicLong(0);
        private final AtomicLong successCount = new AtomicLong(0);
        private final AtomicLong failureCount = new AtomicLong(0);
        private final List<Double> impactScores = new ArrayList<>();

        public PolicyMetrics(String policyId) {
            this.policyId = policyId;
        }

        public void recordExecution(long executionTimeMs, boolean successful) {
            executionCount.incrementAndGet();
            totalExecutionTime.addAndGet(executionTimeMs);

            if (successful) {
                successCount.incrementAndGet();
            } else {
                failureCount.incrementAndGet();
            }
        }

        public void recordImpact(double impactScore) {
            synchronized (impactScores) {
                impactScores.add(impactScore);
                
                if (impactScores.size() > 100) {
                    impactScores.remove(0);
                }
            }
        }

        public String getPolicyId() {
            return policyId;
        }

        public long getExecutionCount() {
            return executionCount.get();
        }

        public double getAverageExecutionTime() {
            long count = executionCount.get();
            if (count == 0) return 0;
            return (double) totalExecutionTime.get() / count;
        }

        public double getFailureRate() {
            long total = successCount.get() + failureCount.get();
            if (total == 0) return 0;
            return (double) failureCount.get() / total;
        }

        public double getAverageImpact() {
            synchronized (impactScores) {
                if (impactScores.isEmpty()) return 0;
                return impactScores.stream()
                    .mapToDouble(Double::doubleValue)
                    .average()
                    .orElse(0.0);
            }
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("policyId", policyId);
            map.put("executionCount", getExecutionCount());
            map.put("averageExecutionTime", getAverageExecutionTime());
            map.put("failureRate", getFailureRate());
            map.put("averageImpact", getAverageImpact());
            return map;
        }
    }
}