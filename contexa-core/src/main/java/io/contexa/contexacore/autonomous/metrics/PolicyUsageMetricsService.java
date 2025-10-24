package io.contexa.contexacore.autonomous.metrics;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * 정책 사용 메트릭 서비스
 *
 * 정책 실행 횟수, 성능, 효과 등을 추적하고 분석합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PolicyUsageMetricsService {

    private final PolicyProposalRepository proposalRepository;

    // 정책별 실행 메트릭
    private final Map<String, PolicyMetrics> policyMetricsMap = new ConcurrentHashMap<>();

    // 정책별 마지막 사용 시간
    private final Map<String, LocalDateTime> lastUsedMap = new ConcurrentHashMap<>();

    /**
     * 정책 실행 기록
     *
     * @param policyId 정책 ID
     * @param executionTimeMs 실행 시간(밀리초)
     * @param successful 성공 여부
     */
    public void recordPolicyExecution(String policyId, long executionTimeMs, boolean successful) {
        PolicyMetrics metrics = policyMetricsMap.computeIfAbsent(policyId, k -> new PolicyMetrics(policyId));

        metrics.recordExecution(executionTimeMs, successful);
        lastUsedMap.put(policyId, LocalDateTime.now());

        log.debug("정책 실행 기록: policyId={}, time={}ms, success={}", policyId, executionTimeMs, successful);
    }

    /**
     * 정책 효과 기록
     *
     * @param policyId 정책 ID
     * @param impactScore 효과 점수 (0.0 ~ 1.0)
     */
    public void recordPolicyImpact(String policyId, double impactScore) {
        PolicyMetrics metrics = policyMetricsMap.computeIfAbsent(policyId, k -> new PolicyMetrics(policyId));
        metrics.recordImpact(impactScore);

        log.debug("정책 효과 기록: policyId={}, impact={}", policyId, impactScore);
    }

    /**
     * 정책 메트릭 조회
     *
     * @param policyId 정책 ID
     * @return 정책 메트릭
     */
    public PolicyMetrics getPolicyMetrics(String policyId) {
        return policyMetricsMap.getOrDefault(policyId, new PolicyMetrics(policyId));
    }

    /**
     * 모든 정책 메트릭 조회
     */
    public Map<String, PolicyMetrics> getAllPolicyMetrics() {
        return new HashMap<>(policyMetricsMap);
    }

    /**
     * 느린 정책 식별
     *
     * @param thresholdMs 임계값(밀리초)
     * @return 느린 정책 목록
     */
    public List<PolicyMetrics> findSlowPolicies(long thresholdMs) {
        return policyMetricsMap.values().stream()
            .filter(metrics -> metrics.getAverageExecutionTime() > thresholdMs)
            .sorted((a, b) -> Double.compare(b.getAverageExecutionTime(), a.getAverageExecutionTime()))
            .collect(Collectors.toList());
    }

    /**
     * 미사용 정책 식별
     *
     * @param unusedDays 미사용 일수 임계값
     * @return 미사용 정책 목록
     */
    public List<String> findUnusedPolicies(int unusedDays) {
        LocalDateTime threshold = LocalDateTime.now().minusDays(unusedDays);

        return lastUsedMap.entrySet().stream()
            .filter(entry -> entry.getValue().isBefore(threshold))
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
    }

    /**
     * 실패율이 높은 정책 식별
     *
     * @param failureRateThreshold 실패율 임계값 (0.0 ~ 1.0)
     * @return 실패율이 높은 정책 목록
     */
    public List<PolicyMetrics> findHighFailurePolicies(double failureRateThreshold) {
        return policyMetricsMap.values().stream()
            .filter(metrics -> metrics.getFailureRate() > failureRateThreshold)
            .sorted((a, b) -> Double.compare(b.getFailureRate(), a.getFailureRate()))
            .collect(Collectors.toList());
    }

    /**
     * 정책 효과 분석
     *
     * @param policyId 정책 ID
     * @return 효과 분석 결과
     */
    @Cacheable(value = "policyEffectiveness", key = "#policyId")
    public Map<String, Object> analyzePolicyEffectiveness(String policyId) {
        Map<String, Object> analysis = new HashMap<>();

        PolicyMetrics metrics = getPolicyMetrics(policyId);
        analysis.put("policyId", policyId);
        analysis.put("executionCount", metrics.getExecutionCount());
        analysis.put("successRate", 1.0 - metrics.getFailureRate());
        analysis.put("averageExecutionTime", metrics.getAverageExecutionTime());
        analysis.put("averageImpact", metrics.getAverageImpact());

        // 효과성 점수 계산 (0.0 ~ 1.0)
        double effectivenessScore = calculateEffectivenessScore(metrics);
        analysis.put("effectivenessScore", effectivenessScore);

        // 권장 사항
        List<String> recommendations = generateRecommendations(metrics, effectivenessScore);
        analysis.put("recommendations", recommendations);

        return analysis;
    }

    /**
     * 효과성 점수 계산
     */
    private double calculateEffectivenessScore(PolicyMetrics metrics) {
        double successWeight = 0.3;
        double impactWeight = 0.4;
        double performanceWeight = 0.3;

        double successScore = 1.0 - metrics.getFailureRate();
        double impactScore = metrics.getAverageImpact();
        double performanceScore = calculatePerformanceScore(metrics.getAverageExecutionTime());

        return (successScore * successWeight) + (impactScore * impactWeight) + (performanceScore * performanceWeight);
    }

    /**
     * 성능 점수 계산
     */
    private double calculatePerformanceScore(double avgExecutionTime) {
        // 실행 시간이 짧을수록 높은 점수
        if (avgExecutionTime <= 100) return 1.0;
        if (avgExecutionTime <= 500) return 0.8;
        if (avgExecutionTime <= 1000) return 0.6;
        if (avgExecutionTime <= 5000) return 0.4;
        return 0.2;
    }

    /**
     * 권장 사항 생성
     */
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

    /**
     * 정기적인 메트릭 정리
     * 오래된 메트릭 데이터 제거
     */
//    @Scheduled(cron = "0 0 2 * * ?") // 매일 새벽 2시 실행
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

    /**
     * 정책 메트릭 클래스
     */
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
                // 최근 100개만 유지
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