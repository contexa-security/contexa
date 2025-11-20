package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.strategy.*;
import io.contexa.contexacore.infra.redis.RedisAtomicOperations;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * IntegratedThreatEvaluator - 통합 위협 평가기
 *
 * 여러 전략을 병렬로 실행하고 가중 평균을 통해 정밀한 위협 평가를 수행합니다.
 * 최소 3개 이상의 전략이 동의해야 최종 결정을 신뢰합니다.
 *
 * @since 1.0
 */
@Slf4j
@ConditionalOnClass(name = "io.contexa.contexacore.repository.PolicyProposalRepository")
@Component
@RequiredArgsConstructor
public class IntegratedThreatEvaluator {

    // 전략 컴포넌트
    // SessionThreatEvaluationStrategy removed - handled by SecurityEventProcessingOrchestrator

    @Autowired(required = false)
    private MitreAttackEvaluationStrategy mitreStrategy;

    @Autowired(required = false)
    private NistCsfEvaluationStrategy nistStrategy;

    @Autowired(required = false)
    private CisControlsEvaluationStrategy cisStrategy;

    @Autowired(required = false)
    private CompositeEvaluationStrategy compositeStrategy;

    @Autowired(required = false)
    private BehavioralAnalysisLabConnector behavioralConnector;

    // Redis 컴포넌트
    private final RedisAtomicOperations redisAtomicOperations;
    private final RedisTemplate<String, Object> redisTemplate;

    // 설정값
    @Value("${security.evaluator.consensus.threshold:0.75}")
    private double consensusThreshold;

    @Value("${security.evaluator.min.strategies:3}")
    private int minStrategiesRequired;

    @Value("${security.evaluator.timeout.ms:500}")
    private long evaluationTimeoutMs;

    @Value("${security.evaluator.parallel.enabled:true}")
    private boolean parallelEvaluationEnabled;

    // 전략 가중치 설정
    // sessionStrategyWeight removed - SecurityEventProcessingOrchestrator로 이관

    @Value("${security.evaluator.weight.behavioral:0.3}")
    private double behavioralStrategyWeight;

    @Value("${security.evaluator.weight.mitre:0.2}")
    private double mitreStrategyWeight;

    @Value("${security.evaluator.weight.nist:0.1}")
    private double nistStrategyWeight;

    // 실행자 서비스
    private final ExecutorService executorService = Executors.newFixedThreadPool(10);

    /**
     * 통합 위협 평가 - 메인 메서드
     *
     * 모든 가용한 전략을 병렬로 실행하고 가중 평균을 계산합니다.
     *
     * @param event 보안 이벤트
     * @return 통합 위협 평가 결과
     */
    public ThreatAssessment evaluateIntegrated(SecurityEvent event) {
        String evaluationId = UUID.randomUUID().toString();
        LocalDateTime startTime = LocalDateTime.now();

        log.info("[IntegratedEvaluator] 통합 평가 시작 - ID: {}, Event: {}",
            evaluationId, event.getEventId());

        try {
            // 1. 모든 전략 병렬 실행
            Map<String, CompletableFuture<StrategyResult>> futures = executeStrategiesInParallel(event);

            // 2. 결과 수집 (타임아웃 적용)
            Map<String, StrategyResult> results = collectResults(futures, evaluationTimeoutMs);

            // 3. 유효성 검증
            validateResults(results);

            // 4. 가중 평균 계산
            ThreatAssessment finalAssessment = calculateWeightedAssessment(event, results, evaluationId);

            // 5. 감사 로그 기록
            recordAuditLog(evaluationId, event, results, finalAssessment);

            // 6. Redis에 평가 결과 저장
            storeEvaluationResult(evaluationId, finalAssessment);

            long elapsedMs = java.time.Duration.between(startTime, LocalDateTime.now()).toMillis();
            log.info("[IntegratedEvaluator] 평가 완료 - ID: {}, 소요시간: {}ms, 위험점수: {}, 신뢰도: {}",
                evaluationId, elapsedMs, finalAssessment.getRiskScore(), finalAssessment.getConfidence());

            return finalAssessment;

        } catch (Exception e) {
            log.error("[IntegratedEvaluator] 평가 실패 - ID: {}", evaluationId, e);
            return createFallbackAssessment(event, evaluationId, e.getMessage());
        }
    }

    /**
     * 전략들을 병렬로 실행
     */
    private Map<String, CompletableFuture<StrategyResult>> executeStrategiesInParallel(SecurityEvent event) {
        Map<String, CompletableFuture<StrategyResult>> futures = new HashMap<>();

        // SessionThreatStrategy - SecurityEventProcessingOrchestrator로 이관됨
        // 세션 위협 처리는 더 이상 여기서 직접 실행하지 않음

        // BehavioralAnalysis - 두 번째 중요
       /* if (behavioralConnector != null && behavioralConnector.isEnabled()) {
            futures.put("BEHAVIORAL", CompletableFuture.supplyAsync(() ->
                executeBehavioralAnalysis(event), executorService));
        }*/

        // MITRE ATT&CK
        if (mitreStrategy != null && mitreStrategy.isEnabled()) {
            futures.put("MITRE", CompletableFuture.supplyAsync(() ->
                executeStrategy("MITRE", mitreStrategy, event), executorService));
        }

        // NIST CSF
        if (nistStrategy != null && nistStrategy.isEnabled()) {
            futures.put("NIST", CompletableFuture.supplyAsync(() ->
                executeStrategy("NIST", nistStrategy, event), executorService));
        }

        // CIS Controls
        if (cisStrategy != null && cisStrategy.isEnabled()) {
            futures.put("CIS", CompletableFuture.supplyAsync(() ->
                executeStrategy("CIS", cisStrategy, event), executorService));
        }

        // Composite Strategy
        if (compositeStrategy != null && compositeStrategy.isEnabled()) {
            futures.put("COMPOSITE", CompletableFuture.supplyAsync(() ->
                executeStrategy("COMPOSITE", compositeStrategy, event), executorService));
        }

        log.debug("[IntegratedEvaluator] {} 전략 병렬 실행 시작", futures.size());

        return futures;
    }

    /**
     * 단일 전략 실행
     */
    private StrategyResult executeStrategy(String name, ThreatEvaluationStrategy strategy, SecurityEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            ThreatAssessment assessment = strategy.evaluate(event);
            long executionTime = System.currentTimeMillis() - startTime;

            return StrategyResult.builder()
                .strategyName(name)
                .assessment(assessment)
                .executionTimeMs(executionTime)
                .success(true)
                .confidence(assessment.getConfidence())
                .build();

        } catch (Exception e) {
            log.error("[IntegratedEvaluator] 전략 실행 실패 - {}", name, e);
            return StrategyResult.builder()
                .strategyName(name)
                .success(false)
                .error(e.getMessage())
                .executionTimeMs(System.currentTimeMillis() - startTime)
                .build();
        }
    }

    /**
     * 행동 분석 실행 (BehavioralAnalysisLab 연동)
     */
    private StrategyResult executeBehavioralAnalysis(SecurityEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            ThreatAssessment assessment = behavioralConnector.analyzeBehavior(event);
            long executionTime = System.currentTimeMillis() - startTime;

            return StrategyResult.builder()
                .strategyName("BEHAVIORAL")
                .assessment(assessment)
                .executionTimeMs(executionTime)
                .success(true)
                .confidence(assessment.getConfidence())
                .build();

        } catch (Exception e) {
            log.error("[IntegratedEvaluator] 행동 분석 실패", e);
            return StrategyResult.builder()
                .strategyName("BEHAVIORAL")
                .success(false)
                .error(e.getMessage())
                .executionTimeMs(System.currentTimeMillis() - startTime)
                .build();
        }
    }

    /**
     * 결과 수집 (타임아웃 적용)
     */
    private Map<String, StrategyResult> collectResults(
            Map<String, CompletableFuture<StrategyResult>> futures, long timeoutMs) {

        Map<String, StrategyResult> results = new HashMap<>();

        for (Map.Entry<String, CompletableFuture<StrategyResult>> entry : futures.entrySet()) {
            String strategyName = entry.getKey();
            CompletableFuture<StrategyResult> future = entry.getValue();

            try {
                StrategyResult result = future.get(timeoutMs, TimeUnit.MILLISECONDS);
                if (result.isSuccess()) {
                    results.put(strategyName, result);
                }
            } catch (TimeoutException e) {
                log.warn("[IntegratedEvaluator] 전략 타임아웃 - {}", strategyName);
            } catch (Exception e) {
                log.error("[IntegratedEvaluator] 결과 수집 실패 - {}", strategyName, e);
            }
        }

        return results;
    }

    /**
     * 결과 유효성 검증
     */
    private void validateResults(Map<String, StrategyResult> results) throws IllegalStateException {
        if (results.size() < minStrategiesRequired) {
            throw new IllegalStateException(
                String.format("최소 %d개의 전략이 필요하지만 %d개만 성공",
                    minStrategiesRequired, results.size())
            );
        }

        // 신뢰도 검증
        double avgConfidence = results.values().stream()
            .mapToDouble(StrategyResult::getConfidence)
            .average()
            .orElse(0.0);

        if (avgConfidence < consensusThreshold) {
            log.warn("[IntegratedEvaluator] 평균 신뢰도 부족: {}", avgConfidence);
        }
    }

    /**
     * 가중 평균 계산
     */
    private ThreatAssessment calculateWeightedAssessment(
            SecurityEvent event, Map<String, StrategyResult> results, String evaluationId) {

        double totalWeight = 0.0;
        double weightedRiskSum = 0.0;
        double weightedConfidenceSum = 0.0;
        List<String> allRecommendedActions = new ArrayList<>();
        Map<String, Object> combinedDetails = new HashMap<>();

        // 각 전략별 가중치 적용
        for (Map.Entry<String, StrategyResult> entry : results.entrySet()) {
            String strategyName = entry.getKey();
            StrategyResult result = entry.getValue();
            ThreatAssessment assessment = result.getAssessment();

            double weight = getStrategyWeight(strategyName);
            totalWeight += weight;

            weightedRiskSum += assessment.getRiskScore() * weight;
            weightedConfidenceSum += assessment.getConfidence() * weight;

            // 추천 액션 수집
            if (assessment.getRecommendedActions() != null) {
                allRecommendedActions.addAll(assessment.getRecommendedActions());
            }

            // 상세 정보 병합
            combinedDetails.put(strategyName, Map.of(
                "riskScore", assessment.getRiskScore(),
                "confidence", assessment.getConfidence(),
                "executionTime", result.getExecutionTimeMs()
            ));
        }

        // 최종 점수 계산
        double finalRiskScore = totalWeight > 0 ? weightedRiskSum / totalWeight : 0.5;
        double finalConfidence = totalWeight > 0 ? weightedConfidenceSum / totalWeight : 0.5;

        // 위협 레벨 결정
        ThreatAssessment.ThreatLevel threatLevel = determineThreatLevel(finalRiskScore);

        // 중복 제거된 추천 액션
        List<String> uniqueActions = allRecommendedActions.stream()
            .distinct()
            .collect(Collectors.toList());

        // 합의 달성 및 전략 정보를 메타데이터에 추가
        combinedDetails.put("consensusAchieved", results.size() >= minStrategiesRequired);
        combinedDetails.put("strategiesUsed", new ArrayList<>(results.keySet()));
        combinedDetails.put("totalStrategies", results.size());
        combinedDetails.put("minRequiredStrategies", minStrategiesRequired);

        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(evaluationId)
            .assessedAt(LocalDateTime.now())
            .evaluator("IntegratedThreatEvaluator")
            .threatLevel(threatLevel)
            .riskScore(finalRiskScore)
            .confidence(finalConfidence)
            .recommendedActions(uniqueActions)
            .metadata(combinedDetails)
            .build();
    }

    /**
     * 전략별 가중치 반환
     */
    private double getStrategyWeight(String strategyName) {
        switch (strategyName) {
            case "SESSION":
                // SESSION 전략은 SecurityEventProcessingOrchestrator로 이관됨
                return 0.0;
            case "BEHAVIORAL":
                return behavioralStrategyWeight;
            case "MITRE":
                return mitreStrategyWeight;
            case "NIST":
                return nistStrategyWeight;
            default:
                return 0.05; // 기본 가중치
        }
    }

    /**
     * 위험 점수로 위협 레벨 결정
     */
    private ThreatAssessment.ThreatLevel determineThreatLevel(double riskScore) {
        if (riskScore >= 0.9) {
            return ThreatAssessment.ThreatLevel.CRITICAL;
        } else if (riskScore >= 0.7) {
            return ThreatAssessment.ThreatLevel.HIGH;
        } else if (riskScore >= 0.5) {
            return ThreatAssessment.ThreatLevel.MEDIUM;
        } else if (riskScore >= 0.3) {
            return ThreatAssessment.ThreatLevel.LOW;
        } else {
            return ThreatAssessment.ThreatLevel.INFO;
        }
    }

    /**
     * 감사 로그 기록
     */
    private void recordAuditLog(String evaluationId, SecurityEvent event,
                                Map<String, StrategyResult> results, ThreatAssessment finalAssessment) {

        Map<String, Object> auditEntry = new HashMap<>();
        auditEntry.put("evaluationId", evaluationId);
        auditEntry.put("eventId", event.getEventId());
        auditEntry.put("userId", event.getUserId());
        auditEntry.put("timestamp", LocalDateTime.now());
        auditEntry.put("strategiesExecuted", results.keySet());
        auditEntry.put("finalRiskScore", finalAssessment.getRiskScore());
        auditEntry.put("finalConfidence", finalAssessment.getConfidence());
        auditEntry.put("threatLevel", finalAssessment.getThreatLevel());
        auditEntry.put("consensusAchieved", finalAssessment.getMetadata().get("consensusAchieved"));

        // 각 전략의 결과
        Map<String, Map<String, Object>> strategyDetails = new HashMap<>();
        for (Map.Entry<String, StrategyResult> entry : results.entrySet()) {
            StrategyResult result = entry.getValue();
            strategyDetails.put(entry.getKey(), Map.of(
                "riskScore", result.getAssessment() != null ? result.getAssessment().getRiskScore() : 0,
                "confidence", result.getConfidence(),
                "executionTime", result.getExecutionTimeMs(),
                "success", result.isSuccess()
            ));
        }
        auditEntry.put("strategyDetails", strategyDetails);

        // Redis에 감사 로그 저장
        String auditKey = "security:audit:evaluation:" + evaluationId;
        redisTemplate.opsForValue().set(auditKey, auditEntry, java.time.Duration.ofDays(30));

        log.info("[IntegratedEvaluator] 감사 로그 저장 - Key: {}", auditKey);
    }

    /**
     * 평가 결과 Redis 저장
     */
    private void storeEvaluationResult(String evaluationId, ThreatAssessment assessment) {
        String resultKey = "security:evaluation:result:" + evaluationId;
        redisTemplate.opsForValue().set(resultKey, assessment, java.time.Duration.ofHours(24));
    }

    /**
     * 폴백 평가 생성
     */
    private ThreatAssessment createFallbackAssessment(SecurityEvent event, String evaluationId, String error) {
        log.warn("[IntegratedEvaluator] 폴백 평가 사용 - Error: {}", error);

        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(evaluationId)
            .assessedAt(LocalDateTime.now())
            .evaluator("IntegratedThreatEvaluator-Fallback")
            .threatLevel(ThreatAssessment.ThreatLevel.MEDIUM)
            .riskScore(0.5)
            .confidence(0.3)
            .recommendedActions(List.of("monitor", "log", "alert"))
            .metadata(Map.of("error", error, "fallback", true, "consensusAchieved", false))
            .build();
    }

    /**
     * 평가기 종료
     */
    public void shutdown() {
        try {
            executorService.shutdown();
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * 전략 결과 내부 클래스
     */
    @lombok.Builder
    @lombok.Getter
    private static class StrategyResult {
        private final String strategyName;
        private final ThreatAssessment assessment;
        private final long executionTimeMs;
        private final boolean success;
        private final double confidence;
        private final String error;
    }
}