package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.ThreatEvaluator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.strategy.CompositeEvaluationStrategy;
import io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy;


import io.contexa.contexacore.infra.redis.RedisAtomicOperations;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class IntegratedThreatEvaluator implements ThreatEvaluator {

    
    

    
    

    @Autowired(required = false)
    private CompositeEvaluationStrategy compositeStrategy;

    @Autowired(required = false)
    private BehavioralAnalysisLabConnector behavioralConnector;

    
    private final RedisAtomicOperations redisAtomicOperations;
    private final RedisTemplate<String, Object> redisTemplate;

    
    @Value("${security.evaluator.consensus.threshold:0.75}")
    private double consensusThreshold;

    @Value("${security.evaluator.min.strategies:3}")
    private int minStrategiesRequired;

    @Value("${security.evaluator.timeout.ms:500}")
    private long evaluationTimeoutMs;

    @Value("${security.evaluator.parallel.enabled:true}")
    private boolean parallelEvaluationEnabled;

    
    
    

    @Value("${security.evaluator.weight.behavioral:0.3}")
    private double behavioralStrategyWeight;

    
    private final ExecutorService executorService = Executors.newFixedThreadPool(10);

    
    @Override
    public ThreatAssessment evaluateIntegrated(SecurityEvent event) {
        String evaluationId = UUID.randomUUID().toString();
        LocalDateTime startTime = LocalDateTime.now();

        log.info("[IntegratedEvaluator] 통합 평가 시작 - ID: {}, Event: {}",
            evaluationId, event.getEventId());

        try {
            
            Map<String, CompletableFuture<StrategyResult>> futures = executeStrategiesInParallel(event);

            
            Map<String, StrategyResult> results = collectResults(futures, evaluationTimeoutMs);

            
            validateResults(results);

            
            ThreatAssessment finalAssessment = calculateWeightedAssessment(event, results, evaluationId);

            
            recordAuditLog(evaluationId, event, results, finalAssessment);

            
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

    
    private Map<String, CompletableFuture<StrategyResult>> executeStrategiesInParallel(SecurityEvent event) {
        Map<String, CompletableFuture<StrategyResult>> futures = new HashMap<>();

        
        

        
       

        
        

        
        if (compositeStrategy != null && compositeStrategy.isEnabled()) {
            futures.put("COMPOSITE", CompletableFuture.supplyAsync(() ->
                executeStrategy("COMPOSITE", compositeStrategy, event), executorService));
        }

        log.debug("[IntegratedEvaluator] {} 전략 병렬 실행 시작", futures.size());

        return futures;
    }

    
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

    
    private void validateResults(Map<String, StrategyResult> results) throws IllegalStateException {
        if (results.size() < minStrategiesRequired) {
            throw new IllegalStateException(
                String.format("최소 %d개의 전략이 필요하지만 %d개만 성공",
                    minStrategiesRequired, results.size())
            );
        }

        
        double avgConfidence = results.values().stream()
            .mapToDouble(StrategyResult::getConfidence)
            .average()
            .orElse(0.0);

        if (avgConfidence < consensusThreshold) {
            log.warn("[IntegratedEvaluator] 평균 신뢰도 부족: {}", avgConfidence);
        }
    }

    
    private ThreatAssessment calculateWeightedAssessment(
            SecurityEvent event, Map<String, StrategyResult> results, String evaluationId) {

        double totalWeight = 0.0;
        double weightedRiskSum = 0.0;
        double weightedConfidenceSum = 0.0;
        List<String> allRecommendedActions = new ArrayList<>();
        Map<String, Object> combinedDetails = new HashMap<>();

        
        for (Map.Entry<String, StrategyResult> entry : results.entrySet()) {
            String strategyName = entry.getKey();
            StrategyResult result = entry.getValue();
            ThreatAssessment assessment = result.getAssessment();

            double weight = getStrategyWeight(strategyName);
            totalWeight += weight;

            weightedRiskSum += assessment.getRiskScore() * weight;
            weightedConfidenceSum += assessment.getConfidence() * weight;

            
            if (assessment.getRecommendedActions() != null) {
                allRecommendedActions.addAll(assessment.getRecommendedActions());
            }

            
            combinedDetails.put(strategyName, Map.of(
                "riskScore", assessment.getRiskScore(),
                "confidence", assessment.getConfidence(),
                "executionTime", result.getExecutionTimeMs()
            ));
        }

        
        double finalRiskScore = totalWeight > 0 ? weightedRiskSum / totalWeight : 0.5;
        double finalConfidence = totalWeight > 0 ? weightedConfidenceSum / totalWeight : 0.5;

        
        String action = determineAction(finalRiskScore);

        
        List<String> uniqueActions = allRecommendedActions.stream()
            .distinct()
            .collect(Collectors.toList());

        
        combinedDetails.put("consensusAchieved", results.size() >= minStrategiesRequired);
        combinedDetails.put("strategiesUsed", new ArrayList<>(results.keySet()));
        combinedDetails.put("totalStrategies", results.size());
        combinedDetails.put("minRequiredStrategies", minStrategiesRequired);

        
        log.debug("[IntegratedEvaluator] Combined details - evaluationId: {}, totalStrategies: {}, minRequired: {}",
            evaluationId, results.size(), minStrategiesRequired);

        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(evaluationId)
            .assessedAt(LocalDateTime.now())
            .evaluator("IntegratedThreatEvaluator")
            .riskScore(finalRiskScore)
            .confidence(finalConfidence)
            .recommendedActions(uniqueActions)
            
            .action(action)  
            .build();
    }

    
    private double getStrategyWeight(String strategyName) {
        switch (strategyName) {
            case "SESSION":
                
                return 0.0;
            case "BEHAVIORAL":
                return behavioralStrategyWeight;
            
            
            default:
                return 0.05; 
        }
    }

    
    private String determineAction(double riskScore) {
        
        
        return "ESCALATE";
    }

    
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
        
        auditEntry.put("consensusAchieved", finalAssessment.getConfidence() >= 0.6);

        
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

        
        String auditKey = "security:audit:evaluation:" + evaluationId;
        redisTemplate.opsForValue().set(auditKey, auditEntry, java.time.Duration.ofDays(30));

        log.info("[IntegratedEvaluator] 감사 로그 저장 - Key: {}", auditKey);
    }

    
    private void storeEvaluationResult(String evaluationId, ThreatAssessment assessment) {
        String resultKey = "security:evaluation:result:" + evaluationId;
        redisTemplate.opsForValue().set(resultKey, assessment, java.time.Duration.ofHours(24));
    }

    
    private ThreatAssessment createFallbackAssessment(SecurityEvent event, String evaluationId, String error) {
        log.warn("[IntegratedEvaluator] 폴백 평가 사용 - Error: {}", error);

        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(evaluationId)
            .assessedAt(LocalDateTime.now())
            .evaluator("IntegratedThreatEvaluator-Fallback")
            .riskScore(0.5)
            .confidence(0.3)
            .recommendedActions(List.of("ESCALATE", "LLM_ANALYSIS_REQUIRED"))
            
            .description("Fallback assessment - Error: " + error)
            .action("ESCALATE")  
            .build();
    }

    
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