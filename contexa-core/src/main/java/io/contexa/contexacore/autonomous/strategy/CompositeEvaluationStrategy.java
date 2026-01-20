package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.domain.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;


@Slf4j
public class CompositeEvaluationStrategy implements ThreatEvaluationStrategy {
    
    @Autowired(required = false)
    private List<ThreatEvaluationStrategy> availableStrategies = new ArrayList<>();
    
    private final Map<String, Double> strategyWeights = new HashMap<>();
    private final Map<String, ThreatEvaluationStrategy> strategiesMap = new HashMap<>();
    private ExecutorService executorService;
    
    @Value("${security.composite.strategy.parallel.enabled:true}")
    private boolean parallelExecutionEnabled;
    
    @Value("${security.composite.strategy.thread.pool.size:10}")
    private int threadPoolSize;
    
    @Value("${security.composite.strategy.timeout.seconds:5}")
    private int timeoutSeconds;
    
    @Value("${security.composite.strategy.min.strategies:2}")
    private int minStrategiesRequired;
    
    @PostConstruct
    public void initialize() {
        log.info("Initializing CompositeEvaluationStrategy with {} available strategies", 
            availableStrategies.size());
        
        
        availableStrategies = availableStrategies.stream()
            .filter(s -> !(s instanceof CompositeEvaluationStrategy))
            .collect(Collectors.toList());
        
        
        for (ThreatEvaluationStrategy strategy : availableStrategies) {
            strategiesMap.put(strategy.getStrategyName(), strategy);
            
            double weight = 1.0 / (strategy.getPriority() / 10.0 + 1.0);
            strategyWeights.put(strategy.getStrategyName(), weight);
        }
        
        
        normalizeWeights();
        
        
        if (parallelExecutionEnabled) {
            executorService = Executors.newFixedThreadPool(threadPoolSize);
        }
        
        log.info("CompositeEvaluationStrategy initialized with strategies: {}", 
            strategiesMap.keySet());
    }
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.debug("Composite evaluation starting for event: {}", event.getEventId());
        
        
        List<ThreatEvaluationStrategy> applicableStrategies = filterApplicableStrategies(event);
        
        if (applicableStrategies.size() < minStrategiesRequired) {
            log.warn("Not enough strategies available for composite evaluation. Required: {}, Available: {}",
                minStrategiesRequired, applicableStrategies.size());
            return createFallbackAssessment(event, applicableStrategies);
        }
        
        
        List<StrategyResult> results = parallelExecutionEnabled ?
            executeStrategiesInParallel(applicableStrategies, event) :
            executeStrategiesSequentially(applicableStrategies, event);
        
        
        return mergeAssessments(event, results);
    }
    
    
    private List<ThreatEvaluationStrategy> filterApplicableStrategies(SecurityEvent event) {
        return availableStrategies.stream()
            .filter(ThreatEvaluationStrategy::isEnabled)
            
            .filter(s -> s.canEvaluate(event.getSeverity()))
            .sorted(Comparator.comparingInt(ThreatEvaluationStrategy::getPriority))
            .collect(Collectors.toList());
    }
    
    
    private List<StrategyResult> executeStrategiesInParallel(
            List<ThreatEvaluationStrategy> strategies, SecurityEvent event) {
        
        List<CompletableFuture<StrategyResult>> futures = strategies.stream()
            .map(strategy -> CompletableFuture.supplyAsync(() -> {
                try {
                    long startTime = System.currentTimeMillis();
                    ThreatAssessment assessment = strategy.evaluate(event);
                    long executionTime = System.currentTimeMillis() - startTime;
                    
                    return new StrategyResult(
                        strategy.getStrategyName(),
                        assessment,
                        executionTime,
                        true
                    );
                } catch (Exception e) {
                    log.error("Strategy {} failed for event {}", 
                        strategy.getStrategyName(), event.getEventId(), e);
                    return new StrategyResult(
                        strategy.getStrategyName(),
                        null,
                        0L,
                        false
                    );
                }
            }, executorService))
            .collect(Collectors.toList());
        
        
        return futures.stream()
            .map(CompletableFuture::join)
            .filter(StrategyResult::isSuccess)
            .collect(Collectors.toList());
    }
    
    
    private List<StrategyResult> executeStrategiesSequentially(
            List<ThreatEvaluationStrategy> strategies, SecurityEvent event) {
        
        List<StrategyResult> results = new ArrayList<>();
        
        for (ThreatEvaluationStrategy strategy : strategies) {
            try {
                long startTime = System.currentTimeMillis();
                ThreatAssessment assessment = strategy.evaluate(event);
                long executionTime = System.currentTimeMillis() - startTime;
                
                results.add(new StrategyResult(
                    strategy.getStrategyName(),
                    assessment,
                    executionTime,
                    true
                ));
            } catch (Exception e) {
                log.error("Strategy {} failed for event {}", 
                    strategy.getStrategyName(), event.getEventId(), e);
            }
        }
        
        return results;
    }
    
    
    private ThreatAssessment mergeAssessments(SecurityEvent event, List<StrategyResult> results) {
        if (results.isEmpty()) {
            return createMinimalAssessment(event);
        }

        
        double weightedRiskScore = calculateWeightedRiskScore(results);

        
        String consensusAction = determineConsensusAction(results);

        
        List<ThreatIndicator> allIndicators = collectAllIndicators(results, event);

        
        List<String> recommendedActions = mergeRecommendedActions(results);

        
        double confidence = calculateCompositeConfidence(results);

        
        Map<String, Object> metadata = createCompositeMetadata(results);

        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName())
            .riskScore(weightedRiskScore)
            .indicators(allIndicators.stream()
                .map(indicator -> indicator.getType().getDescription() + ": " + indicator.getValue())
                .collect(Collectors.toList()))
            .recommendedActions(recommendedActions)
            .confidence(confidence)
            
            .action(consensusAction)  
            .build();
    }
    
    
    private double calculateWeightedRiskScore(List<StrategyResult> results) {
        double totalWeightedScore = 0.0;
        double totalWeight = 0.0;
        
        for (StrategyResult result : results) {
            if (result.getAssessment() != null) {
                double weight = strategyWeights.getOrDefault(result.getStrategyName(), 1.0);
                totalWeightedScore += result.getAssessment().getRiskScore() * weight;
                totalWeight += weight;
            }
        }
        
        return totalWeight > 0 ? totalWeightedScore / totalWeight : 0.0;
    }
    
    
    private String determineConsensusAction(List<StrategyResult> results) {
        
        Map<String, Double> votes = new HashMap<>();

        for (StrategyResult result : results) {
            if (result.getAssessment() != null) {
                String action = result.getAssessment().getAction();
                if (action != null && !action.isBlank()) {
                    double weight = strategyWeights.getOrDefault(result.getStrategyName(), 1.0);
                    
                    String normalizedAction = normalizeAction(action);
                    votes.merge(normalizedAction, weight, Double::sum);
                }
            }
        }

        
        if (votes.containsKey("BLOCK")) {
            return "BLOCK";
        }
        if (votes.containsKey("ESCALATE")) {
            return "ESCALATE";
        }
        if (votes.containsKey("CHALLENGE")) {
            return "CHALLENGE";
        }
        if (votes.containsKey("ALLOW")) {
            return "ALLOW";
        }

        
        return "ESCALATE";
    }

    
    private String normalizeAction(String action) {
        if (action == null) return "ESCALATE";
        String upper = action.toUpperCase();
        return switch (upper) {
            case "INVESTIGATE", "MONITOR" -> "ESCALATE";
            default -> upper;
        };
    }
    
    
    private List<ThreatIndicator> collectAllIndicators(List<StrategyResult> results, SecurityEvent event) {
        
        
        List<ThreatIndicator> allIndicators = new ArrayList<>();
        
        if (event == null) {
            log.warn("SecurityEvent가 null입니다. 지표 수집을 건너뜁니다.");
            return allIndicators;
        }
        
        for (StrategyResult result : results) {
            if (result.getAssessment() != null) {
                
                String strategyName = result.getStrategyName();
                ThreatEvaluationStrategy strategy = strategiesMap.get(strategyName);
                if (strategy != null) {
                    try {
                        List<ThreatIndicator> indicators = strategy.extractIndicators(event);
                        allIndicators.addAll(indicators);
                    } catch (Exception e) {
                        log.warn("지표 추출 실패 - Strategy: {}", strategyName, e);
                    }
                }
            }
        }
        
        return allIndicators;
    }
    
    
    private List<String> mergeRecommendedActions(List<StrategyResult> results) {
        Set<String> uniqueActions = new LinkedHashSet<>();
        
        results.stream()
            .filter(r -> r.getAssessment() != null && r.getAssessment().getRecommendedActions() != null)
            .forEach(r -> uniqueActions.addAll(r.getAssessment().getRecommendedActions()));
        
        return new ArrayList<>(uniqueActions);
    }
    
    
    private double calculateCompositeConfidence(List<StrategyResult> results) {
        if (results.isEmpty()) {
            return 0.0;
        }
        
        
        double totalWeightedConfidence = 0.0;
        double totalWeight = 0.0;
        
        for (StrategyResult result : results) {
            if (result.getAssessment() != null) {
                double weight = strategyWeights.getOrDefault(result.getStrategyName(), 1.0);
                totalWeightedConfidence += result.getAssessment().getConfidence() * weight;
                totalWeight += weight;
            }
        }
        
        double baseConfidence = totalWeight > 0 ? totalWeightedConfidence / totalWeight : 0.5;
        
        
        double strategyCountBonus = Math.min(0.2, results.size() * 0.05);
        
        return Math.min(1.0, baseConfidence + strategyCountBonus);
    }
    
    
    private Map<String, Object> createCompositeMetadata(List<StrategyResult> results) {
        Map<String, Object> metadata = new HashMap<>();
        
        metadata.put("strategiesUsed", results.stream()
            .map(StrategyResult::getStrategyName)
            .collect(Collectors.toList()));
        
        metadata.put("strategyCount", results.size());
        
        metadata.put("executionTimes", results.stream()
            .collect(Collectors.toMap(
                StrategyResult::getStrategyName,
                StrategyResult::getExecutionTime
            )));
        
        metadata.put("parallelExecution", parallelExecutionEnabled);
        
        
        Map<String, String> strategyActions = new HashMap<>();
        for (StrategyResult result : results) {
            if (result.getAssessment() != null) {
                String action = result.getAssessment().getAction();
                strategyActions.put(
                    result.getStrategyName(),
                    action != null ? action : "ESCALATE"
                );
            }
        }
        metadata.put("strategyActions", strategyActions);
        
        return metadata;
    }
    
    
    private ThreatAssessment createFallbackAssessment(SecurityEvent event, 
                                                     List<ThreatEvaluationStrategy> strategies) {
        
        if (!strategies.isEmpty()) {
            try {
                return strategies.get(0).evaluate(event);
            } catch (Exception e) {
                log.error("Fallback strategy failed", e);
            }
        }
        
        return createMinimalAssessment(event);
    }
    
    
    private ThreatAssessment createMinimalAssessment(SecurityEvent event) {
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName())
            .riskScore(Double.NaN)  
            .indicators(new ArrayList<>())
            .recommendedActions(List.of("INSUFFICIENT_DATA", "LLM_ANALYSIS_REQUIRED"))
            .confidence(Double.NaN)  
            .action("ESCALATE")  
            .build();
    }
    
    
    private void normalizeWeights() {
        double totalWeight = strategyWeights.values().stream()
            .mapToDouble(Double::doubleValue)
            .sum();
        
        if (totalWeight > 0) {
            strategyWeights.replaceAll((k, v) -> v / totalWeight);
        }
    }
    
    
    public void updateStrategyWeight(String strategyName, double weight) {
        if (strategiesMap.containsKey(strategyName)) {
            strategyWeights.put(strategyName, weight);
            normalizeWeights();
            log.info("Updated weight for strategy {}: {}", strategyName, weight);
        }
    }
    
    @Override
    public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
        if (event == null) {
            log.warn("SecurityEvent가 null입니다. 지표 추출을 건너뜁니다.");
            return new ArrayList<>();
        }
        
        List<ThreatEvaluationStrategy> strategies = filterApplicableStrategies(event);
        return strategies.stream()
            .flatMap(s -> {
                try {
                    return s.extractIndicators(event).stream();
                } catch (Exception e) {
                    log.error("전략에서 지표 추출 실패: {}", 
                        s.getStrategyName(), e);
                    return Stream.<ThreatIndicator>empty();
                }
            })
            .distinct()
            .collect(Collectors.toList());
    }
    
    @Override
    public String getStrategyName() {
        return "COMPOSITE_EVALUATION";
    }
    
    @Override
    public String getDescription() {
        return "Composite evaluation strategy that combines multiple threat evaluation strategies";
    }
    
    
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();

        
        mapping.put("EVALUATION_TYPE", "COMPOSITE");
        mapping.put("STRATEGIES_COUNT", String.valueOf(availableStrategies.size()));
        
        return mapping;
    }
    
    @Override
    public List<String> getRecommendedActions(SecurityEvent event) {
        List<ThreatEvaluationStrategy> strategies = filterApplicableStrategies(event);
        return strategies.stream()
            .flatMap(s -> {
                try {
                    return s.getRecommendedActions(event).stream();
                } catch (Exception e) {
                    return Stream.<String>empty();
                }
            })
            .distinct()
            .collect(Collectors.toList());
    }
    
    @Override
    public double calculateRiskScore(List<ThreatIndicator> indicators) {
        
        List<ThreatEvaluationStrategy> strategies = filterApplicableStrategies(null);
        
        if (strategies.isEmpty()) {
            return 0.0;
        }
        
        double totalScore = strategies.stream()
            .mapToDouble(s -> s.calculateRiskScore(indicators))
            .sum();
        
        return totalScore / strategies.size();
    }
    
    @Override
    public int getPriority() {
        return 10; 
    }
    
    
    private static class StrategyResult {
        private final String strategyName;
        private final ThreatAssessment assessment;
        private final long executionTime;
        private final boolean success;
        
        public StrategyResult(String strategyName, ThreatAssessment assessment, 
                            long executionTime, boolean success) {
            this.strategyName = strategyName;
            this.assessment = assessment;
            this.executionTime = executionTime;
            this.success = success;
        }
        
        public String getStrategyName() { return strategyName; }
        public ThreatAssessment getAssessment() { return assessment; }
        public long getExecutionTime() { return executionTime; }
        public boolean isSuccess() { return success; }
    }
    
    
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        return evaluate(event);
    }
}
