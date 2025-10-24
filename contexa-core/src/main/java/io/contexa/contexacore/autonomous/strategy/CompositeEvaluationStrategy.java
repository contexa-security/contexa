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

/**
 * 복합 위협 평가 전략
 * 
 * 여러 전략을 조합하여 종합적인 위협 평가를 수행합니다.
 * 각 전략의 결과를 가중치 기반으로 통합하여 최종 평가를 도출합니다.
 * 
 * 주요 기능:
 * - 다중 전략 병렬 실행
 * - 가중치 기반 결과 통합
 * - 전략별 신뢰도 계산
 * - 종합 위협 수준 도출
 */
@Slf4j
@Component
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
        
        // 자기 자신을 제외한 전략들만 사용
        availableStrategies = availableStrategies.stream()
            .filter(s -> !(s instanceof CompositeEvaluationStrategy))
            .collect(Collectors.toList());
        
        // 전략 맵 초기화
        for (ThreatEvaluationStrategy strategy : availableStrategies) {
            strategiesMap.put(strategy.getStrategyName(), strategy);
            // 기본 가중치 설정 (우선순위 기반)
            double weight = 1.0 / (strategy.getPriority() / 10.0 + 1.0);
            strategyWeights.put(strategy.getStrategyName(), weight);
        }
        
        // 가중치 정규화
        normalizeWeights();
        
        // 실행 서비스 초기화
        if (parallelExecutionEnabled) {
            executorService = Executors.newFixedThreadPool(threadPoolSize);
        }
        
        log.info("CompositeEvaluationStrategy initialized with strategies: {}", 
            strategiesMap.keySet());
    }
    
    @Override
    public ThreatAssessment evaluate(SecurityEvent event) {
        log.debug("Composite evaluation starting for event: {}", event.getEventId());
        
        // 평가 가능한 전략 필터링
        List<ThreatEvaluationStrategy> applicableStrategies = filterApplicableStrategies(event);
        
        if (applicableStrategies.size() < minStrategiesRequired) {
            log.warn("Not enough strategies available for composite evaluation. Required: {}, Available: {}",
                minStrategiesRequired, applicableStrategies.size());
            return createFallbackAssessment(event, applicableStrategies);
        }
        
        // 전략 실행 (병렬 또는 순차)
        List<StrategyResult> results = parallelExecutionEnabled ?
            executeStrategiesInParallel(applicableStrategies, event) :
            executeStrategiesSequentially(applicableStrategies, event);
        
        // 결과 통합
        return mergeAssessments(event, results);
    }
    
    /**
     * 적용 가능한 전략 필터링
     */
    private List<ThreatEvaluationStrategy> filterApplicableStrategies(SecurityEvent event) {
        return availableStrategies.stream()
            .filter(ThreatEvaluationStrategy::isEnabled)
            .filter(s -> s.canEvaluate(event.getEventType()))
            .sorted(Comparator.comparingInt(ThreatEvaluationStrategy::getPriority))
            .collect(Collectors.toList());
    }
    
    /**
     * 병렬 전략 실행
     */
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
        
        // 모든 Future 완료 대기
        return futures.stream()
            .map(CompletableFuture::join)
            .filter(StrategyResult::isSuccess)
            .collect(Collectors.toList());
    }
    
    /**
     * 순차 전략 실행
     */
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
    
    /**
     * 평가 결과 통합
     */
    private ThreatAssessment mergeAssessments(SecurityEvent event, List<StrategyResult> results) {
        if (results.isEmpty()) {
            return createMinimalAssessment(event);
        }
        
        // 가중치 적용하여 위험 점수 계산
        double weightedRiskScore = calculateWeightedRiskScore(results);
        
        // 위협 수준 결정
        ThreatAssessment.ThreatLevel threatLevel = determineConsensusThreatLevel(results, weightedRiskScore);
        
        // 모든 지표 수집
        List<ThreatIndicator> allIndicators = collectAllIndicators(results, event);
        
        // 권장 액션 통합
        List<String> recommendedActions = mergeRecommendedActions(results);
        
        // 신뢰도 계산
        double confidence = calculateCompositeConfidence(results);
        
        // 메타데이터 생성
        Map<String, Object> metadata = createCompositeMetadata(results);
        
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName())
            .threatLevel(threatLevel)
            .riskScore(weightedRiskScore)
            .indicators(allIndicators.stream()
                .map(indicator -> indicator.getType().getDescription() + ": " + indicator.getValue())
                .collect(Collectors.toList()))
            .recommendedActions(recommendedActions)
            .confidence(confidence)
            .metadata(metadata)
            .build();
    }
    
    /**
     * 가중치 적용 위험 점수 계산
     */
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
    
    /**
     * 합의 기반 위협 수준 결정
     */
    private ThreatAssessment.ThreatLevel determineConsensusThreatLevel(
            List<StrategyResult> results, double weightedRiskScore) {
        
        // 각 위협 수준별 투표 수 계산
        Map<ThreatAssessment.ThreatLevel, Double> votes = new HashMap<>();
        
        for (StrategyResult result : results) {
            if (result.getAssessment() != null) {
                ThreatAssessment.ThreatLevel level = result.getAssessment().getThreatLevel();
                double weight = strategyWeights.getOrDefault(result.getStrategyName(), 1.0);
                votes.merge(level, weight, Double::sum);
            }
        }
        
        // 최다 득표 수준 선택
        ThreatAssessment.ThreatLevel consensusLevel = votes.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse(ThreatAssessment.ThreatLevel.INFO);
        
        // 가중치 점수 기반 조정
        if (weightedRiskScore >= 0.9 && consensusLevel.ordinal() < ThreatAssessment.ThreatLevel.CRITICAL.ordinal()) {
            return ThreatAssessment.ThreatLevel.CRITICAL;
        } else if (weightedRiskScore >= 0.7 && consensusLevel.ordinal() < ThreatAssessment.ThreatLevel.HIGH.ordinal()) {
            return ThreatAssessment.ThreatLevel.HIGH;
        }
        
        return consensusLevel;
    }
    
    /**
     * 모든 지표 수집
     */
    private List<ThreatIndicator> collectAllIndicators(List<StrategyResult> results, SecurityEvent event) {
        // ThreatAssessment.indicators는 List<String>이므로 변환 필요
        // 각 전략에서 ThreatIndicator 객체를 직접 추출해야 함
        List<ThreatIndicator> allIndicators = new ArrayList<>();
        
        if (event == null) {
            log.warn("SecurityEvent가 null입니다. 지표 수집을 건너뜁니다.");
            return allIndicators;
        }
        
        for (StrategyResult result : results) {
            if (result.getAssessment() != null) {
                // 각 전략에서 ThreatIndicator 객체를 직접 추출
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
    
    /**
     * 권장 액션 통합 (중복 제거)
     */
    private List<String> mergeRecommendedActions(List<StrategyResult> results) {
        Set<String> uniqueActions = new LinkedHashSet<>();
        
        results.stream()
            .filter(r -> r.getAssessment() != null && r.getAssessment().getRecommendedActions() != null)
            .forEach(r -> uniqueActions.addAll(r.getAssessment().getRecommendedActions()));
        
        return new ArrayList<>(uniqueActions);
    }
    
    /**
     * 복합 신뢰도 계산
     */
    private double calculateCompositeConfidence(List<StrategyResult> results) {
        if (results.isEmpty()) {
            return 0.0;
        }
        
        // 가중 평균 신뢰도
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
        
        // 전략 수에 따른 보정
        double strategyCountBonus = Math.min(0.2, results.size() * 0.05);
        
        return Math.min(1.0, baseConfidence + strategyCountBonus);
    }
    
    /**
     * 복합 메타데이터 생성
     */
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
        
        // 각 전략의 위협 수준
        Map<String, String> strategyThreatLevels = new HashMap<>();
        for (StrategyResult result : results) {
            if (result.getAssessment() != null) {
                strategyThreatLevels.put(
                    result.getStrategyName(),
                    result.getAssessment().getThreatLevel().toString()
                );
            }
        }
        metadata.put("strategyThreatLevels", strategyThreatLevels);
        
        return metadata;
    }
    
    /**
     * 폴백 평가 생성
     */
    private ThreatAssessment createFallbackAssessment(SecurityEvent event, 
                                                     List<ThreatEvaluationStrategy> strategies) {
        // 사용 가능한 전략이 있으면 첫 번째 전략 사용
        if (!strategies.isEmpty()) {
            try {
                return strategies.get(0).evaluate(event);
            } catch (Exception e) {
                log.error("Fallback strategy failed", e);
            }
        }
        
        return createMinimalAssessment(event);
    }
    
    /**
     * 최소 평가 결과 생성
     */
    private ThreatAssessment createMinimalAssessment(SecurityEvent event) {
        return ThreatAssessment.builder()
            .eventId(event.getEventId())
            .assessmentId(UUID.randomUUID().toString())
            .assessedAt(LocalDateTime.now())
            .evaluator(getStrategyName())
            .threatLevel(ThreatAssessment.ThreatLevel.INFO)
            .riskScore(0.0)
            .indicators(new ArrayList<>())
            .recommendedActions(List.of("INSUFFICIENT_DATA"))
            .confidence(0.1)
            .build();
    }
    
    /**
     * 가중치 정규화
     */
    private void normalizeWeights() {
        double totalWeight = strategyWeights.values().stream()
            .mapToDouble(Double::doubleValue)
            .sum();
        
        if (totalWeight > 0) {
            strategyWeights.replaceAll((k, v) -> v / totalWeight);
        }
    }
    
    /**
     * 전략 가중치 업데이트
     */
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
    
    @Override
    public Map<String, String> mapToFramework(SecurityEvent event) {
        Map<String, String> mapping = new HashMap<>();
        
        // 종합 프레임워크 매핑
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
        // 각 전략에서 계산된 위험 점수의 평균
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
        return 10; // 높은 우선순위 (복합 평가)
    }
    
    /**
     * 전략 실행 결과 래퍼
     */
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
    
    /**
     * Zero Trust 아키텍처 - SecurityContext 기반 위협 평가 (기본 구현)
     */
    @Override
    public ThreatAssessment evaluateWithContext(SecurityEvent event, SecurityContext context) {
        return evaluate(event);
    }
}
