package io.contexa.contexacore.autonomous.strategy;

import io.contexa.contexacore.autonomous.domain.ThreatIndicators;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatAssessment;
import io.contexa.contexacore.autonomous.ThreatEvaluator;
import io.contexa.contexacore.domain.entity.ThreatIndicator;
import io.contexa.contexacore.std.rag.processors.ThreatCorrelator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import jakarta.annotation.PostConstruct;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class DynamicStrategySelector {
    
    
    private final ThreatCorrelator threatCorrelator;

    
    @Autowired(required = false)
    private ThreatEvaluator threatEvaluator;
    
    
    
    
    @Autowired(required = false)
    private CompositeEvaluationStrategy compositeStrategy;

    
    
    
    
    @Value("${security.strategy.cache.ttl-seconds:300}")
    private int cacheTimeToLiveSeconds;
    
    @Value("${security.strategy.learning.enabled:true}")
    private boolean learningEnabled;
    
    @Value("${security.strategy.combination.max:3}")
    private int maxCombinedStrategies;
    
    @Value("${security.strategy.confidence.threshold:0.75}")
    private double confidenceThreshold;
    
    
    private final Map<String, ThreatEvaluationStrategy> strategies = new ConcurrentHashMap<>();
    
    
    private final Map<String, StrategySelectionResult> selectionCache = new ConcurrentHashMap<>();
    
    
    private final Map<String, StrategyPerformanceMetrics> performanceMetrics = new ConcurrentHashMap<>();
    
    
    private final Map<String, LearningData> learningData = new ConcurrentHashMap<>();
    
    
    private final AtomicLong totalSelections = new AtomicLong(0);
    private final AtomicLong cacheHits = new AtomicLong(0);
    
    @PostConstruct
    public void initialize() {
        log.info("동적 전략 선택기 초기화 시작");
        
        
        registerDefaultStrategies();
        
        
        startCacheCleaner();
        
        log.info("동적 전략 선택기 초기화 완료 - 등록된 전략: {}", strategies.size());
    }
    
    
    public Mono<String> selectOptimalStrategy(String eventType, Map<String, Object> context) {
        return Mono.fromCallable(() -> {
            totalSelections.incrementAndGet();
            
            
            String cacheKey = generateCacheKey(eventType, context);
            StrategySelectionResult cached = selectionCache.get(cacheKey);
            
            if (cached != null && !cached.isExpired()) {
                cacheHits.incrementAndGet();
                log.debug("캐시된 전략 사용: {}", cached.getStrategy());
                return cached.getStrategy();
            }
            
            
            StrategySelectionResult result = executeStrategySelection(eventType, context);
            
            
            selectionCache.put(cacheKey, result);
            
            
            if (learningEnabled) {
                updateLearningData(eventType, context, result);
            }
            
            log.info("전략 선택 완료 - Event Type: {}, Selected: {}, Confidence: {}", 
                eventType, result.getStrategy(), result.getConfidence());
            
            return result.getStrategy();
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    public Mono<Map<String, Double>> selectCombinedStrategies(String eventType, Map<String, Object> context) {
        return Mono.fromCallable(() -> {
            
            Map<String, Double> strategyScores = evaluateAllStrategies(eventType, context);
            
            
            Map<String, Double> selected = strategyScores.entrySet().stream()
                .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
                .limit(maxCombinedStrategies)
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    Map.Entry::getValue,
                    (e1, e2) -> e1,
                    LinkedHashMap::new
                ));
            
            
            double totalWeight = selected.values().stream()
                .mapToDouble(Double::doubleValue)
                .sum();
            
            if (totalWeight > 0) {
                selected.replaceAll((k, v) -> v / totalWeight);
            }
            
            log.info("전략 조합 선택 완료 - Strategies: {}", selected);
            
            return selected;
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    private StrategySelectionResult executeStrategySelection(String eventType, Map<String, Object> context) {
        
        EventCategory category = classifyEvent(eventType, context);
        
        
        double complexity = calculateComplexity(context);

        
        if (complexity > 0.8 && threatEvaluator != null) {
            return new StrategySelectionResult("INTEGRATED", 0.95,
                LocalDateTime.now().plusSeconds(cacheTimeToLiveSeconds));
        }

        
        if (isSessionRelatedEvent(eventType, context)) {
            
            if (context.containsKey("multipleThreats") || complexity > 0.7) {
                return new StrategySelectionResult("COMPOSITE", 0.9,
                    LocalDateTime.now().plusSeconds(cacheTimeToLiveSeconds));
            } else {
                
                return new StrategySelectionResult("INTEGRATED", 0.85,
                    LocalDateTime.now().plusSeconds(cacheTimeToLiveSeconds));
            }
        }
        
        
        ThreatIndicators indicators = extractThreatIndicators(context);
        
        
        Map<String, Double> strategyScores = new HashMap<>();
        
        for (Map.Entry<String, ThreatEvaluationStrategy> entry : strategies.entrySet()) {
            String strategyName = entry.getKey();
            ThreatEvaluationStrategy strategy = entry.getValue();
            
            
            double score = calculateStrategyFitness(
                strategy, category, complexity, indicators
            );
            
            
            if (performanceMetrics.containsKey(strategyName)) {
                StrategyPerformanceMetrics metrics = performanceMetrics.get(strategyName);
                score *= metrics.getPerformanceMultiplier();
            }
            
            
            if (learningEnabled && learningData.containsKey(strategyName)) {
                LearningData learning = learningData.get(strategyName);
                score *= learning.getEffectivenessScore();
            }
            
            strategyScores.put(strategyName, score);
        }
        
        
        Map.Entry<String, Double> best = strategyScores.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .orElse(new AbstractMap.SimpleEntry<>("DEFAULT", 0.5));
        
        return new StrategySelectionResult(
            best.getKey(),
            best.getValue(),
            LocalDateTime.now().plusSeconds(cacheTimeToLiveSeconds)
        );
    }
    
    
    private boolean isSessionRelatedEvent(String eventType, Map<String, Object> context) {
        
        if (eventType != null) {
            String type = eventType.toUpperCase();
            if (type.contains("SESSION") || type.contains("AUTH") || 
                type.contains("LOGIN") || type.contains("LOGOUT")) {
                return true;
            }
        }
        
        
        if (context.containsKey("sessionId") || context.containsKey("sessionContext")) {
            return true;
        }
        
        
        if (context.containsKey("ipChanged") || context.containsKey("userAgentChanged")) {
            return true;
        }
        
        
        if (context.containsKey("sessionThreatIndicators") || 
            context.containsKey("sessionHijackSuspected")) {
            return true;
        }
        
        return false;
    }
    
    
    private EventCategory classifyEvent(String eventType, Map<String, Object> context) {
        
        if (eventType.contains("AUTH") || eventType.contains("LOGIN")) {
            return EventCategory.AUTHENTICATION;
        } else if (eventType.contains("ACCESS") || eventType.contains("PERMISSION")) {
            return EventCategory.AUTHORIZATION;
        } else if (eventType.contains("API") || eventType.contains("CALL")) {
            return EventCategory.API_ACCESS;
        } else if (eventType.contains("DATA") || eventType.contains("FILE")) {
            return EventCategory.DATA_ACCESS;
        } else if (eventType.contains("NETWORK") || eventType.contains("CONNECTION")) {
            return EventCategory.NETWORK;
        } else if (eventType.contains("SYSTEM") || eventType.contains("PROCESS")) {
            return EventCategory.SYSTEM;
        } else if (eventType.contains("THREAT") || eventType.contains("ATTACK")) {
            return EventCategory.THREAT_DETECTION;
        }
        
        
        if (context.containsKey("severity")) {
            String severity = String.valueOf(context.get("severity"));
            if ("CRITICAL".equals(severity) || "HIGH".equals(severity)) {
                return EventCategory.HIGH_RISK;
            }
        }
        
        return EventCategory.GENERAL;
    }
    
    
    private double calculateComplexity(Map<String, Object> context) {
        double complexity = 0.0;
        
        
        complexity += Math.min(context.size() / 20.0, 0.3);
        
        
        for (Object value : context.values()) {
            if (value instanceof Map || value instanceof List) {
                complexity += 0.1;
            }
        }
        
        
        if (context.containsKey("threatIndicators")) {
            Object indicators = context.get("threatIndicators");
            if (indicators instanceof List) {
                complexity += Math.min(((List<?>) indicators).size() / 10.0, 0.3);
            }
        }
        
        
        if (context.containsKey("urgency")) {
            String urgency = String.valueOf(context.get("urgency"));
            if ("CRITICAL".equals(urgency)) {
                complexity += 0.2;
            }
        }
        
        return Math.min(complexity, 1.0);
    }
    
    
    private ThreatIndicators extractThreatIndicators(Map<String, Object> context) {
        ThreatIndicators indicators = new ThreatIndicators();
        
        
        if (context.containsKey("ioc")) {
            indicators.setIocPresent(true);
            indicators.setIocCount(getListSize(context.get("ioc")));
        }
        
        
        if (context.containsKey("mitre")) {
            indicators.setMitreMapping(true);
            indicators.setMitreTechniques(getListSize(context.get("mitre")));
        }
        
        
        if (context.containsKey("anomaly")) {
            indicators.setAnomalyDetected(true);
            indicators.setAnomalyScore(getDoubleValue(context.get("anomaly")));
        }
        
        
        if (context.containsKey("previousThreats")) {
            indicators.setHistoricalThreat(true);
            indicators.setHistoricalCount(getIntValue(context.get("previousThreats")));
        }
        
        
        if (context.containsKey("riskScore")) {
            indicators.setRiskScore(getDoubleValue(context.get("riskScore")));
        }
        
        return indicators;
    }
    
    
    private double calculateStrategyFitness(
        io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy strategy,
        EventCategory category,
        double complexity,
        ThreatIndicators indicators
    ) {
        double fitness = 0.0;
        
        
        fitness = 0.5;
        
        
        
        if (strategy.isEnabled()) {
            fitness += 0.2;
        }
        
        
        int priority = strategy.getPriority();
        if (priority < 50) {
            fitness += 0.2;
        } else if (priority < 100) {
            fitness += 0.1;
        }
        
        return fitness;
    }
    
    
    private Map<String, Double> evaluateAllStrategies(String eventType, Map<String, Object> context) {
        EventCategory category = classifyEvent(eventType, context);
        double complexity = calculateComplexity(context);
        ThreatIndicators indicators = extractThreatIndicators(context);
        
        Map<String, Double> scores = new HashMap<>();
        
        for (Map.Entry<String, io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy> entry : strategies.entrySet()) {
            double score = calculateStrategyFitness(
                entry.getValue(), category, complexity, indicators
            );
            
            if (score >= confidenceThreshold) {
                scores.put(entry.getKey(), score);
            }
        }
        
        return scores;
    }
    
    
    private void updateLearningData(
        String eventType, 
        Map<String, Object> context, 
        StrategySelectionResult result
    ) {
        String strategyName = result.getStrategy();
        
        LearningData data = learningData.computeIfAbsent(
            strategyName, 
            k -> new LearningData()
        );
        
        data.incrementUsageCount();
        data.updateLastUsed();
        
        
        data.addContextPattern(eventType, context);
        
        
        data.updateConfidenceAverage(result.getConfidence());
        
        log.debug("학습 데이터 업데이트 - Strategy: {}, Usage Count: {}", 
            strategyName, data.getUsageCount());
    }
    
    
    private void registerDefaultStrategies() {
        
        if (threatEvaluator != null) {
            strategies.put("INTEGRATED", new IntegratedThreatEvaluationStrategyAdapter(threatEvaluator));
            performanceMetrics.put("INTEGRATED", new StrategyPerformanceMetrics());
            log.info("통합 위협 평가 전략 등록: INTEGRATED");
        }

        
        

        
        

        
        if (compositeStrategy != null) {
            strategies.put("COMPOSITE", compositeStrategy);
            performanceMetrics.put("COMPOSITE", new StrategyPerformanceMetrics());
            log.info("복합 평가 전략 등록: COMPOSITE");
        }

        
        strategies.put("DEFAULT", new DefaultThreatEvaluationStrategy());
        performanceMetrics.put("DEFAULT", new StrategyPerformanceMetrics());
        log.info("기본 위협 평가 전략 등록: DEFAULT");
    }
    
    
    public void registerStrategy(String name, io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy strategy) {
        strategies.put(name, strategy);
        performanceMetrics.put(name, new StrategyPerformanceMetrics());
        log.info("전략 등록 완료: {}", name);
    }
    
    
    public io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy getStrategy(String name) {
        return strategies.get(name);
    }
    
    
    public void updateStrategyPerformance(String strategyName, long executionTime, boolean success) {
        StrategyPerformanceMetrics metrics = performanceMetrics.get(strategyName);
        if (metrics != null) {
            metrics.updateMetrics(executionTime, success);
        }
    }
    
    
    private void startCacheCleaner() {
        Schedulers.parallel().schedulePeriodically(() -> {
            LocalDateTime now = LocalDateTime.now();
            
            selectionCache.entrySet().removeIf(entry -> {
                StrategySelectionResult result = entry.getValue();
                return result.getExpiryTime().isBefore(now);
            });
            
            log.debug("전략 선택 캐시 정리 완료 - 남은 엔트리: {}", selectionCache.size());
            
        }, cacheTimeToLiveSeconds, cacheTimeToLiveSeconds, java.util.concurrent.TimeUnit.SECONDS);
    }
    
    
    private String generateCacheKey(String eventType, Map<String, Object> context) {
        
        StringBuilder keyBuilder = new StringBuilder(eventType);
        
        
        String[] importantFields = {"severity", "userId", "source", "category"};
        
        for (String field : importantFields) {
            if (context.containsKey(field)) {
                keyBuilder.append(":").append(context.get(field));
            }
        }
        
        return keyBuilder.toString();
    }
    
    
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        metrics.put("totalSelections", totalSelections.get());
        metrics.put("cacheHits", cacheHits.get());
        metrics.put("cacheHitRate", 
            totalSelections.get() > 0 ? 
                (double) cacheHits.get() / totalSelections.get() : 0.0);
        metrics.put("registeredStrategies", strategies.size());
        metrics.put("cacheSize", selectionCache.size());
        metrics.put("learningDataSize", learningData.size());
        
        
        Map<String, Map<String, Object>> strategyMetrics = new HashMap<>();
        for (Map.Entry<String, StrategyPerformanceMetrics> entry : performanceMetrics.entrySet()) {
            strategyMetrics.put(entry.getKey(), entry.getValue().toMap());
        }
        metrics.put("strategyPerformance", strategyMetrics);
        
        return metrics;
    }
    
    
    
    private int getListSize(Object obj) {
        if (obj instanceof List) {
            return ((List<?>) obj).size();
        }
        return 0;
    }
    
    private double getDoubleValue(Object obj) {
        if (obj instanceof Number) {
            return ((Number) obj).doubleValue();
        }
        return 0.0;
    }
    
    private int getIntValue(Object obj) {
        if (obj instanceof Number) {
            return ((Number) obj).intValue();
        }
        return 0;
    }
    
    
    
    
    private static class StrategySelectionResult {
        private final String strategy;
        private final double confidence;
        private final LocalDateTime expiryTime;
        
        public StrategySelectionResult(String strategy, double confidence, LocalDateTime expiryTime) {
            this.strategy = strategy;
            this.confidence = confidence;
            this.expiryTime = expiryTime;
        }
        
        public String getStrategy() {
            return strategy;
        }
        
        public double getConfidence() {
            return confidence;
        }
        
        public LocalDateTime getExpiryTime() {
            return expiryTime;
        }
        
        public boolean isExpired() {
            return LocalDateTime.now().isAfter(expiryTime);
        }
    }
    
    
    private static class StrategyPerformanceMetrics {
        private long totalExecutions = 0;
        private long successfulExecutions = 0;
        private long totalExecutionTime = 0;
        private double averageExecutionTime = 0;
        
        public void updateMetrics(long executionTime, boolean success) {
            totalExecutions++;
            totalExecutionTime += executionTime;
            
            if (success) {
                successfulExecutions++;
            }
            
            averageExecutionTime = (double) totalExecutionTime / totalExecutions;
        }
        
        public double getPerformanceMultiplier() {
            if (totalExecutions == 0) {
                return 1.0;  
            }
            
            double successRate = (double) successfulExecutions / totalExecutions;
            double speedFactor = averageExecutionTime < 100 ? 1.2 : 
                                  averageExecutionTime < 500 ? 1.0 : 0.8;
            
            return successRate * speedFactor;
        }
        
        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("totalExecutions", totalExecutions);
            map.put("successfulExecutions", successfulExecutions);
            map.put("successRate", 
                totalExecutions > 0 ? (double) successfulExecutions / totalExecutions : 0.0);
            map.put("averageExecutionTime", averageExecutionTime);
            return map;
        }
    }
    
    
    private static class LearningData {
        private long usageCount = 0;
        private LocalDateTime lastUsed;
        private double confidenceSum = 0;
        private double effectivenessScore = 1.0;
        private final Map<String, Integer> contextPatterns = new HashMap<>();
        
        public void incrementUsageCount() {
            usageCount++;
        }
        
        public void updateLastUsed() {
            lastUsed = LocalDateTime.now();
        }
        
        public void updateConfidenceAverage(double confidence) {
            confidenceSum += confidence;
            effectivenessScore = confidenceSum / usageCount;
        }
        
        public void addContextPattern(String eventType, Map<String, Object> context) {
            contextPatterns.merge(eventType, 1, Integer::sum);
        }
        
        public long getUsageCount() {
            return usageCount;
        }
        
        public double getEffectivenessScore() {
            return effectivenessScore;
        }
    }
    
    
    public enum EventCategory {
        AUTHENTICATION,
        AUTHORIZATION,
        API_ACCESS,
        DATA_ACCESS,
        NETWORK,
        SYSTEM,
        THREAT_DETECTION,
        HIGH_RISK,
        GENERAL
    }
    
    
    @lombok.Builder
    @lombok.Getter
    public static class StrategyProperties {
        private final String name;
        private final String description;
        private final Set<EventCategory> supportedCategories;
        private final double minComplexity;
        private final double maxComplexity;
        private final boolean supportsIoc;
        private final boolean supportsMitre;
        private final boolean supportsAnomaly;
        private final boolean highPerformance;
    }

    
    private static class DefaultThreatEvaluationStrategy implements ThreatEvaluationStrategy {

        @Override
        public ThreatAssessment evaluate(SecurityEvent event) {
            
            return ThreatAssessment.builder()
                .eventId(event.getEventId())
                .assessmentId("default-" + System.currentTimeMillis())
                .assessedAt(LocalDateTime.now())
                .evaluator("DEFAULT")
                .riskScore(0.5)
                .confidence(0.5)
                .recommendedActions(List.of("ESCALATE", "LLM_ANALYSIS_REQUIRED"))
                
                .action("ESCALATE")  
                .build();
        }

        @Override
        public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
            return Collections.emptyList();
        }

        @Override
        public String getStrategyName() {
            return "DEFAULT";
        }

        @Override
        public List<String> getRecommendedActions(SecurityEvent event) {
            return List.of("monitor", "log");
        }

        @Override
        public double calculateRiskScore(List<ThreatIndicator> indicators) {
            return 0.5; 
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public int getPriority() {
            return 1000; 
        }
    }

    
    private static class IntegratedThreatEvaluationStrategyAdapter implements ThreatEvaluationStrategy {
        private final ThreatEvaluator threatEvaluator;

        public IntegratedThreatEvaluationStrategyAdapter(ThreatEvaluator threatEvaluator) {
            this.threatEvaluator = threatEvaluator;
        }

        @Override
        public ThreatAssessment evaluate(SecurityEvent event) {
            
            return threatEvaluator.evaluateIntegrated(event);
        }

        @Override
        public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
            return Collections.emptyList(); 
        }

        @Override
        public String getStrategyName() {
            return "INTEGRATED";
        }

        @Override
        public List<String> getRecommendedActions(SecurityEvent event) {
            return List.of("comprehensive_analysis", "multi_strategy_evaluation");
        }

        @Override
        public double calculateRiskScore(List<ThreatIndicator> indicators) {
            return 0.8; 
        }

        @Override
        public boolean isEnabled() {
            return threatEvaluator != null;
        }

        @Override
        public int getPriority() {
            return 10; 
        }
    }
}