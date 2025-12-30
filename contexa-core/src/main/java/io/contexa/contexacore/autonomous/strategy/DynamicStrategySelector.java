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

/**
 * DynamicStrategySelector - 동적 전략 선택기
 * 
 * 외부기관의 요구사항에 따라 이벤트 타입과 컨텍스트를 기반으로 
 * 최적의 위협 평가 전략을 선택하고 가중치를 부여합니다.
 * 
 * 주요 기능:
 * - 전략 선택 알고리즘
 * - 가중치 계산
 * - 성능 최적화
 * - 학습 기반 개선
 * - 전략 조합
 * 
 * @author contexa
 * @since 1.0
 */
@Slf4j
@RequiredArgsConstructor
public class DynamicStrategySelector {
    
    // 기존 컴포넌트 재사용
    private final ThreatCorrelator threatCorrelator;

    // Enterprise 기능 - Spring Boot AutoConfiguration을 통한 직접 주입
    @Autowired(required = false)
    private ThreatEvaluator threatEvaluator;
    
    // 전략 컴포넌트 주입
    // SessionThreatEvaluationStrategy removed - replaced by SecurityEventProcessingOrchestrator
    
    @Autowired(required = false)
    private CompositeEvaluationStrategy compositeStrategy;

    // AI Native: MitreAttackEvaluationStrategy, NistCsfEvaluationStrategy, CisControlsEvaluationStrategy 제거
    // LLM과 연동되지 않는 규칙 기반 Strategy는 AI Native 아키텍처에서 사용하지 않음
    
    // 설정값
    @Value("${security.strategy.cache.ttl-seconds:300}")
    private int cacheTimeToLiveSeconds;
    
    @Value("${security.strategy.learning.enabled:true}")
    private boolean learningEnabled;
    
    @Value("${security.strategy.combination.max:3}")
    private int maxCombinedStrategies;
    
    @Value("${security.strategy.confidence.threshold:0.75}")
    private double confidenceThreshold;
    
    // 전략 정의 (인터페이스 사용)
    private final Map<String, ThreatEvaluationStrategy> strategies = new ConcurrentHashMap<>();
    
    // 전략 선택 캐시
    private final Map<String, StrategySelectionResult> selectionCache = new ConcurrentHashMap<>();
    
    // 전략 성능 메트릭
    private final Map<String, StrategyPerformanceMetrics> performanceMetrics = new ConcurrentHashMap<>();
    
    // 학습 데이터
    private final Map<String, LearningData> learningData = new ConcurrentHashMap<>();
    
    // 카운터
    private final AtomicLong totalSelections = new AtomicLong(0);
    private final AtomicLong cacheHits = new AtomicLong(0);
    
    @PostConstruct
    public void initialize() {
        log.info("동적 전략 선택기 초기화 시작");
        
        // 기본 전략 등록
        registerDefaultStrategies();
        
        // 캐시 정리 스케줄러 시작
        startCacheCleaner();
        
        log.info("동적 전략 선택기 초기화 완료 - 등록된 전략: {}", strategies.size());
    }
    
    /**
     * 최적 전략 선택 (메인 메서드)
     * 
     * 이벤트 타입과 컨텍스트를 분석하여 가장 적합한 전략을 선택합니다.
     * 
     * @param eventType 이벤트 타입
     * @param context 이벤트 컨텍스트
     * @return 선택된 전략 이름
     */
    public Mono<String> selectOptimalStrategy(String eventType, Map<String, Object> context) {
        return Mono.fromCallable(() -> {
            totalSelections.incrementAndGet();
            
            // 캐시 확인
            String cacheKey = generateCacheKey(eventType, context);
            StrategySelectionResult cached = selectionCache.get(cacheKey);
            
            if (cached != null && !cached.isExpired()) {
                cacheHits.incrementAndGet();
                log.debug("캐시된 전략 사용: {}", cached.getStrategy());
                return cached.getStrategy();
            }
            
            // 전략 선택 알고리즘 실행
            StrategySelectionResult result = executeStrategySelection(eventType, context);
            
            // 캐시 저장
            selectionCache.put(cacheKey, result);
            
            // 학습 데이터 업데이트
            if (learningEnabled) {
                updateLearningData(eventType, context, result);
            }
            
            log.info("전략 선택 완료 - Event Type: {}, Selected: {}, Confidence: {}", 
                eventType, result.getStrategy(), result.getConfidence());
            
            return result.getStrategy();
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * 전략 조합 선택
     * 
     * 복잡한 위협에 대해 여러 전략을 조합하여 평가합니다.
     * 
     * @param eventType 이벤트 타입
     * @param context 컨텍스트
     * @return 전략과 가중치 맵
     */
    public Mono<Map<String, Double>> selectCombinedStrategies(String eventType, Map<String, Object> context) {
        return Mono.fromCallable(() -> {
            // 모든 전략의 적합도 평가
            Map<String, Double> strategyScores = evaluateAllStrategies(eventType, context);
            
            // 상위 N개 전략 선택
            Map<String, Double> selected = strategyScores.entrySet().stream()
                .sorted(Map.Entry.<String, Double>comparingByValue().reversed())
                .limit(maxCombinedStrategies)
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    Map.Entry::getValue,
                    (e1, e2) -> e1,
                    LinkedHashMap::new
                ));
            
            // 가중치 정규화
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
    
    /**
     * 전략 선택 알고리즘 실행
     */
    private StrategySelectionResult executeStrategySelection(String eventType, Map<String, Object> context) {
        // 1. 이벤트 분류
        EventCategory category = classifyEvent(eventType, context);
        
        // 2. 컨텍스트 복잡도 계산
        double complexity = calculateComplexity(context);

        // 고복잡도 이벤트는 통합 평가기 사용
        if (complexity > 0.8 && threatEvaluator != null) {
            return new StrategySelectionResult("INTEGRATED", 0.95,
                LocalDateTime.now().plusSeconds(cacheTimeToLiveSeconds));
        }

        // 세션 관련 이벤트는 통합 평가기 또는 복합 전략으로 처리
        if (isSessionRelatedEvent(eventType, context)) {
            // 복합 전략 선택 (세션 위협은 SecurityEventProcessingOrchestrator가 처리)
            if (context.containsKey("multipleThreats") || complexity > 0.7) {
                return new StrategySelectionResult("COMPOSITE", 0.9,
                    LocalDateTime.now().plusSeconds(cacheTimeToLiveSeconds));
            } else {
                // 세션 이벤트는 통합 전략으로 라우팅
                return new StrategySelectionResult("INTEGRATED", 0.85,
                    LocalDateTime.now().plusSeconds(cacheTimeToLiveSeconds));
            }
        }
        
        // 3. 위협 지표 추출
        ThreatIndicators indicators = extractThreatIndicators(context);
        
        // 4. 전략별 적합도 평가
        Map<String, Double> strategyScores = new HashMap<>();
        
        for (Map.Entry<String, ThreatEvaluationStrategy> entry : strategies.entrySet()) {
            String strategyName = entry.getKey();
            ThreatEvaluationStrategy strategy = entry.getValue();
            
            // 적합도 점수 계산
            double score = calculateStrategyFitness(
                strategy, category, complexity, indicators
            );
            
            // 성능 가중치 적용
            if (performanceMetrics.containsKey(strategyName)) {
                StrategyPerformanceMetrics metrics = performanceMetrics.get(strategyName);
                score *= metrics.getPerformanceMultiplier();
            }
            
            // 학습 기반 조정
            if (learningEnabled && learningData.containsKey(strategyName)) {
                LearningData learning = learningData.get(strategyName);
                score *= learning.getEffectivenessScore();
            }
            
            strategyScores.put(strategyName, score);
        }
        
        // 5. 최고 점수 전략 선택
        Map.Entry<String, Double> best = strategyScores.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .orElse(new AbstractMap.SimpleEntry<>("DEFAULT", 0.5));
        
        return new StrategySelectionResult(
            best.getKey(),
            best.getValue(),
            LocalDateTime.now().plusSeconds(cacheTimeToLiveSeconds)
        );
    }
    
    /**
     * 세션 관련 이벤트 확인
     */
    private boolean isSessionRelatedEvent(String eventType, Map<String, Object> context) {
        // 이벤트 타입 확인
        if (eventType != null) {
            String type = eventType.toUpperCase();
            if (type.contains("SESSION") || type.contains("AUTH") || 
                type.contains("LOGIN") || type.contains("LOGOUT")) {
                return true;
            }
        }
        
        // 컨텍스트에 세션 정보 확인
        if (context.containsKey("sessionId") || context.containsKey("sessionContext")) {
            return true;
        }
        
        // IP 변경이나 User-Agent 변경 감지
        if (context.containsKey("ipChanged") || context.containsKey("userAgentChanged")) {
            return true;
        }
        
        // 세션 위협 지표 확인
        if (context.containsKey("sessionThreatIndicators") || 
            context.containsKey("sessionHijackSuspected")) {
            return true;
        }
        
        return false;
    }
    
    /**
     * 이벤트 분류
     */
    private EventCategory classifyEvent(String eventType, Map<String, Object> context) {
        // 이벤트 타입 기반 분류
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
        
        // 컨텍스트 기반 추가 분류
        if (context.containsKey("severity")) {
            String severity = String.valueOf(context.get("severity"));
            if ("CRITICAL".equals(severity) || "HIGH".equals(severity)) {
                return EventCategory.HIGH_RISK;
            }
        }
        
        return EventCategory.GENERAL;
    }
    
    /**
     * 컨텍스트 복잡도 계산
     */
    private double calculateComplexity(Map<String, Object> context) {
        double complexity = 0.0;
        
        // 컨텍스트 크기
        complexity += Math.min(context.size() / 20.0, 0.3);
        
        // 중첩 구조 복잡도
        for (Object value : context.values()) {
            if (value instanceof Map || value instanceof List) {
                complexity += 0.1;
            }
        }
        
        // 위협 지표 수
        if (context.containsKey("threatIndicators")) {
            Object indicators = context.get("threatIndicators");
            if (indicators instanceof List) {
                complexity += Math.min(((List<?>) indicators).size() / 10.0, 0.3);
            }
        }
        
        // 시간적 긴급성
        if (context.containsKey("urgency")) {
            String urgency = String.valueOf(context.get("urgency"));
            if ("CRITICAL".equals(urgency)) {
                complexity += 0.2;
            }
        }
        
        return Math.min(complexity, 1.0);
    }
    
    /**
     * 위협 지표 추출
     */
    private ThreatIndicators extractThreatIndicators(Map<String, Object> context) {
        ThreatIndicators indicators = new ThreatIndicators();
        
        // IOC (Indicators of Compromise)
        if (context.containsKey("ioc")) {
            indicators.setIocPresent(true);
            indicators.setIocCount(getListSize(context.get("ioc")));
        }
        
        // MITRE ATT&CK
        if (context.containsKey("mitre")) {
            indicators.setMitreMapping(true);
            indicators.setMitreTechniques(getListSize(context.get("mitre")));
        }
        
        // 이상 행동
        if (context.containsKey("anomaly")) {
            indicators.setAnomalyDetected(true);
            indicators.setAnomalyScore(getDoubleValue(context.get("anomaly")));
        }
        
        // 과거 위협
        if (context.containsKey("previousThreats")) {
            indicators.setHistoricalThreat(true);
            indicators.setHistoricalCount(getIntValue(context.get("previousThreats")));
        }
        
        // 위험 점수
        if (context.containsKey("riskScore")) {
            indicators.setRiskScore(getDoubleValue(context.get("riskScore")));
        }
        
        return indicators;
    }
    
    /**
     * 전략 적합도 계산
     */
    private double calculateStrategyFitness(
        io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy strategy,
        EventCategory category,
        double complexity,
        ThreatIndicators indicators
    ) {
        double fitness = 0.0;
        
        // 기본 적합도 (모든 전략에 기본 점수)
        fitness = 0.5;
        
        // 이벤트 타입 기반 적합도
        // 실제 인터페이스의 메서드를 사용
        if (strategy.isEnabled()) {
            fitness += 0.2;
        }
        
        // 우선순위 기반 점수
        int priority = strategy.getPriority();
        if (priority < 50) {
            fitness += 0.2;
        } else if (priority < 100) {
            fitness += 0.1;
        }
        
        return fitness;
    }
    
    /**
     * 모든 전략 평가
     */
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
    
    /**
     * 학습 데이터 업데이트
     */
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
        
        // 컨텍스트 패턴 학습
        data.addContextPattern(eventType, context);
        
        // 신뢰도 업데이트
        data.updateConfidenceAverage(result.getConfidence());
        
        log.debug("학습 데이터 업데이트 - Strategy: {}, Usage Count: {}", 
            strategyName, data.getUsageCount());
    }
    
    /**
     * 기본 전략 등록
     */
    private void registerDefaultStrategies() {
        // 통합 위협 평가기 (최우선)
        if (threatEvaluator != null) {
            strategies.put("INTEGRATED", new IntegratedThreatEvaluationStrategyAdapter(threatEvaluator));
            performanceMetrics.put("INTEGRATED", new StrategyPerformanceMetrics());
            log.info("통합 위협 평가 전략 등록: INTEGRATED");
        }

        // 세션 위협 평가 전략 - SecurityEventProcessingOrchestrator로 이관됨
        // SESSION_THREAT 전략은 더 이상 직접 등록하지 않음

        // AI Native: MITRE, NIST, CIS 규칙 기반 전략 제거
        // LLM이 직접 위협 평가를 수행하므로 하드코딩된 규칙 전략 불필요

        // 복합 평가 전략 (마지막에 등록 - 다른 전략들을 사용)
        if (compositeStrategy != null) {
            strategies.put("COMPOSITE", compositeStrategy);
            performanceMetrics.put("COMPOSITE", new StrategyPerformanceMetrics());
            log.info("복합 평가 전략 등록: COMPOSITE");
        }

        // 기본 전략 등록 (DefaultThreatEvaluationStrategy 사용)
        strategies.put("DEFAULT", new DefaultThreatEvaluationStrategy());
        performanceMetrics.put("DEFAULT", new StrategyPerformanceMetrics());
        log.info("기본 위협 평가 전략 등록: DEFAULT");
    }
    
    /**
     * 전략 등록
     */
    public void registerStrategy(String name, io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy strategy) {
        strategies.put(name, strategy);
        performanceMetrics.put(name, new StrategyPerformanceMetrics());
        log.info("전략 등록 완료: {}", name);
    }
    
    /**
     * 전략 가져오기
     */
    public io.contexa.contexacore.autonomous.strategy.ThreatEvaluationStrategy getStrategy(String name) {
        return strategies.get(name);
    }
    
    /**
     * 전략 성능 업데이트
     */
    public void updateStrategyPerformance(String strategyName, long executionTime, boolean success) {
        StrategyPerformanceMetrics metrics = performanceMetrics.get(strategyName);
        if (metrics != null) {
            metrics.updateMetrics(executionTime, success);
        }
    }
    
    /**
     * 캐시 정리 스케줄러
     */
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
    
    /**
     * 캐시 키 생성
     */
    private String generateCacheKey(String eventType, Map<String, Object> context) {
        // 주요 컨텍스트 요소만 사용하여 캐시 키 생성
        StringBuilder keyBuilder = new StringBuilder(eventType);
        
        // 중요한 컨텍스트 필드만 포함
        String[] importantFields = {"severity", "userId", "source", "category"};
        
        for (String field : importantFields) {
            if (context.containsKey(field)) {
                keyBuilder.append(":").append(context.get(field));
            }
        }
        
        return keyBuilder.toString();
    }
    
    /**
     * 메트릭 조회
     */
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
        
        // 전략별 성능 메트릭
        Map<String, Map<String, Object>> strategyMetrics = new HashMap<>();
        for (Map.Entry<String, StrategyPerformanceMetrics> entry : performanceMetrics.entrySet()) {
            strategyMetrics.put(entry.getKey(), entry.getValue().toMap());
        }
        metrics.put("strategyPerformance", strategyMetrics);
        
        return metrics;
    }
    
    // 유틸리티 메서드들
    
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
    
    // 내부 클래스들
    
    /**
     * 전략 선택 결과
     */
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
    
    /**
     * 전략 성능 메트릭
     */
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
                return 1.0;  // 기본값
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
    
    /**
     * 학습 데이터
     */
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
    
    /**
     * 이벤트 카테고리
     */
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
    
    /**
     * 위협 평가 전략 속성 정의 (내부 클래스)
     * Note: 실제 전략은 ThreatEvaluationStrategy 인터페이스를 구현
     */
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

    /**
     * 기본 위협 평가 전략 구현
     */
    private static class DefaultThreatEvaluationStrategy implements ThreatEvaluationStrategy {

        @Override
        public ThreatAssessment evaluate(SecurityEvent event) {
            // AI Native: 기본 위협 평가 - LLM 분석 필요 표시
            return ThreatAssessment.builder()
                .eventId(event.getEventId())
                .assessmentId("default-" + System.currentTimeMillis())
                .assessedAt(LocalDateTime.now())
                .evaluator("DEFAULT")
                .riskScore(0.5)
                .confidence(0.5)
                .recommendedActions(List.of("ESCALATE", "LLM_ANALYSIS_REQUIRED"))
                // AI Native v3.1: metadata 필드 제거됨 - 죽은 필드
                .action("ESCALATE")  // AI Native: LLM 분석 필요
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
            return 0.5; // 기본 위험 점수
        }

        @Override
        public boolean isEnabled() {
            return true;
        }

        @Override
        public int getPriority() {
            return 1000; // 가장 낮은 우선순위
        }
    }

    /**
     * ThreatEvaluator를 ThreatEvaluationStrategy로 어댑터
     */
    private static class IntegratedThreatEvaluationStrategyAdapter implements ThreatEvaluationStrategy {
        private final ThreatEvaluator threatEvaluator;

        public IntegratedThreatEvaluationStrategyAdapter(ThreatEvaluator threatEvaluator) {
            this.threatEvaluator = threatEvaluator;
        }

        @Override
        public ThreatAssessment evaluate(SecurityEvent event) {
            // ThreatEvaluator 사용
            return threatEvaluator.evaluateIntegrated(event);
        }

        @Override
        public List<ThreatIndicator> extractIndicators(SecurityEvent event) {
            return Collections.emptyList(); // IntegratedThreatEvaluator가 내부적으로 처리
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
            return 0.8; // 통합 전략의 기본 높은 위험도
        }

        @Override
        public boolean isEnabled() {
            return threatEvaluator != null;
        }

        @Override
        public int getPriority() {
            return 10; // 가장 높은 우선순위
        }
    }
}