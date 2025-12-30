package io.contexa.contexacoreenterprise.autonomous.helper;

import io.contexa.contexacore.autonomous.LearningEngine;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatIndicators;
import io.contexa.contexacoreenterprise.autonomous.intelligence.AITuningService;
import io.contexa.contexacore.autonomous.state.DistributedStateManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * LearningEngineHelper - 학습 엔진 구현체
 *
 * 자율 학습 및 진화를 담당하는 클래스입니다.
 * SecurityPlaneAgent와 협력하여 지속적인 학습과 개선을 수행합니다.
 *
 * 주요 기능:
 * - 이벤트 패턴 학습
 * - 행동 패턴 분석
 * - 피드백 기반 학습
 * - 학습 모델 관리
 *
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class LearningEngineHelper implements LearningEngine {
    
    // 기존 서비스 재사용
    private final AITuningService aiTuningService;
    private final DistributedStateManager stateManager;
    
    // Redis를 통한 이벤트 저장소 관리
    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;
    
    // 설정값
    @Value("${learning.engine.enabled:true}")
    private boolean learningEnabled;
    
    @Value("${learning.engine.batch-size:50}")
    private int batchSize;
    
    @Value("${learning.engine.learning-rate:0.01}")
    private double learningRate;
    
    @Value("${learning.engine.confidence-threshold:0.75}")
    private double confidenceThreshold;
    
    @Value("${learning.engine.retention-hours:168}")
    private int retentionHours;
    
    @Value("${learning.engine.pattern-min-occurrences:3}")
    private int patternMinOccurrences;
    
    // 학습 데이터 저장소
    private final Map<String, LearningContext> learningContexts = new ConcurrentHashMap<>();
    
    // 패턴 저장소
    private final Map<String, LearnedPattern> learnedPatterns = new ConcurrentHashMap<>();
    
    // 학습 큐
    private final Queue<LearningEvent> learningQueue = new LinkedList<>();
    
    // 피드백 저장소
    private final Map<String, FeedbackData> feedbackStore = new ConcurrentHashMap<>();
    
    // 학습 이벤트 저장소 (findOriginalEvent에서 사용)
    private final Map<String, LearningEvent> learningEvents = new ConcurrentHashMap<>();
    
    // 통계
    private final AtomicLong totalLearningCycles = new AtomicLong(0);
    private final AtomicLong patternsIdentified = new AtomicLong(0);
    private final AtomicLong feedbackProcessed = new AtomicLong(0);
    
    @PostConstruct
    public void initialize() {
        if (!learningEnabled) {
            log.info("학습 엔진 비활성화됨");
            return;
        }
        
        log.info("LearningEngineHelper 초기화 시작");
        
        // 기존 학습 데이터 복원
        restoreLearningState();
        
        // 학습 워커 시작
        startLearningWorker();
        
        log.info("LearningEngineHelper 초기화 완료 - {} 개의 패턴 로드됨", learnedPatterns.size());
    }
    
    /**
     * 보안 이벤트로부터 학습
     *
     * @param event 보안 이벤트
     * @param response 시스템 응답
     * @param effectiveness 효과성 (0.0 ~ 1.0)
     * @return 학습 결과
     */
    @Override
    public Mono<?> learnFromEvent(
            SecurityEvent event,
            String response,
            double effectiveness) {
        
        if (!learningEnabled) {
            return Mono.just(LearningResult.disabled());
        }
        
        return Mono.defer(() -> {
            // 학습 이벤트 생성
            LearningEvent learningEvent = new LearningEvent(
                event, response, effectiveness, LocalDateTime.now()
            );
            
            // 학습 큐에 추가
            synchronized (learningQueue) {
                learningQueue.offer(learningEvent);
                
                // 배치 크기에 도달하면 즉시 처리
                if (learningQueue.size() >= batchSize) {
                    return processBatchLearning();
                }
            }
            
            return Mono.just(LearningResult.queued(event.getEventId()));
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * 사용자 피드백 처리
     * 
     * @param eventId 이벤트 ID
     * @param feedback 피드백 타입
     * @param details 상세 정보
     * @return 처리 결과
     */
    public Mono<FeedbackResult> processFeedback(
            String eventId,
            FeedbackType feedback,
            Map<String, Object> details) {
        
        if (!learningEnabled) {
            return Mono.just(FeedbackResult.disabled());
        }
        
        return Mono.defer(() -> {
            // 피드백 저장
            FeedbackData data = new FeedbackData(eventId, feedback, details, LocalDateTime.now());
            feedbackStore.put(eventId, data);
            
            // 관련 학습 컨텍스트 업데이트
            updateLearningContextWithFeedback(eventId, feedback);
            
            // AI 튜닝 서비스에 피드백 전달
            if (feedback == FeedbackType.FALSE_POSITIVE) {
                // AITuningService의 기존 메서드 활용
                SecurityEvent originalEvent = findOriginalEvent(eventId);
                if (originalEvent != null) {
                    // UserFeedback는 패키지 프라이빗이므로 직접 생성할 수 없음
                    // 단순히 false positive 학습만 수행
                    return Mono.just(FeedbackResult.processed(eventId));
                }
            }
            
            feedbackProcessed.incrementAndGet();
            
            return Mono.just(FeedbackResult.processed(eventId));
        });
    }
    
    /**
     * 패턴 식별 및 학습
     * 
     * @param events 이벤트 목록
     * @return 식별된 패턴
     */
    public Flux<LearnedPattern> identifyPatterns(List<SecurityEvent> events) {
        if (!learningEnabled || events.isEmpty()) {
            return Flux.empty();
        }
        
        return Flux.defer(() -> {
            Map<String, List<SecurityEvent>> groupedEvents = groupEventsByPattern(events);
            
            return Flux.fromIterable(groupedEvents.entrySet())
                .filter(entry -> entry.getValue().size() >= patternMinOccurrences)
                .map(entry -> {
                    String patternId = entry.getKey();
                    List<SecurityEvent> patternEvents = entry.getValue();
                    
                    // 패턴 학습
                    LearnedPattern pattern = learnPattern(patternId, patternEvents);
                    
                    // 저장
                    learnedPatterns.put(patternId, pattern);
                    patternsIdentified.incrementAndGet();
                    
                    return pattern;
                });
        });
    }
    
    /**
     * 학습된 지식 적용
     *
     * @param event 새로운 이벤트
     * @return 예측 및 추천
     */
    @Override
    public Mono<?> applyLearning(SecurityEvent event) {
        if (!learningEnabled) {
            return Mono.empty();
        }
        
        return Mono.defer(() -> {
            // 유사 패턴 찾기
            LearnedPattern matchingPattern = findMatchingPattern(event);
            
            if (matchingPattern == null) {
                return Mono.just(PredictionResult.noMatch());
            }
            
            // 예측 생성
            double confidence = matchingPattern.getConfidence();
            String predictedResponse = matchingPattern.getRecommendedResponse();
            List<String> alternatives = matchingPattern.getAlternativeResponses();
            
            return Mono.just(new PredictionResult(
                predictedResponse,
                confidence,
                alternatives,
                matchingPattern.getPatternId()
            ));
        });
    }
    
    /**
     * 배치 학습 처리
     */
    private Mono<LearningResult> processBatchLearning() {
        return Mono.defer(() -> {
            List<LearningEvent> batch = new ArrayList<>();
            
            synchronized (learningQueue) {
                while (!learningQueue.isEmpty() && batch.size() < batchSize) {
                    batch.add(learningQueue.poll());
                }
            }
            
            if (batch.isEmpty()) {
                return Mono.just(LearningResult.nothingToLearn());
            }
            
            // 배치 학습 수행
            for (LearningEvent event : batch) {
                updateLearningContext(event);
            }
            
            // 패턴 재평가
            reevaluatePatterns();
            
            totalLearningCycles.incrementAndGet();
            
            return Mono.just(LearningResult.batchProcessed(batch.size()));
        })
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * Trust Score 예측
     * 
     * 학습된 패턴을 기반으로 신뢰 점수를 예측합니다.
     * 
     * @param contextMap 컨텍스트 맵
     * @return 예측된 trust score (0.0 ~ 1.0)
     */
    public Double predictTrustScore(Map<String, Object> contextMap) {
        if (!learningEnabled || contextMap == null) {
            return 0.5; // 기본값
        }
        
        try {
            // 1. 컨텍스트에서 특징 추출
            String userId = (String) contextMap.get("userId");
            String sourceIp = (String) contextMap.get("sourceIp");
            String userAgent = (String) contextMap.get("userAgent");
            
            // 2. 학습된 패턴에서 매칭 찾기
            double totalScore = 0.0;
            double totalWeight = 0.0;
            int matchCount = 0;
            
            for (LearnedPattern pattern : learnedPatterns.values()) {
                double similarity = calculateSimilarity(contextMap, pattern);
                
                if (similarity > confidenceThreshold) {
                    // 패턴의 신뢰도와 유사도를 가중치로 사용
                    double weight = similarity * pattern.getConfidence();
                    double score = pattern.getEffectiveness(); // 패턴의 효과성을 점수로 사용
                    
                    totalScore += score * weight;
                    totalWeight += weight;
                    matchCount++;
                }
            }
            
            // 3. 가중 평균 계산
            if (totalWeight > 0) {
                double predictedScore = totalScore / totalWeight;
                
                // 매칭된 패턴 수에 따른 보정
                double confidence = Math.min(1.0, matchCount / 10.0); // 10개 이상 매칭시 최대 신뢰도
                
                // 신뢰도를 반영한 최종 점수
                // 신뢰도가 낮으면 기본값(0.5)에 가깝게 조정
                double finalScore = predictedScore * confidence + 0.5 * (1 - confidence);
                
                log.debug("Predicted trust score: {} (based on {} patterns, confidence: {})", 
                    finalScore, matchCount, confidence);
                
                return finalScore;
            }
            
            // 매칭된 패턴이 없으면 기본값
            return 0.5;
            
        } catch (Exception e) {
            log.error("Error predicting trust score", e);
            return 0.5; // 에러시 기본값
        }
    }
    
    /**
     * 컨텍스트와 패턴 간 유사도 계산
     */
    private double calculateSimilarity(Map<String, Object> context, LearnedPattern pattern) {
        // 간단한 자카드 유사도 계산
        Set<String> contextKeys = context.keySet();
        Set<String> patternKeys = pattern.getFeatures().keySet();
        
        Set<String> intersection = new HashSet<>(contextKeys);
        intersection.retainAll(patternKeys);
        
        Set<String> union = new HashSet<>(contextKeys);
        union.addAll(patternKeys);
        
        if (union.isEmpty()) {
            return 0.0;
        }
        
        // 교집합 크기 / 합집합 크기
        double similarity = (double) intersection.size() / union.size();
        
        // 값 일치도 고려
        double valueMatch = 0.0;
        for (String key : intersection) {
            Object contextValue = context.get(key);
            Object patternValue = pattern.getFeatures().get(key);
            
            if (contextValue != null && contextValue.equals(patternValue)) {
                valueMatch += 1.0;
            }
        }
        
        if (!intersection.isEmpty()) {
            valueMatch = valueMatch / intersection.size();
        }
        
        // 키 유사도와 값 일치도의 평균
        return (similarity + valueMatch) / 2.0;
    }
    
    /**
     * 학습 컨텍스트 업데이트
     */
    private void updateLearningContext(LearningEvent event) {
        String contextId = generateContextId(event.getEvent());
        
        LearningContext context = learningContexts.computeIfAbsent(
            contextId, k -> new LearningContext(k)
        );
        
        // 이벤트 추가
        context.addEvent(event);
        
        // 효과성 업데이트
        context.updateEffectiveness(event.getEffectiveness());
        
        // 응답 패턴 업데이트
        context.recordResponse(event.getResponse(), event.getEffectiveness());
    }
    
    /**
     * 피드백으로 학습 컨텍스트 업데이트
     */
    private void updateLearningContextWithFeedback(String eventId, FeedbackType feedback) {
        // 모든 컨텍스트에서 해당 이벤트 찾기
        learningContexts.values().forEach(context -> {
            context.applyFeedback(eventId, feedback);
        });
    }
    
    /**
     * 패턴 재평가
     */
    private void reevaluatePatterns() {
        learnedPatterns.values().forEach(pattern -> {
            // 신뢰도 재계산
            pattern.recalculateConfidence();
            
            // 오래된 패턴 제거
            if (pattern.isExpired(retentionHours)) {
                learnedPatterns.remove(pattern.getPatternId());
            }
        });
    }
    
    /**
     * 이벤트를 패턴별로 그룹화
     */
    private Map<String, List<SecurityEvent>> groupEventsByPattern(List<SecurityEvent> events) {
        return events.stream()
            .collect(Collectors.groupingBy(this::extractPatternSignature));
    }
    
    /**
     * 패턴 학습
     */
    private LearnedPattern learnPattern(String patternId, List<SecurityEvent> events) {
        LearnedPattern pattern = new LearnedPattern(patternId);
        
        // 공통 특징 추출
        pattern.extractFeatures(events);
        
        // 최적 응답 결정
        pattern.determineOptimalResponse(events);
        
        // 신뢰도 계산
        pattern.calculateConfidence();
        
        return pattern;
    }
    
    /**
     * 매칭 패턴 찾기
     */
    private LearnedPattern findMatchingPattern(SecurityEvent event) {
        String signature = extractPatternSignature(event);
        
        // 정확한 매칭
        LearnedPattern exactMatch = learnedPatterns.get(signature);
        if (exactMatch != null && exactMatch.getConfidence() >= confidenceThreshold) {
            return exactMatch;
        }
        
        // 유사 패턴 검색
        return learnedPatterns.values().stream()
            .filter(p -> p.matches(event) && p.getConfidence() >= confidenceThreshold)
            .max(Comparator.comparingDouble(LearnedPattern::getConfidence))
            .orElse(null);
    }
    
    /**
     * 학습 워커 시작
     */
    private void startLearningWorker() {
        // 주기적인 배치 학습 처리
        Flux.interval(Duration.ofMinutes(5))
            .flatMap(tick -> processBatchLearning())
            .subscribe(
                result -> log.debug("배치 학습 완료: {}", result),
                error -> log.error("배치 학습 실패", error)
            );
    }
    
    /**
     * 학습 상태 복원
     */
    private void restoreLearningState() {
        // 분산 상태 관리자에서 학습 상태 복원
        try {
            // DistributedStateManager의 getState는 Mono<SecurityState>를 반환
            stateManager.getState("learning_engine").subscribe(
                savedState -> {
                    if (savedState != null) {
                        // 복원 로직
                        log.info("학습 상태 복원 완료");
                    }
                },
                error -> log.warn("학습 상태 복원 실패, 새로 시작", error)
            );
        } catch (Exception e) {
            log.warn("학습 상태 복원 중 예외 발생", e);
        }
    }
    
    /**
     * 학습 상태 저장
     */
//    @Scheduled(fixedDelay = 300000) // 5분마다
    public void saveLearningState() {
        if (!learningEnabled) {
            return;
        }
        
        try {
            Map<String, Object> state = new HashMap<>();
            state.put("patterns", learnedPatterns);
            state.put("contexts", learningContexts);
            state.put("statistics", Map.of(
                "totalCycles", totalLearningCycles.get(),
                "patternsIdentified", patternsIdentified.get(),
                "feedbackProcessed", feedbackProcessed.get()
            ));
            
            // SecurityState 객체로 변환하여 저장
            DistributedStateManager.SecurityState securityState = DistributedStateManager.SecurityState.builder()
                .id("learning_engine")
                .type("learning")
                .data(state)
                .lastModified(LocalDateTime.now())
                .modifiedBy("learning-helper")
                .version(1)
                .build();
            stateManager.saveState("learning_engine", securityState).subscribe();
            log.debug("학습 상태 저장 완료");
        } catch (Exception e) {
            log.error("학습 상태 저장 실패", e);
        }
    }
    
    // Helper 메서드들
    // AI Native v4.0.0: eventType 제거 - severity + source 기반
    private String generateContextId(SecurityEvent event) {
        return event.getSeverity() + "_" + event.getSource();
    }

    // AI Native v4.0.0: eventType 제거 - severity + source 기반
    private String extractPatternSignature(SecurityEvent event) {
        // 이벤트의 패턴 시그니처 추출
        return event.getSeverity() + "_" +
               event.getSource() + "_" +
               event.getEventId();
    }
    
    /**
     * 원본 이벤트 찾기
     * 
     * Redis와 이벤트 저장소에서 원본 이벤트를 조회합니다.
     * 이벤트는 일정 기간 동안 Redis에 캐시되며, 만료된 경우 영구 저장소에서 조회합니다.
     * 
     * @param eventId 이벤트 ID
     * @return 원본 SecurityEvent 또는 null
     */
    private SecurityEvent findOriginalEvent(String eventId) {
        if (eventId == null || eventId.isEmpty()) {
            return null;
        }
        
        try {
            // 1. Redis에서 먼저 조회 (최근 이벤트는 캐시됨)
            if (redisTemplate != null) {
                String cacheKey = "security:event:" + eventId;
                Object cachedEvent = redisTemplate.opsForValue().get(cacheKey);
                
                if (cachedEvent instanceof SecurityEvent) {
                    log.debug("Found event in Redis cache: {}", eventId);
                    return (SecurityEvent) cachedEvent;
                }
            }
            
            // 2. 학습 이벤트 저장소에서 조회
            String learningEventKey = "learning:event:" + eventId;
            LearningEvent learningEvent = learningEvents.get(learningEventKey);
            
            if (learningEvent != null && learningEvent.getEvent() != null) {
                log.debug("Found event in learning store: {}", eventId);
                return learningEvent.getEvent();
            }
            
            // 3. DistributedStateManager에서 조회 (분산 상태 저장소)
            DistributedStateManager.SecurityState securityState = stateManager.getState("event:" + eventId)
                .block(Duration.ofSeconds(5));
            Map<String, Object> eventState = securityState != null ? securityState.getData() : null;
            if (eventState != null && !eventState.isEmpty()) {
                // 상태에서 SecurityEvent 재구성
                SecurityEvent reconstructedEvent = reconstructEventFromState(eventId, eventState);
                if (reconstructedEvent != null) {
                    log.debug("Reconstructed event from distributed state: {}", eventId);
                    // Redis에 캐시 (5분간)
                    cacheEvent(eventId, reconstructedEvent);
                    return reconstructedEvent;
                }
            }
            
            log.warn("Event not found in any storage: {}", eventId);
            
        } catch (Exception e) {
            log.error("Error finding original event: {}", eventId, e);
        }
        
        return null;
    }
    
    /**
     * 상태 맵에서 SecurityEvent 재구성
     */
    // AI Native v4.0.0: eventType, targetResource 필드 제거
    private SecurityEvent reconstructEventFromState(String eventId, Map<String, Object> state) {
        try {
            Map<String, Object> metadata = (Map<String, Object>) state.get("metadata");
            if (metadata == null) {
                metadata = new HashMap<>();
            }
            // targetResource를 metadata에 저장
            if (state.get("targetResource") != null) {
                metadata.put("targetResource", state.get("targetResource"));
            }

            return SecurityEvent.builder()
                .eventId(eventId)
                .userId((String) state.get("userId"))
                .sourceIp((String) state.get("sourceIp"))
                .severity(SecurityEvent.Severity.valueOf(
                    (String) state.getOrDefault("severity", "MEDIUM")))
                .timestamp(state.containsKey("timestamp") ?
                    LocalDateTime.parse(state.get("timestamp").toString()) :
                    LocalDateTime.now())
                .metadata(metadata)
                .build();
        } catch (Exception e) {
            log.error("Failed to reconstruct event from state", e);
            return null;
        }
    }
    
    /**
     * 이벤트를 Redis에 캐시
     */
    private void cacheEvent(String eventId, SecurityEvent event) {
        if (redisTemplate != null && event != null) {
            try {
                String cacheKey = "security:event:" + eventId;
                redisTemplate.opsForValue().set(cacheKey, event, Duration.ofMinutes(5));
                log.debug("Cached event in Redis: {}", eventId);
            } catch (Exception e) {
                log.warn("Failed to cache event in Redis: {}", eventId, e);
            }
        }
    }
    
    // 내부 클래스들
    
    /**
     * 학습 이벤트
     */
    private static class LearningEvent {
        private final SecurityEvent event;
        private final String response;
        private final double effectiveness;
        private final LocalDateTime timestamp;
        
        public LearningEvent(SecurityEvent event, String response, 
                            double effectiveness, LocalDateTime timestamp) {
            this.event = event;
            this.response = response;
            this.effectiveness = effectiveness;
            this.timestamp = timestamp;
        }
        
        // Getters
        public SecurityEvent getEvent() { return event; }
        public String getResponse() { return response; }
        public double getEffectiveness() { return effectiveness; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    /**
     * 학습 컨텍스트
     */
    private static class LearningContext {
        private final String contextId;
        private final List<LearningEvent> events = new ArrayList<>();
        private final Map<String, ResponseStats> responseStats = new HashMap<>();
        private double averageEffectiveness = 0.0;
        private int eventCount = 0;
        
        public LearningContext(String contextId) {
            this.contextId = contextId;
        }
        
        public void addEvent(LearningEvent event) {
            events.add(event);
            eventCount++;
        }
        
        public void updateEffectiveness(double effectiveness) {
            averageEffectiveness = ((averageEffectiveness * (eventCount - 1)) + effectiveness) / eventCount;
        }
        
        public void recordResponse(String response, double effectiveness) {
            ResponseStats stats = responseStats.computeIfAbsent(response, k -> new ResponseStats());
            stats.record(effectiveness);
        }
        
        public void applyFeedback(String eventId, FeedbackType feedback) {
            // 피드백 적용 로직
        }
    }
    
    /**
     * 응답 통계
     */
    private static class ResponseStats {
        private int count = 0;
        private double totalEffectiveness = 0.0;
        
        public void record(double effectiveness) {
            count++;
            totalEffectiveness += effectiveness;
        }
        
        public double getAverageEffectiveness() {
            return count > 0 ? totalEffectiveness / count : 0.0;
        }
    }
    
    /**
     * 학습된 패턴
     */
    public static class LearnedPattern {
        private final String patternId;
        private final Map<String, Object> features = new HashMap<>();
        private String recommendedResponse;
        private List<String> alternativeResponses = new ArrayList<>();
        private double confidence = 0.5;
        private LocalDateTime lastUpdated = LocalDateTime.now();
        
        public LearnedPattern(String patternId) {
            this.patternId = patternId;
        }
        
        public void extractFeatures(List<SecurityEvent> events) {
            // 특징 추출 로직
        }
        
        public void determineOptimalResponse(List<SecurityEvent> events) {
            // 최적 응답 결정 로직
        }
        
        public void calculateConfidence() {
            // 신뢰도 계산 로직
        }
        
        public void recalculateConfidence() {
            // 신뢰도 재계산
        }
        
        public boolean matches(SecurityEvent event) {
            // 패턴 매칭 로직
            return false;
        }
        
        public boolean isExpired(int retentionHours) {
            return lastUpdated.plusHours(retentionHours).isBefore(LocalDateTime.now());
        }
        
        // Getters
        public String getPatternId() { return patternId; }
        public Map<String, Object> getFeatures() { return features; }
        public String getRecommendedResponse() { return recommendedResponse; }
        public List<String> getAlternativeResponses() { return alternativeResponses; }
        public double getConfidence() { return confidence; }
        public double getEffectiveness() { 
            // 효과성은 신뢰도와 비례하는 값으로 계산
            return confidence; 
        }
    }
    
    /**
     * 피드백 데이터
     */
    private static class FeedbackData {
        private final String eventId;
        private final FeedbackType type;
        private final Map<String, Object> details;
        private final LocalDateTime timestamp;
        
        public FeedbackData(String eventId, FeedbackType type, 
                           Map<String, Object> details, LocalDateTime timestamp) {
            this.eventId = eventId;
            this.type = type;
            this.details = details;
            this.timestamp = timestamp;
        }
    }
    
    /**
     * 피드백 타입
     */
    public enum FeedbackType {
        FALSE_POSITIVE,
        FALSE_NEGATIVE,
        CORRECT,
        INCORRECT,
        PARTIAL
    }
    
    /**
     * 학습 결과
     */
    public static class LearningResult {
        private final String status;
        private final int processedCount;
        
        private LearningResult(String status, int processedCount) {
            this.status = status;
            this.processedCount = processedCount;
        }
        
        public static LearningResult disabled() {
            return new LearningResult("disabled", 0);
        }
        
        public static LearningResult queued(String eventId) {
            return new LearningResult("queued", 0);
        }
        
        public static LearningResult batchProcessed(int count) {
            return new LearningResult("processed", count);
        }
        
        public static LearningResult nothingToLearn() {
            return new LearningResult("empty", 0);
        }
        
        // Getters
        public String getStatus() { return status; }
        public int getProcessedCount() { return processedCount; }
    }
    
    /**
     * 피드백 결과
     */
    public static class FeedbackResult {
        private final String status;
        private final String eventId;
        
        private FeedbackResult(String status, String eventId) {
            this.status = status;
            this.eventId = eventId;
        }
        
        public static FeedbackResult disabled() {
            return new FeedbackResult("disabled", null);
        }
        
        public static FeedbackResult processed(String eventId) {
            return new FeedbackResult("processed", eventId);
        }
        
        // Getters
        public String getStatus() { return status; }
        public String getEventId() { return eventId; }
    }
    
    /**
     * 예측 결과
     */
    public static class PredictionResult {
        private final String predictedResponse;
        private final double confidence;
        private final List<String> alternatives;
        private final String patternId;
        
        public PredictionResult(String predictedResponse, double confidence,
                               List<String> alternatives, String patternId) {
            this.predictedResponse = predictedResponse;
            this.confidence = confidence;
            this.alternatives = alternatives;
            this.patternId = patternId;
        }
        
        public static PredictionResult noMatch() {
            return new PredictionResult(null, 0.0, Collections.emptyList(), null);
        }
        
        // Getters
        public String getPredictedResponse() { return predictedResponse; }
        public double getConfidence() { return confidence; }
        public List<String> getAlternatives() { return alternatives; }
        public String getPatternId() { return patternId; }
    }
}