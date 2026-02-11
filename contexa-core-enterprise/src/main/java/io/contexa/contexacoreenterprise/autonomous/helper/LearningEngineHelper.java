package io.contexa.contexacoreenterprise.autonomous.helper;

import io.contexa.contexacore.autonomous.LearningEngine;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacoreenterprise.autonomous.intelligence.AITuningService;
import io.contexa.contexacoreenterprise.properties.LearningEngineProperties;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class LearningEngineHelper implements LearningEngine {

    private final AITuningService aiTuningService;
    private final DistributedStateManager stateManager;

    private final LearningEngineProperties learningEngineProperties;

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    private final Map<String, LearningContext> learningContexts = new ConcurrentHashMap<>();

    private final Map<String, LearnedPattern> learnedPatterns = new ConcurrentHashMap<>();

    private final Queue<LearningEvent> learningQueue = new LinkedList<>();

    private final Map<String, FeedbackData> feedbackStore = new ConcurrentHashMap<>();

    private final Map<String, LearningEvent> learningEvents = new ConcurrentHashMap<>();

    private final AtomicLong totalLearningCycles = new AtomicLong(0);
    private final AtomicLong patternsIdentified = new AtomicLong(0);
    private final AtomicLong feedbackProcessed = new AtomicLong(0);

    @PostConstruct
    public void initialize() {
        if (!learningEngineProperties.isEnabled()) {
            return;
        }
        restoreLearningState();
        startLearningWorker();
    }

    @Override
    public Mono<?> learnFromEvent(
            SecurityEvent event,
            String response,
            double effectiveness) {

        if (!learningEngineProperties.isEnabled()) {
            return Mono.just(LearningResult.disabled());
        }

        return Mono.defer(() -> {

                    LearningEvent learningEvent = new LearningEvent(
                            event, response, effectiveness, LocalDateTime.now()
                    );

                    synchronized (learningQueue) {
                        learningQueue.offer(learningEvent);

                        if (learningQueue.size() >= learningEngineProperties.getBatchSize()) {
                            return processBatchLearning();
                        }
                    }

                    return Mono.just(LearningResult.queued(event.getEventId()));
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Mono<FeedbackResult> processFeedback(
            String eventId,
            FeedbackType feedback,
            Map<String, Object> details) {

        if (!learningEngineProperties.isEnabled()) {
            return Mono.just(FeedbackResult.disabled());
        }

        return Mono.defer(() -> {

            FeedbackData data = new FeedbackData(eventId, feedback, details, LocalDateTime.now());
            feedbackStore.put(eventId, data);

            updateLearningContextWithFeedback(eventId, feedback);

            if (feedback == FeedbackType.FALSE_POSITIVE) {

                SecurityEvent originalEvent = findOriginalEvent(eventId);
                if (originalEvent != null) {

                    return Mono.just(FeedbackResult.processed(eventId));
                }
            }

            feedbackProcessed.incrementAndGet();

            return Mono.just(FeedbackResult.processed(eventId));
        });
    }

    public Flux<LearnedPattern> identifyPatterns(List<SecurityEvent> events) {
        if (!learningEngineProperties.isEnabled() || events.isEmpty()) {
            return Flux.empty();
        }

        return Flux.defer(() -> {
            Map<String, List<SecurityEvent>> groupedEvents = groupEventsByPattern(events);

            return Flux.fromIterable(groupedEvents.entrySet())
                    .filter(entry -> entry.getValue().size() >= learningEngineProperties.getPatternMinOccurrences())
                    .map(entry -> {
                        String patternId = entry.getKey();
                        List<SecurityEvent> patternEvents = entry.getValue();

                        LearnedPattern pattern = learnPattern(patternId, patternEvents);

                        learnedPatterns.put(patternId, pattern);
                        patternsIdentified.incrementAndGet();

                        return pattern;
                    });
        });
    }

    @Override
    public Mono<?> applyLearning(SecurityEvent event) {
        if (!learningEngineProperties.isEnabled()) {
            return Mono.empty();
        }

        return Mono.defer(() -> {

            LearnedPattern matchingPattern = findMatchingPattern(event);

            if (matchingPattern == null) {
                return Mono.just(PredictionResult.noMatch());
            }

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

    private Mono<LearningResult> processBatchLearning() {
        return Mono.defer(() -> {
                    List<LearningEvent> batch = new ArrayList<>();

                    synchronized (learningQueue) {
                        while (!learningQueue.isEmpty() && batch.size() < learningEngineProperties.getBatchSize()) {
                            batch.add(learningQueue.poll());
                        }
                    }

                    if (batch.isEmpty()) {
                        return Mono.just(LearningResult.nothingToLearn());
                    }

                    for (LearningEvent event : batch) {
                        updateLearningContext(event);
                    }

                    reevaluatePatterns();

                    totalLearningCycles.incrementAndGet();

                    return Mono.just(LearningResult.batchProcessed(batch.size()));
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    public Double predictTrustScore(Map<String, Object> contextMap) {
        if (!learningEngineProperties.isEnabled() || contextMap == null) {
            return 0.5;
        }

        try {

            String userId = (String) contextMap.get("userId");
            String sourceIp = (String) contextMap.get("sourceIp");
            String userAgent = (String) contextMap.get("userAgent");

            double totalScore = 0.0;
            double totalWeight = 0.0;
            int matchCount = 0;

            for (LearnedPattern pattern : learnedPatterns.values()) {
                double similarity = calculateSimilarity(contextMap, pattern);

                if (similarity > learningEngineProperties.getConfidenceThreshold()) {

                    double weight = similarity * pattern.getConfidence();
                    double score = pattern.getEffectiveness();

                    totalScore += score * weight;
                    totalWeight += weight;
                    matchCount++;
                }
            }

            if (totalWeight > 0) {
                double predictedScore = totalScore / totalWeight;

                double confidence = Math.min(1.0, matchCount / 10.0);

                double finalScore = predictedScore * confidence + 0.5 * (1 - confidence);

                return finalScore;
            }

            return 0.5;

        } catch (Exception e) {
            log.error("Error predicting trust score", e);
            return 0.5;
        }
    }

    private double calculateSimilarity(Map<String, Object> context, LearnedPattern pattern) {

        Set<String> contextKeys = context.keySet();
        Set<String> patternKeys = pattern.getFeatures().keySet();

        Set<String> intersection = new HashSet<>(contextKeys);
        intersection.retainAll(patternKeys);

        Set<String> union = new HashSet<>(contextKeys);
        union.addAll(patternKeys);

        if (union.isEmpty()) {
            return 0.0;
        }

        double similarity = (double) intersection.size() / union.size();

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

        return (similarity + valueMatch) / 2.0;
    }

    private void updateLearningContext(LearningEvent event) {
        String contextId = generateContextId(event.getEvent());

        LearningContext context = learningContexts.computeIfAbsent(
                contextId, k -> new LearningContext(k)
        );

        context.addEvent(event);

        context.updateEffectiveness(event.getEffectiveness());

        context.recordResponse(event.getResponse(), event.getEffectiveness());
    }

    private void updateLearningContextWithFeedback(String eventId, FeedbackType feedback) {

        learningContexts.values().forEach(context -> {
            context.applyFeedback(eventId, feedback);
        });
    }

    private void reevaluatePatterns() {
        learnedPatterns.values().forEach(pattern -> {

            pattern.recalculateConfidence();

            if (pattern.isExpired(learningEngineProperties.getRetentionHours())) {
                learnedPatterns.remove(pattern.getPatternId());
            }
        });
    }

    private Map<String, List<SecurityEvent>> groupEventsByPattern(List<SecurityEvent> events) {
        return events.stream()
                .collect(Collectors.groupingBy(this::extractPatternSignature));
    }

    private LearnedPattern learnPattern(String patternId, List<SecurityEvent> events) {
        LearnedPattern pattern = new LearnedPattern(patternId);

        pattern.extractFeatures(events);

        pattern.determineOptimalResponse(events);

        pattern.calculateConfidence();

        return pattern;
    }

    private LearnedPattern findMatchingPattern(SecurityEvent event) {
        String signature = extractPatternSignature(event);

        LearnedPattern exactMatch = learnedPatterns.get(signature);
        if (exactMatch != null && exactMatch.getConfidence() >= learningEngineProperties.getConfidenceThreshold()) {
            return exactMatch;
        }

        return learnedPatterns.values().stream()
                .filter(p -> p.matches(event) && p.getConfidence() >= learningEngineProperties.getConfidenceThreshold())
                .max(Comparator.comparingDouble(LearnedPattern::getConfidence))
                .orElse(null);
    }

    private void startLearningWorker() {

        Flux.interval(Duration.ofMinutes(5))
                .flatMap(tick -> processBatchLearning())
                .subscribe(
                        result -> log.debug("배치 학습 완료: {}", result),
                        error -> log.error("배치 학습 실패", error)
                );
    }

    private void restoreLearningState() {

        try {

            stateManager.getState("learning_engine").subscribe(
                    savedState -> {
                        if (savedState != null) {

                        }
                    },
                    error -> log.warn("학습 상태 복원 실패, 새로 시작", error)
            );
        } catch (Exception e) {
            log.warn("학습 상태 복원 중 예외 발생", e);
        }
    }

    public void saveLearningState() {
        if (!learningEngineProperties.isEnabled()) {
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

            DistributedStateManager.SecurityState securityState = DistributedStateManager.SecurityState.builder()
                    .id("learning_engine")
                    .type("learning")
                    .data(state)
                    .lastModified(LocalDateTime.now())
                    .modifiedBy("learning-helper")
                    .version(1)
                    .build();
            stateManager.saveState("learning_engine", securityState).subscribe();
        } catch (Exception e) {
            log.error("학습 상태 저장 실패", e);
        }
    }

    private String generateContextId(SecurityEvent event) {
        return event.getSeverity() + "_" + event.getSource();
    }

    private String extractPatternSignature(SecurityEvent event) {

        return event.getSeverity() + "_" +
                event.getSource() + "_" +
                event.getEventId();
    }

    private SecurityEvent findOriginalEvent(String eventId) {
        if (eventId == null || eventId.isEmpty()) {
            return null;
        }

        try {

            if (redisTemplate != null) {
                String cacheKey = "security:event:" + eventId;
                Object cachedEvent = redisTemplate.opsForValue().get(cacheKey);

                if (cachedEvent instanceof SecurityEvent) {
                    return (SecurityEvent) cachedEvent;
                }
            }

            String learningEventKey = "learning:event:" + eventId;
            LearningEvent learningEvent = learningEvents.get(learningEventKey);

            if (learningEvent != null && learningEvent.getEvent() != null) {
                return learningEvent.getEvent();
            }

            DistributedStateManager.SecurityState securityState = stateManager.getState("event:" + eventId)
                    .block(Duration.ofSeconds(5));
            Map<String, Object> eventState = securityState != null ? securityState.getData() : null;
            if (eventState != null && !eventState.isEmpty()) {

                SecurityEvent reconstructedEvent = reconstructEventFromState(eventId, eventState);
                if (reconstructedEvent != null) {

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

    private SecurityEvent reconstructEventFromState(String eventId, Map<String, Object> state) {
        try {
            Map<String, Object> metadata = (Map<String, Object>) state.get("metadata");
            if (metadata == null) {
                metadata = new HashMap<>();
            }

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

    private void cacheEvent(String eventId, SecurityEvent event) {
        if (redisTemplate != null && event != null) {
            try {
                String cacheKey = "security:event:" + eventId;
                redisTemplate.opsForValue().set(cacheKey, event, Duration.ofMinutes(5));
            } catch (Exception e) {
                log.warn("Failed to cache event in Redis: {}", eventId, e);
            }
        }
    }

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

        public SecurityEvent getEvent() {
            return event;
        }

        public String getResponse() {
            return response;
        }

        public double getEffectiveness() {
            return effectiveness;
        }

        public LocalDateTime getTimestamp() {
            return timestamp;
        }
    }

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

        }
    }

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

        }

        public void determineOptimalResponse(List<SecurityEvent> events) {

        }

        public void calculateConfidence() {

        }

        public void recalculateConfidence() {

        }

        public boolean matches(SecurityEvent event) {

            return false;
        }

        public boolean isExpired(int retentionHours) {
            return lastUpdated.plusHours(retentionHours).isBefore(LocalDateTime.now());
        }

        public String getPatternId() {
            return patternId;
        }

        public Map<String, Object> getFeatures() {
            return features;
        }

        public String getRecommendedResponse() {
            return recommendedResponse;
        }

        public List<String> getAlternativeResponses() {
            return alternativeResponses;
        }

        public double getConfidence() {
            return confidence;
        }

        public double getEffectiveness() {

            return confidence;
        }
    }

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

    public enum FeedbackType {
        FALSE_POSITIVE,
        FALSE_NEGATIVE,
        CORRECT,
        INCORRECT,
        PARTIAL
    }

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

        public String getStatus() {
            return status;
        }

        public int getProcessedCount() {
            return processedCount;
        }
    }

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

        public String getStatus() {
            return status;
        }

        public String getEventId() {
            return eventId;
        }
    }

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

        public String getPredictedResponse() {
            return predictedResponse;
        }

        public double getConfidence() {
            return confidence;
        }

        public List<String> getAlternatives() {
            return alternatives;
        }

        public String getPatternId() {
            return patternId;
        }
    }
}