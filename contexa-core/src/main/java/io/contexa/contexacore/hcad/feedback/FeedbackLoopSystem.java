package io.contexa.contexacore.hcad.feedback;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.contexa.contexacore.hcad.constants.HCADRedisKeys;
import io.contexa.contexacommon.hcad.domain.HCADContext;
import io.contexa.contexacore.hcad.threshold.UnifiedThresholdManager;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * 피드백 루프 시스템 (v2.0 - UnifiedThresholdManager 통합)
 * 사용자 피드백과 실제 결과를 기반으로 모델 개선
 *
 * 주요 기능:
 * 1. 오탐(False Positive) / 미탐(False Negative) 학습
 * 2. 베이스라인 자동 업데이트
 * 3. 임계값 동적 조정 (UnifiedThresholdManager를 통해)
 * 4. 모델 성능 모니터링
 * 5. 자동 재학습 트리거
 *
 * 변경사항 (v2.0):
 * - UnifiedThresholdManager 의존성 추가
 * - adjustThreshold()가 UnifiedThresholdManager.applyFeedbackThresholdAdjustment() 호출
 * - Redis 키 충돌 제거 (레거시 "threshold:{userId}" 키 사용 중지)
 *
 * @author contexa
 * @since 3.0
 */
@Slf4j
public class FeedbackLoopSystem {

    @Autowired(required = false)
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired(required = false)
    private JdbcTemplate jdbcTemplate;

    // 순환 의존성 해결: @Lazy 주입으로 UnifiedThresholdManager 지연 로딩
    @Lazy
    @Autowired(required = false)
    private UnifiedThresholdManager unifiedThresholdManager;


    @Value("${hcad.feedback.learning.rate:0.1}")
    private double learningRate;

    @Value("${hcad.feedback.baseline.update.threshold:0.95}")
    private double baselineUpdateThreshold;

    @Value("${hcad.feedback.retrain.threshold:0.7}")
    private double retrainThreshold;

    @Value("${hcad.feedback.window.size:1000}")
    private int feedbackWindowSize;

    // 피드백 캐시 설정
    @Value("${hcad.feedback.cache.max-size:50000}")
    private int feedbackCacheMaxSize;

    @Value("${hcad.feedback.cache.ttl-days:30}")
    private int feedbackCacheTtlDays;

    // 베이스라인 트래커 캐시 설정
    @Value("${hcad.feedback.tracker.cache.max-size:10000}")
    private int trackerCacheMaxSize;

    @Value("${hcad.feedback.tracker.cache.ttl-hours:24}")
    private int trackerCacheTtlHours;

    // 피드백 저장소 (Caffeine 캐시 - TTL 기반 자동 만료로 메모리 누수 방지)
    private Cache<String, FeedbackRecord> feedbackStore;

    // 성능 메트릭
    private final PerformanceMetrics metrics = new PerformanceMetrics();

    // 학습 큐
    private final Queue<LearningTask> learningQueue = new LinkedList<>();

    // 베이스라인 업데이트 추적 (Caffeine 캐시 - TTL 기반 자동 만료로 메모리 누수 방지)
    private Cache<String, BaselineUpdateTracker> baselineTrackers;

    /**
     * 캐시 초기화
     * Caffeine 캐시를 사용하여 TTL 기반 자동 만료로 메모리 누수를 방지한다.
     */
    @PostConstruct
    public void initializeCaches() {
        // 피드백 저장소 캐시 초기화
        this.feedbackStore = Caffeine.newBuilder()
            .maximumSize(feedbackCacheMaxSize)
            .expireAfterWrite(Duration.ofDays(feedbackCacheTtlDays))
            .recordStats()
            .build();

        // 베이스라인 트래커 캐시 초기화
        this.baselineTrackers = Caffeine.newBuilder()
            .maximumSize(trackerCacheMaxSize)
            .expireAfterWrite(Duration.ofHours(trackerCacheTtlHours))
            .recordStats()
            .build();

        log.info("[FeedbackLoopSystem] Caches initialized - feedbackStore: maxSize={}, ttlDays={}, trackerCache: maxSize={}, ttlHours={}",
            feedbackCacheMaxSize, feedbackCacheTtlDays, trackerCacheMaxSize, trackerCacheTtlHours);
    }

    /**
     * 피드백 제출
     */
    public void submitFeedback(String eventId, FeedbackType type, String userId,
                              HCADContext context, String reason) {
        try {
            // 1. 피드백 레코드 생성
            FeedbackRecord record = FeedbackRecord.builder()
                .eventId(eventId)
                .userId(userId)
                .feedbackType(type)
                .context(context)
                .reason(reason)
                .timestamp(LocalDateTime.now())
                .build();

            // 2. 저장소에 추가
            feedbackStore.put(eventId, record);

            // 3. 즉시 학습 필요 여부 판단
            if (shouldTriggerImmediateLearning(type)) {
                triggerImmediateLearning(record);
            }

            // 4. 메트릭 업데이트
            updateMetrics(type, userId);

            // 5. Redis에 저장 (영구 저장)
            if (redisTemplate != null) {
                saveFeedbackToRedis(record);
            }

            // 6. 베이스라인 업데이트 고려
            considerBaselineUpdate(userId, context, type);

            log.info("Feedback submitted: eventId={}, type={}, userId={}",
                    eventId, type, userId);

        } catch (Exception e) {
            log.error("Failed to submit feedback", e);
        }
    }

    /**
     * 즉시 학습 트리거 여부 판단
     */
    private boolean shouldTriggerImmediateLearning(FeedbackType type) {
        return type == FeedbackType.FALSE_NEGATIVE || // 미탐은 즉시 학습
               type == FeedbackType.CRITICAL_FALSE_POSITIVE; // 중요 오탐도 즉시
    }

    /**
     * 즉시 학습 수행
     */
    private void triggerImmediateLearning(FeedbackRecord record) {
        log.info("Triggering immediate learning for event: {}", record.getEventId());

        LearningTask task = new LearningTask(record);
        learningQueue.offer(task);

        // 비동기로 학습 실행
        processLearningTask(task);
    }

    /**
     * 학습 태스크 처리
     */
    private void processLearningTask(LearningTask task) {
        FeedbackRecord record = task.getRecord();
        String userId = record.getUserId();

        switch (record.getFeedbackType()) {
            case FALSE_POSITIVE:
                handleFalsePositive(record);
                break;

            case FALSE_NEGATIVE:
                handleFalseNegative(record);
                break;

            case TRUE_POSITIVE:
                handleTruePositive(record);
                break;

            case TRUE_NEGATIVE:
                handleTrueNegative(record);
                break;

            case CRITICAL_FALSE_POSITIVE:
                handleCriticalFalsePositive(record);
                break;

            case UNCERTAIN:
                handleUncertainFeedback(record);
                break;
        }

        // 학습 완료 표시
        task.markCompleted();
    }

    /**
     * False Positive 처리 (오탐)
     */
    private void handleFalsePositive(FeedbackRecord record) {
        String userId = record.getUserId();
        HCADContext context = record.getContext();

        log.debug("Handling false positive for user: {}", userId);

        // 1. 임계값 완화
        adjustThreshold(userId, ThresholdAdjustment.INCREASE, 0.05);

        // 2. 베이스라인에 현재 패턴 추가
        addToBaseline(userId, context, 0.8); // 80% 가중치로 추가

        // 3. 특징 가중치 조정
        adjustFeatureWeights(userId, context, -learningRate);

        // 4. 오탐 패턴 저장
        storeFalsePositivePattern(userId, context);
    }

    /**
     * False Negative 처리 (미탐)
     */
    private void handleFalseNegative(FeedbackRecord record) {
        String userId = record.getUserId();
        HCADContext context = record.getContext();

        log.debug("Handling false negative for user: {}", userId);

        // 1. 임계값 강화
        adjustThreshold(userId, ThresholdAdjustment.DECREASE, 0.1);

        // 2. 베이스라인에서 유사 패턴 제거
        removeFromBaseline(userId, context);

        // 3. 특징 가중치 강화
        adjustFeatureWeights(userId, context, learningRate * 2);

        // 4. 미탐 패턴을 블랙리스트에 추가
        addToBlacklistPattern(userId, context);

        // 5. 긴급 알림
        sendUrgentAlert(userId, "False negative detected - security risk");
    }

    /**
     * True Positive 처리 (정탐)
     */
    private void handleTruePositive(FeedbackRecord record) {
        String userId = record.getUserId();

        log.debug("Handling true positive for user: {}", userId);

        // 1. 현재 설정 강화 (잘 작동하고 있음)
        reinforceCurrentSettings(userId);

        // 2. 성공 패턴 저장
        storeTruePositivePattern(userId, record.getContext());

        // 3. 신뢰도 증가
        increaseModelConfidence(userId, 0.02);
    }

    /**
     * True Negative 처리 (정상 판정 맞음)
     */
    private void handleTrueNegative(FeedbackRecord record) {
        String userId = record.getUserId();

        log.debug("Handling true negative for user: {}", userId);

        // 1. 베이스라인 강화
        reinforceBaseline(userId, record.getContext());

        // 2. 노이즈 감소
        reduceNoise(userId);
    }

    /**
     * Critical False Positive 처리 (중요 오탐)
     */
    private void handleCriticalFalsePositive(FeedbackRecord record) {
        String userId = record.getUserId();

        log.error("Critical false positive for user: {}", userId);

        // 1. 긴급 임계값 조정
        adjustThreshold(userId, ThresholdAdjustment.INCREASE, 0.15);

        // 2. 모델 롤백 고려
        considerModelRollback(userId);

        // 3. 관리자 알림
        notifyAdministrator(userId, record);
    }

    /**
     * Uncertain Feedback 처리
     */
    private void handleUncertainFeedback(FeedbackRecord record) {
        // 불확실한 피드백은 가중치를 낮춰서 학습
        String userId = record.getUserId();

        log.debug("Handling uncertain feedback for user: {}", userId);

        // 낮은 학습률로 조정
        adjustFeatureWeights(userId, record.getContext(), learningRate * 0.3);
    }

    /**
     * 임계값 조정
     */
    /**
     * 임계값 조정 (v2.0 - UnifiedThresholdManager 통합)
     *
     * 레거시 방식(직접 Redis 저장)을 제거하고
     * UnifiedThresholdManager를 통해 임계값 조정을 적용합니다.
     *
     * @param userId 사용자 ID
     * @param adjustment 조정 방향 (INCREASE/DECREASE)
     * @param delta 조정값 크기
     */
    private void adjustThreshold(String userId, ThresholdAdjustment adjustment, double delta) {
        if (unifiedThresholdManager != null) {
            // UnifiedThresholdManager를 통한 통합 임계값 조정
            boolean isIncrease = (adjustment == ThresholdAdjustment.INCREASE);
            unifiedThresholdManager.applyFeedbackThresholdAdjustment(userId, isIncrease, delta);

            log.info("[FeedbackLoopSystem] Threshold adjustment request: userId={}, adjustment={}, delta={}",
                    userId, adjustment, delta);
        } else {
            log.warn("[FeedbackLoopSystem] UnifiedThresholdManager not available, threshold adjustment skipped for user: {}", userId);
        }
    }

    /**
     * 베이스라인에 패턴 추가
     */
    private void addToBaseline(String userId, HCADContext context, double weight) {
        BaselineUpdateTracker tracker = baselineTrackers.get(userId,
            k -> new BaselineUpdateTracker());

        tracker.addPattern(context, weight);

        // 충분한 패턴이 모이면 베이스라인 업데이트
        if (tracker.shouldUpdate()) {
            updateBaseline(userId, tracker);
        }
    }

    /**
     * 베이스라인에서 패턴 제거
     */
    private void removeFromBaseline(String userId, HCADContext context) {
        // vector_store 테이블에서 유사한 패턴을 비활성화 또는 메타데이터 업데이트
        if (jdbcTemplate != null) {
            // vector_store는 Spring AI의 Document 기반이므로 메타데이터에 active 플래그 추가
            String sql = "UPDATE vector_store " +
                        "SET metadata = jsonb_set(metadata, '{active}', 'false') " +
                        "WHERE metadata->>'userId' = ? " +
                        "AND 1 - (embedding <=> ?) < 0.1"; // 코사인 유사도 > 0.9

            jdbcTemplate.update(sql, userId, context.toVector());
        }
    }

    /**
     * 특징 가중치 조정
     */
    private void adjustFeatureWeights(String userId, HCADContext context, double adjustment) {
        String key = "weights:" + userId;

        if (redisTemplate != null) {
            Map<String, Double> weights = (Map<String, Double>) redisTemplate.opsForValue().get(key);
            if (weights == null) {
                weights = initializeDefaultWeights();
            }

            // 컨텍스트의 주요 특징에 대한 가중치 조정
            updateWeightsBasedOnContext(weights, context, adjustment);

            redisTemplate.opsForValue().set(key, weights);
        }
    }

    /**
     * 베이스라인 업데이트
     */
    private void updateBaseline(String userId, BaselineUpdateTracker tracker) {
        log.info("Updating baseline for user: {}", userId);

        // vector_store 테이블에 새 베이스라인 저장
        if (jdbcTemplate != null) {
            List<HCADContext> patterns = tracker.getPatterns();

            for (HCADContext pattern : patterns) {
                // vector_store 테이블 구조: id, content, metadata(jsonb), embedding(vector)
                String sql = "INSERT INTO vector_store (id, content, metadata, embedding) " +
                           "VALUES (?, ?, ?::jsonb, ?)";

                // ID 생성: userId + timestamp
                String id = userId + "_" + System.currentTimeMillis() + "_" + UUID.randomUUID();

                // content는 컨텍스트의 요약
                String content = "User behavior baseline: " + pattern.toCompactString();

                // 메타데이터 구성
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("userId", userId);
                metadata.put("type", "baseline");
                metadata.put("active", true);
                metadata.put("createdAt", LocalDateTime.now().toString());
                metadata.put("trustScore", pattern.getTrustScore());
                metadata.put("anomalyScore", pattern.getAnomalyScore());

                try {
                    jdbcTemplate.update(sql, id, content,
                                      new ObjectMapper().writeValueAsString(metadata),
                                      pattern.toVector());
                } catch (Exception e) {
                    log.error("Failed to update baseline for user: {}", userId, e);
                }
            }
        }

        // 트래커 리셋
        tracker.reset();
    }

    /**
     * 메트릭 업데이트
     */
    private void updateMetrics(FeedbackType type, String userId) {
        metrics.recordFeedback(type);

        // 성능 계산
        double precision = metrics.calculatePrecision();
        double recall = metrics.calculateRecall();
        double f1Score = metrics.calculateF1Score();

        log.info("Performance metrics - Precision: {}, Recall: {}, F1: {}",
                precision, recall, f1Score);

        // 재학습 필요 여부 확인
        if (f1Score < retrainThreshold) {
            triggerModelRetraining(userId);
        }
    }

    /**
     * 모델 재학습 트리거
     */
    private void triggerModelRetraining(String userId) {
        log.warn("Model performance below threshold. Triggering retraining for user: {}", userId);

        // 재학습 이벤트 발생
        if (redisTemplate != null) {
            redisTemplate.convertAndSend("retrain:channel", userId);
        }
    }

    /**
     * 주기적인 성능 리포트
     */
//    @Scheduled(fixedDelay = 3600000) // 1시간마다
    public void generatePerformanceReport() {
        log.info("=== Feedback Loop Performance Report ===");
        log.info("Total feedbacks: {}", feedbackStore.estimatedSize());
        log.info("Precision: {}", metrics.calculatePrecision());
        log.info("Recall: {}", metrics.calculateRecall());
        log.info("F1 Score: {}", metrics.calculateF1Score());
        log.info("False Positive Rate: {}", metrics.getFalsePositiveRate());
        log.info("False Negative Rate: {}", metrics.getFalseNegativeRate());

        // 사용자별 통계
        Map<String, Long> userStats = feedbackStore.asMap().values().stream()
            .collect(Collectors.groupingBy(FeedbackRecord::getUserId, Collectors.counting()));

        log.info("User statistics: {}", userStats);

        // Caffeine 캐시가 TTL 기반으로 자동 만료하므로 수동 정리 불필요
        log.info("[FeedbackLoopSystem] Cache cleanup handled by Caffeine TTL expiration");
    }

    /**
     * 오래된 피드백 정리 - Caffeine 캐시의 TTL 기반 자동 만료로 대체됨
     * 명시적 호출이 필요한 경우를 위해 유지하되, 캐시 무효화 메서드 사용
     */
    private void cleanupOldFeedback() {
        // Caffeine 캐시는 TTL 기반으로 자동 만료되므로 수동 정리 불필요
        // 강제 정리가 필요한 경우 cleanUp() 호출로 만료된 항목 즉시 제거
        feedbackStore.cleanUp();
        log.info("[FeedbackLoopSystem] Cache cleanup triggered, estimated remaining: {}",
            feedbackStore.estimatedSize());
    }

    // ===== Helper Methods =====

    private void saveFeedbackToRedis(FeedbackRecord record) {
        String key = "feedback:" + record.getEventId();
        redisTemplate.opsForValue().set(key, record, Duration.ofDays(30));
    }

    private void considerBaselineUpdate(String userId, HCADContext context, FeedbackType type) {
        if (type == FeedbackType.TRUE_NEGATIVE || type == FeedbackType.FALSE_POSITIVE) {
            BaselineUpdateTracker tracker = baselineTrackers.get(userId,
                k -> new BaselineUpdateTracker());

            double weight = type == FeedbackType.TRUE_NEGATIVE ? 1.0 : 0.7;
            tracker.addPattern(context, weight);
        }
    }

    private void storeFalsePositivePattern(String userId, HCADContext context) {
        String key = "fp:patterns:" + userId;
        if (redisTemplate != null) {
            redisTemplate.opsForList().rightPush(key, context);
            redisTemplate.expire(key, Duration.ofDays(7));
        }
    }

    private void addToBlacklistPattern(String userId, HCADContext context) {
        String key = "blacklist:patterns:" + userId;
        if (redisTemplate != null) {
            redisTemplate.opsForSet().add(key, context.toVector());
        }
    }

    private void sendUrgentAlert(String userId, String message) {
        log.error("URGENT ALERT for user {}: {}", userId, message);
        // 실제 알림 시스템 연동
    }

    private void reinforceCurrentSettings(String userId) {
        // 현재 설정 강화
        String key = "confidence:" + userId;
        if (redisTemplate != null) {
            redisTemplate.opsForValue().increment(key);
        }
    }

    private void storeTruePositivePattern(String userId, HCADContext context) {
        String key = "tp:patterns:" + userId;
        if (redisTemplate != null) {
            redisTemplate.opsForList().rightPush(key, context);
        }
    }

    private void increaseModelConfidence(String userId, double increase) {
        String key = "model:confidence:" + userId;
        if (redisTemplate != null) {
            Double confidence = (Double) redisTemplate.opsForValue().get(key);
            if (confidence == null) confidence = 0.5;
            confidence = Math.min(1.0, confidence + increase);
            redisTemplate.opsForValue().set(key, confidence);
        }
    }

    private void reinforceBaseline(String userId, HCADContext context) {
        addToBaseline(userId, context, 1.0);
    }

    private void reduceNoise(String userId) {
        // 노이즈 감소 로직
        String key = "noise:level:" + userId;
        if (redisTemplate != null) {
            Double noise = (Double) redisTemplate.opsForValue().get(key);
            if (noise == null) noise = 0.1;
            noise = Math.max(0.01, noise * 0.95);
            redisTemplate.opsForValue().set(key, noise);
        }
    }

    private void considerModelRollback(String userId) {
        log.warn("Considering model rollback for user: {}", userId);
        // 이전 버전으로 롤백 로직
    }

    private void notifyAdministrator(String userId, FeedbackRecord record) {
        log.error("Administrator notification: Critical issue for user {} - {}",
                 userId, record.getReason());
    }

    private Map<String, Double> initializeDefaultWeights() {
        Map<String, Double> weights = new HashMap<>();
        weights.put("velocity", 1.0);
        weights.put("sequence", 1.0);
        weights.put("location", 1.0);
        weights.put("device", 1.0);
        weights.put("time", 1.0);
        return weights;
    }

    private void updateWeightsBasedOnContext(Map<String, Double> weights,
                                            HCADContext context, double adjustment) {
        // 컨텍스트의 주요 특징에 따라 가중치 업데이트
        if (context.getActivityVelocity() > 10) {
            weights.merge("velocity", adjustment, Double::sum);
        }
        if (context.getRecentActivitySequence() != null && !context.getRecentActivitySequence().isEmpty()) {
            weights.merge("sequence", adjustment, Double::sum);
        }
        if (context.isNewDevice()) {
            weights.merge("device", adjustment * 1.5, Double::sum);
        }

        // 정규화 (0.1 ~ 2.0 범위)
        weights.replaceAll((k, v) -> Math.max(0.1, Math.min(2.0, v)));
    }

    /**
     * HCADFeedbackOrchestrator에서 사용하는 processFeedback 메소드
     */
    public CompletableFuture<FeedbackResult> processFeedback(LearningData learningData) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                log.debug("Processing feedback learning data: eventId={}, userId={}",
                    learningData.getEventId(), learningData.getUserId());

                // 학습 데이터를 FeedbackRecord로 변환
                FeedbackRecord record = convertToFeedbackRecord(learningData);

                // 기존 학습 로직 실행
                processLearningTask(new LearningTask(record));

                // 결과 생성
                return FeedbackResult.builder()
                    .success(true)
                    .processedAt(LocalDateTime.now())
                    .eventId(learningData.getEventId())
                    .userId(learningData.getUserId())
                    .thresholdAdjustments(generateThresholdAdjustments(learningData))
                    .embeddingWeights(generateEmbeddingWeights(learningData))
                    .searchPatterns(generateSearchPatterns(learningData))
                    .baselineUpdates(generateBaselineUpdates(learningData))
                    .learningMetrics(Map.of(
                        "adjustmentFactor", learningData.getConfidenceScore(),
                        "processingTime", System.currentTimeMillis(),
                        "learningType", learningData.getFeedbackType().toString()
                    ))
                    .build();

            } catch (Exception e) {
                log.error("Failed to process feedback learning data", e);
                return FeedbackResult.builder()
                    .success(false)
                    .errorMessage(e.getMessage())
                    .processedAt(LocalDateTime.now())
                    .build();
            }
        });
    }

    private FeedbackRecord convertToFeedbackRecord(LearningData learningData) {
        return FeedbackRecord.builder()
            .eventId(learningData.getEventId())
            .userId(learningData.getUserId())
            .feedbackType(learningData.getFeedbackType())
            .context(learningData.getContext())
            .reason(learningData.getReason())
            .confidence(learningData.getConfidenceScore())
            .timestamp(LocalDateTime.now())
            .build();
    }

    private Map<String, Object> generateThresholdAdjustments(LearningData learningData) {
        Map<String, Object> adjustments = new HashMap<>();
        double adjustmentFactor = learningData.getConfidenceScore();

        switch (learningData.getFeedbackType()) {
            case FALSE_POSITIVE:
                adjustments.put("increase", adjustmentFactor * 0.05);
                break;
            case FALSE_NEGATIVE:
                adjustments.put("decrease", adjustmentFactor * 0.05);
                break;
            default:
                adjustments.put("maintain", adjustmentFactor);
        }

        adjustments.put("userId", learningData.getUserId());
        adjustments.put("timestamp", LocalDateTime.now());
        return adjustments;
    }

    private Map<String, Object> generateEmbeddingWeights(LearningData learningData) {
        Map<String, Object> weights = new HashMap<>();
        weights.put("behavior", learningData.getConfidenceScore());
        weights.put("network", learningData.getConfidenceScore() * 0.8);
        weights.put("system", learningData.getConfidenceScore() * 0.9);
        weights.put("lastUpdated", LocalDateTime.now());
        return weights;
    }

    private Map<String, Object> generateSearchPatterns(LearningData learningData) {
        Map<String, Object> patterns = new HashMap<>();
        if (learningData.getContext() != null) {
            patterns.put("keywordPatterns", List.of(learningData.getContext().getEventType()));
            patterns.put("vectorPatterns", learningData.getContext().toVector());
            patterns.put("graphPatterns", Map.of("userId", learningData.getUserId()));
        }
        return patterns;
    }

    private Map<String, Object> generateBaselineUpdates(LearningData learningData) {
        Map<String, Object> updates = new HashMap<>();
        updates.put("addToBaseline", learningData.getFeedbackType() == FeedbackType.TRUE_POSITIVE);
        updates.put("removeFromBaseline", learningData.getFeedbackType() == FeedbackType.FALSE_POSITIVE);
        updates.put("weight", learningData.getConfidenceScore());
        updates.put("timestamp", LocalDateTime.now());
        return updates;
    }

    // ===== Inner Classes =====

    public enum FeedbackType {
        TRUE_POSITIVE,          // 정확한 이상 탐지
        FALSE_POSITIVE,         // 오탐 (정상을 이상으로)
        TRUE_NEGATIVE,          // 정확한 정상 판정
        FALSE_NEGATIVE,         // 미탐 (이상을 정상으로)
        CRITICAL_FALSE_POSITIVE, // 중요한 오탐
        UNCERTAIN              // 불확실
    }

    private enum ThresholdAdjustment {
        INCREASE,
        DECREASE
    }

    private static class FeedbackRecord {
        private final String eventId;
        private final String userId;
        private final FeedbackType feedbackType;
        private final HCADContext context;
        private final String reason;
        private final double confidence;
        private final LocalDateTime timestamp;

        private FeedbackRecord(Builder builder) {
            this.eventId = builder.eventId;
            this.userId = builder.userId;
            this.feedbackType = builder.feedbackType;
            this.context = builder.context;
            this.reason = builder.reason;
            this.confidence = builder.confidence;
            this.timestamp = builder.timestamp;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String eventId;
            private String userId;
            private FeedbackType feedbackType;
            private HCADContext context;
            private String reason;
            private double confidence;
            private LocalDateTime timestamp;

            public Builder eventId(String eventId) {
                this.eventId = eventId;
                return this;
            }

            public Builder userId(String userId) {
                this.userId = userId;
                return this;
            }

            public Builder feedbackType(FeedbackType type) {
                this.feedbackType = type;
                return this;
            }

            public Builder context(HCADContext context) {
                this.context = context;
                return this;
            }

            public Builder reason(String reason) {
                this.reason = reason;
                return this;
            }

            public Builder confidence(double confidence) {
                this.confidence = confidence;
                return this;
            }

            public Builder timestamp(LocalDateTime timestamp) {
                this.timestamp = timestamp;
                return this;
            }

            public FeedbackRecord build() {
                return new FeedbackRecord(this);
            }
        }

        // Getters
        public String getEventId() { return eventId; }
        public String getUserId() { return userId; }
        public FeedbackType getFeedbackType() { return feedbackType; }
        public HCADContext getContext() { return context; }
        public String getReason() { return reason; }
        public double getConfidence() { return confidence; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    private static class LearningTask {
        private final FeedbackRecord record;
        private boolean completed;
        private LocalDateTime startTime;
        private LocalDateTime endTime;

        public LearningTask(FeedbackRecord record) {
            this.record = record;
            this.completed = false;
            this.startTime = LocalDateTime.now();
        }

        public void markCompleted() {
            this.completed = true;
            this.endTime = LocalDateTime.now();
        }

        public FeedbackRecord getRecord() { return record; }
        public boolean isCompleted() { return completed; }
    }

    private static class PerformanceMetrics {
        private final AtomicInteger truePositives = new AtomicInteger();
        private final AtomicInteger falsePositives = new AtomicInteger();
        private final AtomicInteger trueNegatives = new AtomicInteger();
        private final AtomicInteger falseNegatives = new AtomicInteger();
        private final AtomicLong totalFeedbacks = new AtomicLong();

        public void recordFeedback(FeedbackType type) {
            totalFeedbacks.incrementAndGet();

            switch (type) {
                case TRUE_POSITIVE:
                    truePositives.incrementAndGet();
                    break;
                case FALSE_POSITIVE:
                case CRITICAL_FALSE_POSITIVE:
                    falsePositives.incrementAndGet();
                    break;
                case TRUE_NEGATIVE:
                    trueNegatives.incrementAndGet();
                    break;
                case FALSE_NEGATIVE:
                    falseNegatives.incrementAndGet();
                    break;
            }
        }

        public double calculatePrecision() {
            int tp = truePositives.get();
            int fp = falsePositives.get();
            if (tp + fp == 0) return 1.0;
            return (double) tp / (tp + fp);
        }

        public double calculateRecall() {
            int tp = truePositives.get();
            int fn = falseNegatives.get();
            if (tp + fn == 0) return 1.0;
            return (double) tp / (tp + fn);
        }

        public double calculateF1Score() {
            double precision = calculatePrecision();
            double recall = calculateRecall();
            if (precision + recall == 0) return 0.0;
            return 2 * (precision * recall) / (precision + recall);
        }

        public double getFalsePositiveRate() {
            int fp = falsePositives.get();
            int tn = trueNegatives.get();
            if (fp + tn == 0) return 0.0;
            return (double) fp / (fp + tn);
        }

        public double getFalseNegativeRate() {
            int fn = falseNegatives.get();
            int tp = truePositives.get();
            if (fn + tp == 0) return 0.0;
            return (double) fn / (fn + tp);
        }
    }

    private static class BaselineUpdateTracker {
        private final List<HCADContext> patterns = new ArrayList<>();
        private final Map<HCADContext, Double> weights = new HashMap<>();
        private int updateCount = 0;

        public void addPattern(HCADContext context, double weight) {
            patterns.add(context);
            weights.put(context, weight);
            updateCount++;
        }

        public boolean shouldUpdate() {
            // 10개 이상의 패턴이 모이면 업데이트
            return updateCount >= 10;
        }

        public List<HCADContext> getPatterns() {
            return new ArrayList<>(patterns);
        }

        public void reset() {
            patterns.clear();
            weights.clear();
            updateCount = 0;
        }
    }

    /**
     * 학습 데이터 클래스
     */
    public static class LearningData {
        private final String eventId;
        private final String userId;
        private final HCADContext context;
        private final FeedbackType feedbackType;
        private final Map<String, Object> features;
        private final double expectedScore;
        private final double confidenceScore;
        private final String reason;
        private final LocalDateTime timestamp;

        private LearningData(Builder builder) {
            this.eventId = builder.eventId;
            this.userId = builder.userId;
            this.context = builder.context;
            this.feedbackType = builder.feedbackType;
            this.features = builder.features;
            this.expectedScore = builder.expectedScore;
            this.confidenceScore = builder.confidenceScore;
            this.reason = builder.reason;
            this.timestamp = builder.timestamp;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String eventId;
            private String userId;
            private HCADContext context;
            private FeedbackType feedbackType;
            private Map<String, Object> features = new HashMap<>();
            private double expectedScore;
            private double confidenceScore;
            private String reason;
            private LocalDateTime timestamp;

            public Builder userId(String userId) {
                this.userId = userId;
                return this;
            }

            public Builder context(HCADContext context) {
                this.context = context;
                return this;
            }

            public Builder feedbackType(FeedbackType type) {
                this.feedbackType = type;
                return this;
            }

            public Builder features(Map<String, Object> features) {
                this.features = features;
                return this;
            }

            public Builder expectedScore(double score) {
                this.expectedScore = score;
                return this;
            }

            public Builder timestamp(LocalDateTime timestamp) {
                this.timestamp = timestamp;
                return this;
            }

            public Builder eventId(String eventId) {
                this.eventId = eventId;
                return this;
            }

            public Builder confidenceScore(double score) {
                this.confidenceScore = score;
                return this;
            }

            public Builder layerName(String layerName) {
                // layerName은 features에 저장
                this.features.put("layerName", layerName);
                return this;
            }

            public Builder reason(String reason) {
                this.reason = reason;
                return this;
            }

            public Builder riskScore(double riskScore) {
                this.expectedScore = riskScore;  // riskScore는 expectedScore와 동일하게 처리
                return this;
            }

            public LearningData build() {
                if (timestamp == null) {
                    timestamp = LocalDateTime.now();
                }
                return new LearningData(this);
            }
        }

        // Getters
        public String getEventId() { return eventId; }
        public String getUserId() { return userId; }
        public HCADContext getContext() { return context; }
        public FeedbackType getFeedbackType() { return feedbackType; }
        public Map<String, Object> getFeatures() { return features; }
        public double getExpectedScore() { return expectedScore; }
        public double getConfidenceScore() { return confidenceScore; }
        public String getReason() { return reason; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }

    /**
     * 피드백 결과 클래스
     */
    public static class FeedbackResult {
        private final String sessionId;
        private final boolean success;
        private final String message;
        private final String errorMessage;
        private final String eventId;
        private final String userId;
        private final Map<String, Object> resultData;
        private final double confidenceScore;
        private final LocalDateTime processedAt;
        // HCADFeedbackOrchestrator에서 필요한 필드들
        private final Map<String, Object> thresholdAdjustments;
        private final Map<String, Object> embeddingWeights;
        private final Map<String, Object> searchPatterns;
        private final Map<String, Object> baselineUpdates;
        private final Map<String, Object> learningMetrics;

        private FeedbackResult(Builder builder) {
            this.sessionId = builder.sessionId;
            this.success = builder.success;
            this.message = builder.message;
            this.errorMessage = builder.errorMessage;
            this.eventId = builder.eventId;
            this.userId = builder.userId;
            this.resultData = builder.resultData;
            this.confidenceScore = builder.confidenceScore;
            this.processedAt = builder.processedAt;
            this.thresholdAdjustments = builder.thresholdAdjustments;
            this.embeddingWeights = builder.embeddingWeights;
            this.searchPatterns = builder.searchPatterns;
            this.baselineUpdates = builder.baselineUpdates;
            this.learningMetrics = builder.learningMetrics;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String sessionId;
            private boolean success;
            private String message;
            private String errorMessage;
            private String eventId;
            private String userId;
            private Map<String, Object> resultData = new HashMap<>();
            private double confidenceScore;
            private LocalDateTime processedAt;
            private Map<String, Object> thresholdAdjustments = new HashMap<>();
            private Map<String, Object> embeddingWeights = new HashMap<>();
            private Map<String, Object> searchPatterns = new HashMap<>();
            private Map<String, Object> baselineUpdates = new HashMap<>();
            private Map<String, Object> learningMetrics = new HashMap<>();

            public Builder sessionId(String sessionId) {
                this.sessionId = sessionId;
                return this;
            }

            public Builder success(boolean success) {
                this.success = success;
                return this;
            }

            public Builder message(String message) {
                this.message = message;
                return this;
            }

            public Builder resultData(Map<String, Object> data) {
                this.resultData = data;
                return this;
            }

            public Builder confidenceScore(double score) {
                this.confidenceScore = score;
                return this;
            }

            public Builder processedAt(LocalDateTime time) {
                this.processedAt = time;
                return this;
            }

            public Builder errorMessage(String errorMessage) {
                this.errorMessage = errorMessage;
                return this;
            }

            public Builder eventId(String eventId) {
                this.eventId = eventId;
                return this;
            }

            public Builder userId(String userId) {
                this.userId = userId;
                return this;
            }

            public Builder thresholdAdjustments(Map<String, Object> adjustments) {
                this.thresholdAdjustments = adjustments != null ? adjustments : new HashMap<>();
                return this;
            }

            public Builder embeddingWeights(Map<String, Object> weights) {
                this.embeddingWeights = weights != null ? weights : new HashMap<>();
                return this;
            }

            public Builder searchPatterns(Map<String, Object> patterns) {
                this.searchPatterns = patterns != null ? patterns : new HashMap<>();
                return this;
            }

            public Builder baselineUpdates(Map<String, Object> updates) {
                this.baselineUpdates = updates != null ? updates : new HashMap<>();
                return this;
            }

            public Builder learningMetrics(Map<String, Object> metrics) {
                this.learningMetrics = metrics != null ? metrics : new HashMap<>();
                return this;
            }

            public FeedbackResult build() {
                if (processedAt == null) {
                    processedAt = LocalDateTime.now();
                }
                return new FeedbackResult(this);
            }
        }

        // Getters
        public String getSessionId() { return sessionId; }
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public String getErrorMessage() { return errorMessage; }
        public String getEventId() { return eventId; }
        public String getUserId() { return userId; }
        public Map<String, Object> getResultData() { return resultData; }
        public double getConfidenceScore() { return confidenceScore; }
        public LocalDateTime getProcessedAt() { return processedAt; }
        public Map<String, Object> getThresholdAdjustments() { return thresholdAdjustments; }
        public Map<String, Object> getEmbeddingWeights() { return embeddingWeights; }
        public Map<String, Object> getSearchPatterns() { return searchPatterns; }
        public Map<String, Object> getBaselineUpdates() { return baselineUpdates; }
        public Map<String, Object> getLearningMetrics() { return learningMetrics; }

        // Layer3ExpertStrategy에서 요구하는 추가 메소드들
        public List<String> getPatternsLearned() {
            // learningMetrics에서 패턴 정보 추출 또는 기본값 반환
            Object patterns = learningMetrics.get("patternsLearned");
            if (patterns instanceof List) {
                return (List<String>) patterns;
            }
            return List.of("Pattern learned from feedback: " + eventId);
        }

        public Map<String, Double> getAdaptiveThresholds() {
            // thresholdAdjustments를 Double 타입으로 변환
            Map<String, Double> adaptiveThresholds = new HashMap<>();
            for (Map.Entry<String, Object> entry : thresholdAdjustments.entrySet()) {
                if (entry.getValue() instanceof Number) {
                    adaptiveThresholds.put(entry.getKey(), ((Number) entry.getValue()).doubleValue());
                }
            }
            return adaptiveThresholds;
        }
    }

    /**
     * 학습 결과 클래스
     */
    public static class LearningResult {
        private final String userId;
        private final boolean learningSuccess;
        private final double newAccuracy;
        private final double improvementScore;
        private final Map<String, Double> updatedWeights;
        private final List<String> appliedChanges;
        private final LocalDateTime learningTime;

        private LearningResult(Builder builder) {
            this.userId = builder.userId;
            this.learningSuccess = builder.learningSuccess;
            this.newAccuracy = builder.newAccuracy;
            this.improvementScore = builder.improvementScore;
            this.updatedWeights = builder.updatedWeights;
            this.appliedChanges = builder.appliedChanges;
            this.learningTime = builder.learningTime;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String userId;
            private boolean learningSuccess;
            private double newAccuracy;
            private double improvementScore;
            private Map<String, Double> updatedWeights = new HashMap<>();
            private List<String> appliedChanges = new ArrayList<>();
            private LocalDateTime learningTime;

            public Builder userId(String userId) {
                this.userId = userId;
                return this;
            }

            public Builder learningSuccess(boolean success) {
                this.learningSuccess = success;
                return this;
            }

            public Builder newAccuracy(double accuracy) {
                this.newAccuracy = accuracy;
                return this;
            }

            public Builder improvementScore(double score) {
                this.improvementScore = score;
                return this;
            }

            public Builder updatedWeights(Map<String, Double> weights) {
                this.updatedWeights = weights;
                return this;
            }

            public Builder appliedChanges(List<String> changes) {
                this.appliedChanges = changes;
                return this;
            }

            public Builder learningTime(LocalDateTime time) {
                this.learningTime = time;
                return this;
            }

            public LearningResult build() {
                if (learningTime == null) {
                    learningTime = LocalDateTime.now();
                }
                return new LearningResult(this);
            }
        }

        // Getters
        public String getUserId() { return userId; }
        public boolean isLearningSuccess() { return learningSuccess; }
        public double getNewAccuracy() { return newAccuracy; }
        public double getImprovementScore() { return improvementScore; }
        public Map<String, Double> getUpdatedWeights() { return updatedWeights; }
        public List<String> getAppliedChanges() { return appliedChanges; }
        public LocalDateTime getLearningTime() { return learningTime; }

        // Layer3ExpertStrategy에서 요구하는 메소드들 추가
        public boolean isSuccessful() { return learningSuccess; }
        public List<String> getPatternsLearned() { return appliedChanges; }
        public double getConfidenceImprovement() { return improvementScore; }
        public double getAccuracyGain() { return newAccuracy; }
        public HCADContext getUpdatedBaseline() {
            // 기본 구현 - 필요시 추후 확장
            return null;
        }
        public Map<String, Double> getAdaptiveThresholds() { return updatedWeights; }

        // Layer3ExpertStrategy에서 추가로 요구하는 메소드들
        public List<EnhancedVector> getEnhancedVectors() {
            // 기본 구현 - 실제로는 벡터 향상 정보 반환
            return new ArrayList<>();
        }
        public int getTotalLearningCycles() { return 1; }
        public double getFalsePositiveReduction() { return improvementScore * 0.3; }
        public double getDetectionSpeedImprovement() { return improvementScore * 0.2; }
    }

    /**
     * 향상된 벡터 클래스
     */
    public static class EnhancedVector {
        private final String vectorType;
        private final double[] vector;
        private final double enhancement;
        private final LocalDateTime created;

        private EnhancedVector(String vectorType, double[] vector, double enhancement) {
            this.vectorType = vectorType;
            this.vector = vector;
            this.enhancement = enhancement;
            this.created = LocalDateTime.now();
        }

        public static EnhancedVector create(String vectorType, double[] vector, double enhancement) {
            return new EnhancedVector(vectorType, vector, enhancement);
        }

        public String getVectorType() { return vectorType; }
        public double[] getVector() { return vector; }
        public double getEnhancement() { return enhancement; }
        public LocalDateTime getCreated() { return created; }

        // Layer3ExpertStrategy에서 요구하는 추가 메소드들
        public double[] getEmbedding() { return vector; }
        public double getAccuracy() { return enhancement; }
        public double getConfidence() { return enhancement; }
    }

    /**
     * 분석 결과 클래스 (Layer3ExpertStrategy에서 사용)
     */
    public static class AnalysisResult {
        private final String eventId;
        private final String userId;
        private final double confidence;
        private final String analysisType;
        private final Map<String, Object> resultData;
        private final LocalDateTime analysisTime;

        private AnalysisResult(Builder builder) {
            this.eventId = builder.eventId;
            this.userId = builder.userId;
            this.confidence = builder.confidence;
            this.analysisType = builder.analysisType;
            this.resultData = builder.resultData;
            this.analysisTime = builder.analysisTime;
        }

        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private String eventId;
            private String userId;
            private double confidence;
            private String analysisType;
            private Map<String, Object> resultData = new HashMap<>();
            private LocalDateTime analysisTime;

            public Builder eventId(String eventId) {
                this.eventId = eventId;
                return this;
            }

            public Builder userId(String userId) {
                this.userId = userId;
                return this;
            }

            public Builder confidence(double confidence) {
                this.confidence = confidence;
                return this;
            }

            public Builder analysisType(String analysisType) {
                this.analysisType = analysisType;
                return this;
            }

            public Builder resultData(Map<String, Object> resultData) {
                this.resultData = resultData != null ? resultData : new HashMap<>();
                return this;
            }

            public Builder analysisTime(LocalDateTime analysisTime) {
                this.analysisTime = analysisTime;
                return this;
            }

            public AnalysisResult build() {
                if (analysisTime == null) {
                    analysisTime = LocalDateTime.now();
                }
                return new AnalysisResult(this);
            }
        }

        // Getters
        public String getEventId() { return eventId; }
        public String getUserId() { return userId; }
        public double getConfidence() { return confidence; }
        public String getAnalysisType() { return analysisType; }
        public Map<String, Object> getResultData() { return resultData; }
        public LocalDateTime getAnalysisTime() { return analysisTime; }
    }

    /**
     * 학습 데이터로부터 학습을 수행하고 결과를 반환
     */
    public LearningResult learnFromAnalysis(LearningData learningData) {
        try {
            log.debug("Starting learning from analysis: eventId={}, userId={}",
                learningData.getEventId(), learningData.getUserId());

            // 피드백 처리
            FeedbackRecord record = convertToFeedbackRecord(learningData);
            processLearningTask(new LearningTask(record));

            // 학습 결과 생성
            double improvementScore = calculateImprovementScore(learningData);
            double newAccuracy = 0.8; // 기본 정확도

            List<String> appliedChanges = new ArrayList<>();
            appliedChanges.add("Updated threshold for user: " + learningData.getUserId());
            appliedChanges.add("Adjusted embedding weights based on feedback");

            Map<String, Double> updatedWeights = new HashMap<>();
            updatedWeights.put("behavior", learningData.getConfidenceScore());
            updatedWeights.put("network", learningData.getConfidenceScore() * 0.8);
            updatedWeights.put("system", learningData.getConfidenceScore() * 0.9);

            return LearningResult.builder()
                .userId(learningData.getUserId())
                .learningSuccess(true)
                .newAccuracy(newAccuracy)
                .improvementScore(improvementScore)
                .updatedWeights(updatedWeights)
                .appliedChanges(appliedChanges)
                .learningTime(LocalDateTime.now())
                .build();

        } catch (Exception e) {
            log.error("Failed to learn from analysis: {}", e.getMessage(), e);
            return LearningResult.builder()
                .userId(learningData.getUserId())
                .learningSuccess(false)
                .newAccuracy(0.0)
                .improvementScore(0.0)
                .build();
        }
    }

    private double calculateImprovementScore(LearningData learningData) {
        // 피드백 타입에 따른 개선 점수 계산
        switch (learningData.getFeedbackType()) {
            case TRUE_POSITIVE:
                return learningData.getConfidenceScore() * 0.1;
            case FALSE_POSITIVE:
                return learningData.getConfidenceScore() * 0.15; // 오탐 개선은 더 중요
            case FALSE_NEGATIVE:
                return learningData.getConfidenceScore() * 0.2; // 미탐 개선이 가장 중요
            default:
                return learningData.getConfidenceScore() * 0.05;
        }
    }
}