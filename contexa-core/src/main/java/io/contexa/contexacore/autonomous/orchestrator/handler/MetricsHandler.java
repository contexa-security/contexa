package io.contexa.contexacore.autonomous.orchestrator.handler;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventHandler;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 메트릭스 핸들러
 *
 * SecurityPlaneAgent의 통계 관리 로직을 분리
 * - processedEvents 카운터
 * - executedActions 카운터
 * - createdIncidents 카운터
 * - 통계 정보 Redis 저장
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j

@RequiredArgsConstructor
public class MetricsHandler implements SecurityEventHandler {

    private final RedisTemplate<String, Object> redisTemplate;

    // 통계 카운터
    private static final AtomicLong processedEvents = new AtomicLong(0);
    private static final AtomicLong executedActions = new AtomicLong(0);
    private static final AtomicLong createdIncidents = new AtomicLong(0);

    // Redis 키
    private static final String METRICS_KEY_PREFIX = "security:metrics:";
    private static final String PROCESSED_EVENTS_KEY = METRICS_KEY_PREFIX + "processed_events";
    private static final String EXECUTED_ACTIONS_KEY = METRICS_KEY_PREFIX + "executed_actions";
    private static final String CREATED_INCIDENTS_KEY = METRICS_KEY_PREFIX + "created_incidents";

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();

        log.debug("[MetricsHandler] Updating metrics for event: {}", event.getEventId());

        try {
            // 1. 처리된 이벤트 카운트 증가
            long processed = processedEvents.incrementAndGet();
            updateRedisCounter(PROCESSED_EVENTS_KEY, processed);

            // 2. 실행된 액션 카운트 업데이트
            updateExecutedActions(context);

            // 3. 생성된 인시던트 카운트 업데이트
            updateCreatedIncidents(context);

            // 4. 컨텍스트에 메트릭스 추가
            addMetricsToContext(context);

            // 5. 주기적으로 통계 로그 출력
            if (processed % 100 == 0) {
                logStatistics();
            }

            log.debug("[MetricsHandler] Metrics updated - processed: {}, actions: {}, incidents: {}",
                processed, executedActions.get(), createdIncidents.get());

            return true; // 다음 핸들러로 계속 진행

        } catch (Exception e) {
            log.error("[MetricsHandler] Error updating metrics for event: {}", event.getEventId(), e);
            // 메트릭스 오류는 처리를 중단하지 않음
            return true;
        }
    }

    /**
     * 실행된 액션 카운트 업데이트
     */
    private void updateExecutedActions(SecurityEventContext context) {
        // ProcessingResult에서 실행된 액션 확인
        ProcessingResult result = (ProcessingResult) context.getMetadata().get("processingResult");
        if (result != null && result.getExecutedActions() != null) {
            int actionCount = result.getExecutedActions().size();
            if (actionCount > 0) {
                long total = executedActions.addAndGet(actionCount);
                updateRedisCounter(EXECUTED_ACTIONS_KEY, total);
                log.debug("[MetricsHandler] {} actions executed, total: {}", actionCount, total);
            }
        }

        // ResponseAction에서도 확인
        if (context.getResponseActions() != null && !context.getResponseActions().isEmpty()) {
            int actionCount = context.getResponseActions().size();
            long total = executedActions.addAndGet(actionCount);
            updateRedisCounter(EXECUTED_ACTIONS_KEY, total);
        }
    }

    /**
     * 생성된 인시던트 카운트 업데이트
     */
    private void updateCreatedIncidents(SecurityEventContext context) {
        // ProcessingResult에서 인시던트 필요 여부 확인
        ProcessingResult result = (ProcessingResult) context.getMetadata().get("processingResult");
        if (result != null && result.isRequiresIncident()) {
            long total = createdIncidents.incrementAndGet();
            updateRedisCounter(CREATED_INCIDENTS_KEY, total);
            log.info("[MetricsHandler] Incident created, total: {}", total);
        }

        // 메타데이터에서도 확인
        Boolean incidentCreated = (Boolean) context.getMetadata().get("incidentCreated");
        if (Boolean.TRUE.equals(incidentCreated)) {
            long total = createdIncidents.incrementAndGet();
            updateRedisCounter(CREATED_INCIDENTS_KEY, total);
        }
    }

    /**
     * Redis 카운터 업데이트
     */
    private void updateRedisCounter(String key, long value) {
        try {
            redisTemplate.opsForValue().set(key, value, Duration.ofDays(30));
        } catch (Exception e) {
            log.error("[MetricsHandler] Failed to update Redis counter: {}", key, e);
        }
    }

    /**
     * 컨텍스트에 메트릭스 추가
     */
    private void addMetricsToContext(SecurityEventContext context) {
        context.addMetadata("metrics.processedEvents", processedEvents.get());
        context.addMetadata("metrics.executedActions", executedActions.get());
        context.addMetadata("metrics.createdIncidents", createdIncidents.get());
        context.addMetadata("metrics.timestamp", System.currentTimeMillis());
    }

    /**
     * 통계 로그 출력
     */
    private void logStatistics() {
        log.info("[MetricsHandler] Statistics - Processed Events: {}, Executed Actions: {}, Created Incidents: {}",
            processedEvents.get(), executedActions.get(), createdIncidents.get());
    }

    /**
     * 통계 조회
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("processedEvents", processedEvents.get());
        stats.put("executedActions", executedActions.get());
        stats.put("createdIncidents", createdIncidents.get());

        // Redis에서도 조회
        try {
            Long redisProcessed = (Long) redisTemplate.opsForValue().get(PROCESSED_EVENTS_KEY);
            Long redisActions = (Long) redisTemplate.opsForValue().get(EXECUTED_ACTIONS_KEY);
            Long redisIncidents = (Long) redisTemplate.opsForValue().get(CREATED_INCIDENTS_KEY);

            stats.put("redis.processedEvents", redisProcessed);
            stats.put("redis.executedActions", redisActions);
            stats.put("redis.createdIncidents", redisIncidents);
        } catch (Exception e) {
            log.error("[MetricsHandler] Failed to get Redis statistics", e);
        }

        return stats;
    }

    /**
     * 통계 초기화
     */
    public void resetStatistics() {
        processedEvents.set(0);
        executedActions.set(0);
        createdIncidents.set(0);

        // Redis도 초기화
        try {
            redisTemplate.delete(PROCESSED_EVENTS_KEY);
            redisTemplate.delete(EXECUTED_ACTIONS_KEY);
            redisTemplate.delete(CREATED_INCIDENTS_KEY);
        } catch (Exception e) {
            log.error("[MetricsHandler] Failed to reset Redis statistics", e);
        }

        log.info("[MetricsHandler] Statistics reset");
    }

    @Override
    public String getName() {
        return "MetricsHandler";
    }

    @Override
    public int getOrder() {
        return 60; // ProcessingExecutionHandler(50) 다음에 실행
    }
}