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

@Slf4j

@RequiredArgsConstructor
public class MetricsHandler implements SecurityEventHandler {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final AtomicLong processedEvents = new AtomicLong(0);
    private static final AtomicLong executedActions = new AtomicLong(0);
    private static final AtomicLong createdIncidents = new AtomicLong(0);

    private static final String METRICS_KEY_PREFIX = "security:metrics:";
    private static final String PROCESSED_EVENTS_KEY = METRICS_KEY_PREFIX + "processed_events";
    private static final String EXECUTED_ACTIONS_KEY = METRICS_KEY_PREFIX + "executed_actions";
    private static final String CREATED_INCIDENTS_KEY = METRICS_KEY_PREFIX + "created_incidents";

    @Override
    public boolean handle(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();

        try {
            
            long processed = processedEvents.incrementAndGet();
            updateRedisCounter(PROCESSED_EVENTS_KEY, processed);

            updateExecutedActions(context);

            updateCreatedIncidents(context);

            addMetricsToContext(context);

            if (processed % 100 == 0) {
                logStatistics();
            }

            return true; 

        } catch (Exception e) {
            log.error("[MetricsHandler] Error updating metrics for event: {}", event.getEventId(), e);
            
            return true;
        }
    }

    private void updateExecutedActions(SecurityEventContext context) {
        
        ProcessingResult result = (ProcessingResult) context.getMetadata().get("processingResult");
        if (result != null && result.getExecutedActions() != null) {
            int actionCount = result.getExecutedActions().size();
            if (actionCount > 0) {
                long total = executedActions.addAndGet(actionCount);
                updateRedisCounter(EXECUTED_ACTIONS_KEY, total);
                            }
        }

        if (context.getResponseActions() != null && !context.getResponseActions().isEmpty()) {
            int actionCount = context.getResponseActions().size();
            long total = executedActions.addAndGet(actionCount);
            updateRedisCounter(EXECUTED_ACTIONS_KEY, total);
        }
    }

    private void updateCreatedIncidents(SecurityEventContext context) {
        
        ProcessingResult result = (ProcessingResult) context.getMetadata().get("processingResult");
        if (result != null && result.isRequiresIncident()) {
            long total = createdIncidents.incrementAndGet();
            updateRedisCounter(CREATED_INCIDENTS_KEY, total);
                    }

        Boolean incidentCreated = (Boolean) context.getMetadata().get("incidentCreated");
        if (Boolean.TRUE.equals(incidentCreated)) {
            long total = createdIncidents.incrementAndGet();
            updateRedisCounter(CREATED_INCIDENTS_KEY, total);
        }
    }

    private void updateRedisCounter(String key, long value) {
        try {
            redisTemplate.opsForValue().set(key, value, Duration.ofDays(30));
        } catch (Exception e) {
            log.error("[MetricsHandler] Failed to update Redis counter: {}", key, e);
        }
    }

    private void addMetricsToContext(SecurityEventContext context) {
        context.addMetadata("metrics.processedEvents", processedEvents.get());
        context.addMetadata("metrics.executedActions", executedActions.get());
        context.addMetadata("metrics.createdIncidents", createdIncidents.get());
        context.addMetadata("metrics.timestamp", System.currentTimeMillis());
    }

    private void logStatistics() {
            }

    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("processedEvents", processedEvents.get());
        stats.put("executedActions", executedActions.get());
        stats.put("createdIncidents", createdIncidents.get());

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

    public void resetStatistics() {
        processedEvents.set(0);
        executedActions.set(0);
        createdIncidents.set(0);

        try {
            redisTemplate.delete(PROCESSED_EVENTS_KEY);
            redisTemplate.delete(EXECUTED_ACTIONS_KEY);
            redisTemplate.delete(CREATED_INCIDENTS_KEY);
        } catch (Exception e) {
            log.error("[MetricsHandler] Failed to reset Redis statistics", e);
        }

            }

    @Override
    public String getName() {
        return "MetricsHandler";
    }

    @Override
    public int getOrder() {
        return 60; 
    }
}