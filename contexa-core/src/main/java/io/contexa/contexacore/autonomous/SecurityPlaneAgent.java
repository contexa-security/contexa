package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.CommandLineRunner;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@RequiredArgsConstructor
@Slf4j
public class SecurityPlaneAgent implements CommandLineRunner, ISecurityPlaneAgent {

    private final SecurityMonitoringService securityMonitor;
    private final RedisTemplate<String, Object> redisTemplate;
    private final SecurityPlaneAuditLogger auditLogger;
    private final SecurityEventProcessor processingOrchestrator;
    private final SecurityPlaneProperties securityPlaneProperties;

    private AgentState currentState;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong processedEvents = new AtomicLong(0);

    @PostConstruct
    public void initialize() {
        currentState = AgentState.INITIALIZING;
        securityMonitor.setBatchProcessor(this::processBatch);
    }

    private void processBatch(List<SecurityEvent> events) {
        if (!running.get()) {
            log.error("[SecurityPlaneAgent] Agent not running, dropping {} events", events.size());
            return;
        }

        for (SecurityEvent event : events) {
            llmAnalysisExecutor.execute(() -> {
                try {
                    processSecurityEvent(event);
                    processedEvents.incrementAndGet();
                } catch (Exception e) {
                    log.error("[SecurityPlaneAgent] Error processing event: {}", event.getEventId(), e);
                }
            });
        }
    }

    @Override
    public void run(String... args) throws Exception {

        if (securityPlaneProperties.getAgent().isAutoStart()) {
            start();
        }
    }

    @Override
    public void start() {
        String agentName = securityPlaneProperties.getAgent().getName();
        if (running.compareAndSet(false, true)) {
            currentState = AgentState.RUNNING;
            Map<String, Object> config = createMonitoringConfig();
            securityMonitor.startMonitoring(agentName, config);
        } else {
            log.error("Agent {} is already running", agentName);
        }
    }

    @Override
    public void stop() {
        String agentName = securityPlaneProperties.getAgent().getName();
        if (running.compareAndSet(true, false)) {
            currentState = AgentState.STOPPING;
            securityMonitor.stopMonitoring(agentName);
            currentState = AgentState.STOPPED;
        }
    }

    @PreDestroy
    public void shutdown() {
        stop();
    }

    public void processSecurityEvent(SecurityEvent event) {
        if (processingOrchestrator != null) {
            processWithOrchestrator(event);
        } else {
            log.error("SecurityEventProcessingOrchestrator is not configured. Cannot process event: {}", event.getEventId());
            throw new IllegalStateException("SecurityEventProcessingOrchestrator must be configured");
        }
    }

    public void processWithOrchestrator(SecurityEvent event) {
        long startTime = System.currentTimeMillis();
        SecurityEventContext context = null;

        try {
            if (isEventAlreadyProcessed(event.getEventId())) {
                log.error("[SecurityPlaneAgent] Event {} already processed, skipping duplicate",
                        event.getEventId());
                return;
            }
            context = processingOrchestrator.process(event);
            markEventAsProcessed(event.getEventId());

        } catch (Exception e) {
            log.error("[SecurityPlaneAgent] Error processing event with orchestrator: {}",
                    event.getEventId(), e);

            if (context == null) {
                context = SecurityEventContext.builder()
                        .securityEvent(event)
                        .processingStatus(SecurityEventContext.ProcessingStatus.FAILED)
                        .createdAt(LocalDateTime.now())
                        .build();
            }

            context.markAsFailed("Processing error: " + e.getMessage());

            if (auditLogger != null) {
                Map<String, Object> errorContext = Map.of(
                        "eventId", event.getEventId(),
                        "userId", event.getUserId() != null ? event.getUserId() : "unknown",
                        "sourceIp", event.getSourceIp() != null ? event.getSourceIp() : "unknown",
                        "processingTime", System.currentTimeMillis() - startTime
                );
                auditLogger.auditError("SecurityPlaneAgent", "processWithOrchestrator", e, errorContext);
            }

            throw new RuntimeException("Event processing failed: " + event.getEventId(), e);

        }
    }

    private boolean isEventAlreadyProcessed(String eventId) {
        try {
            String processingKey = ZeroTrustRedisKeys.eventProcessed(eventId);
            return redisTemplate.hasKey(processingKey);
        } catch (Exception e) {
            log.error("[SecurityPlaneAgent] Failed to check event processing status: {}", eventId, e);
            return false;
        }
    }

    private void markEventAsProcessed(String eventId) {
        try {
            String processingKey = ZeroTrustRedisKeys.eventProcessed(eventId);
            redisTemplate.opsForValue().set(processingKey, "1", Duration.ofHours(24));
        } catch (Exception e) {
            log.error("[SecurityPlaneAgent] Failed to mark event as processed: {}", eventId, e);
        }
    }


    private Map<String, Object> createMonitoringConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("agentId", securityPlaneProperties.getAgent().getName());
        config.put("threatThreshold", securityPlaneProperties.getAgent().getThreatThreshold());
        config.put("correlationWindow", 10);
        return config;
    }

    @Override
    public boolean isRunning() {
        return running.get() && currentState == AgentState.RUNNING;
    }

    @Autowired
    @Qualifier("llmAnalysisExecutor")
    private Executor llmAnalysisExecutor;

    private enum AgentState {
        INITIALIZING,
        RUNNING,
        PAUSED,
        STOPPING,
        STOPPED,
        ERROR
    }
}
