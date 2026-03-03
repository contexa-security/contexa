package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.CommandLineRunner;

import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@RequiredArgsConstructor
@Slf4j
public class SecurityPlaneAgent implements CommandLineRunner, ISecurityPlaneAgent {

    private final SecurityMonitoringService securityMonitor;
    private final SecurityContextDataStore dataStore;
    private final SecurityPlaneAuditLogger auditLogger;
    private final SecurityEventProcessor securityEventProcessor;
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
                    if (auditLogger != null) {
                        Map<String, Object> errorContext = Map.of(
                                "eventId", event.getEventId(),
                                "userId", event.getUserId() != null ? event.getUserId() : "unknown",
                                "phase", "async_batch_processing"
                        );
                        auditLogger.auditError("SecurityPlaneAgent", "processBatch", e, errorContext);
                    }
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
        } else {
            log.error("Agent {} is already running", agentName);
        }
    }

    @Override
    public void stop() {
        if (running.compareAndSet(true, false)) {
            currentState = AgentState.STOPPING;
        }
    }

    @PreDestroy
    public void shutdown() {
        stop();
    }

    public void processSecurityEvent(SecurityEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            if (!tryMarkEventAsProcessed(event.getEventId())) {
                log.error("[SecurityPlaneAgent] Event {} already processed, skipping duplicate",
                        event.getEventId());
                return;
            }
            securityEventProcessor.process(event);

        } catch (Exception e) {
            log.error("[SecurityPlaneAgent] Error processing event: {}", event.getEventId(), e);

            if (auditLogger != null) {
                Map<String, Object> errorContext = Map.of(
                        "eventId", event.getEventId(),
                        "userId", event.getUserId() != null ? event.getUserId() : "unknown",
                        "sourceIp", event.getSourceIp() != null ? event.getSourceIp() : "unknown",
                        "processingTime", System.currentTimeMillis() - startTime
                );
                auditLogger.auditError("SecurityPlaneAgent", "processSecurityEvent", e, errorContext);
            }
            throw new RuntimeException("Event processing failed: " + event.getEventId(), e);
        }
    }

    private boolean tryMarkEventAsProcessed(String eventId) {
        return dataStore.tryMarkEventAsProcessed(eventId);
    }

    @Autowired
    @Qualifier("llmAnalysisExecutor")
    private Executor llmAnalysisExecutor;

    private enum AgentState {
        INITIALIZING,
        RUNNING,
        STOPPING
    }
}
