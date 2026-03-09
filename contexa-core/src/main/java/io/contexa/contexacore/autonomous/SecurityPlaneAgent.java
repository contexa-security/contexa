package io.contexa.contexacore.autonomous;

import io.contexa.contexacommon.enums.AuditEventCategory;
import io.contexa.contexacore.autonomous.audit.AuditRecord;
import io.contexa.contexacore.autonomous.audit.CentralAuditFacade;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;

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
    private final SecurityContextDataStore dataStore;
    private final CentralAuditFacade centralAuditFacade;
    private final SecurityEventProcessor securityEventProcessor;
    private final SecurityPlaneProperties securityPlaneProperties;
    private final Executor llmAnalysisExecutor;

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
                    if (centralAuditFacade != null) {
                        auditError("SecurityPlaneAgent", "processBatch", e, Map.of(
                                "eventId", event.getEventId(),
                                "userId", event.getUserId() != null ? event.getUserId() : "unknown",
                                "phase", "async_batch_processing"
                        ));
                    }
                }
            });
        }
    }

    @Override
    public void run(String... args) {
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

    public SecurityEventContext processSecurityEvent(SecurityEvent event) {
        long startTime = System.currentTimeMillis();

        try {
            if (!tryMarkEventAsProcessed(event.getEventId())) {
                log.error("[SecurityPlaneAgent] Event {} already processed, skipping duplicate", event.getEventId());
                SecurityEventContext skippedContext = SecurityEventContext.builder()
                        .securityEvent(event)
                        .processingStatus(SecurityEventContext.ProcessingStatus.SKIPPED)
                        .build();
                skippedContext.addMetadata("skipReason", "duplicate_event");
                return skippedContext;
            }
            return securityEventProcessor.process(event);

        } catch (Exception e) {
            log.error("[SecurityPlaneAgent] Error processing event: {}", event.getEventId(), e);

            if (centralAuditFacade != null) {
                auditError("SecurityPlaneAgent", "processSecurityEvent", e, Map.of(
                        "eventId", event.getEventId(),
                        "userId", event.getUserId() != null ? event.getUserId() : "unknown",
                        "sourceIp", event.getSourceIp() != null ? event.getSourceIp() : "unknown",
                        "processingTime", System.currentTimeMillis() - startTime
                ));
            }
            throw new RuntimeException("Event processing failed: " + event.getEventId(), e);
        }
    }

    private void auditError(String component, String operation, Exception exception,
                            Map<String, Object> errorContext) {
        try {
            Map<String, Object> details = new HashMap<>();
            details.put("component", component);
            details.put("operation", operation);
            details.put("errorClass", exception.getClass().getName());
            details.put("errorMessage", exception.getMessage());
            if (errorContext != null) {
                details.put("errorContext", errorContext);
            }
            if (exception.getCause() != null) {
                details.put("cause", exception.getCause().getMessage());
            }

            String userId = errorContext != null ? String.valueOf(errorContext.getOrDefault("userId", "SYSTEM")) : "SYSTEM";
            String sourceIp = errorContext != null ? String.valueOf(errorContext.getOrDefault("sourceIp", "")) : null;
            String eventId = errorContext != null ? String.valueOf(errorContext.getOrDefault("eventId", component)) : component;

            centralAuditFacade.recordSync(AuditRecord.builder()
                    .eventCategory(AuditEventCategory.SECURITY_ERROR)
                    .principalName(userId)
                    .eventSource("CORE")
                    .clientIp(sourceIp != null && !sourceIp.isBlank() ? sourceIp : null)
                    .resourceIdentifier(eventId)
                    .resourceUri("/errors/" + component)
                    .action("SECURITY_ERROR")
                    .decision("ERROR")
                    .reason(exception.getMessage())
                    .outcome(exception.getClass().getSimpleName())
                    .details(details)
                    .build());
        } catch (Exception e) {
            log.error("Failed to audit error for component: {}", component, e);
        }
    }

    private boolean tryMarkEventAsProcessed(String eventId) {
        return dataStore.tryMarkEventAsProcessed(eventId);
    }

    private enum AgentState {
        INITIALIZING,
        RUNNING,
        STOPPING
    }
}
