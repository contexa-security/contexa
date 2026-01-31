package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.audit.SecurityPlaneAuditLogger;
import io.contexa.contexacore.autonomous.domain.*;
import io.contexa.contexacore.autonomous.event.DynamicThreatResponseEvent;
import io.contexa.contexacore.autonomous.event.IncidentResolvedEvent;
import io.contexa.contexacore.autonomous.orchestrator.SecurityEventProcessingOrchestrator;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.ISoarContextProvider;
import io.contexa.contexacore.autonomous.service.ISoarNotifier;
import io.contexa.contexacore.autonomous.service.impl.SecurityMonitoringService;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.utils.ZeroTrustRedisKeys;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.soar.SoarLab;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@RequiredArgsConstructor
@Slf4j
public class SecurityPlaneAgent implements CommandLineRunner, ISecurityPlaneAgent {

    private final SecurityMonitoringService securityMonitor;
    private final RedisTemplate<String, Object> redisTemplate;
    private final ApplicationEventPublisher eventPublisher;
    private final SecurityPlaneAuditLogger auditLogger;

    @Autowired(required = false)
    private ISoarContextProvider contextProvider;

    @Autowired(required = false)
    private ISoarNotifier soarNotifier;

    @Autowired(required = false)
    private LearningEngine learningEngine;

    @Autowired(required = false)
    private MemorySystem memorySystem;

    private final SecurityEventProcessingOrchestrator processingOrchestrator;

    @Value("${security.plane.agent.name:SecurityPlaneAgent-1}")
    private String agentName;

    @Value("${security.plane.agent.auto-start:true}")
    private boolean autoStart;

    @Value("${security.plane.agent.max-concurrent-incidents:10}")
    private int maxConcurrentIncidents;

    @Value("${security.plane.agent.threat-threshold:0.7}")
    private double threatThreshold;

    @Value("${security.plane.agent.dynamic-response.min-severity:HIGH}")
    private String dynamicResponseMinSeverity;

    private AgentState currentState;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong processedEvents = new AtomicLong(0);
    private final AtomicLong createdIncidents = new AtomicLong(0);
    private final Map<String, IncidentHandler> activeIncidentHandlers = Collections.synchronizedMap(new WeakHashMap<>());
    private ScheduledExecutorService scheduler;

    @PostConstruct
    public void initialize() {

        if (auditLogger != null) {
            auditLogger.auditAgentStateChange(agentName, "UNINITIALIZED", "INITIALIZING",
                    "Security Plane Agent initialization started", null);
        }

        currentState = AgentState.INITIALIZING;

        securityMonitor.setBatchProcessor(this::processBatch);

        scheduler = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, agentName + "-Scheduler");
            t.setDaemon(true);
            return t;
        });

    }

    private void processBatch(List<SecurityEvent> events) {
        if (!running.get()) {
            log.warn("[SecurityPlaneAgent] Agent not running, dropping {} events", events.size());
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

        if (autoStart) {
            start();
        }
    }

    @Override
    public void start() {
        if (running.compareAndSet(false, true)) {
            currentState = AgentState.RUNNING;

            Map<String, Object> config = createMonitoringConfig();
            securityMonitor.startMonitoring(agentName, config);

            scheduler.scheduleWithFixedDelay(
                    this::cleanupIncidentHandlers,
                    5, 5, TimeUnit.MINUTES
            );

        } else {
            log.warn("Agent {} is already running", agentName);
        }
    }

    @Override
    public void stop() {
        if (running.compareAndSet(true, false)) {
            currentState = AgentState.STOPPING;

            securityMonitor.stopMonitoring(agentName);

            waitForActiveHandlers();

            if (scheduler != null) {
                scheduler.shutdown();
                try {
                    if (!scheduler.awaitTermination(30, TimeUnit.SECONDS)) {
                        scheduler.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    scheduler.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }

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

    @Transactional(rollbackFor = Exception.class)
    public void processWithOrchestrator(SecurityEvent event) {
        long startTime = System.currentTimeMillis();
        SecurityEventContext context = null;

        try {
            if (isEventAlreadyProcessed(event.getEventId())) {
                log.warn("[SecurityPlaneAgent] Event {} already processed, skipping duplicate",
                        event.getEventId());
                return;
            }

            context = processingOrchestrator.process(event);

            long processingTime = System.currentTimeMillis() - startTime;
            if (context.getProcessingMetrics() == null) {
                context.setProcessingMetrics(new SecurityEventContext.ProcessingMetrics());
            }
            context.getProcessingMetrics().setResponseTimeMs(processingTime);

            ProcessingMode mode = (ProcessingMode) context.getMetadata().get("processingMode");

            ProcessingResult result = (ProcessingResult) context.getMetadata().get("processingResult");
            if (result != null) {
                handleProcessingResult(event, result);
            }

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
            log.warn("[SecurityPlaneAgent] Failed to check event processing status: {}", eventId, e);
            return false;
        }
    }

    private void markEventAsProcessed(String eventId) {
        try {
            String processingKey = ZeroTrustRedisKeys.eventProcessed(eventId);

            redisTemplate.opsForValue().set(processingKey, "1", Duration.ofHours(24));
        } catch (Exception e) {
            log.warn("[SecurityPlaneAgent] Failed to mark event as processed: {}", eventId, e);
        }
    }

    public void handleNewIncident(SecurityIncident incident, SecurityEvent sourceEvent) {
        if (activeIncidentHandlers.size() >= maxConcurrentIncidents) {
            log.warn("Agent {} reached max concurrent incidents limit", agentName);
            return;
        }
        try {
            IncidentHandler handler = new IncidentHandler(incident.getIncidentId());

            SoarIncident soarIncident = new SoarIncident();
            soarIncident.setIncidentId(incident.getIncidentId());
            soarIncident.setType(incident.getType().toString());
            soarIncident.setDescription(incident.getDescription());
            soarIncident.setSeverity(incident.getThreatLevel().toString());
            soarIncident.setStatus(io.contexa.contexacore.domain.SoarIncidentStatus.NEW);
            soarIncident.setCreatedAt(LocalDateTime.now());
            soarIncident.setMetadata(new HashMap<>());
            handler.setSoarIncident(soarIncident);

            if (sourceEvent != null) {
                handler.setSecurityEvent(sourceEvent);
            }

            activeIncidentHandlers.put(incident.getIncidentId(), handler);

            if (incident.getAffectedUser() != null) {
                SecurityEvent relatedEvent = new SecurityEvent();
                relatedEvent.setUserId(incident.getAffectedUser());
                relatedEvent.setSource(SecurityEvent.EventSource.IAM);
                relatedEvent.setEventId(incident.getIncidentId());
                relatedEvent.setSeverity(convertThreatLevelToSeverity(incident.getThreatLevel()));
                relatedEvent.addMetadata("incidentType", "INCIDENT_CREATED");

                String response = "INCIDENT_" + incident.getType();
                double effectiveness = incident.getRiskScore();

                if (learningEngine != null) {
                    try {
                        learningEngine.learnFromEvent(relatedEvent, response, effectiveness).subscribe(
                                result -> log.debug("[SecurityPlaneAgent] Learning from incident {} completed",
                                        incident.getIncidentId()),
                                error -> log.error("[SecurityPlaneAgent] Failed to learn from incident {}: {}",
                                        incident.getIncidentId(), error.getMessage(), error)
                        );
                    } catch (Exception e) {

                        log.error("[SecurityPlaneAgent] Failed to learn from incident {}: {}",
                                incident.getIncidentId(), e.getMessage(), e);
                    }
                }
            }

            String key = "incident:" + incident.getIncidentId();
            storeInMemory(key, incident);

            if (contextProvider != null && soarNotifier != null) {

                if (incident.getThreatLevel() != null &&
                        (incident.getThreatLevel() == SecurityIncident.ThreatLevel.CRITICAL ||
                                incident.getThreatLevel() == SecurityIncident.ThreatLevel.HIGH)) {

                    SoarContext context = contextProvider.createContextFromIncident(incident);

                    CompletableFuture<NotificationResult> notificationResult =
                            soarNotifier.notifyIncident(incident, context);

                    notificationResult.thenAccept(result -> {
                        if (result.isSuccess()) {
                            handler.setSoarRequestId(result.getRequestId());
                        } else {
                            log.error("Failed to notify SOAR for high risk incident {}: {}",
                                    incident.getIncidentId(), result.getMessage());
                        }
                    });
                }
            } else {
                log.warn("SOAR integration not available for incident {}", incident.getIncidentId());
            }

            createdIncidents.incrementAndGet();

        } catch (Exception e) {
            log.error("Error handling incident {}", incident.getIncidentId(), e);
        }
    }

    public void resolveIncident(String incidentId, String resolvedBy, String resolutionMethod, boolean wasSuccessful) {
        IncidentHandler handler = activeIncidentHandlers.get(incidentId);
        if (handler == null) {
            log.warn("Cannot resolve incident - handler not found: {}", incidentId);
            return;
        }
        try {
            handler.resolveIncident(resolvedBy, resolutionMethod);
            IncidentResolvedEvent resolvedEvent = new IncidentResolvedEvent(
                    this,
                    incidentId,
                    handler.getSoarIncident(),
                    handler.getSecurityEvent(),
                    resolvedBy,
                    resolutionMethod,
                    handler.getResolutionTimeMs(),
                    wasSuccessful
            );

            eventPublisher.publishEvent(resolvedEvent);

            if (wasSuccessful && shouldCreateDynamicThreatResponse(handler)) {
                publishDynamicThreatResponseEvent(handler, resolutionMethod);
            }

            activeIncidentHandlers.remove(incidentId);

        } catch (Exception e) {
            log.error("Failed to resolve incident and publish event: {}", incidentId, e);
        }
    }

    private boolean shouldCreateDynamicThreatResponse(IncidentHandler handler) {
        SoarIncident soarIncident = handler.getSoarIncident();
        if (soarIncident == null) {
            return false;
        }

        String severity = soarIncident.getSeverity();
        if (severity == null) {
            return false;
        }

        int incidentSeverityRank = convertSeverityToRank(severity);
        int minSeverityRank = convertSeverityToRank(dynamicResponseMinSeverity);

        return incidentSeverityRank >= minSeverityRank;
    }

    private int convertSeverityToRank(String severity) {
        if (severity == null) {
            return 0;
        }
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> 5;
            case "HIGH" -> 4;
            case "MEDIUM" -> 3;
            case "LOW" -> 2;
            case "INFO" -> 1;
            default -> 0;
        };
    }

    private void publishDynamicThreatResponseEvent(IncidentHandler handler, String resolutionMethod) {
        try {
            SoarIncident soarIncident = handler.getSoarIncident();
            SecurityEvent securityEvent = handler.getSecurityEvent();

            String attackVector = null;
            if (securityEvent != null && securityEvent.getMetadata() != null) {
                Object av = securityEvent.getMetadata().get("attackVector");
                if (av != null) {
                    attackVector = av.toString();
                }
            }

            DynamicThreatResponseEvent threatEvent = DynamicThreatResponseEvent.builder()
                    .eventSource(this)
                    .severity(soarIncident.getSeverity())
                    .description("Threat response completed: " + resolutionMethod)
                    .threatType(soarIncident.getType())
                    .attackVector(attackVector)
                    .targetResource(extractTargetResource(soarIncident, securityEvent))
                    .attackerIdentity(securityEvent != null ? securityEvent.getSourceIp() : null)
                    .mitigationAction(resolutionMethod)
                    .responseSuccessful(true)
                    .responseDescription("Automated threat response successful")
                    .incidentId(parseIncidentIdToLong(soarIncident.getIncidentId()))
                    .soarWorkflowId(handler.getSoarRequestId())
                    .build();

            eventPublisher.publishEvent(threatEvent);

        } catch (Exception e) {
            log.error("Failed to publish DynamicThreatResponseEvent for incident: {}",
                    handler.getIncidentId(), e);
        }
    }

    private Long parseIncidentIdToLong(String incidentId) {
        if (incidentId == null || incidentId.isEmpty()) {
            return null;
        }
        try {
            return Long.parseLong(incidentId);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private String extractTargetResource(SoarIncident soarIncident, SecurityEvent securityEvent) {

        if (securityEvent != null && securityEvent.getMetadata() != null) {
            Object resource = securityEvent.getMetadata().get("targetResource");
            if (resource != null) {
                return resource.toString();
            }
        }

        if (soarIncident != null && soarIncident.getMetadata() != null) {
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                java.util.Map<String, Object> metadataMap = mapper.readValue(
                        soarIncident.getMetadata(), java.util.Map.class);
                Object resource = metadataMap.get("targetResource");
                if (resource != null) {
                    return resource.toString();
                }
            } catch (Exception e) {
                log.error(e.getMessage());
            }
        }
        return null;
    }

    private Map<String, Object> createMonitoringConfig() {
        Map<String, Object> config = new HashMap<>();
        config.put("agentId", agentName);
        config.put("autoIncidentCreation", true);
        config.put("threatThreshold", threatThreshold);
        config.put("correlationWindow", 10);
        return config;
    }

    private void waitForActiveHandlers() {
        int waitCount = 0;
        while (!activeIncidentHandlers.isEmpty() && waitCount < 60) {
            try {
                Thread.sleep(1000);
                waitCount++;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    @Override
    public boolean isRunning() {
        return running.get() && currentState == AgentState.RUNNING;
    }

    private void handleProcessingResult(SecurityEvent event, ProcessingResult result) {
        if (result == null) {
            log.warn("Processing result is null for event: {}", event.getEventId());
            return;
        }

        String userId = event.getUserId();
        if (userId == null) {
            return;
        }

        try {

            if (result.isRequiresIncident()) {
                createIncidentFromResult(event, result);
            }
        } catch (Exception e) {
            log.error("Failed to handle processing result for event: {}", event.getEventId(), e);
        }
    }

    private void createIncidentFromResult(SecurityEvent event, ProcessingResult result) {
        try {

            String severityStr = result.getIncidentSeverity();
            ProcessingResult.IncidentSeverity severity = severityStr != null ?
                    ProcessingResult.IncidentSeverity.valueOf(severityStr) :
                    ProcessingResult.IncidentSeverity.MEDIUM;
            SecurityIncident.ThreatLevel threatLevel = mapSeverityToThreatLevel(severity);

            SecurityIncident incident = SecurityIncident.builder()
                    .incidentId("INC-" + result.getProcessingPath() + "-" + System.currentTimeMillis())
                    .type(mapSeverityToIncidentType(severity))
                    .threatLevel(threatLevel)
                    .status(SecurityIncident.IncidentStatus.NEW)
                    .description(String.format("%s path detected %s threat",
                            result.getProcessingPath(), severity))
                    .sourceIp(event.getSourceIp())
                    .affectedUser(event.getUserId())
                    .detectedBy(agentName)
                    .detectionSource(result.getProcessingPath().toString())
                    .detectedAt(LocalDateTime.now())
                    .riskScore(result.getCurrentRiskLevel())
                    .autoResponseEnabled(severity == ProcessingResult.IncidentSeverity.CRITICAL)
                    .build();

            handleNewIncident(incident, event);

        } catch (Exception e) {
            log.error("Failed to create incident from processing result", e);
        }
    }

    private SecurityIncident.ThreatLevel mapSeverityToThreatLevel(ProcessingResult.IncidentSeverity severity) {
        if (severity == null) {
            return SecurityIncident.ThreatLevel.MEDIUM;
        }

        return switch (severity) {
            case CRITICAL -> SecurityIncident.ThreatLevel.CRITICAL;
            case HIGH -> SecurityIncident.ThreatLevel.HIGH;
            case MEDIUM -> SecurityIncident.ThreatLevel.MEDIUM;
            case LOW -> SecurityIncident.ThreatLevel.LOW;
            default -> SecurityIncident.ThreatLevel.MEDIUM;
        };
    }

    private SecurityIncident.IncidentType mapSeverityToIncidentType(ProcessingResult.IncidentSeverity severity) {
        return switch (severity) {
            case CRITICAL -> SecurityIncident.IncidentType.INTRUSION_ATTEMPT;
            case HIGH -> SecurityIncident.IncidentType.POLICY_VIOLATION;
            case MEDIUM -> SecurityIncident.IncidentType.SUSPICIOUS_ACTIVITY;
            default -> SecurityIncident.IncidentType.SUSPICIOUS_ACTIVITY;
        };
    }

    private void storeInMemory(String key, Object value) {
        if (memorySystem != null) {
            try {
                Map<String, Object> metadata = new HashMap<>();
                metadata.put("timestamp", LocalDateTime.now().toString());
                metadata.put("agentName", agentName);

                Object valueToStore = value;
                if (value instanceof SecurityIncident) {
                    valueToStore = SecurityIncidentDTO.fromEntity((SecurityIncident) value);
                }

                memorySystem.storeInWM(key, valueToStore, "security-plane")
                        .subscribe(
                                result -> log.debug("Memory storage completed: {}", key),
                                error -> log.error("Memory storage failed", error)
                        );

                if (value instanceof ThreatAssessment) {
                    ThreatAssessment ta = (ThreatAssessment) value;
                    if ("BLOCK".equals(ta.getAction())) {
                        memorySystem.storeInSTM(key, valueToStore, metadata)
                                .subscribe();
                    }
                }
            } catch (Exception e) {
                log.error("Error during memory storage", e);
            }
        }
    }

    private SecurityEvent.Severity convertThreatLevelToSeverity(SecurityIncident.ThreatLevel threatLevel) {
        if (threatLevel == null) {
            return SecurityEvent.Severity.MEDIUM;
        }
        return switch (threatLevel) {
            case CRITICAL -> SecurityEvent.Severity.CRITICAL;
            case HIGH -> SecurityEvent.Severity.HIGH;
            case MEDIUM -> SecurityEvent.Severity.MEDIUM;
            case LOW -> SecurityEvent.Severity.LOW;
            default -> SecurityEvent.Severity.INFO;
        };
    }

    @Autowired
    @Qualifier("llmAnalysisExecutor")
    private Executor llmAnalysisExecutor;

    private void cleanupIncidentHandlers() {
        try {

            List<String> toRemove = new ArrayList<>();

            activeIncidentHandlers.forEach((id, handler) -> {
                if (handler.isCompleted() || handler.isExpired()) {
                    toRemove.add(id);
                }
            });

            toRemove.forEach(activeIncidentHandlers::remove);

            if (!toRemove.isEmpty()) {
            }
        } catch (Exception e) {
            log.error("Error cleaning up incident handlers", e);
        }
    }

    private static class IncidentHandler {
        private final String incidentId;
        private final LocalDateTime createdAt;
        private final LocalDateTime expiresAt;
        private volatile boolean completed;
        private String soarRequestId;
        private SecurityEvent securityEvent;
        private SoarIncident soarIncident;
        private String resolutionMethod;
        private String resolvedBy;
        private LocalDateTime resolvedAt;

        public IncidentHandler(String incidentId) {
            this.incidentId = incidentId;
            this.createdAt = LocalDateTime.now();
            this.expiresAt = createdAt.plusHours(24);
            this.completed = false;
        }

        public boolean isCompleted() {
            return completed;
        }

        public boolean isExpired() {
            return LocalDateTime.now().isAfter(expiresAt);
        }

        public String getIncidentId() {
            return incidentId;
        }

        public String getSoarRequestId() {
            return soarRequestId;
        }

        public void setSoarRequestId(String soarRequestId) {
            this.soarRequestId = soarRequestId;
        }

        public void resolveIncident(String resolvedBy, String resolutionMethod) {
            this.completed = true;
            this.resolvedBy = resolvedBy;
            this.resolutionMethod = resolutionMethod;
            this.resolvedAt = LocalDateTime.now();
        }

        public SecurityEvent getSecurityEvent() {
            return securityEvent;
        }

        public void setSecurityEvent(SecurityEvent securityEvent) {
            this.securityEvent = securityEvent;
        }

        public SoarIncident getSoarIncident() {
            return soarIncident;
        }

        public void setSoarIncident(SoarIncident soarIncident) {
            this.soarIncident = soarIncident;
        }

        public long getResolutionTimeMs() {
            if (resolvedAt != null) {
                return Duration.between(createdAt, resolvedAt).toMillis();
            }
            return 0;
        }
    }

    private enum AgentState {
        INITIALIZING,
        RUNNING,
        PAUSED,
        STOPPING,
        STOPPED,
        ERROR
    }
}