package io.contexa.contexacoreenterprise.soar.service;

import io.contexa.contexacore.domain.SessionState;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarExecutionMode;
import io.contexa.contexacoreenterprise.soar.domain.SimulationEvent;
import io.contexa.contexacoreenterprise.soar.domain.SimulationStartRequest;
import io.contexa.contexacoreenterprise.mcp.tool.provider.McpClientProvider;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class SoarSimulationService {
    
    private final SoarToolCallingService soarToolCallingService;
    private final SimpMessagingTemplate brokerTemplate;
    private final McpClientProvider mcpClientProvider;

    private final Map<String, SimulationSession> activeSessions = new ConcurrentHashMap<>();

    public SoarSimulationService(SoarToolCallingService soarToolCallingService,
                                 @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerTemplate,
                                 McpClientProvider mcpClientProvider) {
        this.soarToolCallingService = soarToolCallingService;
        this.brokerTemplate = brokerTemplate;
        this.mcpClientProvider = mcpClientProvider;
    }

    public Mono<SimulationResult> startSimulation(SimulationStartRequest request) {

        SoarContext soarContext = createSoarContext(request);

        String sessionId = UUID.randomUUID().toString();
        soarContext.setSessionId(sessionId);
        String conversationId = UUID.randomUUID().toString();

        SimulationSession session = SimulationSession.builder()
            .sessionId(sessionId)
            .conversationId(conversationId)
            .incidentId(request.getIncidentId())
            .soarContext(soarContext)
            .status("INITIALIZING")
            .currentStage("PREPROCESSING")
            .progress(0)
            .executedTools(new ArrayList<>())
            .pendingApprovals(new ArrayList<>())
            .startTime(LocalDateTime.now())
            .build();
        
        activeSessions.put(sessionId, session);

        notifySimulationStarted(sessionId, request);

        return soarToolCallingService.executeWithApproval(
                request.getUserQuery() != null ? request.getUserQuery() : buildDefaultQuery(request),
                request.getIncidentId(),
                request.getOrganizationId(),
                soarContext
            )
            .map(executionResult -> {
                
                session.setStatus("COMPLETED");
                session.setProgress(100);
                session.setEndTime(LocalDateTime.now());

                notifySimulationComplete(sessionId, executionResult);
                
                return SimulationResult.builder()
                    .sessionId(sessionId)
                    .conversationId(executionResult.getConversationId())
                    .success(executionResult.isSuccess())
                    .finalResponse(executionResult.getFinalResponse())
                    .executedTools(executionResult.getExecutedTools())
                    .durationMs(executionResult.getDurationMs())
                    .build();
            })
            .subscribeOn(Schedulers.boundedElastic())
            .doOnError(error -> {
                log.error("SOAR simulation failed: sessionId={}", sessionId, error);
                session.setStatus("FAILED");
                session.setError(error.getMessage());
                notifySimulationError(sessionId, error);
            })
            .doFinally(signal -> {
                
                if (!"COMPLETED".equals(session.getStatus()) && !"FAILED".equals(session.getStatus())) {
                    log.error("Abnormal termination detected, forcing completion event: sessionId={}, signal={}", sessionId, signal);
                    session.setStatus("COMPLETED");
                    session.setEndTime(LocalDateTime.now());

                    SoarToolCallingService.SoarExecutionResult fallbackResult = 
                        SoarToolCallingService.SoarExecutionResult.builder()
                            .conversationId(conversationId)
                            .success(false)
                            .finalResponse("Analysis has been terminated.")
                            .executedTools(session.getExecutedTools())
                            .durationMs(System.currentTimeMillis() - session.getStartTime().toEpochSecond(java.time.ZoneOffset.UTC) * 1000)
                            .build();
                    
                    notifySimulationComplete(sessionId, fallbackResult);
                }
            });
    }

    public void stopSimulation(String sessionId) {
        SimulationSession session = activeSessions.get(sessionId);
        if (session == null) {
            throw new IllegalArgumentException("Session not found: " + sessionId);
        }
        session.setStatus("CANCELLED");
        session.setEndTime(LocalDateTime.now());
        activeSessions.remove(sessionId);

        SimulationErrorEvent event = SimulationErrorEvent.builder()
            .sessionId(sessionId)
            .error("Simulation cancelled by user")
            .timestamp(LocalDateTime.now())
            .build();
        brokerTemplate.convertAndSend("/topic/soar/error", event);
    }

    public Optional<SessionStatus> getSessionStatus(String sessionId) {
        SimulationSession session = activeSessions.get(sessionId);
        if (session == null) {
            return Optional.empty();
        }

        Map<String, Boolean> mcpStatus = getMcpServerStatus();
        
        return Optional.of(SessionStatus.builder()
            .sessionId(sessionId)
            .status(session.getStatus())
            .currentStage(session.getCurrentStage())
            .progress(session.getProgress())
            .executedTools(session.getExecutedTools())
            .pendingApprovals(session.getPendingApprovals())
            .mcpServersStatus(mcpStatus)
            .build());
    }

    public void handleApproval(String sessionId, String approvalId, String toolName, boolean approved, String reason) {

        SimulationSession session = activeSessions.get(sessionId);
        if (session == null) {
            log.error("Session not found: {}", sessionId);
            return;
        }

        session.getPendingApprovals().remove(approvalId);

        if (approved && toolName != null) {
            session.getSoarContext().approveTool(toolName);
        }

        notifyApprovalProcessed(sessionId, approvalId, approved, reason);

        resumeWorkflow(sessionId);
    }

    public Map<String, Boolean> getMcpServerStatus() {
        Map<String, Boolean> status = new HashMap<>();

        if (mcpClientProvider == null) {
            return status;
        }

        mcpClientProvider.getAllClients().keySet()
            .forEach(name -> status.put(name, true));

        return status;
    }

    private static final int SESSION_EXPIRY_MINUTES = 30;

    @Scheduled(fixedDelay = 300000)
    public void cleanupExpiredSessions() {
        LocalDateTime expiryThreshold = LocalDateTime.now().minusMinutes(SESSION_EXPIRY_MINUTES);
        List<String> expiredIds = new ArrayList<>();

        activeSessions.forEach((id, session) -> {
            LocalDateTime lastActive = session.getEndTime() != null
                    ? session.getEndTime()
                    : session.getStartTime();
            if (lastActive != null && lastActive.isBefore(expiryThreshold)) {
                expiredIds.add(id);
            }
        });

        for (String id : expiredIds) {
            activeSessions.remove(id);
        }

        if (!expiredIds.isEmpty()) {
            log.error("Cleaned up {} expired sessions, active: {}", expiredIds.size(), activeSessions.size());
        }
    }

    private SoarContext createSoarContext(SimulationStartRequest request) {
        SoarContext context = new SoarContext();

        String incidentId = request.getIncidentId();
        if (incidentId == null || incidentId.trim().isEmpty()) {
            incidentId = "INC-" + UUID.randomUUID().toString();
        }
        context.setIncidentId(incidentId);
        context.setThreatType(request.getThreatType());
        context.setDescription(request.getDescription());
        context.setAffectedAssets(request.getAffectedAssets());
        context.setDetectedSource(request.getDetectedSource());
        context.setSeverity(request.getSeverity());
        context.setOrganizationId(request.getOrganizationId());
        if (request.getExecutionMode() != null) {
            context.setExecutionMode(SoarExecutionMode.fromCode(request.getExecutionMode()));
        }
        context.setSessionState(SessionState.ACTIVE);
        context.setCreatedAt(LocalDateTime.now());

        context.setThreatLevel(mapSeverityToThreatLevel(request.getSeverity()));
        
        return context;
    }
    
    private SoarContext.ThreatLevel mapSeverityToThreatLevel(String severity) {
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> SoarContext.ThreatLevel.CRITICAL;
            case "HIGH" -> SoarContext.ThreatLevel.HIGH;
            case "MEDIUM" -> SoarContext.ThreatLevel.MEDIUM;
            case "LOW" -> SoarContext.ThreatLevel.LOW;
            default -> SoarContext.ThreatLevel.INFO;
        };
    }
    
    private String buildDefaultQuery(SimulationStartRequest request) {
        return String.format(
            "Analyze security incident: %s. Threat type: %s. Affected assets: %s. Severity: %s",
            request.getDescription(),
            request.getThreatType(),
            String.join(", ", request.getAffectedAssets()),
            request.getSeverity()
        );
    }
    
    private void resumeWorkflow(String sessionId) {
        SimulationSession session = activeSessions.get(sessionId);
        if (session == null) return;

        session.setStatus("ACTIVE");
    }

    private void notifySimulationStarted(String sessionId, SimulationStartRequest request) {
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("incidentId", request.getIncidentId() != null ? request.getIncidentId() : "");
        eventData.put("threatType", request.getThreatType() != null ? request.getThreatType() : "");
        eventData.put("severity", request.getSeverity() != null ? request.getSeverity() : "");
        
        SimulationEvent event = SimulationEvent.builder()
            .sessionId(sessionId)
            .eventType("SIMULATION_STARTED")
            .data(eventData)
            .timestamp(LocalDateTime.now())
            .build();
        
        brokerTemplate.convertAndSend("/topic/soar/events", event);
            }
    
    private void notifySimulationComplete(String sessionId, SoarToolCallingService.SoarExecutionResult result) {
        SimulationCompleteEvent event = SimulationCompleteEvent.builder()
            .sessionId(sessionId)
            .success(result.isSuccess())
            .finalResponse(result.getFinalResponse())  
            .executedTools(result.getExecutedTools())
            .durationMs(result.getDurationMs())
            .timestamp(LocalDateTime.now())
            .build();

        brokerTemplate.convertAndSend("/topic/soar/complete", event);
            }
    
    private void notifySimulationError(String sessionId, Throwable error) {
        SimulationErrorEvent event = SimulationErrorEvent.builder()
            .sessionId(sessionId)
            .error(error.getMessage())
            .timestamp(LocalDateTime.now())
            .build();

        brokerTemplate.convertAndSend("/topic/soar/error", event);
    }
    
    private void notifyApprovalProcessed(String sessionId, String approvalId, boolean approved, String reason) {
        ApprovalProcessedEvent event = ApprovalProcessedEvent.builder()
            .sessionId(sessionId)
            .approvalId(approvalId)
            .approved(approved)
            .reason(reason)
            .timestamp(LocalDateTime.now())
            .build();

        brokerTemplate.convertAndSend("/topic/soar/approval-results/" + approvalId, event);

        brokerTemplate.convertAndSend("/topic/soar/approvals", event);
    }
    
    @Data
    @Builder
    public static class SimulationSession {
        private String sessionId;
        private String conversationId;
        private String incidentId;
        private SoarContext soarContext;
        private String status;
        private String currentStage;
        private int progress;
        private List<String> executedTools;
        private List<String> pendingApprovals;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private String error;
    }
    
    @Data
    @Builder
    public static class SimulationResult {
        private String sessionId;
        private String conversationId;
        private boolean success;
        private String finalResponse;
        private List<String> executedTools;
        private long durationMs;
    }
    
    @Data
    @Builder
    public static class SessionStatus {
        private String sessionId;
        private String status;
        private String currentStage;
        private int progress;
        private List<String> executedTools;
        private List<String> pendingApprovals;
        private Map<String, Boolean> mcpServersStatus;
    }
    
    @Data
    @Builder
    public static class SimulationCompleteEvent {
        private String sessionId;
        private boolean success;
        private String finalResponse;  
        private List<String> executedTools;
        private long durationMs;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    public static class SimulationErrorEvent {
        private String sessionId;
        private String error;
        private LocalDateTime timestamp;
    }
    
    @Data
    @Builder
    public static class ApprovalProcessedEvent {
        private String sessionId;
        private String approvalId;
        private boolean approved;
        private String reason;
        private LocalDateTime timestamp;
    }
}